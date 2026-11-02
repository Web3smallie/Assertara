/**
 * Approval necessity and duration analysis (Capability 5, B6).
 *
 * For every authorization-side effect (approval, approval-nft,
 * permit-authorization), determines:
 *
 * - DURATION: does the grant persist indefinitely, expire at a known
 *   time, or is its duration unestablished? A permit/expiry deadline
 *   bounds signature submission, never the resulting allowance —
 *   except Permit2 `approve`, whose expiration IS the allowance
 *   expiry. That distinction is the core of this module.
 * - NECESSITY: does the batch spend the granted token (measured
 *   need), and does the granted amount exceed it? Excess over
 *   measured in-batch need persists beyond the batch.
 *
 * Only established-token, exact-amount cases produce findings.
 * Unestablished tokens, undecodable amounts, delta semantics
 * (increaseAllowance), and unlimited grants (owned by
 * INFINITE_APPROVAL) yield assessments and notes, never B6 findings.
 *
 * Pure and deterministic. Never throws on malformed input.
 */

// Permit2 uint48 max expiration: the protocol's "never expires".
const PERMIT2_MAX_EXPIRATION = (1n << 48n) - 1n;

const APPROVAL_KINDS = new Set(['approval', 'approval-nft', 'permit-authorization']);
const SPEND_KINDS = new Set(['transfer', 'transfer-nft', 'swap', 'bridge']);

function tokenKey(e) {
  const a = e && typeof e.asset === 'object' ? e.asset : null;
  if (!a || typeof a.contract !== 'string' || a.contract.length === 0) return null;
  if (a.standard !== 'ERC20' && a.standard !== 'ERC721') return null;
  return `${a.standard}:${a.contract.toLowerCase()}`;
}

function granterOf(e) {
  if (!e) return null;
  if (typeof e.spender === 'string' && e.spender.length > 0) return e.spender.toLowerCase();
  if (typeof e.operator === 'string' && e.operator.length > 0) return e.operator.toLowerCase();
  return null;
}

function effectRef(e) {
  return e && typeof e.effectId === 'string' ? e.effectId : '?';
}

function opOf(e) {
  return e && typeof e.operation === 'object' ? e.operation : {};
}

function isDigits(s) {
  return typeof s === 'string' && /^[0-9]+$/.test(s);
}

function analyzeApprovalNecessity(args) {
  const effects = args && typeof args === 'object' ? args.effects : null;
  const list = effects && Array.isArray(effects.effects) ? effects.effects : [];
  const nodes = list.filter((e) => e && typeof e === 'object' && typeof e.kind === 'string');
  const assessments = [];
  const findings = [];
  const notes = [];
  const summary = { approvals: 0, exceeds: 0, persists: 0, permitPersistent: 0, revocations: 0, unknown: 0 };

  const approvals = [];
  const spends = [];
  nodes.forEach((e, index) => {
    if (APPROVAL_KINDS.has(e.kind)) approvals.push({ e, index });
    if (SPEND_KINDS.has(e.kind)) spends.push({ e, index });
  });
  summary.approvals = approvals.length;

  for (const { e: a, index: ai } of approvals) {
    const id = effectRef(a);
    const key = tokenKey(a);
    const fn = opOf(a).functionName;
    const std = opOf(a).standard;
    const granter = granterOf(a);
    const assessment = {
      effectId: id, kind: a.kind, functionName: fn || null, standard: std || null,
      token: key, granter, amount: isDigits(a.amount) ? a.amount : null,
      unlimited: a.unlimited === true,
      duration: 'unknown', durationBasis: null,
      batchNeed: null, needMeasured: false, excess: null,
      verdict: 'unknown'
    };
    const tokenLabel = key ? key.split(':')[1] : '(unestablished token)';

    // Revocations remove authority: observed, never flagged.
    const isRevocation = (a.kind === 'approval' && a.amount === '0')
      || (a.kind === 'approval-nft' && a.unlimited === false)
      || (a.kind === 'permit-authorization' && a.amount === '0');
    if (isRevocation) {
      assessment.verdict = 'revocation';
      assessment.duration = 'none';
      assessment.durationBasis = 'zero amount / revoked operator removes authority rather than granting it';
      summary.revocations += 1;
      notes.push(`${id} revokes authority (${a.kind} to ${granter || '?'}); no grant persists.`);
      assessments.push(assessment);
      continue;
    }

    // Duration classification.
    if (a.kind === 'approval-nft') {
      assessment.duration = 'persistent';
      assessment.durationBasis = 'ERC-721 operator approval has no expiry mechanism';
    } else if (a.kind === 'permit-authorization' && std === 'ERC20') {
      // The B6 anti-assumption: an EIP-2612 deadline bounds when the
      // signature may be SUBMITTED. The allowance it grants persists
      // on-chain exactly like an on-chain approve.
      assessment.duration = 'persistent';
      assessment.durationBasis = 'EIP-2612 deadline bounds signature submission only; the granted allowance has no expiry';
    } else if (a.kind === 'permit-authorization' && std === 'Permit2') {
      if (isDigits(a.signedExpiry)) {
        assessment.duration = 'bounded';
        assessment.durationBasis = `Permit2 signed expiration ${a.signedExpiry} bounds the allowance`;
      } else {
        assessment.duration = 'unknown';
        assessment.durationBasis = 'Permit2 signed expiration undecoded; duration unestablished';
      }
    } else if (a.kind === 'approval' && std === 'Permit2') {
      if (!isDigits(a.expiration)) {
        assessment.duration = 'unknown';
        assessment.durationBasis = 'Permit2 expiration undecodable; duration unestablished';
      } else if (BigInt(a.expiration) >= PERMIT2_MAX_EXPIRATION) {
        assessment.duration = 'persistent';
        assessment.durationBasis = 'Permit2 expiration is max-uint48: effectively never expires';
      } else {
        assessment.duration = 'bounded';
        assessment.durationBasis = `Permit2 allowance expires at ${a.expiration}`;
      }
    } else if (a.kind === 'approval') {
      assessment.duration = 'persistent';
      assessment.durationBasis = 'ERC-20 approval has no expiry mechanism';
    }

    const deltaSemantics = fn === 'increaseAllowance';
    if (deltaSemantics) {
      // A delta adds to an unknown on-chain total: excess is
      // uncomputable without chain state. Duration still holds.
      assessment.verdict = assessment.duration === 'persistent' ? 'persists-unknown-total' : 'unknown';
      summary.unknown += 1;
      notes.push(`${id} increaseAllowance adds ${assessment.amount || '?'} to an unknown current allowance for ${granter || '?'}; `
        + `resulting total needs chain state, so excess is unmeasurable (grant is persistent).`);
      assessments.push(assessment);
      continue;
    }

    if (key === null) {
      assessment.verdict = 'unknown-token';
      summary.unknown += 1;
      notes.push(`${id} grants authority with no established token; necessity and excess are unmeasurable.`);
      assessments.push(assessment);
      continue;
    }

    // Measured in-batch need: exact sum of same-token spends AFTER
    // the grant. Earlier spends cannot consume this authorization.
    const later = spends.filter(({ e: s, index: si }) => si > ai && tokenKey(s) === key);
    let need = 0n;
    let measurable = true;
    for (const { e: s } of later) {
      if (!isDigits(s.amount)) { measurable = false; break; }
      need += BigInt(s.amount);
    }
    if (!measurable) {
      assessment.verdict = 'unknown-need';
      summary.unknown += 1;
      notes.push(`${id} authorizes ${tokenLabel} but a same-batch movement amount is undecodable; need unmeasurable.`);
      assessments.push(assessment);
      continue;
    }
    assessment.batchNeed = need.toString();
    assessment.needMeasured = true;

    // Unlimited grants are owned by INFINITE_APPROVAL; B6 records
    // duration and use, never duplicates the finding.
    if (assessment.unlimited) {
      assessment.verdict = later.length > 0 ? 'unlimited-utilized' : 'unlimited-unused-in-batch';
      if (later.length === 0) {
        notes.push(`${id} grants UNLIMITED ${tokenLabel} to ${granter || '?'} with no same-batch movement; standing authority persists.`);
      }
      assessments.push(assessment);
      continue;
    }

    if (a.kind === 'approval-nft') {
      if (later.length === 0 && assessment.duration === 'persistent') {
        assessment.verdict = 'persists-unused';
        summary.persists += 1;
        findings.push({
          ruleId: 'APPROVAL_PERSISTS_BEYOND_BATCH',
          severity: 'MEDIUM',
          description: `${id} grants ${granter || '?'} operator authority over ${tokenLabel} NFTs with no same-batch movement; `
            + `the persistent grant outlives the batch. Held for review.`,
          triggered: true,
          evidenceRefs: [id],
          metadata: { approval: id, kind: a.kind, token: key, granter, duration: 'persistent' }
        });
      } else {
        assessment.verdict = later.length > 0 ? 'utilized' : 'unknown';
      }
      assessments.push(assessment);
      continue;
    }

    if (!isDigits(a.amount)) {
      assessment.verdict = 'unknown-amount';
      summary.unknown += 1;
      notes.push(`${id} authorizes ${tokenLabel} with an undecodable amount; excess unmeasurable.`);
      assessments.push(assessment);
      continue;
    }

    // ERC-20 permit: persistent by mechanism, deadlined by signature.
    if (a.kind === 'permit-authorization' && std === 'ERC20') {
      assessment.verdict = 'permit-persistent';
      summary.permitPersistent += 1;
      findings.push({
        ruleId: 'PERMIT_GRANTS_PERSISTENT_ALLOWANCE',
        severity: 'MEDIUM',
        description: `${id} is an EIP-2612 permit granting ${a.amount} ${tokenLabel} to ${granter || '?'}; `
          + `the signature deadline does NOT expire the allowance — the grant persists on-chain like an approve. Held for review.`,
        triggered: true,
        evidenceRefs: [id],
        metadata: { approval: id, kind: a.kind, token: key, granter, amount: a.amount, duration: 'persistent' }
      });
      assessments.push(assessment);
      continue;
    }

    // Bounded on-chain approvals: excess over measured need, or a
    // persistent grant with no observed use.
    const granted = BigInt(a.amount);
    if (later.length > 0 && granted > need) {
      assessment.excess = (granted - need).toString();
      assessment.verdict = 'exceeds-need';
      summary.exceeds += 1;
      findings.push({
        ruleId: 'APPROVAL_EXCEEDS_BATCH_NEED',
        severity: 'MEDIUM',
        description: `${id} approves ${a.amount} ${tokenLabel} to ${granter || '?'} but the batch moves only ${need.toString()}; `
          + `excess ${(granted - need).toString()} persists beyond the batch${assessment.duration === 'bounded' ? ` (expires ${a.expiration})` : ''}. Held for review.`,
        triggered: true,
        evidenceRefs: [id, ...later.map(({ e: s }) => effectRef(s))],
        metadata: { approval: id, kind: a.kind, token: key, granter, amount: a.amount, need: need.toString(), excess: assessment.excess, duration: assessment.duration }
      });
    } else if (later.length > 0) {
      assessment.verdict = 'utilized';
      assessment.excess = '0';
    } else if (assessment.duration === 'persistent') {
      assessment.verdict = 'persists-unused';
      summary.persists += 1;
      findings.push({
        ruleId: 'APPROVAL_PERSISTS_BEYOND_BATCH',
        severity: 'MEDIUM',
        description: `${id} approves ${a.amount} ${tokenLabel} to ${granter || '?'} with no same-batch movement; `
          + `the persistent grant outlives the batch. Held for review.`,
        triggered: true,
        evidenceRefs: [id],
        metadata: { approval: id, kind: a.kind, token: key, granter, amount: a.amount, duration: 'persistent' }
      });
    } else {
      assessment.verdict = assessment.duration === 'bounded' ? 'bounded-unused' : 'unknown';
      if (assessment.duration === 'bounded') {
        notes.push(`${id} approves ${a.amount} ${tokenLabel} with no same-batch movement; bounded until ${a.expiration}.`);
      }
    }
    assessments.push(assessment);
  }

  return { assessments, findings, notes, summary };
}

module.exports = { analyzeApprovalNecessity, PERMIT2_MAX_EXPIRATION };
