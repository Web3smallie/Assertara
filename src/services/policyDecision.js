/**
 * Policy Decision Composer (Phase 1: verdict integrity).
 *
 * Centralized, deterministic mapping from the investigation outcome to the
 * final policy decision. This is the ONLY place that maps findings and
 * verdicts to ALLOW / BLOCK / REVIEW / UNCERTAIN.
 *
 * Authority order (highest first):
 *   1. Mandatory deterministic blocks — never overridden by the model.
 *   2. Discrepancy verdicts (MISMATCH) — held for human review.
 *   3. Uncertain verdicts — held as UNCERTAIN.
 *   4. Review-required deterministic findings — held for human review.
 *   5. Degraded reasoning (non-model origin) — held for human review.
 *   6. Clean MATCH from the model — ALLOW eligible.
 *
 * MATCH is an intent-alignment signal, not an authorization. An ALLOW
 * decision additionally requires every mandatory deterministic check to
 * have passed with no blocking or review findings outstanding.
 *
 * Scope: findings-based composition only (browser evaluation path). The
 * autonomous-agent path additionally gates ALLOW on an independently
 * authorised mandate (src/services/mandate.js), composed with this
 * decision in agentController.combineDecisions (BLOCK > UNCERTAIN >
 * REVIEW > ALLOW). MATCH from this composer is necessary but never
 * sufficient for agent execution.
 */

const POLICY_ID = 'assertara-mvp-1';

/**
 * Explicit per-finding policy. Every known decoder ruleId maps to exactly
 * one action. Unknown ruleIds fail closed to REVIEW (see findingActionFor).
 *
 * BLOCK justification:
 * - ZERO_ADDRESS_SPENDER: granting an allowance to 0x0 is never a
 *   legitimate operation (unrecoverable approval target). Mandatory block.
 *
 * REVIEW justification (legitimate uses exist, so a human must decide):
 * - INFINITE_APPROVAL / NFT_SET_APPROVAL_FOR_ALL / PERMIT2_OFFCHAIN_APPROVAL:
 *   standard DeFi patterns (DEX routers, marketplaces, Permit2) that are
 *   also the shape of drainer attacks. Hold for review, never auto-allow.
 * - AMBIGUOUS_APPROVAL_SCOPE: the allowance-vs-token-id question is
 *   unresolved from calldata alone. Uncertainty must not become approval.
 * - UNVERIFIED_SPENDER: unknown is not malicious, but it is unverified.
 * - SWAP_RECIPIENT_DIFFERS_FROM_SENDER: pay-to-other flows can be
 *   legitimate; the recipient must be verified first.
 *
 * REVIEW justification (Capability 4 B2 privileged operations):
 * - PROXY_UPGRADE / PROXY_ADMIN_CHANGE / OWNERSHIP_TRANSFER /
 *   OWNERSHIP_RENOUNCED / ROLE_GRANTED / ROLE_REVOKED / ROLE_RENOUNCED /
 *   CONTRACT_PAUSED / CONTRACT_UNPAUSED: authority changes over a
 *   contract. Legitimate administrators perform these routinely, so
 *   they hold for human review rather than blocking unconditionally;
 *   severity (CRITICAL/HIGH/MEDIUM) records the blast radius.
 *
 * REVIEW justification (Capability 4 B3 value protection):
 * - ZERO_MINIMUM_OUTPUT / MISSING_OUTPUT_PROTECTION: the swap's
 *   enforced floor is zero or unestablished, so a displayed quote is
 *   unenforced. Naive frontends do this routinely (hence REVIEW, not
 *   BLOCK), but a MATCH must never stand unqualified over it — the
 *   safeguard pipeline downgrades first.
 *
 * REVIEW justification (Capability 4 B4 nested calls):
 * - UNKNOWN_INNER_CALL: a batch contains an uninterpretable inner
 *   operation (unknown selector, depth limit, or analysis failure).
 *   Batches routinely include benign unknown helpers (hence REVIEW,
 *   not BLOCK), but a MATCH must never stand unqualified over them.
 *
 * REVIEW justification (Capability 4 B6 deadlines):
 * - EXPIRED_OPERATION / MISSING_DEADLINE: the operation reverts if
 *   submitted (past grace), or its time-sensitivity is unassessable.
 *   Clock skew and UI staleness make these reviewable rather than
 *   blockable, but signing a known-reverting transaction autonomously
 *   is never allowed — the safeguard downgrades first.
 */
const FINDING_ACTIONS = {
  ZERO_ADDRESS_SPENDER: 'BLOCK',
  INFINITE_APPROVAL: 'REVIEW',
  AMBIGUOUS_APPROVAL_SCOPE: 'REVIEW',
  NFT_SET_APPROVAL_FOR_ALL: 'REVIEW',
  UNVERIFIED_SPENDER: 'REVIEW',
  PERMIT2_OFFCHAIN_APPROVAL: 'REVIEW',
  SWAP_RECIPIENT_DIFFERS_FROM_SENDER: 'REVIEW',
  PROXY_UPGRADE: 'REVIEW',
  PROXY_ADMIN_CHANGE: 'REVIEW',
  OWNERSHIP_TRANSFER: 'REVIEW',
  OWNERSHIP_RENOUNCED: 'REVIEW',
  ROLE_GRANTED: 'REVIEW',
  ROLE_REVOKED: 'REVIEW',
  ROLE_RENOUNCED: 'REVIEW',
  CONTRACT_PAUSED: 'REVIEW',
  CONTRACT_UNPAUSED: 'REVIEW',
  ZERO_MINIMUM_OUTPUT: 'REVIEW',
  MISSING_OUTPUT_PROTECTION: 'REVIEW',
  BATCH_APPROVE_THEN_SPEND: 'REVIEW',
  BATCH_SPEND_BEFORE_APPROVAL: 'REVIEW',
  BRIDGE_DEPOSIT: 'REVIEW',
  BRIDGE_UNVERIFIED_CONTRACT: 'REVIEW',
  APPROVAL_EXCEEDS_BATCH_NEED: 'REVIEW',
  APPROVAL_PERSISTS_BEYOND_BATCH: 'REVIEW',
  PERMIT_GRANTS_PERSISTENT_ALLOWANCE: 'REVIEW',
  UNKNOWN_INNER_CALL: 'REVIEW',
  EXPIRED_OPERATION: 'REVIEW',
  MISSING_DEADLINE: 'REVIEW'
};

const DECISIONS = ['ALLOW', 'BLOCK', 'REVIEW', 'UNCERTAIN'];

/**
 * Policy action for one rule finding. Unknown or malformed ruleIds fail
 * closed to REVIEW: a finding the policy does not recognize must hold the
 * transaction, never pass it.
 */
function findingActionFor(ruleId) {
  if (typeof ruleId === 'string' && Object.prototype.hasOwnProperty.call(FINDING_ACTIONS, ruleId)) {
    return FINDING_ACTIONS[ruleId];
  }
  return 'REVIEW';
}

function findingIds(findings) {
  return (Array.isArray(findings) ? findings : [])
    .filter((f) => f && typeof f.ruleId === 'string')
    .map((f) => f.ruleId);
}

/**
 * Compose the final policy decision. Pure and deterministic.
 *
 * Inputs are post-safeguard values EXCEPT modelVerdict/modelConfidence,
 * which are the model's proposal captured before safeguards ran.
 * Model confidence is deliberately NOT an input: no confidence score can
 * promote, demote, or override a deterministic rule.
 *
 * @param {object} args
 * @param {string} args.verdict Post-safeguard verdict.
 * @param {string} [args.modelVerdict] Model/heuristic proposal (provenance).
 * @param {number} [args.modelConfidence] Proposed confidence (provenance).
 * @param {string} [args.reasoningOrigin] 'model' | 'heuristic-fallback' | other.
 * @param {Array} [args.ruleFindings] Decoder rule findings.
 * @param {Array} [args.safeguards] Ordered safeguard records.
 * @param {Array} [args.advisoryEscalations] Model advisories [{source,
 *   reason}]. Escalation-only: a non-empty list converts would-be ALLOW
 *   into REVIEW. Never demotes BLOCK/REVIEW/UNCERTAIN, never permits.
 * @param {Array} [args.deterministicHolds] Deterministic holds [{source,
 *   reason}] from chain verification, support validation, or mechanism
 *   reconciliation. Same escalation-only contract as advisories,
 *   evaluated first (deterministic before model).
 * @returns {{policyId, decision, modelVerdict, modelConfidence, reasoningOrigin,
 *   blockingFindings, reviewFindings, reasons}}
 */
function composePolicyDecision({
  verdict,
  modelVerdict = null,
  modelConfidence = null,
  reasoningOrigin = 'unknown',
  ruleFindings = [],
  safeguards = [],
  advisoryEscalations = [],
  deterministicHolds = []
} = {}) {
  const ids = findingIds(ruleFindings);
  const blockingFindings = ids.filter((id) => findingActionFor(id) === 'BLOCK');
  const reviewFindings = ids.filter((id) => findingActionFor(id) === 'REVIEW');
  const safeguardTriggers = (Array.isArray(safeguards) ? safeguards : [])
    .filter((s) => s && typeof s.trigger === 'string')
    .map((s) => s.trigger);

  const base = {
    policyId: POLICY_ID,
    modelVerdict: typeof modelVerdict === 'string' ? modelVerdict : null,
    modelConfidence: typeof modelConfidence === 'number' && Number.isFinite(modelConfidence)
      ? modelConfidence
      : null,
    reasoningOrigin: typeof reasoningOrigin === 'string' ? reasoningOrigin : 'unknown',
    blockingFindings,
    reviewFindings
  };

  // 1. Mandatory deterministic blocks dominate everything: verdict,
  //    origin, confidence, and safeguards are all irrelevant here.
  if (blockingFindings.length > 0) {
    return {
      ...base,
      decision: 'BLOCK',
      reasons: blockingFindings.map(
        (id) => `Mandatory deterministic block: ${id}. The model verdict cannot override it.`
      )
    };
  }

  // 2. A discrepancy verdict is preserved as a hold for human review.
  if (verdict === 'MISMATCH') {
    return {
      ...base,
      decision: 'REVIEW',
      reasons: ['Discrepancy verdict (MISMATCH) between displayed intent and transaction requires human review.']
    };
  }

  // 3. Uncertainty holds, whatever the origin: an UNCERTAIN (or
  //    missing, or unrecognized) verdict is preserved, never promoted.
  //    Safeguard triggers are cited when present so the hold reason
  //    stays inspectable.
  if (verdict === 'UNCERTAIN' || typeof verdict !== 'string' || !['MATCH', 'MISMATCH', 'UNCERTAIN'].includes(verdict)) {
    const via = safeguardTriggers.length > 0
      ? ` Safeguards triggered: ${safeguardTriggers.join(', ')}.`
      : '';
    return {
      ...base,
      decision: 'UNCERTAIN',
      reasons: [`Investigation is UNCERTAIN; execution held.${via}`.trim()]
    };
  }

  // 4. Review-required findings hold the transaction even when the
  //    model reports MATCH: a match is not an authorization.
  if (reviewFindings.length > 0) {
    return {
      ...base,
      decision: 'REVIEW',
      reasons: reviewFindings.map(
        (id) => `Deterministic finding ${id} requires human review before any approval.`
      )
    };
  }

  // 5. Degraded reasoning cannot authorize: only a real model verdict
  //    counts toward ALLOW. Anything else (heuristic fallback, unknown
  //    origin) holds for review instead of silently approving. This
  //    stage is reachable only with a MATCH verdict (MISMATCH and
  //    UNCERTAIN returned above), so it gates authorization exactly.
  if (reasoningOrigin !== 'model') {
    return {
      ...base,
      decision: 'REVIEW',
      reasons: [`Reasoning origin is '${base.reasoningOrigin}', not verified model output; held for human review.`]
    };
  }

  // 6. Deterministic verification holds, then model advisory
  //    escalation: either may hold a clean MATCH for human review, but
  //    neither can permit anything. These stages only convert would-be
  //    ALLOW into REVIEW; every hold above is unaffected, and nothing
  //    here can demote a BLOCK or REVIEW.
  const holds = Array.isArray(deterministicHolds) ? deterministicHolds.filter((e) => e && typeof e.reason === 'string') : [];
  if (holds.length > 0) {
    return {
      ...base,
      decision: 'REVIEW',
      reasons: holds.map((e) => `Deterministic hold (${e.source || 'analysis'}): ${e.reason}`)
    };
  }
  const escalations = Array.isArray(advisoryEscalations) ? advisoryEscalations.filter((e) => e && typeof e.reason === 'string') : [];
  if (escalations.length > 0) {
    return {
      ...base,
      decision: 'REVIEW',
      reasons: escalations.map((e) => `Model advisory escalation (${e.source || 'investigation'}): ${e.reason}`)
    };
  }

  // 7. Clean MATCH from the model with no outstanding findings.
  return {
    ...base,
    decision: 'ALLOW',
    reasons: ['Model verdict MATCH with all mandatory deterministic checks passed and no blocking or review findings.']
  };
}

module.exports = { POLICY_ID, DECISIONS, FINDING_ACTIONS, findingActionFor, composePolicyDecision };
