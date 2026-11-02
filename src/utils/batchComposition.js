/**
 * Within-batch composition analysis (Capability 5, B4).
 *
 * Reads the B2 effect list in emission order (native leg, top-level
 * operation, then subcalls in execution order) and identifies how
 * operations interact inside the one atomic transaction:
 *
 * - approval/authorization followed by movement of the same token
 *   (the in-batch approve-then-spend pattern);
 * - movement that precedes its only in-batch approval (ordering
 *   hazard: the movement cannot rely on an approval granted later);
 * - per-token outflow aggregates (exact totals, recipient fan-out);
 * - multiple distinct spenders approved for one token in one batch.
 *
 * Linkage is positional + token-based and labeled as such: inner
 * calls execute through the batch contract, so calldata alone never
 * proves that a later movement consumed a specific approval. The
 * module reports what the ordering establishes, not a proven
 * causal chain. Where token identity is unestablished (the honest
 * B2 default for inner operations), authorization/movement pairs
 * are reported as indeterminate coexistence — never linked, never
 * silently dropped.
 *
 * Pure and deterministic. Never throws on malformed input: bad
 * nodes are skipped, and an unusable list yields an explicit
 * empty result.
 */

const APPROVAL_KINDS = new Set(['approval', 'approval-nft', 'permit-authorization']);
// Spend-side: operations that move or consume token units. Native
// transfers join the aggregates below but need no approval, so they
// never link to an approval finding.
const SPEND_KINDS = new Set(['transfer', 'transfer-nft', 'swap', 'bridge']);
const AGGREGATE_KINDS = new Set(['transfer', 'transfer-nft', 'native-transfer', 'swap', 'bridge']);

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

function shortToken(key, effects) {
  const e = effects.find((x) => tokenKey(x) === key);
  const sym = e && e.asset && typeof e.asset.symbol === 'string' ? e.asset.symbol : null;
  const contract = key.split(':')[1] || '?';
  return sym ? `${sym} (${contract.slice(0, 10)}…)` : contract;
}

function analyzeBatchComposition(args) {
  const effects = args && typeof args === 'object' ? args.effects : null;
  const list = effects && Array.isArray(effects.effects) ? effects.effects : [];
  const nodes = list.filter((e) => e && typeof e === 'object' && typeof e.kind === 'string');
  const findings = [];
  const notes = [];
  const aggregates = [];
  const summary = {
    effects: nodes.length, approvals: 0, spends: 0,
    approveThenSpend: 0, spendBeforeApproval: 0,
    multiSpenderTokens: 0, fanOutGroups: 0,
    unlinkedApprovals: 0, unlinkedMovements: 0
  };

  const approvals = [];
  const spends = [];
  nodes.forEach((e, index) => {
    if (APPROVAL_KINDS.has(e.kind)) { approvals.push({ e, index }); summary.approvals += 1; }
    if (SPEND_KINDS.has(e.kind)) { spends.push({ e, index }); summary.spends += 1; }
  });

  // Rule 1: approval followed by same-token movement. One finding per
  // approval, naming the first subsequent movement and the count.
  for (const { e: a, index: ai } of approvals) {
    const key = tokenKey(a);
    if (key === null) continue;
    const later = spends.filter(({ e: s, index: si }) => si > ai && tokenKey(s) === key);
    if (later.length === 0) continue;
    summary.approveThenSpend += 1;
    const granter = granterOf(a);
    findings.push({
      ruleId: 'BATCH_APPROVE_THEN_SPEND',
      severity: 'MEDIUM',
      description: `${a.kind} of ${shortToken(key, nodes)}${granter ? ` to ${granter}` : ''} `
        + `at ${effectRef(a)} precedes ${later.length} same-token movement(s) in the same batch `
        + `(first: ${effectRef(later[0].e)}); the movement may execute under this authorization. `
        + `Positional linkage only — calldata does not prove the spender link.`,
      triggered: true,
      evidenceRefs: [effectRef(a), effectRef(later[0].e)],
      metadata: {
        approval: effectRef(a), approvalKind: a.kind, token: key, granter,
        movementCount: later.length, firstMovement: effectRef(later[0].e),
        linkage: 'positional-same-token'
      }
    });
  }

  // Rule 2: movement precedes its only in-batch approval(s). A spend
  // with an earlier same-token approval is covered and stays silent.
  for (const { e: s, index: si } of spends) {
    const key = tokenKey(s);
    if (key === null) continue;
    const before = approvals.filter(({ e: a, index: ai }) => ai < si && tokenKey(a) === key);
    if (before.length > 0) continue;
    const after = approvals.filter(({ e: a, index: ai }) => ai > si && tokenKey(a) === key);
    if (after.length === 0) continue;
    summary.spendBeforeApproval += 1;
    findings.push({
      ruleId: 'BATCH_SPEND_BEFORE_APPROVAL',
      severity: 'MEDIUM',
      description: `Movement of ${shortToken(key, nodes)} at ${effectRef(s)} executes before `
        + `its only in-batch authorization(s) (first: ${effectRef(after[0].e)}); it cannot rely on `
        + `an approval granted later in the batch, so it needs a pre-existing allowance or the batch reverts.`,
      triggered: true,
      evidenceRefs: [effectRef(s), effectRef(after[0].e)],
      metadata: {
        movement: effectRef(s), movementKind: s.kind, token: key,
        laterApprovals: after.map(({ e: a }) => effectRef(a)),
        linkage: 'positional-same-token'
      }
    });
  }

  // Aggregates: exact per-(token, sender) outflow over movement kinds.
  // Native legs aggregate under a native: key without a contract.
  const groups = new Map();
  for (const e of nodes) {
    if (!AGGREGATE_KINDS.has(e.kind)) continue;
    let key;
    if (e.kind === 'native-transfer') {
      key = 'native:';
    } else {
      key = tokenKey(e);
      if (key === null) continue;
    }
    const sender = typeof e.from === 'string' && e.from.length > 0 ? e.from.toLowerCase() : '(unestablished)';
    const gk = `${key}|${sender}`;
    if (!groups.has(gk)) {
      groups.set(gk, {
        token: e.kind === 'native-transfer' ? 'native' : shortToken(key, nodes),
        tokenKey: key, sender, count: 0, recipients: new Set(), total: 0n, exact: true, effectIds: []
      });
    }
    const g = groups.get(gk);
    g.count += 1;
    g.effectIds.push(effectRef(e));
    if (typeof e.to === 'string' && e.to.length > 0) g.recipients.add(e.to.toLowerCase());
    if (typeof e.amount === 'string' && /^[0-9]+$/.test(e.amount)) {
      try { g.total += BigInt(e.amount); } catch { g.exact = false; }
    } else {
      g.exact = false;
    }
  }
  for (const g of groups.values()) {
    if (g.count < 2) continue;
    aggregates.push({
      token: g.token, tokenKey: g.tokenKey, sender: g.sender,
      transfers: g.count, distinctRecipients: g.recipients.size,
      totalAmount: g.total.toString(), totalExact: g.exact,
      effectIds: g.effectIds
    });
    if (g.recipients.size >= 3) {
      summary.fanOutGroups += 1;
      notes.push(`Fan-out: ${g.count} ${g.token} outflow(s) from ${g.sender} to ${g.recipients.size} distinct recipients `
        + `(total ${g.total.toString()}${g.exact ? '' : ' — PARTIAL, some amounts undecodable'}; ${g.effectIds.join(', ')}).`);
    }
  }

  // Multi-spender approvals: one token, distinct grantees, one batch.
  const byToken = new Map();
  for (const { e: a } of approvals) {
    const key = tokenKey(a);
    const g = granterOf(a);
    if (key === null || g === null) continue;
    if (!byToken.has(key)) byToken.set(key, new Map());
    if (!byToken.get(key).has(g)) byToken.get(key).set(g, effectRef(a));
  }
  for (const [key, grantees] of byToken) {
    if (grantees.size < 2) continue;
    summary.multiSpenderTokens += 1;
    notes.push(`Multi-spender authorization: ${shortToken(key, nodes)} approved to ${grantees.size} distinct grantees `
      + `in one batch (${[...grantees.entries()].map(([g, id]) => `${g} at ${id}`).join('; ')}).`);
  }

  // Indeterminate coexistence: authorizations or movements whose
  // token identity is unestablished can neither be linked nor
  // excluded. One note per side so the gap is listed, not implied.
  const unknownApprovals = approvals.filter(({ e: a }) => tokenKey(a) === null).map(({ e: a }) => effectRef(a));
  const unknownSpends = spends.filter(({ e: s }) => tokenKey(s) === null).map(({ e: s }) => effectRef(s));
  summary.unlinkedApprovals = unknownApprovals.length;
  summary.unlinkedMovements = unknownSpends.length;
  if (unknownApprovals.length > 0 && spends.length > 0) {
    notes.push(`Indeterminate authorization: ${unknownApprovals.join(', ')} grant(s) spending authority with no established token; `
      + `the batch's ${spends.length} movement(s) can neither be linked to nor excluded from these grants.`);
  }
  if (unknownSpends.length > 0 && approvals.length > 0) {
    notes.push(`Indeterminate movement: ${unknownSpends.join(', ')} move(s) value with no established token; `
      + `the batch's ${approvals.length} authorization(s) can neither be linked to nor excluded from these movements.`);
  }
  const unknownAggregate = nodes.filter((e) => AGGREGATE_KINDS.has(e.kind) && e.kind !== 'native-transfer' && tokenKey(e) === null);
  if (unknownAggregate.length >= 2) {
    notes.push(`${unknownAggregate.length} movement(s) carry no token identity and are excluded from outflow aggregates `
      + `(${unknownAggregate.map(effectRef).join(', ')}); combined totals cover established tokens only.`);
  }

  return { findings, aggregates, notes, summary };
}

module.exports = { analyzeBatchComposition, APPROVAL_KINDS, SPEND_KINDS };
