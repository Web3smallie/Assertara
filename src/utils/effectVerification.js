/**
 * Post-execution effect verification (Capability 5, B7).
 *
 * Reconciles receipt-confirmed Transfer / Approval / ApprovalForAll
 * logs against the authorized reconstructed effect list:
 *
 * - EFFECTS_MATCHED: every log-emitting expectation met exactly,
 *   no unexpected logs, no wildcards, no unverifiable operations.
 * - EFFECTS_DIVERGED: an expected log is missing, or an unexpected
 *   log appeared that no authorized effect explains.
 * - EFFECTS_UNVERIFIED: anything else — undecodable receipt, skipped
 *   operations (swaps, wraps, bridges, opaque nodes), or matches that
 *   needed wildcard fields (unestablished inner parties/contracts).
 *
 * Precedence is DIVERGED > UNVERIFIED > MATCHED, with one guard:
 * when the batch contains operations that legitimately emit logs
 * this module cannot model (swap/wrap/bridge/opaque), unexpected
 * logs cannot be attributed, so they cap at UNVERIFIED instead of
 * DIVERGED. Missing expected logs always diverge.
 *
 * Pure and deterministic. Never throws on malformed input.
 */

const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const APPROVAL_FOR_ALL_TOPIC = '0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31';

// Effect kinds whose log emissions this module cannot model: their
// presence disables the unexpected-log rule (can't attribute) and
// caps the outcome at UNVERIFIED.
const UNMODELED_KINDS = new Set(['swap', 'wrap', 'unwrap', 'bridge', 'opaque']);

const TOPIC_RE = /^0x[0-9a-fA-F]{64}$/;

function topicToAddress(t) {
  if (typeof t !== 'string' || !TOPIC_RE.test(t)) return null;
  return `0x${t.slice(-40)}`.toLowerCase();
}

function topicToBool(t, data) {
  // ApprovalForAll packs `approved` in data, not topics.
  try {
    if (typeof data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(data)) return null;
    const v = BigInt(data.length > 2 ? data : '0x0');
    return v === 1n ? true : v === 0n ? false : null;
  } catch {
    return null;
  }
}

function dataToUint(data) {
  try {
    if (typeof data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(data) || data.length <= 2) return null;
    return BigInt(data).toString();
  } catch {
    return null;
  }
}

function lowerAddr(v) {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v) ? v.toLowerCase() : null;
}

function isDigits(s) {
  return typeof s === 'string' && /^[0-9]+$/.test(s);
}

/**
 * Parse receipt logs into Transfer / Approval / ApprovalForAll
 * records. Returns { ok, transfers, approvals, approvalsForAll,
 * undecodable }.
 */
function parseReceiptLogs(receipt) {
  const out = { ok: false, transfers: [], approvals: [], approvalsForAll: [], undecodable: 0, note: null };
  const logs = receipt && typeof receipt === 'object' ? receipt.logs : null;
  if (!Array.isArray(logs)) {
    out.note = 'receipt logs unavailable (missing logs array)';
    return out;
  }
  out.ok = true;
  logs.forEach((log, index) => {
    try {
      const topics = log && typeof log === 'object' && Array.isArray(log.topics) ? log.topics : [];
      const t0 = typeof topics[0] === 'string' ? topics[0].toLowerCase() : null;
      const contract = log && typeof log.address === 'string' ? log.address.toLowerCase() : null;
      if (t0 === TRANSFER_TOPIC && topics.length >= 3) {
        const from = topicToAddress(topics[1]);
        const to = topicToAddress(topics[2]);
        const value = dataToUint(log.data);
        if (!contract || !from || !to || value === null) { out.undecodable += 1; return; }
        out.transfers.push({ logIndex: index, contract, from, to, value });
      } else if (t0 === APPROVAL_TOPIC && topics.length >= 3) {
        const owner = topicToAddress(topics[1]);
        const spender = topicToAddress(topics[2]);
        const value = dataToUint(log.data);
        if (!contract || !owner || !spender || value === null) { out.undecodable += 1; return; }
        out.approvals.push({ logIndex: index, contract, owner, spender, value });
      } else if (t0 === APPROVAL_FOR_ALL_TOPIC && topics.length >= 3) {
        const owner = topicToAddress(topics[1]);
        const operator = topicToAddress(topics[2]);
        const approved = topicToBool(topics[2], log.data);
        if (!contract || !owner || !operator || approved === null) { out.undecodable += 1; return; }
        out.approvalsForAll.push({ logIndex: index, contract, owner, operator, approved });
      }
      // All other topics are out of scope and ignored.
    } catch {
      out.undecodable += 1;
    }
  });
  return out;
}

function tokenOf(e) {
  const a = e && typeof e.asset === 'object' ? e.asset : null;
  if (!a || typeof a.contract !== 'string' || a.contract.length === 0) return null;
  return a.contract.toLowerCase();
}

function effectRef(e) {
  return e && typeof e.effectId === 'string' ? e.effectId : '?';
}

function isTopLevel(e) {
  return !e || e.subcall === null || e.subcall === undefined;
}

/**
 * Build log expectations from authorized effects.
 * Returns { transfer, approval, approvalForAll, unmatchable, unmodeled }.
 * Expectation fields are exact values or null (wildcard).
 */
function buildExpectations({ nodes, sender }) {
  const exp = { transfer: [], approval: [], approvalForAll: [], unmatchable: [], unmodeled: [] };
  for (const e of nodes) {
    const id = effectRef(e);
    if (UNMODELED_KINDS.has(e.kind)) {
      exp.unmodeled.push(id);
      continue;
    }
    if (e.kind === 'transfer') {
      const c = tokenOf(e);
      const established = [c, e.from, e.to, e.amount].filter((v) => typeof v === 'string' && v.length > 0).length;
      if (established === 0) { exp.unmatchable.push(id); continue; }
      exp.transfer.push({
        effectId: id, contract: c,
        from: typeof e.from === 'string' ? e.from.toLowerCase() : null,
        to: typeof e.to === 'string' ? e.to.toLowerCase() : null,
        value: isDigits(e.amount) ? BigInt(e.amount).toString() : null
      });
    } else if (e.kind === 'transfer-nft') {
      const c = tokenOf(e);
      const tid = e.asset && isDigits(e.asset.tokenId) ? BigInt(e.asset.tokenId).toString() : null;
      const established = [c, e.from, e.to, tid].filter((v) => typeof v === 'string' && v.length > 0).length;
      if (established === 0) { exp.unmatchable.push(id); continue; }
      exp.transfer.push({
        effectId: id, contract: c,
        from: typeof e.from === 'string' ? e.from.toLowerCase() : null,
        to: typeof e.to === 'string' ? e.to.toLowerCase() : null,
        value: tid
      });
    } else if (e.kind === 'approval' || e.kind === 'permit-authorization') {
      const c = tokenOf(e);
      // Owner: an explicit owner param wins (permits name theirs);
      // else top-level on-chain grants come from the sender, while
      // nested grants execute under batch mechanics this module does
      // not model (wildcard, capped at UNVERIFIED).
      const explicitOwner = typeof e.owner === 'string' ? e.owner.toLowerCase() : null;
      const owner = explicitOwner || (e.kind === 'approval' && isTopLevel(e) ? sender : null);
      const spender = typeof e.spender === 'string' ? e.spender.toLowerCase() : null;
      const value = isDigits(e.amount) ? BigInt(e.amount).toString() : null;
      const established = [c, owner, spender, value].filter((v) => typeof v === 'string' && v.length > 0).length;
      if (established === 0) { exp.unmatchable.push(id); continue; }
      exp.approval.push({ effectId: id, contract: c, owner, spender, value });
    } else if (e.kind === 'approval-nft') {
      const c = tokenOf(e);
      const owner = isTopLevel(e) ? sender : null;
      const operator = typeof e.operator === 'string' ? e.operator.toLowerCase() : null;
      const approved = e.unlimited === true ? true : e.unlimited === false ? false : null;
      const established = [c, owner, operator].filter((v) => typeof v === 'string' && v.length > 0).length
        + (approved === null ? 0 : 1);
      if (established === 0) { exp.unmatchable.push(id); continue; }
      exp.approvalForAll.push({ effectId: id, contract: c, owner, operator, approved });
    }
    // native-transfer emits no logs; authority-change emits no
    // Transfer/Approval logs. Both are correctly silent here.
  }
  return exp;
}

function fieldsMatch(want, got, fields) {
  const wildcards = [];
  for (const f of fields) {
    if (want[f] === null || want[f] === undefined) { wildcards.push(f); continue; }
    if (got[f] !== want[f]) return { match: false, wildcards: [] };
  }
  return { match: true, wildcards };
}

/**
 * Reconcile authorized effects against a transaction receipt.
 * @param {{effects: object, receipt: object, sender: string|null}} args
 */
function verifyEffectsAgainstReceipt(args) {
  const a = args && typeof args === 'object' ? args : {};
  const effects = a.effects && typeof a.effects === 'object' ? a.effects : null;
  const list = effects && Array.isArray(effects.effects) ? effects.effects : [];
  const nodes = list.filter((e) => e && typeof e === 'object' && typeof e.kind === 'string');
  const sender = lowerAddr(a.sender);
  const notes = [];
  const matches = [];
  const missing = [];
  const unexpected = [];

  const parsed = parseReceiptLogs(a.receipt);
  if (!parsed.ok) {
    return {
      status: 'EFFECTS_UNVERIFIED',
      reason: parsed.note,
      matches, missing, unexpected, notes: [parsed.note],
      summary: { expectations: 0, matched: 0, missing: 0, unexpected: 0, wildcards: 0 }
    };
  }
  if (parsed.undecodable > 0) {
    notes.push(`${parsed.undecodable} Transfer/Approval-shaped log(s) undecodable; capping at UNVERIFIED`);
  }

  const exp = buildExpectations({ nodes, sender });
  if (exp.unmodeled.length > 0) {
    notes.push(`unmodeled operation(s) present (${exp.unmodeled.join(', ')}): unexpected logs unattributable; capping at UNVERIFIED`);
  }
  if (exp.unmatchable.length > 0) {
    notes.push(`expectation(s) with no established field (${exp.unmatchable.join(', ')}): unverifiable; capping at UNVERIFIED`);
  }

  const used = new Set();
  let wildcards = 0;
  const consume = (pool, want, fields, label) => {
    for (const got of pool) {
      if (used.has(got.logIndex)) continue;
      const r = fieldsMatch(want, got, fields);
      if (r.match) {
        used.add(got.logIndex);
        matches.push({ effectId: want.effectId, logIndex: got.logIndex, kind: label, wildcards: r.wildcards });
        if (r.wildcards.length > 0) {
          wildcards += 1;
          notes.push(`${want.effectId} matched log #${got.logIndex} with wildcard field(s): ${r.wildcards.join(', ')}`);
        }
        return true;
      }
    }
    missing.push({ effectId: want.effectId, kind: label, want });
    return false;
  };

  for (const w of exp.transfer) consume(parsed.transfers, w, ['contract', 'from', 'to', 'value'], 'Transfer');
  for (const w of exp.approval) consume(parsed.approvals, w, ['contract', 'owner', 'spender', 'value'], 'Approval');
  for (const w of exp.approvalForAll) consume(parsed.approvalsForAll, w, ['contract', 'owner', 'operator', 'approved'], 'ApprovalForAll');

  const unexpectedCheckDisabled = exp.unmodeled.length > 0;
  for (const pool of [parsed.transfers, parsed.approvals, parsed.approvalsForAll]) {
    for (const got of pool) {
      if (!used.has(got.logIndex)) unexpected.push({ logIndex: got.logIndex });
    }
  }

  const expectationCount = exp.transfer.length + exp.approval.length + exp.approvalForAll.length;
  let status;
  let reason = null;
  if (missing.length > 0) {
    status = 'EFFECTS_DIVERGED';
    reason = `expected log(s) missing: ${missing.map((m) => m.effectId).join(', ')}`;
  } else if (unexpected.length > 0 && !unexpectedCheckDisabled) {
    status = 'EFFECTS_DIVERGED';
    reason = `unexpected log(s) no authorized effect explains: ${unexpected.map((u) => `#${u.logIndex}`).join(', ')}`;
  } else if (unexpected.length > 0 || wildcards > 0 || exp.unmodeled.length > 0
    || exp.unmatchable.length > 0 || parsed.undecodable > 0) {
    status = 'EFFECTS_UNVERIFIED';
    reason = unexpected.length > 0
      ? `${unexpected.length} log(s) unattributable beside unmodeled operations`
      : 'matches incomplete: wildcards, unmodeled, or undecodable elements present';
  } else {
    status = 'EFFECTS_MATCHED';
    reason = expectationCount === 0
      ? 'no log-emitting effects expected or observed'
      : 'every expected log observed exactly, no extras';
  }

  return {
    status,
    reason,
    matches, missing, unexpected,
    notes,
    summary: {
      expectations: expectationCount, matched: matches.length,
      missing: missing.length, unexpected: unexpected.length, wildcards
    }
  };
}

module.exports = {
  verifyEffectsAgainstReceipt,
  parseReceiptLogs,
  buildExpectations,
  TRANSFER_TOPIC,
  APPROVAL_TOPIC,
  APPROVAL_FOR_ALL_TOPIC
};
