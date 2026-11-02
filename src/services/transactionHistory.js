/**
 * Transaction history and sequence reasoning (Capability 4, B8).
 *
 * A transaction can only be understood in sequence: an approval is
 * harmless in isolation, but a later transferFrom through it moves
 * funds. This module assembles a BOUNDED, provenance-labeled sequence
 * context for the investigated sender from three sources:
 *
 * 1. Chain event logs (eth_getLogs): Approval / Transfer /
 *    ApprovalForAll events involving the sender inside a bounded
 *    block window. Verified chain data, ordered by (block, logIndex).
 * 2. Prior local investigations: tail-read of the investigation JSONL
 *    for same-sender, same-chain records (records persisted with the
 *    B8 sender envelope; older records carry no sender and are
 *    skipped, never guessed at).
 * 3. Admitted agent prior-results: agent-submitted history, always
 *    UNTRUSTED, included for the model with provenance intact.
 *
 * Sequence relationships (APPROVAL_THEN_SPEND, REPEATED_INTERACTION,
 * SAME_COUNTERPARTY, PRIOR_INVESTIGATION) are deterministic
 * observations, not accusations: absence from a bounded window proves
 * nothing, so missing approvals are noted, never flagged. The
 * APPROVAL_THEN_SPEND finding is informational (no policy action);
 * its job is to put the enabling approval in front of the model.
 *
 * Deliberately NOT integrated: the spending ledger (no sender
 * attribution; owned by the agent execution layer, unreachable from
 * the investigation layer without wrong-direction coupling).
 */

const fs = require('fs');

const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3ff';
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL_FOR_ALL_TOPIC = '0x17307eab39ab6107e8899845ad3d59bd9653f133f97a6bdaea955636b505bde2';

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const DEFAULT_BLOCK_WINDOW = 2000;
const DEFAULT_MAX_ENTRIES = 8;
const DEFAULT_LOG_CAP = 120;
const DEFAULT_PRIOR_BYTES = 262144;

function padAddress(addr) {
  return `0x${'0'.repeat(24)}${addr.slice(2).toLowerCase()}`;
}

function topicAddress(topic) {
  if (typeof topic !== 'string' || topic.length < 42) return null;
  const body = topic.slice(-40);
  if (!/^[0-9a-fA-F]{40}$/.test(body)) return null;
  return `0x${body}`.toLowerCase();
}

function hexToDec(hex) {
  try {
    if (typeof hex !== 'string' || !hex.startsWith('0x')) return null;
    return BigInt(hex).toString(10);
  } catch {
    return null;
  }
}

function parseLog(log) {
  if (!log || typeof log !== 'object') return null;
  const topics = Array.isArray(log.topics) ? log.topics : [];
  const topic0 = typeof topics[0] === 'string' ? topics[0].toLowerCase() : null;
  const token = typeof log.address === 'string' && ADDRESS_RE.test(log.address) ? log.address.toLowerCase() : null;
  if (!token || !topic0) return null;
  const blockNumber = typeof log.blockNumber === 'string' ? log.blockNumber : null;
  const logIndex = typeof log.logIndex === 'string' ? log.logIndex : null;
  const txHash = typeof log.transactionHash === 'string' ? log.transactionHash : null;
  const base = { token, blockNumber, logIndex, txHash };
  if (topic0 === APPROVAL_TOPIC) {
    if (topics.length >= 4) {
      return { ...base, event: 'Approval', owner: topicAddress(topics[1]), spender: topicAddress(topics[2]), tokenId: hexToDec(topics[3]), amount: null, nft: true };
    }
    return { ...base, event: 'Approval', owner: topicAddress(topics[1]), spender: topicAddress(topics[2]), amount: hexToDec(log.data), tokenId: null, nft: false };
  }
  if (topic0 === TRANSFER_TOPIC) {
    if (topics.length >= 4) {
      return { ...base, event: 'Transfer', from: topicAddress(topics[1]), to: topicAddress(topics[2]), tokenId: hexToDec(topics[3]), amount: null, nft: true };
    }
    return { ...base, event: 'Transfer', from: topicAddress(topics[1]), to: topicAddress(topics[2]), amount: hexToDec(log.data), tokenId: null, nft: false };
  }
  if (topic0 === APPROVAL_FOR_ALL_TOPIC) {
    let approved = null;
    try {
      approved = typeof log.data === 'string' ? BigInt(log.data) === 1n : null;
    } catch {
      approved = null;
    }
    return { ...base, event: 'ApprovalForAll', owner: topicAddress(topics[1]), operator: topicAddress(topics[2]), approved, amount: null, nft: true };
  }
  return null;
}

async function rpcBatch(rpcUrl, calls, { timeoutMs, fetchImpl }) {
  const ctrl = new AbortController();
  let timer;
  const timeoutP = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try { ctrl.abort(); } catch { /* best effort */ }
      const timeout = new Error(`history logs timed out after ${timeoutMs}ms`);
      timeout.code = 'RPC_TIMEOUT';
      reject(timeout);
    }, timeoutMs);
  });
  try {
    const res = await Promise.race([
      fetchImpl(rpcUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(calls.map((c, i) => ({ jsonrpc: '2.0', id: i + 1, method: c.method, params: c.params }))),
        signal: ctrl.signal
      }),
      timeoutP
    ]);
    if (!res.ok) {
      const err = new Error(`history rpc http ${res.status}`);
      err.code = 'RPC_HTTP';
      throw err;
    }
    const body = await res.json();
    const list = Array.isArray(body) ? body : [body];
    return calls.map((c, i) => {
      const row = list.find((r) => r && r.id === i + 1);
      if (!row || row.error || !Object.prototype.hasOwnProperty.call(row, 'result')) {
        const err = new Error((row && row.error && row.error.message) || 'history rpc error');
        err.code = 'RPC_ERROR';
        throw err;
      }
      return row.result;
    });
  } catch (err) {
    if (err && err.name === 'AbortError') {
      const timeout = new Error(`history logs timed out after ${timeoutMs}ms`);
      timeout.code = 'RPC_TIMEOUT';
      throw timeout;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch sender-involving token events in [fromBlock, toBlock].
 * Infallible on transport problems (they become statuses).
 */
async function fetchSenderEvents({ rpcUrl, sender, fromBlock, toBlock, timeoutMs = 8000, fetchImpl, logCap = DEFAULT_LOG_CAP } = {}) {
  if (!rpcUrl || typeof rpcUrl !== 'string') {
    return { status: 'unavailable', events: [], truncated: 0, note: 'no chain RPC configured' };
  }
  if (typeof sender !== 'string' || !ADDRESS_RE.test(sender)) {
    return { status: 'no-sender', events: [], truncated: 0, note: 'sender unknown; history is sender-keyed' };
  }
  const fetchFn = fetchImpl || fetch;
  const padded = padAddress(sender);
  const range = { fromBlock, toBlock };
  const queries = [
    { topics: [APPROVAL_TOPIC, padded] },
    { topics: [APPROVAL_TOPIC, null, padded] },
    { topics: [TRANSFER_TOPIC, padded] },
    { topics: [TRANSFER_TOPIC, null, padded] },
    { topics: [APPROVAL_FOR_ALL_TOPIC, padded] },
    { topics: [APPROVAL_FOR_ALL_TOPIC, null, padded] }
  ];
  try {
    const batches = await rpcBatch(rpcUrl,
      queries.map((q) => ({ method: 'eth_getLogs', params: [{ ...range, topics: q.topics }] })),
      { timeoutMs, fetchImpl: fetchFn });
    const seen = new Set();
    const events = [];
    for (const list of batches) {
      for (const log of Array.isArray(list) ? list : []) {
        const parsed = parseLog(log);
        if (!parsed) continue;
        const key = `${parsed.txHash || ''}:${parsed.logIndex || ''}:${parsed.token}:${parsed.event}`;
        if (seen.has(key)) continue;
        seen.add(key);
        events.push(parsed);
      }
    }
    events.sort((a, b) => {
      const bn = (x) => { try { return BigInt(x.blockNumber || 0); } catch { return 0n; } };
      const li = (x) => { try { return BigInt(x.logIndex || 0); } catch { return 0n; } };
      if (bn(a) !== bn(b)) return bn(a) < bn(b) ? -1 : 1;
      if (li(a) !== li(b)) return li(a) < li(b) ? -1 : 1;
      return 0;
    });
    const truncated = Math.max(0, events.length - logCap);
    return { status: 'ok', events: events.slice(0, logCap), truncated, fromBlock, toBlock, note: null };
  } catch (err) {
    return {
      status: 'unavailable', events: [], truncated: 0,
      note: `event logs failed (${String((err && err.message) || err).slice(0, 160)})`
    };
  }
}

/**
 * Tail-read the investigation JSONL for same-sender, same-chain prior
 * records (B8 envelope: top-level sender/chainId). Bounded bytes,
 * newest first, corrupt lines counted.
 */
function readPriorInvestigations({ file, sender, chainId, maxBytes = DEFAULT_PRIOR_BYTES, limit = 8 } = {}) {
  if (!file || typeof file !== 'string') return { status: 'unavailable', priors: [], note: 'no investigation file configured' };
  if (typeof sender !== 'string' || !ADDRESS_RE.test(sender)) {
    return { status: 'no-sender', priors: [], note: 'sender unknown; priors are sender-keyed' };
  }
  try {
    if (!fs.existsSync(file)) return { status: 'empty', priors: [], note: 'no local investigations yet' };
    const stat = fs.statSync(file);
    const start = Math.max(0, stat.size - maxBytes);
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(stat.size - start);
      fs.readSync(fd, buf, 0, buf.length, start);
      const lines = buf.toString('utf8').split('\n');
      // First line may be a truncated fragment when tail-reading.
      if (start > 0) lines.shift();
      const wantChain = chainId === undefined || chainId === null ? null : String(chainId);
      const priors = [];
      let skipped = 0;
      for (const line of lines) {
        if (line.trim().length === 0) continue;
        let r;
        try {
          r = JSON.parse(line);
        } catch {
          skipped += 1;
          continue;
        }
        if (!r || typeof r !== 'object') { skipped += 1; continue; }
        if (typeof r.sender !== 'string' || r.sender.toLowerCase() !== sender.toLowerCase()) continue;
        if (wantChain !== null && r.chainId !== undefined && r.chainId !== null && String(r.chainId) !== wantChain) continue;
        priors.push(r);
      }
      priors.sort((a, b) => (b.recordedAt || 0) - (a.recordedAt || 0));
      return { status: 'ok', priors: priors.slice(0, limit), skipped, note: null };
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    return { status: 'unavailable', priors: [], note: `prior investigations unreadable (${String((err && err.message) || err).slice(0, 160)})` };
  }
}

function eventSummary(e) {
  if (e.event === 'Approval') {
    return e.nft
      ? `Approval NFT tokenId=${e.tokenId} owner=${e.owner} spender=${e.spender} @${e.blockNumber}`
      : `Approval amount=${e.amount} owner=${e.owner} spender=${e.spender} @${e.blockNumber}`;
  }
  if (e.event === 'Transfer') {
    return e.nft
      ? `Transfer NFT tokenId=${e.tokenId} ${e.from}->${e.to} @${e.blockNumber}`
      : `Transfer amount=${e.amount} ${e.from}->${e.to} @${e.blockNumber}`;
  }
  return `ApprovalForAll owner=${e.owner} operator=${e.operator} approved=${e.approved === true} @${e.blockNumber}`;
}

/**
 * Assemble the bounded sequence context: stable H-xxx entries plus
 * deterministic relationships to the CURRENT investigation.
 */
function buildSequenceContext({ decodedTx, sender, chainId, senderEvents, priors, admittedPriors, maxEntries = DEFAULT_MAX_ENTRIES } = {}) {
  const entries = [];
  const relationships = [];
  const findings = [];
  let seq = 0;
  const hid = () => { seq += 1; return `H-${String(seq).padStart(3, '0')}`; };

  const events = (senderEvents && Array.isArray(senderEvents.events)) ? senderEvents.events : [];
  for (const e of events) {
    entries.push({
      historyId: hid(), kind: 'chain-event', provenance: 'chain-logs',
      blockNumber: e.blockNumber, txHash: e.txHash, token: e.token,
      summary: `${e.event} on ${e.token}: ${eventSummary(e)}`,
      event: e.event, detail: e
    });
  }
  const priorList = (priors && Array.isArray(priors.priors)) ? priors.priors : [];
  for (const p of priorList) {
    const dt = (p && p.decodedTransaction) || {};
    entries.push({
      historyId: hid(), kind: 'prior-investigation', provenance: 'local-investigations',
      recordId: p.recordId || null, recordedAt: p.recordedAt || null,
      summary: `prior ${dt.functionName || '?'} on ${dt.contract || '?'} → ${p.verdict || '?'} (${p.recordId || 'no-id'})`,
      verdict: p.verdict || null, functionName: dt.functionName || null, to: dt.contract || null
    });
  }
  const agentPriors = Array.isArray(admittedPriors) ? admittedPriors : [];
  for (const a of agentPriors) {
    entries.push({
      historyId: hid(), kind: 'agent-prior', provenance: 'agent-submitted',
      trust: 'UNTRUSTED',
      summary: `agent prior-result [${a.evidenceId || '?'}]: ${String(a.content || '').slice(0, 200)}`,
      evidenceId: a.evidenceId || null
    });
  }

  const truncated = Math.max(0, entries.length - maxEntries);
  const kept = entries.slice(0, maxEntries);
  const keptIds = new Set(kept.map((e) => e.historyId));

  // Relationships to the current transaction.
  const fn = decodedTx && decodedTx.functionName;
  const params = (decodedTx && decodedTx.parameters) || {};
  const to = decodedTx && typeof decodedTx.contract === 'string' ? decodedTx.contract.toLowerCase() : null;
  const from = typeof sender === 'string' ? sender.toLowerCase() : null;

  // APPROVAL_THEN_SPEND: current transferFrom(sender=S, owner=O) with a
  // prior Approval(owner=O, spender=S) in-window. The enabling approval
  // is what makes the current spend possible.
  if (fn === 'transferFrom' && from) {
    const owner = typeof params.sender === 'string' ? params.sender.toLowerCase() : null;
    if (owner) {
      const enabling = kept.find((e) => e.kind === 'chain-event' && e.detail && e.detail.event === 'Approval'
        && e.detail.owner === owner && e.detail.spender === from
        && (to === null || !e.token || e.token === to));
      if (enabling) {
        relationships.push({
          type: 'APPROVAL_THEN_SPEND', entryIds: [enabling.historyId],
          explanation: `Current transferFrom spends ${owner}'s tokens via spender ${from}; ${enabling.historyId} records the enabling on-chain Approval (token ${enabling.token}).`
        });
        findings.push({
          ruleId: 'APPROVAL_THEN_SPEND',
          severity: 'LOW',
          description: `Current transferFrom executes through a prior on-chain Approval (${enabling.historyId}, token ${enabling.token}, amount ${enabling.detail.amount}); evaluate the spend against the approval's scope, not in isolation.`,
          triggered: true,
          metadata: { historyId: enabling.historyId, token: enabling.token, owner, spender: from, amount: enabling.detail.amount }
        });
      }
    }
  }

  // REPEATED_INTERACTION: same target + same function in kept history.
  if (to && typeof fn === 'string') {
    const repeats = kept.filter((e) => e.kind === 'prior-investigation' && e.to === to && e.functionName === fn);
    if (repeats.length > 0) {
      relationships.push({
        type: 'REPEATED_INTERACTION',
        entryIds: repeats.map((e) => e.historyId),
        explanation: `Same target + function (${fn} on ${to}) investigated ${repeats.length} time(s) before in local history.`
      });
    }
  }

  // SAME_COUNTERPARTY: same target, different operation.
  if (to) {
    const same = kept.filter((e) => ((e.kind === 'prior-investigation' && e.to === to && e.functionName !== fn)
      || (e.kind === 'chain-event' && e.token === to)));
    if (same.length > 0) {
      relationships.push({
        type: 'SAME_COUNTERPARTY',
        entryIds: same.map((e) => e.historyId).slice(0, 4),
        explanation: `Target ${to} appears in ${same.length} prior histor${same.length === 1 ? 'y entry' : 'y entries'} (different operations).`
      });
    }
  }

  return {
    entries: kept,
    entryCount: kept.length,
    truncated,
    droppedIds: entries.filter((e) => !keptIds.has(e.historyId)).map((e) => e.historyId),
    relationships,
    findings,
    sender: from,
    chainId: chainId === undefined || chainId === null ? null : String(chainId),
    sources: {
      chainEvents: senderEvents ? senderEvents.status || null : null,
      chainEventsNote: senderEvents ? senderEvents.note || null : null,
      chainTruncated: senderEvents ? senderEvents.truncated || 0 : 0,
      priors: priors ? priors.status || null : null,
      priorsNote: priors ? priors.note || null : null,
      priorsSkipped: priors ? priors.skipped || 0 : 0,
      agentPriors: agentPriors.length
    }
  };
}

module.exports = {
  APPROVAL_TOPIC,
  TRANSFER_TOPIC,
  APPROVAL_FOR_ALL_TOPIC,
  DEFAULT_BLOCK_WINDOW,
  DEFAULT_MAX_ENTRIES,
  DEFAULT_LOG_CAP,
  fetchSenderEvents,
  readPriorInvestigations,
  buildSequenceContext
};
