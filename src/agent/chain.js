/**
 * Assertara read-only chain readers. All RPC access goes through an injectable
 * client so logic is unit-testable with stubs; production passes a live viem
 * client (or rpcUrl). Pure computation (exposure, diffs) is fully deterministic.
 * Never signs, sends, or simulates state-changing transactions.
 */

const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
// NOTE: viem's getLogs has NO raw `topics` parameter — unknown props are
// silently dropped (verified live: topics arrived as []). Filters must be
// expressed as event+args so viem encodes the wire topics itself.
const APPROVAL_EVENT = {
  type: 'event',
  name: 'Approval',
  inputs: [
    { name: 'owner', type: 'address', indexed: true },
    { name: 'spender', type: 'address', indexed: true },
    { name: 'value', type: 'uint256', indexed: false }
  ]
};
const ALLOWANCE_ABI = [
  {
    type: 'function', name: 'allowance', stateMutability: 'view',
    inputs: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }]
  }
];
const DEFAULT_LOOKBACK_BLOCKS = 20000n;
const DEFAULT_MAX_LOGS = 500;

function buildClient(rpcUrl) {
  const { createPublicClient, http } = require('viem');
  const config = require('../config/env');
  return createPublicClient({ transport: http(rpcUrl || config.ethereumRpcUrl) });
}

function padTopicAddress(address) {
  return `0x000000000000000000000000${address.slice(2).toLowerCase()}`;
}

function topicToAddress(topic) {
  return `0x${topic.slice(-40)}`;
}

/**
 * Fetch ERC20 Approval events for an owner, then read current allowances.
 * @returns { approvals: [{ token, spender, allowance, txHash, blockNumber }], truncated, fromBlock, toBlock }
 */
async function fetchApprovals({ owner, client, rpcUrl, fromBlock, toBlock, maxLogs }) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(owner || '')) throw new Error('fetchApprovals: owner must be a 0x address');
  const c = client || buildClient(rpcUrl);
  const tip = await c.getBlockNumber();
  const to = toBlock !== undefined ? toBlock : 'latest';
  const from = fromBlock !== undefined ? fromBlock : (tip > DEFAULT_LOOKBACK_BLOCKS ? tip - DEFAULT_LOOKBACK_BLOCKS : 0n);
  const logs = await c.getLogs({ event: APPROVAL_EVENT, args: { owner }, fromBlock: from, toBlock: to });
  const sliced = logs.slice(0, maxLogs || DEFAULT_MAX_LOGS);
  // Latest event per (token, spender) wins; then read live allowances.
  const latest = new Map();
  for (const log of sliced) {
    latest.set(`${log.address.toLowerCase()}:${topicToAddress(log.topics[2]).toLowerCase()}`, log);
  }
  const approvals = [];
  for (const log of latest.values()) {
    const token = log.address;
    const spender = topicToAddress(log.topics[2]);
    let allowance = null;
    try {
      allowance = await c.readContract({ address: token, abi: ALLOWANCE_ABI, functionName: 'allowance', args: [owner, spender] });
    } catch {
      allowance = null; // Token may not implement allowance; report honestly.
    }
    approvals.push({
      token, spender,
      allowance: allowance === null ? null : allowance.toString(),
      txHash: log.transactionHash || null,
      blockNumber: log.blockNumber !== undefined && log.blockNumber !== null ? log.blockNumber.toString() : null
    });
  }
  return { approvals, truncated: logs.length > sliced.length, fromBlock: from.toString(), toBlock: to.toString(), tip: tip.toString() };
}

/**
 * Pure exposure computation over fetched approvals. No network.
 */
function computeExposure(approvals, { unlimitedThreshold } = {}) {
  const threshold = BigInt(unlimitedThreshold !== undefined ? unlimitedThreshold : (1n << 255n).toString());
  const list = Array.isArray(approvals) ? approvals : [];
  let unlimited = 0;
  let unreadable = 0;
  const bySpender = {};
  for (const a of list) {
    const key = `${(a.token || '').toLowerCase()}:${(a.spender || '').toLowerCase()}`;
    if (a.allowance === null || a.allowance === undefined) {
      unreadable += 1;
      bySpender[key] = { token: a.token, spender: a.spender, allowance: null, unlimited: false, readable: false };
      continue;
    }
    const isUnlimited = BigInt(a.allowance) >= threshold;
    if (isUnlimited) unlimited += 1;
    bySpender[key] = { token: a.token, spender: a.spender, allowance: String(a.allowance), unlimited: isUnlimited, readable: true };
  }
  return {
    approvalCount: list.length,
    unlimitedCount: unlimited,
    unreadableCount: unreadable,
    threshold: threshold.toString(),
    bySpender
  };
}

/**
 * Read-only contract metadata (bytecode + EIP-1967 slots) with injectable client.
 */
async function readContractMeta({ address, client, rpcUrl }) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address || '')) throw new Error('readContractMeta: address must be a 0x address');
  const c = client || buildClient(rpcUrl);
  const [bytecode, implSlot, adminSlot] = await Promise.all([
    c.getBytecode({ address }),
    c.getStorageAt({ address, slot: '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc' }),
    c.getStorageAt({ address, slot: '0xb53127684a568b3173ae13b250a82a706b1f155a31b16e3cb5684d5a18009d15' })
  ]);
  const slotToAddress = (slot) => (!slot || /^0x0+$/.test(slot) ? null : `0x${slot.slice(-40)}`);
  return {
    address,
    hasCode: Boolean(bytecode && bytecode !== '0x'),
    bytecodeLength: bytecode ? (bytecode.length - 2) / 2 : 0,
    eip1967Implementation: slotToAddress(implSlot),
    eip1967Admin: slotToAddress(adminSlot)
  };
}

/**
 * Pure watch diff between two contract_meta snapshots. No network.
 */
function diffWatch(baseline, current) {
  if (!baseline || !current) throw new Error('diffWatch requires baseline and current snapshots');
  const changes = [];
  for (const field of ['hasCode', 'bytecodeLength', 'eip1967Implementation', 'eip1967Admin']) {
    if (JSON.stringify(baseline[field]) !== JSON.stringify(current[field])) {
      changes.push({ field, before: baseline[field] === undefined ? null : baseline[field], after: current[field] === undefined ? null : current[field] });
    }
  }
  return { changed: changes.length > 0, changes };
}

// ---------------------------------------------------------------------------
// Bounded historical discovery (F6 foundation). Address-scoped, chunked log
// queries with explicit coverage metadata. fetchApprovals above is preserved
// unchanged as the legacy topic-search path for unrestricted providers.
// ---------------------------------------------------------------------------

const COVERAGE_STATUSES = [
  'COMPLETE_WITHIN_REQUESTED_SCOPE', 'PARTIAL_COVERAGE', 'HISTORY_UNAVAILABLE'
];
const FAILURE_REASONS = ['QUERY_REJECTED', 'QUERY_FAILED'];

// Curated mainnet ERC20 registry for address-scoped discovery. Public
// constants, versioned; anything outside this list is out of scope unless the
// caller supplies explicit tokens. Scope is always reported, never implied.
const KNOWN_TOKEN_LIST_VERSION = 'mainnet-major-v1';
const KNOWN_TOKENS = [
  '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
  '0xdAC17F958D2ee523a2206206994597C13D831ec7', // USDT
  '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', // WETH
  '0x6B175474E89094C44Da98b954EedeAC495271d0F', // DAI
  '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599', // WBTC
  '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984'  // UNI
];

const DEFAULT_CHUNK_BLOCKS = 500;
const DEFAULT_MAX_CALLS = 100;
const DEFAULT_PER_CHUNK_CAP = 2000;

function chainError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function isAddress(value) {
  return /^0x[0-9a-fA-F]{40}$/.test(String(value || '').trim());
}

function redactEndpoint(rpcUrl) {
  if (!rpcUrl) return 'default-config';
  try {
    return new URL(rpcUrl).host || 'unparseable-endpoint';
  } catch {
    return 'unparseable-endpoint';
  }
}

function defaultSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Classify an RPC/client failure per the contracts §7 retry policy.
 * Retryable: HTTP 429 / 5xx / timeouts / network failures / RPC -32005.
 * Everything else (restrictions, params, unknown shapes) fails closed.
 */
function classifyRpcError(err) {
  const status = err && (err.status ?? err.statusCode ?? err.cause?.status ?? err.cause?.statusCode);
  const code = err && (err.code ?? err.cause?.code);
  const message = String((err && (err.shortMessage || err.message)) || '');
  const headers = (err && (err.headers || err.cause?.headers)) || {};
  const getHeader = (name) => {
    if (typeof headers.get === 'function') return headers.get(name);
    return headers[name] ?? headers[name.toLowerCase()];
  };
  let retryAfterMs;
  const retryAfterRaw = getHeader('retry-after');
  if (retryAfterRaw !== undefined && retryAfterRaw !== null && retryAfterRaw !== '') {
    const secs = Number(retryAfterRaw);
    if (Number.isFinite(secs) && secs >= 0) retryAfterMs = Math.min(secs * 1000, 10000);
  }
  if (status === 429 || code === -32005 || /rate.?limit|too many requests|exceeds.*limit/i.test(message)) {
    return { retryable: true, kind: 'rate-limit', httpStatus: status ?? null, rpcCode: code ?? null, retryAfterMs };
  }
  if (status !== undefined && status !== null && Number(status) >= 500) {
    return { retryable: true, kind: 'server', httpStatus: Number(status), rpcCode: code ?? null, retryAfterMs };
  }
  if (/timeout|timed out|etimedout|econnreset|econnrefused|fetch failed|network|socket hang up/i.test(message)) {
    return { retryable: true, kind: 'network', httpStatus: status ?? null, rpcCode: code ?? null, retryAfterMs };
  }
  if (code === -32701 || /specify an address|address.*required/i.test(message)) {
    return { retryable: false, kind: 'restriction', reason: 'QUERY_REJECTED', httpStatus: status ?? null, rpcCode: code ?? null };
  }
  if (code === -32602 || /archive|personal token|invalid params|block range/i.test(message)) {
    return { retryable: false, kind: 'restriction', reason: 'QUERY_REJECTED', httpStatus: status ?? null, rpcCode: code ?? null };
  }
  if (typeof status === 'number' && status >= 400 && status < 500) {
    return { retryable: false, kind: 'client', reason: 'QUERY_REJECTED', httpStatus: status, rpcCode: code ?? null };
  }
  return { retryable: false, kind: 'unknown', reason: 'QUERY_FAILED', httpStatus: status ?? null, rpcCode: code ?? null };
}

/**
 * Retry-once wrapper honoring contracts §7: one retry for eligible
 * transient failures (Retry-After capped 10s, else 500ms), then throw.
 */
async function withRetryOnce(fn, { sleep = defaultSleep } = {}) {
  try {
    return await fn();
  } catch (err) {
    const c = classifyRpcError(err);
    if (!c.retryable) throw err;
    await sleep(c.retryAfterMs !== undefined ? c.retryAfterMs : 500);
    return await fn();
  }
}

function toBlockBigInt(value, name) {
  if (typeof value === 'bigint') {
    if (value < 0n) throw chainError('BAD_BLOCK_RANGE', `${name} must be a non-negative integer`);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) throw chainError('BAD_BLOCK_RANGE', `${name} must be a non-negative integer`);
    return BigInt(value);
  }
  if (typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value)) return BigInt(value);
  throw chainError('BAD_BLOCK_RANGE', `${name} must be a block number, hex, or 'latest'`);
}

/**
 * Bounded, address-scoped Approval discovery with coverage metadata.
 * Never represents a partial scope as complete history.
 */
async function discoverApprovals(input) {
  const {
    owner, tokens, chainId = 1, client, rpcUrl,
    fromBlock, toBlock = 'latest',
    chunkBlocks = DEFAULT_CHUNK_BLOCKS, maxLogs = DEFAULT_MAX_LOGS,
    maxCalls = DEFAULT_MAX_CALLS, perChunkCap = DEFAULT_PER_CHUNK_CAP,
    sleep = defaultSleep
  } = input || {};
  if (!isAddress(owner)) throw chainError('BAD_ADDRESS', 'discoverApprovals: owner must be a 0x address');
  if (!Number.isInteger(chainId) || chainId < 1) throw chainError('BAD_CHAIN', 'discoverApprovals: chainId must be a positive integer');
  let tokenList = tokens;
  let tokenSource = 'caller-supplied';
  if (tokenList === undefined) {
    if (chainId !== 1) throw chainError('CHAIN_REGISTRY_UNAVAILABLE', `no token registry for chain ${chainId}; supply explicit tokens`);
    tokenList = KNOWN_TOKENS;
    tokenSource = `registry:${KNOWN_TOKEN_LIST_VERSION}`;
  }
  if (!Array.isArray(tokenList) || tokenList.length === 0) throw chainError('BAD_TOKENS', 'discoverApprovals: tokens must be a non-empty array');
  if (tokenList.length > 25) throw chainError('BAD_TOKENS', 'discoverApprovals: at most 25 tokens per request');
  for (const t of tokenList) {
    if (!isAddress(t)) throw chainError('BAD_ADDRESS', `discoverApprovals: invalid token address ${t}`);
  }
  if (!Number.isInteger(chunkBlocks) || chunkBlocks < 1 || chunkBlocks > 10000) {
    throw chainError('BAD_CHUNKING', 'discoverApprovals: chunkBlocks must be 1-10000');
  }
  if (!Number.isInteger(maxLogs) || maxLogs < 1) throw chainError('BAD_LIMITS', 'discoverApprovals: maxLogs must be >= 1');
  if (!Number.isInteger(maxCalls) || maxCalls < 1) throw chainError('BAD_LIMITS', 'discoverApprovals: maxCalls must be >= 1');
  // Block-bound shapes fail fast before any network use ('latest' allowed).
  for (const [bound, name] of [[fromBlock, 'fromBlock'], [toBlock, 'toBlock']]) {
    if (bound !== undefined && bound !== 'latest') toBlockBigInt(bound, name);
  }
  if (fromBlock !== undefined && fromBlock !== 'latest' && toBlock !== 'latest'
    && toBlockBigInt(fromBlock, 'fromBlock') > toBlockBigInt(toBlock, 'toBlock')) {
    throw chainError('BAD_BLOCK_RANGE', 'discoverApprovals: fromBlock must not exceed toBlock');
  }

  const c = client || buildClient(rpcUrl);
  const endpoint = client ? 'injected-client' : redactEndpoint(rpcUrl || require('../config/env').ethereumRpcUrl);
  const retrievedAt = new Date().toISOString();

  if (typeof c.getChainId === 'function') {
    const providerChain = Number(await withRetryOnce(() => c.getChainId(), { sleep }));
    if (providerChain !== chainId) {
      throw chainError('CHAIN_MISMATCH', `provider chain ${providerChain} does not match requested chain ${chainId}`);
    }
  }
  const tip = BigInt(await withRetryOnce(() => c.getBlockNumber(), { sleep }));
  const to = toBlock === 'latest' ? tip : toBlockBigInt(toBlock, 'toBlock');
  const from = fromBlock === undefined
    ? (tip > DEFAULT_LOOKBACK_BLOCKS ? tip - DEFAULT_LOOKBACK_BLOCKS : 0n)
    : fromBlock === 'latest' ? tip : toBlockBigInt(fromBlock, 'fromBlock');
  if (from > to) throw chainError('BAD_BLOCK_RANGE', 'discoverApprovals: fromBlock must not exceed toBlock');

  const chunks = [];
  for (let start = from; start <= to; start += BigInt(chunkBlocks)) {
    const end = start + BigInt(chunkBlocks) - 1n > to ? to : start + BigInt(chunkBlocks) - 1n;
    chunks.push({ fromBlock: start, toBlock: end });
  }

  const events = new Map(); // `${txHash}:${logIndex}` -> event (dedup across chunks)
  const gaps = [];
  const errors = [];
  const limitations = [
    `token-scope: ${tokenSource} (${tokenList.length} tokens)`,
    'topic-search without address scope is rejected by restricted providers; discovery is address-scoped only'
  ];
  let calls = 0;
  let cappedByMaxLogs = false;
  let chunksOk = 0;
  let foreignLogsFiltered = 0;
  const requestedCalls = chunks.length * tokenList.length;
  const ownerPad = padTopicAddress(owner);

  for (const chunk of chunks) {
    for (const token of tokenList) {
      if (calls >= maxCalls) {
        gaps.push({ fromBlock: chunk.fromBlock.toString(), toBlock: chunk.toBlock.toString(), token, reason: 'max-calls-cap' });
        continue;
      }
      calls += 1;
      let logs;
      try {
        logs = await withRetryOnce(() => c.getLogs({
          address: token,
          event: APPROVAL_EVENT,
          args: { owner },
          fromBlock: chunk.fromBlock,
          toBlock: chunk.toBlock
        }), { sleep });
      } catch (err) {
        const classified = classifyRpcError(err);
        gaps.push({
          fromBlock: chunk.fromBlock.toString(), toBlock: chunk.toBlock.toString(), token,
          reason: classified.reason || 'QUERY_FAILED', kind: classified.kind,
          httpStatus: classified.httpStatus ?? null, rpcCode: classified.rpcCode ?? null
        });
        errors.push(`chunk ${chunk.fromBlock}-${chunk.toBlock} ${token}: ${String(err.shortMessage || err.message).slice(0, 300)}`);
        continue;
      }
      chunksOk += 1;
      const list = Array.isArray(logs) ? logs : [];
      const capped = list.slice(0, perChunkCap);
      if (list.length > capped.length) {
        gaps.push({ fromBlock: chunk.fromBlock.toString(), toBlock: chunk.toBlock.toString(), token, reason: 'chunk-truncated', dropped: list.length - capped.length });
      }
      for (const log of capped) {
        if (events.size >= maxLogs) { cappedByMaxLogs = true; break; }
        // Defense in depth: never trust provider-side filtering (a silently
        // dropped topics arg once flooded us with foreign logs). Foreign
        // logs are counted here, never ingested as the owner's history.
        const topicsOk = Array.isArray(log.topics) && log.topics.length >= 3
          && String(log.topics[0]).toLowerCase() === APPROVAL_TOPIC.toLowerCase()
          && String(log.topics[1]).toLowerCase() === ownerPad;
        const addrOk = String(log.address || '').toLowerCase() === token.toLowerCase();
        if (!topicsOk || !addrOk) { foreignLogsFiltered += 1; continue; }
        const txHash = log.transactionHash || null;
        const logIndex = log.logIndex !== undefined && log.logIndex !== null ? log.logIndex.toString() : null;
        const key = `${txHash}:${logIndex}`;
        if (events.has(key)) continue;
        events.set(key, {
          chainId,
          token: log.address,
          spender: topicToAddress(log.topics[2]),
          txHash,
          blockNumber: log.blockNumber !== undefined && log.blockNumber !== null ? log.blockNumber.toString() : null,
          logIndex,
          source: 'rpc-logs',
          retrievedAt
        });
      }
      if (cappedByMaxLogs) break;
    }
    if (cappedByMaxLogs) break;
  }
  if (cappedByMaxLogs) {
    gaps.push({ reason: 'max-logs-cap', kept: events.size, limit: maxLogs });
  }

  // Latest event per (token, spender) wins; then read live allowances.
  const latest = new Map();
  for (const e of events.values()) {
    latest.set(`${String(e.token).toLowerCase()}:${String(e.spender).toLowerCase()}`, e);
  }
  const approvals = [];
  for (const e of latest.values()) {
    let allowance = null;
    try {
      allowance = await withRetryOnce(
        () => c.readContract({ address: e.token, abi: ALLOWANCE_ABI, functionName: 'allowance', args: [owner, e.spender] }),
        { sleep }
      );
    } catch {
      allowance = null; // Token may not implement allowance; report honestly.
    }
    approvals.push({ ...e, allowance: allowance === null ? null : allowance.toString() });
  }

  const requestedScope = {
    chainId, owner,
    tokens: tokenList.map((t) => t.toLowerCase()),
    tokenSource,
    fromBlock: from.toString(),
    toBlock: to.toString()
  };
  let status;
  if (gaps.length === 0 && errors.length === 0) status = 'COMPLETE_WITHIN_REQUESTED_SCOPE';
  else if (chunksOk === 0) status = 'HISTORY_UNAVAILABLE';
  else status = 'PARTIAL_COVERAGE';
  return {
    approvals,
    truncated: cappedByMaxLogs || events.size >= maxLogs,
    coverage: {
      status,
      requestedScope,
      retrievedScope: {
        fromBlock: from.toString(),
        toBlock: to.toString(),
        chunksOk,
        chunksRequested: requestedCalls,
        callsMade: calls,
        eventsKept: events.size,
        foreignLogsFiltered
      },
      gaps,
      provider: { endpoint, chainId, tip: tip.toString() },
      limitations,
      errors: errors.slice(0, 20)
    }
  };
}

module.exports = {
  fetchApprovals, computeExposure, readContractMeta, diffWatch,
  discoverApprovals, classifyRpcError, withRetryOnce,
  APPROVAL_TOPIC, APPROVAL_EVENT, DEFAULT_LOOKBACK_BLOCKS, DEFAULT_MAX_LOGS,
  KNOWN_TOKENS, KNOWN_TOKEN_LIST_VERSION, COVERAGE_STATUSES
};
