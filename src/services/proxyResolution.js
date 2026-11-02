/**
 * Proxy contract detection and resolution (Capability 4, B1).
 *
 * A transaction target may be a proxy whose behavior is determined by a
 * separate implementation contract. Decoding the proxy's calldata against
 * a static ABI — or trusting a label on the proxy address — can
 * misidentify what will actually execute. This module resolves the
 * proxy-to-implementation relationship from verified chain data:
 *
 * - EIP-1167 minimal proxies: implementation embedded in the 45-byte
 *   runtime bytecode (pure pattern match, no storage read needed).
 * - ERC-1967 direct proxies: implementation address in the standard
 *   storage slot, read via eth_getStorageAt.
 * - ERC-1967 beacon proxies: beacon address in the standard slot, with
 *   the implementation read from the beacon's `implementation()` view.
 *
 * The ERC-1967 admin slot is read opportunistically as context only: an
 * admin pointer alone never classifies a contract as a proxy.
 *
 * Outcomes: `resolved` (proxy + implementation known), `not-proxy`
 * (no proxy pointers), `proxy-unresolved` (proxy confirmed but the
 * implementation is unknown or dangling — conservative handling), and
 * `unknown` (reads failed; reported, never moves a verdict — the same
 * unavailable-never-moves convention as chain verification). Only
 * `proxy-unresolved` sets `downgrade`/`hold`.
 */

const ERC1967_IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3a505ea5742c2be';
const ERC1967_BEACON_SLOT = '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb43d4b1a5b654';
const ERC1967_ADMIN_SLOT = '0xb53127684a568b3173ae13b250acee66067e322793a09a44f1313f5e7f8b3a8';

// Canonical EIP-1167 runtime bytecode: prefix + 20-byte implementation +
// suffix, exactly 45 bytes. PUSH0-style variants are not matched: an
// unrecognized pattern stays a non-minimal-proxy, never a guessed address.
const EIP1167_PREFIX = '363d3d373d3d3d363d73';
const EIP1167_SUFFIX = '5af43d82803e903d91602b57fd5bf3';
const EIP1167_CODE_LEN = 2 + EIP1167_PREFIX.length + 40 + EIP1167_SUFFIX.length;

// Beacon `implementation()` selector.
const BEACON_IMPLEMENTATION_CALLDATA = '0x5c60da1b';

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const WORD_RE = /^0x[0-9a-fA-F]{64}$/;

/**
 * Extract an address from a 32-byte storage word. Returns the lowercase
 * address, or null when the word is zero, malformed, or has nonzero
 * padding (a non-address value in an address slot is data corruption or
 * a different encoding — never silently truncated into an address).
 */
function parseStorageAddress(word) {
  if (typeof word !== 'string' || !WORD_RE.test(word)) return null;
  const padding = word.slice(2, 26);
  const body = word.slice(26);
  if (!/^0+$/.test(padding)) return null;
  if (/^0+$/.test(body)) return null;
  return `0x${body}`.toLowerCase();
}

/**
 * Match canonical EIP-1167 minimal-proxy runtime code.
 * @returns {{isMinimalProxy:boolean, implementation:string|null}}
 */
function detectMinimalProxy(code) {
  if (typeof code !== 'string' || code.length !== EIP1167_CODE_LEN || !code.startsWith('0x')) {
    return { isMinimalProxy: false, implementation: null };
  }
  const body = code.slice(2).toLowerCase();
  if (!body.startsWith(EIP1167_PREFIX) || !body.endsWith(EIP1167_SUFFIX)) {
    return { isMinimalProxy: false, implementation: null };
  }
  return { isMinimalProxy: true, implementation: `0x${body.slice(EIP1167_PREFIX.length, EIP1167_PREFIX.length + 40)}` };
}

function codeHashOf(code) {
  try {
    if (typeof code !== 'string' || code === '0x' || code.length <= 2) return null;
    const { keccak256 } = require('viem');
    return keccak256(code);
  } catch {
    return null;
  }
}

function unresolvedHold(explanation) {
  return {
    downgrade: true,
    hold: {
      source: 'proxy-resolution',
      reason: explanation
    }
  };
}

/**
 * Pure resolution orchestration over injected readers (tests inject fakes;
 * production passes RPC-backed readers via fetchProxyEvidence).
 *
 * @param {object} args
 * @param {string} args.address Investigated target (any case).
 * @param {string|null} args.code Runtime bytecode hex of the target.
 * @param {Function} args.readStorage async (address, slot) -> 32-byte word hex.
 * @param {Function} [args.readCode] async (address) -> bytecode hex.
 * @param {Function} [args.callView] async (address, calldata) -> return word hex.
 * @param {string|number|null} [args.chainId] Chain context for the record.
 * @param {string|null} [args.blockNumber] Block context for the record.
 */
async function resolveProxy({ address, code, readStorage, readCode, callView, chainId, blockNumber }) {
  const target = typeof address === 'string' ? address.toLowerCase() : null;
  const base = {
    target,
    chainId: chainId === undefined || chainId === null ? null : String(chainId),
    blockNumber: typeof blockNumber === 'string' ? blockNumber : null,
    isProxy: null,
    kind: null,
    implementation: null,
    implementationCode: null,
    beacon: null,
    admin: null,
    targetCodeHash: codeHashOf(code),
    reads: [],
    downgrade: false,
    hold: null,
    status: 'unknown',
    explanation: ''
  };
  const read = async (slot) => {
    try {
      const word = await readStorage(target, slot);
      base.reads.push({ slot, status: 'ok' });
      return word;
    } catch (err) {
      base.reads.push({ slot, status: 'failed', error: String((err && err.message) || err).slice(0, 160) });
      return undefined;
    }
  };
  const checkImplCode = async (impl) => {
    if (typeof readCode !== 'function') return { checked: false, hasCode: null, codeHash: null };
    try {
      const implCode = await readCode(impl);
      const hasCode = typeof implCode === 'string' && implCode !== '0x' && implCode.length > 2;
      return { checked: true, hasCode, codeHash: codeHashOf(implCode) };
    } catch (err) {
      base.reads.push({ slot: `code:${impl}`, status: 'failed', error: String((err && err.message) || err).slice(0, 160) });
      return { checked: false, hasCode: null, codeHash: null };
    }
  };

  if (typeof code !== 'string' || code === '0x' || code.length <= 2) {
    return {
      ...base,
      isProxy: false,
      status: 'not-proxy',
      explanation: 'No contract code at the target (EOA or empty account); there is no proxy to resolve.'
    };
  }

  // EIP-1167: the pointer is in the bytecode itself.
  const minimal = detectMinimalProxy(code);
  if (minimal.isMinimalProxy) {
    const implCheck = await checkImplCode(minimal.implementation);
    if (implCheck.checked && implCheck.hasCode === false) {
      return {
        ...base,
        isProxy: true,
        kind: 'EIP-1167',
        implementation: minimal.implementation,
        implementationCode: implCheck,
        status: 'proxy-unresolved',
        explanation: `Target is an EIP-1167 minimal proxy pointing at ${minimal.implementation}, which has no code (dangling pointer); on-chain behavior is unknown.`,
        ...unresolvedHold(`EIP-1167 proxy at ${target} points at codeless implementation ${minimal.implementation}; behavior unknown.`)
      };
    }
    return {
      ...base,
      isProxy: true,
      kind: 'EIP-1167',
      implementation: minimal.implementation,
      implementationCode: implCheck,
      status: 'resolved',
      explanation: `Target is an EIP-1167 minimal proxy for implementation ${minimal.implementation}${implCheck.checked ? (implCheck.hasCode ? ' (code present)' : '') : ' (implementation code not checked)'}. Behavior is determined by the implementation, not the proxy address.`
    };
  }

  // ERC-1967 direct implementation slot.
  const implWord = await read(ERC1967_IMPL_SLOT);
  if (implWord === undefined) {
    return { ...base, status: 'unknown', explanation: 'Implementation-slot read failed; proxy status cannot be established from available data.' };
  }
  const implAddr = parseStorageAddress(implWord);
  if (implAddr) {
    const implCheck = await checkImplCode(implAddr);
    if (implCheck.checked && implCheck.hasCode === false) {
      return {
        ...base,
        isProxy: true,
        kind: 'ERC-1967',
        implementation: implAddr,
        implementationCode: implCheck,
        status: 'proxy-unresolved',
        explanation: `Target is an ERC-1967 proxy pointing at ${implAddr}, which has no code (dangling pointer); on-chain behavior is unknown.`,
        ...unresolvedHold(`ERC-1967 proxy at ${target} points at codeless implementation ${implAddr}; behavior unknown.`)
      };
    }
    return {
      ...base,
      isProxy: true,
      kind: 'ERC-1967',
      implementation: implAddr,
      implementationCode: implCheck,
      status: 'resolved',
      explanation: `Target is an ERC-1967 proxy for implementation ${implAddr}${implCheck.checked ? (implCheck.hasCode ? ' (code present)' : '') : ' (implementation code not checked)'}. Behavior is determined by the implementation, not the proxy address.`
    };
  }

  // ERC-1967 beacon slot.
  const beaconWord = await read(ERC1967_BEACON_SLOT);
  if (beaconWord === undefined) {
    return { ...base, status: 'unknown', explanation: 'Beacon-slot read failed after an empty implementation slot; proxy status cannot be established from available data.' };
  }
  const beaconAddr = parseStorageAddress(beaconWord);
  if (beaconAddr) {
    let implFromBeacon = null;
    if (typeof callView === 'function') {
      try {
        const ret = await callView(beaconAddr, BEACON_IMPLEMENTATION_CALLDATA);
        base.reads.push({ slot: `call:${beaconAddr}.implementation()`, status: 'ok' });
        implFromBeacon = parseStorageAddress(ret);
      } catch (err) {
        base.reads.push({ slot: `call:${beaconAddr}.implementation()`, status: 'failed', error: String((err && err.message) || err).slice(0, 160) });
      }
    }
    if (!implFromBeacon) {
      return {
        ...base,
        isProxy: true,
        kind: 'ERC-1967-beacon',
        beacon: beaconAddr,
        status: 'proxy-unresolved',
        explanation: `Target is an ERC-1967 beacon proxy (beacon ${beaconAddr}) but the beacon's implementation could not be read; on-chain behavior is unknown.`,
        ...unresolvedHold(`Beacon proxy at ${target} (beacon ${beaconAddr}) has an unreadable implementation; behavior unknown.`)
      };
    }
    const implCheck = await checkImplCode(implFromBeacon);
    if (implCheck.checked && implCheck.hasCode === false) {
      return {
        ...base,
        isProxy: true,
        kind: 'ERC-1967-beacon',
        beacon: beaconAddr,
        implementation: implFromBeacon,
        implementationCode: implCheck,
        status: 'proxy-unresolved',
        explanation: `Target is an ERC-1967 beacon proxy whose implementation ${implFromBeacon} has no code (dangling pointer); on-chain behavior is unknown.`,
        ...unresolvedHold(`Beacon proxy at ${target} resolves to codeless implementation ${implFromBeacon}; behavior unknown.`)
      };
    }
    return {
      ...base,
      isProxy: true,
      kind: 'ERC-1967-beacon',
      beacon: beaconAddr,
      implementation: implFromBeacon,
      implementationCode: implCheck,
      status: 'resolved',
      explanation: `Target is an ERC-1967 beacon proxy (beacon ${beaconAddr}) for implementation ${implFromBeacon}. Behavior is determined by the implementation, not the proxy address.`
    };
  }

  // Admin slot is context only: it never classifies a proxy by itself.
  const adminWord = await read(ERC1967_ADMIN_SLOT);
  if (adminWord !== undefined) {
    const adminAddr = parseStorageAddress(adminWord);
    if (adminAddr) base.admin = adminAddr;
  }
  return {
    ...base,
    isProxy: false,
    status: 'not-proxy',
    explanation: base.admin
      ? `No ERC-1967 implementation/beacon pointer and no EIP-1167 pattern (admin slot set to ${base.admin}, which alone does not make a proxy); target treated as a direct contract.`
      : 'No ERC-1967 implementation/beacon pointer and no EIP-1167 pattern; target treated as a direct contract.'
  };
}

async function rpcCall(rpcUrl, calls, { timeoutMs, fetchImpl }) {
  const ctrl = new AbortController();
  let timer;
  const timeoutP = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try { ctrl.abort(); } catch { /* best effort */ }
      const timeout = new Error(`proxy RPC timed out after ${timeoutMs}ms`);
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
      const err = new Error(`rpc http ${res.status}`);
      err.code = 'RPC_HTTP';
      throw err;
    }
    const body = await res.json();
    const list = Array.isArray(body) ? body : [body];
    return calls.map((c, i) => {
      const row = list.find((r) => r && r.id === i + 1);
      if (!row || row.error || !Object.prototype.hasOwnProperty.call(row, 'result')) {
        const err = new Error((row && row.error && row.error.message) || 'rpc error');
        err.code = 'RPC_ERROR';
        throw err;
      }
      return row.result;
    });
  } catch (err) {
    if (err && err.name === 'AbortError') {
      const timeout = new Error(`proxy RPC timed out after ${timeoutMs}ms`);
      timeout.code = 'RPC_TIMEOUT';
      throw timeout;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function normalizeChainId(v) {
  try {
    if (typeof v === 'string' && v.startsWith('0x')) return BigInt(v).toString(10);
    return BigInt(v).toString(10);
  } catch {
    return null;
  }
}

/**
 * RPC-backed proxy evidence for a transaction target. Infallible on
 * transport problems (they become explicit statuses); only programmer
 * misuse (bad address with an RPC configured) throws.
 */
async function fetchProxyEvidence({ rpcUrl, chainId, address, blockTag, timeoutMs, fetchImpl }) {
  const fetchedAt = Date.now();
  const at = timeoutMs || 8000;
  const tag = blockTag || 'latest';
  const fetchFn = fetchImpl || fetch;
  const target = typeof address === 'string' ? address.toLowerCase() : null;
  if (!target || !ADDRESS_RE.test(target)) {
    throw new TypeError('fetchProxyEvidence: address must be a 0x hex address');
  }
  if (!rpcUrl || typeof rpcUrl !== 'string') {
    return {
      target, chainId: chainId === undefined || chainId === null ? null : String(chainId),
      blockNumber: null, isProxy: null, kind: null, implementation: null,
      implementationCode: null, beacon: null, admin: null, targetCodeHash: null,
      reads: [], downgrade: false, hold: null, status: 'unavailable',
      explanation: 'No chain RPC configured; proxy status unknown (not checked).',
      fetchedAt
    };
  }
  try {
    const [rpcChainHex, blockNumber, code] = await rpcCall(rpcUrl, [
      { method: 'eth_chainId', params: [] },
      { method: 'eth_blockNumber', params: [] },
      { method: 'eth_getCode', params: [target, tag] }
    ], { timeoutMs: at, fetchImpl: fetchFn });
    const rpcChainId = normalizeChainId(rpcChainHex);
    const wantChainId = chainId === undefined || chainId === null || chainId === '' ? null : normalizeChainId(chainId);
    if (wantChainId !== null && rpcChainId !== wantChainId) {
      return {
        target, chainId: wantChainId, blockNumber: null, isProxy: null, kind: null,
        implementation: null, implementationCode: null, beacon: null, admin: null,
        targetCodeHash: null, reads: [], downgrade: false, hold: null,
        status: 'wrong-chain',
        explanation: `RPC serves chain ${rpcChainId}, investigation targets ${wantChainId}; proxy evidence discarded.`,
        fetchedAt
      };
    }
    const single = async (method, params) => {
      const [result] = await rpcCall(rpcUrl, [{ method, params }], { timeoutMs: at, fetchImpl: fetchFn });
      return result;
    };
    const resolved = await resolveProxy({
      address: target,
      code,
      readStorage: (addr, slot) => single('eth_getStorageAt', [addr, slot, tag]),
      readCode: (addr) => single('eth_getCode', [addr, tag]),
      callView: (addr, data) => single('eth_call', [{ to: addr, data }, tag]),
      chainId: wantChainId !== null ? wantChainId : rpcChainId,
      blockNumber: typeof blockNumber === 'string' ? blockNumber : null
    });
    return { ...resolved, fetchedAt };
  } catch (err) {
    return {
      target, chainId: chainId === undefined || chainId === null ? null : String(chainId),
      blockNumber: null, isProxy: null, kind: null, implementation: null,
      implementationCode: null, beacon: null, admin: null, targetCodeHash: null,
      reads: [], downgrade: false, hold: null, status: 'unknown',
      explanation: `Proxy reads failed (${String((err && err.message) || err).slice(0, 200)}); proxy status unknown.`,
      fetchedAt
    };
  }
}

module.exports = {
  ERC1967_IMPL_SLOT,
  ERC1967_BEACON_SLOT,
  ERC1967_ADMIN_SLOT,
  BEACON_IMPLEMENTATION_CALLDATA,
  parseStorageAddress,
  detectMinimalProxy,
  resolveProxy,
  fetchProxyEvidence
};
