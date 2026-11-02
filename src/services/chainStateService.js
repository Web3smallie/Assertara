/**
 * Investigation-time blockchain state retrieval (Evidence Assembly).
 *
 * Reads live account state (balance, nonce, code presence + codehash) for
 * addresses under investigation, with explicit chain verification: state
 * fetched from a chain that does not match the investigated chainId is
 * DISCARDED (wrong-chain), never mixed in. Every outcome — including
 * misconfiguration, timeouts, and RPC errors — is a recorded status, so
 * callers can distinguish retrieved facts from gaps. Never throws on
 * transport/data problems; only programmer misuse (no fetch) throws.
 */

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

function normalizeChainId(v) {
  try {
    if (typeof v === 'string' && v.startsWith('0x')) return BigInt(v).toString(10);
    return BigInt(v).toString(10);
  } catch {
    return null;
  }
}

async function rpcBatch(rpcUrl, calls, { timeoutMs, fetchImpl }) {
  const ctrl = new AbortController();
  // Explicit race (not abort-only): a transport that ignores the abort
  // signal must still lose the race instead of hanging the investigation.
  let timer;
  const timeoutP = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try { ctrl.abort(); } catch { /* best effort */ }
      const timeout = new Error(`chain RPC timed out after ${timeoutMs}ms`);
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
      if (!row || row.error) {
        const err = new Error((row && row.error && row.error.message) || 'rpc error');
        err.code = 'RPC_ERROR';
        throw err;
      }
      return row.result;
    });
  } catch (err) {
    if (err && err.name === 'AbortError') {
      const timeout = new Error(`chain RPC timed out after ${timeoutMs}ms`);
      timeout.code = 'RPC_TIMEOUT';
      throw timeout;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @param {object} args
 * @param {string|null} args.rpcUrl Chain RPC endpoint (null → unavailable).
 * @param {string|number|null} args.chainId Expected chain id (null → chain unverified but recorded).
 * @param {Array<{role:string,address:string}>} args.addresses Addresses to read.
 * @param {number} [args.timeoutMs] Default 8000.
 * @param {string} [args.blockTag] Default 'latest'.
 * @param {Function} [args.fetchImpl] Injectable fetch (tests).
 */
async function fetchChainState({ rpcUrl, chainId, addresses, timeoutMs, blockTag, fetchImpl }) {
  const fetchedAt = Date.now();
  const at = timeoutMs || 8000;
  const tag = blockTag || 'latest';
  const fetchFn = fetchImpl || fetch;
  if (!rpcUrl || typeof rpcUrl !== 'string') {
    return { status: 'unavailable', error: 'no chain RPC configured for this investigation', fetchedAt };
  }
  let host = null;
  try {
    host = new URL(rpcUrl).host;
  } catch {
    return { status: 'unavailable', error: 'chain RPC URL is malformed', fetchedAt };
  }
  const roles = (Array.isArray(addresses) ? addresses : [])
    .filter((a) => a && typeof a.address === 'string' && ADDRESS_RE.test(a.address))
    .slice(0, 8)
    .map((a) => ({ role: String(a.role || 'address').slice(0, 32), address: a.address.toLowerCase() }));
  try {
    const [rpcChainHex, blockNumber] = await rpcBatch(rpcUrl, [
      { method: 'eth_chainId', params: [] },
      { method: 'eth_blockNumber', params: [] }
    ], { timeoutMs: at, fetchImpl: fetchFn });
    const rpcChainId = normalizeChainId(rpcChainHex);
    const wantChainId = chainId === undefined || chainId === null || chainId === '' ? null : normalizeChainId(chainId);
    if (wantChainId !== null && rpcChainId !== wantChainId) {
      return {
        status: 'wrong-chain', rpcHost: host, rpcChainId,
        expectedChainId: wantChainId,
        error: `RPC serves chain ${rpcChainId}, investigation targets ${wantChainId}; state discarded`,
        fetchedAt
      };
    }
    const calls = [];
    for (const r of roles) {
      calls.push({ method: 'eth_getBalance', params: [r.address, tag], _role: r.role, _field: 'balance' });
      calls.push({ method: 'eth_getTransactionCount', params: [r.address, tag], _role: r.role, _field: 'nonce' });
      calls.push({ method: 'eth_getCode', params: [r.address, tag], _role: r.role, _field: 'code' });
    }
    const results = calls.length > 0
      ? await rpcBatch(rpcUrl, calls, { timeoutMs: at, fetchImpl: fetchFn })
      : [];
    const { keccak256 } = require('viem');
    const states = {};
    roles.forEach((r, i) => {
      const balance = results[i * 3];
      const nonce = results[i * 3 + 1];
      const code = results[i * 3 + 2];
      let balanceWei = null;
      let nonceDec = null;
      try {
        balanceWei = BigInt(balance).toString(10);
        nonceDec = BigInt(nonce).toString(10);
      } catch {
        states[r.role] = { address: r.address, status: 'rpc-error', error: 'non-numeric balance/nonce' };
        return;
      }
      const hasCode = typeof code === 'string' && code !== '0x' && code.length > 2;
      states[r.role] = {
        address: r.address, status: 'ok', balanceWei, nonce: nonceDec,
        hasCode, codeHash: hasCode ? keccak256(code) : null
      };
    });
    // Capability 4 B6: block timestamp for deadline/expiry reasoning.
    // Best-effort read: a failed timestamp degrades to an explicit
    // unavailable block — never to a failed chain state.
    let block = { status: 'unavailable', number: blockNumber, timestamp: null, timestampHex: null };
    try {
      const [header] = await rpcBatch(rpcUrl, [{ method: 'eth_getBlockByNumber', params: [tag, false] }], { timeoutMs: at, fetchImpl: fetchFn });
      const ts = header && typeof header.timestamp === 'string' ? header.timestamp : null;
      if (ts !== null) {
        block = { status: 'ok', number: (header && header.number) || blockNumber, timestamp: normalizeChainId(ts), timestampHex: ts };
      }
    } catch {
      block = { status: 'unavailable', number: blockNumber, timestamp: null, timestampHex: null };
    }
    return {
      status: 'ok', rpcHost: host, rpcChainId,
      chainVerified: wantChainId !== null,
      blockNumber, blockTag: tag, block, states, fetchedAt
    };
  } catch (err) {
    const code = (err && err.code) || 'RPC_ERROR';
    return {
      status: code === 'RPC_TIMEOUT' ? 'timeout' : 'rpc-error',
      rpcHost: host, error: String((err && err.message) || err).slice(0, 300),
      fetchedAt
    };
  }
}

module.exports = { fetchChainState, normalizeChainId };
