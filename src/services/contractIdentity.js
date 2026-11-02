/**
 * Contract identity verification (Capability 4, B5).
 *
 * A name is not an identity. This module assembles an explicit,
 * chain-aware verification ladder for the transaction target from
 * independent inputs — static maps (chain-scoped), live code reads,
 * proxy resolution (B1), operator bytecode references, a function
 * signature directory (4byte, for unknown selectors), and source
 * verification (Sourcify v2) — and reports exactly one honest status:
 *
 * - 'source-verified': Sourcify full match on this chain.
 * - 'bytecode-matched': codeHash equals an operator-supplied trusted
 *   reference for this chain+address.
 * - 'proxy-implementation-resolved': B1 resolved the proxy to a live
 *   implementation (behavior attribution established).
 * - 'static-label': chain-scoped static entry (display only).
 * - 'code-present-unverified': code exists; nothing identifies it.
 * - 'unknown': confirmed no code (EOA/empty), or no information at all.
 * - 'verification-unavailable': reads failed or were never attempted
 *   (no RPC, disabled lookups) — distinct from 'unknown'.
 *
 * External lookups carry explicit provenance, timeouts, and failure
 * states; a directory name is a HINT, never behavior proof. All
 * lookups are injectable (tests) and infallible (transport problems
 * become statuses, never throws).
 */

const fs = require('fs');
const { KNOWN_TOKENS, KNOWN_ROUTERS, normalizeMapChainId, matchKnownEntry, knownEntryChains } = require('../utils/abiSignatures');

const SELECTOR_RE = /^0x[0-9a-fA-F]{8}$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

async function fetchJson(url, { timeoutMs, fetchImpl }) {
  const ctrl = new AbortController();
  let timer;
  const timeoutP = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try { ctrl.abort(); } catch { /* best effort */ }
      const timeout = new Error(`lookup timed out after ${timeoutMs}ms`);
      timeout.code = 'LOOKUP_TIMEOUT';
      reject(timeout);
    }, timeoutMs);
  });
  try {
    const res = await Promise.race([
      fetchImpl(url, { method: 'GET', headers: { accept: 'application/json' }, signal: ctrl.signal }),
      timeoutP
    ]);
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Function-signature directory fallback for unknown selectors
 * (4byte.directory, no key). Returns the EARLIEST-submitted (min id)
 * text signature as the primary hint — canonical signatures predate
 * later collision spam — plus the collision count. A returned name is
 * a guess about the selector's text, never proof of behavior.
 */
async function lookupSelectorSignature(selector, { fetchImpl, timeoutMs = 2500, enabled = true } = {}) {
  if (enabled === false) return { status: 'disabled', textSignature: null, count: 0 };
  if (typeof selector !== 'string' || !SELECTOR_RE.test(selector)) {
    return { status: 'invalid-selector', textSignature: null, count: 0 };
  }
  const fetchFn = fetchImpl || fetch;
  try {
    const res = await fetchJson(
      `https://www.4byte.directory/api/v1/signatures/?hex_signature=${selector.toLowerCase()}`,
      { timeoutMs, fetchImpl: fetchFn }
    );
    if (!res.ok) {
      return { status: 'unavailable', textSignature: null, count: 0, error: `directory http ${res.status}` };
    }
    const body = await res.json();
    const results = body && Array.isArray(body.results) ? body.results : [];
    const count = typeof body.count === 'number' ? body.count : results.length;
    if (results.length === 0) return { status: 'not-found', textSignature: null, count: 0 };
    let best = null;
    for (const r of results) {
      if (!r || typeof r.text_signature !== 'string') continue;
      if (best === null || (typeof r.id === 'number' && typeof best.id === 'number' && r.id < best.id)) best = r;
    }
    if (!best) return { status: 'not-found', textSignature: null, count };
    return {
      status: 'found', textSignature: best.textSignature || best.text_signature, count,
      source: '4byte.directory', note: count > 1 ? `${count} colliding signatures; earliest shown, all unverified` : 'single directory entry, still unverified'
    };
  } catch (err) {
    return {
      status: 'unavailable', textSignature: null, count: 0,
      error: String((err && err.message) || err).slice(0, 160)
    };
  }
}

/**
 * Source verification via Sourcify v2 (no key):
 * GET /server/v2/contract/{chainId}/{address} → 200 with a `match`
 * field when verified, 404 when not. Only a full `match` counts as
 * source-verified; partial matches are reported as notes (metadata
 * differs), never as verification.
 */
async function lookupSourceVerification(address, chainId, { fetchImpl, timeoutMs = 2500, enabled = true } = {}) {
  if (enabled === false) return { status: 'disabled', match: null };
  const wantChain = normalizeMapChainId(chainId);
  if (typeof address !== 'string' || !ADDRESS_RE.test(address) || wantChain === null) {
    return { status: 'invalid-input', match: null };
  }
  const fetchFn = fetchImpl || fetch;
  try {
    const res = await fetchJson(
      `https://sourcify.dev/server/v2/contract/${wantChain}/${address.toLowerCase()}`,
      { timeoutMs, fetchImpl: fetchFn }
    );
    if (res.status === 404) return { status: 'none', match: null, source: 'sourcify-v2' };
    if (!res.ok) {
      return { status: 'unavailable', match: null, source: 'sourcify-v2', error: `sourcify http ${res.status}` };
    }
    const body = await res.json();
    const match = body && typeof body.match === 'string' ? body.match : null;
    if (match === 'match') {
      return { status: 'full', match: 'match', source: 'sourcify-v2', verifiedAt: body.verifiedAt || null, matchId: body.matchId || null };
    }
    if (match === 'partial') {
      return { status: 'partial', match: 'partial', source: 'sourcify-v2', note: 'partial match (metadata differs); not source verification' };
    }
    return { status: 'none', match, source: 'sourcify-v2' };
  } catch (err) {
    return {
      status: 'unavailable', match: null, source: 'sourcify-v2',
      error: String((err && err.message) || err).slice(0, 160)
    };
  }
}

/**
 * Operator-supplied bytecode references: JSON mapping chain ids to
 * address→codeHash maps, e.g. {"1":{"0xabc…":"0xhash…"}}. Absent or
 * unreadable files mean the bytecode-matched tier is skipped — never
 * a failure, always an explicit note.
 */
function loadBytecodeRefs(file) {
  if (typeof file !== 'string' || file.length === 0) return { ok: true, refs: {}, skipped: ['no bytecode-refs file configured'] };
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, refs: {}, error: 'bytecode refs file must be a JSON object' };
    }
    const refs = {};
    const skipped = [];
    for (const [chain, addrs] of Object.entries(parsed)) {
      if (!addrs || typeof addrs !== 'object' || Array.isArray(addrs)) { skipped.push(String(chain).slice(0, 16)); continue; }
      for (const [addr, hash] of Object.entries(addrs)) {
        if (typeof addr === 'string' && ADDRESS_RE.test(addr) && typeof hash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(hash)) {
          refs[String(chain)] = refs[String(chain)] || {};
          refs[String(chain)][addr.toLowerCase()] = hash.toLowerCase();
        } else {
          skipped.push(`${String(chain).slice(0, 8)}:${String(addr).slice(0, 12)}`);
        }
      }
    }
    return { ok: true, refs, skipped };
  } catch (err) {
    return { ok: false, refs: {}, error: String((err && err.message) || err).slice(0, 200) };
  }
}

/**
 * Assemble the identity record. Pure: every external input arrives as
 * an argument (chain reads, proxy evidence, lookups, refs).
 */
function resolveContractIdentity({
  address, chainId, decodedTx, chainState, proxyResolution,
  bytecodeRefs, selectorSignature, sourceVerification
} = {}) {
  const target = typeof address === 'string' && ADDRESS_RE.test(address) ? address.toLowerCase() : null;
  const wantChain = normalizeMapChainId(chainId);

  // Static label, chain-scoped, with cross-chain collision notes.
  const tokenEntry = matchKnownEntry(KNOWN_TOKENS, target || '', wantChain);
  const routerEntry = !tokenEntry ? matchKnownEntry(KNOWN_ROUTERS, target || '', wantChain) : null;
  const staticLabel = tokenEntry
    ? { label: `${tokenEntry.name} (${tokenEntry.symbol})`, kind: 'token', source: 'static' }
    : (routerEntry ? { label: routerEntry.name, kind: 'router', source: 'static' } : null);
  const otherChains = [...new Set([
    ...knownEntryChains(KNOWN_TOKENS, target || ''),
    ...knownEntryChains(KNOWN_ROUTERS, target || '')
  ])].filter((c) => c !== wantChain);

  // Code presence: chain state first, proxy target hash as fallback.
  const targetState = chainState && chainState.states && chainState.states.target;
  let codePresent = null;
  let codeHash = null;
  let codeSource = null;
  if (targetState && targetState.status === 'ok') {
    codePresent = targetState.hasCode === true;
    codeHash = targetState.codeHash || null;
    codeSource = 'chain-state';
  } else if (proxyResolution && typeof proxyResolution.targetCodeHash === 'string') {
    codePresent = true;
    codeHash = proxyResolution.targetCodeHash;
    codeSource = 'proxy-reads';
  }
  const readsFailed = (chainState && (chainState.status === 'timeout' || chainState.status === 'rpc-error'))
    || (proxyResolution && proxyResolution.status === 'unknown');

  // Proxy context from B1.
  const proxy = proxyResolution && typeof proxyResolution === 'object' ? {
    isProxy: proxyResolution.isProxy === true,
    unknown: proxyResolution.isProxy !== true && proxyResolution.isProxy !== false,
    kind: proxyResolution.kind || null,
    implementation: proxyResolution.implementation || null,
    implementationLive: Boolean(proxyResolution.implementationCode && proxyResolution.implementationCode.checked === true && proxyResolution.implementationCode.hasCode === true),
    implementationCodeHash: (proxyResolution.implementationCode && typeof proxyResolution.implementationCode.codeHash === 'string')
      ? proxyResolution.implementationCode.codeHash.toLowerCase() : null,
    status: proxyResolution.status || null
  } : { isProxy: false, unknown: true, kind: null, implementation: null, implementationLive: false, implementationCodeHash: null, status: null };

  // Bytecode reference match (target, then resolved implementation).
  let bytecodeMatch = null;
  const refs = (bytecodeRefs && bytecodeRefs.refs) || {};
  if (wantChain !== null && refs[wantChain]) {
    const bucket = refs[wantChain];
    if (codeHash && bucket[target] === codeHash.toLowerCase()) {
      bytecodeMatch = { address: target, role: 'target', codeHash: codeHash.toLowerCase() };
    } else if (proxy.implementation && proxy.implementationCodeHash
        && bucket[proxy.implementation.toLowerCase()] === proxy.implementationCodeHash) {
      bytecodeMatch = { address: proxy.implementation.toLowerCase(), role: 'proxy-implementation', codeHash: proxy.implementationCodeHash };
    }
  }

  // Status ladder, highest evidence first.
  const source = sourceVerification && typeof sourceVerification === 'object' ? sourceVerification : { status: 'unavailable' };
  let status;
  let explanation;
  if (source.status === 'full') {
    status = 'source-verified';
    explanation = `Source-verified on chain ${wantChain} via Sourcify (full match).`;
  } else if (bytecodeMatch) {
    status = 'bytecode-matched';
    explanation = `Runtime codeHash matches the operator reference for ${bytecodeMatch.role} ${bytecodeMatch.address} on chain ${wantChain}.`;
  } else if (proxy.isProxy && proxy.implementation && proxy.implementationLive) {
    status = 'proxy-implementation-resolved';
    explanation = `Proxy (${proxy.kind}) resolved to live implementation ${proxy.implementation}; behavior attribution established, implementation identity itself unverified.`;
  } else if (staticLabel) {
    status = 'static-label';
    explanation = `Known by chain-scoped static label "${staticLabel.label}" (display only — not identity proof)${codePresent === true ? '; code present' : ''}.`;
  } else if (codePresent === true) {
    status = 'code-present-unverified';
    explanation = 'Contract code is present but nothing identifies it; the contract is unverified.';
  } else if (codePresent === false) {
    status = 'unknown';
    explanation = 'No contract code at the target on the investigated chain (EOA or empty account).';
  } else if (readsFailed || !chainState || chainState.status === 'unavailable') {
    status = 'verification-unavailable';
    explanation = 'No chain reads establish code presence (RPC unavailable, failed, or disabled); identity cannot be verified.';
  } else {
    status = 'unknown';
    explanation = 'No information identifies this contract.';
  }

  const fn = decodedTx && decodedTx.functionName;
  const sig = selectorSignature && typeof selectorSignature === 'object' ? selectorSignature : null;
  return {
    target,
    chainId: wantChain,
    status,
    explanation,
    staticLabel,
    staticLabelOtherChains: otherChains,
    code: { present: codePresent, codeHash, source: codeSource },
    proxy,
    bytecodeMatch,
    bytecodeRefsNote: bytecodeRefs && bytecodeRefs.skipped && bytecodeRefs.skipped.length > 0
      ? `bytecode refs skipped: ${bytecodeRefs.skipped.slice(0, 4).join(', ')}${bytecodeRefs.skipped.length > 4 ? '…' : ''}`
      : (bytecodeRefs && bytecodeRefs.error ? `bytecode refs unusable: ${bytecodeRefs.error}` : null),
    selectorSignature: fn === 'unknownFunction' ? sig : null,
    sourceVerification: { status: source.status || 'unavailable', source: source.source || null, note: source.note || source.error || null },
    decodedFunction: typeof fn === 'string' ? fn : null,
    decodedStandard: decodedTx && typeof decodedTx.standard === 'string' ? decodedTx.standard : null
  };
}

module.exports = {
  lookupSelectorSignature,
  lookupSourceVerification,
  loadBytecodeRefs,
  resolveContractIdentity
};
