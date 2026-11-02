/**
 * Deterministic chain-to-transaction verification (Capability 3, B3).
 * Independently checks decoded transaction expectations against live
 * chain state and freshness. Pure: no RPC here — the controller supplies
 * already-fetched chainState/freshness.
 *
 * Outcome policy (documented, conservative):
 * - `fail` results downgrade MATCH to UNCERTAIN (safeguard) and hold
 *   for REVIEW (policy verificationHolds). They NEVER hard-BLOCK:
 *   balance/nonce/code readings carry staleness and pending-block
 *   caveats, so measurement-based checks hold rather than prohibit.
 * - `inconclusive` / `unavailable` are informational only (bundle +
 *   prompt), never outcome-moving. Missing state must not silently
 *   approve, but it must not veto either.
 */

function asBigInt(value) {
  try {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return BigInt(value);
    if (typeof value === 'string' && value.trim() !== '') return BigInt(value.trim());
  } catch { /* fall through */ }
  return null;
}

function checkBalance({ decodedTx, chainState }) {
  const base = { checkId: 'BALANCE_SUFFICIENCY', refs: ['chain', 'param:value'] };
  const states = (chainState && chainState.status === 'ok' && chainState.states) || null;
  const sender = states && states.sender && states.sender.status === 'ok' ? states.sender : null;
  if (!sender) return { ...base, status: 'unavailable', explanation: 'sender chain state unavailable; sufficiency unchecked' };
  const required = asBigInt(decodedTx && decodedTx.valueWei);
  if (required === null) return { ...base, status: 'inconclusive', explanation: 'transaction value not numeric; sufficiency unchecked' };
  if (required === 0n) return { ...base, status: 'pass', explanation: 'no native value required' };
  const balance = asBigInt(sender.balanceWei);
  if (balance === null) return { ...base, status: 'unavailable', explanation: 'sender balance unreadable' };
  if (balance < required) {
    return { ...base, status: 'fail', explanation: `insufficient funds: balance ${balance} wei < required ${required} wei (gas excluded)` };
  }
  return { ...base, status: 'pass', explanation: `balance ${balance} wei covers value ${required} wei (gas excluded)` };
}

function checkNonce({ transaction, chainState }) {
  const base = { checkId: 'NONCE_CONSISTENCY', refs: ['chain'] };
  const raw = transaction ? transaction.nonce : undefined;
  if (raw === undefined || raw === null) {
    return { ...base, status: 'inconclusive', explanation: 'proposal carries no nonce; signer auto-assigns at broadcast' };
  }
  const states = (chainState && chainState.status === 'ok' && chainState.states) || null;
  const sender = states && states.sender && states.sender.status === 'ok' ? states.sender : null;
  if (!sender) return { ...base, status: 'unavailable', explanation: 'sender chain state unavailable; nonce unchecked' };
  const proposed = asBigInt(raw);
  const live = asBigInt(sender.nonce);
  if (proposed === null || live === null) return { ...base, status: 'unavailable', explanation: 'nonce unreadable on one side' };
  if (proposed < live) return { ...base, status: 'fail', explanation: `stale proposal nonce ${proposed} < chain nonce ${live}` };
  if (proposed === live) return { ...base, status: 'pass', explanation: `proposal nonce ${proposed} matches chain nonce` };
  return { ...base, status: 'inconclusive', explanation: `proposal nonce ${proposed} ahead of chain nonce ${live} (possibly queued future)` };
}

function checkCodeCall({ decodedTx, chainState }) {
  const base = { checkId: 'CODE_CALL_CONSISTENCY', refs: ['chain', 'tx'] };
  const fn = decodedTx && decodedTx.functionName;
  if (fn === 'unknownFunction' || (decodedTx && decodedTx.standard === 'Unknown')) {
    return { ...base, status: 'inconclusive', explanation: 'undecoded function; call type unclassifiable' };
  }
  const states = (chainState && chainState.status === 'ok' && chainState.states) || null;
  const target = states && states.target && states.target.status === 'ok' ? states.target : null;
  if (!target) return { ...base, status: 'unavailable', explanation: 'target chain state unavailable; code unchecked' };
  const isNative = fn === 'nativeTransfer' || (decodedTx && decodedTx.standard === 'Native');
  if (!isNative && target.hasCode !== true) {
    return { ...base, status: 'fail', explanation: `contract call '${fn}' targets ${target.address} with no code present` };
  }
  if (isNative && target.hasCode === true) {
    return { ...base, status: 'inconclusive', explanation: 'native transfer to a contract address (payable entrypoint possible)' };
  }
  return { ...base, status: 'pass', explanation: isNative ? 'native transfer to an address with no code' : `contract call to ${target.address} with code present` };
}

function checkChainIdentity({ transaction, chainState }) {
  const base = { checkId: 'CHAIN_IDENTITY', refs: ['chain'] };
  if (!chainState || typeof chainState !== 'object') return { ...base, status: 'unavailable', explanation: 'no chain-state record' };
  if (chainState.status === 'wrong-chain') {
    return { ...base, status: 'fail', explanation: `chain mismatch: rpc chain ${chainState.rpcChainId}, state discarded` };
  }
  if (chainState.status !== 'ok') return { ...base, status: 'unavailable', explanation: `chain state ${chainState.status}; identity unverified` };
  if (chainState.chainVerified === true) return { ...base, status: 'pass', explanation: `rpc chain ${chainState.rpcChainId} verified` };
  void transaction;
  return { ...base, status: 'inconclusive', explanation: 'chain read succeeded without identity verification' };
}

function checkFreshness({ freshness, visualMeta }) {
  const base = { checkId: 'FRESHNESS_CORROBORATION', refs: ['freshness', 'ocr'] };
  const shot = freshness && freshness.screenshot;
  if (!shot || typeof shot !== 'object') {
    return { ...base, status: 'pass', explanation: 'no screenshot evidence to gate (agent path or uncaptured)' };
  }
  const texts = visualMeta && Array.isArray(visualMeta.regionTexts) ? visualMeta.regionTexts : [];
  const usableOcr = texts.filter((r) => r && typeof r.text === 'string' && r.text.length > 0 && !r.ocrError).length;
  const detected = Number.isInteger(visualMeta.detectedCount) ? visualMeta.detectedCount : texts.length;
  if (shot.status === 'stale' && usableOcr === 0) {
    return { ...base, status: 'fail', explanation: 'stale screenshot with no usable corroborating OCR; visuals cannot support conclusions' };
  }
  if (shot.status === 'stale') {
    return { ...base, status: 'inconclusive', explanation: `stale screenshot with ${usableOcr} corroborating OCR read(s); treat with suspicion` };
  }
  if (shot.status === 'invalid' && detected > 0) {
    return { ...base, status: 'fail', explanation: 'unverifiable capture timestamp with visual claims present' };
  }
  return { ...base, status: 'pass', explanation: `screenshot ${shot.status || 'unknown'}; no freshness bar to conclusions` };
}

function verifyChainEvidence({ transaction, decodedTx, chainState, freshness, visualMeta }) {
  const checks = [
    checkChainIdentity({ transaction, chainState }),
    checkBalance({ decodedTx, chainState }),
    checkNonce({ transaction, chainState }),
    checkCodeCall({ decodedTx, chainState }),
    checkFreshness({ freshness, visualMeta })
  ];
  const failures = checks.filter((c) => c.status === 'fail');
  return { checks, failures };
}

module.exports = { verifyChainEvidence };
