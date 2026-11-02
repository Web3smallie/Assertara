/**
 * Deadline and expiry reasoning (Capability 4, B6).
 *
 * Time-sensitive parameters (swap deadlines, permit deadlines,
 * Permit2 expirations) decide whether the operation can still execute:
 * an expired operation reverts on-chain, so a UI presenting it as live
 * — or an agent believing it acted — is working from a false picture.
 * This module interprets those parameters against the investigated
 * block's timestamp with explicit, falsifiable outcomes:
 *
 * - valid / near-expiry / expired / missing / unassessable, per call.
 * - EXPIRED_OPERATION and MISSING_DEADLINE findings (MEDIUM) for the
 *   two states that must hold review and downgrade MATCH verdicts.
 *
 * Honesty boundaries:
 * - Only explicitly deadline-bearing (standard, function) pairs are
 *   interpreted. Uniswap V3 exactInputSingle carries NO deadline by
 *   design — its absence is not "missing". No timestamp sniffing.
 * - A 300s grace absorbs miner-timestamp skew before anything counts
 *   as expired; near-expiry (15 min) is informational only.
 * - Without a block timestamp the outcome is unassessable — never a
 *   finding, never a downgrade (unavailable-never-moves).
 * - Freshness (when evidence was captured) is a different question
 *   from expiry (whether the operation is still live); the two are
 *   never conflated here.
 */

const EXPIRED_GRACE_SECONDS = 300n;
const NEAR_EXPIRY_SECONDS = 900n;

// Explicit deadline-bearing operations: standard → function → param.
// Anything not listed here is not interpreted as time-sensitive.
const DEADLINE_FIELDS = {
  UniswapV2Router: {
    swapExactTokensForTokens: 'deadline',
    swapTokensForExactTokens: 'deadline',
    swapExactETHForTokens: 'deadline'
  },
  ERC20: {
    permit: 'deadline'
  },
  Permit2: {
    approve: 'expiration',
    permit: 'expiration'
  }
};

function parseUint(v) {
  try {
    if (typeof v === 'bigint') return v < 0n ? null : v;
    if (typeof v === 'string' && /^\d+$/.test(v.trim())) return BigInt(v.trim());
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
    return null;
  } catch {
    return null;
  }
}

function assessOne({ label, standard, functionName, parameters, blockTime, provenance }) {
  const field = (DEADLINE_FIELDS[standard] || {})[functionName] || null;
  const base = { label, standard, functionName, field, provenance: provenance || null };
  if (!field) {
    return { check: null, finding: null, state: { ...base, outcome: 'not-applicable', note: 'operation carries no deadline parameter by design' } };
  }
  const raw = parameters ? parameters[field] : undefined;
  const deadline = parseUint(raw);
  if (deadline === null) {
    return {
      check: {
        checkId: 'DEADLINE_PRESENT', status: 'fail',
        explanation: `${label}: expected ${field} is missing or unparseable; expiry cannot be assessed.`
      },
      finding: {
        ruleId: 'MISSING_DEADLINE',
        severity: 'MEDIUM',
        description: `${label} is a time-sensitive operation but carries no parseable ${field}; whether it can still execute is unestablished.`,
        triggered: true,
        metadata: { label, standard, functionName, field, subcall: provenance && provenance.subcallId ? { subcallId: provenance.subcallId, path: provenance.path } : null }
      },
      state: { ...base, outcome: 'missing' }
    };
  }
  if (blockTime === null) {
    return {
      check: {
        checkId: 'DEADLINE_VALID', status: 'unavailable',
        explanation: `${label}: ${field} ${deadline} decoded, but no block timestamp anchors the comparison.`
      },
      finding: null,
      state: { ...base, outcome: 'unassessable', deadline: deadline.toString() }
    };
  }
  if (deadline + EXPIRED_GRACE_SECONDS < blockTime) {
    return {
      check: {
        checkId: 'DEADLINE_VALID', status: 'fail',
        explanation: `${label}: ${field} ${deadline} is more than ${EXPIRED_GRACE_SECONDS}s before block time ${blockTime}; the operation reverts if submitted.`
      },
      finding: {
        ruleId: 'EXPIRED_OPERATION',
        severity: 'MEDIUM',
        description: `${label} expired at ${field} ${deadline} (block time ${blockTime}, ${EXPIRED_GRACE_SECONDS}s grace applied); submitting it reverts on-chain.`,
        triggered: true,
        metadata: { label, standard, functionName, field, deadline: deadline.toString(), blockTime: blockTime.toString(), subcall: provenance && provenance.subcallId ? { subcallId: provenance.subcallId, path: provenance.path } : null }
      },
      state: { ...base, outcome: 'expired', deadline: deadline.toString(), blockTime: blockTime.toString() }
    };
  }
  const near = deadline <= blockTime + NEAR_EXPIRY_SECONDS;
  return {
    check: {
      checkId: 'DEADLINE_VALID', status: 'pass',
      explanation: near
        ? `${label}: ${field} ${deadline} is valid but within ${NEAR_EXPIRY_SECONDS}s of block time ${blockTime} (near expiry).`
        : `${label}: ${field} ${deadline} is after block time ${blockTime}.`
    },
    finding: null,
    state: { ...base, outcome: near ? 'near-expiry' : 'valid', deadline: deadline.toString(), blockTime: blockTime.toString() }
  };
}

/**
 * Analyze top-level + nested deadline-bearing operations. Pure:
 * blockTime arrives as an argument (decimal string/bigint) with its
 * provenance recorded, never fetched here.
 */
function analyzeDeadlines({ decodedTx, subcalls, blockTimestamp, blockNumber, chainId } = {}) {
  const blockTime = blockTimestamp === undefined || blockTimestamp === null ? null : parseUint(blockTimestamp);
  const checks = [];
  const findings = [];
  const states = [];
  const params = (decodedTx && decodedTx.parameters) || {};
  const top = assessOne({
    label: 'top-level call',
    standard: decodedTx && decodedTx.standard,
    functionName: decodedTx && decodedTx.functionName,
    parameters: params,
    blockTime,
    provenance: null
  });
  if (top.check) checks.push(top.check);
  if (top.finding) findings.push(top.finding);
  states.push(top.state);

  const inners = Array.isArray(subcalls) ? subcalls : [];
  for (const sc of inners) {
    if (!sc || sc.container === true || sc.unknown === true || sc.depthLimited === true) continue;
    const field = (DEADLINE_FIELDS[sc.standard] || {})[sc.functionName] || null;
    if (!field) continue;
    const r = assessOne({
      label: `nested call ${sc.subcallId}`,
      standard: sc.standard,
      functionName: sc.functionName,
      parameters: sc.parameters || {},
      blockTime,
      provenance: { subcallId: sc.subcallId, path: sc.path }
    });
    if (r.check) checks.push({ ...r.check, checkId: `${r.check.checkId}_INNER` });
    if (r.finding) {
      findings.push({
        ...r.finding,
        description: `[nested ${sc.subcallId} ${sc.functionName}] ${r.finding.description}`
      });
    }
    states.push(r.state);
  }

  const failed = checks.filter((c) => c.status === 'fail');
  const downgrade = failed.length > 0;
  return {
    checks,
    findings,
    states,
    blockTime: blockTime === null ? null : blockTime.toString(),
    blockNumber: typeof blockNumber === 'string' ? blockNumber : null,
    chainId: chainId === undefined || chainId === null ? null : String(chainId),
    downgrade,
    hold: downgrade ? {
      source: 'deadline-analysis',
      reason: failed.map((c) => c.explanation).join(' | ').slice(0, 400)
    } : null
  };
}

module.exports = { EXPIRED_GRACE_SECONDS, NEAR_EXPIRY_SECONDS, DEADLINE_FIELDS, analyzeDeadlines };
