/**
 * Value-protection decoder rules (Capability 4, B3). Pure calldata
 * checks: a swap with a zero (or missing) enforced minimum leaves the
 * entire displayed expectation unprotected on-chain. Amounts are
 * compared as exact integers; unparseable values become findings about
 * missing protection, never silent passes.
 */

function parseAmount(v) {
  try {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'string' && /^-?\d+$/.test(v.trim())) return BigInt(v.trim());
    if (typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
    return null;
  } catch {
    return null;
  }
}

const MIN_OUTPUT_FUNCTIONS = {
  exactInputSingle: 'amountOutMinimum',
  swapExactTokensForTokens: 'amountOutMin',
  swapExactETHForTokens: 'amountOutMin'
};

function evaluateValueProtection(decodedTx) {
  if (!decodedTx) return null;
  // Capability 4 B6: Uniswap V2 exact-input swaps carry the same
  // minimum-output hazard under the `amountOutMin` name. (V3
  // exactInputSingle unchanged; amountInMax-style caps are chain
  // fail-closed, not user-risk, and stay with the model.)
  const field = MIN_OUTPUT_FUNCTIONS[decodedTx.functionName] || null;
  if (!field) return null;
  const params = decodedTx.parameters || {};
  const minOut = parseAmount(params[field]);
  if (minOut === null || minOut < 0n) {
    return {
      ruleId: 'MISSING_OUTPUT_PROTECTION',
      severity: 'MEDIUM',
      description: `Swap calldata carries no parseable ${field}: no enforceable floor under the received output can be established.`,
      triggered: true,
      metadata: { [field]: params[field] === undefined ? null : String(params[field]).slice(0, 80) }
    };
  }
  if (minOut === 0n) {
    return {
      ruleId: 'ZERO_MINIMUM_OUTPUT',
      severity: 'HIGH',
      description: `Swap enforces ${field} = 0: any nonzero output satisfies the transaction, so the full quoted expectation is unprotected against slippage and MEV extraction.`,
      triggered: true,
      metadata: { [field]: '0', amountIn: params.amountIn === undefined ? null : String(params.amountIn).slice(0, 80) }
    };
  }
  return null;
}

module.exports = { evaluateValueProtection };
