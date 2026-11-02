/**
 * Transaction value and output-protection analysis (Capability 4, B3).
 *
 * Pure utility (no services, no network): swap parameters have economic
 * meaning — amountOutMinimum is the enforceable floor under what the
 * user receives, and the gap between a displayed quote and that floor
 * measures how much of the expectation is unprotected. Exact BigInt
 * arithmetic with explicit insufficient-data outcomes.
 *
 * Honesty boundaries (never crossed here):
 * - A displayed quote is an estimate, never a promise: gap ratios are
 *   INDICATIVE, drive no verdict by themselves, and are always labeled.
 * - Market prices are never invented: without a corroborated quote (or a
 *   simulation output), no ratio is computed.
 * - All inputs are base-unit integers: display strings must be converted
 *   with the token's own decimals BEFORE calling in (confusing "3,450"
 *   with 3450 base units is a classic decimal error this module refuses
 *   to make — it takes integers only).
 */

const INFINITE_APPROVAL_THRESHOLD = 2n ** 255n;
const MAX_UINT256 = (2n ** 256n) - 1n;

/**
 * Classify a decoded approval amount against the documented unlimited
 * threshold. Allowances at or above 2^255 exceed any plausible intended
 * spend, so they count as unlimited even when they are not exactly
 * 2^256-1 (the common UI encoding); near-max values are equivalent in
 * effect. Accepts bigint or integer strings; anything else is
 * unparseable, never defaulted.
 */
function classifyApprovalAmount(amount) {
  let value;
  try {
    if (typeof amount === 'bigint') value = amount;
    else if (typeof amount === 'string' && /^-?\d+$/.test(amount.trim())) value = BigInt(amount.trim());
    else if (typeof amount === 'number' && Number.isSafeInteger(amount)) value = BigInt(amount);
    else return { kind: 'unparseable', threshold: '2^255', isMaxUint: false, value: null };
  } catch {
    return { kind: 'unparseable', threshold: '2^255', isMaxUint: false, value: null };
  }
  if (value < 0n) return { kind: 'unparseable', threshold: '2^255', isMaxUint: false, value: null };
  if (value === 0n) return { kind: 'zero', threshold: '2^255', isMaxUint: false, value: '0' };
  if (value >= INFINITE_APPROVAL_THRESHOLD) {
    return { kind: 'unlimited', threshold: '2^255', isMaxUint: value === MAX_UINT256, value: value.toString() };
  }
  return { kind: 'ordinary', threshold: '2^255', isMaxUint: false, value: value.toString() };
}

function parseWei(v) {
  try {
    if (typeof v === 'bigint') return v < 0n ? null : v;
    if (typeof v === 'string' && /^\d+$/.test(v.trim())) return BigInt(v.trim());
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
    return null;
  } catch {
    return null;
  }
}

/**
 * Indicative gap between a corroborated output quote and the enforced
 * minimum, in basis points of the quote: gapBps = (quote - minOut) *
 * 10000 / quote (floored). Levels:
 * - 'unprotected': minimum is zero — none of the displayed expectation
 *   is enforced on-chain.
 * - 'minimum-exceeds-quote': enforced floor above the displayed quote —
 *   the quoted outcome is unsatisfiable as stated.
 * - 'none': floor equals the quote (no slippage tolerance at all).
 * - 'partial': a positive floor below the quote.
 * Anything missing or degenerate is insufficient-data with a reason.
 */
function analyzeOutputGap({ amountOutMinimum, quotedOutputWei }) {
  const minOut = parseWei(amountOutMinimum);
  if (minOut === null) {
    return { status: 'insufficient-data', reason: 'decoded amountOutMinimum unavailable' };
  }
  const quote = parseWei(quotedOutputWei);
  if (quote === null) {
    return { status: 'insufficient-data', reason: 'no corroborated output quote in base units' };
  }
  if (quote === 0n) {
    return { status: 'insufficient-data', reason: 'quoted output is zero; no meaningful ratio' };
  }
  if (minOut === 0n) {
    return {
      status: 'analyzed', level: 'unprotected', gapBps: '10000',
      minOutWei: '0', quoteWei: quote.toString(),
      note: 'indicative: quote is an estimate; minimum is enforced'
    };
  }
  if (minOut > quote) {
    return {
      status: 'analyzed', level: 'minimum-exceeds-quote',
      gapBps: ((minOut - quote) * 10000n / quote).toString(),
      minOutWei: minOut.toString(), quoteWei: quote.toString(),
      note: 'indicative: quote is an estimate; minimum is enforced'
    };
  }
  const gapBps = ((quote - minOut) * 10000n / quote).toString();
  return {
    status: 'analyzed', level: gapBps === '0' ? 'none' : 'partial', gapBps,
    minOutWei: minOut.toString(), quoteWei: quote.toString(),
    note: 'indicative: quote is an estimate; minimum is enforced'
  };
}

module.exports = { INFINITE_APPROVAL_THRESHOLD, MAX_UINT256, classifyApprovalAmount, analyzeOutputGap };
