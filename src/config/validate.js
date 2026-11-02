/**
 * Small configuration validators shared by env.js and unit tests.
 * Pure functions of their inputs: no process.env or dotenv coupling, so
 * every invalid-value policy is testable deterministically.
 */

// Node's setTimeout clamps larger delays to 1ms with a warning — values
// above this bound must never become active timeouts.
const MAX_TIMEOUT_MS = 2147483647;

/**
 * Parse a timeout env value (ms). Policy: sanitize to the documented
 * default. Only positive integers within setTimeout's usable range are
 * accepted; missing, empty, negative, zero, decimal, non-numeric, and
 * out-of-range values all fall back. Never throws, so a typo cannot crash
 * the server at require time — consistent with env.js's existing `||`
 * fallback philosophy.
 */
function parseTimeoutMs(raw, fallback) {
  // Env values are strings; anything else (including numbers, which cannot
  // arrive via process.env) falls back rather than being coerced.
  if (typeof raw !== 'string') return fallback;
  const text = raw.trim();
  if (text === '') return fallback;
  const parsed = Number(text);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > MAX_TIMEOUT_MS) return fallback;
  return parsed;
}

module.exports = { parseTimeoutMs, MAX_TIMEOUT_MS };
