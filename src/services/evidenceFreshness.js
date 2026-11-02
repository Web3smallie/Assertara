/**
 * Evidence freshness validation (Evidence Assembly). Pure and deterministic.
 *
 * A screenshot captured long before evaluation may no longer depict the
 * page the transaction was built from. Freshness compares the client-
 * supplied capture timestamp against evaluation time and reports an
 * explicit status; it never blocks evaluation by itself (Phase B keeps
 * freshness advisory — see bundle + prompt labels), but stale or
 * unverifiable evidence is always labeled so neither the model nor
 * reviewers mistake it for current fact.
 *
 * Statuses: fresh | stale | unknown (no usable timestamp) | invalid
 * (unparseable or future timestamp — clock skew or tampering, treated
 * as unknown-evidence, never as fresh).
 */

const FUTURE_SKEW_MS = 60000;

function parseCapturedAt(value) {
  if (value === undefined || value === null || value === '') return { ok: false, reason: 'missing' };
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return { ok: true, ms: value };
  if (typeof value === 'string' && value.trim().length > 0) {
    const ms = Date.parse(value.trim());
    if (Number.isSafeInteger(ms) && ms > 0) return { ok: true, ms };
  }
  return { ok: false, reason: 'unparseable' };
}

function evaluateFreshness({ capturedAt, receivedAt, nowMs, maxAgeMs }) {
  const now = Number.isSafeInteger(nowMs) ? nowMs : Date.now();
  const maxAge = Number.isSafeInteger(maxAgeMs) && maxAgeMs > 0 ? maxAgeMs : 300000;
  const parsed = parseCapturedAt(capturedAt);
  if (!parsed.ok) {
    return { status: 'unknown', ageMs: null, capturedAt: null, maxAgeMs: maxAge, evaluatedAt: now, reason: `no usable capture timestamp (${parsed.reason})` };
  }
  if (parsed.ms > now + FUTURE_SKEW_MS) {
    return { status: 'invalid', ageMs: null, capturedAt: parsed.ms, maxAgeMs: maxAge, evaluatedAt: now, reason: 'capture timestamp is in the future' };
  }
  const received = Number.isSafeInteger(receivedAt) ? receivedAt : now;
  const ageMs = Math.max(0, received - parsed.ms);
  if (ageMs > maxAge) {
    return { status: 'stale', ageMs, capturedAt: parsed.ms, maxAgeMs: maxAge, evaluatedAt: now, reason: `captured ${ageMs}ms before evaluation (limit ${maxAge}ms)` };
  }
  return { status: 'fresh', ageMs, capturedAt: parsed.ms, maxAgeMs: maxAge, evaluatedAt: now, reason: null };
}

module.exports = { evaluateFreshness, FUTURE_SKEW_MS };
