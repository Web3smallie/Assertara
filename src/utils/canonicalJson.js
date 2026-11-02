/**
 * Canonical JSON + digests for provenance instrumentation (Phase 1).
 *
 * Observer-only helpers: deterministic serialization for hashing model
 * inputs/outputs. Never throws on JSON-shaped input; safeProvenance
 * wraps any call so instrumentation failures degrade to null instead
 * of breaking the investigation they observe.
 */

const crypto = require('crypto');

function canonicalize(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (Array.isArray(value)) return value.map((v) => canonicalize(v));
  if (typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) {
      const v = value[k];
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
      out[k] = canonicalize(v);
    }
    return out;
  }
  return null;
}

function canonicalStringify(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function safeProvenance(fn, fallback) {
  try {
    return fn();
  } catch {
    return fallback === undefined ? null : fallback;
  }
}

module.exports = { canonicalStringify, sha256Hex, safeProvenance };
