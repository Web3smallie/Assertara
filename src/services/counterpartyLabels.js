/**
 * Counterparty labels (Evidence Assembly): static known-address maps plus
 * an optional operator-configured label file. Labels are DISPLAY HINTS
 * for investigators and the model prompt — they are never identity proof,
 * never enter mandate/policy/comparison decisions, and every surfaced
 * label carries its source (static | configured | unknown).
 */

const fs = require('fs');
const { KNOWN_TOKENS, KNOWN_ROUTERS } = require('../utils/abiSignatures');

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

/**
 * Load an operator label file: {"0xaddr": "Label"}. Malformed JSON fails
 * the load (caller falls back to static-only); individually invalid
 * entries are skipped and reported, never trusted.
 */
function loadCounterpartyLabels(filePath) {
  if (!filePath || typeof filePath !== 'string') return { ok: true, labels: {}, skipped: [] };
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    return { ok: false, labels: {}, skipped: [], error: `cannot read label file: ${err.message}` };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, labels: {}, skipped: [], error: 'label file is not valid JSON' };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, labels: {}, skipped: [], error: 'label file must be a JSON object of address to label' };
  }
  const labels = {};
  const skipped = [];
  for (const [addr, label] of Object.entries(parsed)) {
    if (!ADDRESS_RE.test(addr) || typeof label !== 'string' || label.trim().length === 0 || label.length > 120) {
      skipped.push(String(addr).slice(0, 42));
      continue;
    }
    labels[addr.toLowerCase()] = label.trim();
  }
  return { ok: true, labels, skipped };
}

function resolveLabel(address, configured) {
  if (typeof address !== 'string' || !ADDRESS_RE.test(address)) return { address, label: null, source: 'unknown' };
  const lower = address.toLowerCase();
  const token = KNOWN_TOKENS[lower];
  if (token) return { address: lower, label: `${token.name} (${token.symbol})`, source: 'static' };
  const router = KNOWN_ROUTERS[lower];
  // Capability 4 B5: display HINT only (never identity proof), so the
  // static shape change is adopted without chain scoping here; the
  // decoder and the identity service scope authoritatively.
  if (router) return { address: lower, label: router.name || router, source: 'static' };
  // Capability 5 B5: canonical bridge contracts as display HINTs (never
  // identity proof, never decisions — same contract as routers above).
  try {
    const { ACROSS_V3_SPOKEPOOLS, CCTP_V1_MESSENGERS } = require('../utils/bridgeAnalysis');
    for (const [chain, addr] of Object.entries(ACROSS_V3_SPOKEPOOLS)) {
      if (addr === lower) return { address: lower, label: `Across V3 SpokePool (chain ${chain})`, source: 'static' };
    }
    for (const [chain, addr] of Object.entries(CCTP_V1_MESSENGERS)) {
      if (addr === lower) return { address: lower, label: `CCTP V1 TokenMessenger (chain ${chain})`, source: 'static' };
    }
  } catch { /* labels unavailable; fall through to configured/unknown */ }
  if (configured && typeof configured[lower] === 'string') {
    return { address: lower, label: configured[lower], source: 'configured' };
  }
  return { address: lower, label: null, source: 'unknown' };
}

/** Resolve a deduped label list for display/prompt hints (never decisions). */
function resolveCounterparties(addresses, configured) {
  const seen = new Set();
  const out = [];
  for (const a of Array.isArray(addresses) ? addresses : []) {
    if (typeof a !== 'string' || !ADDRESS_RE.test(a)) continue;
    const lower = a.toLowerCase();
    if (seen.has(lower)) continue;
    seen.add(lower);
    out.push(resolveLabel(lower, configured));
  }
  return out.slice(0, 16);
}

module.exports = { loadCounterpartyLabels, resolveLabel, resolveCounterparties };
