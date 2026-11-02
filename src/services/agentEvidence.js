/**
 * Agent evidence admission (Capability 3, B6). Typed, bounded, untrusted
 * evidence envelopes that compatible autonomous agents may attach to a
 * transaction proposal. Agent-agnostic: the envelope schema is fixed and
 * carries no demo-agent concepts.
 *
 * Security contract:
 * - Server assigns canonical IDs (X-001...); client IDs are opaque
 *   labels and can never collide with system IDs (R-*, L-*, AMB-*).
 * - Trust is server-assigned UNTRUSTED, always. Envelopes asserting
 *   trust/tier/verified status are rejected as trust-smuggling.
 * - Content is data, never instructions: packed under an explicit
 *   untrusted framing (see packer), never fetched (URLs are inert
 *   text), control characters stripped, sizes bounded.
 */

const EVIDENCE_TYPES = [
  'objective', 'intent', 'visual-note', 'ocr-observation', 'prior-result',
  'contract-info', 'tx-context', 'chain-observation', 'counter-evidence', 'document'
];

const MAX_ITEMS = 10;
const MAX_ARRAY_ITEMS = 25;
const MAX_CONTENT_CHARS = 4000;
const MAX_TOTAL_CHARS = 32000;
const MAX_META_CHARS = 500;
const FUTURE_SKEW_MS = 120000;

function cleanText(value, max) {
  if (typeof value !== 'string') return null;
   
  const stripped = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  return stripped.slice(0, max);
}

function parseTimestamp(ts) {
  if (ts === undefined || ts === null) return { ok: true, ms: null };
  let ms = null;
  if (typeof ts === 'number' && Number.isFinite(ts)) ms = ts;
  else if (typeof ts === 'string' && ts.length <= 64) {
    const parsed = Date.parse(ts);
    if (!Number.isNaN(parsed)) ms = parsed;
  }
  if (ms === null) return { ok: false, error: 'unparseable timestamp' };
  if (ms - Date.now() > FUTURE_SKEW_MS) return { ok: false, error: 'timestamp too far in the future' };
  if (ms < 0) return { ok: false, error: 'negative timestamp' };
  return { ok: true, ms };
}

function admitAgentEvidence(items) {
  if (!Array.isArray(items)) return { ok: false, error: 'evidence must be an array', admitted: [], rejected: [] };
  if (items.length > MAX_ARRAY_ITEMS) {
    return { ok: false, error: `evidence array exceeds ${MAX_ARRAY_ITEMS} items`, admitted: [], rejected: [] };
  }
  const admitted = [];
  const rejected = [];
  let totalChars = 0;
  items.forEach((env, index) => {
    const clientId = env && typeof env.evidenceId === 'string' ? env.evidenceId.slice(0, 120) : null;
    const reject = (error) => rejected.push({ index, clientId, error });
    if (!env || typeof env !== 'object' || Array.isArray(env)) return reject('envelope must be an object');
    if (!EVIDENCE_TYPES.includes(env.type)) return reject(`unknown evidence type: ${String(env.type).slice(0, 60)}`);
    if (('trust' in env && env.trust !== 'untrusted') || ('tier' in env) || env.verified === true) {
      return reject('trust-smuggling: agents cannot self-assign trust status');
    }
    const content = cleanText(env.content, MAX_CONTENT_CHARS + 1);
    if (content === null || content.length === 0) return reject('content must be a non-empty string');
    if (content.length > MAX_CONTENT_CHARS) return reject(`content exceeds ${MAX_CONTENT_CHARS} chars`);
    const ts = parseTimestamp(env.timestamp);
    if (!ts.ok) return reject(ts.error);
    if (admitted.length >= MAX_ITEMS) return reject(`admission cap of ${MAX_ITEMS} items reached`);
    if (totalChars + content.length > MAX_TOTAL_CHARS) return reject('total evidence budget exceeded');
    totalChars += content.length;
    admitted.push({
      evidenceId: `X-${String(admitted.length + 1).padStart(3, '0')}`,
      clientId,
      type: env.type,
      source: cleanText(env.source, MAX_META_CHARS) || 'agent',
      origin: cleanText(env.origin, MAX_META_CHARS) || 'agent-submitted',
      timestamp: ts.ms,
      provenance: cleanText(env.provenance, MAX_META_CHARS) || 'agent-submitted, unverified',
      trust: 'UNTRUSTED',
      content
    });
  });
  return { ok: true, admitted, rejected };
}

module.exports = {
  EVIDENCE_TYPES,
  MAX_ITEMS,
  MAX_CONTENT_CHARS,
  MAX_TOTAL_CHARS,
  admitAgentEvidence
};
