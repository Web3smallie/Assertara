/**
 * Investigation persistence (Capability 3, B1). Append-only JSONL store
 * for completed investigations so live model reasoning can be inspected
 * and graded after the fact. Follows the repo's durable file-store
 * pattern (agent ledger, signer log): synchronous atomic appends,
 * infallible reads (corrupt lines are skipped with a count, never throw).
 *
 * Privacy: screenshots and oversized blobs are redacted to hashes before
 * anything hits disk. Secrets must never be in the record; belt-and-braces
 * key-name screening drops anything resembling credentials.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_STRING_CHARS = 20000;
const SCREENSHOT_KEYS = new Set(['screenshot', 'screenshotBase64', 'imageDataUrl', 'imageData', 'image_base64']);
// Bare `token` is an ERC-20 token-identity field throughout the Cap5
// effect pipeline (effects, composition, necessity, history) and must
// survive to disk; only credential-shaped compounds redact.
const SECRET_KEY_RE = /(api[_-]?key|secret|password|private[_-]?key|operatorSig|approvalSecret|(approval|pending|access|auth|refresh|id|bearer|api|session|csrf)[_-]?token)/i;

function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

function redactValue(value, key) {
  if (typeof key === 'string' && SECRET_KEY_RE.test(key)) return { redacted: 'credential-like key' };
  if (typeof key === 'string' && SCREENSHOT_KEYS.has(key)) {
    const s = typeof value === 'string' ? value : '';
    return { redacted: 'image blob', sha256: sha256Hex(s), chars: s.length };
  }
  if (typeof value === 'string' && value.length > MAX_STRING_CHARS) {
    return { truncated: true, sha256: sha256Hex(value), chars: value.length, head: value.slice(0, 200) };
  }
  if (Array.isArray(value)) return value.map((v) => redactValue(v, null));
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) out[k] = redactValue(value[k], k);
    return out;
  }
  return value;
}

function defaultFile() {
  try {
    const appConfig = require('../config/env');
    if (typeof appConfig.investigationsFile === 'string' && appConfig.investigationsFile.length > 0) {
      return appConfig.investigationsFile;
    }
  } catch { /* fall through to default */ }
  return path.join('data', 'investigations.jsonl');
}

function recordId(txDigest) {
  const rand = crypto.randomBytes(4).toString('hex');
  const short = typeof txDigest === 'string' && txDigest.length >= 12 ? txDigest.slice(0, 12) : 'notx';
  return `inv_${Date.now().toString(36)}_${short}_${rand}`;
}

function persistInvestigation(record, file) {
  const target = file || defaultFile();
  try {
    const dir = path.dirname(target);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const redacted = redactValue(record, null);
    fs.appendFileSync(target, `${JSON.stringify(redacted)}\n`, 'utf8');
    return { ok: true, file: target };
  } catch (err) {
    return { ok: false, file: target, error: String((err && err.message) || err).slice(0, 200) };
  }
}

function readRecords(file) {
  const target = file || defaultFile();
  let lines = [];
  try {
    if (!fs.existsSync(target)) return { records: [], skipped: 0, file: target };
    lines = fs.readFileSync(target, 'utf8').split('\n');
  } catch (err) {
    return { records: [], skipped: 0, file: target, error: String((err && err.message) || err).slice(0, 200) };
  }
  const records = [];
  let skipped = 0;
  for (const line of lines) {
    if (line.trim().length === 0) continue;
    try {
      records.push(JSON.parse(line));
    } catch {
      skipped += 1;
    }
  }
  return { records, skipped, file: target };
}

/**
 * Capability 4 B9: record quality classification. The review corpus
 * exists for qualitative evaluation of LIVE reasoning, so only
 * complete model-origin investigations count as genuine:
 * - genuine-complete: model origin, a REAL (non-mock) serving model
 *   id, structured investigation with conclusions, real summary.
 * - null-investigation: investigation field null/missing.
 * - empty-conclusions: model output with no conclusions to review.
 * - non-model: mock/heuristic/fallback origin (unit-covered already).
 * - mock-model: origin says model but serving id is a mock client.
 * - unverified-model-id: model origin but no serving id — live
 *   provenance cannot be demonstrated, so it cannot anchor a
 *   qualitative review (kept in quarantine for manual inspection).
 * - test-fixture: canned mock summary or placeholder content.
 * - corrupt: unparseable or shapeless.
 */
function classifyInvestigationRecord(r) {
  if (!r || typeof r !== 'object') return 'corrupt';
  const origin = r.reasoningOrigin || r.origin || null;
  const inv = r.investigation;
  const summary = typeof r.summary === 'string' ? r.summary : '';
  if (/^s \[/.test(summary) || /^canned\b/.test(summary) || summary === 's') return 'test-fixture';
  if (origin !== null && origin !== 'model') return 'non-model';
  if (inv === null || inv === undefined) return origin === 'model' ? 'null-investigation' : 'test-fixture';
  if (typeof inv !== 'object') return 'test-fixture';
  const modelId = typeof r.modelId === 'string' ? r.modelId : '';
  if (origin === 'model') {
    if (/^mock/i.test(modelId)) return 'mock-model';
    const conclusions = Array.isArray(inv.conclusions) ? inv.conclusions : null;
    if (!conclusions || conclusions.length === 0) return 'empty-conclusions';
    if (modelId.length === 0) return 'unverified-model-id';
    return 'genuine-complete';
  }
  return 'test-fixture';
}

function listInvestigations({ file, limit = 20, offset = 0, verdict, origin, genuineOnly = false } = {}) {
  const { records, skipped, error } = readRecords(file);
  const filtered = records.filter((r) => (
    (!verdict || r.verdict === verdict) && (!origin || r.reasoningOrigin === origin)
    && (!genuineOnly || classifyInvestigationRecord(r) === 'genuine-complete')
  ));
  const total = filtered.length;
  const items = filtered.slice(Math.max(0, offset), Math.max(0, offset) + Math.max(0, limit)).map((r) => ({
    recordId: r.recordId || null,
    recordedAt: r.recordedAt || null,
    verdict: r.verdict || null,
    reasoningOrigin: r.reasoningOrigin || null,
    investigationType: r.investigationType || null,
    promptVersion: r.promptVersion || null,
    modelId: r.modelId || null,
    decision: (r.policyDecision && r.policyDecision.decision) || null
  }));
  return { ok: !error, items, total, skipped, error: error || null };
}

function getInvestigation(recordId, file) {
  if (typeof recordId !== 'string' || recordId.length === 0) return { ok: false, error: 'recordId required' };
  const { records, error } = readRecords(file);
  if (error) return { ok: false, error };
  const found = records.find((r) => r && r.recordId === recordId);
  if (!found) return { ok: false, error: 'not found' };
  return { ok: true, record: found };
}

// Command-centre lookup: agent requests carry the evaluation bundle id
// (evalId), while records are keyed by digest-derived recordId. Scans
// for the record whose bundle id matches. Records are redacted at
// persist time, so serving one over HTTP exposes no secrets.
function findByEvalId(evalId, file) {
  if (typeof evalId !== 'string' || evalId.length === 0) return { ok: false, error: 'evalId required' };
  const { records, error } = readRecords(file);
  if (error) return { ok: false, error };
  const found = records.find((r) => r && (r.id === evalId || r.evalId === evalId));
  if (!found) return { ok: false, error: 'not found' };
  return { ok: true, record: found };
}

/**
 * Capability 4 B9: corpus quarantine. Classifies every record; with
 * apply=true, non-genuine records move to the quarantine file (each
 * wrapped with quarantinedAt + reason) and the main file is rewritten
 * with genuine records only (atomic rename). Nothing is deleted:
 * quarantine preserves every moved record with its reason. Idempotent:
 * a second run moves nothing.
 */
function quarantineInvestigations({ file, quarantineFile, apply = false } = {}) {
  const src = file || defaultFile();
  const dst = quarantineFile || `${src}.quarantine.jsonl`;
  const { records, skipped, error } = readRecords(src);
  if (error) return { ok: false, error, counts: null };
  const counts = {
    'genuine-complete': 0, 'null-investigation': 0, 'empty-conclusions': 0,
    'non-model': 0, 'mock-model': 0, 'unverified-model-id': 0,
    'test-fixture': 0, corrupt: skipped
  };
  const genuine = [];
  const quarantined = [];
  for (const r of records) {
    const cls = classifyInvestigationRecord(r);
    counts[cls] = (counts[cls] || 0) + 1;
    if (cls === 'genuine-complete') genuine.push(r);
    else quarantined.push({ quarantinedAt: Date.now(), reason: cls, record: r });
  }
  const report = { ok: true, file: src, quarantineFile: dst, total: records.length, counts, moved: quarantined.length, kept: genuine.length, applied: false };
  if (!apply) return report;
  try {
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    if (quarantined.length > 0) {
      fs.appendFileSync(dst, `${quarantined.map((q) => JSON.stringify(q)).join('\n')}\n`, 'utf8');
    }
    const tmp = `${src}.tmp-${Date.now()}-${process.pid}`;
    fs.writeFileSync(tmp, genuine.length > 0 ? `${genuine.map((r) => JSON.stringify(r)).join('\n')}\n` : '', 'utf8');
    fs.renameSync(tmp, src);
  } catch (err) {
    return { ok: false, error: String((err && err.message) || err), counts };
  }
  report.applied = true;
  return report;
}

module.exports = {
  persistInvestigation,
  listInvestigations,
  getInvestigation,
  findByEvalId,
  classifyInvestigationRecord,
  quarantineInvestigations,
  recordId,
  redactValue,
  MAX_STRING_CHARS
};
