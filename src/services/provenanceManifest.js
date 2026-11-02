/**
 * Cryptographic provenance manifest (Phase 2).
 *
 * Pure, on-demand builder: assembles a deterministic, independently
 * verifiable manifest from a persisted investigation record and, on the
 * agent path, its associated agent request. No lifecycle hooks, no
 * pipeline changes, no trace/ring reads, no model calls, no signing.
 *
 * Digest architecture (all SHA-256 over canonical JSON bytes):
 *   evidenceDigest         = sha256(canonical(persistedRecord))
 *   publicDigest           = sha256(canonical(publicProjection))
 *   requestProjectionDigest= sha256(canonical(requestProjection)) (agent path)
 *   manifestDigest         = sha256(canonical(manifest))
 * The envelope {manifestDigest, createdAt, builderVersion} stays outside
 * the committed bytes so rebuilds are byte-identical.
 *
 * Strictness: every input is validated (no silent normalization);
 * mismatched or insufficient evidence refuses with a typed error;
 * unknown statuses refuse rather than guess.
 *
 * Phase 2.1 audit fixes: the builder enforces cross-field consistency
 * between related provenance fields (B2) and gates VALIDATED_AGAINST on
 * model reasoning origin (B3); verifyPackage re-validates manifest and
 * projection semantics and re-derives contribution claims from disclosed
 * evidence instead of trusting consistent digests (B1); investigation
 * lookup returns the latest valid manifest (B4).
 */

const fs = require('fs');
const path = require('path');
const { canonicalStringify, sha256Hex } = require('../utils/canonicalJson');

const SCHEMA_VERSION = 'assertara-provenance-1';
const BUILDER_VERSION = 'phase2-2';
const PACKAGE_VERSION = 'assertara-verify-1';
const DEFAULT_MANIFESTS_FILE = path.join('data', 'manifests.jsonl');
const MIN_MS = Date.UTC(2020, 0, 1);
const MAX_MS = Date.UTC(2100, 0, 1);
const HEX64 = /^[0-9a-f]{64}$/;
const TX_HASH = /^0x[0-9a-fA-F]{64}$/;

const MUSE_STATUSES = ['success', 'http-error', 'empty-content', 'invalid-output', 'timeout', 'transport-error', 'skipped'];
const SAM_PROMPT_STATUSES = ['success', 'error', 'timeout', 'incomplete'];
const SAM_AGGREGATE = ['success', 'partial', 'failed', 'mock', 'skipped'];
const DECISIONS = ['ALLOW', 'BLOCK', 'REVIEW', 'UNCERTAIN'];
const VERDICTS = ['MATCH', 'MISMATCH', 'UNCERTAIN'];
const EXECUTION_OUTCOMES = ['EXECUTED', 'EXECUTED_UNVERIFIED', 'EFFECTS_DIVERGED', 'MISMATCH', 'FAILED'];
const HASHABLE_OUTCOMES = ['EXECUTED', 'EXECUTED_UNVERIFIED', 'EFFECTS_DIVERGED', 'FAILED'];
const MUSE_CONTRIBUTIONS = ['NOT_INVOKED', 'INVOKED', 'SUCCEEDED', 'OUTPUT_INCLUDED', 'VERDICT_ACCEPTED'];
const SAM_CONTRIBUTIONS = ['NOT_INVOKED', 'INVOKED', 'SUCCEEDED', 'INCOMPLETE', 'FAILED', 'TIMEOUT', 'PARTIAL', 'MOCK', 'OUTPUT_INCLUDED', 'PROMPT_INCLUDED', 'VALIDATED_AGAINST'];
const REASONING_ORIGINS = ['model', 'heuristic-fallback'];

class ManifestError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

// Strict structural gate: rejects every type the canonicalizer would
// silently normalize (undefined, non-finite, BigInt, Date, Buffer,
// functions, symbols, class instances, circular refs). Plain JSON only.
function assertValidInput(value, where) {
  const ancestors = new Set();
  const walk = (v, p) => {
    if (v === null) return;
    const t = typeof v;
    if (t === 'string' || t === 'boolean') return;
    if (t === 'number') {
      if (!Number.isFinite(v)) throw new ManifestError('MANIFEST_INVALID', `${p}: non-finite number`);
      return;
    }
    if (t === 'undefined' || t === 'function' || t === 'symbol' || t === 'bigint') {
      throw new ManifestError('MANIFEST_INVALID', `${p}: forbidden type ${t} (use explicit null)`);
    }
    if (v instanceof Date) throw new ManifestError('MANIFEST_INVALID', `${p}: Date not allowed (use ms number)`);
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(v)) throw new ManifestError('MANIFEST_INVALID', `${p}: Buffer not allowed (use hex digest)`);
    if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(v)) throw new ManifestError('MANIFEST_INVALID', `${p}: typed array not allowed`);
    const proto = Object.getPrototypeOf(v);
    if (!Array.isArray(v) && proto !== Object.prototype && proto !== null) {
      throw new ManifestError('MANIFEST_INVALID', `${p}: unsupported object type`);
    }
    if (ancestors.has(v)) throw new ManifestError('MANIFEST_INVALID', `${p}: circular reference`);
    ancestors.add(v);
    if (Array.isArray(v)) v.forEach((e, i) => walk(e, `${p}[${i}]`));
    else for (const k of Object.keys(v)) walk(v[k], `${p}.${k}`);
    ancestors.delete(v);
  };
  walk(value, where || 'input');
}

function req(value, name) {
  if (value === null || value === undefined) throw new ManifestError('MANIFEST_INVALID', `${name}: required`);
  return value;
}

function assertId(v, name) {
  req(v, name);
  if (typeof v !== 'string' || v.length === 0 || v.length > 256) {
    throw new ManifestError('MANIFEST_INVALID', `${name}: non-empty string ≤256 chars required`);
  }
  return v;
}

function assertHex64(v, name) {
  req(v, name);
  if (typeof v !== 'string' || !HEX64.test(v)) throw new ManifestError('MANIFEST_INVALID', `${name}: 64-hex digest required`);
  return v;
}

function assertMs(v, name) {
  req(v, name);
  if (!Number.isSafeInteger(v) || v < MIN_MS || v > MAX_MS) {
    throw new ManifestError('MANIFEST_INVALID', `${name}: safe ms timestamp 2020–2100 required`);
  }
  return v;
}

function assertEnum(v, list, name) {
  req(v, name);
  if (!list.includes(v)) throw new ManifestError('MANIFEST_INVALID', `${name}: one of ${list.join('|')}`);
  return v;
}

function optHex64(v, name) {
  if (v === null || v === undefined) return null;
  if (typeof v !== 'string' || !HEX64.test(v)) throw new ManifestError('MANIFEST_INVALID', `${name}: 64-hex digest or null`);
  return v;
}

function optMs(v, name) {
  if (v === null || v === undefined) return null;
  if (!Number.isSafeInteger(v) || v < MIN_MS || v > MAX_MS) {
    throw new ManifestError('MANIFEST_INVALID', `${name}: safe ms timestamp 2020–2100 or null`);
  }
  return v;
}

function optStr(v, name, max) {
  if (v === null || v === undefined) return null;
  if (typeof v !== 'string' || v.length > (max || 2048)) {
    throw new ManifestError('MANIFEST_INVALID', `${name}: string ≤${max || 2048} chars or null`);
  }
  return v;
}

function normalizeChainId(v, name) {
  req(v, name);
  if (typeof v === 'number' && Number.isSafeInteger(v) && v > 0) return v;
  if (typeof v === 'string' && /^\d+$/.test(v) && Number.isSafeInteger(Number(v)) && Number(v) > 0) return Number(v);
  if (typeof v === 'string' && /^0x[0-9a-fA-F]+$/.test(v)) {
    const n = parseInt(v, 16);
    if (Number.isSafeInteger(n) && n > 0) return n;
  }
  throw new ManifestError('MANIFEST_INVALID', `${name}: positive chain id required`);
}

// Minimal explicit public projection of a persisted record. Anything
// not listed here is excluded by construction: page content, agent
// claims, full model outputs, region geometry/OCR text, assembly
// detail, owner identity, and (already redacted at persist) images.
function buildPublicProjection(record) {
  const dt = record.decodedTransaction && typeof record.decodedTransaction === 'object' ? record.decodedTransaction : null;
  const pd = record.policyDecision && typeof record.policyDecision === 'object' ? record.policyDecision : null;
  const safeguards = Array.isArray(record.verdictSafeguards) ? record.verdictSafeguards : null;
  if (safeguards === null) throw new ManifestError('MANIFEST_INVALID', 'record.verdictSafeguards: array required');
  const packing = record.evidencePacking && typeof record.evidencePacking === 'object' ? record.evidencePacking : null;
  const refVal = record.referenceValidation && typeof record.referenceValidation === 'object' ? record.referenceValidation : null;
  const regions = record.visualEvidence && Array.isArray(record.visualEvidence.regions) ? record.visualEvidence.regions : null;
  return {
    recordId: assertId(record.recordId, 'record.recordId'),
    evalId: assertId(record.id, 'record.id'),
    traceId: assertId(record.traceId, 'record.traceId'),
    requestId: record.requestId === null || record.requestId === undefined ? null : assertId(record.requestId, 'record.requestId'),
    recordedAt: assertMs(record.recordedAt, 'record.recordedAt'),
    investigationPath: assertEnum(record.investigationPath, ['browser', 'agent'], 'record.investigationPath'),
    chainId: normalizeChainId(record.chainId, 'record.chainId'),
    sender: optStr(record.sender, 'record.sender', 64),
    to: optStr(record.to, 'record.to', 64),
    verdict: assertEnum(record.verdict, VERDICTS, 'record.verdict'),
    confidence: (typeof record.confidence === 'number' && Number.isFinite(record.confidence)) ? record.confidence : null,
    recommendedAction: optStr(record.recommendedAction, 'record.recommendedAction', 64),
    policyDecision: pd === null ? null : {
      decision: assertEnum(pd.decision, DECISIONS, 'record.policyDecision.decision'),
      reasons: Array.isArray(pd.reasons) ? pd.reasons.map((r) => String(r).slice(0, 2000)) : []
    },
    verdictSafeguards: safeguards.map((s) => ({
      trigger: assertId(s.trigger, 'safeguard.trigger'),
      from: optStr(s.from, 'safeguard.from', 64),
      to: optStr(s.to, 'safeguard.to', 64)
    })),
    txBinding: record.txBinding === null || record.txBinding === undefined ? null : {
      receivedTxDigest: optHex64(record.txBinding.receivedTxDigest, 'record.txBinding.receivedTxDigest'),
      evaluatedTxDigest: optHex64(record.txBinding.evaluatedTxDigest, 'record.txBinding.evaluatedTxDigest'),
      match: record.txBinding.match === null || record.txBinding.match === undefined ? null : Boolean(record.txBinding.match)
    },
    decodedTransaction: dt === null ? null : {
      contract: optStr(dt.contract, 'decodedTransaction.contract', 64),
      contractName: optStr(dt.contractName, 'decodedTransaction.contractName', 128),
      functionName: optStr(dt.functionName, 'decodedTransaction.functionName', 128),
      standard: optStr(dt.standard, 'decodedTransaction.standard', 64),
      valueEth: optStr(dt.valueEth, 'decodedTransaction.valueEth', 64),
      isUnlimitedApproval: dt.isUnlimitedApproval === true
    },
    ruleIds: Array.isArray(record.ruleFindings)
      ? record.ruleFindings.map((r) => (r && typeof r.ruleId === 'string' ? r.ruleId.slice(0, 128) : 'unknown'))
      : [],
    museProvenance: projectMuseProvenance(req(record.museProvenance, 'record.museProvenance')),
    samProvenance: projectSamProvenance(req(record.samProvenance, 'record.samProvenance')),
    regionsDisclosed: regions === null ? 0 : regions.length,
    packingTruncations: packing !== null && Array.isArray(packing.truncations)
      ? packing.truncations.map((t) => ({
          section: String((t && t.section) || 'unknown').slice(0, 64),
          removed: Number.isSafeInteger(t && t.removedChars) ? t.removedChars : 0
        }))
      : [],
    referenceValidation: refVal === null ? { present: false, ok: null } : {
      present: refVal.present === true,
      ok: refVal.ok === true ? true : (refVal.ok === false ? false : null)
    }
  };
}

function projectMuseProvenance(mp) {
  if (!mp || typeof mp !== 'object') throw new ManifestError('MANIFEST_INVALID', 'museProvenance: object required');
  return {
    status: assertEnum(mp.status, MUSE_STATUSES, 'museProvenance.status'),
    provider: optStr(mp.provider, 'museProvenance.provider', 64),
    endpoint: optStr(mp.endpoint, 'museProvenance.endpoint', 64),
    requested: optStr(mp.requested, 'museProvenance.requested', 128),
    served: optStr(mp.served, 'museProvenance.served', 128),
    responseId: optStr(mp.responseId, 'museProvenance.responseId', 128),
    invokedAt: optMs(mp.invokedAt, 'museProvenance.invokedAt'),
    completedAt: optMs(mp.completedAt, 'museProvenance.completedAt'),
    inputDigest: optHex64(mp.inputDigest, 'museProvenance.inputDigest'),
    outputDigest: optHex64(mp.outputDigest, 'museProvenance.outputDigest'),
    latencyMs: (mp.latencyMs === null || mp.latencyMs === undefined) ? null
      : (Number.isSafeInteger(mp.latencyMs) && mp.latencyMs >= 0 ? mp.latencyMs : (() => { throw new ManifestError('MANIFEST_INVALID', 'museProvenance.latencyMs: ms >= 0 or null'); })()),
    usage: mp.usage === null || mp.usage === undefined ? null : mp.usage
  };
}

function projectSamPrompt(p, index) {
  if (!p || typeof p !== 'object') throw new ManifestError('MANIFEST_INVALID', `samProvenance.perPrompt[${index}]: object required`);
  if (p.index !== index) throw new ManifestError('MANIFEST_INVALID', `samProvenance.perPrompt[${index}]: index sequence broken`);
  const detections = p.detections === undefined ? p.matches : p.detections;
  if (!Number.isSafeInteger(detections) || detections < 0) {
    throw new ManifestError('MANIFEST_INVALID', `samProvenance.perPrompt[${index}]: detections >= 0 required`);
  }
  return {
    index,
    prompt: assertId(p.prompt, `samProvenance.perPrompt[${index}].prompt`),
    status: assertEnum(p.status, SAM_PROMPT_STATUSES, `samProvenance.perPrompt[${index}].status`),
    invokedAt: optMs(p.invokedAt, `samProvenance.perPrompt[${index}].invokedAt`),
    completedAt: optMs(p.completedAt, `samProvenance.perPrompt[${index}].completedAt`),
    responseId: optStr(p.responseId, `samProvenance.perPrompt[${index}].responseId`, 128),
    inputDigest: optHex64(p.inputDigest, `samProvenance.perPrompt[${index}].inputDigest`),
    outputDigest: optHex64(p.outputDigest, `samProvenance.perPrompt[${index}].outputDigest`),
    detections,
    error: optStr(p.error, `samProvenance.perPrompt[${index}].error`, 2000),
    timeout: p.timeout === true,
    incomplete: p.incomplete === true
  };
}

function projectSamProvenance(sp) {
  if (!sp || typeof sp !== 'object') throw new ManifestError('MANIFEST_INVALID', 'samProvenance: object required');
  if (!Array.isArray(sp.perPrompt)) throw new ManifestError('MANIFEST_INVALID', 'samProvenance.perPrompt: array required');
  return {
    status: assertEnum(sp.status, SAM_AGGREGATE, 'samProvenance.status'),
    mode: sp.mode === null || sp.mode === undefined ? null : assertEnum(sp.mode, ['live', 'mock'], 'samProvenance.mode'),
    configured: optStr(sp.configured, 'samProvenance.configured', 128),
    observed: optStr(sp.observed, 'samProvenance.observed', 128),
    invokedAt: optMs(sp.invokedAt, 'samProvenance.invokedAt'),
    completedAt: optMs(sp.completedAt, 'samProvenance.completedAt'),
    responseId: optStr(sp.responseId, 'samProvenance.responseId', 128),
    usage: sp.usage === null || sp.usage === undefined ? null : sp.usage,
    outputDigest: optHex64(sp.outputDigest, 'samProvenance.outputDigest'),
    screenshotDigest: optHex64(sp.screenshotDigest, 'samProvenance.screenshotDigest'),
    submittedImageDigest: optHex64(sp.submittedImageDigest, 'samProvenance.submittedImageDigest'),
    detectedCount: (!Number.isSafeInteger(sp.detectedCount) || sp.detectedCount < 0)
      ? (() => { throw new ManifestError('MANIFEST_INVALID', 'samProvenance.detectedCount: >= 0 required'); })() : sp.detectedCount,
    perPrompt: sp.perPrompt.map((p, i) => projectSamPrompt(p, i))
  };
}

// Minimal whitelisted agent-request projection. Only the fields
// required to verify association, decision, and execution. Approval
// tokens, pending tokens, normalized transactions, agent evidence,
// purpose text, and owner identity are never included.
function buildRequestProjection(request) {
  if (!request || typeof request !== 'object') throw new ManifestError('MANIFEST_INVALID', 'request: object required');
  const ex = request.execution && typeof request.execution === 'object' ? request.execution : null;
  return {
    id: assertId(request.id, 'request.id'),
    traceId: assertId(request.traceId, 'request.traceId'),
    evalId: request.evalId === null || request.evalId === undefined ? null : assertId(request.evalId, 'request.evalId'),
    status: optStr(request.status, 'request.status', 64),
    decision: request.decision === null || request.decision === undefined ? null : assertEnum(request.decision, DECISIONS, 'request.decision'),
    reasons: Array.isArray(request.reasons) ? request.reasons.map((r) => String(r).slice(0, 2000)) : [],
    txDigest: optHex64(request.txDigest, 'request.txDigest'),
    chainId: (request.normalizedTx && typeof request.normalizedTx === 'object')
      ? normalizeChainId(request.normalizedTx.chainId, 'request.normalizedTx.chainId')
      : null,
    execution: ex === null ? null : {
      outcome: assertEnum(ex.outcome, EXECUTION_OUTCOMES, 'request.execution.outcome'),
      txHash: ex.txHash === null || ex.txHash === undefined ? null : (() => {
        if (typeof ex.txHash !== 'string' || !TX_HASH.test(ex.txHash)) {
          throw new ManifestError('MANIFEST_INVALID', 'request.execution.txHash: 0x 32-byte hash or null');
        }
        return ex.txHash;
      })(),
      receiptStatus: optStr(ex.receiptStatus, 'request.execution.receiptStatus', 16),
      blockNumber: (ex.blockNumber === null || ex.blockNumber === undefined) ? null : String(ex.blockNumber).slice(0, 32)
    }
  };
}

function deriveMuseContribution(muse, record) {
  if (muse.status === 'skipped') return 'NOT_INVOKED';
  if (muse.status !== 'success') return 'INVOKED';
  const hasOutput = record.investigation && typeof record.investigation === 'object' && muse.outputDigest !== null;
  const safeguards = Array.isArray(record.verdictSafeguards) ? record.verdictSafeguards : [];
  if (!hasOutput) return 'SUCCEEDED';
  if (safeguards.length === 0) return 'VERDICT_ACCEPTED';
  return 'OUTPUT_INCLUDED';
}

function allPromptsTimeout(perPrompt) {
  return perPrompt.length > 0 && perPrompt.every((p) => p.status === 'timeout');
}

function deriveSamContribution(sam, record) {
  if (sam.status === 'skipped') return 'NOT_INVOKED';
  if (sam.status === 'mock') return 'MOCK';
  if (sam.status === 'failed') {
    return allPromptsTimeout(sam.perPrompt) ? 'TIMEOUT' : 'FAILED';
  }
  if (sam.status === 'partial') return 'PARTIAL';
  if (sam.outputDigest === null) return 'SUCCEEDED';
  const packing = record.evidencePacking && typeof record.evidencePacking === 'object' ? record.evidencePacking : null;
  const promptIncluded = packing !== null;
  const refVal = record.referenceValidation && typeof record.referenceValidation === 'object' ? record.referenceValidation : null;
  // B3: referenceValidation.present is also set by the heuristic fallback
  // (reasonerService.js) as a vacuous pass — presence alone never proves
  // model output was validated. Only model-origin records may claim it.
  if (record.reasoningOrigin === 'model' && refVal !== null && refVal.present === true) return 'VALIDATED_AGAINST';
  if (promptIncluded) return 'PROMPT_INCLUDED';
  return 'OUTPUT_INCLUDED';
}

// Reconstructs the model's own verdict from the disclosed safeguard
// record: untouched verdicts stand; INVALID_VERDICT normalization names
// its source; any other safeguard means the model said MATCH and a
// deterministic rule moved it. Shared by builder and verifier.
function deriveModelVerdict(safeguards, verdict) {
  if (safeguards.length === 0) return verdict;
  const invalid = safeguards.find((s) => s.trigger === 'INVALID_VERDICT');
  if (invalid && invalid.from) return invalid.from;
  return 'MATCH';
}

function regionsWithheld(record) {
  const packing = record.evidencePacking && typeof record.evidencePacking === 'object' ? record.evidencePacking : null;
  if (!packing || !Array.isArray(packing.truncations)) return 0;
  return packing.truncations
    .filter((t) => t && t.section === 'regions' && Number.isSafeInteger(t.removedChars) && t.removedChars > 0)
    .reduce((n, t) => n + t.removedChars, 0);
}

// B2: cross-field consistency for Muse provenance. Every rule mirrors a
// verified Phase 1 invariant (reasonerService.js builds the prov record,
// evidenceService.js persists it): skipped carries status alone; every
// attempt records invokedAt/inputDigest/completedAt even on failure; only
// the success path sets origin 'model' and any success-only evidence
// (outputDigest, responseId, served model, usage, latency). Provider,
// endpoint, and requested model are config metadata and unconstrained.
// Operates on projection-shaped blocks so the builder (projected record
// values) and the verifier (disclosed values + claimed origin) share it.
function assertMuseConsistency(m, origin, where) {
  const tag = where || 'museProvenance';
  if (!m || typeof m !== 'object') throw new ManifestError('MANIFEST_INVALID', `${tag}: object required`);
  if (m.status === 'skipped') {
    for (const f of ['invokedAt', 'completedAt', 'inputDigest', 'outputDigest', 'responseId', 'served', 'usage', 'latencyMs']) {
      if (m[f] !== null) throw new ManifestError('MANIFEST_INVALID', `${tag}: skipped invocation carries ${f} artifact`);
    }
    if (origin !== 'heuristic-fallback') throw new ManifestError('MANIFEST_INVALID', `${tag}: skipped invocation requires heuristic-fallback origin`);
    return;
  }
  if (m.invokedAt === null || m.inputDigest === null || m.completedAt === null) {
    throw new ManifestError('MANIFEST_INVALID', `${tag}: attempted status '${m.status}' lacks invokedAt/inputDigest/completedAt`);
  }
  if (m.completedAt < m.invokedAt) throw new ManifestError('MANIFEST_INVALID', `${tag}: completedAt precedes invokedAt`);
  if (m.status === 'success') {
    if (m.outputDigest === null) throw new ManifestError('MANIFEST_INVALID', `${tag}: success without outputDigest`);
    if (origin !== 'model') throw new ManifestError('MANIFEST_INVALID', `${tag}: success requires model origin`);
    return;
  }
  for (const f of ['outputDigest', 'responseId', 'served', 'usage', 'latencyMs']) {
    if (m[f] !== null) throw new ManifestError('MANIFEST_INVALID', `${tag}: status '${m.status}' carries success-only ${f}`);
  }
  if (origin !== 'heuristic-fallback') throw new ManifestError('MANIFEST_INVALID', `${tag}: status '${m.status}' requires heuristic-fallback origin`);
}

// B2: cross-field consistency for SAM provenance (samService.js result
// shapes + evidenceService.js persistence, verified field by field).
// Invalid-input prompts carry nulls plus an error; main-loop prompts
// carry full attempt evidence; success/incomplete responses add their
// completion evidence. Aggregates equal first/last per-prompt stamps,
// first-observed provider metadata, and the per-prompt rollup: empty
// prompts only for mock/skipped (empty prompt lists throw in SAM);
// failed means every prompt errored; success means every prompt
// succeeded; partial is the mixed remainder. Detected counts cannot
// exceed summed per-prompt detections (dedupe only removes). The
// screenshot digest is intake evidence (present even when SAM never
// ran) and the configured model is config metadata: unconstrained.
function assertSamConsistency(s, where) {
  const tag = where || 'samProvenance';
  if (!s || typeof s !== 'object') throw new ManifestError('MANIFEST_INVALID', `${tag}: object required`);
  if (!Array.isArray(s.perPrompt)) throw new ManifestError('MANIFEST_INVALID', `${tag}.perPrompt: array required`);
  for (const p of s.perPrompt) {
    const pt = `${tag}.perPrompt[${p && Number.isInteger(p.index) ? p.index : '?'}]`;
    if (!p || typeof p !== 'object') throw new ManifestError('MANIFEST_INVALID', `${pt}: object required`);
    if ((p.inputDigest === null) !== (p.invokedAt === null)) {
      throw new ManifestError('MANIFEST_INVALID', `${pt}: inputDigest and invokedAt must agree (attempted or not)`);
    }
    if ((p.invokedAt === null) !== (p.completedAt === null)) {
      throw new ManifestError('MANIFEST_INVALID', `${pt}: invokedAt and completedAt must agree (attempted or not)`);
    }
    if (p.invokedAt !== null && p.completedAt < p.invokedAt) {
      throw new ManifestError('MANIFEST_INVALID', `${pt}: completedAt precedes invokedAt`);
    }
    if ((p.status === 'timeout') !== (p.timeout === true)) {
      throw new ManifestError('MANIFEST_INVALID', `${pt}: timeout flag must match timeout status`);
    }
    if ((p.status === 'incomplete') !== (p.incomplete === true)) {
      throw new ManifestError('MANIFEST_INVALID', `${pt}: incomplete flag must match incomplete status`);
    }
    if (p.status === 'success') {
      if (p.completedAt === null || p.inputDigest === null || p.outputDigest === null) {
        throw new ManifestError('MANIFEST_INVALID', `${pt}: success lacks completion evidence`);
      }
    } else if (p.status === 'incomplete') {
      if (p.invokedAt === null || p.inputDigest === null) {
        throw new ManifestError('MANIFEST_INVALID', `${pt}: incomplete lacks attempt evidence`);
      }
      if (p.outputDigest !== null || p.error !== null) {
        throw new ManifestError('MANIFEST_INVALID', `${pt}: incomplete claims output or error evidence`);
      }
    } else if (p.status === 'error' || p.status === 'timeout') {
      if (p.error === null) throw new ManifestError('MANIFEST_INVALID', `${pt}: status '${p.status}' without error detail`);
      if (p.outputDigest !== null) throw new ManifestError('MANIFEST_INVALID', `${pt}: status '${p.status}' with outputDigest`);
      if (p.detections !== 0) throw new ManifestError('MANIFEST_INVALID', `${pt}: status '${p.status}' claims detections`);
      // Per-prompt usage is not projected (undefined on projected blocks);
      // a present non-null value on a failed prompt is contradictory.
      if (p.responseId !== null || (p.usage !== null && p.usage !== undefined)) {
        throw new ManifestError('MANIFEST_INVALID', `${pt}: status '${p.status}' with provider metadata`);
      }
    } else {
      throw new ManifestError('MANIFEST_INVALID', `${pt}: unknown per-prompt status '${p.status}'`);
    }
  }
  const n = s.perPrompt.length;
  const allSuccess = n > 0 && s.perPrompt.every((p) => p.status === 'success');
  const allError = n > 0 && s.perPrompt.every((p) => p.error !== null);
  if (n === 0) {
    if (s.status !== 'mock' && s.status !== 'skipped') {
      throw new ManifestError('MANIFEST_INVALID', `${tag}: empty perPrompt requires mock or skipped aggregate status`);
    }
  } else {
    if (s.status === 'mock' || s.status === 'skipped') {
      throw new ManifestError('MANIFEST_INVALID', `${tag}: status '${s.status}' with per-prompt records`);
    }
    if (s.invokedAt !== s.perPrompt[0].invokedAt || s.completedAt !== s.perPrompt[n - 1].completedAt) {
      throw new ManifestError('MANIFEST_INVALID', `${tag}: aggregate stamps must equal first invokedAt / last completedAt`);
    }
  }
  if ((s.status === 'mock') !== (s.mode === 'mock')) {
    throw new ManifestError('MANIFEST_INVALID', `${tag}: mock status and mock mode must agree`);
  }
  if (s.status === 'mock' || s.status === 'skipped') {
    if (s.detectedCount !== 0) throw new ManifestError('MANIFEST_INVALID', `${tag}: status '${s.status}' claims detections`);
    for (const f of ['invokedAt', 'completedAt', 'outputDigest', 'submittedImageDigest', 'responseId', 'usage', 'observed']) {
      if (s[f] !== null) throw new ManifestError('MANIFEST_INVALID', `${tag}: status '${s.status}' carries ${f} artifact`);
    }
    return;
  }
  if (s.status === 'failed') {
    if (!allError) throw new ManifestError('MANIFEST_INVALID', `${tag}: failed requires every prompt to carry an error`);
    if (s.outputDigest !== null || s.detectedCount !== 0) {
      throw new ManifestError('MANIFEST_INVALID', `${tag}: failed claims output evidence`);
    }
    for (const f of ['responseId', 'usage', 'observed']) {
      if (s[f] !== null) throw new ManifestError('MANIFEST_INVALID', `${tag}: failed carries ${f} artifact`);
    }
    return;
  }
  if (s.status === 'success' && !allSuccess) {
    throw new ManifestError('MANIFEST_INVALID', `${tag}: success requires every prompt successful`);
  }
  if (s.status === 'partial' && (allSuccess || allError)) {
    throw new ManifestError('MANIFEST_INVALID', `${tag}: partial requires mixed prompt outcomes`);
  }
  for (const f of ['outputDigest', 'submittedImageDigest', 'invokedAt', 'completedAt']) {
    if (s[f] === null) throw new ManifestError('MANIFEST_INVALID', `${tag}: status '${s.status}' lacks ${f}`);
  }
  if (s.completedAt < s.invokedAt) throw new ManifestError('MANIFEST_INVALID', `${tag}: completedAt precedes invokedAt`);
  const firstObserved = (key) => {
    const found = s.perPrompt.find((p) => p[key] !== null && p[key] !== undefined);
    return found ? found[key] : null;
  };
  if (s.responseId !== firstObserved('responseId')) {
    throw new ManifestError('MANIFEST_INVALID', `${tag}: responseId must be the first per-prompt value`);
  }
  // Per-prompt usage is not projected, so aggregate usage has no
  // per-prompt cross-check; it is integrity-protected but opaque.
  const totalDetections = s.perPrompt.reduce((t, p) => t + p.detections, 0);
  if (s.detectedCount > totalDetections) {
    throw new ManifestError('MANIFEST_INVALID', `${tag}: detectedCount exceeds summed per-prompt detections`);
  }
}

function buildManifest({ record, request }) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new ManifestError('MANIFEST_UNAVAILABLE', 'persisted investigation record required');
  }
  assertValidInput(record, 'record');
  if (request !== null && request !== undefined) {
    if (typeof request !== 'object' || Array.isArray(request)) {
      throw new ManifestError('MANIFEST_INVALID', 'request: object or null required');
    }
    assertValidInput(request, 'request');
  }
  const req = request === undefined ? null : request;

  // Cross-checks bind exactly one investigation: any mismatch refuses.
  const mismatch = (msg) => { throw new ManifestError('MANIFEST_MISMATCH', msg); };
  if (req !== null) {
    if (req.id !== record.requestId) mismatch('request.id !== record.requestId');
    if (typeof req.traceId !== 'string' || req.traceId !== record.traceId) mismatch('request.traceId !== record.traceId');
    if (typeof req.evalId === 'string' && req.evalId !== record.id) mismatch('request.evalId !== record.id');
    if (typeof req.txDigest === 'string' && record.txBinding && typeof record.txBinding.evaluatedTxDigest === 'string'
        && req.txDigest.toLowerCase() !== record.txBinding.evaluatedTxDigest.toLowerCase()) {
      mismatch('request.txDigest !== record evaluatedTxDigest');
    }
    if (typeof req.evalVerdict === 'string' && req.evalVerdict !== record.verdict) mismatch('request.evalVerdict !== record.verdict');
  }

  const publicProjection = buildPublicProjection(record);
  const requestProjection = req === null ? null : buildRequestProjection(req);
  if (req !== null && requestProjection.chainId !== null && requestProjection.chainId !== publicProjection.chainId) {
    mismatch('request chainId !== record chainId');
  }

  // B2: cross-field consistency refuses contradictory provenance
  // instead of manifesting it. Output claims additionally require the
  // persisted regions array (evidenceService.js always persists one).
  assertMuseConsistency(publicProjection.museProvenance, record.reasoningOrigin, 'record.museProvenance');
  assertSamConsistency(publicProjection.samProvenance, 'record.samProvenance');
  if (publicProjection.samProvenance.outputDigest !== null) {
    const regions = record.visualEvidence && record.visualEvidence.regions;
    if (!Array.isArray(regions)) {
      throw new ManifestError('MANIFEST_INVALID', 'record.samProvenance: output claimed without persisted visualEvidence.regions array');
    }
  }

  // Muse contribution (projected block carries validated fields).
  const muse = publicProjection.museProvenance;
  const museContribution = deriveMuseContribution(muse, record);
  const modelVerdict = deriveModelVerdict(publicProjection.verdictSafeguards, publicProjection.verdict);

  // SAM contribution + prompt-inclusion counts.
  const sam = publicProjection.samProvenance;
  const withheld = regionsWithheld(record);
  const samContribution = deriveSamContribution(sam, record);

  // Transaction binding: hash only from a verified execution record.
  // BLOCK / unreleased REVIEW / absent / pending / MISMATCH → null.
  let transactionHash = null;
  let executionStatus = null;
  let receiptStatus = null;
  let blockNumber = null;
  if (requestProjection !== null && requestProjection.execution !== null) {
    const ex = requestProjection.execution;
    executionStatus = ex.outcome;
    receiptStatus = ex.receiptStatus;
    blockNumber = ex.blockNumber;
    if (HASHABLE_OUTCOMES.includes(ex.outcome) && ex.txHash !== null) {
      transactionHash = ex.txHash;
    }
  }
  const txBinding = publicProjection.txBinding;

  const manifest = {
    schemaVersion: SCHEMA_VERSION,
    investigationId: publicProjection.evalId,
    traceId: publicProjection.traceId,
    requestId: publicProjection.requestId,
    evidence: {
      available: true,
      digest: sha256Hex(canonicalStringify(record)),
      publicDigest: sha256Hex(canonicalStringify(publicProjection))
    },
    request: {
      available: requestProjection !== null,
      digest: requestProjection === null ? null : sha256Hex(canonicalStringify(requestProjection))
    },
    modelCalls: {
      museSpark: {
        provider: muse.provider,
        endpoint: muse.endpoint,
        configuredModel: muse.requested,
        observedModel: muse.served,
        status: muse.status,
        contribution: museContribution,
        invokedAt: muse.invokedAt,
        completedAt: muse.completedAt,
        responseId: muse.responseId,
        inputDigest: muse.inputDigest,
        outputDigest: muse.outputDigest,
        latencyMs: muse.latencyMs,
        usage: muse.usage,
        modelVerdict,
        verdictAccepted: museContribution === 'VERDICT_ACCEPTED'
      },
      sam: {
        configuredModel: sam.configured,
        observedModel: sam.observed,
        aggregateStatus: sam.status,
        mode: sam.mode,
        contribution: samContribution,
        invokedAt: sam.invokedAt,
        completedAt: sam.completedAt,
        responseId: sam.responseId,
        usage: sam.usage,
        screenshotDigest: sam.screenshotDigest,
        submittedImageDigest: sam.submittedImageDigest,
        outputDigest: sam.outputDigest,
        detectedCount: sam.detectedCount,
        regionsInPrompt: Math.max(publicProjection.regionsDisclosed - withheld, 0),
        regionsWithheld: withheld,
        refsValidated: publicProjection.referenceValidation.present === true,
        prompts: sam.perPrompt.map((p) => ({
          index: p.index,
          prompt: p.prompt,
          status: p.status,
          invokedAt: p.invokedAt,
          completedAt: p.completedAt,
          responseId: p.responseId,
          inputDigest: p.inputDigest,
          outputDigest: p.outputDigest,
          detections: p.detections,
          error: p.error,
          timeout: p.timeout,
          incomplete: p.incomplete
        }))
      }
    },
    decision: {
      agent: requestProjection !== null ? requestProjection.decision : null,
      evaluation: publicProjection.policyDecision !== null ? publicProjection.policyDecision.decision : null,
      evalVerdict: publicProjection.verdict,
      reasoningOrigin: (record.reasoningOrigin === 'model' || record.reasoningOrigin === 'heuristic-fallback')
        ? record.reasoningOrigin
        : (() => { throw new ManifestError('MANIFEST_INVALID', 'record.reasoningOrigin: model|heuristic-fallback required'); })()
    },
    transaction: {
      chainId: publicProjection.chainId,
      transactionDigest: txBinding !== null ? txBinding.evaluatedTxDigest : null,
      digestMatch: txBinding !== null ? txBinding.match : null,
      transactionHash,
      executionStatus,
      receiptStatus,
      blockNumber
    }
  };
  if (manifest.transaction.transactionDigest === null) {
    throw new ManifestError('MANIFEST_UNAVAILABLE', 'record lacks an evaluated transaction digest; cannot bind');
  }
  // Self-check: builder output must satisfy the same semantics and
  // linkage the verifier enforces (B1 drift guard).
  assertManifestSemantics(manifest);
  checkManifestLinkage(manifest, publicProjection, requestProjection);
  assertValidInput(manifest, 'manifest');
  const manifestDigest = sha256Hex(canonicalStringify(manifest));
  return {
    manifest,
    manifestDigest,
    publicProjection,
    requestProjection,
    envelope: {
      manifestDigest,
      createdAt: Date.now(),
      builderVersion: BUILDER_VERSION
    }
  };
}

// B1: semantic validation for judge-side verification. Digests prove
// bytes match; these checks prove the bytes mean something coherent:
// exact schema shapes, enums, digest/timestamp formats, prompt
// sequences, provenance consistency on disclosed evidence, contribution
// claims re-derived from that evidence, and manifest-to-projection
// linkage. Anything failing here fails closed even when every digest
// recomputes. The builder self-checks its own output with the same
// functions so builder/verifier drift fails loudly at build time.
function assertExactKeys(obj, keys, name) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new ManifestError('MANIFEST_INVALID', `${name}: object required`);
  }
  const actual = Object.keys(obj).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((k, i) => k !== expected[i])) {
    throw new ManifestError('MANIFEST_INVALID', `${name}: unexpected shape (exactly {${expected.join(',')}})`);
  }
}

function assertLatencyMs(v, name) {
  if (v === null || v === undefined) return null;
  if (!Number.isSafeInteger(v) || v < 0) throw new ManifestError('MANIFEST_INVALID', `${name}: ms >= 0 or null`);
  return v;
}

function assertPositiveInt(v, name) {
  req(v, name);
  if (!Number.isSafeInteger(v) || v <= 0) throw new ManifestError('MANIFEST_INVALID', `${name}: positive integer required`);
  return v;
}

function assertCount(v, name) {
  if (!Number.isSafeInteger(v) || v < 0) throw new ManifestError('MANIFEST_INVALID', `${name}: integer >= 0 required`);
  return v;
}

function assertManifestSemantics(m) {
  assertExactKeys(m, ['schemaVersion', 'investigationId', 'traceId', 'requestId', 'evidence', 'request', 'modelCalls', 'decision', 'transaction'], 'manifest');
  if (m.schemaVersion !== SCHEMA_VERSION) throw new ManifestError('MANIFEST_INVALID', 'manifest.schemaVersion: unknown version');
  assertId(m.investigationId, 'manifest.investigationId');
  assertId(m.traceId, 'manifest.traceId');
  if (m.requestId !== null && m.requestId !== undefined) assertId(m.requestId, 'manifest.requestId');
  assertExactKeys(m.evidence, ['available', 'digest', 'publicDigest'], 'manifest.evidence');
  if (m.evidence.available !== true) throw new ManifestError('MANIFEST_INVALID', 'manifest.evidence.available: true required');
  assertHex64(m.evidence.digest, 'manifest.evidence.digest');
  assertHex64(m.evidence.publicDigest, 'manifest.evidence.publicDigest');
  assertExactKeys(m.request, ['available', 'digest'], 'manifest.request');
  if (typeof m.request.available !== 'boolean') throw new ManifestError('MANIFEST_INVALID', 'manifest.request.available: boolean required');
  if (m.request.available === true) assertHex64(m.request.digest, 'manifest.request.digest');
  else if (m.request.digest !== null) throw new ManifestError('MANIFEST_INVALID', 'manifest.request.digest: null required when unavailable');
  assertExactKeys(m.modelCalls, ['museSpark', 'sam'], 'manifest.modelCalls');
  const ms = m.modelCalls.museSpark;
  assertExactKeys(ms, ['provider', 'endpoint', 'configuredModel', 'observedModel', 'status', 'contribution', 'invokedAt', 'completedAt', 'responseId', 'inputDigest', 'outputDigest', 'latencyMs', 'usage', 'modelVerdict', 'verdictAccepted'], 'manifest.modelCalls.museSpark');
  optStr(ms.provider, 'manifest.modelCalls.museSpark.provider', 64);
  optStr(ms.endpoint, 'manifest.modelCalls.museSpark.endpoint', 64);
  optStr(ms.configuredModel, 'manifest.modelCalls.museSpark.configuredModel', 128);
  optStr(ms.observedModel, 'manifest.modelCalls.museSpark.observedModel', 128);
  assertEnum(ms.status, MUSE_STATUSES, 'manifest.modelCalls.museSpark.status');
  assertEnum(ms.contribution, MUSE_CONTRIBUTIONS, 'manifest.modelCalls.museSpark.contribution');
  optMs(ms.invokedAt, 'manifest.modelCalls.museSpark.invokedAt');
  optMs(ms.completedAt, 'manifest.modelCalls.museSpark.completedAt');
  optStr(ms.responseId, 'manifest.modelCalls.museSpark.responseId', 128);
  optHex64(ms.inputDigest, 'manifest.modelCalls.museSpark.inputDigest');
  optHex64(ms.outputDigest, 'manifest.modelCalls.museSpark.outputDigest');
  assertLatencyMs(ms.latencyMs, 'manifest.modelCalls.museSpark.latencyMs');
  // usage is integrity-protected but schema-opaque (existing limitation).
  if (typeof ms.modelVerdict !== 'string' || ms.modelVerdict.length === 0 || ms.modelVerdict.length > 64) {
    throw new ManifestError('MANIFEST_INVALID', 'manifest.modelCalls.museSpark.modelVerdict: string 1..64 required');
  }
  if (typeof ms.verdictAccepted !== 'boolean') throw new ManifestError('MANIFEST_INVALID', 'manifest.modelCalls.museSpark.verdictAccepted: boolean required');
  const sm = m.modelCalls.sam;
  assertExactKeys(sm, ['configuredModel', 'observedModel', 'aggregateStatus', 'mode', 'contribution', 'invokedAt', 'completedAt', 'responseId', 'usage', 'screenshotDigest', 'submittedImageDigest', 'outputDigest', 'detectedCount', 'regionsInPrompt', 'regionsWithheld', 'refsValidated', 'prompts'], 'manifest.modelCalls.sam');
  optStr(sm.configuredModel, 'manifest.modelCalls.sam.configuredModel', 128);
  optStr(sm.observedModel, 'manifest.modelCalls.sam.observedModel', 128);
  assertEnum(sm.aggregateStatus, SAM_AGGREGATE, 'manifest.modelCalls.sam.aggregateStatus');
  if (sm.mode !== null && sm.mode !== undefined) assertEnum(sm.mode, ['live', 'mock'], 'manifest.modelCalls.sam.mode');
  assertEnum(sm.contribution, SAM_CONTRIBUTIONS, 'manifest.modelCalls.sam.contribution');
  optMs(sm.invokedAt, 'manifest.modelCalls.sam.invokedAt');
  optMs(sm.completedAt, 'manifest.modelCalls.sam.completedAt');
  optStr(sm.responseId, 'manifest.modelCalls.sam.responseId', 128);
  optHex64(sm.screenshotDigest, 'manifest.modelCalls.sam.screenshotDigest');
  optHex64(sm.submittedImageDigest, 'manifest.modelCalls.sam.submittedImageDigest');
  optHex64(sm.outputDigest, 'manifest.modelCalls.sam.outputDigest');
  assertCount(sm.detectedCount, 'manifest.modelCalls.sam.detectedCount');
  assertCount(sm.regionsInPrompt, 'manifest.modelCalls.sam.regionsInPrompt');
  assertCount(sm.regionsWithheld, 'manifest.modelCalls.sam.regionsWithheld');
  if (typeof sm.refsValidated !== 'boolean') throw new ManifestError('MANIFEST_INVALID', 'manifest.modelCalls.sam.refsValidated: boolean required');
  if (!Array.isArray(sm.prompts)) throw new ManifestError('MANIFEST_INVALID', 'manifest.modelCalls.sam.prompts: array required');
  sm.prompts.forEach((p, i) => {
    const pn = `manifest.modelCalls.sam.prompts[${i}]`;
    assertExactKeys(p, ['index', 'prompt', 'status', 'invokedAt', 'completedAt', 'responseId', 'inputDigest', 'outputDigest', 'detections', 'error', 'timeout', 'incomplete'], pn);
    if (p.index !== i) throw new ManifestError('MANIFEST_INVALID', `${pn}: index sequence broken`);
    assertId(p.prompt, `${pn}.prompt`);
    assertEnum(p.status, SAM_PROMPT_STATUSES, `${pn}.status`);
    optMs(p.invokedAt, `${pn}.invokedAt`);
    optMs(p.completedAt, `${pn}.completedAt`);
    optStr(p.responseId, `${pn}.responseId`, 128);
    optHex64(p.inputDigest, `${pn}.inputDigest`);
    optHex64(p.outputDigest, `${pn}.outputDigest`);
    assertCount(p.detections, `${pn}.detections`);
    optStr(p.error, `${pn}.error`, 2000);
    if (typeof p.timeout !== 'boolean' || typeof p.incomplete !== 'boolean') {
      throw new ManifestError('MANIFEST_INVALID', `${pn}: timeout/incomplete booleans required`);
    }
  });
  assertExactKeys(m.decision, ['agent', 'evaluation', 'evalVerdict', 'reasoningOrigin'], 'manifest.decision');
  if (m.decision.agent !== null && m.decision.agent !== undefined) assertEnum(m.decision.agent, DECISIONS, 'manifest.decision.agent');
  if (m.decision.evaluation !== null && m.decision.evaluation !== undefined) assertEnum(m.decision.evaluation, DECISIONS, 'manifest.decision.evaluation');
  assertEnum(m.decision.evalVerdict, VERDICTS, 'manifest.decision.evalVerdict');
  assertEnum(m.decision.reasoningOrigin, REASONING_ORIGINS, 'manifest.decision.reasoningOrigin');
  assertExactKeys(m.transaction, ['chainId', 'transactionDigest', 'digestMatch', 'transactionHash', 'executionStatus', 'receiptStatus', 'blockNumber'], 'manifest.transaction');
  assertPositiveInt(m.transaction.chainId, 'manifest.transaction.chainId');
  optHex64(m.transaction.transactionDigest, 'manifest.transaction.transactionDigest');
  if (m.transaction.digestMatch !== null && m.transaction.digestMatch !== undefined && typeof m.transaction.digestMatch !== 'boolean') {
    throw new ManifestError('MANIFEST_INVALID', 'manifest.transaction.digestMatch: boolean or null');
  }
  if (m.transaction.transactionHash !== null && m.transaction.transactionHash !== undefined) {
    if (typeof m.transaction.transactionHash !== 'string' || !TX_HASH.test(m.transaction.transactionHash)) {
      throw new ManifestError('MANIFEST_INVALID', 'manifest.transaction.transactionHash: 0x 32-byte hash or null');
    }
  }
  if (m.transaction.executionStatus !== null && m.transaction.executionStatus !== undefined) {
    assertEnum(m.transaction.executionStatus, EXECUTION_OUTCOMES, 'manifest.transaction.executionStatus');
  }
  optStr(m.transaction.receiptStatus, 'manifest.transaction.receiptStatus', 16);
  if (m.transaction.blockNumber !== null && m.transaction.blockNumber !== undefined) {
    if (typeof m.transaction.blockNumber !== 'string' || m.transaction.blockNumber.length > 32) {
      throw new ManifestError('MANIFEST_INVALID', 'manifest.transaction.blockNumber: string ≤32 or null');
    }
  }
}

function assertPublicProjectionShape(pp) {
  assertExactKeys(pp, ['recordId', 'evalId', 'traceId', 'requestId', 'recordedAt', 'investigationPath', 'chainId', 'sender', 'to', 'verdict', 'confidence', 'recommendedAction', 'policyDecision', 'verdictSafeguards', 'txBinding', 'decodedTransaction', 'ruleIds', 'museProvenance', 'samProvenance', 'regionsDisclosed', 'packingTruncations', 'referenceValidation'], 'publicProjection');
  assertId(pp.recordId, 'publicProjection.recordId');
  assertId(pp.evalId, 'publicProjection.evalId');
  assertId(pp.traceId, 'publicProjection.traceId');
  if (pp.requestId !== null && pp.requestId !== undefined) assertId(pp.requestId, 'publicProjection.requestId');
  assertMs(pp.recordedAt, 'publicProjection.recordedAt');
  assertEnum(pp.investigationPath, ['browser', 'agent'], 'publicProjection.investigationPath');
  assertPositiveInt(pp.chainId, 'publicProjection.chainId');
  optStr(pp.sender, 'publicProjection.sender', 64);
  optStr(pp.to, 'publicProjection.to', 64);
  assertEnum(pp.verdict, VERDICTS, 'publicProjection.verdict');
  if (pp.confidence !== null && pp.confidence !== undefined && !(typeof pp.confidence === 'number' && Number.isFinite(pp.confidence))) {
    throw new ManifestError('MANIFEST_INVALID', 'publicProjection.confidence: finite number or null');
  }
  optStr(pp.recommendedAction, 'publicProjection.recommendedAction', 64);
  if (pp.policyDecision !== null && pp.policyDecision !== undefined) {
    assertExactKeys(pp.policyDecision, ['decision', 'reasons'], 'publicProjection.policyDecision');
    assertEnum(pp.policyDecision.decision, DECISIONS, 'publicProjection.policyDecision.decision');
    if (!Array.isArray(pp.policyDecision.reasons)) throw new ManifestError('MANIFEST_INVALID', 'publicProjection.policyDecision.reasons: array required');
    pp.policyDecision.reasons.forEach((r, i) => {
      if (typeof r !== 'string' || r.length > 2000) throw new ManifestError('MANIFEST_INVALID', `publicProjection.policyDecision.reasons[${i}]: string ≤2000 required`);
    });
  }
  if (!Array.isArray(pp.verdictSafeguards)) throw new ManifestError('MANIFEST_INVALID', 'publicProjection.verdictSafeguards: array required');
  pp.verdictSafeguards.forEach((s, i) => {
    assertExactKeys(s, ['trigger', 'from', 'to'], `publicProjection.verdictSafeguards[${i}]`);
    assertId(s.trigger, `publicProjection.verdictSafeguards[${i}].trigger`);
    optStr(s.from, `publicProjection.verdictSafeguards[${i}].from`, 64);
    optStr(s.to, `publicProjection.verdictSafeguards[${i}].to`, 64);
  });
  if (pp.txBinding !== null && pp.txBinding !== undefined) {
    assertExactKeys(pp.txBinding, ['receivedTxDigest', 'evaluatedTxDigest', 'match'], 'publicProjection.txBinding');
    optHex64(pp.txBinding.receivedTxDigest, 'publicProjection.txBinding.receivedTxDigest');
    optHex64(pp.txBinding.evaluatedTxDigest, 'publicProjection.txBinding.evaluatedTxDigest');
    if (pp.txBinding.match !== null && pp.txBinding.match !== undefined && typeof pp.txBinding.match !== 'boolean') {
      throw new ManifestError('MANIFEST_INVALID', 'publicProjection.txBinding.match: boolean or null');
    }
  }
  if (pp.decodedTransaction !== null && pp.decodedTransaction !== undefined) {
    assertExactKeys(pp.decodedTransaction, ['contract', 'contractName', 'functionName', 'standard', 'valueEth', 'isUnlimitedApproval'], 'publicProjection.decodedTransaction');
    optStr(pp.decodedTransaction.contract, 'publicProjection.decodedTransaction.contract', 64);
    optStr(pp.decodedTransaction.contractName, 'publicProjection.decodedTransaction.contractName', 128);
    optStr(pp.decodedTransaction.functionName, 'publicProjection.decodedTransaction.functionName', 128);
    optStr(pp.decodedTransaction.standard, 'publicProjection.decodedTransaction.standard', 64);
    optStr(pp.decodedTransaction.valueEth, 'publicProjection.decodedTransaction.valueEth', 64);
    if (typeof pp.decodedTransaction.isUnlimitedApproval !== 'boolean') {
      throw new ManifestError('MANIFEST_INVALID', 'publicProjection.decodedTransaction.isUnlimitedApproval: boolean required');
    }
  }
  if (!Array.isArray(pp.ruleIds)) throw new ManifestError('MANIFEST_INVALID', 'publicProjection.ruleIds: array required');
  pp.ruleIds.forEach((r, i) => {
    if (typeof r !== 'string' || r.length > 128) throw new ManifestError('MANIFEST_INVALID', `publicProjection.ruleIds[${i}]: string ≤128 required`);
  });
  // Provenance blocks must be exactly valid projections: re-running the
  // projectors re-validates every enum/digest/timestamp/sequence and the
  // byte comparison rejects smuggled extra fields.
  if (canonicalStringify(projectMuseProvenance(pp.museProvenance)) !== canonicalStringify(pp.museProvenance)) {
    throw new ManifestError('MANIFEST_INVALID', 'publicProjection.museProvenance: not an exact valid projection');
  }
  if (canonicalStringify(projectSamProvenance(pp.samProvenance)) !== canonicalStringify(pp.samProvenance)) {
    throw new ManifestError('MANIFEST_INVALID', 'publicProjection.samProvenance: not an exact valid projection');
  }
  assertCount(pp.regionsDisclosed, 'publicProjection.regionsDisclosed');
  if (!Array.isArray(pp.packingTruncations)) throw new ManifestError('MANIFEST_INVALID', 'publicProjection.packingTruncations: array required');
  pp.packingTruncations.forEach((t, i) => {
    assertExactKeys(t, ['section', 'removed'], `publicProjection.packingTruncations[${i}]`);
    if (typeof t.section !== 'string' || t.section.length > 64) {
      throw new ManifestError('MANIFEST_INVALID', `publicProjection.packingTruncations[${i}].section: string ≤64 required`);
    }
    if (!Number.isSafeInteger(t.removed)) throw new ManifestError('MANIFEST_INVALID', `publicProjection.packingTruncations[${i}].removed: integer required`);
  });
  assertExactKeys(pp.referenceValidation, ['present', 'ok'], 'publicProjection.referenceValidation');
  if (typeof pp.referenceValidation.present !== 'boolean') {
    throw new ManifestError('MANIFEST_INVALID', 'publicProjection.referenceValidation.present: boolean required');
  }
  if (pp.referenceValidation.ok !== null && pp.referenceValidation.ok !== undefined && typeof pp.referenceValidation.ok !== 'boolean') {
    throw new ManifestError('MANIFEST_INVALID', 'publicProjection.referenceValidation.ok: boolean or null');
  }
}

// The disclosed request projection must be exactly the whitelisted
// shape: rebuilding it through the projector re-validates every field
// and the byte comparison proves no secret or extra field was added.
function assertDisclosedRequestProjection(rp) {
  if (!rp || typeof rp !== 'object' || Array.isArray(rp)) {
    throw new ManifestError('MANIFEST_INVALID', 'requestProjection: object required');
  }
  const rebuilt = buildRequestProjection({
    id: rp.id,
    traceId: rp.traceId,
    evalId: rp.evalId,
    status: rp.status,
    decision: rp.decision,
    reasons: rp.reasons,
    txDigest: rp.txDigest,
    normalizedTx: rp.chainId === null || rp.chainId === undefined ? undefined : { chainId: rp.chainId },
    execution: rp.execution
  });
  if (canonicalStringify(rebuilt) !== canonicalStringify(rp)) {
    throw new ManifestError('MANIFEST_INVALID', 'requestProjection: not an exact whitelisted projection');
  }
}

// Re-derives the Muse contribution claim from disclosed evidence.
// Terminal levels are exact; success-path levels narrow to the set the
// disclosed evidence supports (persisted-investigation presence is
// undisclosed, so SUCCEEDED admits the company of the two levels above
// it — but the safeguard record still excludes one level each way).
function checkMuseContributionClaim(m, mp, safeguards, verdict) {
  if (mp.status === 'skipped' && m.contribution !== 'NOT_INVOKED') {
    throw new ManifestError('MANIFEST_INVALID', 'museSpark.contribution contradicts skipped status');
  }
  if (m.contribution === 'NOT_INVOKED' && mp.status !== 'skipped') {
    throw new ManifestError('MANIFEST_INVALID', 'museSpark.contribution NOT_INVOKED contradicts attempted status');
  }
  if (mp.status !== 'success' && mp.status !== 'skipped' && m.contribution !== 'INVOKED') {
    throw new ManifestError('MANIFEST_INVALID', `museSpark.contribution contradicts status '${mp.status}'`);
  }
  if (m.contribution === 'INVOKED' && (mp.status === 'success' || mp.status === 'skipped')) {
    throw new ManifestError('MANIFEST_INVALID', 'museSpark.contribution INVOKED contradicts terminal status');
  }
  if (mp.status === 'success') {
    if (!['SUCCEEDED', 'OUTPUT_INCLUDED', 'VERDICT_ACCEPTED'].includes(m.contribution)) {
      throw new ManifestError('MANIFEST_INVALID', 'museSpark.contribution contradicts success status');
    }
    if (m.contribution === 'OUTPUT_INCLUDED' && safeguards.length === 0) {
      throw new ManifestError('MANIFEST_INVALID', 'museSpark OUTPUT_INCLUDED requires safeguard evidence');
    }
    if (m.contribution === 'VERDICT_ACCEPTED' && safeguards.length !== 0) {
      throw new ManifestError('MANIFEST_INVALID', 'museSpark VERDICT_ACCEPTED contradicts safeguard evidence');
    }
  }
  if (m.verdictAccepted !== (m.contribution === 'VERDICT_ACCEPTED')) {
    throw new ManifestError('MANIFEST_INVALID', 'museSpark.verdictAccepted contradicts contribution');
  }
  if (m.modelVerdict !== deriveModelVerdict(safeguards, verdict)) {
    throw new ManifestError('MANIFEST_INVALID', 'museSpark.modelVerdict contradicts safeguard record');
  }
}

// Re-derives the SAM contribution claim from disclosed evidence.
// Terminal levels are exact (TIMEOUT re-derives from per-prompt
// statuses); packing presence is undisclosed, so OUTPUT_INCLUDED and
// PROMPT_INCLUDED are mutually indistinguishable here — but both are
// excluded when validation evidence is present, and VALIDATED_AGAINST
// additionally requires the model-origin claim and output evidence.
function checkSamContributionClaim(s, sp, refPresent, origin) {
  if (sp.status === 'skipped' && s.contribution !== 'NOT_INVOKED') {
    throw new ManifestError('MANIFEST_INVALID', 'sam.contribution contradicts skipped status');
  }
  if (s.contribution === 'NOT_INVOKED' && sp.status !== 'skipped') {
    throw new ManifestError('MANIFEST_INVALID', 'sam.contribution NOT_INVOKED contradicts attempted status');
  }
  if (sp.status === 'mock' && s.contribution !== 'MOCK') {
    throw new ManifestError('MANIFEST_INVALID', 'sam.contribution contradicts mock status');
  }
  if (s.contribution === 'MOCK' && sp.status !== 'mock') {
    throw new ManifestError('MANIFEST_INVALID', 'sam.contribution MOCK contradicts non-mock status');
  }
  if (sp.status === 'partial' && s.contribution !== 'PARTIAL') {
    throw new ManifestError('MANIFEST_INVALID', 'sam.contribution contradicts partial status');
  }
  if (s.contribution === 'PARTIAL' && sp.status !== 'partial') {
    throw new ManifestError('MANIFEST_INVALID', 'sam.contribution PARTIAL contradicts non-partial status');
  }
  if (sp.status === 'failed' && s.contribution !== (allPromptsTimeout(sp.perPrompt) ? 'TIMEOUT' : 'FAILED')) {
    throw new ManifestError('MANIFEST_INVALID', 'sam.contribution contradicts failed per-prompt evidence');
  }
  if ((s.contribution === 'FAILED' || s.contribution === 'TIMEOUT') && sp.status !== 'failed') {
    throw new ManifestError('MANIFEST_INVALID', `sam.contribution ${s.contribution} contradicts non-failed status`);
  }
  if (sp.status === 'success') {
    if (sp.outputDigest === null && s.contribution !== 'SUCCEEDED') {
      throw new ManifestError('MANIFEST_INVALID', 'sam.contribution contradicts success without output');
    }
    if (sp.outputDigest !== null && !['OUTPUT_INCLUDED', 'PROMPT_INCLUDED', 'VALIDATED_AGAINST'].includes(s.contribution)) {
      throw new ManifestError('MANIFEST_INVALID', 'sam.contribution contradicts success with output');
    }
    if (s.contribution === 'SUCCEEDED' && sp.outputDigest !== null) {
      throw new ManifestError('MANIFEST_INVALID', 'sam.contribution SUCCEEDED contradicts output evidence');
    }
    if ((s.contribution === 'OUTPUT_INCLUDED' || s.contribution === 'PROMPT_INCLUDED') && refPresent === true) {
      throw new ManifestError('MANIFEST_INVALID', `sam.contribution ${s.contribution} contradicts validation evidence`);
    }
    if (s.contribution === 'VALIDATED_AGAINST' && !(refPresent === true && sp.outputDigest !== null && origin === 'model')) {
      throw new ManifestError('MANIFEST_INVALID', 'sam.contribution VALIDATED_AGAINST lacks validation evidence');
    }
  }
  if (['SUCCEEDED', 'OUTPUT_INCLUDED', 'PROMPT_INCLUDED', 'VALIDATED_AGAINST'].includes(s.contribution) && sp.status !== 'success') {
    throw new ManifestError('MANIFEST_INVALID', `sam.contribution ${s.contribution} contradicts non-success status`);
  }
  // Authorized levels the builder never emits: no disclosed evidence
  // can support them, so any such claim is unsupported by definition.
  if (s.contribution === 'INVOKED' || s.contribution === 'INCOMPLETE') {
    throw new ManifestError('MANIFEST_INVALID', `sam.contribution ${s.contribution} is not derivable from disclosed evidence`);
  }
}

// Every manifest field copied or derived from the projections must
// equal its recomputed value: copied provenance, safeguard-derived
// verdict accounting, packing-derived region counts, validation flags,
// decisions, and the transaction-binding rule.
function checkManifestLinkage(m, pp, rp) {
  const bad = (msg) => { throw new ManifestError('MANIFEST_INVALID', msg); };
  if (m.investigationId !== pp.evalId) bad('manifest.investigationId !== publicProjection.evalId');
  if (m.traceId !== pp.traceId) bad('manifest.traceId !== publicProjection.traceId');
  if (m.requestId !== pp.requestId) bad('manifest.requestId !== publicProjection.requestId');
  const ms = m.modelCalls.museSpark;
  const mp = pp.museProvenance;
  for (const f of ['provider', 'endpoint', 'status', 'invokedAt', 'completedAt', 'responseId', 'inputDigest', 'outputDigest', 'latencyMs']) {
    if (ms[f] !== mp[f]) bad(`manifest.modelCalls.museSpark.${f} !== disclosed projection value`);
  }
  if (ms.configuredModel !== mp.requested) bad('manifest museSpark.configuredModel !== disclosed requested model');
  if (ms.observedModel !== mp.served) bad('manifest museSpark.observedModel !== disclosed served model');
  if (canonicalStringify(ms.usage) !== canonicalStringify(mp.usage)) bad('manifest museSpark.usage !== disclosed projection value');
  const sm = m.modelCalls.sam;
  const sp = pp.samProvenance;
  if (sm.configuredModel !== sp.configured) bad('manifest sam.configuredModel !== disclosed projection value');
  if (sm.observedModel !== sp.observed) bad('manifest sam.observedModel !== disclosed projection value');
  if (sm.aggregateStatus !== sp.status) bad('manifest sam.aggregateStatus !== disclosed projection value');
  if (sm.mode !== sp.mode) bad('manifest sam.mode !== disclosed projection value');
  for (const f of ['invokedAt', 'completedAt', 'responseId', 'screenshotDigest', 'submittedImageDigest', 'outputDigest', 'detectedCount']) {
    if (sm[f] !== sp[f]) bad(`manifest.modelCalls.sam.${f} !== disclosed projection value`);
  }
  if (canonicalStringify(sm.usage) !== canonicalStringify(sp.usage)) bad('manifest sam.usage !== disclosed projection value');
  if (canonicalStringify(sm.prompts) !== canonicalStringify(sp.perPrompt)) bad('manifest sam.prompts !== disclosed projection values');
  const withheld = pp.packingTruncations
    .filter((t) => t.section === 'regions' && t.removed > 0)
    .reduce((n, t) => n + t.removed, 0);
  if (sm.regionsWithheld !== withheld) bad('manifest sam.regionsWithheld contradicts packing evidence');
  if (sm.regionsInPrompt !== Math.max(pp.regionsDisclosed - withheld, 0)) bad('manifest sam.regionsInPrompt contradicts packing evidence');
  if (sm.refsValidated !== (pp.referenceValidation.present === true)) bad('manifest sam.refsValidated contradicts validation evidence');
  if (m.decision.agent !== (rp ? rp.decision : null)) bad('manifest.decision.agent !== disclosed request decision');
  if (m.decision.evaluation !== (pp.policyDecision ? pp.policyDecision.decision : null)) bad('manifest.decision.evaluation !== disclosed policy decision');
  if (m.decision.evalVerdict !== pp.verdict) bad('manifest.decision.evalVerdict !== disclosed verdict');
  if (m.transaction.chainId !== pp.chainId) bad('manifest.transaction.chainId !== disclosed chainId');
  if (m.transaction.transactionDigest !== (pp.txBinding ? pp.txBinding.evaluatedTxDigest : null)) {
    bad('manifest.transaction.transactionDigest !== disclosed txBinding value');
  }
  if (m.transaction.digestMatch !== (pp.txBinding ? pp.txBinding.match : null)) {
    bad('manifest.transaction.digestMatch !== disclosed txBinding value');
  }
  const ex = rp && rp.execution ? rp.execution : null;
  if (m.transaction.executionStatus !== (ex ? ex.outcome : null)) bad('manifest.transaction.executionStatus !== disclosed execution value');
  if (m.transaction.receiptStatus !== (ex ? ex.receiptStatus : null)) bad('manifest.transaction.receiptStatus !== disclosed execution value');
  if (m.transaction.blockNumber !== (ex ? ex.blockNumber : null)) bad('manifest.transaction.blockNumber !== disclosed execution value');
  const expectedHash = (ex && HASHABLE_OUTCOMES.includes(ex.outcome) && ex.txHash !== null) ? ex.txHash : null;
  if (m.transaction.transactionHash !== expectedHash) bad('manifest.transaction.transactionHash violates the binding rule');
}

// Append-only, content-addressed manifest persistence. Explicit
// caller only — never wired into the investigation pipeline. The
// manifest id is its digest, so duplicate builds are idempotent.
function manifestsFile(file) {
  return typeof file === 'string' && file.length > 0 ? file : DEFAULT_MANIFESTS_FILE;
}

function readManifestLines(file) {
  const target = manifestsFile(file);
  try {
    if (!fs.existsSync(target)) return { lines: [], file: target };
    const raw = fs.readFileSync(target, 'utf8').split('\n');
    return { lines: raw.filter((l) => l.trim().length > 0), file: target };
  } catch (err) {
    throw new ManifestError('MANIFEST_STORE_ERROR', `manifest store unreadable: ${String((err && err.message) || err).slice(0, 160)}`);
  }
}

function parseManifestLine(line) {
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    return { ok: false, error: 'unparseable line' };
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.manifest || typeof parsed.manifestDigest !== 'string') {
    return { ok: false, error: 'not a manifest envelope' };
  }
  let recomputed;
  try {
    assertValidInput(parsed.manifest, 'stored.manifest');
    recomputed = sha256Hex(canonicalStringify(parsed.manifest));
  } catch (err) {
    return { ok: false, error: `stored manifest invalid: ${err.message}` };
  }
  if (recomputed !== parsed.manifestDigest) return { ok: false, error: 'digest mismatch: stored manifest altered' };
  return { ok: true, envelope: parsed };
}

function saveManifest(built, file) {
  if (!built || typeof built !== 'object' || !built.manifest || typeof built.manifestDigest !== 'string') {
    throw new ManifestError('MANIFEST_INVALID', 'saveManifest: buildManifest output required');
  }
  const target = manifestsFile(file);
  const { lines } = readManifestLines(target);
  for (const line of lines) {
    const parsed = parseManifestLine(line);
    if (parsed.ok && parsed.envelope.manifestDigest === built.manifestDigest) {
      return { ok: true, file: target, duplicate: true, digest: built.manifestDigest };
    }
  }
  const dir = path.dirname(target);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const stored = { manifest: built.manifest, manifestDigest: built.manifestDigest, createdAt: built.envelope.createdAt, builderVersion: built.envelope.builderVersion };
  fs.appendFileSync(target, `${JSON.stringify(stored)}\n`, 'utf8');
  return { ok: true, file: target, duplicate: false, digest: built.manifestDigest };
}

function findManifestByDigest(digest, file) {
  if (typeof digest !== 'string' || !HEX64.test(digest)) {
    throw new ManifestError('MANIFEST_INVALID', 'digest: 64-hex required');
  }
  const { lines } = readManifestLines(file);
  let corrupted = 0;
  let found = null;
  for (const line of lines) {
    const parsed = parseManifestLine(line);
    if (!parsed.ok) { corrupted += 1; continue; }
    if (found === null && parsed.envelope.manifestDigest === digest) found = parsed.envelope;
  }
  if (found !== null) return { ok: true, envelope: found, corrupted };
  return { ok: false, corrupted };
}

function findManifestByInvestigation(investigationId, file) {
  assertId(investigationId, 'investigationId');
  const { lines } = readManifestLines(file);
  let corrupted = 0;
  let found = null;
  for (const line of lines) {
    const parsed = parseManifestLine(line);
    if (!parsed.ok) { corrupted += 1; continue; }
    // B4: latest valid match wins. The store is append-only and never
    // rewrites, so file position is time order: a later post-execution
    // manifest for the same investigation supersedes the earlier
    // pre-execution one. Corrupted lines are counted, never returned.
    if (parsed.envelope.manifest && parsed.envelope.manifest.investigationId === investigationId) {
      found = parsed.envelope;
    }
  }
  if (found !== null) return { ok: true, envelope: found, corrupted };
  return { ok: false, corrupted };
}

const VERIFY_STEPS = [
  '1. Canonicalize publicProjection with canonicalJson.js and compare to manifest.evidence.publicDigest.',
  '2. Canonicalize requestProjection (when present) and compare to manifest.request.digest.',
  '3. Canonicalize manifest and compare to manifestDigest / envelope.manifestDigest.',
  '4. Re-validate manifest/projection semantics and re-derive contribution claims from the disclosed projection fields (invalid statuses or contradicted claims fail even when digests match).',
  '5. Check transactionHash and executionStatus against the Arc Testnet explorer when a hash is present.',
  '6. evidence.digest commits to the complete internal record; it is verifiable only by the record holder.'
];

const PACKAGE_LIMITATIONS = [
  'Digests prove the disclosed material is exactly what was committed, not that a provider executed a model.',
  'Unsigned manifests prove internal consistency, not authorship: anyone can rebuild a fully consistent package by altering components and recomputing the public digests, until Phase 3 signatures exist.',
  'Provider-signed receipts and TEE execution proofs are outside Phase 2.',
  'The remote transaction chainId is not independently compared against the expected chain (RPC-endpoint trust).',
  'Model contribution levels describe persisted-evidence linkage, not causal proof of reasoning influence.'
];

function buildVerificationPackage(built) {
  if (!built || typeof built !== 'object' || !built.manifest || !built.envelope || !built.publicProjection) {
    throw new ManifestError('MANIFEST_INVALID', 'buildVerificationPackage: buildManifest output required');
  }
  return {
    packageVersion: PACKAGE_VERSION,
    manifest: built.manifest,
    envelope: built.envelope,
    publicProjection: built.publicProjection,
    requestProjection: built.requestProjection,
    digests: {
      evidenceDigest: built.manifest.evidence.digest,
      publicDigest: built.manifest.evidence.publicDigest,
      requestProjectionDigest: built.manifest.request.digest,
      manifestDigest: built.manifestDigest
    },
    verifySteps: [...VERIFY_STEPS],
    disclosed: [
      'publicProjection (whitelisted record fields)', 'requestProjection (whitelisted request fields, no secrets)',
      'manifest', 'envelope', 'all four digests'
    ],
    limitations: [...PACKAGE_LIMITATIONS]
  };
}

// Judge-side verification: recompute every digest from disclosed
// material and check linkage. Dependency-free apart from canonicalJson.
function verifyPackage(pkg) {
  const checks = [];
  const fail = (name, detail) => { checks.push({ name, ok: false, detail }); };
  const pass = (name) => { checks.push({ name, ok: true }); };
  try {
    if (!pkg || typeof pkg !== 'object') throw new ManifestError('MANIFEST_INVALID', 'package: object required');
    assertValidInput(pkg, 'package');
    const manifest = req(pkg.manifest, 'package.manifest');
    assertValidInput(manifest, 'package.manifest');
    // 1. public projection digest.
    if (!pkg.publicProjection || typeof pkg.publicProjection !== 'object') {
      fail('publicDigest', 'publicProjection missing');
    } else if (sha256Hex(canonicalStringify(pkg.publicProjection)) !== manifest.evidence.publicDigest) {
      fail('publicDigest', 'recomputed public digest differs');
    } else pass('publicDigest');
    // 2. request projection digest + linkage.
    if (manifest.request.available === true) {
      if (!pkg.requestProjection || typeof pkg.requestProjection !== 'object') {
        fail('requestDigest', 'requestProjection missing but manifest requires it');
      } else if (sha256Hex(canonicalStringify(pkg.requestProjection)) !== manifest.request.digest) {
        fail('requestDigest', 'recomputed request digest differs');
      } else pass('requestDigest');
      if (pkg.requestProjection && pkg.requestProjection.id !== manifest.requestId) {
        fail('requestLinkage', 'requestProjection.id !== manifest.requestId');
      } else if (pkg.requestProjection) pass('requestLinkage');
    } else if (pkg.requestProjection !== null && pkg.requestProjection !== undefined) {
      fail('requestDigest', 'unexpected requestProjection for a request-less manifest');
    } else pass('requestDigest');
    // 3. manifest digest.
    if (sha256Hex(canonicalStringify(manifest)) !== pkg.envelope.manifestDigest) {
      fail('manifestDigest', 'recomputed manifest digest differs');
    } else pass('manifestDigest');
    // 4. projection linkage.
    if (pkg.publicProjection && pkg.publicProjection.evalId !== manifest.investigationId) {
      fail('projectionLinkage', 'publicProjection.evalId !== manifest.investigationId');
    } else if (pkg.publicProjection && pkg.publicProjection.traceId !== manifest.traceId) {
      fail('projectionLinkage', 'publicProjection.traceId !== manifest.traceId');
    } else if (pkg.publicProjection) pass('projectionLinkage');
    // 5. manifest semantics: schema, enums, digests, timestamps, prompt
    // sequences. Invalid values fail even when digests recompute.
    try {
      assertManifestSemantics(manifest);
      pass('manifestSemantics');
    } catch (err) { fail('manifestSemantics', err.message); }
    // 6. disclosed projection semantics: exact whitelisted shapes.
    try {
      if (!pkg.publicProjection || typeof pkg.publicProjection !== 'object') {
        throw new ManifestError('MANIFEST_INVALID', 'publicProjection missing');
      }
      assertPublicProjectionShape(pkg.publicProjection);
      if (manifest.request.available === true) {
        if (!pkg.requestProjection || typeof pkg.requestProjection !== 'object') {
          throw new ManifestError('MANIFEST_INVALID', 'requestProjection missing but manifest requires it');
        }
        assertDisclosedRequestProjection(pkg.requestProjection);
      }
      pass('projectionSemantics');
    } catch (err) { fail('projectionSemantics', err.message); }
    // 7. provenance consistency on disclosed evidence (shared B2 rules).
    try {
      if (!pkg.publicProjection || typeof pkg.publicProjection !== 'object') {
        throw new ManifestError('MANIFEST_INVALID', 'publicProjection missing');
      }
      const origin = manifest.decision && manifest.decision.reasoningOrigin;
      assertMuseConsistency(pkg.publicProjection.museProvenance, origin, 'publicProjection.museProvenance');
      assertSamConsistency(pkg.publicProjection.samProvenance, 'publicProjection.samProvenance');
      pass('provenanceConsistency');
    } catch (err) { fail('provenanceConsistency', err.message); }
    // 8. contribution claims re-derived from disclosed evidence.
    try {
      if (!pkg.publicProjection || typeof pkg.publicProjection !== 'object') {
        throw new ManifestError('MANIFEST_INVALID', 'publicProjection missing');
      }
      const mc = req(manifest.modelCalls, 'manifest.modelCalls');
      if (!Array.isArray(pkg.publicProjection.verdictSafeguards)) {
        throw new ManifestError('MANIFEST_INVALID', 'publicProjection.verdictSafeguards missing');
      }
      if (!pkg.publicProjection.referenceValidation || typeof pkg.publicProjection.referenceValidation !== 'object') {
        throw new ManifestError('MANIFEST_INVALID', 'publicProjection.referenceValidation missing');
      }
      checkMuseContributionClaim(req(mc.museSpark, 'manifest.modelCalls.museSpark'), pkg.publicProjection.museProvenance, pkg.publicProjection.verdictSafeguards, pkg.publicProjection.verdict);
      checkSamContributionClaim(req(mc.sam, 'manifest.modelCalls.sam'), pkg.publicProjection.samProvenance, pkg.publicProjection.referenceValidation.present, manifest.decision && manifest.decision.reasoningOrigin);
      pass('contributionClaims');
    } catch (err) { fail('contributionClaims', err.message); }
    // 9. manifest linkage: every copied/derived field recomputed.
    try {
      if (!pkg.publicProjection || typeof pkg.publicProjection !== 'object') {
        throw new ManifestError('MANIFEST_INVALID', 'publicProjection missing');
      }
      const rp = (pkg.requestProjection && typeof pkg.requestProjection === 'object') ? pkg.requestProjection : null;
      checkManifestLinkage(manifest, pkg.publicProjection, rp);
      pass('manifestLinkage');
    } catch (err) { fail('manifestLinkage', err.message); }
    // 10. informational digest block matches the committed values.
    try {
      if (!pkg.digests || typeof pkg.digests !== 'object') throw new ManifestError('MANIFEST_INVALID', 'package.digests missing');
      assertExactKeys(pkg.digests, ['evidenceDigest', 'publicDigest', 'requestProjectionDigest', 'manifestDigest'], 'package.digests');
      if (pkg.digests.evidenceDigest !== manifest.evidence.digest) fail('packageDigests', 'digests.evidenceDigest mismatch');
      else if (pkg.digests.publicDigest !== manifest.evidence.publicDigest) fail('packageDigests', 'digests.publicDigest mismatch');
      else if (pkg.digests.requestProjectionDigest !== manifest.request.digest) fail('packageDigests', 'digests.requestProjectionDigest mismatch');
      else if (!pkg.envelope || pkg.digests.manifestDigest !== pkg.envelope.manifestDigest) fail('packageDigests', 'digests.manifestDigest mismatch');
      else pass('packageDigests');
    } catch (err) { fail('packageDigests', err.message); }
  } catch (err) {
    fail('packageValid', err.message);
  }
  return { ok: checks.every((c) => c.ok), checks };
}

module.exports = {
  SCHEMA_VERSION,
  BUILDER_VERSION,
  PACKAGE_VERSION,
  ManifestError,
  assertValidInput,
  buildPublicProjection,
  buildRequestProjection,
  buildManifest,
  buildVerificationPackage,
  verifyPackage,
  saveManifest,
  findManifestByDigest,
  findManifestByInvestigation
};
