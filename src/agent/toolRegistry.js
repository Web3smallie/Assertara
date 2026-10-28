/**
 * Assertara Tool Registry — typed, validated backend tools.
 * Every tool wraps genuinely supported capability (existing services, viem
 * read-only calls). Anything unavailable is an explicit UNAVAILABLE boundary
 * with integration requirements — never a silent mock.
 */

const { decodeTransactionCalldata } = require('../services/decoderService');
const { segmentUiRegions } = require('../services/samService');
const { extractUiTexts } = require('../services/ocrService');
const { simulateTransactionWithFoundry } = require('../services/simulatorService');
const { cropImageRegion } = require('../utils/imageUtils');
const { INFINITE_THRESHOLD } = require('../utils/abiSignatures');

function isAddress(value) {
  return /^0x[0-9a-fA-F]{40}$/.test(String(value || '').trim());
}

function isHexBytes(value) {
  return /^0x([0-9a-fA-F]{2})*$/.test(String(value || '').trim());
}

function checkArgs(spec, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    throw new Error(`tool ${spec.name}: args must be an object`);
  }
  for (const field of spec.required || []) {
    if (args[field] === undefined || args[field] === null || args[field] === '') {
      throw new Error(`tool ${spec.name}: missing required argument "${field}"`);
    }
  }
  if (spec.validate) spec.validate(args);
}

function compareField(displayed, actual) {
  const norm = (v) => String(v === undefined || v === null ? '' : v).trim().toLowerCase();
  const d = norm(displayed);
  const a = norm(actual);
  if (!d || !a) return { displayed: displayed ?? null, actual: actual ?? null, verdict: 'UNKNOWN', note: 'missing side' };
  return { displayed, actual, verdict: d === a ? 'MATCH' : 'DIFFER' };
}

async function decodeTxImpl({ to, data, value, from }) {
  // decodeTransactionCalldata is synchronous; keep the async tool contract.
  return decodeTransactionCalldata({ to, from, data: data || '0x', value: value || '0x0' });
}

async function compareFieldsImpl({ displayed, decoded }) {
  if (!displayed || typeof displayed !== 'object') throw new Error('compare_fields: displayed must be an object');
  if (!decoded || typeof decoded !== 'object') throw new Error('compare_fields: decoded must be an object');
  const params = decoded.parameters || {};
  const fields = {
    recipient: compareField(displayed.recipient, params.recipient || params.spender || decoded.contract),
    amount: compareField(displayed.amount, params.amountIn || params.amount),
    token: compareField(displayed.token, params.tokenIn || decoded.contract),
    spender: compareField(displayed.spender, params.spender),
    allowance: compareField(displayed.allowance, params.amount)
  };
  const verdicts = Object.values(fields).map((f) => f.verdict);
  const overall = verdicts.includes('DIFFER') ? 'DIFFER' : (verdicts.every((v) => v === 'MATCH') ? 'MATCH' : 'UNKNOWN');
  return { fields, overall };
}

async function allowanceAnalysisImpl({ decoded }) {
  if (!decoded || typeof decoded !== 'object') throw new Error('allowance_analysis: decoded must be an object');
  const params = decoded.parameters || {};
  const amountRaw = params.amount;
  let amount = null;
  if (typeof amountRaw === 'bigint') amount = amountRaw;
  else if (typeof amountRaw === 'string' && /^[0-9]+$/.test(amountRaw)) amount = BigInt(amountRaw);
  return {
    function: decoded.functionName || null,
    spender: params.spender || null,
    amount: amountRaw === undefined ? null : String(amountRaw),
    isUnlimited: amount !== null && amount >= INFINITE_THRESHOLD,
    threshold: `2^255 (${INFINITE_THRESHOLD.toString()})`,
    flags: [
      ...(decoded.isUnlimitedApproval ? ['UNLIMITED_APPROVAL'] : []),
      ...((decoded.ruleFindings || []).map((r) => r.ruleId))
    ]
  };
}

async function segmentConceptImpl({ imageDataUrl, phrase }) {
  // One concept per request per the SAM API contract.
  return segmentUiRegions(imageDataUrl, [phrase]);
}

async function cropRegionImpl({ imageDataUrl, box }) {
  if (!box || typeof box !== 'object') throw new Error('crop_region: box must be an object');
  const buffer = await cropImageRegion(imageDataUrl, box);
  return { dataUrl: `data:image/png;base64,${buffer.toString('base64')}`, box };
}

async function ocrRegionImpl({ imageDataUrl, regions }) {
  return extractUiTexts(imageDataUrl, Array.isArray(regions) ? regions : []);
}

async function simulateTxImpl({ from, to, data, value, decoded }) {
  const decodedTx = decoded || (await decodeTxImpl({ to, from, data, value }));
  return simulateTransactionWithFoundry({ from, to, data, decodedTx });
}

async function contractMetaImpl({ address, rpcUrl }) {
  const { readContractMeta } = require('./chain');
  return readContractMeta({ address, rpcUrl });
}

async function pdfExtractImpl({ pdfBase64, filename, pageImages, limits }) {
  const { ingestAuditPdf } = require('./pdfIngest');
  return ingestAuditPdf({ data: pdfBase64, filename, pageImages, limits });
}

async function sandboxExecImpl({ kind, files, entry, criterion, poc, suite, timeoutMs, maxLogChars }) {
  const { submitHarnessRun } = require('./harness');
  return submitHarnessRun({ kind, files, entry, criterion, poc, suite, timeoutMs, maxLogChars });
}

async function videoAnalysisImpl({ videoBase64, filename, sampleFps, maxFrames, maxBytes, maxDurationSec }) {
  const { ingestVideo } = require('./videoIngest');
  return ingestVideo({ data: videoBase64, filename, sampleFps, maxFrames, maxBytes, maxDurationSec });
}

async function transcribeAudioImpl({ audioBase64, filename, mimeType, timeoutMs, maxBytes, maxDurationSec, maxSegments, maxChars }) {
  const { ingestAudio } = require('./audioIngest');
  return ingestAudio({ data: audioBase64, filename, mimeType, timeoutMs, maxBytes, maxDurationSec, maxSegments, maxChars });
}

async function chainHistoryImpl({ owner, rpcUrl, fromBlock, toBlock, maxLogs }) {
  const { discoverApprovals, computeExposure } = require('./chain');
  const fetched = await discoverApprovals({ owner, rpcUrl, fromBlock, toBlock, maxLogs });
  return { ...fetched, exposure: computeExposure(fetched.approvals) };
}

function unavailable(name, requirements) {
  return {
    name,
    description: `UNAVAILABLE boundary: ${requirements[0]}`,
    status: 'UNAVAILABLE',
    requirements,
    async run() {
      return { status: 'UNAVAILABLE', tool: name, requirements };
    }
  };
}

const TOOLS = {
  decode_tx: {
    name: 'decode_tx',
    description: 'Deterministically decode EVM calldata with viem plus security rules.',
    required: ['to'],
    validate: (a) => {
      if (!isAddress(a.to)) throw new Error('decode_tx: "to" must be a 0x address');
      if (a.data !== undefined && !isHexBytes(a.data)) throw new Error('decode_tx: "data" must be hex bytes');
    },
    run: decodeTxImpl
  },
  compare_fields: {
    name: 'compare_fields',
    description: 'Deterministically compare displayed claims against decoded fields.',
    required: ['displayed', 'decoded'],
    run: compareFieldsImpl
  },
  allowance_analysis: {
    name: 'allowance_analysis',
    description: 'Analyze approval scope against the 2^255 unlimited threshold.',
    required: ['decoded'],
    run: allowanceAnalysisImpl
  },
  segment_concept: {
    name: 'segment_concept',
    description: 'SAM 3.1: segment one visual concept; returns regions with boxes.',
    required: ['imageDataUrl', 'phrase'],
    validate: (a) => {
      if (typeof a.phrase !== 'string' || !a.phrase.trim()) throw new Error('segment_concept: phrase required');
    },
    run: segmentConceptImpl
  },
  crop_region: {
    name: 'crop_region',
    description: 'Crop a bounding box from an image; returns a PNG data URL.',
    required: ['imageDataUrl', 'box'],
    run: cropRegionImpl
  },
  ocr_region: {
    name: 'ocr_region',
    description: 'OCR text from image regions; empty string when nothing is found.',
    required: ['imageDataUrl'],
    run: ocrRegionImpl
  },
  simulate_tx: {
    name: 'simulate_tx',
    description: 'Foundry simulation with honest EXECUTED/FALLBACK/FAILED states. Inputs are allowlist-validated before any source generation.',
    required: ['to'],
    validate: (a) => {
      if (!isAddress(a.to)) throw new Error('simulate_tx: "to" must be a 0x address');
      if (a.from !== undefined && a.from !== null && !isAddress(a.from)) throw new Error('simulate_tx: "from" must be a 0x address');
      if (a.data !== undefined && !isHexBytes(a.data)) throw new Error('simulate_tx: "data" must be hex bytes');
    },
    run: simulateTxImpl
  },
  contract_meta: {
    name: 'contract_meta',
    description: 'Read-only chain metadata: bytecode presence, EIP-1967 proxy slots.',
    required: ['address'],
    validate: (a) => {
      if (!isAddress(a.address)) throw new Error('contract_meta: address must be a 0x address');
    },
    run: contractMetaImpl
  },
  chain_history: {
    name: 'chain_history',
    description: 'Read-only approval history for an owner: Approval logs plus live allowances and exposure.',
    required: ['owner'],
    validate: (a) => {
      if (!isAddress(a.owner)) throw new Error('chain_history: owner must be a 0x address');
    },
    run: chainHistoryImpl
  },
  check_consistency: {
    name: 'check_consistency',
    description: 'Validate finding evidence references against a supplied id list.',
    required: ['supporting', 'conflicting', 'knownIds'],
    validate: (a) => {
      for (const k of ['supporting', 'conflicting', 'knownIds']) {
        if (!Array.isArray(a[k])) throw new Error(`check_consistency: ${k} must be an array`);
      }
    },
    run: async ({ supporting, conflicting, knownIds }) => {
      const known = new Set(knownIds);
      const unknownSupporting = supporting.filter((id) => !known.has(id));
      const unknownConflicting = conflicting.filter((id) => !known.has(id));
      return {
        ok: unknownSupporting.length === 0 && unknownConflicting.length === 0,
        unknownSupporting,
        unknownConflicting
      };
    }
  },
  transcribe_audio: {
    name: 'transcribe_audio',
    description: 'Validate audio and transcribe via the configured STT backend. No backend is installed in this environment: valid audio returns TRANSCRIPTION_UNAVAILABLE with detection evidence; only WAV/PCM is parseable.',
    required: ['audioBase64'],
    validate: (a) => {
      if (typeof a.audioBase64 !== 'string' || a.audioBase64.length === 0) throw new Error('transcribe_audio: audioBase64 must be a non-empty base64 string');
      if (!/^[A-Za-z0-9+/=\s]+$/.test(a.audioBase64)) throw new Error('transcribe_audio: audioBase64 must be base64');
    },
    run: transcribeAudioImpl
  },
  video_analysis: {
    name: 'video_analysis',
    description: 'Validate a walkthrough video and extract frames via the configured backend. No extractor is installed in this environment: valid video returns VIDEO_PROCESSING_UNAVAILABLE with detection evidence; frames are never faked.',
    required: ['videoBase64'],
    validate: (a) => {
      if (typeof a.videoBase64 !== 'string' || a.videoBase64.length === 0) throw new Error('video_analysis: videoBase64 must be a non-empty base64 string');
      if (!/^[A-Za-z0-9+/=\s]+$/.test(a.videoBase64)) throw new Error('video_analysis: videoBase64 must be base64');
    },
    run: videoAnalysisImpl
  },
  pdf_extract: {
    name: 'pdf_extract',
    description: 'Extract audit PDF text per page with deterministic finding segmentation. Intake enters UNRESOLVED; code refs are report mentions, not verified code.',
    required: ['pdfBase64'],
    validate: (a) => {
      if (typeof a.pdfBase64 !== 'string' || a.pdfBase64.length === 0) throw new Error('pdf_extract: pdfBase64 must be a non-empty base64 string');
      if (!/^[A-Za-z0-9+/=\s]+$/.test(a.pdfBase64)) throw new Error('pdf_extract: pdfBase64 must be base64');
    },
    run: pdfExtractImpl
  },
  schedule_monitor: unavailable('schedule_monitor', [
    'Deliberately not model-callable: monitoring targets require explicit user authorization, which a model tool call cannot supply.',
    'An in-process scheduler exists (src/agent/scheduler.js: WatchScheduler with file store, locking, backoff, and getAlerts); manage targets through the internal service API, not a model tool.'
  ]),
  sandbox_exec: {
    name: 'sandbox_exec',
    description: 'Submit a bounded F15 harness run. No isolated executor is configured in this environment: execute requests return EXECUTION_UNAVAILABLE with detection evidence; nothing runs on the host.',
    required: ['kind', 'files'],
    validate: (a) => {
      if (!['static', 'execute', 'reproduce', 'verify-patch'].includes(a.kind)) throw new Error('sandbox_exec: kind must be static, execute, reproduce, or verify-patch');
      if (!Array.isArray(a.files) || a.files.length === 0) throw new Error('sandbox_exec: files must be a non-empty array');
    },
    run: sandboxExecImpl
  }
};

async function runTool(name, args) {
  const spec = TOOLS[name];
  if (!spec) throw new Error(`unknown tool: ${name}`);
  if (spec.status === 'UNAVAILABLE') return spec.run(args);
  checkArgs(spec, args);
  return spec.run(args);
}

function describeTools() {
  return Object.values(TOOLS).map((t) => ({
    name: t.name,
    description: t.description,
    status: t.status || 'AVAILABLE',
    required: t.required || [],
    ...(t.requirements ? { requirements: t.requirements } : {})
  }));
}

module.exports = { TOOLS, runTool, describeTools, isAddress };
