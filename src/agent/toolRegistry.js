/**
 * Assertara Tool Registry — typed, validated backend tools for the core
 * transaction-intent investigator (decode, compare, allowance, SAM
 * segmentation, crop, OCR, simulation, consistency checks) plus the
 * retained harness lane (sandbox_exec). Every tool wraps a genuinely
 * supported capability. Removed lanes (chain-history, PDF, audio, video,
 * scheduling) were deleted with their modules; unknown tool names throw.
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

async function sandboxExecImpl({ kind, files, entry, criterion, poc, suite, timeoutMs, maxLogChars }) {
  const { submitHarnessRun } = require('./harness');
  return submitHarnessRun({ kind, files, entry, criterion, poc, suite, timeoutMs, maxLogChars });
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
