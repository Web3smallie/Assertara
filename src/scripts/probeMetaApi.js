/**
 * Assertara Visual Sentry - Meta Model API Probe
 *
 * Usage:
 *   npm run probe
 *     Legacy connectivity check: synthetic 1x1 SAM request (concept 'button',
 *     zero matches expected) + a Muse Spark text verdict probe. Mocks when no
 *     key is configured; mock output is always labeled mock, never live.
 *   npm run probe -- <imagePath> <prompt> [prompt...]
 *     Live SAM 3.1 detection on a real image with explicit prompts, e.g.
 *     npm run probe -- "test/fixtures/sam/dapp-screenshot.png" button "swap card" "dialog box"
 *     Requires a configured MODEL_API_KEY; refuses to mock. Raw SSE per
 *     prompt is saved under data/.probe/ (gitignored).
 *
 * Exit codes: 0 completed (zero detections are a valid empty result),
 * 1 the requested operation could not be performed (transport/API failure,
 * missing credentials in image mode), 2 usage/validation error.
 */

const fs = require('fs');
const path = require('path');
const config = require('../config/env');
const { buildSamRequestBody, accumulateSegmentationText, extractBoxesFromSegmentationText } = require('../services/samService');

// Minimal 1x1 transparent PNG in base64 for synthetic probing
const MOCK_PNG_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

// SAM 3.1 takes one short noun-phrase concept per request (Meta docs:
// https://dev.meta.ai/docs/sam/segmenting). A synthetic 1x1 image is expected
// to yield zero matches; HTTP 200 + completed stream is the live success signal.
const SAM_PROBE_CONCEPT = 'button';

const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.webp', '.gif', '.bmp']);
const MAX_PROBE_IMAGE_BYTES = 10 * 1024 * 1024;
const PROBE_TIMEOUT_MS = 90000;

function keyState() {
  const key = config.modelApiKey;
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) {
    return { configured: false, chars: 0 };
  }
  return { configured: true, chars: key.length };
}

/**
 * Parse CLI args. No args -> default connectivity mode. Otherwise the first
 * arg must be an image path and the rest are one or more prompts.
 * Pure; throws coded errors (exit 2) on misuse.
 */
function parseProbeArgs(argv) {
  const args = (argv || []).filter((a) => a !== '--');
  if (args.length === 0) return { mode: 'default', imagePath: null, prompts: [] };
  const [imagePath, ...prompts] = args;
  if (!imagePath) {
    const err = new Error('probe usage: npm run probe -- <imagePath> <prompt> [prompt...]');
    err.code = 'PROBE_USAGE';
    throw err;
  }
  if (prompts.length === 0) {
    const err = new Error(`probe: no prompts supplied for image "${imagePath}". Usage: npm run probe -- <imagePath> <prompt> [prompt...]`);
    err.code = 'PROBE_USAGE';
    throw err;
  }
  for (const p of prompts) {
    if (typeof p !== 'string' || p.trim().length === 0) {
      const err = new Error('probe: prompts must be non-empty strings.');
      err.code = 'PROBE_USAGE';
      throw err;
    }
  }
  return { mode: 'image', imagePath, prompts };
}

/**
 * Validate an image path without network access: must exist, be a supported
 * image extension, parse via sharp metadata, and fit the size cap.
 */
async function validateImageFile(imagePath) {
  const fail = (code, message) => {
    const err = new Error(`probe: invalid image "${imagePath}": ${message}`);
    err.code = code;
    throw err;
  };
  if (typeof imagePath !== 'string' || imagePath.length === 0) fail('PROBE_BAD_IMAGE', 'empty path');
  const ext = path.extname(imagePath).toLowerCase();
  if (!IMAGE_EXTENSIONS.has(ext)) fail('PROBE_BAD_IMAGE', `unsupported extension "${ext || '(none)'}"; expected one of ${[...IMAGE_EXTENSIONS].join(', ')}`);
  let stat;
  try {
    stat = fs.statSync(imagePath);
  } catch {
    fail('PROBE_BAD_IMAGE', 'file does not exist or is unreadable');
  }
  if (!stat.isFile()) fail('PROBE_BAD_IMAGE', 'not a regular file');
  if (stat.size > MAX_PROBE_IMAGE_BYTES) fail('PROBE_BAD_IMAGE', `file is ${stat.size} bytes (cap ${MAX_PROBE_IMAGE_BYTES})`);
  const sharp = require('sharp');
  let meta;
  try {
    meta = await sharp(imagePath).metadata();
  } catch (err) {
    fail('PROBE_BAD_IMAGE', `unparseable image: ${String(err && err.message || err).slice(0, 200)}`);
  }
  if (!Number.isInteger(meta.width) || !Number.isInteger(meta.height)) {
    fail('PROBE_BAD_IMAGE', 'dimensions unreadable');
  }
  const mime = meta.format ? `image/${meta.format === 'jpg' ? 'jpeg' : meta.format}` : 'image/png';
  return { bytes: stat.size, width: meta.width, height: meta.height, mime };
}

/**
 * Classify one SAM prompt outcome for honest reporting.
 * Pure; unit-tested.
 */
function classifySamOutcome({ status, completed, matches, transportError }) {
  if (transportError) return 'TRANSPORT_ERROR';
  if (status !== 200) return 'API_ERROR';
  if (!completed) return 'INCOMPLETE';
  if (matches === 0) return 'ZERO_DETECTIONS';
  return 'SUCCESS';
}

async function postSam({ concept, imageDataUrl, fetchImpl, timeoutMs }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs || PROBE_TIMEOUT_MS);
  try {
    const res = await (fetchImpl || fetch)(`${config.metaApiBaseUrl}/responses`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${config.modelApiKey}`,
        'Content-Type': 'application/json',
        Accept: 'text/event-stream'
      },
      body: JSON.stringify(buildSamRequestBody(config.samModel, concept, imageDataUrl)),
      signal: ctrl.signal
    });
    return { status: res.status, raw: await res.text() };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Live image probe: one request per prompt, raw SSE saved per prompt.
 * Never mocks: missing credentials throw (exit 1) before any request.
 */
async function runImageProbe({ imagePath, prompts, outDir, fetchImpl }) {
  const key = keyState();
  if (!key.configured) {
    const err = new Error('probe: MODEL_API_KEY is not configured; refusing to mock a live image probe. Set a real key in .env.');
    err.code = 'PROBE_NO_KEY';
    throw err;
  }
  const info = await validateImageFile(imagePath);
  const dir = outDir || path.join(__dirname, '..', '..', 'data', '.probe');
  fs.mkdirSync(dir, { recursive: true });
  const imageDataUrl = `data:${info.mime};base64,${fs.readFileSync(imagePath).toString('base64')}`;
  console.log(`Image: ${imagePath} (${info.bytes} bytes, ${info.width}x${info.height}, ${info.mime})`);
  console.log(`Prompts: ${prompts.map((p) => JSON.stringify(p)).join(', ')}`);
  console.log(`Model: ${config.samModel} @ ${config.metaApiBaseUrl}/responses (key: configured, ${key.chars} chars)`);
  const results = [];
  for (const concept of prompts) {
    const tag = concept.replace(/[^a-z0-9]+/gi, '_');
    const t0 = Date.now();
    let status = null;
    let raw = '';
    let transportError = null;
    try {
      ({ status, raw } = await postSam({ concept, imageDataUrl, fetchImpl }));
    } catch (err) {
      transportError = String(err && err.message || err).slice(0, 500);
    }
    const ms = Date.now() - t0;
    fs.writeFileSync(path.join(dir, `${tag}.sse.txt`), raw);
    const { outputText, completed } = status === 200 && !transportError
      ? accumulateSegmentationText(raw)
      : { outputText: '', completed: false };
    const boxes = status === 200 && !transportError ? extractBoxesFromSegmentationText(outputText, concept) : [];
    const outcome = classifySamOutcome({ status, completed, matches: boxes.length, transportError });
    const entry = { prompt: concept, status, ms, rawChars: raw.length, completed, matches: boxes.length, outcome, boxes };
    if (transportError) entry.transportError = transportError;
    if (status !== null && status !== 200) entry.errorBody = raw.slice(0, 500);
    results.push(entry);
    console.log(`[${outcome}] ${JSON.stringify(concept)}: status=${status} ms=${ms} matches=${boxes.length} raw=${path.join(dir, `${tag}.sse.txt`)}`);
    for (const b of boxes) {
      console.log(`  - ${b.label} box=(${b.boundingBox.x},${b.boundingBox.y},${b.boundingBox.width}x${b.boundingBox.height}) confidence=${b.confidence === null ? 'null' : b.confidence}`);
    }
  }
  fs.writeFileSync(path.join(dir, 'summary.json'), JSON.stringify({ image: imagePath, info, prompts, results }, null, 2));
  return { info, results };
}

async function probeSamModel() {
  console.log(`\n[1/2] Probing Meta SAM Model (${config.samModel})...`);
  console.log(`Endpoint: ${config.metaApiBaseUrl}/responses`);

  if (!config.modelApiKey || config.modelApiKey.startsWith('mock_') || config.modelApiKey.includes('your_meta')) {
    console.warn(`[WARN] MODEL_API_KEY is not configured or using placeholder. Running mock simulation.`);
    return {
      success: true,
      mode: 'mock',
      masks: [
        {
          label: 'claim button',
          box: { x: 100, y: 200, width: 300, height: 80 },
          confidence: 0.96
        }
      ]
    };
  }

  const startTime = Date.now();
  try {
    const response = await fetch(`${config.metaApiBaseUrl}/responses`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${config.modelApiKey}`,
        'Content-Type': 'application/json',
        Accept: 'text/event-stream'
      },
      body: JSON.stringify(buildSamRequestBody(
        config.samModel,
        SAM_PROBE_CONCEPT,
        `data:image/png;base64,${MOCK_PNG_BASE64}`
      ))
    });

    const elapsed = Date.now() - startTime;
    if (!response.ok) {
      const errText = await response.text();
      console.error(`[ERROR] SAM probe failed with status ${response.status}: ${errText}`);
      return { success: false, status: response.status, error: errText };
    }

    const { outputText, completed } = accumulateSegmentationText(await response.text());
    const matches = extractBoxesFromSegmentationText(outputText, SAM_PROBE_CONCEPT);
    console.log(`[SUCCESS] SAM 3.1 responded in ${elapsed}ms (completed=${completed}, matches=${matches.length}):`, outputText.slice(0, 200));
    return { success: true, mode: 'live', latencyMs: elapsed, completed, matches: matches.length, data: outputText.slice(0, 500) };
  } catch (err) {
    console.error(`[ERROR] Network error contacting SAM API:`, err.message);
    return { success: false, error: err.message };
  }
}

async function probeMuseSparkModel() {
  console.log(`\n[2/2] Probing Meta Muse Spark Model (${config.museModel})...`);
  console.log(`Endpoint: ${config.metaApiBaseUrl}/chat/completions`);

  if (!config.modelApiKey || config.modelApiKey.startsWith('mock_') || config.modelApiKey.includes('your_meta')) {
    console.warn(`[WARN] MODEL_API_KEY is not configured or using placeholder. Running mock simulation.`);
    return {
      success: true,
      mode: 'mock',
      result: {
        verdict: 'MISMATCH',
        confidence: 0.95,
        reason: 'Visual context claims free token claim, but calldata executes unlimited token approval.'
      }
    };
  }

  const startTime = Date.now();
  try {
    const response = await fetch(`${config.metaApiBaseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${config.modelApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: config.museModel,
        messages: [
          {
            role: 'system',
            content: 'You are Visual Sentry discrepancy evaluator. Output strict JSON with keys: verdict, confidence, reason.'
          },
          {
            role: 'user',
            content: 'Compare visual promise "Claim 500 UNI Airdrop" against transaction fact "USDT approve(0x942c..., max)".'
          }
        ],
        response_format: { type: 'json_object' },
        temperature: 0
      })
    });

    const elapsed = Date.now() - startTime;
    if (!response.ok) {
      const errText = await response.text();
      console.error(`[ERROR] Muse Spark probe failed with status ${response.status}: ${errText}`);
      return { success: false, status: response.status, error: errText };
    }

    const data = await response.json();
    console.log(`[SUCCESS] Muse Spark responded in ${elapsed}ms:`, JSON.stringify(data).slice(0, 200));
    return { success: true, mode: 'live', latencyMs: elapsed, data };
  } catch (err) {
    console.error(`[ERROR] Network error contacting Muse Spark API:`, err.message);
    return { success: false, error: err.message };
  }
}

async function runDefaultProbe() {
  console.log('==============================================');
  console.log('   Assertara Visual Sentry: Model API Probe   ');
  console.log('==============================================');
  console.log(`Base URL: ${config.metaApiBaseUrl}`);
  console.log('Mode: default connectivity check (synthetic 1x1 SAM image; mock when no key).');
  console.log('For real screenshots: npm run probe -- <imagePath> <prompt> [prompt...]');

  const samResult = await probeSamModel();
  const museResult = await probeMuseSparkModel();

  console.log('\n==============================================');
  console.log('                Probe Summary                 ');
  console.log('==============================================');
  console.log(`SAM 3.1:     ${samResult.success ? '✔ PASSED' : '✖ FAILED'} (${samResult.mode || 'error'})`);
  console.log(`Muse Spark:  ${museResult.success ? '✔ PASSED' : '✖ FAILED'} (${museResult.mode || 'error'})`);
  console.log('==============================================\n');
  return samResult.success && museResult.success;
}

async function main(argv) {
  const parsed = parseProbeArgs(argv);
  if (parsed.mode === 'default') {
    const ok = await runDefaultProbe();
    process.exitCode = ok ? 0 : 1;
    return;
  }
  try {
    const { results } = await runImageProbe({ imagePath: parsed.imagePath, prompts: parsed.prompts });
    const failed = results.filter((r) => r.outcome === 'TRANSPORT_ERROR' || r.outcome === 'API_ERROR' || r.outcome === 'INCOMPLETE');
    if (failed.length > 0) {
      console.error(`probe: ${failed.length}/${results.length} prompt(s) failed (${failed.map((r) => `${r.prompt}:${r.outcome}`).join(', ')})`);
      process.exitCode = 1;
      return;
    }
    process.exitCode = 0;
  } catch (err) {
    if (err.code === 'PROBE_NO_KEY') {
      console.error(`[ERROR] ${err.message}`);
      process.exitCode = 1;
      return;
    }
    throw err;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(`[ERROR] ${err.message}`);
    process.exitCode = err.code === 'PROBE_USAGE' || err.code === 'PROBE_BAD_IMAGE' ? 2 : 1;
  });
}

module.exports = { probeSamModel, probeMuseSparkModel, parseProbeArgs, validateImageFile, classifySamOutcome, runImageProbe, keyState };
