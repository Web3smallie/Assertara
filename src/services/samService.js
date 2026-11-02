/**
 * Meta SAM 3.1 Region Isolation Service
 * Identifies spatial boundaries of interactive cards, modals, and buttons.
 * Note: SAM 3.1 is used exclusively for spatial region segmentation, not OCR.
 *
 * Request/response shape follows Meta Model API "Segmenting with prompts"
 * (https://dev.meta.ai/docs/sam/segmenting) and "Reading segmentation output"
 * (https://dev.meta.ai/docs/sam/reading-segmentation):
 * POST {baseUrl}/responses with model "sam-3.1" and
 * input: [{ type: 'message', role: 'user',
 *           content: [{ type: 'input_text', text: '<one concept>' },
 *                     { type: 'input_image', image_url: '<url|data URL>' }] }]
 * There is no top-level `prompts` parameter; one concept per request.
 */

const config = require('../config/env');
const { canonicalStringify, sha256Hex, safeProvenance } = require('../utils/canonicalJson');

/**
 * Build a documented SAM 3.1 Responses API request body for one concept.
 * @param {string} model - Model id, e.g. 'sam-3.1'
 * @param {string} conceptPrompt - One short noun phrase, e.g. 'button'
 * @param {string} imageDataUrl - Public URL or base64 data URL of the image
 */
function buildSamRequestBody(model, conceptPrompt, imageDataUrl) {
  return {
    model,
    input: [
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: conceptPrompt },
          { type: 'input_image', image_url: imageDataUrl }
        ]
      }
    ],
    stream: true
  };
}

/**
 * Accumulate the `output_text` lane from a streamed Responses API (SSE) body.
 * Concatenates `response.output_text.delta` payloads until `response.completed`
 * (or `[DONE]`). Empty output with completion means zero matches, not an error.
 * Phase 1 provenance: also captures first-observed response identifiers,
 * model echo, and usage objects when the provider supplies them; every
 * field stays null when absent (event shapes beyond deltas/completion
 * are not verified against live responses — nothing is assumed).
 * @param {string} sseText - Raw SSE response body
 * @returns {{ outputText: string, completed: boolean, responseId: string|null, modelObserved: string|null, usage: object|null }}
 */
function accumulateSegmentationText(sseText) {
  let outputText = '';
  let completed = false;
  let responseId = null;
  let modelObserved = null;
  let usage = null;
  const takeId = (v) => (typeof v === 'string' && v.length > 0 && v.length <= 256 ? v.slice(0, 128) : null);
  for (const rawLine of String(sseText).split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('data:')) continue;
    const payload = line.slice('data:'.length).trim();
    if (payload === '[DONE]') {
      completed = true;
      continue;
    }
    let event;
    try {
      event = JSON.parse(payload);
    } catch {
      continue;
    }
    if (event && event.type === 'response.output_text.delta' && typeof event.delta === 'string') {
      outputText += event.delta;
    }
    if (event && event.type === 'response.completed') {
      completed = true;
    }
    if (event && typeof event === 'object') {
      if (responseId === null) {
        responseId = takeId(event.response_id) || takeId(event.id)
          || (event.response && typeof event.response === 'object' ? takeId(event.response.id) : null);
      }
      if (modelObserved === null) {
        const m = event.model || (event.response && typeof event.response === 'object' ? event.response.model : null);
        if (typeof m === 'string' && m.length > 0 && m.length <= 128) modelObserved = m;
      }
      if (usage === null) {
        const u = event.usage || (event.response && typeof event.response === 'object' ? event.response.usage : null);
        if (u && typeof u === 'object' && !Array.isArray(u)) usage = u;
      }
    }
  }
  return { outputText, completed, responseId, modelObserved, usage };
}

/**
 * Extract box regions from SAM 3.1 segmentation text.
 * Grammar per Meta docs: `<Nf>id<|box;x1=..;y1=..;x2=..;y2=..;w=..;h=..[;c=..]|><|mask;...|>,...`
 * Box corners are source pixels; x2/y2 are inclusive.
 * @param {string} outputText - Accumulated segmentation output text
 * @param {string} label - Concept prompt that produced these matches
 */
function extractBoxesFromSegmentationText(outputText, label) {
  const regions = [];
  const tokenRe = /<\|box;([^|]*)\|>/g;
  let match;
  while ((match = tokenRe.exec(String(outputText))) !== null) {
    const fields = {};
    for (const part of match[1].split(';')) {
      const eq = part.indexOf('=');
      if (eq > 0) fields[part.slice(0, eq)] = part.slice(eq + 1);
    }
    const x1 = Number(fields.x1);
    const y1 = Number(fields.y1);
    const x2 = Number(fields.x2);
    const y2 = Number(fields.y2);
    if (![x1, y1, x2, y2].every(Number.isFinite)) continue;
    // Phase 1: confidence is preserved ONLY when the model supplies c=.
    // Missing confidence stays null; it is never defaulted (0.9 was fabricated).
    // An empty c= is also absent: Number('') is 0, which would fabricate a score.
    const cRaw = fields.c !== undefined ? String(fields.c).trim() : '';
    const confidence = cRaw !== '' && Number.isFinite(Number(cRaw))
      ? Number(cRaw)
      : null;
    regions.push({
      label,
      boundingBox: { x: x1, y: y1, width: x2 - x1 + 1, height: y2 - y1 + 1 },
      confidence,
      genuine: true,
      prompts: [label]
    });
  }
  return regions;
}

async function requestConceptRegions(imageDataUrl, conceptPrompt) {
  // Fix 3: bounded request. The abort signal covers connection setup AND
  // response-body consumption, so a stalled stream cannot hang the call.
  // Mirrors the probe's AbortController pattern; no retries by design.
  const timeoutMs = config.samTimeoutMs;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const invokedAt = Date.now();
  try {
    const response = await fetch(`${config.metaApiBaseUrl}/responses`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.modelApiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream'
      },
      body: JSON.stringify(buildSamRequestBody(config.samModel, conceptPrompt, imageDataUrl)),
      signal: ctrl.signal
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Status ${response.status}: ${errText}`);
    }

    const raw = await response.text();
    const completedAt = Date.now();
    const { outputText, completed, responseId, modelObserved, usage } = accumulateSegmentationText(raw);
    return {
      regions: extractBoxesFromSegmentationText(outputText, conceptPrompt),
      completed,
      responseEmpty: raw.trim().length === 0,
      invokedAt,
      completedAt,
      responseId,
      modelObserved,
      usage: usage || null
    };
  } catch (err) {
    if (err && err.name === 'AbortError') {
      const timeoutErr = new Error(`SAM request timed out after ${timeoutMs}ms`);
      timeoutErr.code = 'SAM_TIMEOUT';
      throw timeoutErr;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Synthetic fallback geometry: the FULL verified image, origin to true
 * dimensions. Returned ONLY inside `fallback`, never inside `regions`, so
 * downstream code cannot mistake it for genuine SAM output. Returns null
 * when dims are unknown — the caller must record the scan as unrunnable
 * instead of pretending a fixed-size box covered the image.
 */
function syntheticFallbackRegion(reason, dims) {
  if (!dims) return null;
  return {
    regionId: 'R-FALLBACK',
    label: 'fallback scan (synthetic)',
    boundingBox: { x: 0, y: 0, width: dims.width, height: dims.height },
    confidence: null,
    genuine: false,
    synthetic: true,
    reason
  };
}

function boxIoU(a, b) {
  const x1 = Math.max(a.x, b.x);
  const y1 = Math.max(a.y, b.y);
  const x2 = Math.min(a.x + a.width, b.x + b.width);
  const y2 = Math.min(a.y + a.height, b.y + b.height);
  const inter = Math.max(0, x2 - x1) * Math.max(0, y2 - y1);
  if (inter <= 0) return 0;
  const union = a.width * a.height + b.width * b.height - inter;
  return union > 0 ? inter / union : 0;
}

/**
 * Merge near-duplicate detections across prompts (IoU >= 0.9), preserving
 * every prompt that produced the region. Pure; unit-tested.
 */
function dedupeRegions(regions) {
  const out = [];
  for (const r of regions || []) {
    const dup = out.find((o) => boxIoU(o.boundingBox, r.boundingBox) >= 0.9);
    if (dup) {
      for (const p of r.prompts || []) {
        if (!dup.prompts.includes(p)) dup.prompts.push(p);
      }
    } else {
      out.push({ ...r, prompts: [...(r.prompts || [])] });
    }
  }
  return out;
}

// Production defaults (Phase 1, evidence-based on fixture 1366x632 live runs):
// 'button' reproducibly detects transaction controls (3/3, twice); container
// prompts ('dialog box', 'swap card', 'card', 'panel', 'modal', ...) returned
// zero on this fixture. 'dialog box' is retained for modal-style pages where
// no button fires; its zero-detection case is handled honestly (see below).
// Phase 3 adds SUMMARY_PROMPT to target the transaction-details region. Its
// live firing behavior is UNVERIFIED (no live calls in this phase): a zero
// from it is an honest zero, and generic prompts are retained regardless.
const SUMMARY_PROMPT = 'transaction summary';
const DEFAULT_PROMPTS = ['button', 'dialog box', SUMMARY_PROMPT];

async function segmentUiRegions(screenshotBase64, prompts = DEFAULT_PROMPTS, opts = {}) {
  if (!Array.isArray(prompts) || prompts.length === 0
      || prompts.some((p) => typeof p !== 'string' || p.length === 0)) {
    throw new TypeError('segmentUiRegions: prompts must be a non-empty array of concept strings.');
  }
  // Full-image fallback geometry (Phase 3): the scan covers the caller's
  // verified screenshot dimensions. Absent/invalid dims mean the scan
  // cannot run honestly — never silently substitute a fixed-size box.
  const rawDims = opts && opts.dims;
  const dims = rawDims && Number.isInteger(rawDims.width) && rawDims.width > 0
    && Number.isInteger(rawDims.height) && rawDims.height > 0
    ? { width: rawDims.width, height: rawDims.height }
    : null;
  if (!config.modelApiKey || config.modelApiKey.startsWith('mock_') || config.modelApiKey.includes('your_meta')) {
    // Deterministic mock mode for test fixtures and local testing. Mock
    // regions are explicitly non-genuine; detectedCount stays 0.
    return {
      success: true,
      mode: 'mock',
      status: 'mock',
      samModelConfigured: config.samModel,
      samModelObserved: null,
      submittedImageDigest: null,
      invokedAt: null,
      completedAt: null,
      responseId: null,
      usage: null,
      outputDigest: null,
      regions: [
        {
          regionId: 'R-MOCK-1',
          label: 'interactive card',
          boundingBox: { x: 50, y: 150, width: 500, height: 350 },
          confidence: 0.95,
          genuine: false,
          prompts: ['interactive card']
        },
        {
          regionId: 'R-MOCK-2',
          label: 'claim button',
          boundingBox: { x: 120, y: 380, width: 360, height: 60 },
          confidence: 0.98,
          genuine: false,
          prompts: ['claim button']
        }
      ],
      detectedCount: 0,
      promptsQueried: [...prompts],
      perPrompt: [],
      partialFailure: false,
      incomplete: false,
      fallback: null
    };
  }

  // Invalid-but-truthy screenshots (numbers, objects, ...) must never be
  // stringified into model requests: the API 400s on the invalid base64 and
  // burns one call per prompt. Fail honestly without network traffic, in the
  // same all-failed shape a total API failure produces. Mock mode above is
  // deliberately untouched: it never reads the screenshot.
  if (typeof screenshotBase64 !== 'string' || screenshotBase64.length === 0) {
    const got = screenshotBase64 === null ? 'null'
      : Array.isArray(screenshotBase64) ? 'array' : typeof screenshotBase64;
    const detail = `invalid screenshot input: expected a base64 string, got ${got}`;
    console.warn(`[SAM API Warning] ${detail}. No genuine detections.`);
    return {
      success: false,
      mode: 'live',
      status: 'failed',
      samModelConfigured: config.samModel,
      samModelObserved: null,
      submittedImageDigest: null,
      invokedAt: null,
      completedAt: null,
      responseId: null,
      usage: null,
      outputDigest: null,
      regions: [],
      detectedCount: 0,
      promptsQueried: [...prompts],
      perPrompt: prompts.map((conceptPrompt, index) => ({
        prompt: conceptPrompt, index, matches: 0, status: 'error',
        invokedAt: null, completedAt: null, responseId: null,
        modelObserved: null, usage: null, inputDigest: null,
        outputDigest: null, error: detail
      })),
      partialFailure: false,
      incomplete: false,
      error: detail,
      fallback: { reason: 'error', region: syntheticFallbackRegion('error', dims) }
    };
  }

  // Meta accepts a base64 data URL as image_url; preserve the source mime type.
  let mimeType = 'image/png';
  const dataUrlMatch = String(screenshotBase64).match(/^data:(image\/\w+);base64,/);
  if (dataUrlMatch) mimeType = dataUrlMatch[1];
  const cleanBase64 = String(screenshotBase64).replace(/^data:image\/\w+;base64,/, '');
  const imageDataUrl = `data:${mimeType};base64,${cleanBase64}`;
  // Digest of the exact decoded bytes submitted to the provider. No
  // resize or transform runs before SAM, so this equals the intake
  // screenshot digest; both are recorded so any future transform that
  // separates them is visible rather than silent.
  const submittedImageDigest = safeProvenance(() => sha256Hex(Buffer.from(cleanBase64, 'base64')));
  const canonicalMatch = (m) => ({
    label: m.label || null,
    boundingBox: m.boundingBox && typeof m.boundingBox === 'object'
      ? { x: m.boundingBox.x, y: m.boundingBox.y, width: m.boundingBox.width, height: m.boundingBox.height }
      : null,
    confidence: typeof m.confidence === 'number' ? m.confidence : null,
    prompts: Array.isArray(m.prompts) ? [...m.prompts] : []
  });

  // One concept per request, per Meta docs; merge matches across prompts.
  // A single prompt's failure must not discard the other prompts' detections.
  const regions = [];
  const perPrompt = [];
  for (let index = 0; index < prompts.length; index += 1) {
    const conceptPrompt = prompts[index];
    const inputDigest = safeProvenance(() => sha256Hex(canonicalStringify({ image: submittedImageDigest, prompt: conceptPrompt })));
    const attemptedAt = Date.now();
    try {
      const { regions: matches, completed, responseEmpty, invokedAt, completedAt, responseId, modelObserved, usage } = await requestConceptRegions(imageDataUrl, conceptPrompt);
      regions.push(...matches);
      // A stream without the required completion event is incomplete even
      // when boxes parsed: more detections may have been cut off. Parsed
      // boxes are preserved (marked by the aggregate flag below), never
      // silently treated as a complete inspection.
      const outputDigest = completed
        ? safeProvenance(() => sha256Hex(canonicalStringify(matches.map(canonicalMatch))))
        : null;
      perPrompt.push(completed
        ? { prompt: conceptPrompt, index, matches: matches.length, status: 'success', invokedAt, completedAt, responseId: responseId || null, modelObserved: modelObserved || null, usage: usage || null, inputDigest, outputDigest }
        : {
            prompt: conceptPrompt,
            index,
            matches: matches.length,
            status: 'incomplete',
            invokedAt,
            completedAt,
            responseId: responseId || null,
            modelObserved: modelObserved || null,
            usage: usage || null,
            inputDigest,
            outputDigest: null,
            incomplete: true,
            detail: responseEmpty ? 'empty response body' : 'stream ended without response.completed'
          });
    } catch (err) {
      const entry = {
        prompt: conceptPrompt,
        index,
        matches: 0,
        status: (err && err.code === 'SAM_TIMEOUT') ? 'timeout' : 'error',
        invokedAt: attemptedAt,
        completedAt: Date.now(),
        responseId: null,
        modelObserved: null,
        usage: null,
        inputDigest,
        outputDigest: null,
        error: String(err && err.message || err).slice(0, 500)
      };
      // Machine-readable timeout classification; the entry still carries
      // `error`, so timeouts compose with Fix 1 aggregation unchanged.
      if (err && err.code === 'SAM_TIMEOUT') entry.timeout = true;
      perPrompt.push(entry);
    }
  }
  const deduped = dedupeRegions(regions);
  // Phase 2: stable per-result region ids, preserved through OCR and evidence.
  deduped.forEach((r, i) => { r.regionId = `R-${String(i + 1).padStart(3, '0')}`; });
  const failed = perPrompt.filter((p) => p.error);
  const incomplete = perPrompt.some((p) => p.incomplete === true);
  const allFailed = perPrompt.length > 0 && failed.length === perPrompt.length;
  const firstObserved = (key) => {
    const found = perPrompt.find((p) => p[key] !== null && p[key] !== undefined);
    return found ? found[key] : null;
  };
  const aggregateInvokedAt = perPrompt.length > 0 ? perPrompt[0].invokedAt : null;
  const aggregateCompletedAt = perPrompt.length > 0 ? perPrompt[perPrompt.length - 1].completedAt : null;
  if (allFailed) {
    const error = failed.map((p) => `${p.prompt}: ${p.error}`).join(' | ');
    console.warn(`[SAM API Warning] All prompts failed: ${error}. No genuine detections.`);
    return {
      success: false,
      mode: 'live',
      status: 'failed',
      samModelConfigured: config.samModel,
      samModelObserved: null,
      submittedImageDigest,
      invokedAt: aggregateInvokedAt,
      completedAt: aggregateCompletedAt,
      responseId: null,
      usage: null,
      outputDigest: null,
      regions: [],
      detectedCount: 0,
      promptsQueried: [...prompts],
      perPrompt,
      partialFailure: false,
      incomplete: false,
      error,
      fallback: { reason: 'error', region: syntheticFallbackRegion('error', dims) }
    };
  }
  // Partial failure: some prompts errored while others succeeded. Genuine
  // detections from the successful prompts are preserved, but the result
  // must not look like a fully successful inspection: the failed prompts'
  // errors ride the existing `error` channel and raise `partialFailure`.
  const partialFailure = failed.length > 0;
  if (partialFailure) {
    console.warn(`[SAM API Warning] Partial failure: ${failed.map((p) => `${p.prompt}: ${p.error}`).join(' | ')}.`);
  }
  // Fallback reason precedence on zero detections: hard errors dominate
  // (partial-error), then unvalidatable streams (incomplete), then a clean
  // zero — which becomes 'unavailable' when dims are unknown, since no scan
  // can honestly run. The independent flags carry the full state when
  // several conditions coincide.
  const fallbackReason = deduped.length === 0
    ? (partialFailure ? 'partial-error' : (incomplete ? 'incomplete' : (dims ? 'zero-detections' : 'unavailable')))
    : null;
  // Aggregate output digest covers deduped genuine regions only; an
  // empty success hashes the empty set (a valid result), while mock
  // and synthetic geometry are never included.
  const genuineDeduped = deduped.filter((r) => r && r.genuine !== false);
  return {
    success: true,
    mode: 'live',
    status: (partialFailure || incomplete) ? 'partial' : 'success',
    samModelConfigured: config.samModel,
    samModelObserved: firstObserved('modelObserved'),
    submittedImageDigest,
    invokedAt: aggregateInvokedAt,
    completedAt: aggregateCompletedAt,
    responseId: firstObserved('responseId'),
    usage: firstObserved('usage'),
    outputDigest: safeProvenance(() => sha256Hex(canonicalStringify(
      genuineDeduped.map((r) => ({ regionId: r.regionId || null, ...canonicalMatch(r) }))
    ))),
    regions: deduped,
    detectedCount: deduped.length,
    promptsQueried: [...prompts],
    perPrompt,
    partialFailure,
    incomplete,
    ...(partialFailure ? { error: failed.map((p) => `${p.prompt}: ${p.error}`).join(' | ') } : {}),
    fallback: fallbackReason
      ? { reason: fallbackReason, region: syntheticFallbackRegion(fallbackReason, dims) }
      : null
  };
}

module.exports = {
  segmentUiRegions,
  buildSamRequestBody,
  accumulateSegmentationText,
  extractBoxesFromSegmentationText,
  dedupeRegions,
  DEFAULT_PROMPTS,
  SUMMARY_PROMPT
};
