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
 * @param {string} sseText - Raw SSE response body
 * @returns {{ outputText: string, completed: boolean }}
 */
function accumulateSegmentationText(sseText) {
  let outputText = '';
  let completed = false;
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
  }
  return { outputText, completed };
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
    const confidence = fields.c !== undefined && Number.isFinite(Number(fields.c))
      ? Number(fields.c)
      : 0.9;
    regions.push({
      label,
      boundingBox: { x: x1, y: y1, width: x2 - x1 + 1, height: y2 - y1 + 1 },
      confidence
    });
  }
  return regions;
}

async function requestConceptRegions(imageDataUrl, conceptPrompt) {
  const response = await fetch(`${config.metaApiBaseUrl}/responses`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.modelApiKey}`,
      'Content-Type': 'application/json',
      'Accept': 'text/event-stream'
    },
    body: JSON.stringify(buildSamRequestBody(config.samModel, conceptPrompt, imageDataUrl))
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Status ${response.status}: ${errText}`);
  }

  const { outputText } = accumulateSegmentationText(await response.text());
  return extractBoxesFromSegmentationText(outputText, conceptPrompt);
}

async function segmentUiRegions(screenshotBase64, prompts = ['transaction modal', 'claim button', 'interactive card']) {
  if (!config.modelApiKey || config.modelApiKey.startsWith('mock_') || config.modelApiKey.includes('your_meta')) {
    // Deterministic fallback/mock mode for test fixtures and local testing
    return {
      success: true,
      mode: 'mock',
      regions: [
        {
          label: 'interactive card',
          boundingBox: { x: 50, y: 150, width: 500, height: 350 },
          confidence: 0.95
        },
        {
          label: 'claim button',
          boundingBox: { x: 120, y: 380, width: 360, height: 60 },
          confidence: 0.98
        }
      ]
    };
  }

  try {
    // Meta accepts a base64 data URL as image_url; preserve the source mime type.
    let mimeType = 'image/png';
    const dataUrlMatch = screenshotBase64.match(/^data:(image\/\w+);base64,/);
    if (dataUrlMatch) mimeType = dataUrlMatch[1];
    const cleanBase64 = screenshotBase64.replace(/^data:image\/\w+;base64,/, '');
    const imageDataUrl = `data:${mimeType};base64,${cleanBase64}`;

    // One concept per request, per Meta docs; merge matches across prompts.
    const regions = [];
    for (const conceptPrompt of prompts) {
      const matches = await requestConceptRegions(imageDataUrl, conceptPrompt);
      regions.push(...matches);
    }

    return {
      success: true,
      mode: 'live',
      regions: regions.length > 0 ? regions : [{ label: 'main container', boundingBox: { x: 0, y: 0, width: 800, height: 600 } }]
    };
  } catch (err) {
    console.warn(`[SAM API Warning] ${err.message}. Using fallback regions.`);
    return {
      success: false,
      error: err.message,
      regions: [{ label: 'viewport', boundingBox: { x: 0, y: 0, width: 800, height: 600 } }]
    };
  }
}

module.exports = {
  segmentUiRegions,
  buildSamRequestBody,
  accumulateSegmentationText,
  extractBoxesFromSegmentationText
};
