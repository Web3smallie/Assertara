/**
 * Assertara Visual Sentry - Meta Model API Probe
 * Tests connectivity and response formatting for:
 * 1. Meta SAM 3.1 (Segment Anything Model 3.1)
 * 2. Meta Muse Spark (muse-spark-1.3)
 */

const config = require('../config/env');
const { buildSamRequestBody, accumulateSegmentationText, extractBoxesFromSegmentationText } = require('../services/samService');

// Minimal 1x1 transparent PNG in base64 for synthetic probing
const MOCK_PNG_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

// SAM 3.1 takes one short noun-phrase concept per request (Meta docs:
// https://dev.meta.ai/docs/sam/segmenting). A synthetic 1x1 image is expected
// to yield zero matches; HTTP 200 + completed stream is the live success signal.
const SAM_PROBE_CONCEPT = 'button';

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
        'Authorization': `Bearer ${config.modelApiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream'
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
        'Authorization': `Bearer ${config.modelApiKey}`,
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
        response_format: { type: 'json_object' }
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

async function runProbe() {
  console.log('==============================================');
  console.log('   Assertara Visual Sentry: Model API Probe   ');
  console.log('==============================================');
  console.log(`Base URL: ${config.metaApiBaseUrl}`);

  const samResult = await probeSamModel();
  const museResult = await probeMuseSparkModel();

  console.log('\n==============================================');
  console.log('                Probe Summary                 ');
  console.log('==============================================');
  console.log(`SAM 3.1:     ${samResult.success ? '✔ PASSED' : '✖ FAILED'} (${samResult.mode || 'error'})`);
  console.log(`Muse Spark:  ${museResult.success ? '✔ PASSED' : '✖ FAILED'} (${museResult.mode || 'error'})`);
  console.log('==============================================\n');
}

if (require.main === module) {
  runProbe();
}

module.exports = { probeSamModel, probeMuseSparkModel };
