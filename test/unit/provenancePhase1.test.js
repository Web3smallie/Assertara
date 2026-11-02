const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const config = require('../../src/config/env');
const { evaluateSemanticDiscrepancy } = require('../../src/services/reasonerService');
const { segmentUiRegions, accumulateSegmentationText } = require('../../src/services/samService');
const { compileEvidenceBundle } = require('../../src/services/evidenceService');
const telemetry = require('../../src/services/investigationTelemetry');
const { canonicalStringify, sha256Hex, safeProvenance } = require('../../src/utils/canonicalJson');

// Phase 1 provenance instrumentation: Muse + SAM invocation evidence,
// output digests, and bundle/record carry-through. Provider transports
// are fully stubbed (no network, no model, no live probes).

const TX = {
  to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  value: '0x1000', data: '0x', chainId: 31337,
  functionName: '', symbol: 'ETH', ruleFindings: [], parameters: {}
};
const PAGE = { title: 't', url: 'http://example.test/', visibleText: 'hello' };
const MODEL_OK = '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{"visualIntent":"x","actualExecution":"y","criticalMismatch":false},"recommendedAction":"PROCEED"}';
const PNG_1X1 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

function useLiveKey() {
  const original = config.modelApiKey;
  config.modelApiKey = 'test-live-key';
  return () => { config.modelApiKey = original; };
}

function useMockKey() {
  const original = config.modelApiKey;
  config.modelApiKey = 'mock_test';
  return () => { config.modelApiKey = original; };
}

function sseFrame(obj) {
  return `data: ${JSON.stringify(obj)}\n`;
}
function samOkBody(box, extra) {
  return sseFrame({ type: 'response.output_text.delta', delta: `<|box;${box}|>` })
    + sseFrame(Object.assign({ type: 'response.completed' }, extra || {}));
}

// Load a controller whose ocrService.extractUiTexts is stubbed (mirrors
// evaluate.test.js); everything else runs for real.
function loadControllerWithOcr(fakeExtract) {
  const ocrPath = require.resolve('../../src/services/ocrService');
  const ctlPath = require.resolve('../../src/controllers/evaluateController');
  const realOcrEntry = require.cache[ocrPath];
  const hadCtl = Object.prototype.hasOwnProperty.call(require.cache, ctlPath);
  const realCtlEntry = require.cache[ctlPath];
  require.cache[ocrPath] = { id: ocrPath, filename: ocrPath, loaded: true, exports: { extractUiTexts: fakeExtract } };
  delete require.cache[ctlPath];
  try {
    return require(ctlPath);
  } finally {
    if (realOcrEntry) require.cache[ocrPath] = realOcrEntry;
    else delete require.cache[ocrPath];
    if (hadCtl) require.cache[ctlPath] = realCtlEntry;
    else delete require.cache[ctlPath];
  }
}

function runWith(handle, body, internal) {
  return new Promise((resolve) => {
    const req = { body };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); }
    };
    handle(req, res, internal || null);
  });
}

async function runProvenanceTests() {
  console.log('Testing Phase 1 provenance instrumentation...\n');
  const realFetch = global.fetch;

  // Test 1: canonical JSON is key-order stable; digests deterministic.
  {
    const a = canonicalStringify({ b: 2, a: { d: [3, 1], c: 'x' } });
    const b = canonicalStringify({ a: { c: 'x', d: [3, 1] }, b: 2 });
    assert.strictEqual(a, b, 'key order must not affect canonical form');
    assert.strictEqual(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.strictEqual(safeProvenance(() => { throw new Error('boom'); }), null);
    assert.strictEqual(safeProvenance(() => { throw new Error('boom'); }, 'fb'), 'fb');
    const circular = {}; circular.self = circular;
    assert.strictEqual(safeProvenance(() => canonicalStringify(circular)), null, 'circular input degrades to null');
    console.log('✔ Test 1 Passed: canonicalization, digests, failure isolation.');
  }

  // Test 2: Muse success captures provider echo, ids, timestamps, digests.
  {
    const restoreKey = useLiveKey();
    let calls = 0;
    global.fetch = async () => {
      calls += 1;
      return {
        ok: true,
        json: async () => ({
          id: 'chatcmpl-test-1', created: 1799999999, model: 'muse-spark-1.3-echo',
          choices: [{ message: { content: MODEL_OK } }],
          usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 }
        })
      };
    };
    let out;
    try {
      const trace = telemetry.createTrace({ source: 'test' });
      out = await evaluateSemanticDiscrepancy('', PAGE, TX, {}, {}, { trace });
      const span = trace.spans.find((s) => s.component === 'muse-spark');
      assert.strictEqual(span.status, 'COMPLETED');
      assert.strictEqual(span.extra.outputDigest, sha256Hex(MODEL_OK), 'span carries output digest');
      assert.strictEqual(span.extra.provenanceStatus, 'success');
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    assert.strictEqual(calls, 1, 'exactly one provider call');
    assert.strictEqual(out.origin, 'model');
    assert.strictEqual(out.modelRequested, config.museModel, 'configured id recorded');
    assert.strictEqual(out.modelId, 'muse-spark-1.3-echo', 'provider echo kept separate');
    const p = out.museProvenance;
    assert.strictEqual(p.provenanceStatus, 'success');
    assert.strictEqual(p.responseId, 'chatcmpl-test-1');
    assert.strictEqual(p.responseCreated, 1799999999);
    assert.ok(Number.isInteger(p.invokedAt) && Number.isInteger(p.completedAt) && p.completedAt >= p.invokedAt);
    assert.match(p.inputDigest, /^[0-9a-f]{64}$/);
    assert.strictEqual(p.outputDigest, sha256Hex(MODEL_OK), 'output digest covers exact bytes');
    console.log('✔ Test 2 Passed: Muse success provenance captured.');
  }

  // Test 3: Muse failure attempts preserve attempt evidence, never output.
  {
    const restoreKey = useLiveKey();
    const cases = [
      { name: 'http-error', fetch: async () => ({ ok: false, status: 500 }), status: 'http-error' },
      { name: 'empty', fetch: async () => ({ ok: true, json: async () => ({ choices: [{ finish_reason: 'length' }] }) }), status: 'empty-content' },
      { name: 'unparseable', fetch: async () => ({ ok: true, json: async () => ({ choices: [{ message: { content: 'not json {{{' } }] }) }), status: 'invalid-output' },
      { name: 'timeout', fetch: async () => { const e = new Error('x'); e.name = 'AbortError'; throw e; }, status: 'timeout' },
      { name: 'transport', fetch: async () => { throw new Error('socket hangup'); }, status: 'transport-error' }
    ];
    for (const c of cases) {
      let calls = 0;
      global.fetch = async (...a) => { calls += 1; return c.fetch(...a); };
      let out;
      try {
        out = await evaluateSemanticDiscrepancy('', PAGE, TX);
      } finally {
        global.fetch = realFetch;
      }
      assert.strictEqual(calls, 1, `${c.name}: one attempt, no retry`);
      assert.strictEqual(out.origin, 'heuristic-fallback', `${c.name}: decision path unchanged`);
      const p = out.museProvenance;
      assert.strictEqual(p.provenanceStatus, c.status, `${c.name}: status`);
      assert.ok(Number.isInteger(p.invokedAt), `${c.name}: invokedAt kept`);
      assert.ok(Number.isInteger(p.completedAt), `${c.name}: completedAt kept`);
      assert.match(p.inputDigest, /^[0-9a-f]{64}$/, `${c.name}: input digest kept`);
      assert.strictEqual(p.outputDigest, null, `${c.name}: no output digest without valid output`);
      assert.strictEqual(p.responseId, null, `${c.name}: no invented provider id`);
    }
    restoreKey();
    console.log('✔ Test 3 Passed: Muse failure attempts preserve attempt evidence.');
  }

  // Test 4: Muse skip records status only; zero provider contact.
  {
    const restoreKey = useMockKey();
    let calls = 0;
    global.fetch = async () => { calls += 1; throw new Error('must not call'); };
    let out;
    try {
      out = await evaluateSemanticDiscrepancy('', PAGE, TX);
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    assert.strictEqual(calls, 0);
    assert.deepStrictEqual(out.museProvenance, {
      provenanceStatus: 'skipped', invokedAt: null, completedAt: null,
      inputDigest: null, outputDigest: null, responseId: null, responseCreated: null
    });
    console.log('✔ Test 4 Passed: Muse skip carries no attempt artifacts.');
  }

  // Test 5: SAM success captures per-prompt provenance, ids, usage, digests.
  {
    const restoreKey = useLiveKey();
    let calls = 0;
    global.fetch = async () => {
      calls += 1;
      return {
        ok: true,
        text: async () => samOkBody('x1=10;y1=20;x2=110;y2=120;c=0.9', {
          response: { id: 'resp_1', model: 'sam-3.1', usage: { input_tokens: 7, output_tokens: 3 } }
        })
      };
    };
    let out;
    try {
      out = await segmentUiRegions(PNG_1X1, ['button', 'card'], { dims: { width: 200, height: 200 } });
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    assert.strictEqual(calls, 2, 'one request per prompt, no extras');
    assert.strictEqual(out.mode, 'live');
    assert.strictEqual(out.status, 'success');
    assert.strictEqual(out.samModelConfigured, config.samModel);
    assert.strictEqual(out.samModelObserved, 'sam-3.1');
    assert.strictEqual(out.responseId, 'resp_1');
    assert.deepStrictEqual(out.usage, { input_tokens: 7, output_tokens: 3 });
    assert.match(out.submittedImageDigest, /^[0-9a-f]{64}$/);
    assert.match(out.outputDigest, /^[0-9a-f]{64}$/);
    assert.strictEqual(out.perPrompt.length, 2);
    assert.deepStrictEqual(out.perPrompt.map((p) => p.status), ['success', 'success']);
    assert.deepStrictEqual(out.perPrompt.map((p) => p.index), [0, 1]);
    for (const p of out.perPrompt) {
      assert.ok(p.invokedAt <= p.completedAt);
      assert.strictEqual(p.responseId, 'resp_1');
      assert.match(p.inputDigest, /^[0-9a-f]{64}$/);
      assert.match(p.outputDigest, /^[0-9a-f]{64}$/);
    }
    // Determinism: identical inputs hash identically.
    global.fetch = async () => ({
      ok: true,
      text: async () => samOkBody('x1=10;y1=20;x2=110;y2=120;c=0.9', {})
    });
    let first;
    let second;
    try {
      first = await segmentUiRegions(PNG_1X1, ['button'], { dims: { width: 200, height: 200 } });
      second = await segmentUiRegions(PNG_1X1, ['button'], { dims: { width: 200, height: 200 } });
    } finally {
      global.fetch = realFetch;
    }
    assert.strictEqual(second.outputDigest, first.outputDigest, 'identical outputs hash identically');
    assert.strictEqual(second.submittedImageDigest, first.submittedImageDigest, 'identical inputs hash identically');
    restoreKey();
    console.log('✔ Test 5 Passed: SAM success per-prompt provenance captured.');
  }

  // Test 6: SAM partial failure is never reported as unqualified success.
  {
    const restoreKey = useLiveKey();
    let calls = 0;
    global.fetch = async (url, opts) => {
      calls += 1;
      const prompt = JSON.parse(opts.body).input[0].content[0].text;
      if (prompt.includes('bad')) throw new Error('boom');
      return { ok: true, text: async () => samOkBody('x1=10;y1=20;x2=30;y2=40', {}) };
    };
    let out;
    try {
      out = await segmentUiRegions(PNG_1X1, ['good-a', 'bad', 'good-b'], { dims: { width: 200, height: 200 } });
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    assert.strictEqual(calls, 3);
    assert.strictEqual(out.status, 'partial');
    assert.strictEqual(out.partialFailure, true, 'legacy flag preserved');
    assert.deepStrictEqual(out.perPrompt.map((p) => p.status), ['success', 'error', 'success']);
    assert.ok(out.perPrompt[1].error.includes('boom'));
    assert.ok(Number.isInteger(out.perPrompt[1].invokedAt), 'failed attempt keeps invokedAt');
    assert.match(out.perPrompt[1].inputDigest, /^[0-9a-f]{64}$/, 'failed attempt keeps input digest');
    assert.strictEqual(out.perPrompt[1].outputDigest, null);
    assert.ok(out.outputDigest, 'surviving regions still digestible');
    restoreKey();
    console.log('✔ Test 6 Passed: SAM partial failure preserved per prompt.');
  }

  // Test 7: SAM timeout, all-failed, zero-detection, mock, invalid input.
  {
    const restoreKey = useLiveKey();
    // Timeout code preserved with attempt evidence.
    global.fetch = async () => { const e = new Error('x'); e.name = 'AbortError'; throw e; };
    let out;
    try {
      out = await segmentUiRegions(PNG_1X1, ['button'], { dims: { width: 10, height: 10 } });
    } finally {
      global.fetch = realFetch;
    }
    assert.strictEqual(out.status, 'failed');
    assert.strictEqual(out.perPrompt[0].status, 'timeout');
    assert.strictEqual(out.perPrompt[0].timeout, true);
    assert.ok(Number.isInteger(out.invokedAt) && Number.isInteger(out.completedAt));
    assert.strictEqual(out.outputDigest, null);
    // Zero detections is an honest successful empty result.
    global.fetch = async () => ({ ok: true, text: async () => sseFrame({ type: 'response.completed' }) });
    try {
      out = await segmentUiRegions(PNG_1X1, ['button'], { dims: { width: 10, height: 10 } });
    } finally {
      global.fetch = realFetch;
    }
    assert.strictEqual(out.status, 'success');
    assert.strictEqual(out.detectedCount, 0);
    assert.strictEqual(out.outputDigest, sha256Hex('[]'), 'empty set hashes honestly');
    // Mock mode: no fetch, null digests, mock regions excluded.
    let calls = 0;
    global.fetch = async () => { calls += 1; throw new Error('must not call'); };
    const restoreMock = useMockKey();
    try {
      out = await segmentUiRegions(PNG_1X1, ['button']);
    } finally {
      global.fetch = realFetch;
      restoreMock();
    }
    assert.strictEqual(calls, 0);
    assert.strictEqual(out.status, 'mock');
    assert.strictEqual(out.outputDigest, null);
    // Invalid input: failed without any provider attempt.
    calls = 0;
    global.fetch = async () => { calls += 1; throw new Error('must not call'); };
    try {
      out = await segmentUiRegions(123, ['button']);
    } finally {
      global.fetch = realFetch;
    }
    assert.strictEqual(calls, 0);
    assert.strictEqual(out.status, 'failed');
    assert.strictEqual(out.perPrompt[0].invokedAt, null, 'never attempted: no timestamps');
    assert.strictEqual(out.perPrompt[0].inputDigest, null);
    restoreKey();
    console.log('✔ Test 7 Passed: SAM timeout/empty/mock/invalid outcomes correct.');
  }

  // Test 8: bundle carries both provenance blocks; direct callers get honest defaults.
  {
    const bundle = compileEvidenceBundle({
      decodedTx: {},
      pageContext: {},
      visualResult: {
        regions: [], detectedCount: 0, visualAvailable: false,
        samMode: 'live', samStatus: 'success', samModelConfigured: 'sam-3.1',
        samOutputDigest: 'ab'.repeat(32), samPromptResults: [{ prompt: 'b', index: 0, status: 'success' }],
        screenshot: { sha256: 'cd'.repeat(32), width: 10, height: 10 }
      },
      reasoningResult: {
        origin: 'model', modelId: 'echo', latencyMs: 5, usage: { total_tokens: 3 },
        modelRequested: 'req', provider: 'meta-model-api', apiEndpoint: 'chat/completions',
        museProvenance: { provenanceStatus: 'success', invokedAt: 1, completedAt: 2, inputDigest: 'i', outputDigest: 'o', responseId: 'r', responseCreated: 3 }
      }
    });
    assert.strictEqual(bundle.museProvenance.status, 'success');
    assert.strictEqual(bundle.museProvenance.served, 'echo');
    assert.strictEqual(bundle.museProvenance.outputDigest, 'o');
    assert.strictEqual(bundle.samProvenance.status, 'success');
    assert.strictEqual(bundle.samProvenance.screenshotDigest, 'cd'.repeat(32));
    assert.strictEqual(bundle.samProvenance.perPrompt.length, 1);
    const bare = compileEvidenceBundle({ decodedTx: {}, pageContext: {}, visualResult: { regions: [] }, reasoningResult: { origin: 'heuristic-fallback' } });
    assert.strictEqual(bare.museProvenance.status, 'unknown', 'no invented Muse status');
    assert.strictEqual(bare.museProvenance.outputDigest, null);
    assert.strictEqual(bare.samProvenance.status, 'skipped');
    assert.deepStrictEqual(bare.samProvenance.perPrompt, []);
    console.log('✔ Test 8 Passed: bundle carry-through with honest defaults.');
  }

  // Test 9: controller exposes provenance end to end (mock SAM, skipped
  // Muse, OCR stubbed); agent path without screenshot reports SAM skipped.
  {
    const ctl = loadControllerWithOcr(async () => ({ combinedText: '', perRegion: [] }));
    const restoreMock = useMockKey();
    let shot;
    try {
      shot = await runWith(ctl.handleEvaluateTransaction, { transaction: TX, pageContext: PAGE, screenshot: PNG_1X1 });
    } finally {
      restoreMock();
    }
    assert.strictEqual(shot.status, 200);
    assert.strictEqual(shot.body.samProvenance.status, 'mock');
    assert.strictEqual(shot.body.samProvenance.screenshotDigest.length, 64, 'intake byte digest projected');
    assert.strictEqual(shot.body.museProvenance.status, 'skipped');
    const restoreMock2 = useMockKey();
    let agent;
    try {
      agent = await runWith(ctl.handleEvaluateTransaction, { transaction: TX, pageContext: PAGE });
    } finally {
      restoreMock2();
    }
    assert.strictEqual(agent.status, 200);
    assert.strictEqual(agent.body.samProvenance.status, 'skipped');
    console.log('✔ Test 9 Passed: controller carry-through incl. screenshot digest.');
  }

  // Test 10: persisted record links trace and carries invocation evidence.
  {
    const tmpDir = path.join(__dirname, '..', 'tmp', `prov-${process.pid}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    const tmpFile = path.join(tmpDir, 'inv.jsonl');
    const origFile = config.investigationsFile;
    config.investigationsFile = tmpFile;
    const restoreKey = useLiveKey();
    const realFetch2 = global.fetch;
    global.fetch = async () => ({
      ok: true,
      json: async () => ({
        id: 'chatcmpl-rec', model: 'muse-spark-1.3',
        choices: [{ message: { content: MODEL_OK } }],
        usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 }
      })
    });
    try {
      const ctl = require('../../src/controllers/evaluateController');
      const trace = telemetry.createTrace({ source: 'test' });
      const out = await runWith(ctl.handleEvaluateTransaction, { transaction: TX, pageContext: PAGE }, { trace });
      assert.strictEqual(out.status, 200);
      const lines = fs.readFileSync(tmpFile, 'utf8').trim().split('\n');
      assert.strictEqual(lines.length, 1, 'model-origin record persisted once');
      const rec = JSON.parse(lines[0]);
      assert.strictEqual(rec.traceId, trace.id, 'record links its trace');
      assert.strictEqual(rec.museProvenance.status, 'success');
      assert.strictEqual(rec.museProvenance.responseId, 'chatcmpl-rec');
      assert.strictEqual(rec.museProvenance.outputDigest, sha256Hex(MODEL_OK));
      assert.strictEqual(rec.samProvenance.status, 'skipped', 'agent-less path without screenshot');
    } finally {
      global.fetch = realFetch2;
      restoreKey();
      config.investigationsFile = origFile;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
    console.log('✔ Test 10 Passed: persisted record links trace with evidence.');
  }

  console.log('\nAll Phase 1 Provenance Tests Passed Successfully!');
}

runProvenanceTests().catch((err) => { console.error(err); process.exit(1); });
