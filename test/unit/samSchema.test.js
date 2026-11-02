const assert = require('assert');
const config = require('../../src/config/env');
const {
  buildSamRequestBody,
  accumulateSegmentationText,
  extractBoxesFromSegmentationText,
  dedupeRegions,
  segmentUiRegions,
  DEFAULT_PROMPTS,
  SUMMARY_PROMPT
} = require('../../src/services/samService');

// Fix 3: mock primitives honoring AbortSignal the way undici does. A mock
// that ignores the signal would hang forever if the service regressed, so a
// missing signal rejects immediately to fail the test honestly.
function abortError() {
  const e = new Error('The operation was aborted');
  e.name = 'AbortError';
  return e;
}
function hangOnSignal(signal) {
  return new Promise((_, reject) => {
    if (!signal || typeof signal.addEventListener !== 'function') {
      reject(new Error('test mock requires an AbortSignal'));
      return;
    }
    if (signal.aborted) {
      reject(abortError());
      return;
    }
    signal.addEventListener('abort', () => reject(abortError()), { once: true });
  });
}

async function runSamSchemaTests() {
  console.log('Testing SAM 3.1 Request Schema & Output Parsing...\n');

  // Test 1: Request body matches Meta's documented Responses API shape.
  // See https://dev.meta.ai/docs/sam/segmenting — there is no top-level
  // `prompts` parameter (it 400s with "unknown parameter 'prompts'") and no
  // `image_base64` part type; the image goes in as an `input_image` data URL.
  const body = buildSamRequestBody('sam-3.1', 'button', 'data:image/png;base64,AAA');
  assert.strictEqual(body.model, 'sam-3.1', 'Should target the SAM model');
  assert.ok(!('prompts' in body), 'Body must not contain top-level prompts');
  assert.strictEqual(body.stream, true, 'Should request a streamed response');
  assert.strictEqual(body.input.length, 1, 'Should send one message');
  assert.strictEqual(body.input[0].type, 'message', 'Input item should be a message');
  assert.strictEqual(body.input[0].role, 'user', 'Message role should be user');
  const [textPart, imagePart] = body.input[0].content;
  assert.strictEqual(textPart.type, 'input_text', 'First part should be input_text');
  assert.strictEqual(textPart.text, 'button', 'Should carry the single concept phrase');
  assert.strictEqual(imagePart.type, 'input_image', 'Second part should be input_image');
  assert.strictEqual(imagePart.image_url, 'data:image/png;base64,AAA', 'Should pass the image data URL');
  console.log('✔ Test 1 Passed: Request body uses the documented Meta schema.');

  // Test 2: SSE accumulation concatenates output_text deltas until completion.
  const sse = [
    'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;"}',
    'data: {"type":"response.output_text.delta","delta":"x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}',
    'data: {"type":"response.completed"}',
    ''
  ].join('\n');
  const accumulated = accumulateSegmentationText(sse);
  assert.strictEqual(accumulated.completed, true, 'Should detect response.completed');
  assert.strictEqual(
    accumulated.outputText,
    '<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>',
    'Should concatenate delta payloads in order'
  );
  console.log('✔ Test 2 Passed: Streamed output_text accumulates until completion.');

  // Test 3: Box tokens parse to pixel regions (x2/y2 inclusive per Meta docs).
  const regions = extractBoxesFromSegmentationText(accumulated.outputText, 'button');
  assert.strictEqual(regions.length, 1, 'Should extract one region');
  assert.strictEqual(regions[0].label, 'button', 'Region should keep the concept label');
  assert.deepStrictEqual(
    regions[0].boundingBox,
    { x: 1, y: 2, width: 11, height: 11 },
    'Bounding box should use inclusive x2/y2 pixel math'
  );
  assert.strictEqual(regions[0].confidence, null, 'Missing c= must stay null, never defaulted');
  assert.strictEqual(regions[0].genuine, true, 'Parsed detections are genuine observations');
  assert.deepStrictEqual(regions[0].prompts, ['button'], 'Detection keeps its producing prompt');
  console.log('✔ Test 3 Passed: Box grammar parses to pixel bounding boxes.');

  // Test 4: Documented image example with confidence parses every record.
  const docLine = '<0f>0<|box;x1=353;y1=382;x2=453;y2=427;w=537;h=561;c=0.96|>'
    + '<|mask;x=0;y=0;c=0.96;data=46,101,~AAA|>,1<|box;x1=260;y1=382;x2=340;y2=427;w=537;h=561|>'
    + '<|mask;x=0;y=0;data=46,81,~BBB|>';
  const docRegions = extractBoxesFromSegmentationText(docLine, 'button');
  assert.strictEqual(docRegions.length, 2, 'Should extract both records');
  assert.strictEqual(docRegions[0].confidence, 0.96, 'Should read confidence by key');
  assert.strictEqual(docRegions[1].confidence, null, 'Record without c= keeps null confidence');
  assert.deepStrictEqual(docRegions[1].boundingBox, { x: 260, y: 382, width: 81, height: 46 });
  console.log('✔ Test 4 Passed: Multi-record output parses with per-record confidence.');

  // Test 5: Zero matches (empty output_text) is valid and yields no regions.
  const empty = accumulateSegmentationText('data: {"type":"response.completed"}\n');
  assert.strictEqual(empty.completed, true, 'Empty stream should still complete');
  assert.strictEqual(empty.outputText, '', 'Zero matches means empty output_text');
  assert.deepStrictEqual(extractBoxesFromSegmentationText(empty.outputText, 'button'), []);
  console.log('✔ Test 5 Passed: Zero-match output is a valid empty result.');

  // Test 6 (Phase 1): duplicates merge with prompt associations preserved.
  {
    const a = { label: 'button', boundingBox: { x: 10, y: 10, width: 100, height: 50 }, confidence: null, genuine: true, prompts: ['button'] };
    const b = { label: 'dialog box', boundingBox: { x: 11, y: 11, width: 100, height: 50 }, confidence: null, genuine: true, prompts: ['dialog box'] };
    const c = { label: 'button', boundingBox: { x: 500, y: 500, width: 40, height: 40 }, confidence: null, genuine: true, prompts: ['button'] };
    const merged = dedupeRegions([a, b, c]);
    assert.strictEqual(merged.length, 2, 'Near-duplicate pair must merge, disjoint box kept');
    assert.deepStrictEqual(merged[0].prompts.sort(), ['button', 'dialog box'], 'Merged region keeps both prompts');
    assert.strictEqual(merged[0].label, 'button', 'First prompt wins the label');
    assert.deepStrictEqual(dedupeRegions([]), [], 'Empty input stays empty');
    console.log('✔ Test 6 Passed: Cross-prompt duplicates merge with associations kept.');
  }

  // Test 7 (Phase 1): mock mode is labeled and never counts as detections.
  {
    const original = config.modelApiKey;
    config.modelApiKey = 'mock_phase1';
    try {
      const res = await segmentUiRegions('dummy');
      assert.strictEqual(res.mode, 'mock');
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.detectedCount, 0, 'Mock regions are not genuine detections');
      assert.strictEqual(res.fallback, null, 'Mock mode needs no fallback');
      assert.ok(res.regions.length > 0 && res.regions.every((r) => r.genuine === false), 'Every mock region flagged non-genuine');
    } finally {
      config.modelApiKey = original;
    }
    console.log('✔ Test 7 Passed: Mock mode is labeled and claim-free.');
  }

  // Test 8 (Phase 1): zero detections vs API errors stay distinguishable.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    try {
      global.fetch = async () => ({ ok: true, text: async () => 'data: {"type":"response.completed"}\n' });
      const zero = await segmentUiRegions('dummy', ['button'], { dims: { width: 1366, height: 632 } });
      assert.strictEqual(zero.success, true, 'Empty result is success, not failure');
      assert.deepStrictEqual(zero.regions, [], 'Zero detections yield zero regions');
      assert.strictEqual(zero.detectedCount, 0);
      assert.strictEqual(zero.fallback.reason, 'zero-detections');
      assert.strictEqual(zero.fallback.region.synthetic, true, 'Fallback explicitly marked synthetic');
      assert.strictEqual(zero.fallback.region.genuine, false);
      assert.deepStrictEqual(zero.fallback.region.boundingBox, { x: 0, y: 0, width: 1366, height: 632 }, 'Fallback covers the true full image');
      global.fetch = async () => ({ ok: false, status: 500, text: async () => 'internal error' });
      const failed = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(failed.success, false, 'API failure is not success');
      assert.ok(failed.error.includes('500'), 'Error text preserved');
      assert.deepStrictEqual(failed.regions, [], 'Failed run yields zero regions');
      assert.strictEqual(failed.fallback.reason, 'error', 'Error fallback distinguished from zero-match');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 8 Passed: Empty success and API error stay distinct.');
  }

  // Test 9 (Phase 1): production defaults target firing transaction concepts.
  {
    assert.ok(Array.isArray(DEFAULT_PROMPTS) && DEFAULT_PROMPTS.length > 0);
    assert.ok(DEFAULT_PROMPTS.includes('button'), 'Proven firing prompt must be a default');
    assert.ok(DEFAULT_PROMPTS.every((p) => typeof p === 'string' && p.length > 0));
    await assert.rejects(segmentUiRegions('dummy', {}), TypeError, 'Non-array prompts rejected loudly');
    console.log('✔ Test 9 Passed: Production defaults pinned; bad prompts rejected.');
  }

  // Test 10 (Fix 1): one prompt 500s while another cleanly zeroes — the
  // failure stays visible instead of collapsing into a clean zero.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url, opts) => {
      const c = JSON.parse(opts.body).input[0].content[0].text;
      if (c === 'button') return { ok: false, status: 500, text: async () => 'boom' };
      return { ok: true, text: async () => 'data: {"type":"response.completed"}\n' };
    };
    try {
      const res = await segmentUiRegions('dummy', ['button', 'dialog box']);
      assert.strictEqual(res.success, true, 'Partial results stay usable');
      assert.strictEqual(res.partialFailure, true, 'Partial failure flagged explicitly');
      assert.ok(res.error.includes('button') && res.error.includes('500'), 'Failed prompt error preserved');
      assert.strictEqual(res.detectedCount, 0);
      assert.deepStrictEqual(res.regions, [], 'No regions fabricated from failure');
      assert.strictEqual(res.fallback.reason, 'partial-error', 'Partial zero distinct from clean zero');
      assert.strictEqual(res.perPrompt.length, 2, 'Every prompt status kept');
      assert.ok(res.perPrompt.find((p) => p.prompt === 'button').error.includes('500'));
      assert.strictEqual(res.perPrompt.find((p) => p.prompt === 'dialog box').error, undefined);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 10 Passed: Partial 500 + zero stays visible and honest.');
  }

  // Test 11 (Fix 1): a successful prompt's genuine detections survive
  // another prompt's failure; no fallback displaces real evidence.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}\n'
      + 'data: {"type":"response.completed"}\n';
    global.fetch = async (url, opts) => {
      const c = JSON.parse(opts.body).input[0].content[0].text;
      if (c === 'dialog box') return { ok: false, status: 500, text: async () => 'boom' };
      return { ok: true, text: async () => boxSse };
    };
    try {
      const res = await segmentUiRegions('dummy', ['button', 'dialog box']);
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.partialFailure, true, 'Failure flagged despite surviving evidence');
      assert.ok(res.error.includes('dialog box') && res.error.includes('500'));
      assert.strictEqual(res.detectedCount, 1, 'Genuine detection preserved');
      assert.strictEqual(res.regions[0].genuine, true);
      assert.deepStrictEqual(res.regions[0].boundingBox, { x: 1, y: 2, width: 11, height: 11 });
      assert.strictEqual(res.regions[0].regionId, 'R-001');
      assert.strictEqual(res.fallback, null, 'No fallback displaces genuine detections');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 11 Passed: Detections survive a sibling prompt failure.');
  }

  // Test 12 (Fix 2): boxes without the completion event are preserved
  // but explicitly marked incomplete — never a clean success.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const truncated = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}\n';
    global.fetch = async () => ({ ok: true, text: async () => truncated });
    try {
      const res = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(res.success, true, 'Parsed output stays usable');
      assert.strictEqual(res.incomplete, true, 'Missing completion flagged');
      assert.strictEqual(res.detectedCount, 1, 'Parsed boxes preserved');
      assert.strictEqual(res.regions[0].genuine, true);
      assert.deepStrictEqual(res.regions[0].boundingBox, { x: 1, y: 2, width: 11, height: 11 });
      assert.strictEqual(res.fallback, null, 'No fallback displaces parsed detections');
      assert.strictEqual(res.perPrompt.length, 1);
      const entry = res.perPrompt[0];
      assert.strictEqual(entry.prompt, 'button');
      assert.strictEqual(entry.matches, 1);
      assert.strictEqual(entry.incomplete, true);
      assert.strictEqual(entry.detail, 'stream ended without response.completed');
      assert.strictEqual(entry.status, 'incomplete');
      assert.strictEqual(entry.index, 0);
      assert.ok(entry.invokedAt <= entry.completedAt, 'attempt timestamps ordered');
      assert.match(entry.inputDigest, /^[0-9a-f]{64}$/, 'attempt keeps input digest');
      assert.strictEqual(entry.outputDigest, null, 'no output digest without completion');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 12 Passed: Truncated boxes preserved and marked incomplete.');
  }

  // Test 13 (Fix 2): an empty HTTP 200 body is unvalidatable — incomplete,
  // never a clean zero-detection result.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({ ok: true, text: async () => '' });
    try {
      const res = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.incomplete, true, 'Empty body cannot validate');
      assert.strictEqual(res.detectedCount, 0);
      assert.deepStrictEqual(res.regions, []);
      assert.strictEqual(res.fallback.reason, 'incomplete', 'Not a clean zero');
      assert.strictEqual(res.perPrompt[0].detail, 'empty response body');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 13 Passed: Empty 200 body is incomplete, not zero.');
  }

  // Test 14 (Fix 2): invalid SSE/JSON payloads are incomplete, not zero.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({ ok: true, text: async () => 'data: not-json{{{\ndata: {"type":"something-else"}\n' });
    try {
      const res = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(res.incomplete, true, 'Unparseable stream cannot validate');
      assert.strictEqual(res.detectedCount, 0);
      assert.strictEqual(res.fallback.reason, 'incomplete');
      assert.strictEqual(res.perPrompt[0].detail, 'stream ended without response.completed');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 14 Passed: Malformed payloads are incomplete, not zero.');
  }

  // Test 15 (Fix 2): Fix 1 partial-errors compose with incompleteness —
  // both flags set, error channel carries only the hard failure.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url, opts) => {
      const c = JSON.parse(opts.body).input[0].content[0].text;
      if (c === 'button') return { ok: false, status: 500, text: async () => 'boom' };
      return { ok: true, text: async () => '' };
    };
    try {
      const res = await segmentUiRegions('dummy', ['button', 'dialog box']);
      assert.strictEqual(res.partialFailure, true, 'Hard failure flagged');
      assert.strictEqual(res.incomplete, true, 'Truncation flagged alongside');
      assert.ok(res.error.includes('button') && res.error.includes('500'), 'Error channel carries the 500');
      assert.ok(!res.error.includes('dialog box'), 'Incomplete prompt is not an error entry');
      assert.strictEqual(res.fallback.reason, 'partial-error', 'Hard errors dominate the fallback reason');
      const byName = Object.fromEntries(res.perPrompt.map((p) => [p.prompt, p]));
      assert.ok(byName.button.error.includes('500'));
      assert.strictEqual(byName.button.incomplete, undefined, 'Error entries are not double-marked');
      assert.strictEqual(byName['dialog box'].incomplete, true);
      assert.strictEqual(byName['dialog box'].error, undefined, 'Incomplete entries are not error entries');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 15 Passed: Partial-error and incomplete stay distinct.');
  }

  // Test 16 (Fix 3): a request that never resolves until aborted is
  // classified as a timeout instead of hanging.
  {
    const origKey = config.modelApiKey;
    const origMs = config.samTimeoutMs;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    config.samTimeoutMs = 50;
    global.fetch = async (url, opts) => hangOnSignal(opts.signal);
    try {
      const t0 = Date.now();
      const res = await segmentUiRegions('dummy', ['button']);
      assert.ok(Date.now() - t0 < 5000, 'bounded call must not hang');
      assert.strictEqual(res.success, false);
      assert.deepStrictEqual(res.regions, [], 'No regions fabricated on timeout');
      assert.strictEqual(res.fallback.reason, 'error');
      assert.strictEqual(res.perPrompt[0].timeout, true, 'Stable timeout classification');
      assert.ok(res.error.includes('timed out'), 'Timeout detail preserved');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
      config.samTimeoutMs = origMs;
    }
    console.log('✔ Test 16 Passed: Hung requests abort with timeout classification.');
  }

  // Test 17 (Fix 3): a body stalled after headers is bounded too — the
  // timeout covers response consumption, not just connection setup.
  {
    const origKey = config.modelApiKey;
    const origMs = config.samTimeoutMs;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    config.samTimeoutMs = 50;
    global.fetch = async (url, opts) => ({ ok: true, text: () => hangOnSignal(opts.signal) });
    try {
      const res = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(res.success, false, 'Stalled body is a failure, not a result');
      assert.strictEqual(res.perPrompt[0].timeout, true);
      assert.strictEqual(res.fallback.reason, 'error');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
      config.samTimeoutMs = origMs;
    }
    console.log('✔ Test 17 Passed: Stalled response bodies are bounded.');
  }

  // Test 18 (Fix 3): one prompt timing out while another succeeds — the
  // success is preserved and the timeout records as a partial failure.
  {
    const origKey = config.modelApiKey;
    const origMs = config.samTimeoutMs;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    config.samTimeoutMs = 50;
    global.fetch = async (url, opts) => {
      const c = JSON.parse(opts.body).input[0].content[0].text;
      if (c === 'button') return hangOnSignal(opts.signal);
      return { ok: true, text: async () => 'data: {"type":"response.completed"}\n' };
    };
    try {
      const res = await segmentUiRegions('dummy', ['button', 'dialog box']);
      assert.strictEqual(res.success, true, 'Usable output preserved');
      assert.strictEqual(res.partialFailure, true, 'Timeout composes with Fix 1 aggregation');
      assert.strictEqual(res.fallback.reason, 'partial-error');
      const byName = Object.fromEntries(res.perPrompt.map((p) => [p.prompt, p]));
      assert.strictEqual(byName.button.timeout, true);
      assert.ok(byName.button.error.includes('timed out'));
      assert.strictEqual(byName['dialog box'].timeout, undefined, 'Clean prompt unmarked');
      assert.strictEqual(byName['dialog box'].error, undefined);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
      config.samTimeoutMs = origMs;
    }
    console.log('✔ Test 18 Passed: Timeout + success composes as partial failure.');
  }

  // Test 19 (Fix 3): all prompts timing out produce a bounded aggregate
  // failure with every timeout classified.
  {
    const origKey = config.modelApiKey;
    const origMs = config.samTimeoutMs;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    config.samTimeoutMs = 50;
    global.fetch = async (url, opts) => hangOnSignal(opts.signal);
    try {
      const res = await segmentUiRegions('dummy', ['button', 'dialog box']);
      assert.strictEqual(res.success, false);
      assert.strictEqual(res.partialFailure, false, 'Total failure is not partial');
      assert.strictEqual(res.fallback.reason, 'error');
      assert.ok(res.perPrompt.every((p) => p.timeout === true), 'Every prompt classified');
      assert.ok(res.error.includes('button') && res.error.includes('dialog box'));
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
      config.samTimeoutMs = origMs;
    }
    console.log('✔ Test 19 Passed: Total timeout is a bounded aggregate failure.');
  }

  // Test 20 (Fix 3): timer cleanup — fast and within-bound responses are
  // never spuriously aborted.
  {
    const origKey = config.modelApiKey;
    const origMs = config.samTimeoutMs;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}\n'
      + 'data: {"type":"response.completed"}\n';
    try {
      config.samTimeoutMs = 50;
      global.fetch = async () => ({ ok: true, text: async () => boxSse });
      const fast = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(fast.detectedCount, 1, 'Fast success unaffected by the timer');
      assert.strictEqual(fast.perPrompt[0].timeout, undefined);
      assert.strictEqual(fast.incomplete, false);
      config.samTimeoutMs = 2000;
      global.fetch = async () => {
        await new Promise((r) => setTimeout(r, 30));
        return { ok: true, text: async () => boxSse };
      };
      const slow = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(slow.detectedCount, 1, 'Within-bound responses complete');
      assert.strictEqual(slow.perPrompt[0].timeout, undefined);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
      config.samTimeoutMs = origMs;
    }
    console.log('✔ Test 20 Passed: Cleanup leaves normal requests intact.');
  }

  // Test 21 (config fix): the configured timeout value drives the bound.
  {
    const origKey = config.modelApiKey;
    const origMs = config.samTimeoutMs;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    config.samTimeoutMs = 45;
    global.fetch = async (url, opts) => hangOnSignal(opts.signal);
    try {
      const res = await segmentUiRegions('dummy', ['button']);
      assert.ok(res.error.includes('45ms'), 'Configured value reaches the service');
      assert.strictEqual(res.perPrompt[0].timeout, true);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
      config.samTimeoutMs = origMs;
    }
    console.log('✔ Test 21 Passed: Configured SAM timeout drives the bound.');
  }

  // Test 22 (Phase 3): fallback geometry follows true image dimensions,
  // including small and non-4:3 screenshots.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({ ok: true, text: async () => 'data: {"type":"response.completed"}\n' });
    try {
      for (const [w, h] of [[1366, 632], [800, 600], [1, 1], [500, 2000], [2000, 500]]) {
        const res = await segmentUiRegions('dummy', ['button'], { dims: { width: w, height: h } });
        assert.strictEqual(res.fallback.reason, 'zero-detections');
        assert.deepStrictEqual(
          res.fallback.region.boundingBox, { x: 0, y: 0, width: w, height: h },
          `Full-image fallback for ${w}x${h}`
        );
        assert.strictEqual(res.fallback.region.synthetic, true, 'Still explicitly synthetic');
      }
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 22 Passed: Fallback geometry matches true dimensions.');
  }

  // Test 23 (Phase 3): unknown or invalid dims make a clean zero
  // 'unavailable' — never a pretended scan.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({ ok: true, text: async () => 'data: {"type":"response.completed"}\n' });
    try {
      for (const [name, opts] of [
        ['missing opts', undefined],
        ['missing dims', {}],
        ['null dims', { dims: null }],
        ['negative', { dims: { width: -5, height: 600 } }],
        ['zero', { dims: { width: 0, height: 600 } }],
        ['non-integer', { dims: { width: 1.5, height: 600 } }],
        ['non-numeric', { dims: { width: 'x', height: 600 } }]
      ]) {
        const res = opts === undefined
          ? await segmentUiRegions('dummy', ['button'])
          : await segmentUiRegions('dummy', ['button'], opts);
        assert.strictEqual(res.fallback.reason, 'unavailable', `${name} cannot scan`);
        assert.strictEqual(res.fallback.region, null, `${name} yields no fabricated box`);
        assert.strictEqual(res.success, true, 'Clean zero stays success');
      }
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 23 Passed: Unknown dims are honestly unavailable.');
  }

  // Test 24 (Phase 3): hard-error causes survive missing dims; the operative
  // failure stays visible even though no scan geometry exists.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({ ok: false, status: 500, text: async () => 'boom' });
    try {
      const res = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(res.success, false);
      assert.strictEqual(res.fallback.reason, 'error', 'Operative cause preserved');
      assert.strictEqual(res.fallback.region, null, 'No fabricated box');
      assert.ok(res.error.includes('500'));
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 24 Passed: Error cause preserved without dims.');
  }

  // Test 25 (Phase 3): the summary prompt fires through the same supported
  // text-prompt mechanism and its regions carry the prompt tag.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    assert.ok(DEFAULT_PROMPTS.includes(SUMMARY_PROMPT), 'Summary prompt is a production default');
    const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=10;y1=20;x2=110;y2=120;w=200;h=200|>"}\n'
      + 'data: {"type":"response.completed"}\n';
    global.fetch = async () => ({ ok: true, text: async () => boxSse });
    try {
      const res = await segmentUiRegions('dummy', [SUMMARY_PROMPT], { dims: { width: 200, height: 200 } });
      assert.strictEqual(res.detectedCount, 1);
      assert.deepStrictEqual(res.regions[0].prompts, [SUMMARY_PROMPT], 'Region tagged with its prompt');
      assert.strictEqual(res.regions[0].genuine, true);
      assert.strictEqual(res.perPrompt[0].prompt, SUMMARY_PROMPT);
      assert.strictEqual(res.fallback, null, 'Detections need no fallback');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 25 Passed: Summary prompt flows through supported machinery.');
  }

  // Test 26 (Component 2): every prompt element must be a non-empty concept
  // string — a non-string element previously slipped into the request body.
  {
    await assert.rejects(segmentUiRegions('dummy', ['button', 123]), TypeError, 'Numeric element rejected');
    await assert.rejects(segmentUiRegions('dummy', ['button', '']), TypeError, 'Empty element rejected');
    await assert.rejects(segmentUiRegions('dummy', [null]), TypeError, 'Null element rejected');
    await assert.rejects(segmentUiRegions('dummy', []), TypeError, 'Empty array still rejected');
    console.log('✔ Test 26 Passed: Non-string prompt elements rejected loudly.');
  }

  // Test 27 (Component 2): a truthy non-string screenshot fails honestly in
  // the live path without issuing model requests (previously each prompt
  // burned one call that 400d on invalid base64). Shape matches a total API
  // failure so downstream handling is unchanged.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    let calls = 0;
    global.fetch = async () => { calls += 1; throw new Error('must not be called'); };
    try {
      const res = await segmentUiRegions(12345, ['button', 'dialog box']);
      assert.strictEqual(calls, 0, 'No network traffic for invalid input');
      assert.strictEqual(res.success, false);
      assert.strictEqual(res.mode, 'live');
      assert.deepStrictEqual(res.regions, []);
      assert.strictEqual(res.detectedCount, 0);
      assert.strictEqual(res.perPrompt.length, 2, 'One error entry per prompt');
      assert.ok(res.perPrompt.every((p) => p.matches === 0 && p.error.includes('got number')), 'Cause preserved per prompt');
      assert.ok(res.error.includes('expected a base64 string'), 'Aggregate error preserved');
      assert.strictEqual(res.fallback.reason, 'error');
      assert.strictEqual(res.fallback.region, null, 'No dims, no fabricated box');
      const withDims = await segmentUiRegions({ not: 'a string' }, ['button'], { dims: { width: 800, height: 600 } });
      assert.strictEqual(calls, 0, 'Still no network traffic');
      assert.deepStrictEqual(
        withDims.fallback.region.boundingBox, { x: 0, y: 0, width: 800, height: 600 },
        'Caller-verified dims still yield honest geometry'
      );
      assert.strictEqual(withDims.fallback.region.synthetic, true);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 27 Passed: Invalid screenshot fails without model calls.');
  }

  // Test 28 (Component 2): parser confidence and coordinate edge cases.
  // Malformed scores stay null; the parser preserves model coordinates
  // verbatim — geometric validity is downstream's job (cropImageRegion and
  // association both reject invalid boxes; per-region OCR records failures).
  {
    const malformed = extractBoxesFromSegmentationText(
      '<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100;c=high|>'
      + '<0f>1<|box;x1=20;y1=20;x2=30;y2=30;w=100;h=100;c=|>'
      + '<0f>2<|box;x1=40;y1=40;x2=50;y2=50;w=100;h=100;c=1|>',
      'button'
    );
    assert.strictEqual(malformed.length, 3, 'Boxes kept regardless of score shape');
    assert.strictEqual(malformed[0].confidence, null, 'Non-numeric c= stays null');
    assert.strictEqual(malformed[1].confidence, null, 'Empty c= stays null');
    assert.strictEqual(malformed[2].confidence, 1, 'Integer c= parses');
    const odd = extractBoxesFromSegmentationText(
      '<0f>0<|box;x1=-5;y1=2;x2=11;y2=12;w=100;h=100|>'
      + '<0f>1<|box;x1=30;y1=30;x2=10;y2=40;w=100;h=100|>',
      'button'
    );
    assert.strictEqual(odd.length, 2, 'Finite coordinates pass through verbatim');
    assert.deepStrictEqual(odd[0].boundingBox, { x: -5, y: 2, width: 17, height: 11 });
    assert.deepStrictEqual(odd[1].boundingBox, { x: 30, y: 30, width: -19, height: 11 });
    assert.ok(odd.every((r) => r.genuine === true), 'Pass-through keeps the genuine flag');
    const nonFinite = extractBoxesFromSegmentationText(
      '<0f>0<|box;x1=NaN;y1=2;x2=11;y2=12;w=100;h=100|>',
      'button'
    );
    assert.deepStrictEqual(nonFinite, [], 'Non-finite coordinates still dropped');
    console.log('✔ Test 28 Passed: Confidence/box edges handled and documented.');
  }

  // Test 29 (reliability fix): live SAM responses interleave <|mask;...|>
  // tokens between boxes (observed in the fixture probe). The parser must
  // skip mask payloads and still extract every box, with no confidence
  // fabricated (live boxes carry no c= field).
  {
    const liveShaped = '<0f>0<|box;x1=801;y1=343;x2=856;y2=371;w=1366;h=632|>'
      + '<|mask;x=0;y=0;data=29,56,~!!!$q!kCm?/XIw\u0027F#t^.nix.pTcPqPVY(@[*OmY|>'
      + '<0f>1<|box;x1=494;y1=411;x2=871;y2=458;w=1366;h=632|>';
    const boxes = extractBoxesFromSegmentationText(liveShaped, 'button');
    assert.strictEqual(boxes.length, 2, 'Both boxes survive mask interleaving');
    assert.deepStrictEqual(boxes[0].boundingBox, { x: 801, y: 343, width: 56, height: 29 });
    assert.deepStrictEqual(boxes[1].boundingBox, { x: 494, y: 411, width: 378, height: 48 });
    assert.ok(boxes.every((b) => b.confidence === null), 'No c= in stream means null, never defaulted');
    assert.ok(boxes.every((b) => b.genuine === true));
    console.log('✔ Test 29 Passed: Mask-interleaved live shape parses cleanly.');
  }

  console.log('\nAll SAM Schema Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runSamSchemaTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSamSchemaTests };
