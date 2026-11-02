const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { parseProbeArgs, validateImageFile, classifySamOutcome, runImageProbe } = require('../../src/scripts/probeMetaApi');

// Phase 3: probe CLI parsing, image validation, and outcome classification.
// Deterministic: no live API access (fetch is injected or never reached).
const FIXTURE = path.join(__dirname, '..', 'fixtures', 'sam', 'dapp-screenshot.png');
const SCRATCH = path.join(__dirname, '..', '..', 'data', '.test-tmp');

function boxSse() {
  const delta = JSON.stringify({ type: 'response.output_text.delta', delta: '<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>' });
  const done = JSON.stringify({ type: 'response.completed' });
  return `data: ${delta}\ndata: ${done}\n`;
}

async function runProbeTests() {
  console.log('Testing Probe CLI: Args, Validation & Classification...\n');

  // Test 1: argument parsing.
  {
    assert.deepStrictEqual(parseProbeArgs([]), { mode: 'default', imagePath: null, prompts: [] });
    assert.deepStrictEqual(
      parseProbeArgs(['img.png', 'button', 'dialog box']),
      { mode: 'image', imagePath: 'img.png', prompts: ['button', 'dialog box'] }
    );
    assert.deepStrictEqual(parseProbeArgs(['--', 'img.png', 'button']).prompts, ['button'], 'npm -- separator tolerated');
    assert.throws(() => parseProbeArgs(['img.png']), (e) => e.code === 'PROBE_USAGE', 'Prompts required with an image');
    assert.throws(() => parseProbeArgs(['img.png', '  ']), (e) => e.code === 'PROBE_USAGE', 'Empty prompt rejected');
    console.log('✔ Test 1 Passed: CLI args parse with strict usage errors.');
  }

  // Test 2: image validation (real fixture + synthetic bad inputs, offline).
  {
    const info = await validateImageFile(FIXTURE);
    assert.strictEqual(info.width, 1366);
    assert.strictEqual(info.height, 632);
    assert.strictEqual(info.mime, 'image/png');
    assert.ok(info.bytes > 10000);
    await assert.rejects(validateImageFile('does/not-exist.png'), (e) => e.code === 'PROBE_BAD_IMAGE');
    fs.mkdirSync(SCRATCH, { recursive: true });
    const txt = path.join(SCRATCH, 'probe-not-image.txt');
    const fakePng = path.join(SCRATCH, 'probe-fake.png');
    fs.writeFileSync(txt, 'hello');
    fs.writeFileSync(fakePng, 'this is not png data');
    try {
      await assert.rejects(validateImageFile(txt), (e) => e.code === 'PROBE_BAD_IMAGE', 'Bad extension rejected');
      await assert.rejects(validateImageFile(fakePng), (e) => e.code === 'PROBE_BAD_IMAGE', 'Unparseable bytes rejected');
    } finally {
      fs.rmSync(txt, { force: true });
      fs.rmSync(fakePng, { force: true });
    }
    console.log('✔ Test 2 Passed: Real image accepted; missing/fake rejected pre-network.');
  }

  // Test 3: outcome classification matrix.
  {
    assert.strictEqual(classifySamOutcome({ status: 200, completed: true, matches: 3 }), 'SUCCESS');
    assert.strictEqual(classifySamOutcome({ status: 200, completed: true, matches: 0 }), 'ZERO_DETECTIONS');
    assert.strictEqual(classifySamOutcome({ status: 500, completed: false, matches: 0 }), 'API_ERROR');
    assert.strictEqual(classifySamOutcome({ status: null, completed: false, matches: 0, transportError: 'boom' }), 'TRANSPORT_ERROR');
    assert.strictEqual(classifySamOutcome({ status: 200, completed: false, matches: 0 }), 'INCOMPLETE');
    console.log('✔ Test 3 Passed: All five outcome classes distinct.');
  }

  // Test 4: image probe with injected fetch writes raw output + parses boxes.
  {
    const original = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    const outDir = path.join(SCRATCH, 'probe-out');
    fs.rmSync(outDir, { recursive: true, force: true });
    const calls = [];
    const fetchImpl = async (url, opts) => {
      calls.push(JSON.parse(opts.body));
      const concept = calls[calls.length - 1].input[0].content[0].text;
      if (concept === 'button') return { status: 200, text: async () => boxSse() };
      if (concept === 'boom') throw new Error('socket hangup');
      return { status: 200, text: async () => 'data: {"type":"response.completed"}\n' };
    };
    try {
      const res = await runImageProbe({ imagePath: FIXTURE, prompts: ['button', 'nothing-here', 'boom'], outDir, fetchImpl });
      assert.strictEqual(res.info.width, 1366);
      assert.strictEqual(res.results.length, 3);
      assert.strictEqual(res.results[0].outcome, 'SUCCESS');
      assert.strictEqual(res.results[0].matches, 1);
      assert.strictEqual(res.results[0].boxes[0].confidence, null, 'Probe boxes carry honest null confidence');
      assert.deepStrictEqual(res.results[0].boxes[0].boundingBox, { x: 1, y: 2, width: 11, height: 11 });
      assert.strictEqual(res.results[1].outcome, 'ZERO_DETECTIONS');
      assert.strictEqual(res.results[2].outcome, 'TRANSPORT_ERROR');
      assert.ok(fs.existsSync(path.join(outDir, 'button.sse.txt')), 'Raw SSE saved per prompt');
      assert.ok(fs.existsSync(path.join(outDir, 'summary.json')), 'Summary saved');
      assert.ok(calls.every((b) => b.model === config.samModel && b.stream === true), 'Real request builder + configured model used');
    } finally {
      config.modelApiKey = original;
      fs.rmSync(outDir, { recursive: true, force: true });
    }
    console.log('✔ Test 4 Passed: Injected probe run saves raw output, parses honestly.');
  }

  // Test 5: image mode refuses to mock without a key (fetch never reached).
  {
    const original = config.modelApiKey;
    config.modelApiKey = 'mock_phase3';
    try {
      await assert.rejects(
        runImageProbe({ imagePath: FIXTURE, prompts: ['button'], fetchImpl: async () => { throw new Error('must not fetch'); } }),
        (e) => e.code === 'PROBE_NO_KEY'
      );
    } finally {
      config.modelApiKey = original;
    }
    console.log('✔ Test 5 Passed: Keyless image probe refuses instead of mocking.');
  }

  console.log('\nAll Probe CLI Tests Passed Successfully!\n');
}

if (require.main === module) {
  runProbeTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runProbeTests };
