const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const sharp = require('sharp');
const { base64ToBuffer, cropImageRegion, prepareOcrCrop, screenshotMeta } = require('../../src/utils/imageUtils');
const { extractTextFromRegion, extractUiTexts, closeOcrWorker } = require('../../src/services/ocrService');
const { compileEvidenceBundle } = require('../../src/services/evidenceService');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');
const { segmentUiRegions } = require('../../src/services/samService');

// Phase 2: OCR reliability + evidence provenance. Deterministic: injected
// recognizers, stubbed fetch, real sharp crops (offline). Anything labeled
// mock/override below is a test double, never live inference.
const DUMMY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const FIXTURE = path.join(__dirname, '..', 'fixtures', 'sam', 'dapp-screenshot.png');

// Load an ocrService whose Tesseract engine factory is stubbed, mirroring
// the simulator cache-injection idiom in evaluate.test.js. Everything else
// (crop, worker reuse, error wrapping, per-region recording) runs for real.
function loadOcrWithCreateWorker(fakeCreateWorker) {
  const tessPath = require.resolve('tesseract.js');
  const ocrPath = require.resolve('../../src/services/ocrService');
  const realTessEntry = require.cache[tessPath];
  const hadOcr = Object.prototype.hasOwnProperty.call(require.cache, ocrPath);
  const realOcrEntry = require.cache[ocrPath];
  const realTess = require('tesseract.js');
  require.cache[tessPath] = {
    id: tessPath, filename: tessPath, loaded: true,
    exports: { ...realTess, createWorker: fakeCreateWorker }
  };
  delete require.cache[ocrPath];
  try {
    return require(ocrPath);
  } finally {
    if (realTessEntry) require.cache[tessPath] = realTessEntry;
    else delete require.cache[tessPath];
    if (hadOcr) require.cache[ocrPath] = realOcrEntry;
    else delete require.cache[ocrPath];
  }
}

function mockWorker(text) {
  return { recognize: async () => ({ data: { text } }) };
}
function failingWorker(message) {
  return {
    recognize: async () => { const e = new Error(message); e.code = 'OCR_ENGINE_DOWN'; throw e; }
  };
}

async function runOcrProvenanceTests() {
  console.log('Testing OCR Reliability & Evidence Provenance...\n');

  // Test 1: successful region OCR preserves id, geometry, and text.
  {
    const regions = [
      { regionId: 'R-001', label: 'button', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true, confidence: null, prompts: ['button'] },
      { regionId: 'R-002', label: 'button', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true, confidence: 0.97, prompts: ['button'] }
    ];
    const res = await extractUiTexts(DUMMY_PNG, regions, mockWorker('Swap'));
    assert.strictEqual(res.regionTexts.length, 2);
    assert.strictEqual(res.regionTexts[0].regionId, 'R-001');
    assert.deepStrictEqual(res.regionTexts[0].boundingBox, { x: 0, y: 0, width: 1, height: 1 });
    assert.strictEqual(res.regionTexts[0].text, 'Swap');
    assert.strictEqual(res.regionTexts[0].empty, false);
    assert.strictEqual(res.regionTexts[0].ocrError, null);
    assert.strictEqual(res.regionTexts[1].confidence, 0.97, 'Confidence rides along untouched');
    assert.ok(res.combinedText.includes('[BUTTON]: Swap'));
    console.log('✔ Test 1 Passed: Region id, geometry, and text preserved.');
  }

  // Test 2: blank-but-successful OCR is distinct from OCR failure.
  {
    const blank = await extractUiTexts(DUMMY_PNG, [
      { regionId: 'R-001', label: 'button', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true }
    ], mockWorker('   '));
    assert.strictEqual(blank.regionTexts[0].text, '');
    assert.strictEqual(blank.regionTexts[0].empty, true, 'Blank read flagged empty');
    assert.strictEqual(blank.regionTexts[0].ocrError, null, 'Blank read is not a failure');
    assert.strictEqual(blank.combinedText, '', 'Blank regions contribute no text');
    const failed = await extractUiTexts(DUMMY_PNG, [
      { regionId: 'R-001', label: 'button', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true }
    ], failingWorker('tesseract exploded'));
    assert.strictEqual(failed.regionTexts[0].text, null, 'Failed read has no text');
    assert.strictEqual(failed.regionTexts[0].empty, false, 'Failed read is not blank');
    assert.strictEqual(failed.regionTexts[0].ocrError.code, 'OCR_ENGINE_DOWN');
    assert.ok(failed.regionTexts[0].ocrError.message.includes('tesseract exploded'));
    console.log('✔ Test 2 Passed: Blank success and failure are distinct states.');
  }

  // Test 3: OCR failure survives into the evidence bundle.
  {
    const bundle = compileEvidenceBundle({
      visualResult: {
        regions: [{ regionId: 'R-001', label: 'button', boundingBox: { x: 1, y: 2, width: 3, height: 4 }, genuine: true, confidence: null, prompts: ['button'] }],
        regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: { x: 1, y: 2, width: 3, height: 4 }, genuine: true, text: null, empty: false, ocrError: { code: 'OCR_FAILED', message: 'boom' } }],
        combinedText: '', detectedCount: 1, visualAvailable: true
      },
      decodedTx: { contract: '0x0', contractName: 'C', functionName: 'f', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] },
      reasoningResult: { verdict: 'UNCERTAIN' },
      simulationResult: null
    });
    assert.strictEqual(bundle.visualEvidence.regions.length, 1);
    assert.deepStrictEqual(bundle.visualEvidence.regions[0].ocr, { text: null, empty: false, error: { code: 'OCR_FAILED', message: 'boom' } });
    console.log('✔ Test 3 Passed: OCR failure preserved in bundle region.');
  }

  // Test 4: invalid crops throw coded errors; full image never substituted.
  {
    const ok = await cropImageRegion(DUMMY_PNG, { x: 0, y: 0, width: 1, height: 1 });
    assert.ok(Buffer.isBuffer(ok) && ok.length > 0, 'Valid 1x1 crop succeeds');
    for (const [name, box, code] of [
      ['negative origin', { x: -1, y: 0, width: 1, height: 1 }, 'BAD_BOX'],
      ['zero width', { x: 0, y: 0, width: 0, height: 1 }, 'BAD_BOX'],
      ['non-numeric', { x: 0, y: 0, width: '1', height: 1 }, 'BAD_BOX'],
      ['outside image', { x: 5, y: 5, width: 10, height: 10 }, 'BOX_OUT_OF_BOUNDS'],
      ['non-object', null, 'BAD_BOX']
    ]) {
      await assert.rejects(cropImageRegion(DUMMY_PNG, box), (e) => e.code === code, `${name} must throw ${code}`);
    }
    console.log('✔ Test 4 Passed: Invalid crops throw; no silent full-image return.');
  }

  // Test 5: one bad crop does not block valid regions.
  {
    const res = await extractUiTexts(DUMMY_PNG, [
      { regionId: 'R-001', label: 'button', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true },
      { regionId: 'R-002', label: 'button', boundingBox: { x: -5, y: 0, width: 10, height: 10 }, genuine: true },
      { regionId: 'R-003', label: 'button', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true }
    ], mockWorker('ok'));
    assert.strictEqual(res.regionTexts.length, 3);
    assert.strictEqual(res.regionTexts[0].text, 'ok');
    assert.strictEqual(res.regionTexts[1].ocrError.code, 'BAD_BOX');
    assert.strictEqual(res.regionTexts[2].text, 'ok', 'Valid region after a bad one still processed');
    console.log('✔ Test 5 Passed: Bad crops isolated per region.');
  }

  // Test 6: multiple regions with OCR join survive into the bundle.
  {
    const mk = (id) => ({
      regionId: id, label: 'button', boundingBox: { x: 1, y: 1, width: 2, height: 2 },
      genuine: true, confidence: null, prompts: ['button']
    });
    const regions = [mk('R-001'), mk('R-002'), mk('R-003')];
    const regionTexts = [
      { ...regions[0], text: 'Pay', empty: false, ocrError: null },
      { ...regions[1], text: '', empty: true, ocrError: null },
      { ...regions[2], text: null, empty: false, ocrError: { code: 'BOX_OUT_OF_BOUNDS', message: 'outside' } }
    ];
    const bundle = compileEvidenceBundle({
      visualResult: { regions, regionTexts, combinedText: '[BUTTON]: Pay', detectedCount: 3, visualAvailable: true },
      decodedTx: { contract: '0x0', contractName: 'C', functionName: 'f', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] },
      reasoningResult: { verdict: 'MATCH' },
      simulationResult: null
    });
    assert.strictEqual(bundle.visualEvidence.regions.length, 3, 'All three regions survive');
    assert.strictEqual(bundle.visualEvidence.regions[0].ocr.text, 'Pay');
    assert.strictEqual(bundle.visualEvidence.regions[1].ocr.empty, true);
    assert.strictEqual(bundle.visualEvidence.regions[2].ocr.error.code, 'BOX_OUT_OF_BOUNDS');
    assert.strictEqual(bundle.visualEvidence.ocrMode, 'regions');
    console.log('✔ Test 6 Passed: Full region list with OCR states reaches the bundle.');
  }

  // Test 7: ids, boxes, confidence, prompts, and genuine flags stay joined.
  {
    const res = await extractUiTexts(DUMMY_PNG, [
      { regionId: 'R-007', label: 'swap card', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true, confidence: 0.88, prompts: ['button', 'dialog box'] }
    ], mockWorker('Hi'));
    const r = res.regionTexts[0];
    assert.strictEqual(r.regionId, 'R-007');
    assert.deepStrictEqual(r.boundingBox, { x: 0, y: 0, width: 1, height: 1 });
    assert.strictEqual(r.confidence, 0.88);
    assert.deepStrictEqual(r.prompts, ['button', 'dialog box']);
    assert.strictEqual(r.genuine, true);
    assert.strictEqual(r.synthetic, false);
    console.log('✔ Test 7 Passed: Provenance fields stay associated with OCR.');
  }

  // Test 8: synthetic fallback stays separate from genuine detections.
  {
    const fb = { regionId: 'R-FALLBACK', label: 'fallback scan (synthetic)', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: false, synthetic: true };
    const res = await extractUiTexts(DUMMY_PNG, [fb], mockWorker('scan text'));
    assert.strictEqual(res.regionTexts[0].synthetic, true);
    assert.strictEqual(res.regionTexts[0].genuine, false);
    const bundle = compileEvidenceBundle({
      visualResult: {
        regions: [], regionTexts: [], combinedText: res.combinedText, combinedTextSynthetic: true,
        detectedCount: 0, visualAvailable: false, fallbackUsed: true, fallbackReason: 'zero-detections',
        fallbackRecords: res.regionTexts
      },
      decodedTx: { contract: '0x0', contractName: 'C', functionName: 'f', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] },
      reasoningResult: { verdict: 'UNCERTAIN' },
      simulationResult: null
    });
    assert.deepStrictEqual(bundle.visualEvidence.regions, [], 'Fallback never enters genuine regions');
    assert.strictEqual(bundle.visualEvidence.fallback.reason, 'zero-detections');
    assert.strictEqual(bundle.visualEvidence.fallback.regionId, 'R-FALLBACK');
    assert.strictEqual(bundle.visualEvidence.fallback.ocr.text, 'scan text');
    assert.strictEqual(bundle.visualEvidence.ocrMode, 'fallback-scan');
    assert.strictEqual(bundle.visualEvidence.textSources[0].synthetic, true);
    console.log('✔ Test 8 Passed: Synthetic fallback isolated and labeled.');
  }

  // Test 9 (Phase 1 intact): zero live detections + decode + safeguards.
  {
    const original = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({ ok: true, text: async () => 'data: {"type":"response.completed"}\n' });
    try {
      const sam = await segmentUiRegions('dummy', ['button'], { dims: { width: 1366, height: 632 } });
      assert.strictEqual(sam.detectedCount, 0);
      assert.strictEqual(sam.fallback.reason, 'zero-detections');
      assert.strictEqual(sam.fallback.region.synthetic, true);
      assert.deepStrictEqual(
        sam.fallback.region.boundingBox, { x: 0, y: 0, width: 1366, height: 632 },
        'Fallback covers the verified full image (Phase 3)'
      );
      const nodims = await segmentUiRegions('dummy', ['button']);
      assert.strictEqual(nodims.fallback.reason, 'unavailable', 'No dims means no runnable scan');
      assert.strictEqual(nodims.fallback.region, null, 'No fabricated box');
      const decoded = decodeTransactionCalldata({
        to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
        data: '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4',
        value: '0xde0b6b3a7640000'
      });
      assert.strictEqual(decoded.functionName, 'exactInputSingle');
      assert.strictEqual(decoded.isUnlimitedApproval, false);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = original;
    }
    console.log('✔ Test 9 Passed: Phase 1 fallback + deterministic decode intact.');
  }

  // Test 10: screenshot identity is stable and dimensioned (real fixture, offline).
  {
    const a = await screenshotMeta(fs.readFileSync(FIXTURE));
    const b = await screenshotMeta(fs.readFileSync(FIXTURE).toString('base64'));
    assert.strictEqual(a.width, 1366);
    assert.strictEqual(a.height, 632);
    assert.ok(/^[0-9a-f]{64}$/.test(a.sha256), 'sha256 hex digest');
    assert.strictEqual(a.sha256, b.sha256, 'Buffer and base64 inputs hash identically');
    const bad = await screenshotMeta('not-an-image');
    assert.ok(bad.error, 'Unreadable input reports an error object');
    assert.strictEqual(bad.error.code, 'IMAGE_META_FAILED', 'coded garbage-input failure');
    console.log('✔ Test 10 Passed: Screenshot hash + dimensions stable; garbage honest.');
  }

  // Test 11 (Component 1): ingestion input validation. Non-string input
  // yields a coded BAD_IMAGE failure (never a raw TypeError, never a
  // throw from screenshotMeta), and identical payload bytes hash
  // identically regardless of data-URI wrapper.
  {
    for (const bad of [12345, null, undefined, {}, [], true]) {
      assert.throws(() => base64ToBuffer(bad), (e) => e.code === 'BAD_IMAGE', JSON.stringify(bad));
      const meta = await screenshotMeta(bad);
      assert.strictEqual(meta.error && meta.error.code, 'BAD_IMAGE', `coded error for ${JSON.stringify(bad)}`);
      assert.strictEqual(meta.sha256, undefined, 'no hash without bytes');
    }
    const raw = fs.readFileSync(FIXTURE).toString('base64');
    const variants = [
      raw,
      `data:image/png;base64,${raw}`,
      `data:image/jpeg;base64,${raw}`
    ];
    const metas = [];
    for (const v of variants) metas.push(await screenshotMeta(v));
    assert.ok(metas.every((m) => !m.error), 'all wrapper variants parse');
    assert.ok(metas.every((m) => m.sha256 === metas[0].sha256), 'hash covers bytes, not the wrapper');
    assert.ok(metas.every((m) => m.width === 1366 && m.height === 632), 'dims stable across wrappers');
    console.log('✔ Test 11 Passed: Input validation + wrapper-independent hashing.');
  }

  // Test 12 (Component 3): production recognizer-selection path with an
  // uninitializable engine. Only the engine factory is stubbed (the real one
  // would fetch language data over the network); the real crop, worker
  // lookup, error wrapping, and per-region recording all run. Failures stay
  // coded per-region errors — never fabricated text, never blank.
  {
    const ocr = loadOcrWithCreateWorker(async () => { throw new Error('no engine offline'); });
    const regions = [
      { regionId: 'R-001', label: 'button', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true },
      { regionId: 'R-002', label: 'button', boundingBox: { x: 0, y: 0, width: 1, height: 1 }, genuine: true }
    ];
    await assert.rejects(
      ocr.extractTextFromRegion(DUMMY_PNG, regions[0].boundingBox),
      (e) => e && e.code === 'OCR_WORKER_UNAVAILABLE',
      'Engine failure surfaces a coded error'
    );
    const res = await ocr.extractUiTexts(DUMMY_PNG, regions);
    assert.strictEqual(res.regionTexts.length, 2);
    for (const rec of res.regionTexts) {
      assert.strictEqual(rec.text, null, 'No fabricated text');
      assert.strictEqual(rec.empty, false, 'Failure is not blank');
      assert.strictEqual(rec.ocrError && rec.ocrError.code, 'OCR_WORKER_UNAVAILABLE');
    }
    assert.strictEqual(res.combinedText, '', 'No combined text from failures');
    await ocr.closeOcrWorker();
    console.log('✔ Test 12 Passed: Engine failure stays a coded per-region error.');
  }

  // Test 13 (reliability fix): OCR crop preparation is dimension-driven and
  // deterministic — short crops upscale toward ~120px height (max 4x) and
  // grayscale; tall crops pass through byte-identical. No engine involved.
  {
    const shot = fs.readFileSync(FIXTURE);
    const tiny = await cropImageRegion(shot, { x: 801, y: 343, width: 56, height: 29 });
    const tinyMeta = await sharp(tiny).metadata();
    assert.strictEqual(tinyMeta.height, 29);
    const tinyPrep = await prepareOcrCrop(tiny);
    const tinyPrepMeta = await sharp(tinyPrep).metadata();
    assert.strictEqual(tinyPrepMeta.height, 116, '29px -> 4x -> 116px');
    assert.strictEqual(tinyPrepMeta.width, 224, 'Aspect preserved');
    const prepMeans = (await sharp(tinyPrep).stats()).channels.slice(0, 3).map((c) => Math.round(c.mean));
    assert.deepStrictEqual(
      [prepMeans[0] === prepMeans[1], prepMeans[1] === prepMeans[2]], [true, true],
      `Scaled path grayscales (channel means ${prepMeans})`
    );
    assert.strictEqual(tinyPrepMeta.format, 'png');
    const small = await cropImageRegion(shot, { x: 494, y: 411, width: 378, height: 48 });
    const smallPrepMeta = await sharp(await prepareOcrCrop(small)).metadata();
    assert.strictEqual(smallPrepMeta.height, 144, '48px -> 3x -> 144px');
    const tall = await cropImageRegion(shot, { x: 0, y: 0, width: 1366, height: 632 });
    assert.ok((await prepareOcrCrop(tall)).equals(tall), 'Tall crops pass through byte-identical');
    console.log('✔ Test 13 Passed: Crop preparation scales short crops, keeps tall ones.');
  }

  // Test 14 (reliability fix): the production recognition path — real
  // crops, real preprocessing, real Tesseract worker (tracked language
  // data) — reads the fixture's three button regions. This is the true
  // engine, not an injected recognizer.
  {
    const shot = fs.readFileSync(FIXTURE).toString('base64');
    const pill = await extractTextFromRegion(shot, { x: 801, y: 343, width: 56, height: 29 });
    assert.ok(pill.includes('USDC'), `USDC pill reads exactly (got ${JSON.stringify(pill)})`);
    const eth = await extractTextFromRegion(shot, { x: 811, y: 251, width: 46, height: 28 });
    assert.ok(eth.includes('ETH'), `ETH pill reads (got ${JSON.stringify(eth)})`);
    const button = await extractTextFromRegion(shot, { x: 494, y: 411, width: 378, height: 48 });
    assert.ok(button.includes('Swap'), `Swap button reads (got ${JSON.stringify(button)})`);
    await closeOcrWorker();
    console.log('✔ Test 14 Passed: Production engine reads all three regions.');
  }

  console.log('\nAll OCR Provenance Tests Passed Successfully!\n');
}

if (require.main === module) {
  runOcrProvenanceTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runOcrProvenanceTests };
