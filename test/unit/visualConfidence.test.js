const assert = require('assert');
const { assessVisualConfidenceCap, ZERO_VISUAL_CAP } = require('../../src/utils/visualConfidence');

// Pure visual-confidence assessment. Deterministic: synthetic regionTexts,
// no network, no OCR engine. Controller wiring is covered in evaluate.test.js.
const R = (over = {}) => ({
  regionId: 'R-001', genuine: true, text: null, empty: false, ocrError: null, ...over
});
const TEXT = (id) => R({ regionId: id, text: 'Swap', empty: false });
const EMPTY = (id) => R({ regionId: id, text: '', empty: true });
const FAILED = (id) => R({ regionId: id, ocrError: { code: 'BOX_OUT_OF_BOUNDS', message: 'outside' } });
const assess = (over = {}) => assessVisualConfidenceCap({
  screenshotProvided: true, detectedCount: 1, regionTexts: [], fallbackReason: null, ...over
});

function runVisualConfidenceTests() {
  console.log('Testing Visual-Confidence Assessment...\n');

  // Test 1: no screenshot -> no cap regardless of other inputs.
  {
    const res = assess({ screenshotProvided: false, detectedCount: 0 });
    assert.strictEqual(res.capped, false, 'No screenshot means no cap');
    assert.strictEqual(res.trigger, null);
    const res2 = assess({ screenshotProvided: false, detectedCount: 3, regionTexts: [TEXT('R-001')] });
    assert.strictEqual(res2.capped, false, 'No-screenshot contract holds even with regions');
    console.log('✔ Test 1 Passed: No screenshot leaves confidence untouched.');
  }

  // Test 2: zero detections -> existing ZERO_GENUINE_DETECTIONS trigger.
  {
    const res = assess({ detectedCount: 0, fallbackReason: 'zero-detections' });
    assert.strictEqual(res.capped, true);
    assert.strictEqual(res.trigger, 'ZERO_GENUINE_DETECTIONS', 'Original 5C trigger preserved');
    assert.strictEqual(res.detail, 'no genuine visual regions detected');
    assert.ok(res.reason.includes('MATCH confidence capped at 0.65'));
    console.log('✔ Test 2 Passed: Zero detections keep the original trigger.');
  }

  // Test 3: zero detections via SAM error -> failure cause distinguished.
  {
    const res = assess({ detectedCount: 0, fallbackReason: 'error' });
    assert.strictEqual(res.capped, true);
    assert.strictEqual(res.trigger, 'ZERO_GENUINE_DETECTIONS');
    assert.strictEqual(res.detail, 'visual segmentation failed');
    console.log('✔ Test 3 Passed: SAM-error cause distinguished.');
  }

  // Test 4: every genuine OCR attempt failed -> capped, all-failed reason.
  {
    const res = assess({ detectedCount: 2, regionTexts: [FAILED('R-001'), FAILED('R-002')] });
    assert.strictEqual(res.capped, true, 'All-failed OCR must cap');
    assert.strictEqual(res.trigger, 'ZERO_USABLE_OCR_TEXT');
    assert.ok(res.reason.includes('every genuine region OCR attempt failed'), 'All-failed distinguished');
    assert.ok(res.reason.includes('(2 region(s))'), 'Region count recorded');
    console.log('✔ Test 4 Passed: All-failed OCR caps with its own reason.');
  }

  // Test 5: successful but empty OCR on every region -> capped.
  {
    const res = assess({ detectedCount: 2, regionTexts: [EMPTY('R-001'), EMPTY('R-002')] });
    assert.strictEqual(res.capped, true, 'All-empty OCR must cap');
    assert.strictEqual(res.trigger, 'ZERO_USABLE_OCR_TEXT');
    assert.ok(res.reason.includes('no genuine region yielded usable OCR text'));
    assert.ok(res.reason.includes('0 failed, 2 empty'), 'Outcome mix recorded');
    console.log('✔ Test 5 Passed: All-empty OCR caps without alleging failure.');
  }

  // Test 6: mixed failed + empty, no usable text -> capped.
  {
    const res = assess({ detectedCount: 2, regionTexts: [FAILED('R-001'), EMPTY('R-002')] });
    assert.strictEqual(res.capped, true, 'Mixed failed/empty with no text must cap');
    assert.strictEqual(res.trigger, 'ZERO_USABLE_OCR_TEXT');
    assert.ok(res.reason.includes('1 failed, 1 empty'));
    console.log('✔ Test 6 Passed: Mixed failed/empty caps with counts.');
  }

  // Test 7: one region with text exempts, despite other failures.
  {
    const res = assess({ detectedCount: 3, regionTexts: [FAILED('R-001'), EMPTY('R-002'), TEXT('R-003')] });
    assert.strictEqual(res.capped, false, 'One usable text exempts the cap');
    assert.strictEqual(res.trigger, null);
    console.log('✔ Test 7 Passed: A single usable text exempts.');
  }

  // Test 8: synthetic fallback text never counts as genuine evidence.
  {
    const synthetic = R({ regionId: 'R-FALLBACK', genuine: false, synthetic: true, text: 'scan text' });
    const res = assess({ detectedCount: 1, regionTexts: [EMPTY('R-001'), synthetic] });
    assert.strictEqual(res.capped, true, 'Synthetic text must not satisfy the requirement');
    assert.strictEqual(res.trigger, 'ZERO_USABLE_OCR_TEXT');
    const nonGenuine = R({ regionId: 'R-X', genuine: false, text: 'Swap' });
    const res2 = assess({ detectedCount: 1, regionTexts: [nonGenuine] });
    assert.strictEqual(res2.capped, true, 'Non-genuine records are excluded');
    console.log('✔ Test 8 Passed: Synthetic/non-genuine text excluded.');
  }

  // Test 9: detections without OCR records -> capped defensively.
  {
    const res = assess({ detectedCount: 2, regionTexts: undefined });
    assert.strictEqual(res.capped, true, 'Missing records cannot prove usable text');
    assert.strictEqual(res.trigger, 'ZERO_USABLE_OCR_TEXT');
    console.log('✔ Test 9 Passed: Missing OCR records cap defensively.');
  }

  // Test 10: shared cap value pinned.
  {
    assert.strictEqual(ZERO_VISUAL_CAP, 0.65, 'Cap value shared with the controller');
    console.log('✔ Test 10 Passed: Cap value pinned at 0.65.');
  }

  // Test 11 (Fix 1): partial-error zero names the partial cause.
  {
    const res = assess({ detectedCount: 0, fallbackReason: 'partial-error' });
    assert.strictEqual(res.capped, true);
    assert.strictEqual(res.trigger, 'ZERO_GENUINE_DETECTIONS');
    assert.strictEqual(res.detail, 'visual segmentation partially failed');
    assert.ok(res.reason.includes('partially failed'));
    console.log('✔ Test 11 Passed: Partial cause distinguished in cap record.');
  }

  // Test 12 (Fix 2): incomplete zero names the incomplete cause — never
  // misreported as "no regions detected".
  {
    const res = assess({ detectedCount: 0, fallbackReason: 'incomplete' });
    assert.strictEqual(res.capped, true);
    assert.strictEqual(res.trigger, 'ZERO_GENUINE_DETECTIONS');
    assert.strictEqual(res.detail, 'visual segmentation response incomplete');
    assert.ok(res.reason.includes('response incomplete'));
    console.log('✔ Test 12 Passed: Incomplete cause distinguished in cap record.');
  }

  console.log('\nAll Visual-Confidence Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runVisualConfidenceTests();
}

module.exports = { runVisualConfidenceTests };
