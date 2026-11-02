const assert = require('assert');
const { validateVisualClaims, CLAIM_TYPES } = require('../../src/utils/grounding');

// Visual-claim grounding validation. Deterministic fixtures only: no
// network, no model, no OCR engine. Pipeline integration lives in
// evaluate.test.js (T31-T34).
const B = (x, y, w, h) => ({ x, y, width: w, height: h });
const REGIONS = [
  { regionId: 'R-001', genuine: true, boundingBox: B(0, 0, 100, 30), ocr: { text: '1.0 ETH', empty: false, error: null } },
  { regionId: 'R-002', genuine: true, boundingBox: B(0, 50, 150, 30), ocr: { text: null, empty: false, error: { code: 'OCR_FAILED', message: 'boom' } } },
  { regionId: 'R-003', genuine: true, boundingBox: B(0, 100, 150, 30), ocr: { text: '', empty: true, error: null } },
  { regionId: 'R-004', genuine: true, boundingBox: B(0, 150, 200, 30), ocr: { text: '0xabababababababababababababababababababab', empty: false, error: null } }
];
const ASSOC = {
  links: [{ linkId: 'L-001', kind: 'amount-recipient', members: [{ regionId: 'R-001' }, { regionId: 'R-004' }] }],
  ambiguities: [{ ambiguityId: 'AMB-001', kind: 'amount-recipient', anchor: { regionId: 'R-001' }, candidates: [{ regionId: 'R-004' }] }]
};
const EV = { regions: REGIONS, associations: ASSOC, syntheticRegionIds: ['R-FALLBACK'] };
const run = (claims, ev = EV) => validateVisualClaims(claims, ev);

function runGroundingTests() {
  console.log('Testing Visual-Claim Grounding Validation...\n');

  // Test 1: valid claim on genuine readable region, interpretation kept
  // separate from observation.
  {
    const res = run([{ type: 'amount', value: 'one ether', regionIds: ['R-001'], associationIds: [] }]);
    assert.strictEqual(res.status, 'evaluated');
    assert.deepStrictEqual(res.summary, { supported: 1, invalid: 0, ambiguous: 0, unsupported: 0 });
    const c = res.claims[0];
    assert.strictEqual(c.status, 'supported');
    assert.strictEqual(c.value, 'one ether', 'Interpretation preserved');
    assert.strictEqual(c.observed[0].text, '1.0 ETH', 'Observation preserved separately');
    assert.deepStrictEqual(c.observed[0].boundingBox, B(0, 0, 100, 30));
    assert.strictEqual(c.observed[0].issue, null);
    assert.deepStrictEqual(c.relatedLinks, ['L-001'], 'Phase 1 link cross-referenced');
    console.log('✔ Test 1 Passed: Valid claim supported with separated evidence.');
  }

  // Test 2: nonexistent region ID is invalid, explicitly recorded.
  {
    const res = run([{ type: 'amount', value: '1.0 ETH', regionIds: ['R-999'] }]);
    const c = res.claims[0];
    assert.strictEqual(c.status, 'invalid');
    assert.deepStrictEqual(c.reasons, ['unknown-region']);
    assert.deepStrictEqual(c.observed, [{ regionId: 'R-999', available: false, issue: 'unknown-region' }]);
    console.log('✔ Test 2 Passed: Unknown region rejected explicitly.');
  }

  // Test 3: synthetic references are invalid, never genuine evidence.
  {
    const res = run([{ type: 'amount', value: 'x', regionIds: ['R-FALLBACK'] }]);
    assert.strictEqual(res.claims[0].status, 'invalid');
    assert.deepStrictEqual(res.claims[0].reasons, ['synthetic-region']);
    const ev2 = { ...EV, regions: [...REGIONS, { regionId: 'R-005', genuine: false, boundingBox: B(0, 0, 1, 1), ocr: { text: 'scan', empty: false, error: null } }] };
    const res2 = run([{ type: 'amount', value: 'x', regionIds: ['R-005'] }], ev2);
    assert.strictEqual(res2.claims[0].status, 'invalid');
    assert.deepStrictEqual(res2.claims[0].reasons, ['synthetic-region']);
    console.log('✔ Test 3 Passed: Synthetic references rejected.');
  }

  // Test 4: failed OCR makes the claim unsupported, error preserved.
  {
    const res = run([{ type: 'recipient', value: '0xabc', regionIds: ['R-002'] }]);
    const c = res.claims[0];
    assert.strictEqual(c.status, 'unsupported');
    assert.deepStrictEqual(c.reasons, ['region-ocr-failed']);
    assert.strictEqual(c.observed[0].ocrError.code, 'OCR_FAILED');
    assert.deepStrictEqual(c.observed[0].boundingBox, B(0, 50, 150, 30));
    console.log('✔ Test 4 Passed: Failed OCR is unsupported, never blank.');
  }

  // Test 5: empty OCR and missing references preserve uncertainty.
  {
    const res = run([{ type: 'amount', value: 'x', regionIds: ['R-003'] }]);
    assert.strictEqual(res.claims[0].status, 'unsupported');
    assert.deepStrictEqual(res.claims[0].reasons, ['region-ocr-empty']);
    const res2 = run([{ type: 'amount', value: 'x', regionIds: [] }]);
    assert.strictEqual(res2.claims[0].status, 'unsupported');
    assert.deepStrictEqual(res2.claims[0].reasons, ['no-region-reference']);
    console.log('✔ Test 5 Passed: Empty and uncited claims stay unsupported.');
  }

  // Test 6: valid claims survive alongside invalid ones.
  {
    const res = run([
      { type: 'amount', value: 'one ether', regionIds: ['R-001'] },
      { type: 'amount', value: 'x', regionIds: ['R-999'] },
      { type: 'amount', value: 'x', regionIds: ['R-003'] },
      'oops'
    ]);
    assert.deepStrictEqual(res.claims.map((c) => c.status), ['supported', 'invalid', 'unsupported', 'invalid']);
    assert.strictEqual(res.claims[0].observed[0].text, '1.0 ETH', 'Valid claim intact');
    assert.deepStrictEqual(res.summary, { supported: 1, invalid: 2, ambiguous: 0, unsupported: 1 });
    console.log('✔ Test 6 Passed: Per-claim independence preserved.');
  }

  // Test 7: model-supplied geometry/OCR is rejected as fabrication.
  {
    const res = run([{
      type: 'amount', value: '1.0 ETH', regionIds: ['R-001'],
      boundingBox: { x: 1, y: 1, width: 1, height: 1 }, ocrText: 'HACKED'
    }]);
    const c = res.claims[0];
    assert.strictEqual(c.status, 'invalid');
    assert.ok(c.reasons.includes('model-supplied-geometry-rejected'));
    assert.ok(c.reasons.includes('model-supplied-ocr-rejected'));
    assert.strictEqual(c.observed[0].text, '1.0 ETH', 'Observed evidence comes from the evaluation, never the claim');
    assert.deepStrictEqual(c.observed[0].boundingBox, B(0, 0, 100, 30));
    console.log('✔ Test 7 Passed: Fabricated evidence rejected.');
  }

  // Test 8: nonexistent association reference is invalid.
  {
    const res = run([{ type: 'amount', value: 'x', regionIds: ['R-001'], associationIds: ['L-999'] }]);
    assert.strictEqual(res.claims[0].status, 'invalid');
    assert.deepStrictEqual(res.claims[0].reasons, ['unknown-association']);
    console.log('✔ Test 8 Passed: Unknown association rejected.');
  }

  // Test 9: existing association verifies; ambiguity reference stays ambiguous.
  {
    const res = run([{ type: 'amount', value: 'x', regionIds: ['R-001'], associationIds: ['L-001'] }]);
    assert.strictEqual(res.claims[0].status, 'supported');
    assert.deepStrictEqual(res.claims[0].relatedLinks, ['L-001']);
    const res2 = run([{ type: 'amount', value: 'x', regionIds: ['R-001'], associationIds: ['AMB-001'] }]);
    assert.strictEqual(res2.claims[0].status, 'ambiguous');
    assert.deepStrictEqual(res2.claims[0].reasons, ['association-unresolved']);
    const badAssoc = { links: [{ linkId: 'L-009', kind: 'x', members: [{ regionId: 'R-001' }, { regionId: 'R-GONE' }] }], ambiguities: [] };
    const res3 = run([{ type: 'amount', value: 'x', regionIds: ['R-001'], associationIds: ['L-009'] }], { ...EV, associations: badAssoc });
    assert.strictEqual(res3.claims[0].status, 'invalid');
    assert.deepStrictEqual(res3.claims[0].reasons, ['association-member-missing']);
    console.log('✔ Test 9 Passed: Association references verified.');
  }

  // Test 10: missing claims (timeout/heuristic/old model) are not-evaluated.
  {
    for (const missing of [undefined, null]) {
      const res = run(missing);
      assert.strictEqual(res.status, 'not-evaluated');
      assert.strictEqual(res.reason, 'no-structured-claims');
      assert.deepStrictEqual(res.claims, [], 'Nothing fabricated when claims are absent');
    }
    console.log('✔ Test 10 Passed: Absent claims are honestly unavailable.');
  }

  // Test 11: malformed claims container and malformed items recorded.
  {
    const res = run('oops');
    assert.strictEqual(res.status, 'not-evaluated');
    assert.strictEqual(res.reason, 'malformed-claims');
    const res2 = run([{ type: 'teleport', value: 'x', regionIds: ['R-001'] }, { type: 'amount', regionIds: ['R-001'] }]);
    assert.strictEqual(res2.claims[0].status, 'invalid');
    assert.deepStrictEqual(res2.claims[0].reasons, ['unknown-claim-type']);
    assert.strictEqual(res2.claims[1].status, 'invalid');
    assert.ok(res2.claims[1].reasons.includes('malformed-claim'), 'Missing value rejected');
    assert.ok(CLAIM_TYPES.includes('warning') && CLAIM_TYPES.length === 6, 'Claim vocabulary pinned');
    console.log('✔ Test 11 Passed: Malformed claims recorded explicitly.');
  }

  // Test 12: empty array is an honest evaluated-empty, not unavailable.
  {
    const res = run([]);
    assert.strictEqual(res.status, 'evaluated');
    assert.strictEqual(res.reason, null);
    assert.deepStrictEqual(res.claims, []);
    assert.deepStrictEqual(res.summary, { supported: 0, invalid: 0, ambiguous: 0, unsupported: 0 });
    console.log('✔ Test 12 Passed: Empty claims evaluate to empty.');
  }

  // Test 13: identical inputs validate identically.
  {
    const claims = [
      { type: 'amount', value: 'x', regionIds: ['R-001', 'R-004'] },
      { type: 'recipient', value: 'y', regionIds: ['R-999'] }
    ];
    assert.deepStrictEqual(run(claims), run(JSON.parse(JSON.stringify(claims))), 'Deterministic validation');
    console.log('✔ Test 13 Passed: Validation is deterministic.');
  }

  console.log('\nAll Grounding Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runGroundingTests();
}

module.exports = { runGroundingTests };
