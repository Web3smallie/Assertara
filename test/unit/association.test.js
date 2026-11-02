const assert = require('assert');
const { associateRegions, classifyTextRoles, PROXIMITY_FACTOR } = require('../../src/utils/association');

// Deterministic geometric association. All fixtures are synthetic and
// offline; no network, no OCR engine, no live APIs.
function R(regionId, box, text, over = {}) {
  return Object.assign({
    regionId,
    label: 'button',
    boundingBox: box,
    genuine: true,
    ocr: { text, empty: text === '', error: null }
  }, over);
}
const B = (x, y, w, h) => ({ x, y, width: w, height: h });
const ADDR = `0x${'ab'.repeat(20)}`;

async function runAssociationTests() {
  console.log('Testing Geometric Element Association...\n');

  // Test 1: amount + recipient inside a shared observed container.
  {
    const card = R('R-000', B(0, 0, 400, 300), 'Review screen');
    const amount = R('R-001', B(50, 50, 100, 30), '1.0 ETH');
    const recip = R('R-002', B(50, 120, 200, 30), `Funds to ${ADDR} for processing`);
    const res = associateRegions([card, amount, recip]);
    assert.strictEqual(res.links.length, 1, 'Exactly one link');
    const link = res.links[0];
    assert.strictEqual(link.kind, 'amount-recipient');
    assert.strictEqual(link.method, 'shared-container');
    assert.strictEqual(link.containerRegionId, 'R-000');
    assert.strictEqual(link.gapPx, 40, 'Measured edge gap recorded');
    assert.deepStrictEqual(link.members.map((m) => [m.regionId, m.role]), [['R-001', 'amount'], ['R-002', 'recipient']]);
    assert.ok(link.rationale.includes('R-000'), 'Rationale names the container');
    assert.deepStrictEqual(res.ambiguities, []);
    assert.deepStrictEqual(res.unassociated, [{ regionId: 'R-000', roles: [], reason: 'no-transaction-role' }]);
    assert.deepStrictEqual(res.rejected, []);
    console.log('✔ Test 1 Passed: Shared-container amount/recipient link.');
  }

  // Test 2: action linked to its amount by adjacency, with measured gap.
  {
    const action = R('R-001', B(0, 0, 80, 30), 'Swap');
    const amount = R('R-002', B(100, 0, 120, 30), '3,450 USDC');
    const res = associateRegions([action, amount]);
    const link = res.links.find((l) => l.kind === 'action-amount');
    assert.ok(link, 'Action-amount link exists');
    assert.strictEqual(link.method, 'proximity');
    assert.strictEqual(link.gapPx, 20);
    assert.ok(link.rationale.includes('not proof'), 'Proximity disclaimed');
    assert.deepStrictEqual(res.ambiguities, []);
    console.log('✔ Test 2 Passed: Action linked to its amount.');
  }

  // Test 3: warning linked by containment to the amount it covers.
  {
    const warn = R('R-001', B(0, 0, 300, 100), 'Warning: unverified contract');
    const amount = R('R-002', B(20, 40, 80, 24), '1.0 ETH');
    const res = associateRegions([warn, amount]);
    assert.strictEqual(res.links.length, 1);
    const link = res.links[0];
    assert.strictEqual(link.kind, 'warning-context');
    assert.strictEqual(link.method, 'containment');
    assert.strictEqual(link.containerRegionId, 'R-001');
    assert.deepStrictEqual(link.members.map((m) => [m.regionId, m.role]), [['R-001', 'warning'], ['R-002', 'amount']]);
    console.log('✔ Test 3 Passed: Warning linked by containment.');
  }

  // Test 4: distant unrelated text is never associated.
  {
    const amount = R('R-001', B(0, 0, 100, 30), '1.0 ETH');
    const recip = R('R-002', B(900, 900, 150, 30), ADDR);
    const noise = R('R-003', B(1000, 1000, 100, 30), 'Advertisement: fresh shoes');
    const res = associateRegions([amount, recip, noise]);
    assert.deepStrictEqual(res.links, [], 'No links across distance');
    assert.deepStrictEqual(res.ambiguities, []);
    assert.deepStrictEqual(
      res.unassociated.map((u) => [u.regionId, u.reason]).sort(),
      [['R-001', 'no-related-region'], ['R-002', 'no-related-region'], ['R-003', 'no-transaction-role']]
    );
    console.log('✔ Test 4 Passed: Distant text stays unassociated.');
  }

  // Test 5: two plausible recipients produce ambiguity, never a guess.
  {
    const amount = R('R-001', B(200, 100, 100, 30), '1.0 ETH');
    const r1 = R('R-002', B(50, 100, 80, 30), ADDR);
    const r2 = R('R-003', B(350, 100, 80, 30), `0x${'cd'.repeat(20)}`);
    const res = associateRegions([amount, r1, r2]);
    assert.deepStrictEqual(res.links, [], 'No guessed link');
    assert.strictEqual(res.ambiguities.length, 1);
    const amb = res.ambiguities[0];
    assert.strictEqual(amb.kind, 'amount-recipient');
    assert.strictEqual(amb.anchor.regionId, 'R-001');
    assert.deepStrictEqual(amb.candidates.map((c) => [c.regionId, c.gapPx]), [['R-003', 50], ['R-002', 70]], 'Candidates ordered by gap');
    assert.ok(amb.reason.includes('2 recipient candidates'));
    console.log('✔ Test 5 Passed: Multiple candidates yield explicit ambiguity.');
  }

  // Test 6: missing, empty, or failed OCR never generates facts.
  {
    const failed = R('R-001', B(0, 0, 100, 30), null, { ocr: { text: null, empty: false, error: { code: 'OCR_FAILED', message: 'boom' } } });
    const empty = R('R-002', B(0, 50, 100, 30), '');
    const amount = R('R-003', B(0, 100, 100, 30), '2.5 USDC');
    const res = associateRegions([failed, empty, amount]);
    assert.deepStrictEqual(res.links, []);
    assert.deepStrictEqual(res.ambiguities, []);
    assert.deepStrictEqual(
      res.unassociated.map((u) => [u.regionId, u.reason]),
      [['R-001', 'ocr-error:OCR_FAILED'], ['R-002', 'ocr-empty'], ['R-003', 'no-related-region']]
    );
    console.log('✔ Test 6 Passed: No OCR means no invented facts.');
  }

  // Test 7: invalid boxes are rejected safely; valid pairs still link.
  {
    const nan = R('R-bad1', { x: NaN, y: 0, width: 10, height: 10 }, '1.0 ETH');
    const zero = R('R-bad2', B(0, 0, 0, 10), '1.0 ETH');
    const neg = R('R-bad3', B(-5, 0, 10, 10), '1.0 ETH');
    const outside = R('R-bad4', B(900, 900, 10, 10), '1.0 ETH');
    const amount = R('R-001', B(0, 0, 100, 30), '1.0 ETH');
    const recip = R('R-002', B(0, 50, 150, 30), ADDR);
    const res = associateRegions([nan, zero, neg, outside, amount, recip], { dims: { width: 800, height: 600 } });
    assert.deepStrictEqual(res.rejected.map((r) => r.reason), [
      'invalid-box:non-finite-coords',
      'invalid-box:non-positive-size',
      'invalid-box:negative-origin',
      'invalid-box:origin-outside-image'
    ]);
    assert.strictEqual(res.links.length, 1, 'Valid pair still links');
    assert.strictEqual(res.links[0].kind, 'amount-recipient');
    console.log('✔ Test 7 Passed: Invalid boxes rejected without breaking valid links.');
  }

  // Test 8: synthetic/non-genuine regions are never linked as evidence.
  {
    const fake1 = R('R-001', B(0, 0, 100, 30), '1.0 ETH', { genuine: false });
    const fake2 = R('R-002', B(0, 50, 150, 30), ADDR, { genuine: false, synthetic: true });
    const res = associateRegions([fake1, fake2]);
    assert.deepStrictEqual(res.links, []);
    assert.deepStrictEqual(res.rejected, [
      { regionId: 'R-001', reason: 'non-genuine-region' },
      { regionId: 'R-002', reason: 'non-genuine-region' }
    ]);
    console.log('✔ Test 8 Passed: Synthetic regions excluded from evidence.');
  }

  // Test 9: identical inputs in shuffled order give identical outputs.
  {
    const fixture = [
      R('R-000', B(0, 0, 400, 300), 'Review screen'),
      R('R-001', B(50, 50, 100, 30), '1.0 ETH'),
      R('R-002', B(50, 120, 200, 30), ADDR),
      R('R-003', B(700, 700, 80, 30), 'Swap')
    ];
    const a = associateRegions(fixture);
    const b = associateRegions([...fixture].reverse());
    assert.deepStrictEqual(b, a, 'Order-independent deterministic output');
    assert.strictEqual(a.links.length, 1, 'Sanity: the shared-container link exists');
    console.log('✔ Test 9 Passed: Fully deterministic across input order.');
  }

  // Test 10: members preserve exact region IDs, text, and geometry snapshots.
  {
    const boxA = B(0, 0, 100, 30);
    const boxR = B(0, 50, 150, 30);
    const amount = R('R-001', boxA, '1.0 ETH');
    const recip = R('R-002', boxR, ADDR);
    const res = associateRegions([amount, recip]);
    assert.deepStrictEqual(res.links[0].members, [
      { regionId: 'R-001', role: 'amount', text: '1.0 ETH', boundingBox: B(0, 0, 100, 30) },
      { regionId: 'R-002', role: 'recipient', text: ADDR, boundingBox: B(0, 50, 150, 30) }
    ]);
    assert.notStrictEqual(res.links[0].members[0].boundingBox, boxA, 'Geometry snapshotted, not aliased');
    console.log('✔ Test 10 Passed: Provenance preserved with geometry snapshots.');
  }

  // Test 11: pipeline integration — verdict, decode, and safeguards intact,
  // associations present, mock regions rejected as non-genuine.
  {
    const config = require('../../src/config/env');
    const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
    const DUMMY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    // Capability 4 B3: complete swap calldata (the old truncated form
    // would now — correctly — flag MISSING_OUTPUT_PROTECTION, which is
    // not what this association-integration test exercises).
    const SWAP_TX = {
      from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
      value: '0xde0b6b3a7640000',
      data: '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000caa7e2000000000000000000000000000000000000000000000000000000000000000000'
    };
    const ORIGINAL_KEY = config.modelApiKey;
    config.modelApiKey = 'mock_assoc';
    const evaluate = (body) => new Promise((resolve, reject) => {
      const req = { body };
      const res = {
        statusCode: 200,
        status(c) { this.statusCode = c; return this; },
        json(payload) { resolve({ status: this.statusCode, body: payload }); }
      };
      Promise.resolve(handleEvaluateTransaction(req, res)).catch(reject);
    });
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'MATCH', 'Verdict policy unchanged');
      assert.strictEqual(res.body.decodedTransaction.functionName, 'exactInputSingle', 'Decoding unchanged');
      assert.deepStrictEqual(res.body.verdictSafeguards, [], 'No spurious safeguards');
      const assoc = res.body.visualEvidence.associations;
      assert.ok(assoc && Array.isArray(assoc.links), 'Associations field present');
      assert.deepStrictEqual(assoc.links, [], 'Mock regions produce no links');
      assert.deepStrictEqual(assoc.rejected, [], 'Controller pre-filters non-genuine regions before evidence (helper-level exclusion is Test 8)');
      console.log('✔ Test 11 Passed: Pipeline verdict/decode intact; associations integrated.');
    } finally {
      config.modelApiKey = ORIGINAL_KEY;
    }
  }

  // Test 12: transaction decoding is independent of association logic.
  {
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const spender = 'd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'.toLowerCase();
    const decoded = decodeTransactionCalldata({
      to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      data: `0x095ea7b3${'0'.repeat(24)}${spender}${'0'.repeat(63)}1`,
      value: '0x0'
    });
    assert.strictEqual(decoded.functionName, 'approve', 'Decoder unaffected by association code');
    assert.strictEqual(decoded.parameters.spender.toLowerCase(), `0x${spender}`);
    assert.strictEqual(decoded.isUnlimitedApproval, false);
    assert.strictEqual(classifyTextRoles('Approve 1.0 ETH to 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd').sort().join(','),
      'action,amount,recipient', 'Classifier roles stay independent of decoding');
    assert.strictEqual(PROXIMITY_FACTOR, 3, 'Adjacency threshold pinned');
    console.log('✔ Test 12 Passed: Decoder and classifier stay independent.');
  }

  console.log('\nAll Association Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runAssociationTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAssociationTests };
