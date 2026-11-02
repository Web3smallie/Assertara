const assert = require('assert');
const config = require('../../src/config/env');
const { encodeFunctionData, parseAbi } = require('viem');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');
const { handleEvaluateTransaction, applyVerdictSafeguards } = require('../../src/controllers/evaluateController');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Recipient-risk rule + verdict safeguard. Deterministic: no live APIs
// (model verdicts canned via stubbed fetch; decoder/rules run for real).
const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const USER = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const ATTACKER = '0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0';
const ROUTER_ABI = parseAbi([
  'function exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96) params) external payable returns (uint256 amountOut)'
]);
const swapData = (recipient) => encodeFunctionData({
  abi: ROUTER_ABI, functionName: 'exactInputSingle',
  args: [{ tokenIn: WETH, tokenOut: USDC, fee: 500, recipient, amountIn: 10n ** 18n, amountOutMinimum: 3450000000n, sqrtPriceLimitX96: 0n }]
});
const TRUNCATED = '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4';
const DUMMY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const PAGE = { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' };

function evaluate(body) {
  return new Promise((resolve) => {
    const req = { body };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); }
    };
    handleEvaluateTransaction(req, res);
  });
}
function cannedFetch(verdict) {
  return async (url) => {
    if (String(url).endsWith('/responses')) {
      return { ok: true, text: async () => 'data: {"type":"response.completed"}\n' };
    }
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify({ verdict, confidence: 0.95, summary: `canned ${verdict}`, discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION' }) } }] })
    };
  };
}
const findingsOf = (tx) => decodeTransactionCalldata(tx).ruleFindings;

async function runRecipientRuleTests() {
  console.log('Testing Swap-Recipient Risk Rule & Verdict Safeguard...\n');
  const ORIGINAL_KEY = config.modelApiKey;

  // Test 1: recipient equals sender (any casing) -> no finding.
  {
    for (const from of [USER, USER.toLowerCase()]) {
      const rules = findingsOf({ to: ROUTER, data: swapData(USER), value: '0xde0b6b3a7640000', from });
      assert.ok(!rules.some((r) => r.ruleId === 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER'), `No finding when recipient == sender (${from})`);
    }
    console.log('✔ Test 1 Passed: Matching recipient is silent.');
  }

  // Test 2: recipient differs -> advisory MEDIUM finding with both addresses.
  {
    const decoded = decodeTransactionCalldata({ to: ROUTER, data: swapData(ATTACKER), value: '0xde0b6b3a7640000', from: USER });
    const hit = decoded.ruleFindings.find((r) => r.ruleId === 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER');
    assert.ok(hit, 'Differing recipient flagged');
    assert.strictEqual(hit.severity, 'MEDIUM', 'Advisory, not auto-malicious');
    assert.strictEqual(hit.triggered, true);
    assert.strictEqual(hit.metadata.sender, USER);
    assert.strictEqual(hit.metadata.recipient.toLowerCase(), ATTACKER.toLowerCase());
    assert.ok(!/malicious|attack/i.test(hit.description), 'Wording stays advisory');
    console.log('✔ Test 2 Passed: Differing recipient flagged with evidence.');
  }

  // Test 3: missing/invalid sender -> no fabricated comparison.
  {
    assert.ok(!findingsOf({ to: ROUTER, data: swapData(ATTACKER), value: '0x0' }).some((r) => r.ruleId.startsWith('SWAP_RECIPIENT')), 'No sender, no finding');
    assert.ok(!findingsOf({ to: ROUTER, data: swapData(ATTACKER), value: '0x0', from: '0x123' }).some((r) => r.ruleId.startsWith('SWAP_RECIPIENT')), 'Invalid sender, no finding');
    assert.ok(!findingsOf({ to: ROUTER, data: swapData(ATTACKER), value: '0x0', from: 42 }).some((r) => r.ruleId.startsWith('SWAP_RECIPIENT')), 'Non-string sender, no finding');
    console.log('✔ Test 3 Passed: Missing/invalid sender yields no comparison.');
  }

  // Test 4: missing/invalid recipient -> handled explicitly (no finding).
  {
    const trunc = decodeTransactionCalldata({ to: ROUTER, data: TRUNCATED, value: '0xde0b6b3a7640000', from: USER });
    assert.strictEqual(trunc.functionName, 'exactInputSingle');
    assert.strictEqual(trunc.parameters.recipient, undefined, 'Truncated fixture has no recipient field');
    assert.ok(!trunc.ruleFindings.some((r) => r.ruleId.startsWith('SWAP_RECIPIENT')), 'No recipient, no finding');
    console.log('✔ Test 4 Passed: Missing recipient yields no finding.');
  }

  // Test 5: unrelated methods never fire the rule.
  {
    const approve = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const r1 = findingsOf({ to: USDC, data: approve, value: '0x0', from: USER });
    assert.ok(!r1.some((r) => r.ruleId.startsWith('SWAP_RECIPIENT')), 'approve untouched');
    assert.ok(r1.some((r) => r.ruleId === 'INFINITE_APPROVAL'), 'Existing approve rule still fires');
    const r2 = findingsOf({ to: ROUTER, data: '0xdeadbeef', value: '0x0', from: USER });
    assert.ok(!r2.some((r) => r.ruleId.startsWith('SWAP_RECIPIENT')), 'unknownFunction untouched');
    console.log('✔ Test 5 Passed: Rule scoped to exactInputSingle only.');
  }

  // Test 6 (defect regression): canned MATCH + attacker tx -> safeguarded UNCERTAIN.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH');
    try {
      const res = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, value: '0xde0b6b3a7640000', data: swapData(ATTACKER) } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'UNCERTAIN', 'Unsupported MATCH must not survive the safeguard');
      assert.ok(res.body.confidence <= 0.65, 'Downgraded confidence capped');
      assert.ok(res.body.ruleFindings.some((r) => r.ruleId === 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER'));
      assert.deepStrictEqual(res.body.verdictSafeguard.trigger, 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER');
      assert.strictEqual(res.body.verdictSafeguard.from, 'MATCH');
      assert.strictEqual(res.body.verdictSafeguard.to, 'UNCERTAIN');
      assert.ok(res.body.summary.includes('downgraded'), 'Downgrade disclosed in summary');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 6 Passed: Attacker-recipient MATCH downgraded deterministically.');
  }

  // Test 7: legitimate swap keeps MATCH; MISMATCH passes through untouched.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    try {
      global.fetch = cannedFetch('MATCH');
      const ok = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, value: '0xde0b6b3a7640000', data: swapData(USER) } });
      assert.strictEqual(ok.body.verdict, 'MATCH', 'Legitimate swap keeps its MATCH');
      assert.strictEqual(ok.body.verdictSafeguard, null, 'No safeguard without the finding');
      global.fetch = cannedFetch('MISMATCH');
      const bad = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, value: '0xde0b6b3a7640000', data: swapData(ATTACKER) } });
      assert.strictEqual(bad.body.verdict, 'MISMATCH', 'Safe-direction verdict untouched');
      assert.strictEqual(bad.body.verdictSafeguard, null, 'No downgrade needed for MISMATCH');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 7 Passed: Legit MATCH kept; MISMATCH untouched.');
  }

  // Test 8: non-enum model verdicts can never pass through or bypass.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('deceptive');
    try {
      const res = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, value: '0xde0b6b3a7640000', data: swapData(USER) } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'UNCERTAIN', 'Invalid verdict coerced safe');
      assert.ok(res.body.confidence <= 0.65, 'Invalid-verdict confidence capped');
      assert.strictEqual(res.body.verdictSafeguard.trigger, 'INVALID_VERDICT');
      assert.strictEqual(res.body.verdictSafeguard.from, 'deceptive');
      assert.ok(res.body.summary.includes('deceptive'), 'Coercion disclosed');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 8 Passed: Invalid verdict strings coerced to UNCERTAIN.');
  }

  // Test 9: lowercase verdicts canonicalize; recipient bypass stays closed.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    try {
      global.fetch = cannedFetch('match');
      const evil = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, value: '0xde0b6b3a7640000', data: swapData(ATTACKER) } });
      assert.strictEqual(evil.body.verdict, 'UNCERTAIN', 'Lowercase match still capped by recipient rule');
      assert.strictEqual(evil.body.verdictSafeguard.trigger, 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER');
      global.fetch = cannedFetch('mismatch');
      const bad = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, value: '0xde0b6b3a7640000', data: swapData(USER) } });
      assert.strictEqual(bad.body.verdict, 'MISMATCH', 'Lowercase canonicalized, valid verdict kept');
      assert.strictEqual(bad.body.verdictSafeguard, null, 'No safeguard needed for clean MISMATCH');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 9 Passed: Case variants canonicalized; bypass closed.');
  }

  // Test 10 (Phase 5B): unknown selector + MATCH -> safeguarded UNCERTAIN.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH');
    try {
      const res = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: '0x1234567890123456789012345678901234567890', value: '0x6f05b59d3b20000', data: '0xdeadbeef' } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.decodedTransaction.functionName, 'unknownFunction', 'Fixture must decode unknown');
      assert.strictEqual(res.body.verdict, 'UNCERTAIN', 'MATCH on undecodable calldata must not stand');
      assert.ok(res.body.confidence <= 0.65, 'Downgraded confidence capped');
      assert.strictEqual(res.body.verdictSafeguard.trigger, 'UNKNOWN_FUNCTION');
      assert.strictEqual(res.body.verdictSafeguard.from, 'MATCH');
      assert.strictEqual(res.body.verdictSafeguard.to, 'UNCERTAIN');
      assert.ok(res.body.summary.includes('could not be decoded'), 'Downgrade disclosed in summary');
      assert.ok(res.body.summary.includes('0xdeadbeef'), 'Selector disclosed in summary');
      assert.deepStrictEqual(res.body.verdictSafeguards.map((s) => s.trigger), ['UNKNOWN_FUNCTION']);
      assert.strictEqual(res.body.decodedTransaction.valueEth, '0.5', 'Phase 5A exact value intact');
      assert.strictEqual(res.body.decodedTransaction.valueWei, '500000000000000000', 'Phase 5A raw wei intact');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 10 Passed: Unknown-selector MATCH downgraded deterministically.');
  }

  // Test 11 (Phase 5B): safe-direction verdicts on unknown selectors pass through.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    try {
      const tx = { from: USER, to: '0x1234567890123456789012345678901234567890', value: '0x0', data: '0xdeadbeef' };
      global.fetch = cannedFetch('MISMATCH');
      const bad = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE, transaction: tx });
      assert.strictEqual(bad.body.verdict, 'MISMATCH', 'Safe-direction verdict untouched');
      assert.strictEqual(bad.body.confidence, 0.95, 'Confidence untouched without a downgrade');
      assert.strictEqual(bad.body.verdictSafeguard, null, 'No safeguard without a downgrade');
      assert.deepStrictEqual(bad.body.verdictSafeguards, [], 'Safeguard list empty without a downgrade');
      global.fetch = cannedFetch('UNCERTAIN');
      const unsure = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE, transaction: tx });
      assert.strictEqual(unsure.body.verdict, 'UNCERTAIN');
      assert.strictEqual(unsure.body.confidence, 0.95, 'Confidence untouched without a downgrade');
      assert.strictEqual(unsure.body.verdictSafeguard, null);
      assert.deepStrictEqual(unsure.body.verdictSafeguards, []);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 11 Passed: MISMATCH/UNCERTAIN on unknown pass through untouched.');
  }

  // Test 12 (Phase 5B): recognized exactInputSingle MATCH is unaffected.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH');
    try {
      const res = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, value: '0xde0b6b3a7640000', data: swapData(USER) } });
      assert.strictEqual(res.body.decodedTransaction.functionName, 'exactInputSingle');
      assert.strictEqual(res.body.verdict, 'MATCH', 'Decoded-method MATCH unaffected');
      assert.strictEqual(res.body.verdictSafeguard, null);
      assert.deepStrictEqual(res.body.verdictSafeguards, []);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 12 Passed: Recognized-method MATCH unaffected.');
  }

  // Test 13 (Phase 5B): safeguard composition — nothing overwritten.
  // The live decoder cannot emit unknownFunction together with a recipient
  // finding (the rule requires exactInputSingle), so the dual-trigger case
  // is exercised synthetically against the pipeline to guard the mechanism.
  {
    const dual = applyVerdictSafeguards(
      { functionName: 'unknownFunction', standard: 'Unknown', parameters: { selector: '0xdeadbeef' },
        ruleFindings: [{ ruleId: 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER', metadata: { sender: USER, recipient: ATTACKER } }] },
      { verdict: 'MATCH', confidence: 0.95, summary: 'model says match' }
    );
    assert.strictEqual(dual.reasoningResult.verdict, 'UNCERTAIN');
    assert.ok(dual.reasoningResult.confidence <= 0.65, 'Single shared cap across triggers');
    assert.deepStrictEqual(
      dual.safeguards.map((s) => s.trigger),
      ['SWAP_RECIPIENT_DIFFERS_FROM_SENDER', 'UNKNOWN_FUNCTION'],
      'Both triggers preserved in pipeline order'
    );
    assert.ok(dual.reasoningResult.summary.includes('differs from sender'), 'Recipient disclosure kept');
    assert.ok(dual.reasoningResult.summary.includes('could not be decoded'), 'Unknown disclosure kept');

    // Controller-level composition order: an invalid verdict coerces first,
    // so the unknown stage stays idle — one record, primary INVALID_VERDICT.
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('deceptive');
    try {
      const res = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE,
        transaction: { from: USER, to: '0x1234567890123456789012345678901234567890', value: '0x0', data: '0xdeadbeef' } });
      assert.strictEqual(res.body.verdict, 'UNCERTAIN');
      assert.deepStrictEqual(res.body.verdictSafeguards.map((s) => s.trigger), ['INVALID_VERDICT']);
      assert.strictEqual(res.body.verdictSafeguard.trigger, 'INVALID_VERDICT', 'Primary is the first trigger');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 13 Passed: Safeguard composition preserves every trigger.');
  }

  // Test 14 (Phase 5B): case/whitespace variants cannot bypass the unknown check.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    try {
      const tx = { from: USER, to: '0x1234567890123456789012345678901234567890', value: '0x0', data: '0xdeadbeef' };
      for (const variant of ['match', ' MATCH ']) {
        global.fetch = cannedFetch(variant);
        const res = await evaluate({ screenshot: DUMMY_PNG, pageContext: PAGE, transaction: tx });
        assert.strictEqual(res.body.verdict, 'UNCERTAIN', `${JSON.stringify(variant)} must not bypass`);
        assert.strictEqual(res.body.verdictSafeguard.trigger, 'UNKNOWN_FUNCTION', `${JSON.stringify(variant)} attributed correctly`);
      }
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = ORIGINAL_KEY;
    }
    console.log('✔ Test 14 Passed: Verdict variants still hit the unknown safeguard.');
  }

  await closeOcrWorker();
  console.log('\nAll Recipient Rule Tests Passed Successfully!\n');
}

if (require.main === module) {
  runRecipientRuleTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runRecipientRuleTests };
