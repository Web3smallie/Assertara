const assert = require('assert');
const config = require('../../src/config/env');
const { encodeFunctionData, parseAbi } = require('viem');
const { handleEvaluateTransaction, applyVerdictSafeguards } = require('../../src/controllers/evaluateController');
const { findingActionFor, composePolicyDecision, POLICY_ID } = require('../../src/services/policyDecision');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Phase 1 verdict integrity: deterministic blocks dominate the model.
// Deterministic: decoder/rules/policy run for real; model verdicts are
// canned via stubbed fetch; heuristic paths use a mock key.
const ORIGINAL_KEY = config.modelApiKey;
config.modelApiKey = 'mock_policy';

const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const USER = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const ZERO = '0x0000000000000000000000000000000000000000';
const EOA = '0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0';
const MAX_UINT = (1n << 256n) - 1n;

const ERC20_ABI = parseAbi(['function approve(address spender, uint256 amount) external returns (bool)']);
const approveData = (spender, amount) => encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [spender, amount] });
const ROUTER_ABI = parseAbi([
  'function exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96) params) external payable returns (uint256 amountOut)'
]);
const swapData = (recipient) => encodeFunctionData({
  abi: ROUTER_ABI, functionName: 'exactInputSingle',
  args: [{ tokenIn: WETH, tokenOut: USDC, fee: 500, recipient, amountIn: 10n ** 18n, amountOutMinimum: 3450000000n, sqrtPriceLimitX96: 0n }]
});
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

function cannedFetch(verdict, confidence = 0.95, extra = {}) {
  return async (url) => {
    if (String(url).endsWith('/responses')) {
      return { ok: true, text: async () => 'data: {"type":"response.completed"}\n' };
    }
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify({
        verdict, confidence, summary: `canned ${verdict}`, discrepancyDetails: {},
        recommendedAction: 'PROCEED_WITH_CAUTION', ...extra
      }) } }] })
    };
  };
}

async function runPolicyDecisionTests() {
  console.log('Testing Phase 1 Verdict Integrity: Deterministic Policy Decision...\n');

  // Test 1: model MATCH + mandatory block -> BLOCK, MATCH downgraded.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH', 0.99);
    try {
      const res = await evaluate({
        pageContext: PAGE,
        transaction: { from: USER, to: USDT, data: approveData(ZERO, MAX_UINT), value: '0x0' }
      });
      assert.strictEqual(res.status, 200);
      assert.ok(res.body.ruleFindings.some((r) => r.ruleId === 'ZERO_ADDRESS_SPENDER'), 'zero-address finding present');
      assert.strictEqual(res.body.verdict, 'UNCERTAIN', 'MATCH must not stand alongside a mandatory block');
      assert.ok(res.body.verdictSafeguards.some((s) => s.trigger === 'DETERMINISTIC_BLOCK'), 'block safeguard recorded');
      const pd = res.body.policyDecision;
      assert.strictEqual(pd.decision, 'BLOCK', 'final decision is BLOCK');
      assert.deepStrictEqual(pd.blockingFindings, ['ZERO_ADDRESS_SPENDER']);
      assert.strictEqual(pd.modelVerdict, 'MATCH', 'model proposal preserved as provenance');
      assert.strictEqual(pd.policyId, POLICY_ID);
      assert.ok(pd.reasons.length > 0, 'block reason recorded');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 1 Passed: Mandatory block dominates model MATCH.');
  }

  // Test 2: model MATCH + undecodable calldata -> no approval issued.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH', 0.9);
    try {
      const res = await evaluate({
        pageContext: { title: 'Mystery dApp', url: 'https://mystery.local/' },
        transaction: { from: USER, to: '0x1234567890123456789012345678901234567890', value: '0x0', data: '0xdeadbeef' }
      });
      assert.strictEqual(res.body.decodedTransaction.functionName, 'unknownFunction');
      assert.strictEqual(res.body.verdict, 'UNCERTAIN');
      assert.notStrictEqual(res.body.policyDecision.decision, 'ALLOW', 'failed decode check must not approve');
      assert.strictEqual(res.body.policyDecision.decision, 'UNCERTAIN');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 2 Passed: Failed mandatory check never approves.');
  }

  // Test 3: heuristic MATCH (model unavailable) -> held for review.
  {
    const res = await evaluate({
      pageContext: PAGE,
      transaction: { from: USER, to: ROUTER, data: swapData(USER), value: '0xde0b6b3a7640000' }
    });
    assert.strictEqual(res.body.reasoningOrigin, 'heuristic-fallback');
    assert.strictEqual(res.body.verdict, 'MATCH', 'legacy heuristic verdict preserved');
    assert.strictEqual(res.body.policyDecision.decision, 'REVIEW', 'heuristic MATCH held for review');
    assert.strictEqual(res.body.policyDecision.modelVerdict, 'MATCH');
    console.log('✔ Test 3 Passed: Unavailable model holds instead of approving.');
  }

  // Test 4: model MISMATCH handling preserved -> REVIEW + simulation runs.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MISMATCH', 0.9);
    try {
      const res = await evaluate({
        pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, data: swapData(USER), value: '0xde0b6b3a7640000' }
      });
      assert.strictEqual(res.body.verdict, 'MISMATCH', 'discrepancy verdict preserved');
      assert.strictEqual(res.body.policyDecision.decision, 'REVIEW', 'MISMATCH held for review');
      assert.notStrictEqual(res.body.simulation.status, 'NOT_RUN', 'MISMATCH still triggers simulation');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 4 Passed: MISMATCH preserved and held for review.');
  }

  // Test 5: model UNCERTAIN preserved.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('UNCERTAIN', 0.5);
    try {
      const res = await evaluate({
        pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, data: swapData(USER), value: '0xde0b6b3a7640000' }
      });
      assert.strictEqual(res.body.verdict, 'UNCERTAIN');
      assert.strictEqual(res.body.policyDecision.decision, 'UNCERTAIN');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 5 Passed: UNCERTAIN preserved end to end.');
  }

  // Test 6: malformed model output fails safely, never approves.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    try {
      global.fetch = async () => ({ ok: true, json: async () => ({ choices: [{ message: { content: 'not-json{{{' } }] }) });
      const garbled = await evaluate({
        pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, data: swapData(USER), value: '0xde0b6b3a7640000' }
      });
      assert.strictEqual(garbled.status, 200);
      assert.notStrictEqual(garbled.body.policyDecision.decision, 'ALLOW', 'unparsable model output must not approve');

      global.fetch = cannedFetch('deceptive', 0.99);
      const coerced = await evaluate({
        pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, data: swapData(USER), value: '0xde0b6b3a7640000' }
      });
      assert.strictEqual(coerced.body.verdict, 'UNCERTAIN');
      assert.ok(coerced.body.verdictSafeguards.some((s) => s.trigger === 'INVALID_VERDICT'));
      assert.strictEqual(coerced.body.policyDecision.decision, 'UNCERTAIN');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 6 Passed: Malformed model output fails safely.');
  }

  // Test 7: non-blocking informational finding -> REVIEW, never BLOCK.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH', 0.9);
    try {
      const res = await evaluate({
        pageContext: { title: 'Token Allowance', url: 'https://example.com/approve' },
        transaction: { from: USER, to: USDT, data: approveData(EOA, 100n), value: '0x0' }
      });
      assert.ok(res.body.ruleFindings.some((r) => r.ruleId === 'UNVERIFIED_SPENDER'), 'informational finding present');
      assert.ok(!res.body.ruleFindings.some((r) => r.ruleId === 'ZERO_ADDRESS_SPENDER'), 'no block finding');
      const pd = res.body.policyDecision;
      assert.strictEqual(pd.decision, 'REVIEW', 'informational finding holds for review');
      assert.notStrictEqual(pd.decision, 'BLOCK', 'informational finding must not auto-block');
      assert.deepStrictEqual(pd.blockingFindings, []);
      assert.ok(pd.reviewFindings.includes('UNVERIFIED_SPENDER'));
      assert.strictEqual(res.body.verdict, 'MATCH', 'legacy verdict untouched by review findings');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 7 Passed: Informational findings review, never block.');
  }

  // Test 8: legitimate swap preserves behavior and API compatibility.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH', 0.95);
    try {
      const res = await evaluate({
        pageContext: PAGE,
        transaction: { from: USER, to: ROUTER, data: swapData(USER), value: '0xde0b6b3a7640000' }
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'MATCH');
      assert.deepStrictEqual(res.body.verdictSafeguards, []);
      assert.strictEqual(res.body.policyDecision.decision, 'ALLOW');
      for (const key of ['id', 'timestamp', 'verdict', 'confidence', 'summary', 'recommendedAction',
        'reasoningOrigin', 'reasoningTimedOut', 'safetyNotice', 'pageEvidence', 'visualEvidence',
        'decodedTransaction', 'ruleFindings', 'verdictSafeguard', 'verdictSafeguards',
        'confidenceCap', 'simulation', 'policyDecision', 'txBinding']) {
        assert.ok(Object.prototype.hasOwnProperty.call(res.body, key), `bundle keeps ${key}`);
      }
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 8 Passed: Legitimate behavior and API shape preserved.');
  }

  // Test 9: maximum model confidence cannot override a mandatory block.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH', 1.0);
    try {
      const res = await evaluate({
        pageContext: PAGE,
        transaction: { from: USER, to: USDT, data: approveData(ZERO, MAX_UINT), value: '0x0' }
      });
      assert.strictEqual(res.body.policyDecision.modelConfidence, 1.0, 'confidence recorded as provenance');
      assert.strictEqual(res.body.policyDecision.decision, 'BLOCK', 'confidence 1.0 cannot override the block');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 9 Passed: Confidence cannot override deterministic rules.');
  }

  // Test 10: composer precedence battery (pure, no I/O).
  {
    const block = [{ ruleId: 'ZERO_ADDRESS_SPENDER' }];
    const review = [{ ruleId: 'UNVERIFIED_SPENDER' }];
    assert.strictEqual(composePolicyDecision({ verdict: 'MATCH', reasoningOrigin: 'model', ruleFindings: block }).decision, 'BLOCK');
    assert.strictEqual(composePolicyDecision({ verdict: 'MISMATCH', reasoningOrigin: 'model', ruleFindings: block }).decision, 'BLOCK', 'block beats mismatch');
    assert.strictEqual(composePolicyDecision({ verdict: 'UNCERTAIN', reasoningOrigin: 'heuristic-fallback', ruleFindings: block }).decision, 'BLOCK', 'block beats degraded origin');
    assert.strictEqual(composePolicyDecision({ verdict: 'MISMATCH', reasoningOrigin: 'model', ruleFindings: [] }).decision, 'REVIEW');
    assert.strictEqual(composePolicyDecision({ verdict: 'MATCH', reasoningOrigin: 'model', ruleFindings: review }).decision, 'REVIEW');
    assert.strictEqual(composePolicyDecision({ verdict: 'MATCH', reasoningOrigin: 'heuristic-fallback', ruleFindings: [] }).decision, 'REVIEW');
    assert.strictEqual(composePolicyDecision({ verdict: 'MATCH', reasoningOrigin: 'model', ruleFindings: [] }).decision, 'ALLOW');
    assert.strictEqual(composePolicyDecision({ verdict: 'UNCERTAIN', reasoningOrigin: 'model', ruleFindings: [] }).decision, 'UNCERTAIN');
    assert.strictEqual(composePolicyDecision({ verdict: 'UNCERTAIN', reasoningOrigin: 'heuristic-fallback', ruleFindings: review }).decision, 'UNCERTAIN', 'uncertainty preserved across origins');
    assert.strictEqual(composePolicyDecision({ verdict: 'MATCH', reasoningOrigin: 'model', ruleFindings: [{ ruleId: 'FUTURE_UNKNOWN_RULE' }] }).decision, 'REVIEW', 'unknown findings fail closed');
    assert.strictEqual(composePolicyDecision({ verdict: 'BOGUS', reasoningOrigin: 'model', ruleFindings: [] }).decision, 'UNCERTAIN', 'unknown verdict fails closed');
    assert.strictEqual(composePolicyDecision({}).decision, 'UNCERTAIN', 'missing input fails closed');
    assert.strictEqual(findingActionFor('ZERO_ADDRESS_SPENDER'), 'BLOCK');
    assert.strictEqual(findingActionFor('INFINITE_APPROVAL'), 'REVIEW');
    assert.strictEqual(findingActionFor('NO_SUCH_RULE'), 'REVIEW');
    assert.strictEqual(findingActionFor(null), 'REVIEW');
    console.log('✔ Test 10 Passed: Composer precedence exact.');
  }

  // Test 11: safeguard unit — block stage downgrades MATCH, passes safe verdicts through.
  {
    const tx = { functionName: 'approve', standard: 'ERC20', ruleFindings: [{ ruleId: 'ZERO_ADDRESS_SPENDER' }] };
    const hit = applyVerdictSafeguards(tx, { verdict: 'MATCH', confidence: 0.95, summary: 's' });
    assert.strictEqual(hit.reasoningResult.verdict, 'UNCERTAIN');
    assert.strictEqual(hit.safeguards[0].trigger, 'DETERMINISTIC_BLOCK', 'block stage runs right after normalization');
    const pass = applyVerdictSafeguards(tx, { verdict: 'MISMATCH', confidence: 0.9, summary: 's' });
    assert.strictEqual(pass.reasoningResult.verdict, 'MISMATCH');
    assert.deepStrictEqual(pass.safeguards, [], 'safe-direction verdicts pass through');
    const clean = applyVerdictSafeguards(
      { functionName: 'transfer', standard: 'ERC20', ruleFindings: [] },
      { verdict: 'MATCH', confidence: 0.9, summary: 's' }
    );
    assert.strictEqual(clean.reasoningResult.verdict, 'MATCH');
    assert.deepStrictEqual(clean.safeguards, []);
    console.log('✔ Test 11 Passed: Block safeguard downgrades MATCH only.');
  }

  // Test 12: plain native transfers decode as nativeTransfer (never
  // unknownFunction), so a model MATCH stands and can authorize.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = cannedFetch('MATCH', 0.95);
    try {
      const res = await evaluate({
        pageContext: { title: 'Send 0.01 ETH', url: 'https://example.com/send' },
        transaction: { from: USER, to: ROUTER, data: '0x', value: '0x2386f26fc10000' }
      });
      assert.strictEqual(res.body.decodedTransaction.functionName, 'nativeTransfer');
      assert.strictEqual(res.body.decodedTransaction.standard, 'Native');
      assert.strictEqual(res.body.verdict, 'MATCH', 'native-transfer MATCH must stand');
      assert.ok(!res.body.verdictSafeguards.some((s) => s.trigger === 'UNKNOWN_FUNCTION'));
      assert.strictEqual(res.body.policyDecision.decision, 'ALLOW');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_policy';
    }
    console.log('✔ Test 12 Passed: Native transfers can authorize.');
  }

  // Test 13 (Capability 5 B1): unknown nested operations hold browser
  // investigations for review (the browser-side counterpart to the
  // mandate's agent-side BLOCK).
  {
    const unknown = [{ ruleId: 'UNKNOWN_INNER_CALL' }];
    assert.strictEqual(composePolicyDecision({ verdict: 'MATCH', reasoningOrigin: 'model', ruleFindings: unknown }).decision, 'REVIEW', 'unknown inners hold review');
    assert.strictEqual(composePolicyDecision({ verdict: 'MATCH', reasoningOrigin: 'model', ruleFindings: [] }).decision, 'ALLOW', 'no inners still allows');
    console.log('✔ Test 13 Passed: Unknown nested operations hold review.');
  }

  config.modelApiKey = ORIGINAL_KEY;
  await closeOcrWorker();
  console.log('\nAll Policy Decision Tests Passed Successfully!\n');
}

if (require.main === module) {
  runPolicyDecisionTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runPolicyDecisionTests };
