const assert = require('assert');
const config = require('../../src/config/env');
const { evaluateSemanticDiscrepancy, fallbackHeuristicReasoner } = require('../../src/services/reasonerService');

const SWAP_PAGE = { url: 'https://app.uniswap.org/#/swap', title: 'Swap 1.0 ETH for 3,450 USDC' };
const SWAP_TX = {
  contract: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
  contractName: 'Uniswap V3 SwapRouter02',
  functionName: 'exactInputSingle',
  standard: 'UniswapV3Router',
  valueEth: '1',
  parameters: {
    tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
    tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    fee: 500
  },
  isUnlimitedApproval: false,
  ruleFindings: []
};

// Force the live code path deterministically regardless of the local .env.
function useLiveKey() {
  const original = config.modelApiKey;
  config.modelApiKey = 'test-live-key';
  return () => { config.modelApiKey = original; };
}

async function runReasonerTests() {
  console.log('Testing Muse Spark Reasoner Inputs & Determinism...\n');
  const realFetch = global.fetch;

  // Test 1: Live request pins greedy decoding and carries all evidence.
  // Regression: an unpinned sampler returned MATCH once and UNCERTAIN twice
  // for byte-identical swap evidence.
  {
    const restoreKey = useLiveKey();
    let captured;
    global.fetch = async (url, options) => {
      captured = { url, body: JSON.parse(options.body) };
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.95}' } }] })
      };
    };
    try {
      await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    assert.ok(captured.url.endsWith('/chat/completions'), 'Should target chat completions');
    assert.strictEqual(captured.body.temperature, 0, 'Must pin temperature 0 for deterministic verdicts');
    assert.deepStrictEqual(captured.body.response_format, { type: 'json_object' });
    const userContent = captured.body.messages.find((m) => m.role === 'user').content;
    assert.ok(userContent.includes(SWAP_PAGE.title), 'Prompt must carry the page title');
    assert.ok(userContent.includes(SWAP_PAGE.url), 'Prompt must carry the page URL');
    assert.ok(userContent.includes('No text extracted'), 'Prompt must mark empty OCR honestly');
    assert.ok(userContent.includes('exactInputSingle'), 'Prompt must carry the decoded function');
    assert.ok(userContent.includes('Uniswap V3 SwapRouter02'), 'Prompt must carry the contract name');
    assert.ok(userContent.includes('Transaction Value (ETH): 1'), 'Prompt must carry the tx value');
    console.log('✔ Test 1 Passed: Live request pins temperature 0 and carries full evidence.');
  }

  // Test 2: A parsed live verdict is returned unchanged.
  {
    const restoreKey = useLiveKey();
    global.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"verdict":"MISMATCH","confidence":0.9}' } }] })
    });
    try {
      const result = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
      assert.strictEqual(result.verdict, 'MISMATCH', 'Should return the model verdict as-is');
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    console.log('✔ Test 2 Passed: Live verdict passes through unmodified.');
  }

  // Test 3: Failed live calls fall back to the deterministic heuristic.
  {
    const restoreKey = useLiveKey();
    global.fetch = async () => ({ ok: false, status: 500 });
    try {
      const result = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
      assert.strictEqual(result.verdict, 'MATCH', 'Swap fallback must MATCH via heuristic');
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    console.log('✔ Test 3 Passed: Live failure falls back to the heuristic.');
  }

  // Test 4: Heuristic reference semantics — title counts as visual context,
  // unknown transactions stay UNCERTAIN (never forced to MATCH).
  {
    const match = fallbackHeuristicReasoner('', SWAP_PAGE, SWAP_TX);
    assert.strictEqual(match.verdict, 'MATCH', 'Swap title + exactInputSingle must MATCH');
    const mismatch = fallbackHeuristicReasoner('', { title: 'Claim 1,000 UNI Free Airdrop' }, {
      functionName: 'approve', standard: 'ERC20', symbol: 'USDT',
      parameters: { spender: '0x942c733fa43900388424a1bf7f94d934b3531b23' },
      isUnlimitedApproval: true, ruleFindings: [{ ruleId: 'INFINITE_APPROVAL' }]
    });
    assert.strictEqual(mismatch.verdict, 'MISMATCH', 'Airdrop title + approval must MISMATCH');
    const uncertain = fallbackHeuristicReasoner('', { title: 'Governance Proposal #42' }, {
      functionName: 'unknownFunction', standard: 'Unknown', contractName: 'Unknown Contract',
      parameters: { selector: '0x79c65092' }, isUnlimitedApproval: false, ruleFindings: []
    });
    assert.strictEqual(uncertain.verdict, 'UNCERTAIN', 'Unknown transactions must stay UNCERTAIN');
    console.log('✔ Test 4 Passed: Heuristic semantics pinned (MATCH/MISMATCH/UNCERTAIN).');
  }

  console.log('\nAll Reasoner Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runReasonerTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runReasonerTests };
