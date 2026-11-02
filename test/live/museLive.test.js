const assert = require('assert');
const config = require('../../src/config/env');
const { validateModelResult } = require('../../src/services/reasonerService');
const { attemptReasoner } = require('./multiEvidenceHelper');
const { DEFAULT_BUDGETS } = require('../../src/services/evidencePacker');

// LIVE integration test (category B): calls the real Muse Spark API once.
// Gated: runs only with LIVE_MODEL_TESTS=1 and a real MODEL_API_KEY.
// Otherwise it skips with exit 0 and makes no network calls, so the normal
// suite never incurs charges or depends on network availability.
// Run explicitly: LIVE_MODEL_TESTS=1 npm run test:live   (see package.json)

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

function liveEnabled() {
  if (process.env.LIVE_MODEL_TESTS !== '1') return { ok: false, reason: 'LIVE_MODEL_TESTS!=1' };
  const key = config.modelApiKey || '';
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) {
    return { ok: false, reason: 'no real MODEL_API_KEY configured' };
  }
  return { ok: true };
}

async function runMuseLiveTests() {
  const gate = liveEnabled();
  if (!gate.ok) {
    console.log(`SKIP: live Muse test disabled (${gate.reason}). No network calls made.`);
    return;
  }
  console.log('LIVE test: real Muse Spark call through the production reasoner path...\n');
  console.log(`endpoint: ${config.metaApiBaseUrl}/chat/completions (key: configured, ${config.modelApiKey.length} chars)`);
  console.log(`requested model: ${config.museModel}`);
  const origMs = config.museTimeoutMs;
  config.museTimeoutMs = 180000; // observed live latency 25-60s+; give one call room
  try {
    const t0 = Date.now();
    const out = await attemptReasoner('muse-live-1', ['', SWAP_PAGE, SWAP_TX, {
      detectedCount: 0, visualAvailable: false, regionTexts: [], fallbackRecords: [],
      intentSource: 'full-scan (no screenshot supplied)'
    }]);
    const ms = Date.now() - t0;
    console.log(`live call: latencyMs=${ms} origin=${out.origin} verdict=${out.verdict} confidence=${out.confidence} timeout=${out.timeout === true}`);
    assert.strictEqual(out.origin, 'model', 'live call must return genuine model output (not fallback)');
    assert.strictEqual(out.timeout, undefined, 'live call must not time out');
    const check = validateModelResult({
      verdict: out.verdict, confidence: out.confidence, summary: out.summary,
      discrepancyDetails: out.discrepancyDetails, recommendedAction: out.recommendedAction,
      visualClaims: out.visualClaims
    });
    assert.strictEqual(check.ok, true, `live output must validate (${check.reason || 'ok'})`);
    assert.ok(['MATCH', 'MISMATCH', 'UNCERTAIN'].includes(out.verdict), 'live verdict in vocabulary');
    console.log('\n✔ LIVE Passed: real model verdict flowed through validation with model provenance.');

    // Live Test 2: findings-bearing Phase-B pack against the LIVE model.
    console.log('\nLIVE test 2: findings + provenance tiers + freshness through the live model...\n');
    const t1 = Date.now();
    const sus = await attemptReasoner('muse-live-2', [
      'Approve spending cap for USDC',
      {
        url: 'https://app.uniswap.org/swap', title: 'Uniswap Router Approval',
        visibleText: 'Approve spending cap for USDC',
        detectedObjects: [
          { label: 'button', confidence: 90, description: 'Approve USDC button' },
          { label: 'text', confidence: 45, description: 'Spending cap note' }
        ],
        samStatus: 'complete', ocrStatus: 'ok',
        ocr: { provider: 'local-tesseract', text: 'Approve USDC', confidence: 0.82, engine: 'tesseract-5', capturedAt: Date.now() }
      },
      {
        contract: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
        contractName: 'USD Coin (known token)', functionName: 'approve',
        standard: 'ERC20', valueEth: '0',
        parameters: { spender: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', amount: 'max-uint' },
        isUnlimitedApproval: true,
        ruleFindings: [{ ruleId: 'INFINITE_ERC20_APPROVAL', severity: 'high', description: 'Unlimited USDC approval requested' }]
      },
      { detectedCount: 2 },
      {
        chainState: { status: 'unavailable', error: 'no rpc endpoint configured', addresses: [] },
        freshness: { screenshot: { status: 'fresh', ageMs: 1200 } }
      }
    ]);
    const ms2 = Date.now() - t1;
    console.log(`live call 2: latencyMs=${ms2} origin=${sus.origin} verdict=${sus.verdict} confidence=${sus.confidence}`);
    assert.strictEqual(sus.origin, 'model', 'findings pack must reach the LIVE model and validate');
    assert.strictEqual(sus.evidencePacking.sent, true, 'findings pack marked sent');
    assert.ok(
      sus.evidencePacking.totalChars <= DEFAULT_BUDGETS.total,
      `live pack within budget (${sus.evidencePacking.totalChars} <= ${DEFAULT_BUDGETS.total})`
    );
    console.log('✔ LIVE 2 Passed: findings-bearing pack reached the live model within budget.');
  } finally {
    config.museTimeoutMs = origMs;
    try { await require('../../src/services/ocrService').closeOcrWorker(); } catch { /* never fail a green battery on cleanup */ }
  }
}

if (require.main === module) {
  runMuseLiveTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runMuseLiveTests };
