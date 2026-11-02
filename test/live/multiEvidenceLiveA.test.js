const assert = require('assert');
const fs = require('fs');
const { liveEnabled, fixtureScreenshot, attemptModel, jointItems, REVIEW_FILE, config } = require('./multiEvidenceHelper');

// Cap3 live battery A: screenshot controller scenarios (all-live:
// screenshot + SAM + OCR + model). Records persist to cap3-review.jsonl.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const APPROVE_MAX = `0x095ea7b3000000000000000000000000${A1.slice(2).toLowerCase()}${'f'.repeat(64)}`;
const SWAP_PAGE = { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap', visibleText: 'You pay 1.0 ETH. You receive 3,450.00 USDC. Swap' };

function swapTx(valueEth, amountRaw) {
  return {
    contract: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', contractName: 'Uniswap V3 SwapRouter02',
    functionName: 'exactInputSingle', standard: 'UniswapV3Router', valueEth,
    parameters: { tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', tokenOut: USDC, fee: 500, amountIn: amountRaw },
    isUnlimitedApproval: false, ruleFindings: []
  };
}

async function scenario(name, body, internal, check) {
  console.log(`  [${name}] running...`);
  const out = await attemptModel(name, body, internal);
  assert.strictEqual(out.status, 200, `${name}: http 200`);
  const b = out.body;
  console.log(`  [${name}] ${out.wallMs}ms origin=${b.reasoningOrigin} verdict=${b.verdict} decision=${b.policyDecision.decision}`);
  assert.strictEqual(b.reasoningOrigin, 'model', `${name}: genuine live reasoning`);
  assert.ok(b.investigation, `${name}: investigation present`);
  assert.strictEqual(b.referenceValidation.ok, true, `${name}: no fabricated refs`);
  await check(b);
  console.log(`  ✔ ${name}`);
}

async function run() {
  const gate = liveEnabled();
  if (!gate.ok) { console.log(`SKIP: battery A disabled (${gate.reason}).`); return; }
  console.log('LIVE Cap3 battery A: screenshot multi-evidence scenarios...\n');
  if (process.env.CAP3_FRESH === '1' && fs.existsSync(REVIEW_FILE)) fs.unlinkSync(REVIEW_FILE);
  config.investigationsFile = REVIEW_FILE;
  const origMs = config.museTimeoutMs;
  config.museTimeoutMs = 180000;
  const shot = fixtureScreenshot();
  try {
    // 1. Swap visual vs approval tx: joint contradiction.
    await scenario('ME1-swap-vs-approval', {
      screenshot: shot, pageContext: SWAP_PAGE, capturedAt: Date.now(),
      transaction: { from: A0, to: USDC, data: APPROVE_MAX, value: '0x0', chainId: '0x1' }
    }, undefined, (b) => {
      assert.strictEqual(b.verdict, 'MISMATCH');
      assert.ok(jointItems(b.investigation).length > 0, 'discrepancy spans 2+ roots');
      const graphContra = (b.evidenceGraph.edges || []).some((e) => e.type === 'CONTRADICTS');
      const modelContra = (b.investigation.contradictions || []).length > 0;
      assert.ok(graphContra || modelContra, 'contradiction recorded in graph or model output');
    });

    // 2. OCR amount vs decoded amount.
    await scenario('ME2-amount-conflict', {
      screenshot: shot, pageContext: SWAP_PAGE, capturedAt: Date.now(),
      transaction: { from: A0, to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data: '0x', value: '0x4563918244F40000', chainId: '0x1' }
    }, undefined, (b) => {
      assert.strictEqual(b.verdict, 'MISMATCH');
      const detMismatch = (b.visualEvidence.intentComparison.fields || []).some((f) => f.status === 'MISMATCH');
      assert.ok(detMismatch || jointItems(b.investigation).length > 0, 'deterministic or model joint conflict');
    });

    // 3. Displayed identity vs actual address.
    await scenario('ME3-identity-conflict', {
      screenshot: shot,
      pageContext: { title: 'Uniswap V3 Router — official', url: 'https://app.uniswap.org/#/swap', visibleText: SWAP_PAGE.visibleText },
      capturedAt: Date.now(),
      transaction: { from: A0, to: '0x000000000000000000000000000000000000dEaD', data: '0x', value: '0x16345785d8a0000', chainId: '0x1' }
    }, undefined, (b) => {
      // MISMATCH or B2-grounded UNCERTAIN both acceptable: the unknown
      // target legitimately forces UNCERTAIN per the browser rules.
      assert.ok(['MISMATCH', 'UNCERTAIN'].includes(b.verdict), `decisive non-MATCH verdict (got ${b.verdict})`);
      assert.ok(jointItems(b.investigation).length > 0, 'discrepancy spans 2+ roots');
      const graphContra = (b.evidenceGraph.edges || []).some((e) => e.type === 'CONTRADICTS');
      const modelContra = (b.investigation.contradictions || []).length > 0;
      assert.ok(graphContra || modelContra, 'contradiction recorded in graph or model output');
    });

    // 4. Finding vs misleading presentation.
    await scenario('ME4-finding-vs-presentation', {
      screenshot: shot,
      pageContext: { title: 'Safe Swap — audited, no approval needed', url: 'https://safe-swap.example', visibleText: 'Safe audited swap. No approval needed, just swap.' },
      capturedAt: Date.now(),
      transaction: { from: A0, to: USDC, data: APPROVE_MAX, value: '0x0', chainId: '0x1' }
    }, undefined, (b) => {
      assert.strictEqual(b.verdict, 'MISMATCH');
      assert.ok(['BLOCK_TRANSACTION', 'VERIFY_RECIPIENT'].includes(b.recommendedAction), `deception draws hold advice (got ${b.recommendedAction})`);
      const warn = (b.visualEvidence.intentComparison.fields || []).find((f) => f.field === 'warning');
      const modelCites = JSON.stringify(b.investigation.discrepancies || []).length > 50;
      assert.ok((warn && warn.status === 'MISMATCH') || modelCites, 'presentation conflict caught deterministically or by model');
    });

    console.log('\n✔ LIVE Cap3 battery A passed: 4/4 screenshot scenarios.');
  } finally {
    config.museTimeoutMs = origMs;
    try { await require('../../src/services/ocrService').closeOcrWorker(); } catch { /* never fail a green battery on cleanup */ }
  }
}

if (require.main === module) run().catch((err) => { console.error(err); process.exit(1); });
module.exports = { run };
