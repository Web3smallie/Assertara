const assert = require('assert');
const { liveEnabled, fixtureScreenshot, attemptModel, rootsOf, jointItems, REVIEW_FILE, config } = require('./multiEvidenceHelper');

// Cap3 live battery C: stale visuals, citation honesty, corroboration.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const SWAP_PAGE = { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap', visibleText: 'You pay 1.0 ETH. You receive 3,450.00 USDC. Swap' };
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const word = (h) => h.slice(2).toLowerCase().padStart(64, '0');
// Struct words: tokenIn, tokenOut, fee, recipient, amountIn,
// amountOutMinimum, sqrtPriceLimitX96. The minimum is 3,450 USDC in base
// units so the fixture genuinely corroborates the displayed quote:
// a zero minimum with a fixed 3,450 quote is definitionally not
// all-agreeing (Cap4 B3 stage 11 refuses unqualified MATCH over it).
const SWAP_CALLDATA = '0x04e45aaf'
  + word(WETH) + word(USDC)
  + '0'.repeat(61) + '1f4'
  + word(A0)
  + '0000000000000000000000000000000000000000000000000de0b6b3a7640000'
  + '0'.repeat(56) + 'cda2d280' + '0'.repeat(64);

async function run() {
  const gate = liveEnabled();
  if (!gate.ok) { console.log(`SKIP: battery C disabled (${gate.reason}).`); return; }
  console.log('LIVE Cap3 battery C: stale/citation/corroboration scenarios...\n');
  config.investigationsFile = REVIEW_FILE;
  const origMs = config.museTimeoutMs;
  config.museTimeoutMs = 180000;
  const shot = fixtureScreenshot();
  try {
    // ME9: 2-hour-old screenshot vs current data.
    {
      console.log('  [ME9-stale-screenshot] running...');
      const out = await attemptModel('ME9-stale-screenshot', {
        screenshot: shot, pageContext: SWAP_PAGE, capturedAt: Date.now() - 2 * 3600000,
        transaction: { from: A0, to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data: SWAP_CALLDATA, value: '0xde0b6b3a7640000', chainId: '0x1' }
      }, undefined);
      const b = out.body;
      console.log(`  [ME9] ${out.wallMs}ms verdict=${b.verdict} freshness=${b.freshness.screenshot.status}`);
      assert.strictEqual(b.reasoningOrigin, 'model');
      assert.strictEqual(b.freshness.screenshot.status, 'stale', 'staleness detected');
      const check = (b.chainVerification.checks || []).find((c) => c.checkId === 'FRESHNESS_CORROBORATION');
      assert.ok(check && ['fail', 'inconclusive'].includes(check.status), 'freshness check adjudicated');
      const text = JSON.stringify(b.investigation).toLowerCase();
      const handled = text.includes('stal') || (b.investigation.missingEvidence || []).length > 0
        || ['medium', 'high'].includes((b.investigation.uncertainty || {}).level);
      assert.ok(handled, 'model acknowledges staleness (mentions, missing-evidence, or widened uncertainty)');
      console.log('  ✔ ME9-stale-screenshot');
    }

    // ME12: live negative — the model must NOT produce support failures
    // on rich evidence (the attack itself is unit-proven with mocks).
    {
      console.log('  [ME12-citation-honesty] running...');
      const out = await attemptModel('ME12-citation-honesty', {
        screenshot: shot, pageContext: SWAP_PAGE, capturedAt: Date.now(),
        transaction: { from: A0, to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data: SWAP_CALLDATA, value: '0xde0b6b3a7640000', chainId: '0x1' }
      }, undefined);
      const b = out.body;
      console.log(`  [ME12] ${out.wallMs}ms verdict=${b.verdict}`);
      assert.strictEqual(b.reasoningOrigin, 'model');
      assert.strictEqual((b.supportValidation.failures || []).length, 0, 'no quote/support fabrication live');
      assert.strictEqual(b.referenceValidation.ok, true);
      console.log('  ✔ ME12-citation-honesty');
    }

    // ME14: all-agree corroboration with genuine swap calldata.
    {
      console.log('  [ME14-corroboration] running...');
      const out = await attemptModel('ME14-corroboration', {
        screenshot: shot, pageContext: SWAP_PAGE, capturedAt: Date.now(),
        transaction: { from: A0, to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data: SWAP_CALLDATA, value: '0xde0b6b3a7640000', chainId: '0x1' }
      }, undefined);
      const b = out.body;
      console.log(`  [ME14] ${out.wallMs}ms verdict=${b.verdict} conf=${b.confidence}`);
      assert.strictEqual(b.reasoningOrigin, 'model');
      assert.strictEqual(b.verdict, 'MATCH', 'agreeing sources match');
      assert.ok(b.investigation.conclusions.length > 0, 'conclusions present');
      assert.ok(b.investigation.conclusions.every((c) => (c.supportingRefs || []).length > 0), 'every conclusion cites support');
      const multiRoot = b.investigation.conclusions.some((c) => rootsOf(c.supportingRefs).length >= 2);
      const graphSupport = (b.evidenceGraph.edges || []).some((e) => e.type === 'SUPPORTS' || e.type === 'CORROBORATES');
      console.log(`  [ME14] multiRoot=${multiRoot} graphSupport=${graphSupport}`);
      assert.ok(multiRoot || graphSupport, 'corroboration traceable in conclusions or graph');
      console.log('  ✔ ME14-corroboration');
    }

    console.log('\n✔ LIVE Cap3 battery C passed: 3/3 scenarios.');
  } finally {
    config.museTimeoutMs = origMs;
    try { await require('../../src/services/ocrService').closeOcrWorker(); } catch { /* never fail a green battery on cleanup */ }
  }
}

if (require.main === module) run().catch((err) => { console.error(err); process.exit(1); });
module.exports = { run };
