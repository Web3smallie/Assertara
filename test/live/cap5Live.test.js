const assert = require('assert');
const path = require('path');
const { encodeFunctionData } = require('viem');
const { liveEnabled, fixtureScreenshot, attemptModel, config } = require('./multiEvidenceHelper');
const { ERC20_ABI, UNISWAP_V3_ROUTER_ABI, ACROSS_V3_ABI } = require('../../src/utils/abiSignatures');

// Cap5 live battery: transaction-intent understanding with the genuine
// model (muse-spark-1.3). Deterministic assertions are strict; model
// behavior assertions check origin + key content only. Records persist
// to test/tmp/cap5-review.jsonl for the qualitative review.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC = '0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const SPOKE_BASE = '0x09aea4b2242abC8bb4BB78D537A67a245A7bEC64';

async function run() {
  const gate = liveEnabled();
  if (!gate.ok) {
    console.log(`LIVE Cap5 battery skipped: ${gate.reason}`);
    return;
  }
  console.log('LIVE Cap5 battery: intent understanding (genuine model)...\n');
  const origFile = config.investigationsFile;
  config.investigationsFile = path.join(__dirname, '..', 'tmp', 'cap5-review.jsonl');
  const origMs = config.museTimeoutMs;
  config.museTimeoutMs = 120000;
  try {
    // C5-1: Across bridge deposit — terms extracted, model reasons the route.
    {
      console.log('  [C5-1-bridge] running...');
      const data = encodeFunctionData({
        abi: ACROSS_V3_ABI, functionName: 'depositV3',
        args: [A0, A1, USDC_BASE, USDC_BASE, 1000000n, 999000n, 42161n,
          '0x0000000000000000000000000000000000000000', 1700000000, 1900000000, 0, '0x']
      });
      const out = await attemptModel('C5-1-bridge', {
        pageContext: {
          title: 'Bridge 1 USDC to Arbitrum', url: 'https://across.to/bridge',
          visibleText: 'Bridge 1 USDC from Base to Arbitrum. You receive 0.999 USDC.'
        },
        transaction: { from: A0, to: SPOKE_BASE, data, value: '0x0', chainId: '0x2105' }
      }, undefined);
      const b = out.body;
      console.log(`  [C5-1] ${out.wallMs}ms origin=${b.reasoningOrigin} verdict=${b.verdict} decision=${b.policyDecision && b.policyDecision.decision} model=${b.modelId}`);
      assert.strictEqual(b.reasoningOrigin, 'model');
      assert.strictEqual(b.bridge && b.bridge.status, 'supported');
      assert.deepStrictEqual([b.bridge.terms.sourceChain, b.bridge.terms.destinationChain], ['8453', '42161']);
      assert.ok((b.ruleFindings || []).some((f) => f.ruleId === 'BRIDGE_DEPOSIT'), 'bridge finding present');
      assert.ok(['REVIEW', 'UNCERTAIN'].includes(b.policyDecision.decision), 'bridge held, never allowed');
      assert.strictEqual(b.investigation.intentInterpretation.kind, 'inferred');
      const text = JSON.stringify(b.investigation).toLowerCase();
      assert.ok(text.includes('42161') || text.includes('arbitrum'), 'model names the destination');
      assert.ok(!text.includes('received') || text.includes('never') || text.includes('not'), 'no receipt claim without hedge');
      console.log('  ✔ C5-1-bridge');
    }

    // C5-2: standalone approval, agent path — persistence held, quotes exact.
    {
      console.log('  [C5-2-approve-persist] running...');
      const data = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, 1000n] });
      const out = await attemptModel('C5-2-approve-persist', {
        pageContext: {
          title: '[agent-asserted] approve router', url: 'agent:proposal',
          visibleText: 'Approve the router to spend 1000 USDC for future swaps.'
        },
        transaction: { from: A0, to: USDC, data, value: '0x0', chainId: '0x1' }
      }, { investigationType: 'agent' });
      const b = out.body;
      console.log(`  [C5-2] ${out.wallMs}ms origin=${b.reasoningOrigin} verdict=${b.verdict} decision=${b.policyDecision && b.policyDecision.decision}`);
      assert.strictEqual(b.reasoningOrigin, 'model');
      assert.ok((b.ruleFindings || []).some((f) => f.ruleId === 'APPROVAL_PERSISTS_BEYOND_BATCH'), 'persistence finding present');
      // Either hold outcome is safe: MATCH routes to REVIEW via the
      // persistence finding; the model may instead honestly return
      // UNCERTAIN on the ungroundable agent claim (model varies).
      assert.ok(['REVIEW', 'UNCERTAIN'].includes(b.policyDecision.decision), 'approval held, never allowed');
      assert.ok(b.explicitIntent && b.explicitIntent.statements.length >= 1, 'explicit quotes extracted');
      assert.strictEqual(b.explicitIntent.statements[0].quote, 'Approve the router to spend 1000 USDC for future swaps.');
      assert.strictEqual(b.investigation.intentInterpretation.kind, 'inferred');
      assert.ok(!(b.supportValidation.needsReview || []).some((f) => f.kind === 'EXPLICITNESS_UNQUOTED'), 'no posing flag on clean inference');
      console.log('  ✔ C5-2-approve-persist');
    }

    // C5-3: hidden approval inside a presented transfer — unrequested effect.
    {
      console.log('  [C5-3-hidden-approval] running (screenshot + SAM + OCR + model)...');
      const shot = fixtureScreenshot();
      const data = encodeFunctionData({
        abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
        args: [[
          encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 100n] }),
          encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, 500n] })
        ]]
      });
      const out = await attemptModel('C5-3-hidden-approval', {
        screenshot: shot,
        pageContext: {
          title: 'Send 100 USDC', url: 'https://app.uniswap.org/#/send',
          visibleText: 'Send 100 USDC to recipient.'
        },
        transaction: { from: A0, to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data, value: '0x0', chainId: '0x1' },
        capturedAt: Date.now()
      }, undefined);
      const b = out.body;
      const fields = (b.visualEvidence && b.visualEvidence.intentComparison && b.visualEvidence.intentComparison.fields) || [];
      const apprField = fields.find((f) => f.kind === 'approval' && String(f.field).startsWith('effect:'));
      console.log(`  [C5-3] ${out.wallMs}ms origin=${b.reasoningOrigin} verdict=${b.verdict} approvalField=${apprField && apprField.status}`);
      assert.strictEqual(b.reasoningOrigin, 'model');
      assert.ok(apprField && apprField.status === 'MISMATCH', 'inner approval flagged unrequested');
      assert.ok(['MISMATCH', 'UNCERTAIN'].includes(b.verdict), 'verdict not a clean MATCH');
      console.log('  ✔ C5-3-hidden-approval');
    }

    console.log('\n✔ LIVE Cap5 battery passed: 3/3 intent scenarios.');
  } finally {
    config.museTimeoutMs = origMs;
    config.investigationsFile = origFile;
    try { await require('../../src/services/ocrService').closeOcrWorker(); } catch { /* never fail a green battery */ }
  }
}

if (require.main === module) run().catch((err) => { console.error(err); process.exit(1); });
module.exports = { run };
