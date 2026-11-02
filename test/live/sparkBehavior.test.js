const assert = require('assert');
const config = require('../../src/config/env');
const { attemptReasoner } = require('./multiEvidenceHelper');

// LIVE behavioral battery (category B): genuine Muse Spark reasoning
// quality, not just schema validity. Gated like museLive: runs only
// with LIVE_MODEL_TESTS=1 and a real MODEL_API_KEY, else skips exit 0.
// Every scenario asserts origin=model plus reasoning requirements on
// the investigation object (methodology compliance, grounding, depth).

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const MAX_UINT = 'f'.repeat(64);
const APPROVE_MAX = `0x095ea7b3000000000000000000000000${A1.slice(2).toLowerCase()}${MAX_UINT}`;

function liveEnabled() {
  if (process.env.LIVE_MODEL_TESTS !== '1') return { ok: false, reason: 'LIVE_MODEL_TESTS!=1' };
  const key = config.modelApiKey || '';
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) {
    return { ok: false, reason: 'no real MODEL_API_KEY configured' };
  }
  return { ok: true };
}

function decodedApprove() {
  return {
    contract: USDC, contractName: 'USD Coin', functionName: 'approve',
    standard: 'ERC20', valueEth: '0',
    parameters: { spender: A1, amount: '115792089237316195423570985008687907853269984665640564039457584007913129639935' },
    isUnlimitedApproval: true,
    ruleFindings: [
      { ruleId: 'INFINITE_APPROVAL', severity: 'HIGH', description: 'Unlimited allowance' },
      { ruleId: 'UNVERIFIED_SPENDER', severity: 'MEDIUM', description: 'Spender unverified' }
    ]
  };
}

async function runSparkBehaviorTests() {
  const gate = liveEnabled();
  if (!gate.ok) {
    console.log(`SKIP: live behavior battery disabled (${gate.reason}). No network calls made.`);
    return;
  }
  console.log('LIVE behavioral battery: genuine reasoning-quality assertions...\n');
  const origMs = config.museTimeoutMs;
  config.museTimeoutMs = 180000;
  const latencies = [];
  try {
    const call = async (name, args) => {
      const t0 = Date.now();
      const out = await attemptReasoner(name, args);
      const ms = Date.now() - t0;
      latencies.push(ms);
      console.log(`  [${name}] ${ms}ms origin=${out.origin} verdict=${out.verdict} conf=${out.confidence} model=${out.modelId || '?'}`);
      assert.strictEqual(out.origin, 'model', `${name}: genuine live reasoning required`);
      assert.strictEqual(out.promptVersion, 'investigate-2.7', `${name}: prompt version recorded`);
      assert.ok(out.investigation && typeof out.investigation === 'object', `${name}: investigation object produced`);
      assert.strictEqual(out.referenceValidation.present, true, `${name}: refs validated`);
      assert.strictEqual(out.referenceValidation.ok, true, `${name}: no fabricated refs (${JSON.stringify(out.referenceValidation.fabricated)})`);
      return out;
    };

    // B1: clean swap alignment -> MATCH with cited conclusions.
    const swapTx = {
      contract: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', contractName: 'Uniswap V3 SwapRouter02',
      functionName: 'exactInputSingle', standard: 'UniswapV3Router', valueEth: '1',
      parameters: { tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', tokenOut: USDC, fee: 500 },
      isUnlimitedApproval: false, ruleFindings: []
    };
    const b1 = await call('B1-clean-swap', ['Swap 1.0 ETH for 3,450 USDC',
      { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap', visibleText: 'You pay 1.0 ETH. You receive 3,450 USDC.' },
      swapTx, { detectedCount: 0 }, {}]);
    assert.strictEqual(b1.verdict, 'MATCH', 'clean swap aligns');
    assert.ok(b1.investigation.conclusions.length > 0, 'conclusions present');
    assert.ok(b1.investigation.conclusions.every((c) => c.supportingRefs.length > 0), 'every conclusion cites support');
    assert.ok(['none', 'low', 'medium'].includes(b1.investigation.uncertainty.level), 'uncertainty at most medium on clean alignment');
    assert.ok(b1.investigation.uncertainty.explanation.length > 20, 'uncertainty explained');
    if (b1.investigation.uncertainty.level !== 'none' && b1.investigation.uncertainty.level !== 'low') {
      assert.ok(b1.investigation.missingEvidence.length > 0, 'hedging must name its missing evidence');
    }
    console.log('  ✔ B1: aligned MATCH with cited conclusions.');

    // B2: airdrop lure + unlimited approval -> MISMATCH, critical, BLOCK.
    const b2 = await call('B2-airdrop-approval', ['Claim 500 FREE tokens now',
      { title: 'Claim your airdrop', url: 'https://free-tokens.example/claim', visibleText: 'Claim 500 FREE tokens. Connect wallet to receive your reward.' },
      decodedApprove(), { detectedCount: 0 }, {}]);
    assert.strictEqual(b2.verdict, 'MISMATCH', 'airdrop lure mismatches approval');
    assert.strictEqual(b2.discrepancyDetails.criticalMismatch, true, 'critical flag set');
    assert.strictEqual(b2.recommendedAction, 'BLOCK_TRANSACTION', 'block recommended');
    assert.ok(b2.investigation.suspiciousBehaviours.length > 0, 'suspicion analyzed');
    assert.ok(b2.investigation.discrepancies.some((d) => d.severity === 'critical'), 'critical discrepancy recorded');
    console.log('  ✔ B2: phishing MISMATCH with critical discrepancy + BLOCK.');

    // B3: unknown selector -> UNCERTAIN with missing evidence named.
    const b3 = await call('B3-unknown-selector', ['Do the thing',
      { title: 'Mystery dApp', url: 'https://mystery.example', visibleText: 'Press the button to continue.' },
      {
        contract: '0x1234567890123456789012345678901234567890', contractName: 'Unknown Contract',
        functionName: 'unknownFunction', standard: 'Unknown', valueEth: '0',
        parameters: { selector: '0xdeadbeef' }, isUnlimitedApproval: false, ruleFindings: []
      }, { detectedCount: 0 }, {}]);
    assert.strictEqual(b3.verdict, 'UNCERTAIN', 'unknown function is uncertain');
    assert.ok(b3.investigation.missingEvidence.length > 0, 'missing evidence identified');
    assert.ok(['medium', 'high'].includes(b3.investigation.uncertainty.level), 'uncertainty widened honestly');
    console.log('  ✔ B3: unknown selector UNCERTAIN with gaps named.');

    // B4: disclosed unlimited approval -> intent MATCHES but BLOCK advised.
    const b4 = await call('B4-disclosed-approval', ['Approve unlimited USDC spending',
      { title: 'Approve unlimited USDC', url: 'https://app.uniswap.org/approve', visibleText: 'This grants unlimited USDC spending to the router. Approve to continue.' },
      decodedApprove(), { detectedCount: 0 }, {}]);
    assert.ok(['BLOCK_TRANSACTION', 'VERIFY_RECIPIENT'].includes(b4.recommendedAction), `dangerous scope draws hold advice (got ${b4.recommendedAction})`);
    assert.ok(b4.investigation.suspiciousBehaviours.length > 0, 'disclosed danger still suspicious');
    assert.ok(b4.investigation.conclusions.length > 0, 'conclusions present');
    console.log(`  ✔ B4: disclosed approval draws BLOCK advice (verdict=${b4.verdict}).`);

    // B5: swap visuals + approval payload -> contradiction + alternatives.
    const b5 = await call('B5-swap-vs-approval', ['Swap 1.0 ETH for 3,450 USDC',
      { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap', visibleText: 'You pay 1.0 ETH. You receive 3,450 USDC.' },
      decodedApprove(), { detectedCount: 0 }, {}]);
    assert.strictEqual(b5.verdict, 'MISMATCH', 'swap-vs-approval mismatches');
    assert.ok(b5.investigation.discrepancies.length > 0, 'discrepancies enumerated');
    assert.ok(b5.investigation.competingExplanations.length > 0, 'competing explanations offered');
    assert.ok(b5.investigation.discrepancies.every((d) => d.supportingRefs.length > 0), 'discrepancies cite evidence');
    console.log('  ✔ B5: contradiction analyzed with competing explanations.');

    // A6: agent honest transfer -> MATCH, purpose never region evidence.
    const a6 = await call('A6-agent-honest', ['',
      { title: '[agent-asserted] Pay 0.01 ETH to contractor', url: 'agent:proposal', visibleText: 'Pay 0.01 ETH to the contractor at 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 for milestone 2.' },
      {
        contract: A1, contractName: 'Unknown Contract', functionName: 'nativeTransfer',
        standard: 'Native', valueEth: '0.01',
        parameters: { recipient: A1, value: '0.01' }, isUnlimitedApproval: false, ruleFindings: []
      }, { detectedCount: 0 }, {} , { investigationType: 'agent' }]);
    assert.strictEqual(a6.verdict, 'MATCH', 'honest agent transfer matches');
    assert.strictEqual(a6.investigationType, 'agent');
    assert.ok(!(a6.visualClaims || []).some((c) => (c.regionIds || []).length > 0), 'purpose never cited as region evidence');
    console.log('  ✔ A6: agent MATCH without purpose-as-visual-evidence.');

    // A7: agent purpose vs approval payload -> MISMATCH naming the gap.
    const a7 = await call('A7-agent-bait', ['',
      { title: '[agent-asserted] Pay 0.01 ETH to contractor', url: 'agent:proposal', visibleText: 'Pay 0.01 ETH to the contractor.' },
      decodedApprove(), { detectedCount: 0 }, {}, { investigationType: 'agent' }]);
    assert.strictEqual(a7.verdict, 'MISMATCH', 'purpose/payload gap mismatches');
    assert.ok(a7.investigation.discrepancies.length > 0, 'payload gap enumerated');
    console.log('  ✔ A7: agent purpose/payload gap detected.');

    const total = latencies.reduce((a, b) => a + b, 0);
    console.log(`\n✔ LIVE behavioral battery passed: 7/7 genuine reasoning scenarios (total ${total}ms).`);
  } finally {
    config.museTimeoutMs = origMs;
  }
}

if (require.main === module) {
  runSparkBehaviorTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSparkBehaviorTests };
