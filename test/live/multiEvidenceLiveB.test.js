const assert = require('assert');
const { liveEnabled, attemptModel, attemptReasoner, bootAnvil, REVIEW_FILE, config } = require('./multiEvidenceHelper');
const { fetchChainState } = require('../../src/services/chainStateService');

// Cap3 live battery B: chain-state + simulation joint scenarios.
// ME5/ME8 use a live Anvil RPC (genuine chain reads). ME6/ME7 use
// LABELED mocked sim records with a live model (forge cannot genuinely
// execute in this environment; the mock is the sim INPUT, reasoning live).

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const APPROVE_MAX = `0x095ea7b3000000000000000000000000${A1.slice(2).toLowerCase()}${'f'.repeat(64)}`;

async function run() {
  const gate = liveEnabled();
  if (!gate.ok) { console.log(`SKIP: battery B disabled (${gate.reason}).`); return; }
  console.log('LIVE Cap3 battery B: chain + simulation scenarios...\n');
  config.investigationsFile = REVIEW_FILE;
  const origMs = config.museTimeoutMs;
  config.museTimeoutMs = 180000;
  const anvil = await bootAnvil();
  console.log(`  anvil up at ${anvil.rpcUrl}`);
  const origRpc = config.evidenceChainRpcUrl;
  config.evidenceChainRpcUrl = anvil.rpcUrl;
  try {
    // ME5: 50000 ETH transfer from a 10000 ETH account.
    {
      console.log('  [ME5-insufficient-funds] running...');
      const out = await attemptModel('ME5-insufficient-funds', {
        pageContext: { title: 'Send 50000 ETH', url: 'https://w.example', visibleText: 'Send 50000 ETH to contractor' },
        transaction: { from: A0, to: A1, data: '0x', value: '0xa968163f0a57b400000', chainId: '0x7a69' },
        capturedAt: Date.now()
      }, undefined);
      const b = out.body;
      console.log(`  [ME5] ${out.wallMs}ms verdict=${b.verdict} decision=${b.policyDecision.decision}`);
      assert.strictEqual(b.reasoningOrigin, 'model');
      assert.ok((b.chainVerification.failures || []).some((f) => f.checkId === 'BALANCE_SUFFICIENCY'), 'balance failure recorded');
      assert.notStrictEqual(b.verdict, 'MATCH', 'unfunded tx cannot hold MATCH');
      assert.notStrictEqual(b.policyDecision.decision, 'ALLOW', 'unfunded tx never ALLOWs');
      console.log('  ✔ ME5-insufficient-funds');
    }

    // ME6: sim confirms (MOCKED sim input, live model).
    {
      console.log('  [ME6-sim-confirms] running (mocked sim record, live model)...');
      const t0 = Date.now();
      const out = await attemptReasoner('ME6-sim-confirms', [
        'Swap 1.0 ETH for 3,450 USDC',
        { title: 'Swap', url: 'https://app.uniswap.org/#/swap', visibleText: 'Swap 1.0 ETH for USDC' },
        {
          contract: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', contractName: 'Uniswap V3 SwapRouter02',
          functionName: 'exactInputSingle', standard: 'UniswapV3Router', valueEth: '1',
          parameters: { tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', tokenOut: USDC, fee: 500 },
          isUnlimitedApproval: false, ruleFindings: []
        },
        { detectedCount: 0 },
        { simulation: { simId: 'SIM-001', status: 'EXECUTED', executed: true, success: true, escalationDetected: false } }
      ]);
      console.log(`  [ME6] ${Date.now() - t0}ms origin=${out.origin} verdict=${out.verdict}`);
      assert.strictEqual(out.origin, 'model');
      assert.ok(JSON.stringify(out.investigation).toLowerCase().includes('simulat'), 'model engages the sim record');
      assert.strictEqual(out.referenceValidation.ok, true);
      console.log('  ✔ ME6-sim-confirms');
    }

    // ME7: sim reveals revert (MOCKED sim input, live model).
    {
      console.log('  [ME7-sim-reveals] running (mocked sim record, live model)...');
      const t0 = Date.now();
      const out = await attemptReasoner('ME7-sim-reveals', [
        'Swap 1.0 ETH for 3,450 USDC',
        { title: 'Swap', url: 'https://app.uniswap.org/#/swap', visibleText: 'Swap 1.0 ETH for USDC' },
        {
          contract: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', contractName: 'Uniswap V3 SwapRouter02',
          functionName: 'exactInputSingle', standard: 'UniswapV3Router', valueEth: '1',
          parameters: { tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', tokenOut: USDC, fee: 500 },
          isUnlimitedApproval: false, ruleFindings: []
        },
        { detectedCount: 0 },
        { simulation: { simId: 'SIM-001', status: 'EXECUTED', executed: true, success: false, escalationDetected: false, error: 'reverted: insufficient output' } }
      ]);
      console.log(`  [ME7] ${Date.now() - t0}ms origin=${out.origin} verdict=${out.verdict}`);
      assert.strictEqual(out.origin, 'model');
      const text = JSON.stringify(out.investigation).toLowerCase();
      assert.ok(text.includes('simulat'), 'model engages the sim record');
      assert.ok(text.includes('revert') || text.includes('fail'), 'model flags the measured revert');
      console.log('  ✔ ME7-sim-reveals');
    }

    // ME8: disclosed approval + live chain shows target has no code.
    {
      console.log('  [ME8-joint-code-conflict] running...');
      const live = await fetchChainState({ rpcUrl: anvil.rpcUrl, chainId: '0x7a69', addresses: [{ role: 'target', address: USDC }], timeoutMs: 8000 });
      assert.strictEqual(live.states.target.hasCode, false, 'sanity: USDC has no code on Anvil');
      const out = await attemptModel('ME8-joint-code-conflict', {
        pageContext: { title: 'Approve unlimited USDC', url: 'https://app.uniswap.org/approve', visibleText: 'This grants unlimited USDC spending to the router.' },
        transaction: { from: A0, to: USDC, data: APPROVE_MAX, value: '0x0', chainId: '0x7a69' },
        capturedAt: Date.now()
      }, undefined);
      const b = out.body;
      console.log(`  [ME8] ${out.wallMs}ms verdict=${b.verdict} decision=${b.policyDecision.decision}`);
      assert.strictEqual(b.reasoningOrigin, 'model');
      assert.ok((b.chainVerification.failures || []).some((f) => f.checkId === 'CODE_CALL_CONSISTENCY'), 'code-call failure recorded');
      assert.ok(JSON.stringify(b.investigation).toLowerCase().includes('code') || (b.chainVerification.failures || []).length > 0, 'joint conflict visible');
      console.log('  ✔ ME8-joint-code-conflict');
    }

    console.log('\n✔ LIVE Cap3 battery B passed: 4/4 chain/sim scenarios.');
  } finally {
    config.museTimeoutMs = origMs;
    config.evidenceChainRpcUrl = origRpc;
    anvil.kill();
  }
}

if (require.main === module) run().catch((err) => { console.error(err); process.exit(1); });
module.exports = { run };
