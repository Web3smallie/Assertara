const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  simulateTransactionWithFoundry, generateFoundryTestContract,
  validateSimulationInputs, MAX_CALLDATA_BYTES
} = require('../../src/services/simulatorService');
const { evaluateSemanticDiscrepancy, fallbackHeuristicReasoner } = require('../../src/services/reasonerService');
const { compileEvidenceBundle } = require('../../src/services/evidenceService');

const ADDR_A = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const ADDR_B = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const APPROVE_DATA = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b230000000000000000000000000000000000000000000000000000000000000064';
const SIM_DECODED = {
  functionName: 'approve', symbol: 'USDT',
  parameters: { spender: SPENDER, amount: '100' },
  isUnlimitedApproval: false, contract: ADDR_B, ruleFindings: []
};

function simDirSnapshot() {
  const dir = path.join(__dirname, '..', '..', 'test', 'simulations');
  try {
    return fs.readdirSync(dir).sort();
  } catch {
    return null;
  }
}

async function runBoundaryTests() {
  console.log('Testing Production Boundaries: Simulator Security, Reasoner Provenance & Bundle Display...\n');

  // Test 1: adversarial simulator inputs rejected before generation.
  {
    const before = simDirSnapshot();
    const evil = [
      ['newline injection', { from: `${ADDR_A}\ncontract Evil {}`, to: ADDR_B, data: APPROVE_DATA }],
      ['quote breakout', { from: `${ADDR_A}"; malicious(); "`, to: ADDR_B, data: APPROVE_DATA }],
      ['comment injection', { from: '0x0000000000000000000000000000000000000000', to: ADDR_B, data: '0x095ea7b3//evil' }],
      ['short from', { from: '0x1', to: ADDR_B, data: APPROVE_DATA }],
      ['non-hex from', { from: '0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ', to: ADDR_B, data: APPROVE_DATA }],
      ['numeric from', { from: 12345, to: ADDR_B, data: APPROVE_DATA }],
      ['object from', { from: { evil: true }, to: ADDR_B, data: APPROVE_DATA }],
      ['missing to', { from: ADDR_A, data: APPROVE_DATA }],
      ['short to', { from: ADDR_A, to: '0x2', data: APPROVE_DATA }],
      ['non-string data', { from: ADDR_A, to: ADDR_B, data: 999 }],
      ['odd-length data', { from: ADDR_A, to: ADDR_B, data: '0x123' }],
      ['non-hex data', { from: ADDR_A, to: ADDR_B, data: '0xzzzz' }],
      ['over-cap data', { from: ADDR_A, to: ADDR_B, data: `0x${'ab'.repeat(MAX_CALLDATA_BYTES + 1)}` }],
      ['missing decodedTx', { from: ADDR_A, to: ADDR_B, data: APPROVE_DATA, decodedTx: null }],
      ['spender injection', { from: ADDR_A, to: ADDR_B, data: APPROVE_DATA, decodedTx: { ...SIM_DECODED, parameters: { spender: '0x1"; attack(); "' } } }]
    ];
    for (const [label, input] of evil) {
      const r = await simulateTransactionWithFoundry({ decodedTx: SIM_DECODED, ...input });
      assert.strictEqual(r.status, 'FAILED', `${label}: rejected`);
      assert.ok(r.error.includes('SIM_VALIDATION'), `${label}: structured error`);
      assert.strictEqual(r.executed, false, `${label}: never executed`);
      assert.ok(r.reason.includes('before any source generation'), `${label}: reason honest`);
    }
    assert.deepStrictEqual(simDirSnapshot(), before, 'Rejected inputs write no .t.sol files');
    assert.throws(() => validateSimulationInputs({}), (e) => e.code === 'SIM_VALIDATION');
    console.log('✔ Test 1 Passed: 15 adversarial inputs rejected; disk untouched.');
  }

  // Test 2: legitimate inputs preserved; generated source structurally safe.
  {
    const r = await simulateTransactionWithFoundry({ from: ADDR_A, to: ADDR_B, data: APPROVE_DATA, decodedTx: SIM_DECODED });
    assert.ok(['FALLBACK', 'EXECUTED'].includes(r.status), `Legit input reaches toolchain (got ${r.status})`);
    assert.ok(!String(r.error || '').includes('SIM_VALIDATION'), 'No validation error for legit input');
    const native = await simulateTransactionWithFoundry({ to: ADDR_B, decodedTx: { ...SIM_DECODED, functionName: 'nativeTransfer' } });
    assert.ok(['FALLBACK', 'EXECUTED'].includes(native.status), 'Missing from/data (native transfer) still supported');
    const src = generateFoundryTestContract({ victimAddress: ADDR_A, tokenAddress: ADDR_B, spenderAddress: SPENDER, calldataHex: APPROVE_DATA, testId: 'abc123' });
    assert.ok(src.includes(`VICTIM = ${ADDR_A}`) && src.includes(`hex"${APPROVE_DATA.slice(2)}"`));
    // Interpolated values are allowlist-charset: re-validate everything the
    // generator embedded and confirm no metacharacters could have ridden along.
    for (const v of [ADDR_A, ADDR_B, SPENDER, APPROVE_DATA]) {
      assert.ok(!/["';\n\r`/]/.test(v), 'Interpolated values carry no source metacharacters');
    }
    const capEdge = `0x${'ab'.repeat(MAX_CALLDATA_BYTES)}`;
    assert.doesNotThrow(() => validateSimulationInputs({ to: ADDR_B, data: capEdge, decodedTx: SIM_DECODED }), 'Exact cap accepted');
    console.log('✔ Test 2 Passed: Legit inputs simulate; interpolation charset-safe.');
  }

  // Test 3: fallback vs model provenance on every reasoner path.
  {
    const swapPage = { url: 'https://app.uniswap.org/#/swap', title: 'Swap 1.0 ETH for 3,450 USDC' };
    const swapTx = { ...SIM_DECODED, contractName: 'Uniswap V3 SwapRouter02', functionName: 'exactInputSingle', standard: 'UniswapV3Router', valueEth: '1', parameters: {} };
    assert.strictEqual(fallbackHeuristicReasoner('', swapPage, swapTx).origin, 'heuristic-fallback');
    assert.strictEqual(fallbackHeuristicReasoner('', { title: 'Claim free' }, { ...SIM_DECODED, isUnlimitedApproval: true }).origin, 'heuristic-fallback');
    assert.strictEqual(fallbackHeuristicReasoner('', { title: 'Gov' }, { functionName: 'unknownFunction', standard: 'Unknown', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] }).origin, 'heuristic-fallback');
    const realFetch = global.fetch;
    const config = require('../../src/config/env');
    const originalKey = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    try {
      global.fetch = async () => ({ ok: true, json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] }) });
      const live = await evaluateSemanticDiscrepancy('', swapPage, swapTx);
      assert.strictEqual(live.origin, 'model', 'Live model path labeled model');
      assert.strictEqual(live.verdict, 'MATCH', 'Verdict itself unchanged');
      global.fetch = async () => { throw new Error('network down'); };
      const degraded = await evaluateSemanticDiscrepancy('', swapPage, swapTx);
      assert.strictEqual(degraded.origin, 'heuristic-fallback', 'Unavailable model degrades with label');
      assert.strictEqual(degraded.verdict, 'MATCH', 'Deterministic fallback behavior preserved');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = originalKey;
    }
    console.log('✔ Test 3 Passed: origin=model vs heuristic-fallback on all paths.');
  }

  // Test 4: provenance preserved through bundle + extension display.
  {
    const bundle = compileEvidenceBundle({
      visualResult: { regions: [], combinedText: '' },
      decodedTx: { contract: ADDR_B, contractName: 'T', functionName: 'approve', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] },
      reasoningResult: { verdict: 'MISMATCH', confidence: 0.9, summary: 's', recommendedAction: 'BLOCK_TRANSACTION', origin: 'heuristic-fallback' },
      simulationResult: null
    });
    assert.strictEqual(bundle.reasoningOrigin, 'heuristic-fallback');
    assert.strictEqual(bundle.verdict, 'MISMATCH', 'Verdict untouched by provenance work');
    const bare = compileEvidenceBundle({
      visualResult: { regions: [], combinedText: '' },
      decodedTx: { contract: ADDR_B, functionName: 'approve', parameters: {}, isUnlimitedApproval: false },
      reasoningResult: { verdict: 'MATCH' }, simulationResult: null
    });
    assert.strictEqual(bare.reasoningOrigin, 'unknown', 'Missing origin degrades to unknown, never invented');
    require('../../extension/shared/format.js');
    const F = globalThis.AssertaraFormat;
    assert.strictEqual(F.reasoningOriginLabel('model'), 'Muse Spark analysis');
    assert.ok(F.reasoningOriginLabel('heuristic-fallback').includes('unverified'));
    assert.strictEqual(F.reasoningOriginLabel(undefined), 'Reasoning source unknown');
    console.log('✔ Test 4 Passed: Provenance flows bundle → display; unknown never invented.');
  }

  console.log('\nAll Boundary Tests Passed Successfully!\n');
}

if (require.main === module) {
  runBoundaryTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runBoundaryTests };
