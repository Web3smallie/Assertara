const assert = require('assert');
const config = require('../../src/config/env');
const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
const { compileEvidenceBundle } = require('../../src/services/evidenceService');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Force deterministic mock mode: decoder + heuristic reasoner run for real,
// Meta APIs are never touched. Separate node process per suite file.
const ORIGINAL_KEY = config.modelApiKey;
config.modelApiKey = 'mock_eval';

const DUMMY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const APPROVE_UNLIMITED = {
  from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
  to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
  data: '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  value: '0x0'
};
const SWAP_TX = {
  from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
  to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
  data: '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4',
  value: '0xde0b6b3a7640000'
};

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

// Load a simulator whose child_process.exec is stubbed, without touching disk state.
function loadSimulatorWithExec(fakeExec) {
  const realCp = require('child_process');
  const simPath = require.resolve('../../src/services/simulatorService');
  delete require.cache[simPath];
  const cpPath = require.resolve('child_process');
  const realEntry = require.cache[cpPath];
  require.cache[cpPath] = {
    id: cpPath, filename: cpPath, loaded: true,
    exports: { ...realCp, exec: fakeExec }
  };
  try {
    return require(simPath);
  } finally {
    if (realEntry) require.cache[cpPath] = realEntry;
    else delete require.cache[cpPath];
  }
}

const SIM_DECODED = {
  functionName: 'approve', symbol: 'USDT',
  parameters: { spender: '0x942c733fa43900388424a1bf7f94d934b3531b23', amount: '100' },
  isUnlimitedApproval: false
};
// Well-formed simulation input (Phase 14: malformed inputs are rejected by
// validation before reaching the toolchain, so toolchain-path tests use
// valid addresses/data).
const VALID_SIM_TX = {
  from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
  to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
  data: '0x095ea7b3'
};

async function runEvaluateTests() {
  console.log('Testing Evaluate Pipeline: Context, Provenance & Simulation Honesty...\n');

  // Test 1: legacy `page` object reaches reasoning with title, url, visibleText.
  {
    const r1 = await evaluate({
      page: { title: 'Token Dashboard', url: 'https://example.com/app', visibleText: 'Claim your free reward tokens now' },
      transaction: APPROVE_UNLIMITED
    });
    assert.strictEqual(r1.status, 200);
    assert.strictEqual(r1.body.verdict, 'MISMATCH', 'DOM visibleText must reach reasoning');
    const r2 = await evaluate({
      page: { title: 'Claim 1,000 UNI Free Airdrop', url: 'https://example.com/' },
      transaction: APPROVE_UNLIMITED
    });
    assert.strictEqual(r2.body.verdict, 'MISMATCH', 'page.title must reach reasoning');
    const r3 = await evaluate({
      page: { title: 'Exchange', url: 'https://app.uniswap.org/#/swap' },
      transaction: SWAP_TX
    });
    assert.strictEqual(r3.body.verdict, 'MATCH', 'page.url must reach reasoning');
    console.log('✔ Test 1 Passed: page.{title,url,visibleText} all reach downstream reasoning.');
  }

  // Test 2: canonical `pageContext` keeps working.
  {
    const res = await evaluate({
      pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
      transaction: SWAP_TX
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.verdict, 'MATCH', 'pageContext flow must keep working');
    assert.strictEqual(res.body.pageEvidence.url, 'https://app.uniswap.org/#/swap');
    console.log('✔ Test 2 Passed: pageContext-only requests keep working.');
  }

  // Test 3: both objects merge — pageContext wins overlaps, page-only fields survive.
  {
    const precedence = await evaluate({
      pageContext: { title: 'Claim Free Airdrop' },
      page: { title: 'Something Else', url: 'https://app.uniswap.org/#/swap' },
      transaction: APPROVE_UNLIMITED
    });
    assert.strictEqual(precedence.body.verdict, 'MISMATCH', 'pageContext.title must win over page.title');
    const merged = await evaluate({
      pageContext: { title: 'Exchange' },
      page: { url: 'https://app.uniswap.org/#/swap' },
      transaction: SWAP_TX
    });
    assert.strictEqual(merged.body.verdict, 'MATCH', 'page-only url must be preserved in the merge');
    assert.strictEqual(merged.body.pageEvidence.url, 'https://app.uniswap.org/#/swap');
    console.log('✔ Test 3 Passed: Precedence and merge follow the documented rules.');
  }

  // Test 4: missing context stays honestly missing (no crash, no fabrication).
  {
    const res = await evaluate({ transaction: SWAP_TX });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body.pageEvidence, { title: null, url: null });
    const sources = res.body.visualEvidence.textSources;
    assert.strictEqual(sources.find((s) => s.source === 'DOM_TEXT').available, false);
    assert.strictEqual(sources.find((s) => s.source === 'OCR_TEXT').available, false);
    assert.strictEqual(res.body.verdict, 'UNCERTAIN');
    console.log('✔ Test 4 Passed: Missing context is honestly missing.');
  }

  // Test 5: malformed context fails with 400, matching existing conventions.
  {
    for (const [name, body] of [
      ['string pageContext', { pageContext: 'nope', transaction: SWAP_TX }],
      ['array page', { page: [1, 2], transaction: SWAP_TX }],
      ['numeric title', { page: { title: 123 }, transaction: SWAP_TX }],
      ['missing recipient', { pageContext: { title: 'T' }, transaction: { data: '0x' } }]
    ]) {
      const res = await evaluate(body);
      assert.strictEqual(res.status, 400, `${name} must yield 400, got ${res.status}`);
      assert.ok(res.body.error, `${name} must carry an error message`);
    }
    console.log('✔ Test 5 Passed: Malformed context and missing recipient yield 400s.');
  }

  // Test 6: DOM vs OCR provenance labels; DOM text never poses as OCR output.
  {
    const res = await evaluate({
      page: { title: 'T', url: 'https://example.com/', visibleText: 'hello world' },
      transaction: SWAP_TX
    });
    assert.deepStrictEqual(res.body.visualEvidence.textSources, [
      { source: 'OCR_TEXT', available: false, text: '' },
      { source: 'DOM_TEXT', available: true, text: 'hello world' }
    ]);
    assert.strictEqual(res.body.visualEvidence.extractedText, 'No text extracted', 'OCR field must not contain DOM text');
    console.log('✔ Test 6 Passed: DOM_TEXT and OCR_TEXT labeled and separated.');
  }

  // Test 7: a supplied screenshot marks the OCR lane ran (even when empty).
  {
    const res = await evaluate({
      screenshot: DUMMY_PNG,
      pageContext: { title: 'T' },
      transaction: SWAP_TX
    });
    const ocr = res.body.visualEvidence.textSources.find((s) => s.source === 'OCR_TEXT');
    assert.strictEqual(ocr.available, true, 'Supplied screenshot means the OCR lane ran');
    assert.strictEqual(typeof ocr.text, 'string');
    assert.strictEqual(res.body.visualEvidence.textSources.find((s) => s.source === 'DOM_TEXT').available, false);
    console.log('✔ Test 7 Passed: Screenshot presence is distinguished from OCR results.');
  }

  // Test 8: oversized client text is safely truncated.
  {
    const res = await evaluate({
      page: { visibleText: 'x'.repeat(20000) },
      transaction: SWAP_TX
    });
    assert.strictEqual(res.body.visualEvidence.textSources.find((s) => s.source === 'DOM_TEXT').text.length, 8000);
    console.log('✔ Test 8 Passed: Client text is size-limited.');
  }

  // Test 9: forge failure degrades to an honest FALLBACK (never executed:true).
  // Valid inputs reach the toolchain; malformed inputs are rejected by
  // validation before any source generation (Phase 14 contract change:
  // FALLBACK must never substitute for input validation).
  {
    const enoent = loadSimulatorWithExec((cmd, opts, cb) => {
      const err = new Error('spawn forge ENOENT');
      err.code = 'ENOENT';
      cb(err, '', '');
    });
    const r1 = await enoent.simulateTransactionWithFoundry({ ...VALID_SIM_TX, decodedTx: SIM_DECODED });
    assert.strictEqual(r1.status, 'FALLBACK');
    assert.strictEqual(r1.executed, false, 'Fallback must not report executed:true');
    assert.strictEqual(r1.success, false, 'Fallback must not report success');
    assert.ok(Array.isArray(r1.fallbackAnalysis) && r1.fallbackAnalysis.length === 1, 'Fallback keeps its own analysis field');
    assert.ok(!('assetDeltas' in r1), 'Fallback must not use the execution field name');
    assert.ok(r1.manualReproductionHint.includes('not executed'), 'Suggested command must say it was not executed');

    const compileFail = loadSimulatorWithExec((cmd, opts, cb) => {
      cb(new Error('Command failed: forge test'), '', 'Compiler error: Source "forge-std/Test.sol" not found');
    });
    const r2 = await compileFail.simulateTransactionWithFoundry({ ...VALID_SIM_TX, decodedTx: SIM_DECODED });
    assert.strictEqual(r2.status, 'FALLBACK');
    assert.strictEqual(r2.executed, false);
    assert.ok(r2.error.includes('forge-std'), 'Fallback must surface the real underlying error');

    const r3 = await compileFail.simulateTransactionWithFoundry({ from: '0x1', to: '0x2', data: '0x', decodedTx: SIM_DECODED });
    assert.strictEqual(r3.status, 'FAILED', 'Malformed addresses must fail validation, not fall back');
    assert.ok(r3.error.includes('SIM_VALIDATION'));
    assert.strictEqual(r3.executed, false);
    console.log('✔ Test 9 Passed: Forge failures degrade to an honest FALLBACK.');
  }

  // Test 10: a killed/timed-out run is FAILED, with no invented analysis.
  {
    const sim = loadSimulatorWithExec((cmd, opts, cb) => {
      const err = new Error('Timeout');
      err.killed = true;
      err.signal = 'SIGTERM';
      cb(err, '', '');
    });
    const res = await sim.simulateTransactionWithFoundry({ ...VALID_SIM_TX, decodedTx: SIM_DECODED });
    assert.strictEqual(res.status, 'FAILED');
    assert.strictEqual(res.executed, false);
    assert.strictEqual(res.success, false);
    assert.ok(!('fallbackAnalysis' in res) && !('assetDeltas' in res), 'FAILED must not invent analysis');
    console.log('✔ Test 10 Passed: Timeouts report FAILED without invented results.');
  }

  // Test 11: exit 0 is genuine EXECUTED success with real output signals.
  {
    const sim = loadSimulatorWithExec((cmd, opts, cb) => {
      cb(null, '[PASS] test_simulate_execution() (gas: 12345)\nSuite result: ok. 1 passed; 0 failed', '');
    });
    const res = await sim.simulateTransactionWithFoundry({ ...VALID_SIM_TX, decodedTx: SIM_DECODED });
    assert.strictEqual(res.status, 'EXECUTED');
    assert.strictEqual(res.executed, true);
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.escalationDetected, false);
    assert.ok(res.rawLogs.includes('[PASS]'));

    const simEsc = loadSimulatorWithExec((cmd, opts, cb) => {
      cb(null, '[PASS] test_simulate_execution() (gas: 1)\nALLOWANCE_ESCALATION: 999', '');
    });
    const resEsc = await simEsc.simulateTransactionWithFoundry({ ...VALID_SIM_TX, decodedTx: SIM_DECODED });
    assert.strictEqual(resEsc.escalationDetected, true, 'Escalation marker must be detected');
    console.log('✔ Test 11 Passed: Exit 0 reports genuine EXECUTED success.');
  }

  // Test 12: an on-chain test failure is EXECUTED with success:false and the error.
  {
    const sim = loadSimulatorWithExec((cmd, opts, cb) => {
      cb(new Error('Command failed: forge test'), '[FAIL: Transaction call failed] test_simulate_execution() (gas: 999)', '');
    });
    const res = await sim.simulateTransactionWithFoundry({ ...VALID_SIM_TX, decodedTx: SIM_DECODED });
    assert.strictEqual(res.status, 'EXECUTED');
    assert.strictEqual(res.executed, true, 'An on-chain failure still executed');
    assert.strictEqual(res.success, false, 'An on-chain failure must not report success');
    assert.ok(res.error && res.rawLogs.includes('[FAIL'), 'Real failure output must be preserved');
    console.log('✔ Test 12 Passed: On-chain failure reports EXECUTED with success:false.');
  }

  // Test 13: no simulation attempt compiles to NOT_RUN.
  {
    const bundle = compileEvidenceBundle({
      visualResult: { regions: [], combinedText: '' },
      decodedTx: { contract: '0x0', contractName: 'C', functionName: 'transfer', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] },
      reasoningResult: { verdict: 'MATCH' },
      simulationResult: null
    });
    assert.deepStrictEqual(bundle.simulation, {
      status: 'NOT_RUN',
      executed: false,
      success: false,
      reason: 'No simulation required for low-risk verdict.'
    });
    console.log('✔ Test 13 Passed: Missing simulation compiles to honest NOT_RUN.');
  }

  config.modelApiKey = ORIGINAL_KEY;
  console.log('\nAll Evaluate Pipeline Tests Passed Successfully!\n');
}

if (require.main === module) {
  runEvaluateTests()
    .then(() => closeOcrWorker())
    .catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runEvaluateTests };
