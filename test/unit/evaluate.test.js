const assert = require('assert');
const config = require('../../src/config/env');
const { handleEvaluateTransaction, applyVerdictSafeguards } = require('../../src/controllers/evaluateController');
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
// Capability 4 B3: the shared swap fixture carries COMPLETE exactInputSingle
// calldata (1 ETH in, 3,400 USDC minimum out, recipient == sender). The old
// truncated form (fee word last, no minimum) would now — correctly — flag
// MISSING_OUTPUT_PROTECTION and downgrade MATCH verdicts, which is not
// what these pipeline tests exercise. Truncated-decode coverage lives in
// decoder.test.js Test 4 and semanticReasoning.test.js B3.3.
const SWAP_TX = {
  from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
  to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
  data: '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000caa7e2000000000000000000000000000000000000000000000000000000000000000000',
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

// Load a controller whose ocrService.extractUiTexts is stubbed, mirroring the
// simulator cache-injection idiom. Everything else runs for real.
function loadControllerWithOcr(fakeExtract) {
  const ocrPath = require.resolve('../../src/services/ocrService');
  const ctlPath = require.resolve('../../src/controllers/evaluateController');
  const realOcrEntry = require.cache[ocrPath];
  const hadCtl = Object.prototype.hasOwnProperty.call(require.cache, ctlPath);
  const realCtlEntry = require.cache[ctlPath];
  require.cache[ocrPath] = {
    id: ocrPath, filename: ocrPath, loaded: true,
    exports: { extractUiTexts: fakeExtract }
  };
  delete require.cache[ctlPath];
  try {
    return require(ctlPath);
  } finally {
    if (realOcrEntry) require.cache[ocrPath] = realOcrEntry;
    else delete require.cache[ocrPath];
    if (hadCtl) require.cache[ctlPath] = realCtlEntry;
    else delete require.cache[ctlPath];
  }
}

function runWith(handle, body) {
  return new Promise((resolve) => {
    const req = { body };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); }
    };
    handle(req, res);
  });
}

// Phase C harness: transfer pipeline with one genuine summary detection,
// fake OCR showing a recipient address, and a stubbed model verdict. The
// UI shows PC_SPENDER while the tx sends to PC_OTHER, so the comparison
// yields a counterparty MISMATCH every run.
const PC_SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const PC_OTHER = '0x1111111254fb6c44bac0bed2854e76f90643097d';
const PC_USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const PC_FROM = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const PC_TRANSFER_DATA = '0xa9059cbb0000000000000000000000001111111254fb6c44bac0bed2854e76f90643097d00000000000000000000000000000000000000000000000000000000000f4240';
async function evalWithMismatchClaim(modelVerdict, modelConfidence) {
  const realFetch = global.fetch;
  const origKey = config.modelApiKey;
  config.modelApiKey = 'test-live-key';
  const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=0;y1=0;x2=1;y2=1;w=1;h=1|>"}\n'
    + 'data: {"type":"response.completed"}\n';
  const zeroSse = 'data: {"type":"response.completed"}\n';
  global.fetch = async (url, opts) => {
    if (String(url).endsWith('/responses')) {
      const c = JSON.parse(opts.body).input[0].content[0].text;
      return { ok: true, text: async () => (c === 'transaction summary' ? boxSse : zeroSse) };
    }
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify({
        verdict: modelVerdict, confidence: modelConfidence, summary: 's', discrepancyDetails: {},
        recommendedAction: 'PROCEED_WITH_CAUTION',
        visualClaims: [{ type: 'recipient', value: PC_SPENDER, regionIds: ['R-001'], associationIds: [] }]
      }) } }] })
    };
  };
  const ctl = loadControllerWithOcr(async (shot, regions) => ({
    regionTexts: regions.map((r) => ({
      regionId: r.regionId, label: r.label, boundingBox: r.boundingBox,
      genuine: r.genuine, text: `To ${PC_SPENDER}`, empty: false, ocrError: null
    })),
    combinedText: regions.length > 0 ? `[TRANSACTION SUMMARY]: To ${PC_SPENDER}` : ''
  }));
  try {
    return await runWith(ctl.handleEvaluateTransaction, {
      screenshot: DUMMY_PNG,
      pageContext: { title: 'Send demo', url: 'https://demo.local/send' },
      transaction: { from: PC_FROM, to: PC_USDC, data: PC_TRANSFER_DATA, value: '0x0' }
    });
  } finally {
    global.fetch = realFetch;
    config.modelApiKey = origKey;
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
      { source: 'OCR_TEXT', available: false, synthetic: false, text: '' },
      { source: 'DOM_TEXT', available: true, synthetic: false, text: 'hello world' }
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

  // Test 14 (Phase 1): zero live detections are marked insufficient end to end.
  // Full controller run with stubbed fetch: SAM completes empty, model canned.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url) => {
      if (String(url).endsWith('/responses')) {
        return { ok: true, text: async () => 'data: {"type":"response.completed"}\n' };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.status, 200);
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 0, 'Zero detections counted honestly');
      assert.strictEqual(v.visualAvailable, false, 'No detections means unavailable visual evidence');
      assert.deepStrictEqual(v.regions, [], 'Synthetic geometry excluded from genuine regions');
      assert.strictEqual(v.fallback.reason, 'zero-detections', 'Fallback reason preserved');
      assert.strictEqual(v.textSources.find((s) => s.source === 'OCR_TEXT').synthetic, true, 'Fallback OCR labeled synthetic');
      assert.strictEqual(res.body.decodedTransaction.functionName, 'exactInputSingle', 'Decode intact without visual evidence');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 14 Passed: Zero detections marked insufficient; decode intact.');
  }

  // Test 15 (Phase 1): SAM API errors stay errors; deterministic layer survives.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url) => {
      if (String(url).endsWith('/responses')) {
        return { ok: false, status: 503, text: async () => 'overloaded' };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"UNCERTAIN","confidence":0.6,"summary":"s","discrepancyDetails":{},"recommendedAction":"VERIFY_RECIPIENT"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'T', url: 'https://example.com/' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.status, 200);
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 0);
      assert.strictEqual(v.visualAvailable, false);
      assert.strictEqual(v.fallback.reason, 'error', 'Error fallback distinct from zero-match');
      assert.ok((v.samError || '').includes('503'), 'SAM error preserved in bundle');
      assert.strictEqual(res.body.decodedTransaction.contractName, 'Uniswap V3 SwapRouter02');
      assert.deepStrictEqual(res.body.ruleFindings, [], 'Rule findings computed despite SAM failure');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 15 Passed: SAM errors preserved; deterministic findings intact.');
  }

  // Test 16 (Phase 5A): exact value evidence end to end + malformed value 400.
  {
    const res = await evaluate({
      pageContext: { title: 'Swap 0.5 ETH for 1,725 USDC', url: 'https://app.uniswap.org/#/swap' },
      transaction: { ...SWAP_TX, value: '0x6f05b59d3b20000' }
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.verdict, 'MATCH', 'Value fix must not change verdict policy');
    assert.strictEqual(res.body.decodedTransaction.valueEth, '0.5', 'Bundle keeps the exact fractional ETH');
    assert.strictEqual(res.body.decodedTransaction.valueWei, '500000000000000000', 'Bundle keeps the raw wei');
    const bad = await evaluate({
      pageContext: { title: 'T' },
      transaction: { ...SWAP_TX, value: '0xZZ' }
    });
    assert.strictEqual(bad.status, 400, 'Malformed value must yield 400, not 500');
    assert.ok(bad.body.error.includes('value'), '400 must name the value problem');
    console.log('✔ Test 16 Passed: Exact value evidence in bundle; malformed value is a 400.');
  }

  // Test 17 (Phase 5C): screenshot + zero detections + model MATCH 0.9 ->
  // verdict preserved, confidence capped, adjustment recorded.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url) => {
      if (String(url).endsWith('/responses')) {
        return { ok: true, text: async () => 'data: {"type":"response.completed"}\n' };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"swap aligns","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'MATCH', 'Verdict preserved, only confidence capped');
      assert.strictEqual(res.body.confidence, 0.65, 'Zero-visual MATCH capped at 0.65');
      assert.ok(res.body.summary.includes('swap aligns'), 'Original summary kept');
      assert.ok(res.body.summary.includes('Confidence capped at 0.65'), 'Cap disclosed in summary');
      assert.deepStrictEqual(res.body.confidenceCap, {
        trigger: 'ZERO_GENUINE_DETECTIONS',
        previousConfidence: 0.9,
        cap: 0.65,
        reason: 'Screenshot supplied but no genuine visual regions detected; MATCH confidence capped at 0.65.'
      });
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 0, 'Zero detections counted honestly');
      assert.strictEqual(v.visualAvailable, false);
      assert.strictEqual(v.ocrMode, 'fallback-scan');
      assert.strictEqual(v.textSources.find((s) => s.source === 'OCR_TEXT').synthetic, true, 'Fallback OCR stays synthetic');
      assert.deepStrictEqual(res.body.verdictSafeguards, [], 'Cap is separate from safeguard records');
      assert.strictEqual(res.body.verdictSafeguard, null);
      assert.strictEqual(res.body.decodedTransaction.valueEth, '1', 'Phase 5A exact value intact');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 17 Passed: Zero-visual model MATCH capped with full provenance.');
  }

  // Test 18 (Phase 5C): SAM failure + model MATCH -> same cap, error disclosed.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url) => {
      if (String(url).endsWith('/responses')) {
        return { ok: false, status: 503, text: async () => 'overloaded' };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.body.verdict, 'MATCH', 'Verdict preserved on SAM failure');
      assert.strictEqual(res.body.confidence, 0.65, 'SAM-failure MATCH capped at 0.65');
      assert.ok(res.body.summary.includes('visual segmentation failed'), 'Failure cause disclosed');
      assert.strictEqual(res.body.confidenceCap.trigger, 'ZERO_GENUINE_DETECTIONS');
      assert.strictEqual(res.body.confidenceCap.previousConfidence, 0.9);
      assert.ok(res.body.confidenceCap.reason.includes('visual segmentation failed'));
      assert.ok((res.body.visualEvidence.samError || '').includes('503'), 'SAM error preserved');
      assert.strictEqual(res.body.visualEvidence.fallback.reason, 'error');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 18 Passed: SAM-failure MATCH capped with cause recorded.');
  }

  // Test 19 (Phase 5C extension): one genuine detection whose OCR
  // deterministically fails (box outside the 1x1 dummy image; the crop
  // throws before any OCR engine runs) -> MATCH capped under the new
  // ZERO_USABLE_OCR_TEXT trigger. Geometry alone no longer exempts.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}\n'
      + 'data: {"type":"response.completed"}\n';
    global.fetch = async (url) => {
      if (String(url).endsWith('/responses')) {
        return { ok: true, text: async () => boxSse };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.body.visualEvidence.detectedCount, 1, 'Genuine detection counted');
      assert.strictEqual(res.body.visualEvidence.visualAvailable, true);
      assert.strictEqual(res.body.visualEvidence.ocrMode, 'regions');
      assert.strictEqual(res.body.visualEvidence.regions.length, 1);
      assert.strictEqual(res.body.visualEvidence.regions[0].ocr.error.code, 'BOX_OUT_OF_BOUNDS', 'OCR error preserved in bundle');
      assert.strictEqual(res.body.visualEvidence.regions[0].ocr.text, null, 'Failed read keeps null text');
      assert.strictEqual(res.body.verdict, 'MATCH', 'Verdict preserved, only confidence capped');
      assert.strictEqual(res.body.confidence, 0.65, 'All-failed OCR MATCH capped at 0.65');
      assert.strictEqual(res.body.confidenceCap.trigger, 'ZERO_USABLE_OCR_TEXT', 'Distinct trigger for textless regions');
      assert.strictEqual(res.body.confidenceCap.previousConfidence, 0.9);
      assert.ok(res.body.confidenceCap.reason.includes('every genuine region OCR attempt failed'), 'All-failed distinguished in record');
      assert.ok(res.body.summary.includes('Confidence capped at 0.65'), 'Cap disclosed in summary');
      assert.deepStrictEqual(res.body.verdictSafeguards, [], 'Cap is separate from safeguard records');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 19 Passed: All-failed OCR caps under its own trigger.');
  }

  // Test 20 (Phase 5C): heuristic fallback with zero detections is capped too.
  {
    const res = await evaluate({
      screenshot: DUMMY_PNG,
      pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
      transaction: SWAP_TX
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.reasoningOrigin, 'heuristic-fallback', 'Mock mode must use the heuristic');
    assert.strictEqual(res.body.verdict, 'MATCH', 'Heuristic verdict preserved');
    assert.strictEqual(res.body.confidence, 0.65, 'Heuristic zero-visual MATCH capped');
    assert.strictEqual(res.body.confidenceCap.previousConfidence, 0.88, 'Original heuristic confidence recorded');
    assert.ok(res.body.summary.includes('Confidence capped at 0.65'), 'Cap disclosed for heuristic path');
    assert.strictEqual(res.body.visualEvidence.detectedCount, 0);
    console.log('✔ Test 20 Passed: Heuristic fallback capped identically.');
  }

  // Test 21 (Phase 5C): no screenshot -> documented contract preserved, no cap.
  {
    const res = await evaluate({
      pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
      transaction: SWAP_TX
    });
    assert.strictEqual(res.body.verdict, 'MATCH');
    assert.strictEqual(res.body.confidence, 0.88, 'No-screenshot MATCH keeps heuristic confidence');
    assert.strictEqual(res.body.confidenceCap, null, 'No cap without a screenshot');
    assert.ok(!res.body.summary.includes('Confidence capped'), 'No cap disclosure without a screenshot');
    console.log('✔ Test 21 Passed: No-screenshot contract preserved.');
  }

  // Test 22 (Fix 1): partial SAM failure (500 + clean zero) reaches the
  // bundle as a partial failure — never as a clean zero-detection result.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url, opts) => {
      if (String(url).endsWith('/responses')) {
        const c = JSON.parse(opts.body).input[0].content[0].text;
        if (c === 'button') return { ok: false, status: 500, text: async () => 'boom' };
        return { ok: true, text: async () => 'data: {"type":"response.completed"}\n' };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.status, 200);
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 0);
      assert.ok((v.samError || '').includes('button') && v.samError.includes('500'), 'Failed prompt error in bundle');
      assert.strictEqual(v.fallback.reason, 'partial-error', 'Partial zero distinct from clean zero');
      assert.strictEqual(v.samPartialFailure, true, 'Explicit partial-failure status');
      assert.strictEqual(v.samPromptResults.length, 3, 'Every prompt status preserved (incl. summary prompt)');
      assert.ok(v.samPromptResults.find((p) => p.prompt === 'button').error.includes('500'));
      assert.strictEqual(v.samPromptResults.find((p) => p.prompt === 'dialog box').error, undefined);
      assert.strictEqual(v.samPromptResults.find((p) => p.prompt === 'transaction summary').error, undefined, 'Summary prompt clean');
      assert.strictEqual(res.body.verdict, 'MATCH', 'Verdict preserved');
      assert.strictEqual(res.body.confidence, 0.65, 'Zero-detection cap still applies');
      assert.ok(res.body.confidenceCap.reason.includes('partially failed'), 'Cap names the partial cause');
      assert.deepStrictEqual(res.body.verdictSafeguards, [], 'Safeguard records untouched');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 22 Passed: Partial failure visible end to end.');
  }

  // Test 23 (Fix 1): partial failure with surviving genuine detections —
  // the region, its OCR error, and the sibling failure all reach the bundle.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}\n'
      + 'data: {"type":"response.completed"}\n';
    global.fetch = async (url, opts) => {
      if (String(url).endsWith('/responses')) {
        const c = JSON.parse(opts.body).input[0].content[0].text;
        if (c === 'dialog box') return { ok: false, status: 500, text: async () => 'boom' };
        return { ok: true, text: async () => boxSse };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 1, 'Genuine detection survives end to end');
      assert.strictEqual(v.regions.length, 1);
      assert.strictEqual(v.regions[0].genuine, true);
      assert.strictEqual(v.regions[0].ocr.error.code, 'BOX_OUT_OF_BOUNDS', 'Region OCR error preserved');
      assert.strictEqual(v.fallback, null, 'No fallback displaces genuine regions');
      assert.ok((v.samError || '').includes('dialog box'), 'Sibling failure preserved');
      assert.strictEqual(v.samPartialFailure, true);
      assert.strictEqual(res.body.verdict, 'MATCH');
      assert.strictEqual(res.body.confidenceCap.trigger, 'ZERO_USABLE_OCR_TEXT', 'Unreadable survivor caps via the OCR rule');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 23 Passed: Detections and failures coexist honestly.');
  }

  // Test 24 (Fix 2): truncated stream with a parsed box — the detection
  // survives end to end while the bundle marks the inspection incomplete.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const truncated = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}\n';
    global.fetch = async (url) => {
      if (String(url).endsWith('/responses')) {
        return { ok: true, text: async () => truncated };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 1, 'Parsed detection preserved');
      assert.strictEqual(v.regions.length, 1);
      assert.strictEqual(v.regions[0].genuine, true);
      assert.strictEqual(v.samIncomplete, true, 'Bundle marks the inspection incomplete');
      assert.strictEqual(v.samPartialFailure, false, 'No hard failure conflated');
      assert.strictEqual(v.samError, null, 'No HTTP error invented');
      assert.ok(v.samPromptResults.every((p) => p.incomplete === true), 'Every prompt entry marked');
      assert.strictEqual(res.body.verdict, 'MATCH', 'Verdict preserved');
      assert.strictEqual(res.body.confidenceCap.trigger, 'ZERO_USABLE_OCR_TEXT', 'Unreadable survivor caps via the OCR rule');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 24 Passed: Truncated detections flagged end to end.');
  }

  // Test 25 (Fix 2): empty-200 streams are incomplete, never clean zero —
  // bundle reason, flag, and cap cause all agree.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url) => {
      if (String(url).endsWith('/responses')) {
        return { ok: true, text: async () => '' };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 0);
      assert.strictEqual(v.fallback.reason, 'incomplete', 'Not a clean zero');
      assert.strictEqual(v.samIncomplete, true);
      assert.strictEqual(v.samPartialFailure, false);
      assert.strictEqual(v.samError, null, 'Incompleteness is not an HTTP error');
      assert.strictEqual(res.body.verdict, 'MATCH', 'Verdict preserved');
      assert.strictEqual(res.body.confidence, 0.65);
      assert.ok(res.body.confidenceCap.reason.includes('response incomplete'), 'Cap names the incomplete cause');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 25 Passed: Empty streams incomplete end to end.');
  }

  // Test 26 (Fix 3): controller behavior on reasoning timeout — the exact
  // heuristic result surfaces with fallback provenance, nothing fabricated.
  // No screenshot isolates the reasoner (SAM is skipped entirely).
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const origMs = config.museTimeoutMs;
    config.museTimeoutMs = 50;
    global.fetch = async (url, opts) => new Promise((_, reject) => {
      opts.signal.addEventListener('abort', () => {
        const e = new Error('The operation was aborted');
        e.name = 'AbortError';
        reject(e);
      }, { once: true });
    });
    try {
      const res = await evaluate({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'MATCH', 'Heuristic verdict preserved');
      assert.strictEqual(res.body.confidence, 0.88, 'Exact heuristic confidence, uncapped without screenshot');
      assert.strictEqual(res.body.reasoningOrigin, 'heuristic-fallback', 'Fallback provenance preserved');
      assert.strictEqual(res.body.reasoningTimedOut, true, 'Timeout surfaced in the bundle');
      assert.deepStrictEqual(res.body.verdictSafeguards, [], 'No spurious safeguards');
      assert.strictEqual(res.body.confidenceCap, null, 'No cap without a screenshot');
      assert.strictEqual(res.body.decodedTransaction.functionName, 'exactInputSingle', 'Decode intact');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
      config.museTimeoutMs = origMs;
    }
    console.log('✔ Test 26 Passed: Reasoning timeout degrades safely end to end.');
  }

  // Test 27 (timeout provenance): HTTP-error fallback is not a timeout.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({ ok: false, status: 500 });
    try {
      const res = await evaluate({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.body.reasoningOrigin, 'heuristic-fallback');
      assert.strictEqual(res.body.reasoningTimedOut, false, 'HTTP fallback is not a timeout');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 27 Passed: HTTP fallback leaves the timeout flag false.');
  }

  // Test 28 (timeout provenance): transport-error fallback is not a timeout.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => { throw new Error('socket hangup'); };
    try {
      const res = await evaluate({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.body.reasoningOrigin, 'heuristic-fallback');
      assert.strictEqual(res.body.reasoningTimedOut, false, 'Transport fallback is not a timeout');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 28 Passed: Transport fallback leaves the timeout flag false.');
  }

  // Test 29 (timeout provenance): successful model reasoning is not a timeout.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
    });
    try {
      const res = await evaluate({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.body.reasoningOrigin, 'model');
      assert.strictEqual(res.body.reasoningTimedOut, false, 'Model success is not a timeout');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 29 Passed: Model success leaves the timeout flag false.');
  }

  // Test 30 (timeout provenance): a bundle compiled without reasoning
  // results never misreports a timeout.
  {
    const bundle = compileEvidenceBundle({
      visualResult: { regions: [], combinedText: '' },
      decodedTx: { contract: '0x0', contractName: 'C', functionName: 'transfer', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] },
      reasoningResult: { verdict: 'MATCH' },
      simulationResult: null
    });
    assert.strictEqual(bundle.reasoningTimedOut, false, 'Missing flag defaults to false');
    assert.strictEqual(bundle.reasoningOrigin, 'unknown');
    console.log('✔ Test 30 Passed: Unrun reasoning defaults the timeout flag to false.');
  }

  // Test 31 (Phase 2): reasoning timeout yields no fabricated claims —
  // grounding honestly not-evaluated with the timeout flag set.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const origMs = config.museTimeoutMs;
    config.museTimeoutMs = 50;
    global.fetch = async (url, opts) => new Promise((_, reject) => {
      opts.signal.addEventListener('abort', () => {
        const e = new Error('The operation was aborted');
        e.name = 'AbortError';
        reject(e);
      }, { once: true });
    });
    try {
      const res = await evaluate({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.body.reasoningTimedOut, true);
      assert.deepStrictEqual(res.body.visualEvidence.grounding, {
        status: 'not-evaluated', reason: 'no-structured-claims', claims: []
      });
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
      config.museTimeoutMs = origMs;
    }
    console.log('✔ Test 31 Passed: Timeout produces no fabricated claims.');
  }

  // Test 32 (Phase 2): heuristic fallback produces no model claims.
  {
    const res = await evaluate({
      pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
      transaction: SWAP_TX
    });
    assert.strictEqual(res.body.reasoningOrigin, 'heuristic-fallback');
    assert.deepStrictEqual(res.body.visualEvidence.grounding, {
      status: 'not-evaluated', reason: 'no-structured-claims', claims: []
    });
    console.log('✔ Test 32 Passed: Heuristic path has no model claims.');
  }

  // Test 33 (Phase 2): model claims validate end to end; verdict, caps,
  // decode, and Phase 1 associations stay intact.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=1;y1=2;x2=11;y2=12;w=100;h=100|>"}\n'
      + 'data: {"type":"response.completed"}\n';
    global.fetch = async (url) => {
      if (String(url).endsWith('/responses')) {
        return { ok: true, text: async () => boxSse };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION","visualClaims":[{"type":"amount","value":"1.0 ETH","regionIds":["R-001"],"associationIds":[]}]}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      const g = res.body.visualEvidence.grounding;
      assert.strictEqual(g.status, 'evaluated');
      assert.strictEqual(g.claims.length, 1);
      assert.strictEqual(g.claims[0].status, 'unsupported', 'Failed-OCR region cannot verify the claim');
      assert.deepStrictEqual(g.claims[0].reasons, ['region-ocr-failed']);
      assert.strictEqual(g.claims[0].observed[0].regionId, 'R-001');
      assert.strictEqual(g.claims[0].observed[0].ocrError.code, 'BOX_OUT_OF_BOUNDS');
      assert.strictEqual(res.body.verdict, 'MATCH', 'Verdict policy unchanged by grounding');
      assert.strictEqual(res.body.confidenceCap.trigger, 'ZERO_USABLE_OCR_TEXT', 'OCR cap coexists');
      assert.ok(Array.isArray(res.body.visualEvidence.associations.links), 'Phase 1 associations intact');
      assert.strictEqual(res.body.decodedTransaction.functionName, 'exactInputSingle', 'Decode intact');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 33 Passed: Claims validate end to end without side effects.');
  }

  // Test 34 (Phase 2): model success without claims is honestly unavailable.
  {
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
    });
    try {
      const res = await evaluate({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.body.reasoningOrigin, 'model');
      assert.deepStrictEqual(res.body.visualEvidence.grounding, {
        status: 'not-evaluated', reason: 'no-structured-claims', claims: []
      });
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = 'mock_eval';
    }
    console.log('✔ Test 34 Passed: Claimless model output is honestly unavailable.');
  }

  config.modelApiKey = ORIGINAL_KEY;
  // Test 35 (Phase 3): end-to-end, a summary-prompt detection with readable
  // text supplies the transaction-intent text; the bundle and the reasoner
  // prompt both label the source.
  {
    const realFetch = global.fetch;
    const origKey = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=10;y1=20;x2=110;y2=120;w=200;h=200|>"}\n'
      + 'data: {"type":"response.completed"}\n';
    const zeroSse = 'data: {"type":"response.completed"}\n';
    let musePrompt = null;
    global.fetch = async (url, opts) => {
      if (String(url).endsWith('/responses')) {
        const c = JSON.parse(opts.body).input[0].content[0].text;
        return { ok: true, text: async () => (c === 'transaction summary' ? boxSse : zeroSse) };
      }
      musePrompt = JSON.parse(opts.body).messages.map((m) => m.content).join('\n');
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    const fakeExtract = async (shot, regions) => ({
      regionTexts: regions.map((r) => ({
        regionId: r.regionId, label: r.label, boundingBox: r.boundingBox,
        genuine: r.genuine, text: 'Send 1.0 ETH to 0xabc', empty: false, ocrError: null
      })),
      combinedText: regions.length > 0 ? '[TRANSACTION SUMMARY]: Send 1.0 ETH to 0xabc' : ''
    });
    const ctl = loadControllerWithOcr(fakeExtract);
    try {
      const res = await runWith(ctl.handleEvaluateTransaction, {
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Swap demo', url: 'https://demo.local/swap' },
        transaction: SWAP_TX,
        visualClaims: []
      });
      assert.strictEqual(res.status, 200);
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 1);
      assert.strictEqual(v.summaryText.status, 'targeted');
      assert.strictEqual(v.summaryText.usedForIntent, true);
      assert.deepStrictEqual(v.summaryText.regionIds, ['R-001']);
      assert.strictEqual(v.summaryText.text, 'Send 1.0 ETH to 0xabc');
      assert.ok(v.intentTextSource.startsWith('transaction-summary'), 'Intent source labeled');
      assert.ok(musePrompt.includes('Intent Text Source: transaction-summary'), 'Reasoner sees the source');
      assert.ok(musePrompt.includes('Send 1.0 ETH to 0xabc'), 'Reasoner receives summary text');
      assert.strictEqual(v.grounding.status, 'not-evaluated', 'Grounding policy untouched');
      assert.ok(v.associations, 'Associations preserved');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 35 Passed: Summary regions feed the labeled intent text.');
  }

  // Test 36 (Phase 3): a zero-detection run with unknown dimensions is
  // 'unavailable' and the intent falls back to the labeled full scan.
  {
    const realFetch = global.fetch;
    const origKey = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    global.fetch = async (url, opts) => {
      if (String(url).endsWith('/responses')) {
        return { ok: true, text: async () => 'data: {"type":"response.completed"}\n' };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"UNCERTAIN","confidence":0.6,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: '!!!not-an-image!!!',
        pageContext: { title: 'Approve Demo', url: 'https://demo.local/approve' },
        transaction: APPROVE_UNLIMITED,
        visualClaims: []
      });
      assert.strictEqual(res.status, 200);
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 0);
      assert.strictEqual(v.fallback.reason, 'unavailable');
      assert.strictEqual(v.fallback.ocr.error.code, 'FALLBACK_NOT_RUN');
      assert.strictEqual(v.summaryText.status, 'no-summary-regions');
      assert.strictEqual(v.summaryText.usedForIntent, false);
      assert.strictEqual(v.intentTextSource, 'full-scan (no isolated summary)');
      assert.ok(v.screenshotError, 'Screenshot metadata failure preserved');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 36 Passed: Unavailable fallback stays honest.');
  }

  // Test 37 (Phase 3): a summary detection whose crop reads blank is
  // 'empty' — no transaction description is invented.
  {
    const realFetch = global.fetch;
    const origKey = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    const boxSse = 'data: {"type":"response.output_text.delta","delta":"<0f>0<|box;x1=0;y1=0;x2=1;y2=1;w=1;h=1|>"}\n'
      + 'data: {"type":"response.completed"}\n';
    const zeroSse = 'data: {"type":"response.completed"}\n';
    global.fetch = async (url, opts) => {
      if (String(url).endsWith('/responses')) {
        const c = JSON.parse(opts.body).input[0].content[0].text;
        return { ok: true, text: async () => (c === 'transaction summary' ? boxSse : zeroSse) };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: '{"verdict":"UNCERTAIN","confidence":0.6,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
      };
    };
    try {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Approve Demo', url: 'https://demo.local/approve' },
        transaction: APPROVE_UNLIMITED,
        visualClaims: []
      });
      assert.strictEqual(res.status, 200);
      const v = res.body.visualEvidence;
      assert.strictEqual(v.detectedCount, 1);
      assert.strictEqual(v.summaryText.status, 'ocr-empty', 'Blank crop yields no invention');
      assert.strictEqual(v.summaryText.text, '');
      assert.strictEqual(v.summaryText.usedForIntent, false);
      assert.strictEqual(v.intentTextSource, 'full-scan (no isolated summary)');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 37 Passed: Empty summary OCR invents nothing.');
  }

  // Test 38 (Phase 3): the evidence bundle preserves the summary
  // selection, the intent source, and all Phase 1–2 structures side by side.
  {
    const bundle = compileEvidenceBundle({
      visualResult: {
        regions: [{ regionId: 'R-1', label: 'transaction summary', boundingBox: { x: 1, y: 2, width: 3, height: 4 }, genuine: true, confidence: null, prompts: ['transaction summary'] }],
        regionTexts: [{ regionId: 'R-1', label: 'transaction summary', boundingBox: { x: 1, y: 2, width: 3, height: 4 }, genuine: true, text: 'Send 1.0 ETH', empty: false, ocrError: null }],
        combinedText: '[TRANSACTION SUMMARY]: Send 1.0 ETH',
        combinedTextSynthetic: false,
        detectedCount: 1,
        visualAvailable: true,
        fallbackUsed: false,
        fallbackReason: null,
        fallbackRegion: null,
        samPartialFailure: false,
        samIncomplete: false,
        samPromptResults: [{ prompt: 'transaction summary', count: 1 }],
        samError: null,
        summaryText: { status: 'targeted', text: 'Send 1.0 ETH', regionIds: ['R-1'], excludedRegionIds: [], ocrErrors: [], usedForIntent: true },
        intentSource: 'transaction-summary (targeted: R-1)',
        screenshot: { width: 1366, height: 632, sha256: 'abc123' },
        screenshotError: null
      },
      decodedTx: { contract: '0x0', contractName: 'C', functionName: 'f', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] },
      reasoningResult: { verdict: 'MATCH', confidence: 0.9 },
      simulationResult: null
    });
    const v = bundle.visualEvidence;
    assert.deepStrictEqual(v.summaryText, { status: 'targeted', text: 'Send 1.0 ETH', regionIds: ['R-1'], excludedRegionIds: [], ocrErrors: [], usedForIntent: true });
    assert.strictEqual(v.intentTextSource, 'transaction-summary (targeted: R-1)');
    assert.strictEqual(v.regions.length, 1, 'Original region preserved');
    assert.deepStrictEqual(v.regions[0].prompts, ['transaction summary'], 'Prompt tags preserved');
    assert.strictEqual(v.regions[0].genuine, true);
    assert.strictEqual(v.regions[0].ocr.text, 'Send 1.0 ETH');
    assert.deepStrictEqual(v.samPromptResults, [{ prompt: 'transaction summary', count: 1 }]);
    assert.strictEqual(v.samPartialFailure, false);
    assert.strictEqual(v.samIncomplete, false);
    assert.strictEqual(v.grounding.status, 'not-evaluated', 'No claims still means not-evaluated');
    assert.ok(v.associations, 'Phase 1 associations present');
    console.log('✔ Test 38 Passed: Bundle preserves summary, source, and Phase 1–2 structures.');
  }

  // Test 39 (Phase C): a confirmed counterparty MISMATCH downgrades a
  // model MATCH to UNCERTAIN and records the trigger in order.
  {
    const res = await evalWithMismatchClaim('MATCH', 0.95);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.verdict, 'UNCERTAIN');
    assert.strictEqual(res.body.confidence, 0.65);
    assert.strictEqual(res.body.confidenceCap, null, 'no visual cap on top of the safeguard cap');
    assert.deepStrictEqual(
      res.body.verdictSafeguards.map((s) => s.trigger),
      // Cap5 B3: the counterparty mismatch also leaves the transfer
      // effect uncovered by any corroborated request (stage 16).
      ['DETERMINISTIC_COMPARISON_MISMATCH', 'UNREQUESTED_TRANSACTION_EFFECT']
    );
    const rec = res.body.verdictSafeguards[0];
    assert.strictEqual(rec.from, 'MATCH');
    assert.strictEqual(rec.to, 'UNCERTAIN');
    assert.ok(rec.reason.includes('counterparty'), 'mismatched field named');
    assert.ok(res.body.summary.includes('deterministic comparison mismatch on counterparty'));
    const ic = res.body.visualEvidence.intentComparison;
    assert.strictEqual(ic.fields.find((f) => f.field === 'counterparty').status, 'MISMATCH');
    assert.strictEqual(res.body.simulation.status, 'NOT_RUN', 'UNCERTAIN without findings does not simulate');
    console.log('✔ Test 39 Passed: Confirmed mismatch blocks unjustified MATCH.');
  }

  // Test 40 (Phase C): a model MISMATCH passes through untouched even when
  // the comparison also conflicts — no downgrade, no added record.
  {
    const res = await evalWithMismatchClaim('MISMATCH', 0.85);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.verdict, 'MISMATCH');
    assert.strictEqual(res.body.confidence, 0.85, 'safe-direction confidence preserved');
    assert.deepStrictEqual(res.body.verdictSafeguards, []);
    assert.strictEqual(res.body.visualEvidence.intentComparison.fields.find((f) => f.field === 'counterparty').status, 'MISMATCH');
    assert.notStrictEqual(res.body.simulation.status, 'NOT_RUN', 'existing MISMATCH gating engaged');
    console.log('✔ Test 40 Passed: Safe-direction verdicts pass through.');
  }

  // Test 41 (Phase C): an INCONCLUSIVE comparison never becomes a
  // mismatch — the heuristic MATCH stands with no new record. Pins
  // mock_eval explicitly: later suite tests restore the real key, and this
  // test must never issue a live call.
  {
    const origKey = config.modelApiKey;
    config.modelApiKey = 'mock_eval';
    try {
      const res = await evaluate({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'MATCH');
      assert.strictEqual(res.body.confidence, 0.88);
      assert.deepStrictEqual(res.body.verdictSafeguards, []);
      const ic = res.body.visualEvidence.intentComparison;
      assert.strictEqual(ic.overall, 'INCONCLUSIVE');
      assert.ok(ic.fields.every((f) => f.status === 'INCONCLUSIVE'));
    } finally {
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 41 Passed: Inconclusive comparison changes nothing.');
  }

  // Test 42 (Phase C): safeguard unit battery — trigger conditions,
  // error tolerance, and ordering with existing stages.
  {
    const baseTx = { functionName: 'transfer', standard: 'ERC20', ruleFindings: [] };
    const mm = {
      status: 'MISMATCH', overall: 'MISMATCH',
      fields: [
        { field: 'counterparty', status: 'MISMATCH', uiValue: '0xaa', txValue: '0xbb', evidenceRefs: ['ocr:R-001'], reason: 'differs' },
        { field: 'action', status: 'INCONCLUSIVE', uiValue: null, txValue: null, evidenceRefs: [], reason: 'none' }
      ]
    };
    const inc = {
      status: 'INCONCLUSIVE', overall: 'INCONCLUSIVE',
      fields: [{ field: 'action', status: 'INCONCLUSIVE', uiValue: null, txValue: null, evidenceRefs: [], reason: 'none' }]
    };
    const errRec = { status: 'ERROR', error: { code: 'COMPARISON_FAILED', message: 'boom' }, fields: [], overall: 'INCONCLUSIVE' };
    const matchOf = (confidence) => ({ verdict: 'MATCH', confidence, summary: 's' });

    for (const [name, comparison] of [['missing', null], ['undefined', undefined], ['ERROR', errRec], ['INCONCLUSIVE', inc]]) {
      const out = applyVerdictSafeguards(baseTx, matchOf(0.9), comparison);
      assert.strictEqual(out.reasoningResult.verdict, 'MATCH', `${name} never triggers`);
      assert.strictEqual(out.reasoningResult.confidence, 0.9);
      assert.deepStrictEqual(out.safeguards, [], `${name} records nothing`);
    }
    const hit = applyVerdictSafeguards(baseTx, matchOf(0.95), mm);
    assert.strictEqual(hit.reasoningResult.verdict, 'UNCERTAIN');
    assert.strictEqual(hit.reasoningResult.confidence, 0.65, 'shared cap reused');
    assert.deepStrictEqual(hit.safeguards.map((s) => s.trigger), ['DETERMINISTIC_COMPARISON_MISMATCH']);
    const passthrough = applyVerdictSafeguards(baseTx, { verdict: 'MISMATCH', confidence: 0.85, summary: 's' }, mm);
    assert.strictEqual(passthrough.reasoningResult.verdict, 'MISMATCH');
    assert.deepStrictEqual(passthrough.safeguards, []);

    // Ordering: existing stages keep their positions; comparison is last.
    const ordered = applyVerdictSafeguards(
      { functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        ruleFindings: [{ ruleId: 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER', metadata: { sender: '0xs', recipient: '0xr' } }] },
      matchOf(0.95), mm
    );
    assert.deepStrictEqual(
      ordered.safeguards.map((s) => s.trigger),
      ['SWAP_RECIPIENT_DIFFERS_FROM_SENDER', 'DETERMINISTIC_COMPARISON_MISMATCH']
    );
    // Invalid verdicts coerce first, so later stages stay idle.
    const invalid = applyVerdictSafeguards(baseTx, { verdict: 'deceptive', confidence: 0.99, summary: 's' }, mm);
    assert.deepStrictEqual(invalid.safeguards.map((s) => s.trigger), ['INVALID_VERDICT']);
    console.log('✔ Test 42 Passed: Safeguard trigger matrix exact.');
  }

  // Test 43 (Phase C): unknown-selector safeguard intact with comparison
  // attached — original trigger only, no comparison record.
  {
    const realFetch = global.fetch;
    const origKey = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
    });
    try {
      const res = await evaluate({
        pageContext: { title: 'Mystery dApp', url: 'https://mystery.local/' },
        transaction: { from: PC_FROM, to: PC_OTHER, data: '0xdeadbeef', value: '0x0' }
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'UNCERTAIN');
      assert.deepStrictEqual(res.body.verdictSafeguards.map((s) => s.trigger), ['UNKNOWN_FUNCTION']);
      assert.strictEqual(res.body.visualEvidence.intentComparison.overall, 'INCONCLUSIVE');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 43 Passed: Unknown-selector safeguard intact.');
  }

  // Test 44 (Phase C): an invalid model verdict coerces first end to end,
  // even with a comparison MISMATCH present — single INVALID_VERDICT record.
  {
    const res = await evalWithMismatchClaim('deceptive', 0.99);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.verdict, 'UNCERTAIN');
    assert.deepStrictEqual(res.body.verdictSafeguards.map((s) => s.trigger), ['INVALID_VERDICT']);
    assert.strictEqual(res.body.visualEvidence.intentComparison.fields.find((f) => f.field === 'counterparty').status, 'MISMATCH');
    console.log('✔ Test 44 Passed: Invalid verdict coerces first end to end.');
  }

  // Test 45 (Component 1): non-string screenshot input is handled honestly
  // end-to-end — no hash/dimensions invented, a coded BAD_IMAGE
  // screenshotError, zero detections, no fallback-scan fabrication. Pins
  // mock_eval (T41 idiom): this test must never issue a live call.
  {
    const origKey = config.modelApiKey;
    config.modelApiKey = 'mock_eval';
    try {
      const res = await evaluate({ screenshot: 12345, transaction: SWAP_TX });
      assert.strictEqual(res.status, 200);
      const v = res.body.visualEvidence;
      assert.strictEqual(v.screenshot, null, 'no identity without bytes');
      assert.strictEqual(v.screenshotError && v.screenshotError.code, 'BAD_IMAGE');
      assert.strictEqual(v.detectedCount, 0);
      assert.strictEqual(v.visualAvailable, false);
      assert.strictEqual(v.ocrMode, 'none');
      assert.strictEqual(v.fallback, null, 'mock SAM reports no fallback to run');
      assert.deepStrictEqual(v.regions, [], 'no regions from an unreadable image');
      assert.ok(['MATCH', 'MISMATCH', 'UNCERTAIN'].includes(res.body.verdict), 'valid verdict enum');
    } finally {
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 45 Passed: Non-string screenshot honestly recorded.');
  }

  // Test 46 (Component 4): non-string transaction addresses/calldata are
  // client errors (400), never internal 500s.
  {
    const badTo = await evaluate({ transaction: { to: 12345, data: '0x', value: '0x0' } });
    assert.strictEqual(badTo.status, 400);
    assert.ok(badTo.body.error.includes('"to"'), 'Field named in the error');
    const badData = await evaluate({
      transaction: { to: '0xdAC17F958D2ee523a2206206994597C13D831ec7', data: 12345, value: '0x0' }
    });
    assert.strictEqual(badData.status, 400);
    assert.ok(badData.body.error.includes('"data"'), 'Field named in the error');
    console.log('✔ Test 46 Passed: Non-string to/data yield 400s.');
  }

  // Test 47 (Targeted): ambiguous approve(max) end to end. The bundle
  // exposes the ambiguity explicitly, the alert stays medium-severity, and
  // the deterministic comparison does not confirm the uncertain amount.
  // Pins mock_eval (T41 idiom): this test must never issue a live call.
  {
    const origKey = config.modelApiKey;
    config.modelApiKey = 'mock_eval';
    try {
      const res = await evaluate({
        pageContext: { title: 'Approve Demo', url: 'https://demo.local/approve' },
        transaction: {
          from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
          to: '0x1234567890123456789012345678901234567890',
          data: '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          value: '0x0'
        }
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'UNCERTAIN');
      const dt = res.body.decodedTransaction;
      assert.strictEqual(dt.functionName, 'approve');
      assert.strictEqual(dt.standard, 'ERC20');
      assert.strictEqual(dt.standardAmbiguous, true);
      assert.deepStrictEqual(dt.standardCandidates, ['ERC20', 'ERC721']);
      assert.strictEqual(dt.isUnlimitedApproval, false);
      const rules = res.body.ruleFindings.map((r) => r.ruleId);
      assert.ok(rules.includes('AMBIGUOUS_APPROVAL_SCOPE'), 'Ambiguous alert in bundle');
      assert.ok(!rules.includes('INFINITE_APPROVAL'), 'No confirmed-unlimited claim');
      const ic = res.body.visualEvidence.intentComparison;
      assert.strictEqual(ic.fields.find((f) => f.field === 'tokenAmount').status, 'INCONCLUSIVE',
        'Uncertain amount never confirmed by comparison');
      assert.strictEqual(ic.overall, 'INCONCLUSIVE');
      assert.deepStrictEqual(res.body.verdictSafeguards, [], 'No spurious safeguards');
    } finally {
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 47 Passed: Ambiguous approve stays honest end to end.');
  }

  // Test 48 (validation fix): a valid model confidence of 0 survives the
  // whole pipeline exactly (the bundle must not falsy-default it to 0.5).
  {
    const origKey = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
    });
    try {
      const res = await evaluate({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: SWAP_TX
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'MATCH');
      assert.strictEqual(res.body.confidence, 0, 'Validated zero confidence preserved exactly');
      assert.strictEqual(res.body.reasoningOrigin, 'model');
      assert.deepStrictEqual(res.body.verdictSafeguards, []);
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 48 Passed: Model confidence 0 preserved end to end.');
  }

  // Test 49 (validation fix): an out-of-range model confidence falls back
  // end to end — heuristic provenance, heuristic verdict, no timeout flag.
  {
    const origKey = config.modelApiKey;
    const realFetch = global.fetch;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":2,"summary":"s","discrepancyDetails":{},"recommendedAction":"PROCEED_WITH_CAUTION"}' } }] })
    });
    try {
      const res = await evaluate({
        pageContext: { title: 'Governance Proposal #42', url: 'https://demo.local/gov' },
        transaction: { to: '0x1234567890123456789012345678901234567890', data: '0xdeadbeef', value: '0x0' }
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.reasoningOrigin, 'heuristic-fallback', 'Invalid output never labeled model');
      assert.strictEqual(res.body.reasoningTimedOut, false, 'Rejection is not a timeout');
      assert.strictEqual(res.body.verdict, 'UNCERTAIN', 'Heuristic verdict for unknown function');
      assert.strictEqual(res.body.confidence, 0.70, 'Heuristic value, never the rejected 2');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 49 Passed: Invalid model confidence falls back end to end.');
  }

  console.log('\nAll Evaluate Pipeline Tests Passed Successfully!\n');
}

if (require.main === module) {
  runEvaluateTests()
    .then(() => closeOcrWorker())
    .catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runEvaluateTests };
