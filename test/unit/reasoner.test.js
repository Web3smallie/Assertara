const assert = require('assert');
const config = require('../../src/config/env');
const { evaluateSemanticDiscrepancy, fallbackHeuristicReasoner, validateModelResult } = require('../../src/services/reasonerService');

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
      json: async () => ({ choices: [{ message: { content: '{"verdict":"MISMATCH","confidence":0.9,"summary":"s","discrepancyDetails":{},"recommendedAction":"BLOCK_TRANSACTION"}' } }] })
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

  // Test 5: prompt carries structured per-region visual evidence + zero warning.
  {
    const restoreKey = useLiveKey();
    let captured;
    global.fetch = async (url, options) => {
      captured = JSON.parse(options.body);
      return { ok: true, json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH"}' } }] }) };
    };
    try {
      await evaluateSemanticDiscrepancy('[BUTTON]: Hi', SWAP_PAGE, SWAP_TX, {
        detectedCount: 2,
        visualAvailable: true,
        regionTexts: [
          { regionId: 'R-001', label: 'button', boundingBox: { x: 1, y: 2, width: 3, height: 4 }, text: 'Hi', ocrError: null },
          { regionId: 'R-002', label: 'button', boundingBox: { x: 5, y: 6, width: 7, height: 8 }, text: null, ocrError: { code: 'BAD_BOX', message: 'bad' } }
        ],
        fallbackRecords: []
      });
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    const userContent = captured.messages.find((m) => m.role === 'user').content;
    assert.ok(userContent.includes('Genuine SAM detections: 2'), 'Prompt states the genuine count');
    assert.ok(userContent.includes('[R-001]'), 'Prompt carries region ids');
    assert.ok(userContent.includes('"Hi"'), 'Prompt carries region text');
    assert.ok(userContent.includes('OCR FAILED [BAD_BOX]'), 'Prompt marks failed reads as unknown');
    console.log('✔ Test 5 Passed: Structured region evidence reaches the prompt.');
  }

  // Test 6: malformed model output falls back honestly (never throws, never trusts).
  {
    const restoreKey = useLiveKey();
    global.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: 'not json {{{' } }] })
    });
    try {
      const result = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
      assert.strictEqual(result.origin, 'heuristic-fallback', 'Malformed output must fall back');
      assert.strictEqual(result.verdict, 'MATCH', 'Swap heuristic still applies after fallback');
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    console.log('✔ Test 6 Passed: Malformed model output falls back honestly.');
  }

  // Test 7 (Phase 5A): the model prompt receives the exact fractional value.
  {
    const restoreKey = useLiveKey();
    let captured;
    global.fetch = async (url, options) => {
      captured = JSON.parse(options.body);
      return { ok: true, json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH"}' } }] }) };
    };
    try {
      await evaluateSemanticDiscrepancy('', SWAP_PAGE, { ...SWAP_TX, valueEth: '0.5', valueWei: '500000000000000000' });
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    const userContent = captured.messages.find((m) => m.role === 'user').content;
    assert.ok(userContent.includes('Transaction Value (ETH): 0.5'), 'Prompt must carry the exact fractional ETH value');
    console.log('✔ Test 7 Passed: Exact fractional value reaches the reasoner prompt.');
  }

  // Test 8 (Fix 3): a stalled request aborts, classifies as a timeout,
  // and falls back to the deterministic heuristic without fabrication.
  {
    const restoreKey = useLiveKey();
    const origMs = config.museTimeoutMs;
    config.museTimeoutMs = 50;
    global.fetch = async (url, opts) => new Promise((_, reject) => {
      const signal = opts.signal;
      if (!signal || typeof signal.addEventListener !== 'function') {
        reject(new Error('test mock requires an AbortSignal'));
        return;
      }
      signal.addEventListener('abort', () => {
        const e = new Error('The operation was aborted');
        e.name = 'AbortError';
        reject(e);
      }, { once: true });
    });
    try {
      const t0 = Date.now();
      const result = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
      assert.ok(Date.now() - t0 < 5000, 'bounded call must not hang');
      assert.strictEqual(result.timeout, true, 'Timeout classified on the result');
      assert.strictEqual(result.origin, 'heuristic-fallback', 'Fallback origin preserved');
      assert.strictEqual(result.verdict, 'MATCH', 'Swap heuristic applies after timeout');
    } finally {
      global.fetch = realFetch;
      restoreKey();
      config.museTimeoutMs = origMs;
    }
    console.log('✔ Test 8 Passed: Stalled reasoning aborts into the honest fallback.');
  }

  // Test 9 (config fix): the configured timeout value drives the Muse
  // bound, surfaced in the timeout warning.
  {
    const restoreKey = useLiveKey();
    const origMs = config.museTimeoutMs;
    config.museTimeoutMs = 45;
    const origWarn = console.warn;
    const warned = [];
    console.warn = (msg) => { warned.push(String(msg)); };
    global.fetch = async (url, opts) => new Promise((_, reject) => {
      opts.signal.addEventListener('abort', () => {
        const e = new Error('The operation was aborted');
        e.name = 'AbortError';
        reject(e);
      }, { once: true });
    });
    try {
      const result = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
      assert.strictEqual(result.timeout, true);
      assert.ok(
        warned.some((m) => m.includes('[Muse Spark Timeout]') && m.includes('45ms')),
        'Configured value reaches the service'
      );
    } finally {
      global.fetch = realFetch;
      console.warn = origWarn;
      restoreKey();
      config.museTimeoutMs = origMs;
    }
    console.log('✔ Test 9 Passed: Configured Muse timeout drives the bound.');
  }

  // Test 10 (Phase 2): the model prompt carries the visual-claims schema
  // and the cite-only-printed-IDs rule.
  {
    const restoreKey = useLiveKey();
    let captured;
    global.fetch = async (url, options) => {
      captured = JSON.parse(options.body);
      return { ok: true, json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH"}' } }] }) };
    };
    try {
      await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    const systemContent = captured.messages.find((m) => m.role === 'system').content;
    assert.ok(systemContent.includes('visualClaims'), 'Prompt defines the claims schema');
    assert.ok(systemContent.includes('ONLY the [R-xxx] IDs'), 'Prompt pins citation to printed IDs');
    assert.ok(systemContent.includes('NEVER invent region IDs'), 'Prompt forbids invention');
    console.log('✔ Test 10 Passed: Claims schema and citation rules reach the prompt.');
  }

  // Test 11 (Phase 3): the user prompt states which OCR view — the isolated
  // summary or the full scan — the intent text came from.
  {
    const restoreKey = useLiveKey();
    const seen = [];
    global.fetch = async (url, options) => {
      seen.push(JSON.parse(options.body));
      return { ok: true, json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH"}' } }] }) };
    };
    try {
      await evaluateSemanticDiscrepancy('Send 1.0 ETH', SWAP_PAGE, SWAP_TX, {
        intentSource: 'transaction-summary (targeted: R-1)'
      });
      await evaluateSemanticDiscrepancy('Send 1.0 ETH', SWAP_PAGE, SWAP_TX, {});
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    const targeted = seen[0].messages.find((m) => m.role === 'user').content;
    assert.ok(
      targeted.includes('Intent Text Source: transaction-summary (targeted: R-1)'),
      'Summary path labeled in the prompt'
    );
    const unlabeled = seen[1].messages.find((m) => m.role === 'user').content;
    assert.ok(
      unlabeled.includes('Intent Text Source: full-scan (unspecified by caller)'),
      'Missing source degrades to an explicit full-scan label'
    );
    console.log('✔ Test 11 Passed: Intent source reaches the model prompt.');
  }

  // Test 12 (validation fix): boundary confidence values pass through as
  // genuine model results with values and provenance intact.
  {
    const restoreKey = useLiveKey();
    try {
      for (const confidence of [0, 1, 0.73]) {
        global.fetch = async () => ({
          ok: true,
          json: async () => ({ choices: [{ message: { content: JSON.stringify({
            verdict: 'MISMATCH', confidence, summary: 's', discrepancyDetails: {}, recommendedAction: 'BLOCK_TRANSACTION'
          }) } }] })
        });
        const result = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
        assert.strictEqual(result.origin, 'model', `confidence ${confidence} stays a model result`);
        assert.strictEqual(result.confidence, confidence, `confidence ${confidence} preserved exactly`);
        assert.strictEqual(result.verdict, 'MISMATCH');
        assert.strictEqual(result.timeout, undefined, 'No timeout flag on valid output');
      }
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    console.log('✔ Test 12 Passed: Confidence 0, 1, and mid-range pass through intact.');
  }

  // Test 13 (validation fix): invalid confidence never enters the model
  // path — rejected output falls back with fallback provenance, never a
  // timeout flag, and values are never clamped into range.
  {
    const restoreKey = useLiveKey();
    const bad = [
      ['negative', -0.5], ['above one', 1.5], ['missing', undefined],
      ['string', '0.9'], ['null', null], ['boolean', true]
    ];
    try {
      for (const [label, confidence] of bad) {
        const payload = { verdict: 'MISMATCH', summary: 's', discrepancyDetails: {}, recommendedAction: 'BLOCK_TRANSACTION' };
        if (confidence !== undefined) payload.confidence = confidence;
        global.fetch = async () => ({
          ok: true,
          json: async () => ({ choices: [{ message: { content: JSON.stringify(payload) } }] })
        });
        const result = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
        assert.strictEqual(result.origin, 'heuristic-fallback', `${label} confidence must fall back`);
        assert.strictEqual(result.timeout, undefined, `${label}: rejection is not a timeout`);
        assert.strictEqual(result.verdict, 'MATCH', `${label}: swap heuristic applies after rejection`);
      }
      // NaN/Infinity cannot arise from JSON parsing; the validator rejects
      // them directly so no future transport can smuggle them in.
      for (const v of [NaN, Infinity, -Infinity]) {
        assert.strictEqual(validateModelResult({
          verdict: 'MISMATCH', confidence: v, summary: 's', discrepancyDetails: {}, recommendedAction: 'x'
        }).ok, false, `confidence ${String(v)} rejected`);
      }
      assert.strictEqual(validateModelResult({
        verdict: 'MISMATCH', confidence: 0, summary: 's', discrepancyDetails: {}, recommendedAction: 'x'
      }).ok, true, 'confidence 0 valid at the validator');
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    console.log('✔ Test 13 Passed: Bad confidence rejected, never clamped or trusted.');
  }

  // Test 14 (validation fix): malformed shapes fall back; verdict
  // *vocabulary* stays owned by downstream INVALID_VERDICT coercion.
  {
    const restoreKey = useLiveKey();
    const good = { verdict: 'MISMATCH', confidence: 0.9, summary: 's', discrepancyDetails: {}, recommendedAction: 'BLOCK_TRANSACTION' };
    const badShapes = [
      ['missing verdict', { ...good, verdict: undefined }],
      ['numeric verdict', { ...good, verdict: 42 }],
      ['empty verdict', { ...good, verdict: '' }],
      ['missing summary', { ...good, summary: undefined }],
      ['null details', { ...good, discrepancyDetails: null }],
      ['array details', { ...good, discrepancyDetails: [] }],
      ['missing action', { ...good, recommendedAction: undefined }],
      ['object claims', { ...good, visualClaims: { type: 'x' } }],
      ['top-level string', 'just a string'],
      ['top-level array', [1, 2]],
      ['top-level number', 7]
    ];
    try {
      for (const [label, payload] of badShapes) {
        global.fetch = async () => ({
          ok: true,
          json: async () => ({ choices: [{ message: { content: JSON.stringify(payload) } }] })
        });
        const result = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
        assert.strictEqual(result.origin, 'heuristic-fallback', `${label} must fall back`);
        assert.strictEqual(result.timeout, undefined, `${label}: rejection is not a timeout`);
      }
      // Null/missing content rejects without throwing.
      global.fetch = async () => ({ ok: true, json: async () => ({ choices: [{}] }) });
      assert.strictEqual((await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX)).origin, 'heuristic-fallback');
      // Unknown verdict STRINGS pass the boundary by design: the
      // controller coerces them explicitly with an INVALID_VERDICT record
      // (recipientRule T8, evaluate T42/T44) — never silently.
      global.fetch = async () => ({
        ok: true,
        json: async () => ({ choices: [{ message: { content: JSON.stringify({ ...good, verdict: 'deceptive' }) } }] })
      });
      const vocab = await evaluateSemanticDiscrepancy('', SWAP_PAGE, SWAP_TX);
      assert.strictEqual(vocab.origin, 'model', 'String verdicts reach downstream coercion as model output');
      assert.strictEqual(vocab.verdict, 'deceptive');
    } finally {
      global.fetch = realFetch;
      restoreKey();
    }
    console.log('✔ Test 14 Passed: Malformed shapes fall back; vocabulary stays downstream.');
  }

  console.log('\nAll Reasoner Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runReasonerTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runReasonerTests };
