// Phase B: intent-comparison adapter + evidence-bundle integration.
// Proves the trust boundary survives wiring and that verdict behavior is
// byte-identical with the comparison attached.
const assert = require('assert');
const config = require('../../src/config/env');
const { compileEvidenceBundle } = require('../../src/services/evidenceService');
const {
  buildIntentComparison,
  projectClaim,
  resolveStaticTokenMeta
} = require('../../src/services/intentComparisonAdapter');

const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const ALICE = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const OTHER = '0x1111111254fb6c44bac0bed2854e76f90643097d';
const DUMMY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

const BOX = { x: 0, y: 0, width: 10, height: 10 };

function regionEntry(regionId, text, opts = {}) {
  return {
    regionId,
    label: opts.label || 'button',
    boundingBox: BOX,
    confidence: null,
    genuine: true,
    ocr: opts.error
      ? { text: null, empty: false, error: opts.error }
      : { text, empty: text.length === 0, error: null }
  };
}

// Validated grounding-record shape (validator-attached `observed` included:
// the adapter must strip it before the utility ever sees the claim).
function gclaim(type, value, regionIds, opts = {}) {
  return {
    index: opts.index || 0,
    type,
    value,
    regionIds,
    associationIds: opts.associationIds || [],
    observed: opts.observed || [{ regionId: regionIds[0], available: true, genuine: true, text: 'validator-attached', boundingBox: BOX }],
    relatedLinks: [],
    status: opts.status || 'supported',
    reasons: []
  };
}

function link(linkId, kind, method, members) {
  return { linkId, kind, method, members: members.map(([regionId, role]) => ({ regionId, role })) };
}

function fieldOf(comparison, field) {
  return comparison.fields.find((f) => f.field === field);
}

function bundleFor({ regions, regionTexts, claims, decodedTx, sender, visualClaims }) {
  return compileEvidenceBundle({
    visualResult: {
      regions: regions || [],
      regionTexts: regionTexts || [],
      combinedText: '',
      combinedTextSynthetic: false,
      detectedCount: (regions || []).length,
      visualAvailable: (regions || []).length > 0,
      fallbackUsed: false,
      fallbackReason: null,
      screenshot: null,
      screenshotError: null
    },
    decodedTx,
    reasoningResult: { verdict: 'UNCERTAIN', confidence: 0.5, summary: 'probe', visualClaims },
    simulationResult: null,
    pageContext: {},
    screenshotProvided: true,
    sender
  });
}

async function runComparisonIntegrationTests() {
  console.log('\n=== Running Intent Comparison Integration Tests ===');

  // Test 1: projection strips `observed` and every non-approved field; the
  // comparison still succeeds, proving the utility never saw them.
  {
    const projected = projectClaim({
      index: 3, type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [],
      observed: [{ text: 'forged?' }], relatedLinks: ['L-001'], status: 'supported',
      reasons: [], boundingBox: BOX, extra: true
    });
    assert.deepStrictEqual(projected, {
      type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [], status: 'supported'
    });
    // End-to-end: a claim carrying validator `observed` still yields MATCH,
    // which is only possible if the adapter stripped it (the utility
    // rejects any claim carrying `observed`).
    const bundle = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'Pay 1.0 ETH', empty: false, ocrError: null }],
      decodedTx: { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000', ruleFindings: [] },
      visualClaims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] }]
    });
    const ic = bundle.visualEvidence.intentComparison;
    assert.strictEqual(fieldOf(ic, 'nativeValue').status, 'MATCH');
  }
  console.log('✔ Test 1 Passed: Projection strips non-approved fields.');

  // Test 2: genuine successful OCR regions flow through to comparison.
  {
    const bundle = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'Pay 1.0 ETH', empty: false, ocrError: null }],
      decodedTx: { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000', ruleFindings: [] },
      visualClaims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] }]
    });
    assert.strictEqual(bundle.visualEvidence.regions[0].ocr.text, 'Pay 1.0 ETH');
    assert.strictEqual(bundle.visualEvidence.regions[0].genuine, true);
    assert.strictEqual(fieldOf(bundle.visualEvidence.intentComparison, 'nativeValue').status, 'MATCH');
  }
  console.log('✔ Test 2 Passed: Genuine OCR preserved.');

  // Test 3: failed OCR stays distinct from empty OCR; neither compares.
  {
    const failed = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: null, empty: false, ocrError: { code: 'OCR_FAILED', message: 'boom' } }],
      decodedTx: { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000', ruleFindings: [] },
      visualClaims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] }]
    });
    assert.ok(failed.visualEvidence.regions[0].ocr.error, 'failure preserved in bundle');
    assert.strictEqual(fieldOf(failed.visualEvidence.intentComparison, 'nativeValue').status, 'INCONCLUSIVE');
    const empty = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: '', empty: true, ocrError: null }],
      decodedTx: { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000', ruleFindings: [] },
      visualClaims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] }]
    });
    assert.strictEqual(empty.visualEvidence.regions[0].ocr.empty, true);
    assert.strictEqual(empty.visualEvidence.regions[0].ocr.error, null);
    assert.strictEqual(fieldOf(empty.visualEvidence.intentComparison, 'nativeValue').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 3 Passed: Failed vs empty OCR distinct.');

  // Test 4: synthetic fallback text can never create a trusted match.
  {
    const bundle = compileEvidenceBundle({
      visualResult: {
        regions: [], regionTexts: [], combinedText: 'Send 1.0 ETH', combinedTextSynthetic: true,
        detectedCount: 0, visualAvailable: false, fallbackUsed: true, fallbackReason: 'zero-detections',
        fallbackRegion: { boundingBox: { x: 0, y: 0, width: 1, height: 1 } },
        fallbackRecords: [{ regionId: 'R-FALLBACK', label: 'fallback scan (synthetic)', boundingBox: BOX, genuine: false, synthetic: true, text: 'Send 1.0 ETH', empty: false, ocrError: null }],
        screenshot: null, screenshotError: null
      },
      decodedTx: { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000', ruleFindings: [] },
      reasoningResult: {
        verdict: 'UNCERTAIN', confidence: 0.5, summary: 'probe',
        visualClaims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-FALLBACK'], associationIds: [] }]
      },
      simulationResult: null,
      pageContext: {},
      screenshotProvided: true
    });
    const ic = bundle.visualEvidence.intentComparison;
    assert.ok(ic.fields.every((f) => f.status === 'INCONCLUSIVE'), 'no field compares on synthetic evidence');
    assert.strictEqual(ic.overall, 'INCONCLUSIVE');
    assert.strictEqual(bundle.visualEvidence.grounding.claims[0].status, 'invalid', 'fallback citation invalid at grounding');
  }
  console.log('✔ Test 4 Passed: Synthetic fallback unmatchable.');

  // Tests 5-6: sender provenance — validated vs missing/invalid.
  {
    const base = {
      regions: [], regionTexts: [],
      decodedTx: { contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6, parameters: {}, valueWei: '0', ruleFindings: [] },
      visualClaims: []
    };
    const valid = bundleFor({ ...base, sender: ALICE });
    assert.strictEqual(valid.visualEvidence.intentComparison.provenance.senderSource, 'request.from-validated');
    for (const bad of [null, undefined, '', 'not-an-address', '0x1234']) {
      const res = bundleFor({ ...base, sender: bad });
      assert.strictEqual(res.visualEvidence.intentComparison.provenance.senderSource, 'unavailable', String(bad));
      assert.ok(res.visualEvidence.intentComparison.limitations.some((l) => l.includes('sender')));
    }
  }
  console.log('✔ Test 5-6 Passed: Sender provenance honest.');

  // Tests 7-8: trusted static metadata vs unknown tokens.
  {
    const known = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'Send 1.0 USDC', empty: false, ocrError: null }],
      decodedTx: {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0', ruleFindings: []
      },
      visualClaims: [{ type: 'amount', value: '1.0 USDC', regionIds: ['R-001'], associationIds: [] }]
    });
    assert.strictEqual(known.visualEvidence.intentComparison.provenance.tokenMetaSource, 'static-known-tokens');
    assert.strictEqual(fieldOf(known.visualEvidence.intentComparison, 'tokenAmount').status, 'MATCH');
    const unknown = bundleFor({
      regions: [], regionTexts: [],
      decodedTx: {
        contract: OTHER, functionName: 'transfer', standard: 'ERC20', symbol: null, decimals: null,
        parameters: { recipient: SPENDER, amount: '100' }, valueWei: '0', ruleFindings: []
      },
      visualClaims: []
    });
    assert.strictEqual(unknown.visualEvidence.intentComparison.provenance.tokenMetaSource, 'unavailable');
    assert.strictEqual(fieldOf(unknown.visualEvidence.intentComparison, 'tokenAmount').status, 'INCONCLUSIVE');
    assert.deepStrictEqual(resolveStaticTokenMeta(OTHER), null, 'unknown address resolves to nothing');
    assert.deepStrictEqual(resolveStaticTokenMeta(USDC), { symbol: 'USDC', decimals: 6 });
    assert.deepStrictEqual(resolveStaticTokenMeta('garbage'), null);
  }
  console.log('✔ Test 7-8 Passed: Token metadata provenance honest.');

  // Test 9: swap-leg metadata resolves by token address from the static list.
  {
    const bundle = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'You pay 1.0 ETH', empty: false, ocrError: null }],
      decodedTx: {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        symbol: null, decimals: null, valueWei: '1000000000000000000',
        parameters: { tokenIn: WETH, tokenOut: USDC, recipient: SPENDER, amountIn: '1000000000000000000', amountOutMinimum: '1' },
        ruleFindings: []
      },
      visualClaims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] }]
    });
    const ic = bundle.visualEvidence.intentComparison;
    assert.strictEqual(ic.provenance.tokenMetaSource, 'static-known-tokens');
    assert.strictEqual(fieldOf(ic, 'tokenAmount').status, 'MATCH', 'WETH leg resolved by address');
    assert.ok(!ic.limitations.some((l) => l.includes('input-leg')), 'no missing-meta limitation');
    const unknownLeg = bundleFor({
      regions: [], regionTexts: [],
      decodedTx: {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        symbol: null, decimals: null, valueWei: '0',
        parameters: { tokenIn: OTHER, tokenOut: USDC }, ruleFindings: []
      },
      visualClaims: []
    });
    assert.ok(unknownLeg.visualEvidence.intentComparison.limitations.some((l) => l.includes('input-leg')));
  }
  console.log('✔ Test 9 Passed: Swap legs resolve by address.');

  // Test 10: missing decoder fields stay inconclusive without throwing.
  {
    const bundle = bundleFor({
      regions: [], regionTexts: [],
      decodedTx: {},
      visualClaims: []
    });
    const ic = bundle.visualEvidence.intentComparison;
    assert.ok(ic.fields.every((f) => f.status === 'INCONCLUSIVE'));
    assert.strictEqual(ic.status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 10 Passed: Missing decoder fields safe.');

  // Test 11: uncorroborated and invalid claims yield no trusted facts.
  {
    const bundle = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'Confirm swap', empty: false, ocrError: null }],
      decodedTx: { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000', ruleFindings: [] },
      visualClaims: [
        { type: 'amount', value: '99.0 ETH', regionIds: ['R-001'], associationIds: [] },
        { type: 'amount', value: '1.0 ETH', regionIds: ['R-999'], associationIds: [] }
      ]
    });
    const ic = bundle.visualEvidence.intentComparison;
    assert.strictEqual(fieldOf(ic, 'nativeValue').status, 'INCONCLUSIVE');
    assert.strictEqual(bundle.visualEvidence.grounding.claims[1].status, 'invalid', 'unknown region rejected at grounding');
  }
  console.log('✔ Test 11 Passed: Bad claims untrusted.');

  // Test 12: fee and payment in the same dialog — the real association
  // path attributes the payment only; the fee cannot compare.
  {
    const bundle = bundleFor({
      regions: [
        { regionId: 'R-001', label: 'dialog box', boundingBox: BOX, genuine: true },
        { regionId: 'R-002', label: 'dialog box', boundingBox: { x: 20, y: 20, width: 10, height: 10 }, genuine: true }
      ],
      regionTexts: [
        { regionId: 'R-001', label: 'dialog box', boundingBox: BOX, genuine: true, text: 'Pay 1.0 ETH', empty: false, ocrError: null },
        { regionId: 'R-002', label: 'dialog box', boundingBox: { x: 20, y: 20, width: 10, height: 10 }, genuine: true, text: 'Network fee 0.01 ETH', empty: false, ocrError: null }
      ],
      decodedTx: { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000', ruleFindings: [] },
      visualClaims: [
        { type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] },
        { type: 'amount', value: '0.01 ETH', regionIds: ['R-002'], associationIds: [] }
      ]
    });
    const f = fieldOf(bundle.visualEvidence.intentComparison, 'nativeValue');
    assert.strictEqual(f.status, 'MATCH');
    assert.strictEqual(f.uiValue, '1.0 ETH', 'fee value cannot win');
    assert.ok(!f.evidenceRefs.includes('ocr:R-002'), 'fee region never cited');
  }
  console.log('✔ Test 12 Passed: Fee/payment dialog safe.');

  // Test 13: generic Approve wording end-to-end stays inconclusive.
  {
    const bundle = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'Approve', empty: false, ocrError: null }],
      decodedTx: { contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6, parameters: {}, valueWei: '0', ruleFindings: [] },
      visualClaims: [{ type: 'action', value: 'Approve', regionIds: ['R-001'], associationIds: [] }]
    });
    assert.strictEqual(bundle.visualEvidence.grounding.claims[0].status, 'supported');
    assert.strictEqual(fieldOf(bundle.visualEvidence.intentComparison, 'action').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 13 Passed: Generic Approve inconclusive.');

  // Test 14: unknown selectors and partial parameters stay conservative.
  {
    const unknown = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'Swap tokens', empty: false, ocrError: null }],
      decodedTx: { contract: OTHER, functionName: 'unknownFunction', standard: 'Unknown', parameters: { selector: '0xdeadbeef' }, valueWei: '0', ruleFindings: [] },
      visualClaims: [{ type: 'action', value: 'Swap', regionIds: ['R-001'], associationIds: [] }]
    });
    assert.strictEqual(fieldOf(unknown.visualEvidence.intentComparison, 'action').status, 'INCONCLUSIVE');
    const partial = bundleFor({
      regions: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true }],
      regionTexts: [{ regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'You pay 1.0 ETH', empty: false, ocrError: null }],
      decodedTx: {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        symbol: null, decimals: null, valueWei: '0',
        parameters: { tokenIn: WETH, tokenOut: USDC }, ruleFindings: []
      },
      visualClaims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] }]
    });
    assert.strictEqual(fieldOf(partial.visualEvidence.intentComparison, 'tokenAmount').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 14 Passed: Unknown/partial conservative.');

  // Test 15: every evidence reference resolves to real bundle evidence.
  {
    const bundle = bundleFor({
      regions: [
        { regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true },
        { regionId: 'R-002', label: 'dialog box', boundingBox: { x: 20, y: 20, width: 10, height: 10 }, genuine: true }
      ],
      regionTexts: [
        { regionId: 'R-001', label: 'button', boundingBox: BOX, genuine: true, text: 'Pay 1.0 ETH', empty: false, ocrError: null },
        { regionId: 'R-002', label: 'dialog box', boundingBox: { x: 20, y: 20, width: 10, height: 10 }, genuine: true, text: `To ${SPENDER}`, empty: false, ocrError: null }
      ],
      decodedTx: {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0', ruleFindings: []
      },
      visualClaims: [
        { type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] },
        { type: 'recipient', value: SPENDER, regionIds: ['R-002'], associationIds: [] }
      ]
    });
    const regionIds = new Set(bundle.visualEvidence.regions.map((r) => r.regionId));
    const txPaths = new Set(['valueWei', 'symbol', 'functionName', 'functionName(native-ETH)', 'contract',
      'parameters.spender', 'parameters.recipient', 'parameters.operator', 'parameters.amount', 'parameters.amountIn']);
    for (const f of bundle.visualEvidence.intentComparison.fields) {
      for (const ref of f.evidenceRefs) {
        if (ref.startsWith('ocr:')) assert.ok(regionIds.has(ref.slice(4)), `${ref} resolves in bundle regions`);
        else if (ref.startsWith('tx:')) assert.ok(txPaths.has(ref.slice(3)), `${ref} is a known decoded path`);
        else if (ref.startsWith('claim#')) {
          const n = Number(ref.slice(6));
          assert.ok(Number.isInteger(n) && n < 2, `${ref} indexes the input claims`);
        } else assert.fail(`unknown ref shape ${ref}`);
      }
    }
  }
  console.log('✔ Test 15 Passed: Evidence refs traceable.');

  // Test 16: adapter failures become an explicit ERROR record, never throw.
  {
    const evil = {};
    Object.defineProperty(evil, 'regionEntries', { enumerable: true, get() { throw new Error('poisoned evidence'); } });
    const res = buildIntentComparison(evil);
    assert.strictEqual(res.status, 'ERROR');
    assert.strictEqual(res.error.code, 'COMPARISON_FAILED');
    assert.ok(res.error.message.includes('poisoned evidence'));
    assert.strictEqual(res.overall, 'INCONCLUSIVE');
    assert.deepStrictEqual(res.fields, []);
    const empty = buildIntentComparison(null);
    assert.strictEqual(empty.status, 'INCONCLUSIVE', 'null evidence degrades, never errors');
    assert.ok(empty.fields.every((f) => f.status === 'INCONCLUSIVE'));
  }
  console.log('✔ Test 16 Passed: Failures explicit and safe.');

  // Tests 17-22: full-pipeline regression — verdict, confidence, action,
  // safeguards, and simulation identical with comparison attached.
  {
    const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
    const realFetch = global.fetch;
    const origKey = config.modelApiKey;
    config.modelApiKey = 'mock_eval';
    const run = (body) => new Promise((resolve) => {
      handleEvaluateTransaction({ body }, {
        statusCode: 200,
        status(code) { this.statusCode = code; return this; },
        json(payload) { resolve({ status: this.statusCode, body: payload }); }
      });
    });
    try {
      // No-screenshot swap: heuristic MATCH 0.88, action pinned.
      // Capability 4 B3: the fixture minimum is 3,400 USDC. A zero
      // minimum would now — correctly — flag ZERO_MINIMUM_OUTPUT and
      // downgrade the MATCH, which is not what this pin exercises.
      const swap = await run({
        pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap' },
        transaction: {
          from: '0x1111111111111111111111111111111111111111',
          to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
          value: '0xde0b6b3a7640000',
          data: '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
            + '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
            + '0000000000000000000000000000000000000000000000000000000000000bb8'
            + '0000000000000000000000001111111111111111111111111111111111111111'
            + '0000000000000000000000000000000000000000000000000de0b6b3a7640000'
            + '000000000000000000000000000000000000000000000000000000000caa7e20'
            + '0000000000000000000000000000000000000000000000000000000000000000'
        }
      });
      assert.strictEqual(swap.status, 200);
      assert.strictEqual(swap.body.verdict, 'MATCH');
      assert.strictEqual(swap.body.confidence, 0.88);
      assert.strictEqual(swap.body.recommendedAction, 'PROCEED_WITH_CAUTION');
      assert.deepStrictEqual(swap.body.verdictSafeguards, []);
      assert.strictEqual(swap.body.confidenceCap, null);
      assert.strictEqual(swap.body.simulation.status, 'NOT_RUN');
      const ic = swap.body.visualEvidence.intentComparison;
      assert.ok(ic, 'comparison attached');
      assert.strictEqual(ic.status, 'INCONCLUSIVE', 'no visual claims, honestly inconclusive');
      assert.strictEqual(ic.provenance.senderSource, 'request.from-validated');
      assert.ok(ic.limitations.some((l) => l.includes('No structured visual claims')));
      assert.ok(ic.coverage.note.includes('not a security certification'));

      // Swap with recipient mismatch: safeguard output pinned.
      // Capability 4 B3: nonzero minimum isolates the recipient
      // safeguard (a zero minimum would add a second, correct trigger).
      const evil = await run({
        pageContext: { title: 'Swap', url: 'https://app.uniswap.org/#/swap' },
        transaction: {
          from: '0x1111111111111111111111111111111111111111',
          to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
          value: '0x0',
          data: '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
            + '000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
            + '0000000000000000000000000000000000000000000000000000000000000bb8'
            + '000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23'
            + '0000000000000000000000000000000000000000000000000de0b6b3a7640000'
            + '000000000000000000000000000000000000000000000000000000000caa7e20'
            + '0000000000000000000000000000000000000000000000000000000000000000'
        }
      });
      assert.strictEqual(evil.body.verdict, 'UNCERTAIN');
      assert.strictEqual(evil.body.confidence, 0.65);
      assert.strictEqual(evil.body.verdictSafeguards.length, 1);
      assert.strictEqual(evil.body.verdictSafeguards[0].trigger, 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER');
      assert.ok(evil.body.visualEvidence.intentComparison, 'comparison attached alongside safeguards');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 17-22 Passed: Pipeline behavior pinned with comparison attached.');
  }

  // Test 23: end-to-end positive comparison through the live pipeline with
  // stubbed SAM/OCR/model — verdict MATCH and a MATCHed native value.
  {
    const ctlPath = require.resolve('../../src/controllers/evaluateController');
    const ocrPath = require.resolve('../../src/services/ocrService');
    const realOcrEntry = require.cache[ocrPath];
    const hadCtl = Object.prototype.hasOwnProperty.call(require.cache, ctlPath);
    const realCtlEntry = require.cache[ctlPath];
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
          verdict: 'MATCH', confidence: 0.9, summary: 's', discrepancyDetails: {},
          recommendedAction: 'PROCEED_WITH_CAUTION',
          visualClaims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [] }]
        }) } }] })
      };
    };
    require.cache[ocrPath] = {
      id: ocrPath, filename: ocrPath, loaded: true,
      exports: {
        extractUiTexts: async (shot, regions) => ({
          regionTexts: regions.map((r) => ({
            regionId: r.regionId, label: r.label, boundingBox: r.boundingBox,
            genuine: r.genuine, text: 'Send 1.0 ETH to a friend', empty: false, ocrError: null
          })),
          combinedText: regions.length > 0 ? '[TRANSACTION SUMMARY]: Send 1.0 ETH to a friend' : ''
        })
      }
    };
    delete require.cache[ctlPath];
    try {
      const ctl = require(ctlPath);
      const res = await new Promise((resolve) => {
        ctl.handleEvaluateTransaction({ body: {
          screenshot: DUMMY_PNG,
          pageContext: { title: 'Send demo', url: 'https://demo.local/send' },
          transaction: { from: ALICE, to: OTHER, value: '0xde0b6b3a7640000' },
          visualClaims: []
        } }, {
          statusCode: 200,
          status(code) { this.statusCode = code; return this; },
          json(payload) { resolve({ status: this.statusCode, body: payload }); }
        });
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.verdict, 'MATCH');
      const ic = res.body.visualEvidence.intentComparison;
      const native = ic.fields.find((f) => f.field === 'nativeValue');
      assert.strictEqual(native.status, 'MATCH', 'pipeline amount matches value end to end');
      assert.strictEqual(native.uiValue, '1.0 ETH');
      assert.strictEqual(ic.provenance.senderSource, 'request.from-validated');
      assert.strictEqual(ic.overall, 'INCONCLUSIVE', 'uncompared fields keep overall honest');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
      if (realOcrEntry) require.cache[ocrPath] = realOcrEntry;
      else delete require.cache[ocrPath];
      if (hadCtl) require.cache[ctlPath] = realCtlEntry;
      else delete require.cache[ctlPath];
    }
    console.log('✔ Test 23 Passed: Positive comparison end to end.');
  }

  console.log('\nAll Intent Comparison Integration Tests Passed Successfully!\n');
}

module.exports = { runComparisonIntegrationTests };

if (require.main === module) {
  runComparisonIntegrationTests().catch((err) => {
    console.error(`\nIntent Comparison Integration Tests Failed: ${err.message}\n`);
    process.exit(1);
  });
}
