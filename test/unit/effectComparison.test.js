/**
 * Capability 5 B3: requested-vs-actual effect comparison.
 * Unit + integration tests over the B2 effect list.
 */
const assert = require('assert');
const { encodeFunctionData } = require('viem');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');
const { reconstructEffects } = require('../../src/services/effectReconstruction');
const { compareEffectCoverage } = require('../../src/utils/effectComparison');
const { buildIntentComparison } = require('../../src/services/intentComparisonAdapter');
const { buildModelDerivedEdges } = require('../../src/services/evidenceGraph');
const { applyVerdictSafeguards } = require('../../src/controllers/evaluateController');
const { ERC20_ABI } = require('../../src/utils/abiSignatures');

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';

function recon(to, data, value, chainId = '0x1') {
  const decodedTx = decodeTransactionCalldata({ to, data, value });
  return { decodedTx, effects: reconstructEffects({ tx: { from: A0, to, value }, decodedTx, chainId }) };
}

function regions(texts) {
  return texts.map((t, i) => ({ regionId: `R-${i + 1}`, ocr: { text: t, status: 'ok' } }));
}

async function run() {
  console.log('Testing Cap5 B3 requested-vs-actual comparison...\n');

  // B3.1: corroborated transfer request covers the effect.
  {
    const { effects } = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] }), '0x0');
    const r = compareEffectCoverage({
      regions: regions(['Send 1000 USDC to recipient']),
      claims: [{ type: 'amount', value: '1000', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    const f = r.fields.find((x) => x.field === 'effect:EF-001');
    assert.ok(f && f.status === 'MATCH', 'requested transfer must MATCH');
    assert.ok(f.evidenceRefs.includes('EF-001') && f.evidenceRefs.includes('R-1'));
    assert.deepStrictEqual(r.summary.unrequested, []);
    console.log('✔ B3.1 Passed: Corroborated request covers transfer (MATCH).');
  }

  // B3.2: presented swap + hidden approval -> approval unrequested.
  {
    const { effects } = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, (1n << 256n) - 1n] }), '0x0');
    const r = compareEffectCoverage({
      regions: regions(['Swap 100 USDC for ETH']),
      claims: [{ type: 'action', value: 'Swap 100 USDC for ETH', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    const f = r.fields.find((x) => x.field === 'effect:EF-001');
    assert.ok(f && f.status === 'MISMATCH', 'unrequested approval must MISMATCH');
    assert.deepStrictEqual(r.summary.unrequested, ['EF-001']);
    console.log('✔ B3.2 Passed: Hidden approval flagged unrequested (MISMATCH).');
  }

  // B3.3: corroborated amount with no carrying effect -> missing.
  {
    const { effects } = recon(A1, '0x', '0x0');
    assert.strictEqual(effects.effects.length, 0);
    const r = compareEffectCoverage({
      regions: regions(['Pay 5 ETH']),
      claims: [{ type: 'amount', value: '5', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    assert.strictEqual(r.fields.length, 0, 'no effects, no fields');
    console.log('✔ B3.3 Passed: Empty effect list yields no coverage fields.');
  }

  // B3.4: no corroborated claims -> INCONCLUSIVE, never MISMATCH.
  {
    const { effects } = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] }), '0x0');
    const r = compareEffectCoverage({ regions: regions(['...']), claims: [], effects });
    const f = r.fields.find((x) => x.field === 'effect:EF-001');
    assert.ok(f && f.status === 'INCONCLUSIVE');
    assert.deepStrictEqual(r.summary.unrequested, []);
    assert.deepStrictEqual(r.summary.inconclusive, ['EF-001']);
    console.log('✔ B3.4 Passed: No request evidence -> INCONCLUSIVE.');
  }

  // B3.5: opaque effects excluded from judgments.
  {
    const r = compareEffectCoverage({
      regions: regions(['Swap tokens']),
      claims: [{ type: 'action', value: 'Swap tokens', regionIds: ['R-1'], status: 'supported' }],
      effects: { effects: [{ effectId: 'EF-001', kind: 'opaque', amount: null }] }
    });
    assert.strictEqual(r.fields.length, 0);
    assert.strictEqual(r.summary.opaqueSkipped, 1);
    console.log('✔ B3.5 Passed: Opaque effects skipped.');
  }

  // B3.6: approval effect needs an explicit approval request.
  {
    const { effects } = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, 500n] }), '0x0');
    const yes = compareEffectCoverage({
      regions: regions(['Approve 500 USDC for the router']),
      claims: [{ type: 'approval', value: 'Approve 500 USDC', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    assert.strictEqual(yes.fields.find((x) => x.field === 'effect:EF-001').status, 'MATCH');
    const no = compareEffectCoverage({
      regions: regions(['Send 500 USDC']),
      claims: [{ type: 'action', value: 'Send 500 USDC', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    assert.strictEqual(no.fields.find((x) => x.field === 'effect:EF-001').status, 'MISMATCH');
    console.log('✔ B3.6 Passed: Approval requires explicit approval request.');
  }

  // B3.7: decimal-aware display agreement (1000 base units = 1000 USDC raw here;
  // 1 USDC display against 1000000 base with verified decimals).
  {
    const { effects } = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000000n] }), '0x0');
    assert.strictEqual(effects.effects[0].asset.decimals, 6);
    const r = compareEffectCoverage({
      regions: regions(['Send 1 USDC']),
      claims: [{ type: 'amount', value: '1', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    assert.strictEqual(r.fields.find((x) => x.field === 'effect:EF-001').status, 'MATCH');
    // Single-digit noise must not match via containment without decimals.
    const r2 = compareEffectCoverage({
      regions: regions(['Send 1 token']),
      claims: [{ type: 'amount', value: '1', regionIds: ['R-1'], status: 'supported' }],
      effects: { effects: [{ effectId: 'EF-001', kind: 'transfer', amount: '999000', to: A1.toLowerCase(), asset: { symbol: '???' } }] }
    });
    assert.strictEqual(r2.fields.find((x) => x.field === 'effect:EF-001').status, 'MISMATCH');
    console.log('✔ B3.7 Passed: Decimal-aware match; digit noise rejected.');
  }

  // B3.8: unobserved / failed claims never corroborate.
  {
    const { effects } = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] }), '0x0');
    const r = compareEffectCoverage({
      regions: regions(['Send 1000 USDC']),
      claims: [{ type: 'amount', value: '1000', regionIds: ['R-1'], status: 'unobserved' }],
      effects
    });
    assert.strictEqual(r.fields.find((x) => x.field === 'effect:EF-001').status, 'INCONCLUSIVE');
    console.log('✔ B3.8 Passed: Unobserved claims do not corroborate.');
  }

  // B3.9: adapter merges effect fields + exposes coverage; error-proof.
  {
    const data = encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] });
    const { decodedTx, effects } = recon(USDC, data, '0x0');
    const cmp = buildIntentComparison({
      regionEntries: regions(['Send 1000 USDC']),
      grounding: { claims: [{ type: 'amount', value: '1000', regionIds: ['R-1'], associationIds: [], status: 'supported' }] },
      associations: { links: [], ambiguities: [] },
      decodedTx, sender: A0, effects
    });
    assert.ok(cmp.fields.some((f) => f.field === 'effect:EF-001' && f.status === 'MATCH'));
    assert.ok(cmp.effectCoverage && cmp.effectCoverage.assessable === 1);
    const broken = buildIntentComparison({
      regionEntries: regions(['x']),
      grounding: { claims: [] }, associations: { links: [], ambiguities: [] },
      decodedTx, sender: A0, effects: { effects: 'not-an-array' }
    });
    assert.ok(!broken.fields.some((f) => String(f.field).startsWith('effect:')));
    console.log('✔ B3.9 Passed: Adapter merge + coverage payload + safe degrade.');
  }

  // B3.10: stage 16 names the unrequested effect on MATCH downgrade.
  {
    const { decodedTx } = recon(A1, '0x', '0x0');
    const out = applyVerdictSafeguards(
      { ...decodedTx, ruleFindings: [] },
      { verdict: 'MATCH', confidence: 0.9, summary: 'ok' },
      { fields: [{ field: 'effect:EF-002', status: 'MISMATCH', evidenceRefs: ['EF-002'], reason: 'unrequested' }],
        effectCoverage: { unrequested: ['EF-002'], missing: [], inconclusive: [] } }
    );
    assert.strictEqual(out.reasoningResult.verdict, 'UNCERTAIN');
    assert.ok(out.safeguards.some((s) => s.trigger === 'UNREQUESTED_TRANSACTION_EFFECT'));
    const clean = applyVerdictSafeguards(
      { ...decodedTx, ruleFindings: [] },
      { verdict: 'MATCH', confidence: 0.9, summary: 'ok' },
      { fields: [], effectCoverage: { unrequested: [], missing: [], inconclusive: ['EF-001'] } }
    );
    assert.strictEqual(clean.reasoningResult.verdict, 'MATCH');
    console.log('✔ B3.10 Passed: Stage 16 downgrade; clean coverage passes.');
  }

  // B3.11: effect MATCH fields become CORROBORATES graph edges.
  {
    const edges = buildModelDerivedEdges({
      grounding: { claims: [] },
      intentComparison: { fields: [{ field: 'effect:EF-001', status: 'MATCH', evidenceRefs: ['EF-001', 'R-1'], reason: 'requested' }] },
      supportValidation: null, reconciliation: null, modelEdges: []
    });
    assert.ok(edges.some((e) => e.type === 'CORROBORATES' && /effect:EF-001/.test(e.basis)));
    console.log('✔ B3.11 Passed: Effect coverage reaches the evidence graph.');
  }

  // B3.12: decimal display agreement — '1.0 ETH' requests 1 ETH exactly.
  {
    const { effects } = recon(A1, '0x', '0xde0b6b3a7640000');
    assert.strictEqual(effects.effects[0].asset.decimals, 18);
    const r = compareEffectCoverage({
      regions: regions(['Send 1.0 ETH to a friend']),
      claims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    assert.strictEqual(r.fields.find((x) => x.field === 'effect:EF-001').status, 'MATCH');
    // Wrong magnitude must not match: '2.0 ETH' against 1 ETH.
    const r2 = compareEffectCoverage({
      regions: regions(['Send 2.0 ETH to a friend']),
      claims: [{ type: 'amount', value: '2.0 ETH', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    assert.strictEqual(r2.fields.find((x) => x.field === 'effect:EF-001').status, 'MISMATCH');
    console.log('✔ B3.12 Passed: Decimal display exact; wrong magnitude rejected.');
  }

  // B3.13: corroborated amount/recipient with no carrying effect -> missing.
  {
    const { effects } = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] }), '0x0');
    const r = compareEffectCoverage({
      regions: regions([`Send 5000 USDC to ${A0}`]),
      claims: [
        { type: 'amount', value: '5000', regionIds: ['R-1'], status: 'supported' },
        { type: 'recipient', value: `Pay ${A0}`, regionIds: ['R-1'], status: 'supported' }
      ],
      effects
    });
    assert.ok(r.fields.some((x) => x.field === 'effect:missing-amount' && x.status === 'MISMATCH'));
    assert.ok(r.fields.some((x) => x.field === 'effect:missing-recipient' && x.status === 'MISMATCH'));
    assert.strictEqual(r.summary.missing.length, 2);
    console.log('✔ B3.13 Passed: Missing requested amount/recipient flagged.');
  }

  // B3.14: tx-value funding leg inherits the matched swap's coverage.
  {
    const { UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const V3 = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
    const data = encodeFunctionData({
      abi: UNISWAP_V3_ROUTER_ABI, functionName: 'exactInputSingle',
      args: [{ tokenIn: WETH, tokenOut: USDC, fee: 3000, recipient: A1, amountIn: 1000000000000000000n, amountOutMinimum: 3450000000n, sqrtPriceLimitX96: 0n }]
    });
    const { effects } = recon(V3, data, '0xde0b6b3a7640000');
    const kinds = effects.effects.map((e) => e.kind);
    assert.ok(kinds.includes('native-transfer') && kinds.includes('swap'), `legs present: ${kinds}`);
    const r = compareEffectCoverage({
      regions: regions(['Swap tokens now']),
      claims: [{ type: 'action', value: 'Swap', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    const native = effects.effects.find((e) => e.kind === 'native-transfer');
    const f = r.fields.find((x) => x.field === `effect:${native.effectId}`);
    assert.strictEqual(f.status, 'MATCH', 'funding leg covered by the swap request');
    assert.ok(f.reason.includes('same economic movement'));
    assert.deepStrictEqual(r.summary.unrequested, []);
    // Unequal amounts never link.
    const r2 = compareEffectCoverage({
      regions: regions(['Swap 1 ETH for USDC']),
      claims: [{ type: 'action', value: 'Swap', regionIds: ['R-1'], status: 'supported' }],
      effects: { effects: [
        { effectId: 'EF-001', kind: 'native-transfer', amount: '2000000000000000000', subcall: null, asset: { standard: 'native', decimals: 18 } },
        { effectId: 'EF-002', kind: 'swap', amount: '1000000000000000000', subcall: null, asset: { standard: 'ERC20' } }
      ] }
    });
    assert.strictEqual(r2.fields.find((x) => x.field === 'effect:EF-001').status, 'MISMATCH');
    console.log('✔ B3.14 Passed: Funding-leg inheritance exact.');
  }

  console.log('\nAll Cap5 B3 Tests Passed Successfully!\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
