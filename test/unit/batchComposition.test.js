/**
 * Capability 5 B4: within-batch composition analysis.
 * Analyzer unit tests use synthetic effect lists (labeled); linkage
 * against genuine decoder output is covered in B4.5.
 */
const assert = require('assert');
const { encodeFunctionData } = require('viem');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');
const { reconstructEffects } = require('../../src/services/effectReconstruction');
const { analyzeBatchComposition } = require('../../src/utils/batchComposition');
const { findingActionFor } = require('../../src/services/policyDecision');
const { packEvidence } = require('../../src/services/evidencePacker');
const { PROMPT_VERSION, SHARED_SEMANTIC_RULES } = require('../../src/services/reasoningPrompts');
const { ERC20_ABI, UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const A2 = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const DAI = '0x6b175474e89094c44da98b954eedeac495271d0f';
const V3 = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';

function approval(id, token, spender, amount = '1000') {
  return { effectId: id, kind: 'approval', asset: { standard: 'ERC20', contract: token, symbol: 'T' }, amount, spender, from: null, to: null, operator: null };
}
function movement(id, token, from, to, amount = '100') {
  return { effectId: id, kind: 'transfer', asset: { standard: 'ERC20', contract: token, symbol: 'T' }, amount, from, to, spender: null, operator: null };
}

async function run() {
  console.log('Testing Cap5 B4 within-batch composition...\n');

  // B4.1 (synthetic list): approval then same-token spend -> finding + REVIEW.
  {
    const c = analyzeBatchComposition({ effects: { effects: [
      approval('EF-001', USDC, A1),
      movement('EF-002', USDC, A0, A2, '400'),
      movement('EF-003', USDC, A0, A1, '100')
    ] } });
    assert.strictEqual(c.findings.length, 1);
    assert.strictEqual(c.findings[0].ruleId, 'BATCH_APPROVE_THEN_SPEND');
    assert.deepStrictEqual(c.findings[0].evidenceRefs, ['EF-001', 'EF-002']);
    assert.strictEqual(c.findings[0].metadata.movementCount, 2);
    assert.ok(c.findings[0].description.includes('Positional linkage only'));
    assert.strictEqual(findingActionFor('BATCH_APPROVE_THEN_SPEND'), 'REVIEW');
    console.log('✔ B4.1 Passed: Approve-then-spend finding + REVIEW mapping.');
  }

  // B4.2 (synthetic list): spend before its only approval -> ordering finding.
  {
    const c = analyzeBatchComposition({ effects: { effects: [
      movement('EF-001', USDC, A0, A2, '400'),
      approval('EF-002', USDC, A1)
    ] } });
    assert.strictEqual(c.findings.length, 1);
    assert.strictEqual(c.findings[0].ruleId, 'BATCH_SPEND_BEFORE_APPROVAL');
    assert.strictEqual(findingActionFor('BATCH_SPEND_BEFORE_APPROVAL'), 'REVIEW');
    console.log('✔ B4.2 Passed: Spend-before-approval ordering finding.');
  }

  // B4.3 (synthetic list): spend covered by an earlier approval stays silent.
  {
    const c = analyzeBatchComposition({ effects: { effects: [
      approval('EF-001', USDC, A1),
      movement('EF-002', USDC, A0, A2, '400'),
      approval('EF-003', USDC, A2)
    ] } });
    assert.ok(c.findings.every((f) => f.ruleId !== 'BATCH_SPEND_BEFORE_APPROVAL'));
    assert.ok(c.findings.some((f) => f.ruleId === 'BATCH_APPROVE_THEN_SPEND'));
    console.log('✔ B4.3 Passed: Covered spend silent; approve-side still fires.');
  }

  // B4.4 (synthetic list): different tokens never link.
  {
    const c = analyzeBatchComposition({ effects: { effects: [
      approval('EF-001', USDC, A1),
      movement('EF-002', DAI, A0, A2, '400')
    ] } });
    assert.strictEqual(c.findings.length, 0);
    console.log('✔ B4.4 Passed: Cross-token pairs never link.');
  }

  // B4.5 (genuine decoder output): V3 multicall inners carry no token
  // identity -> indeterminate coexistence, never a forced link.
  {
    const data = encodeFunctionData({
      abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
      args: [[
        encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, 1000n] }),
        encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A2, 400n] })
      ]]
    });
    const decodedTx = decodeTransactionCalldata({ to: V3, data, value: '0x0' });
    const effects = reconstructEffects({ tx: { from: A0, to: V3, value: '0x0' }, decodedTx, chainId: '0x1' });
    assert.ok(effects.effects.every((e) => e.asset.contract === null), 'inner tokens unestablished');
    const c = analyzeBatchComposition({ effects });
    assert.strictEqual(c.findings.length, 0, 'no forced link without token identity');
    assert.strictEqual(c.summary.unlinkedApprovals, 1);
    assert.strictEqual(c.summary.unlinkedMovements, 1);
    assert.ok(c.notes.some((n) => n.startsWith('Indeterminate authorization')));
    assert.ok(c.notes.some((n) => n.startsWith('Indeterminate movement')));
    console.log('✔ B4.5 Passed: Genuine batch reports indeterminate coexistence.');
  }

  // B4.6 (synthetic list): outflow aggregates exact + fan-out note.
  {
    const c = analyzeBatchComposition({ effects: { effects: [
      movement('EF-001', USDC, A0, A1, '100'),
      movement('EF-002', USDC, A0, A2, '200'),
      movement('EF-003', USDC, A0, A0, '300')
    ] } });
    assert.strictEqual(c.aggregates.length, 1);
    const g = c.aggregates[0];
    assert.strictEqual(g.transfers, 3);
    assert.strictEqual(g.distinctRecipients, 3);
    assert.strictEqual(g.totalAmount, '600');
    assert.strictEqual(g.totalExact, true);
    assert.ok(c.notes.some((n) => n.startsWith('Fan-out')));
    // Single-transfer groups do not aggregate.
    const c2 = analyzeBatchComposition({ effects: { effects: [movement('EF-001', USDC, A0, A1, '100')] } });
    assert.strictEqual(c2.aggregates.length, 0);
    console.log('✔ B4.6 Passed: Exact outflow aggregates + fan-out note.');
  }

  // B4.7 (synthetic list): multi-spender authorization noted.
  {
    const c = analyzeBatchComposition({ effects: { effects: [
      approval('EF-001', USDC, A1),
      approval('EF-002', USDC, A2)
    ] } });
    assert.ok(c.notes.some((n) => n.startsWith('Multi-spender authorization')));
    assert.strictEqual(c.summary.multiSpenderTokens, 1);
    console.log('✔ B4.7 Passed: Multi-spender authorization noted.');
  }

  // B4.8: malformed input never throws; unusable lists stay explicit.
  {
    for (const bad of [null, undefined, {}, { effects: null }, { effects: { effects: 'x' } }, { effects: { effects: [null, 42, { kind: 'transfer' }] } }]) {
      const c = analyzeBatchComposition(bad);
      assert.ok(Array.isArray(c.findings) && Array.isArray(c.notes) && Array.isArray(c.aggregates));
    }
    console.log('✔ B4.8 Passed: Malformed input degrades safely.');
  }

  // B4.9: packer renders the composition block; absent when null.
  {
    const comp = analyzeBatchComposition({ effects: { effects: [
      movement('EF-001', USDC, A0, A1, '100'),
      movement('EF-002', USDC, A0, A2, '200')
    ] } });
    const packed = packEvidence({
      decodedTx: { contract: USDC, functionName: 'x', parameters: {}, ruleFindings: [] },
      extra: { composition: comp }
    });
    assert.ok(packed.text.includes('Batch Composition'));
    assert.ok(packed.text.includes('total 300'));
    const empty = packEvidence({
      decodedTx: { contract: USDC, functionName: 'x', parameters: {}, ruleFindings: [] },
      extra: {}
    });
    assert.ok(!empty.text.includes('Batch Composition'));
    console.log('✔ B4.9 Passed: Packer composition block renders.');
  }

  // B4.10: prompt carries S11 at version investigate-2.7.
  {
    assert.strictEqual(PROMPT_VERSION, 'investigate-2.7');
    assert.ok(SHARED_SEMANTIC_RULES.includes('S11. Batch composition'));
    assert.ok(SHARED_SEMANTIC_RULES.includes('indeterminate coexistence'));
    console.log('✔ B4.10 Passed: S11 present at prompt version 2.4.');
  }

  console.log('\nAll Cap5 B4 Tests Passed Successfully!\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
