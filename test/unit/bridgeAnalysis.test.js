/**
 * Capability 5 B5: narrow bridge transaction understanding
 * (Across V3 + CCTP V1). Genuine viem-encoded calldata throughout;
 * synthetic lists are labeled where the analyzer is unit-pinned.
 */
const assert = require('assert');
const { encodeFunctionData, toFunctionSelector } = require('viem');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');
const { reconstructEffects } = require('../../src/services/effectReconstruction');
const { analyzeBridge, ACROSS_V3_SPOKEPOOLS, CCTP_V1_MESSENGERS } = require('../../src/utils/bridgeAnalysis');
const { compareEffectCoverage } = require('../../src/utils/effectComparison');
const { analyzeBatchComposition } = require('../../src/utils/batchComposition');
const { findingActionFor } = require('../../src/services/policyDecision');
const { packEvidence } = require('../../src/services/evidencePacker');
const { PROMPT_VERSION, SHARED_SEMANTIC_RULES } = require('../../src/services/reasoningPrompts');
const { ACROSS_V3_ABI, CCTP_V1_ABI } = require('../../src/utils/abiSignatures');

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const SPOKE_BASE = '0x09aea4b2242abC8bb4BB78D537A67a245A7bEC64';
const TM_BASE = '0x1682Ae6375C4E4A97e4B583BC394c861A46D8962';
const recipient32 = `0x000000000000000000000000${A1.slice(2)}`;

function acrossData(over = {}) {
  const args = {
    depositor: A0, recipient: A1, inputToken: USDC_BASE, outputToken: USDC_BASE,
    inputAmount: 1000000n, outputAmount: 999000n, destinationChainId: 42161n,
    exclusiveRelayer: '0x0000000000000000000000000000000000000000',
    quoteTimestamp: 1700000000, fillDeadline: 1900000000, exclusivityDeadline: 0,
    message: '0x', ...over
  };
  return encodeFunctionData({
    abi: ACROSS_V3_ABI, functionName: 'depositV3',
    args: [args.depositor, args.recipient, args.inputToken, args.outputToken, args.inputAmount, args.outputAmount, args.destinationChainId, args.exclusiveRelayer, args.quoteTimestamp, args.fillDeadline, args.exclusivityDeadline, args.message]
  });
}

function cctpData(over = {}) {
  const args = { amount: 500000n, destinationDomain: 3, mintRecipient: recipient32, burnToken: USDC_BASE, ...over };
  return encodeFunctionData({
    abi: CCTP_V1_ABI, functionName: 'depositForBurn',
    args: [args.amount, args.destinationDomain, args.mintRecipient, args.burnToken]
  });
}

async function run() {
  console.log('Testing Cap5 B5 bridge understanding...\n');

  // B5.1: Across depositV3 decodes; selector verified locally.
  {
    assert.strictEqual(
      toFunctionSelector('depositV3(address,address,address,address,uint256,uint256,uint256,address,uint32,uint32,uint32,bytes)'),
      '0x7b939232'
    );
    const d = decodeTransactionCalldata({ to: SPOKE_BASE, data: acrossData(), value: '0x0', chainId: '0x2105' });
    assert.strictEqual(d.functionName, 'depositV3');
    assert.strictEqual(d.standard, 'AcrossV3');
    assert.strictEqual(d.parameters.inputAmount, '1000000');
    assert.strictEqual(d.parameters.destinationChainId, '42161');
    assert.strictEqual(d.parameters.recipient, A1);
    console.log('✔ B5.1 Passed: depositV3 decodes; selector 0x7b939232 confirmed.');
  }

  // B5.2: CCTP depositForBurn decodes; selector verified locally.
  {
    assert.strictEqual(
      toFunctionSelector('depositForBurn(uint256,uint32,bytes32,address)'),
      '0x6fd3504e'
    );
    const d = decodeTransactionCalldata({ to: TM_BASE, data: cctpData(), value: '0x0', chainId: '0x2105' });
    assert.strictEqual(d.functionName, 'depositForBurn');
    assert.strictEqual(d.standard, 'CCTPV1');
    assert.strictEqual(d.parameters.amount, '500000');
    assert.strictEqual(d.parameters.destinationDomain, 3);
    console.log('✔ B5.2 Passed: depositForBurn decodes; selector 0x6fd3504e confirmed.');
  }

  // B5.3: Across supported on canonical SpokePool — exact terms + REVIEW.
  {
    const d = decodeTransactionCalldata({ to: SPOKE_BASE, data: acrossData(), value: '0x0', chainId: '0x2105' });
    const b = analyzeBridge({ decodedTx: d, chainId: '0x2105' });
    assert.strictEqual(b.status, 'supported');
    assert.deepStrictEqual([b.terms.sourceChain, b.terms.destinationChain], ['8453', '42161']);
    assert.strictEqual(b.terms.sourceAsset.contract, USDC_BASE.toLowerCase());
    assert.strictEqual(b.terms.amount, '1000000');
    assert.strictEqual(b.terms.expectedOutput, '999000');
    assert.strictEqual(b.terms.destinationRecipient, A1.toLowerCase());
    assert.strictEqual(b.terms.fillDeadline, '1900000000');
    assert.strictEqual(b.finding.ruleId, 'BRIDGE_DEPOSIT');
    assert.strictEqual(findingActionFor('BRIDGE_DEPOSIT'), 'REVIEW');
    assert.ok(b.notes.some((n) => n.includes('never proves destination receipt')));
    console.log('✔ B5.3 Passed: Across terms exact; BRIDGE_DEPOSIT REVIEW.');
  }

  // B5.4: CCTP supported — domain resolution + bytes32 recipient.
  {
    const d = decodeTransactionCalldata({ to: TM_BASE, data: cctpData(), value: '0x0', chainId: '0x2105' });
    const b = analyzeBridge({ decodedTx: d, chainId: '0x2105' });
    assert.strictEqual(b.status, 'supported');
    assert.deepStrictEqual([b.terms.sourceChain, b.terms.destinationChain], ['8453', '42161']);
    assert.strictEqual(b.terms.destinationDomain, '3');
    assert.strictEqual(b.terms.amount, '500000');
    assert.strictEqual(b.terms.destinationRecipient, A1.toLowerCase());
    assert.strictEqual(b.terms.sourceAsset.contract, USDC_BASE.toLowerCase());
    assert.ok(b.terms.destinationAsset.note.includes('native USDC'));
    console.log('✔ B5.4 Passed: CCTP domain + recipient exact.');
  }

  // B5.5: bridge-shaped call to a non-canonical target stays unsupported.
  {
    const d = decodeTransactionCalldata({ to: A0, data: acrossData(), value: '0x0', chainId: '0x2105' });
    assert.strictEqual(d.functionName, 'depositV3', 'selector still decodes (spoofable claim)');
    const b = analyzeBridge({ decodedTx: d, chainId: '0x2105' });
    assert.strictEqual(b.status, 'unsupported');
    assert.ok(b.reason.includes('not the canonical'));
    assert.strictEqual(b.finding.ruleId, 'BRIDGE_UNVERIFIED_CONTRACT');
    assert.strictEqual(findingActionFor('BRIDGE_UNVERIFIED_CONTRACT'), 'REVIEW');
    console.log('✔ B5.5 Passed: Spoofed bridge target unsupported + REVIEW.');
  }

  // B5.6: unmapped CCTP domain (5 = Solana-style) stays unsupported.
  {
    const d = decodeTransactionCalldata({ to: TM_BASE, data: cctpData({ destinationDomain: 5 }), value: '0x0', chainId: '0x2105' });
    const b = analyzeBridge({ decodedTx: d, chainId: '0x2105' });
    assert.strictEqual(b.status, 'unsupported');
    assert.ok(b.reason.includes('domain 5'));
    console.log('✔ B5.6 Passed: Unmapped domain unsupported.');
  }

  // B5.7: non-EVM bytes32 recipient stays unsupported.
  {
    const full = `0x${'ab'.repeat(32)}`;
    const d = decodeTransactionCalldata({ to: TM_BASE, data: cctpData({ mintRecipient: full }), value: '0x0', chainId: '0x2105' });
    const b = analyzeBridge({ decodedTx: d, chainId: '0x2105' });
    assert.strictEqual(b.status, 'unsupported');
    assert.ok(b.reason.includes('not a left-padded EVM address'));
    console.log('✔ B5.7 Passed: Non-EVM recipient unsupported.');
  }

  // B5.8: cross-token route, message, exclusivity surface as notes.
  {
    const d = decodeTransactionCalldata({
      to: SPOKE_BASE,
      data: acrossData({ outputToken: A0, message: '0x1234', exclusiveRelayer: A1, exclusivityDeadline: 1800000000 }),
      value: '0x0', chainId: '0x2105'
    });
    const b = analyzeBridge({ decodedTx: d, chainId: '0x2105' });
    assert.strictEqual(b.status, 'supported');
    assert.strictEqual(b.terms.hasMessage, true);
    assert.ok(b.notes.some((n) => n.includes('cross-token route')));
    assert.ok(b.notes.some((n) => n.includes('arbitrary destination-side execution')));
    assert.ok(b.notes.some((n) => n.includes('exclusive relayer')));
    console.log('✔ B5.8 Passed: Message/exclusivity/cross-token noted.');
  }

  // B5.9: B2 bridge effect nodes for both protocols (genuine decode).
  {
    const da = decodeTransactionCalldata({ to: SPOKE_BASE, data: acrossData(), value: '0x0', chainId: '0x2105' });
    const ra = reconstructEffects({ tx: { from: A0, to: SPOKE_BASE, value: '0x0' }, decodedTx: da, chainId: '0x2105' });
    const ea = ra.effects.find((e) => e.kind === 'bridge');
    assert.ok(ea, 'across bridge effect present');
    assert.strictEqual(ea.amount, '1000000');
    assert.strictEqual(ea.from, A0.toLowerCase());
    assert.strictEqual(ea.to, A1.toLowerCase());
    assert.strictEqual(ea.bridge.protocol, 'across-v3');
    assert.strictEqual(ea.bridge.destinationChain, '42161');
    const dc = decodeTransactionCalldata({ to: TM_BASE, data: cctpData(), value: '0x0', chainId: '0x2105' });
    const rc = reconstructEffects({ tx: { from: A0, to: TM_BASE, value: '0x0' }, decodedTx: dc, chainId: '0x2105' });
    const ec = rc.effects.find((e) => e.kind === 'bridge');
    assert.ok(ec, 'cctp bridge effect present');
    assert.strictEqual(ec.bridge.protocol, 'cctp-v1');
    assert.strictEqual(ec.to, A1.toLowerCase());
    console.log('✔ B5.9 Passed: Bridge effect nodes exact.');
  }

  // B5.10: B3 covers requested bridges; flags unrequested ones.
  {
    const d = decodeTransactionCalldata({ to: TM_BASE, data: cctpData(), value: '0x0', chainId: '0x2105' });
    const effects = reconstructEffects({ tx: { from: A0, to: TM_BASE, value: '0x0' }, decodedTx: d, chainId: '0x2105' });
    const regions = [{ regionId: 'R-1', ocr: { text: 'Bridge 0.5 USDC to Arbitrum', status: 'ok' } }];
    const yes = compareEffectCoverage({
      regions,
      claims: [{ type: 'action', value: 'Bridge 0.5 USDC to Arbitrum', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    const bridgeId = effects.effects.find((e) => e.kind === 'bridge').effectId;
    assert.strictEqual(yes.fields.find((x) => x.field === `effect:${bridgeId}`).status, 'MATCH');
    const no = compareEffectCoverage({
      regions: [{ regionId: 'R-1', ocr: { text: 'Swap 0.5 USDC for ETH', status: 'ok' } }],
      claims: [{ type: 'action', value: 'Swap 0.5 USDC for ETH', regionIds: ['R-1'], status: 'supported' }],
      effects
    });
    assert.strictEqual(no.fields.find((x) => x.field === `effect:${bridgeId}`).status, 'MISMATCH');
    console.log('✔ B5.10 Passed: Bridge request coverage both directions.');
  }

  // B5.11 (synthetic list): approval then bridge of the same token links.
  {
    const c = analyzeBatchComposition({ effects: { effects: [
      { effectId: 'EF-001', kind: 'approval', asset: { standard: 'ERC20', contract: USDC_BASE.toLowerCase() }, amount: '1000000', spender: TM_BASE.toLowerCase() },
      { effectId: 'EF-002', kind: 'bridge', asset: { standard: 'ERC20', contract: USDC_BASE.toLowerCase() }, amount: '500000', from: A0.toLowerCase(), to: A1.toLowerCase() }
    ] } });
    assert.ok(c.findings.some((f) => f.ruleId === 'BATCH_APPROVE_THEN_SPEND'));
    console.log('✔ B5.11 Passed: Approve-then-bridge composition links.');
  }

  // B5.12: packer renders Bridge Terms (supported + undetermined).
  {
    const d = decodeTransactionCalldata({ to: SPOKE_BASE, data: acrossData(), value: '0x0', chainId: '0x2105' });
    const supported = analyzeBridge({ decodedTx: d, chainId: '0x2105' });
    const packed = packEvidence({
      decodedTx: { contract: SPOKE_BASE, functionName: 'depositV3', parameters: {}, ruleFindings: [] },
      extra: { bridge: supported }
    });
    assert.ok(packed.text.includes('Bridge Terms'));
    assert.ok(packed.text.includes('8453 -> chain 42161'));
    const bad = analyzeBridge({
      decodedTx: decodeTransactionCalldata({ to: A0, data: acrossData(), value: '0x0', chainId: '0x2105' }),
      chainId: '0x2105'
    });
    const packedBad = packEvidence({
      decodedTx: { contract: A0, functionName: 'depositV3', parameters: {}, ruleFindings: [] },
      extra: { bridge: bad }
    });
    assert.ok(packedBad.text.includes('UNDETERMINED'));
    const empty = packEvidence({
      decodedTx: { contract: A0, functionName: 'transfer', parameters: {}, ruleFindings: [] },
      extra: {}
    });
    assert.ok(!empty.text.includes('Bridge Terms'));
    console.log('✔ B5.12 Passed: Packer bridge block renders.');
  }

  // B5.13: prompt carries S12 at version investigate-2.7.
  {
    assert.strictEqual(PROMPT_VERSION, 'investigate-2.7');
    assert.ok(SHARED_SEMANTIC_RULES.includes('S12. Bridge terms'));
    assert.ok(SHARED_SEMANTIC_RULES.includes('NEVER proves destination delivery'));
    console.log('✔ B5.13 Passed: S12 present at prompt version 2.5.');
  }

  // B5.14: malformed input never throws; non-bridge stays silent.
  {
    assert.strictEqual(analyzeBridge(null), null);
    assert.strictEqual(analyzeBridge({}), null);
    const plain = decodeTransactionCalldata({ to: A1, data: '0x', value: '0x1' });
    assert.strictEqual(analyzeBridge({ decodedTx: plain, chainId: '1' }), null);
    const bad = analyzeBridge({ decodedTx: { functionName: 'depositV3', standard: 'AcrossV3' }, chainId: '1' });
    assert.strictEqual(bad.status, 'unsupported');
    console.log('✔ B5.14 Passed: Malformed input safe; non-bridge silent.');
  }

  // B5.15: unknown source chain fails closed (canonical unverifiable).
  {
    const d = decodeTransactionCalldata({ to: SPOKE_BASE, data: acrossData(), value: '0x0' });
    const b = analyzeBridge({ decodedTx: d, chainId: null });
    assert.strictEqual(b.status, 'unsupported');
    assert.ok(b.reason.includes('source chain'));
    assert.ok(ACROSS_V3_SPOKEPOOLS['137'].length === 42 && CCTP_V1_MESSENGERS['8453'].length === 42);
    console.log('✔ B5.15 Passed: Unknown chain fails closed.');
  }

  console.log('\nAll Cap5 B5 Tests Passed Successfully!\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
