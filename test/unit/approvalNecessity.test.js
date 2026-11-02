/**
 * Capability 5 B6: approval necessity and duration.
 * Synthetic effect lists are labeled; genuine decoder paths in
 * B6.9-B6.10.
 */
const assert = require('assert');
const { encodeFunctionData } = require('viem');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');
const { reconstructEffects } = require('../../src/services/effectReconstruction');
const { analyzeApprovalNecessity, PERMIT2_MAX_EXPIRATION } = require('../../src/utils/approvalNecessity');
const { findingActionFor } = require('../../src/services/policyDecision');
const { packEvidence } = require('../../src/services/evidencePacker');
const { PROMPT_VERSION, SHARED_SEMANTIC_RULES } = require('../../src/services/reasoningPrompts');
const { ERC20_ABI, PERMIT2_ABI } = require('../../src/utils/abiSignatures');

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const A2 = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';

function approval(id, over = {}) {
  return {
    effectId: id, kind: 'approval', operation: { functionName: 'approve', standard: 'ERC20' },
    asset: { standard: 'ERC20', contract: USDC.toLowerCase() }, amount: '1000',
    spender: A1.toLowerCase(), unlimited: false, ...over
  };
}
function movement(id, amount = '400') {
  return {
    effectId: id, kind: 'transfer', operation: { functionName: 'transferFrom', standard: 'ERC20' },
    asset: { standard: 'ERC20', contract: USDC.toLowerCase() }, amount,
    from: A0.toLowerCase(), to: A2.toLowerCase()
  };
}

async function run() {
  console.log('Testing Cap5 B6 approval necessity...\n');

  // B6.1 (synthetic): grant exceeds measured need -> exact excess.
  {
    const r = analyzeApprovalNecessity({ effects: { effects: [approval('EF-001'), movement('EF-002')] } });
    assert.strictEqual(r.findings.length, 1);
    assert.strictEqual(r.findings[0].ruleId, 'APPROVAL_EXCEEDS_BATCH_NEED');
    assert.strictEqual(r.findings[0].metadata.excess, '600');
    assert.strictEqual(r.assessments[0].batchNeed, '400');
    assert.strictEqual(findingActionFor('APPROVAL_EXCEEDS_BATCH_NEED'), 'REVIEW');
    console.log('✔ B6.1 Passed: Excess over need exact (600).');
  }

  // B6.2 (synthetic): exact utilization stays silent.
  {
    const r = analyzeApprovalNecessity({ effects: { effects: [approval('EF-001', { amount: '400' }), movement('EF-002')] } });
    assert.strictEqual(r.findings.length, 0);
    assert.strictEqual(r.assessments[0].verdict, 'utilized');
    console.log('✔ B6.2 Passed: Fully utilized grant silent.');
  }

  // B6.3 (synthetic): standalone persistent grant -> persists finding.
  {
    const r = analyzeApprovalNecessity({ effects: { effects: [approval('EF-001')] } });
    assert.strictEqual(r.findings.length, 1);
    assert.strictEqual(r.findings[0].ruleId, 'APPROVAL_PERSISTS_BEYOND_BATCH');
    assert.strictEqual(r.assessments[0].duration, 'persistent');
    assert.strictEqual(findingActionFor('APPROVAL_PERSISTS_BEYOND_BATCH'), 'REVIEW');
    console.log('✔ B6.3 Passed: Standalone persistent grant flagged.');
  }

  // B6.4 (synthetic): ERC-20 permit is persistent despite its deadline.
  {
    const r = analyzeApprovalNecessity({ effects: { effects: [{
      effectId: 'EF-001', kind: 'permit-authorization',
      operation: { functionName: 'permit', standard: 'ERC20' },
      asset: { standard: 'ERC20', contract: USDC.toLowerCase() }, amount: '500',
      spender: A1.toLowerCase(), signedExpiry: '1900000000', unlimited: false
    }] } });
    assert.strictEqual(r.findings.length, 1);
    assert.strictEqual(r.findings[0].ruleId, 'PERMIT_GRANTS_PERSISTENT_ALLOWANCE');
    assert.ok(r.findings[0].description.includes('does NOT expire the allowance'));
    assert.strictEqual(findingActionFor('PERMIT_GRANTS_PERSISTENT_ALLOWANCE'), 'REVIEW');
    console.log('✔ B6.4 Passed: Permit deadline never implies temporary.');
  }

  // B6.5 (synthetic): Permit2 expiration bounds; max expiry = persistent.
  {
    const bounded = analyzeApprovalNecessity({ effects: { effects: [
      { ...approval('EF-001'), operation: { functionName: 'approve', standard: 'Permit2' }, expiration: '1900000000' }
    ] } });
    assert.strictEqual(bounded.assessments[0].duration, 'bounded');
    assert.strictEqual(bounded.findings.length, 0, 'bounded unused grant noted, not flagged');
    assert.ok(bounded.notes.some((n) => n.includes('bounded until 1900000000')));
    const maxed = analyzeApprovalNecessity({ effects: { effects: [
      { ...approval('EF-001'), operation: { functionName: 'approve', standard: 'Permit2' }, expiration: PERMIT2_MAX_EXPIRATION.toString() }
    ] } });
    assert.strictEqual(maxed.assessments[0].duration, 'persistent');
    assert.ok(maxed.findings.some((f) => f.ruleId === 'APPROVAL_PERSISTS_BEYOND_BATCH'));
    console.log('✔ B6.5 Passed: Permit2 expiry semantics exact.');
  }

  // B6.6 (synthetic): revocations observed, never flagged.
  {
    const r = analyzeApprovalNecessity({ effects: { effects: [
      approval('EF-001', { amount: '0' }),
      { effectId: 'EF-002', kind: 'approval-nft', operation: { functionName: 'setApprovalForAll', standard: 'ERC721' },
        asset: { standard: 'ERC721', contract: A2.toLowerCase() }, operator: A1.toLowerCase(), unlimited: false }
    ] } });
    assert.strictEqual(r.findings.length, 0);
    assert.ok(r.assessments.every((a) => a.verdict === 'revocation'));
    assert.strictEqual(r.summary.revocations, 2);
    console.log('✔ B6.6 Passed: Revocations silent.');
  }

  // B6.7 (synthetic): unlimited grants owned by INFINITE_APPROVAL, not B6.
  {
    const r = analyzeApprovalNecessity({ effects: { effects: [approval('EF-001', { amount: String(2n ** 256n - 1n), unlimited: true })] } });
    assert.strictEqual(r.findings.length, 0);
    assert.strictEqual(r.assessments[0].verdict, 'unlimited-unused-in-batch');
    console.log('✔ B6.7 Passed: Unlimited grants not double-flagged.');
  }

  // B6.8 (synthetic): increaseAllowance delta unmeasurable without state.
  {
    const r = analyzeApprovalNecessity({ effects: { effects: [
      { ...approval('EF-001'), operation: { functionName: 'increaseAllowance', standard: 'ERC20' } },
      movement('EF-002')
    ] } });
    assert.strictEqual(r.findings.length, 0);
    assert.strictEqual(r.assessments[0].verdict, 'persists-unknown-total');
    assert.ok(r.notes.some((n) => n.includes('unknown current allowance')));
    console.log('✔ B6.8 Passed: Delta semantics honest.');
  }

  // B6.9 (genuine decode): top-level approve -> persists finding.
  {
    const data = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, 1000n] });
    const decodedTx = decodeTransactionCalldata({ to: USDC, data, value: '0x0' });
    const effects = reconstructEffects({ tx: { from: A0, to: USDC, value: '0x0' }, decodedTx, chainId: '0x1' });
    const r = analyzeApprovalNecessity({ effects });
    assert.ok(r.findings.some((f) => f.ruleId === 'APPROVAL_PERSISTS_BEYOND_BATCH'));
    console.log('✔ B6.9 Passed: Genuine approve persists end to end.');
  }

  // B6.10 (genuine decode): top-level ERC-20 permit -> permit finding.
  {
    const data = encodeFunctionData({
      abi: ERC20_ABI, functionName: 'permit',
      args: [A0, A1, 500n, 1900000000n, 27, `0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`]
    });
    const decodedTx = decodeTransactionCalldata({ to: USDC, data, value: '0x0' });
    assert.strictEqual(decodedTx.functionName, 'permit');
    const effects = reconstructEffects({ tx: { from: A0, to: USDC, value: '0x0' }, decodedTx, chainId: '0x1' });
    assert.ok(effects.effects.some((e) => e.kind === 'permit-authorization'));
    const r = analyzeApprovalNecessity({ effects });
    assert.ok(r.findings.some((f) => f.ruleId === 'PERMIT_GRANTS_PERSISTENT_ALLOWANCE'));
    assert.ok(PERMIT2_ABI.length > 0, 'permit2 abi import live');
    console.log('✔ B6.10 Passed: Genuine permit flagged persistent.');
  }

  // B6.11: packer block renders; prompt carries S13 at 2.6.
  {
    const r = analyzeApprovalNecessity({ effects: { effects: [approval('EF-001')] } });
    const packed = packEvidence({
      decodedTx: { contract: USDC, functionName: 'approve', parameters: {}, ruleFindings: [] },
      extra: { approvalNecessity: r }
    });
    assert.ok(packed.text.includes('Approval Necessity'));
    assert.ok(packed.text.includes('verdict=persists-unused'));
    assert.strictEqual(PROMPT_VERSION, 'investigate-2.7');
    assert.ok(SHARED_SEMANTIC_RULES.includes('S13. Approval necessity'));
    console.log('✔ B6.11 Passed: Packer block + S13 at 2.6.');
  }

  // B6.12: malformed input never throws.
  {
    for (const bad of [null, undefined, {}, { effects: null }, { effects: { effects: [null, 7, { kind: 'approval' }] } }]) {
      const r = analyzeApprovalNecessity(bad);
      assert.ok(Array.isArray(r.findings) && Array.isArray(r.assessments));
    }
    console.log('✔ B6.12 Passed: Malformed input safe.');
  }

  console.log('\nAll Cap5 B6 Tests Passed Successfully!\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
