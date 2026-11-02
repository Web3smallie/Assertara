/**
 * Capability 5 B7: post-execution effect verification.
 * Verifier unit tests use synthetic receipts/effects (labeled);
 * B7.15 drives recordExecution through the agent controller with
 * stubbed chain RPC (labeled sim); genuine Anvil receipts are
 * covered by test/e2e/effectVerification.test.js.
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { keccak256, toBytes, encodeFunctionData } = require('viem');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const config = require('../../src/config/env');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentStore } = require('../../src/services/agentStore');
const { createAgentController } = require('../../src/controllers/agentController');
const {
  verifyEffectsAgainstReceipt, parseReceiptLogs,
  TRANSFER_TOPIC, APPROVAL_TOPIC, APPROVAL_FOR_ALL_TOPIC
} = require('../../src/utils/effectVerification');
const { ERC20_ABI } = require('../../src/utils/abiSignatures');

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const A2 = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const TOKEN = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const HASH = `0x${'ab'.repeat(32)}`;

function padTopic(addr) {
  return `0x${'0'.repeat(24)}${addr.slice(2).toLowerCase()}`;
}
function padData(v) {
  return `0x${BigInt(v).toString(16).padStart(64, '0')}`;
}
function transferLog(contract, from, to, value, index = 0) {
  return { address: contract, topics: [TRANSFER_TOPIC, padTopic(from), padTopic(to)], data: padData(value), logIndex: `0x${index.toString(16)}` };
}
function approvalLog(contract, owner, spender, value, index = 0) {
  return { address: contract, topics: [APPROVAL_TOPIC, padTopic(owner), padTopic(spender)], data: padData(value), logIndex: `0x${index.toString(16)}` };
}
function receipt(logs) {
  return { status: '0x1', blockNumber: '0x10', gasUsed: '0x5208', logs };
}
function transferFx(id, over = {}) {
  return {
    effectId: id, kind: 'transfer', operation: { functionName: 'transfer', standard: 'ERC20' },
    asset: { standard: 'ERC20', contract: TOKEN.toLowerCase() }, amount: '100',
    from: A0.toLowerCase(), to: A1.toLowerCase(), subcall: null, ...over
  };
}

async function run() {
  console.log('Testing Cap5 B7 post-execution verification...\n');

  // B7.1: event topics verified locally from canonical signatures.
  {
    assert.strictEqual(keccak256(toBytes('Transfer(address,address,uint256)')), TRANSFER_TOPIC);
    assert.strictEqual(keccak256(toBytes('Approval(address,address,uint256)')), APPROVAL_TOPIC);
    assert.strictEqual(keccak256(toBytes('ApprovalForAll(address,address,bool)')), APPROVAL_FOR_ALL_TOPIC);
    console.log('✔ B7.1 Passed: Event topics keccak-verified.');
  }

  // B7.2 (synthetic): top-level transfer + exact log -> MATCHED.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [transferFx('EF-001')] },
      receipt: receipt([transferLog(TOKEN, A0, A1, 100n)]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_MATCHED');
    assert.strictEqual(r.summary.wildcards, 0);
    console.log('✔ B7.2 Passed: Exact transfer log MATCHED.');
  }

  // B7.3 (synthetic): top-level approve + exact log -> MATCHED.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [{
        effectId: 'EF-001', kind: 'approval', operation: { functionName: 'approve', standard: 'ERC20' },
        asset: { standard: 'ERC20', contract: TOKEN.toLowerCase() }, amount: '500',
        spender: A1.toLowerCase(), subcall: null
      }] },
      receipt: receipt([approvalLog(TOKEN, A0, A1, 500n)]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_MATCHED');
    console.log('✔ B7.3 Passed: Exact approval log MATCHED.');
  }

  // B7.4 (synthetic): amount mismatch (fee-token semantics) -> DIVERGED.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [transferFx('EF-001')] },
      receipt: receipt([transferLog(TOKEN, A0, A1, 95n)]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_DIVERGED');
    assert.deepStrictEqual(r.missing.map((m) => m.effectId), ['EF-001']);
    assert.strictEqual(r.unexpected.length, 1);
    console.log('✔ B7.4 Passed: Amount mismatch DIVERGED.');
  }

  // B7.5 (synthetic): extra unexplained log -> DIVERGED.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [transferFx('EF-001')] },
      receipt: receipt([transferLog(TOKEN, A0, A1, 100n), transferLog(TOKEN, A0, A2, 50n, 1)]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_DIVERGED');
    assert.deepStrictEqual(r.unexpected.map((u) => u.logIndex), [1]);
    console.log('✔ B7.5 Passed: Unexpected log DIVERGED.');
  }

  // B7.6 (synthetic): expected log absent -> DIVERGED.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [transferFx('EF-001')] },
      receipt: receipt([]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_DIVERGED');
    console.log('✔ B7.6 Passed: Missing log DIVERGED.');
  }

  // B7.7 (synthetic): swap present -> extra logs unattributable -> UNVERIFIED.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [
        transferFx('EF-001'),
        { effectId: 'EF-002', kind: 'swap', asset: {}, amount: null }
      ] },
      receipt: receipt([transferLog(TOKEN, A0, A1, 100n), transferLog(TOKEN, A0, A2, 50n, 1)]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_UNVERIFIED');
    assert.ok(r.notes.some((n) => n.includes('unattributable')));
    console.log('✔ B7.7 Passed: Swap-capped extras UNVERIFIED.');
  }

  // B7.8 (synthetic): nested approval wildcard match -> UNVERIFIED.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [{
        effectId: 'EF-001', kind: 'approval', operation: { functionName: 'approve', standard: 'ERC20' },
        asset: { standard: 'ERC20', contract: TOKEN.toLowerCase() }, amount: '500',
        spender: A1.toLowerCase(), subcall: { subcallId: 'SC-001' }
      }] },
      receipt: receipt([approvalLog(TOKEN, A0, A1, 500n)]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_UNVERIFIED');
    assert.ok(r.notes.some((n) => n.includes('wildcard')));
    console.log('✔ B7.8 Passed: Wildcard match capped UNVERIFIED.');
  }

  // B7.9 (synthetic): native-only, no logs -> MATCHED (trivial).
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [{ effectId: 'EF-001', kind: 'native-transfer', asset: { standard: 'native' }, amount: '1000' }] },
      receipt: receipt([]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_MATCHED');
    console.log('✔ B7.9 Passed: Logless native MATCHED.');
  }

  // B7.10 (synthetic): opaque effect caps at UNVERIFIED.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [transferFx('EF-001'), { effectId: 'EF-002', kind: 'opaque' }] },
      receipt: receipt([transferLog(TOKEN, A0, A1, 100n)]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_UNVERIFIED');
    console.log('✔ B7.10 Passed: Opaque caps UNVERIFIED.');
  }

  // B7.11 (synthetic): missing logs array -> UNVERIFIED, never throws.
  {
    const r = verifyEffectsAgainstReceipt({ effects: { effects: [transferFx('EF-001')] }, receipt: { status: '0x1' }, sender: A0 });
    assert.strictEqual(r.status, 'EFFECTS_UNVERIFIED');
    const r2 = verifyEffectsAgainstReceipt(null);
    assert.strictEqual(r2.status, 'EFFECTS_UNVERIFIED');
    console.log('✔ B7.11 Passed: Unavailable logs UNVERIFIED.');
  }

  // B7.12 (synthetic): NFT transfer matches on tokenId.
  {
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [{
        effectId: 'EF-001', kind: 'transfer-nft', operation: { functionName: 'transferFrom', standard: 'ERC721' },
        asset: { standard: 'ERC721', contract: TOKEN.toLowerCase(), tokenId: '7' },
        from: A0.toLowerCase(), to: A1.toLowerCase(), subcall: null
      }] },
      receipt: receipt([transferLog(TOKEN, A0, A1, 7n)]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_MATCHED');
    console.log('✔ B7.12 Passed: NFT tokenId MATCHED.');
  }

  // B7.13 (synthetic): ApprovalForAll matches operator + flag.
  {
    const log = {
      address: TOKEN, topics: [APPROVAL_FOR_ALL_TOPIC, padTopic(A0), padTopic(A1)],
      data: padData(1n), logIndex: '0x0'
    };
    const r = verifyEffectsAgainstReceipt({
      effects: { effects: [{
        effectId: 'EF-001', kind: 'approval-nft', operation: { functionName: 'setApprovalForAll', standard: 'ERC721' },
        asset: { standard: 'ERC721', contract: TOKEN.toLowerCase() }, operator: A1.toLowerCase(),
        unlimited: true, subcall: null
      }] },
      receipt: receipt([log]),
      sender: A0
    });
    assert.strictEqual(r.status, 'EFFECTS_MATCHED');
    console.log('✔ B7.13 Passed: ApprovalForAll MATCHED.');
  }

  // B7.14 (synthetic): malformed inputs never throw.
  {
    for (const bad of [undefined, {}, { effects: null }, { effects: { effects: 'x' } },
      { effects: { effects: [transferFx('EF-001')] }, receipt: receipt([{ address: TOKEN, topics: [], data: '0xzz' }]), sender: A0 }]) {
      const r = verifyEffectsAgainstReceipt(bad);
      assert.ok(['EFFECTS_MATCHED', 'EFFECTS_DIVERGED', 'EFFECTS_UNVERIFIED'].includes(r.status));
    }
    console.log('✔ B7.14 Passed: Malformed input safe.');
  }

  // B7.15 (sim RPC): recordExecution outcomes end to end.
  {
    const OPERATOR_KEY = generatePrivateKey();
    const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();
    const dir = path.join(__dirname, '..', 'tmp', `b7-${Date.now()}-${Math.floor(Math.random() * 1e6)}`);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'mandate.json');
    const mandate = {
      id: 'b7-mandate', version: 1, issuer: 'test-operator',
      notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
      revokedVersions: [], signerAddress: A0, senders: [A0],
      chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:18545', name: 'sim-test' }],
      recipients: { allow: [A1, TOKEN], deny: [] },
      contracts: { allow: [TOKEN] }, selectors: { allow: ['0xa9059cbb'] },
      allowNativeTransfer: true, maxNativePerTxWei: '100000000000000000',
      approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
      spendingLimits: [], reviewRules: []
    };
    fs.writeFileSync(file, JSON.stringify(mandate), 'utf8');
    const loaded = loadMandate(file);
    assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
    fs.rmSync(dir, { recursive: true, force: true });
    loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
    const c = createAgentController({
      mandate: loaded.mandate, mandateError: null, mandateAuthorities: [OPERATOR_ADDR],
      approvalSecret: 'b7-approval-secret-0123456789abcdef',
      operatorSecret: 'b7-operator-secret-0123456789abcdef',
      approvalTtlMs: 300000, requestTtlMs: 900000,
      store: createAgentStore({ ledgerFile: null }), spendingLedger: createSpendingLedger({})
    });
    const realFetch = global.fetch;
    const origKey = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    const rpcReceipts = new Map();
    const rpcTxs = new Map();
    global.fetch = async (url, opts) => {
      let body = {};
      try { body = JSON.parse(opts && opts.body ? opts.body : '{}'); } catch { body = {}; }
      if (body.method === 'eth_getTransactionReceipt') {
        return { ok: true, json: async () => ({ result: rpcReceipts.get(body.params[0]) || null }) };
      }
      if (body.method === 'eth_getTransactionByHash') {
        return { ok: true, json: async () => ({ result: rpcTxs.get(body.params[0]) || null }) };
      }
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: JSON.stringify({
          verdict: 'MATCH', confidence: 0.95, summary: 'canned', discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
        }) } }] })
      };
    };
    const call = (fn, body, params) => new Promise((resolve) => {
      fn({ body, params: params || {} }, {
        statusCode: 200,
        status(code) { this.statusCode = code; return this; },
        json(payload) { resolve({ status: this.statusCode, body: payload }); }
      });
    });
    try {
      // 15a: native transfer, clean receipt -> EXECUTED + MATCHED.
      const p1 = await call(c.handlePropose, { agentId: 'b7', intent: { purpose: 'tip' },
        transaction: { from: A0, to: A1, data: '0x', value: '0x1000', chainId: '0x7a69' } });
      assert.strictEqual(p1.body.decision, 'ALLOW');
      const h1 = `0x${'11'.repeat(32)}`;
      rpcReceipts.set(h1, { status: '0x1', blockNumber: '0x5', gasUsed: '0x5208', logs: [] });
      rpcTxs.set(h1, { from: A0, to: A1, value: '0x1000' });
      const r1 = await call(c.handleReceipt, { txHash: h1 }, { id: p1.body.requestId });
      assert.strictEqual(r1.body.execution.outcome, 'EXECUTED');
      assert.strictEqual(r1.body.execution.verification.effects, 'EFFECTS_MATCHED');
      // 15b: ERC-20 transfer, short-paid log -> EFFECTS_DIVERGED.
      const data = encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 100n] });
      const p2 = await call(c.handlePropose, { agentId: 'b7', intent: { purpose: 'pay 100' },
        transaction: { from: A0, to: TOKEN, data, value: '0x0', chainId: '0x7a69' } });
      assert.strictEqual(p2.body.decision, 'ALLOW', JSON.stringify(p2.body));
      const h2 = `0x${'22'.repeat(32)}`;
      rpcReceipts.set(h2, { status: '0x1', blockNumber: '0x6', gasUsed: '0x6000', logs: [transferLog(TOKEN, A0, A1, 95n)] });
      rpcTxs.set(h2, { from: A0, to: TOKEN, value: '0x0' });
      const r2 = await call(c.handleReceipt, { txHash: h2 }, { id: p2.body.requestId });
      assert.strictEqual(r2.body.execution.outcome, 'EFFECTS_DIVERGED');
      assert.deepStrictEqual(r2.body.execution.verification.missing, ['EF-001']);
      // 15c: same transfer, exact log -> EXECUTED + MATCHED.
      const h3 = `0x${'33'.repeat(32)}`;
      const p3 = await call(c.handlePropose, { agentId: 'b7', intent: { purpose: 'pay 100' },
        transaction: { from: A0, to: TOKEN, data, value: '0x0', chainId: '0x7a69' } });
      rpcReceipts.set(h3, { status: '0x1', blockNumber: '0x7', gasUsed: '0x6000', logs: [transferLog(TOKEN, A0, A1, 100n)] });
      rpcTxs.set(h3, { from: A0, to: TOKEN, value: '0x0' });
      const r3 = await call(c.handleReceipt, { txHash: h3 }, { id: p3.body.requestId });
      assert.strictEqual(r3.body.execution.outcome, 'EXECUTED');
      assert.strictEqual(r3.body.execution.verification.effects, 'EFFECTS_MATCHED');
      console.log('✔ B7.15 Passed: recordExecution MATCHED/DIVERGED end to end (sim RPC).');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
  }

  console.log('\nAll Cap5 B7 Tests Passed Successfully!\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
