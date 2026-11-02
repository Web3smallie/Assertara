const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentStore } = require('../../src/services/agentStore');
const { createAgentController } = require('../../src/controllers/agentController');
const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
const { issueApproval, countersignApproval } = require('../../src/services/approvals');
const { digestTx } = require('../../extension/shared/txDigest');
const { createSigner } = require('../../src/signer/signerService');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Enforcement boundary: the agent holds no key and reaches the chain only
// through the approval-gated signer; the signer independently validates
// every binding and serves the local dev chain exclusively.

const ORIGINAL_KEY = config.modelApiKey;
const SIGNER_KEY = generatePrivateKey();
const SIGNER = privateKeyToAccount(SIGNER_KEY).address;
const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const APPROVAL_SECRET = 'enforce-test-approval-secret-0123456789ab';
const OPERATOR_SECRET = 'enforce-test-operator-secret-0123456789ab';

function fixtureMandate(overrides) {
  return {
    id: 'enforce-mandate', version: 2, issuer: 'test-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: SIGNER, senders: [SIGNER],
    chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:9', name: 'stub' }],
    recipients: { allow: [RECIPIENT], deny: [] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [],
    reviewRules: [{ when: 'nativeValueAboveWei', value: '10000000000000000' }],
    ...(overrides || {})
  };
}

function loadFixture(overrides) {
  const base = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(base, { recursive: true });
  const dir = fs.mkdtempSync(path.join(base, 'enforce-'));
  try {
    const file = path.join(dir, 'mandate.json');
    fs.writeFileSync(file, JSON.stringify(fixtureMandate(overrides)), 'utf8');
    const loaded = loadMandate(file);
    assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
    return loaded.mandate;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function mockReqRes(body, params) {
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const req = { body, params: params || {} };
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(payload) { resolve({ status: this.statusCode, body: payload }); }
  };
  return { req, res, done };
}

async function sealLoaded(mandate) {
  if (!mandate.seal) mandate.seal = await sealMandateObject(mandate, OPERATOR_KEY);
  return mandate;
}

async function makeController(mandate, store) {
  return createAgentController({
    mandate: await sealLoaded(mandate || loadFixture()),
    mandateError: null,
    mandateAuthorities: [OPERATOR_ADDR],
    approvalSecret: APPROVAL_SECRET,
    operatorSecret: OPERATOR_SECRET,
    approvalTtlMs: 300000,
    requestTtlMs: 900000,
    store: store || createAgentStore({}),
    spendingLedger: createSpendingLedger({})
  });
}

async function makeSigner(mandate, overrides, clients) {
  return createSigner({
    approvalSecret: APPROVAL_SECRET,
    operatorSecret: OPERATOR_SECRET,
    mandate: await sealLoaded(mandate || loadFixture()),
    mandateAuthorities: [OPERATOR_ADDR],
    privateKey: SIGNER_KEY,
    consumedFile: null,
    stateFile: null,
    policyCallbackUrl: null,
    clients,
    ...(overrides || {})
  });
}

function cannedFetch(verdict) {
  return async () => ({
    ok: true,
    json: async () => ({ choices: [{ message: { content: JSON.stringify({
      verdict, confidence: 0.9, summary: `canned ${verdict}`,
      discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
    }) } }] })
  });
}

function validTx(overrides) {
  return { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x2386f26fc10000', chainId: '0x7a69', ...(overrides || {}) };
}

function treeHashFor(tx) {
  const { decodeTransactionCalldata } = require('../../src/services/decoderService');
  const { hashSubcallTree } = require('../../src/services/nestedCalls');
  return hashSubcallTree(decodeTransactionCalldata({ to: tx.to, data: tx.data, value: tx.value }));
}

function approvalFor(tx, overrides) {
  return issueApproval({
    secret: APPROVAL_SECRET, requestId: 'agent_enf-1', txDigest: digestTx(tx),
    chainId: tx.chainId, sender: tx.from,
    mandateId: 'enforce-mandate', mandateVersion: 2, policyId: 'assertara-agent-mvp-1',
    requiresOperator: false, ttlMs: 300000, nowMs: Date.now(),
    subcallTreeHash: treeHashFor(tx),
    ...(overrides || {})
  });
}

const KEY_FRAGMENTS = [SIGNER_KEY.slice(2, 14), SIGNER_KEY.slice(-12)];

async function runEnforcementTests() {
  console.log('Testing execution enforcement boundary...\n');
  config.modelApiKey = 'test-live-key';
  const realFetch = global.fetch;

  // Test 1: no agent-facing response carries key material or secrets.
  {
    const c = await makeController();
    global.fetch = cannedFetch('MATCH');
    try {
      const p = mockReqRes({ agentId: 'probe', transaction: validTx() });
      await c.handlePropose(p.req, p.res);
      const proposed = await p.done;
      assert.strictEqual(proposed.status, 200);
      const blobs = [JSON.stringify(proposed.body)];
      const s = mockReqRes(null, { id: proposed.body.requestId });
      await c.handleStatus(s.req, s.res);
      blobs.push(JSON.stringify((await s.done).body));
      const big = mockReqRes({ transaction: validTx({ value: '0x470de4df820000' }) });
      await c.handlePropose(big.req, big.res);
      const reviewOut = await big.done;
      assert.strictEqual(reviewOut.body.decision, 'REVIEW');
      const a = mockReqRes({ operatorSecret: OPERATOR_SECRET }, { id: reviewOut.body.requestId });
      await c.handleAuthorize(a.req, a.res);
      blobs.push(JSON.stringify((await a.done).body));
      const m = mockReqRes(null, {});
      await c.handleMandateInfo(m.req, m.res);
      blobs.push(JSON.stringify((await m.done).body));
      for (const b of blobs) {
        for (const frag of KEY_FRAGMENTS) assert.ok(!b.includes(frag), 'signing key must never reach the agent');
        assert.ok(!b.includes(APPROVAL_SECRET) && !b.includes(OPERATOR_SECRET), 'no secret in agent responses');
        assert.ok(!b.includes('privateKey') && !b.includes('SIGNER_PRIVATE_KEY'), 'no key field names leak');
      }
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 1 Passed: Agent responses carry no key material.');
  }

  // Test 2: the ordinary evaluation API issues no signing authority.
  {
    global.fetch = cannedFetch('MATCH');
    try {
      const { req, res, done } = mockReqRes({
        pageContext: { title: 'Send 0.01 ETH', url: 'https://wallet.example/send' },
        transaction: validTx()
      });
      await handleEvaluateTransaction(req, res);
      const out = await done;
      assert.strictEqual(out.status, 200);
      assert.ok(!('approval' in out.body) && !('approvalToken' in out.body), 'evaluation issues no approval');
      assert.ok(!JSON.stringify(out.body).includes('apv1.'), 'no approval token smuggled in the bundle');
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 2 Passed: Evaluation API has no signing authority.');
  }

  // Test 3: smuggled mandate / operator / approval fields are ignored.
  {
    const c = await makeController();
    global.fetch = cannedFetch('MATCH');
    try {
      const evil = {
        agentId: 'smuggler',
        mandate: { id: 'evil', recipients: { allow: ['0x000000000000000000000000000000000000dEaD'] } },
        operatorSecret: OPERATOR_SECRET,
        approval: 'apv1.forged.signature',
        decision: 'ALLOW',
        transaction: validTx({ to: '0x000000000000000000000000000000000000dEaD' })
      };
      const { req, res, done } = mockReqRes(evil);
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.status, 200);
      assert.strictEqual(out.body.decision, 'BLOCK', 'smuggled mandate cannot allowlist');
      assert.strictEqual(out.body.mandate.id, 'enforce-mandate', 'operator mandate echoed, not the smuggled one');
      assert.strictEqual(out.body.approval, null);
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 3 Passed: Smuggled authority ignored.');
  }

  // Test 4: stale mandate versions rejected (signer + operator release).
  {
    const tx = validTx();
    const stale = approvalFor(tx, { mandateVersion: 1 });
    const v = (await makeSigner()).verify({ requestId: 'agent_enf-1', transaction: tx, approval: stale });
    assert.strictEqual(v.ok, false);
    assert.ok(/mandate/.test(v.error), 'stale approval version named');
    // Operator release after a mandate upgrade: the recorded version no
    // longer matches the active one, so authorization is refused.
    const store = createAgentStore({});
    const v2 = loadFixture();
    const v3 = loadFixture({ version: 3 });
    const c2 = await makeController(v2, store);
    global.fetch = cannedFetch('MATCH');
    try {
      const p = mockReqRes({ transaction: validTx({ value: '0x470de4df820000' }) });
      await c2.handlePropose(p.req, p.res);
      const id = (await p.done).body.requestId;
      const c3 = await makeController(v3, store);
      const a = mockReqRes({ operatorSecret: OPERATOR_SECRET }, { id });
      await c3.handleAuthorize(a.req, a.res);
      const auth = await a.done;
      assert.strictEqual(auth.status, 409, 'cross-version authorize refused');
      assert.ok(/mandate changed/.test(auth.body.error));
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 4 Passed: Stale mandate versions rejected.');
  }

  // Test 5: altered payload, unsupported chain, missing approval refused.
  {
    const tx = validTx();
    const good = approvalFor(tx);
    const s = await makeSigner();
    const mutatedTo = { ...tx, to: '0x70997970C51812dc3A010C7d01b50e0d17dc79c9' };
    const m = s.verify({ requestId: 'agent_enf-1', transaction: mutatedTo, approval: good });
    assert.strictEqual(m.ok, false);
    assert.ok(/digest/.test(m.error), 'one-nibble mutation breaks the digest');
    const foreignTx = validTx({ chainId: '0x1' });
    const foreign = approvalFor(foreignTx, { chainId: '0x1' });
    const f = s.verify({ requestId: 'agent_enf-1', transaction: foreignTx, approval: foreign });
    assert.strictEqual(f.ok, false);
    assert.ok(/chain/.test(f.error), 'unsupported chain refused');
    const noApproval = s.verify({ requestId: 'agent_enf-1', transaction: tx, approval: undefined });
    assert.strictEqual(noApproval.ok, false, 'approval is mandatory: no generic signing');
    const garbage = s.verify({ requestId: 'agent_enf-1', transaction: tx, approval: 'apv1.evil.sig' });
    assert.strictEqual(garbage.ok, false, 'forged approval rejected');
    console.log('✔ Test 5 Passed: Mutation, foreign chain, missing/forged approvals refused.');
  }

  // Test 6: operator-gated approvals need the operator secret present.
  {
    const tx = validTx();
    const nonce = 'enf-op-nonce-6';
    const pending = approvalFor(tx, { requiresOperator: true, nonce });
    const body = JSON.parse(Buffer.from(pending.split('.')[1], 'base64url').toString('utf8'));
    assert.strictEqual(body.requiresOperator, true);
    const withOp = await makeSigner();
    const ok = withOp.verify({
      requestId: 'agent_enf-1', transaction: tx,
      approval: issueApproval({
        secret: APPROVAL_SECRET, requestId: 'agent_enf-1', txDigest: digestTx(tx),
        chainId: tx.chainId, sender: tx.from, mandateId: 'enforce-mandate',
        mandateVersion: 2, policyId: 'assertara-agent-mvp-1', subcallTreeHash: treeHashFor(tx),
        requiresOperator: true, ttlMs: 300000, nowMs: Date.now(), nonce
      })
    });
    assert.strictEqual(ok.ok, false, 'unsigned operator approval refused even with secret configured');
    const noOp = await makeSigner(null, { operatorSecret: null });
    const pendingSig = countersignApproval({ secret: APPROVAL_SECRET, token: pending, operatorSecret: OPERATOR_SECRET, nowMs: Date.now() });
    assert.strictEqual(pendingSig.ok, true);
    const refused = noOp.verify({ requestId: 'agent_enf-1', transaction: tx, approval: pendingSig.token });
    assert.strictEqual(refused.ok, false);
    assert.ok(/operator/.test(refused.error), 'missing operator secret cannot honor countersigned approvals');
    console.log('✔ Test 6 Passed: Operator gating exact.');
  }

  // Test 7: unsupported transaction types rejected at execution.
  {
    const tx = validTx({ type: '0x1' });
    const approval = approvalFor(tx);
    const f = {
      wallet: { sendTransaction: async () => { throw new Error('must not broadcast'); } },
      public: { getTransactionCount: async () => 7, getBalance: async () => 1n, waitForTransactionReceipt: async () => ({}) }
    };
    const out = await (await makeSigner(null, null, f)).execute({ requestId: 'agent_enf-1', transaction: tx, approval });
    assert.strictEqual(out.ok, false);
    assert.strictEqual(out.code, 'BAD_REQUEST');
    assert.ok(/unsupported transaction type/.test(out.error));
    console.log('✔ Test 7 Passed: Unsupported transaction type rejected.');
  }

  // Test 8: signer serves the local dev chain only.
  {
    await assert.rejects(() => makeSigner(loadFixture({ chains: [{ id: 1, rpcUrl: 'https://cloudflare-eth.com', name: 'mainnet' }] })),
      /not the local dev chain/, 'mainnet refused');
    await assert.rejects(() => makeSigner(loadFixture({ chains: [{ id: 11155111, rpcUrl: 'https://rpc.sepolia.org', name: 'sepolia' }] })),
      /not the local dev chain/, 'public testnet refused');
    await assert.rejects(() => makeSigner(loadFixture({ chains: [{ id: 31337, rpcUrl: 'http://192.168.1.10:8545', name: 'lan' }] })),
      /not the local dev chain/, 'non-loopback RPC refused');
    await assert.rejects(() => makeSigner(loadFixture({ chains: [] })), /no chains/, 'empty chain list refused');
    const local = await makeSigner(loadFixture({ chains: [{ id: 31337, rpcUrl: 'http://localhost:8545', name: 'anvil' }] }));
    assert.strictEqual(local.chainIds[0], '0x7a69', 'loopback 31337 boots');
    console.log('✔ Test 8 Passed: Dev-chain restriction exact.');
  }

  config.modelApiKey = ORIGINAL_KEY;
  await closeOcrWorker();
  console.log('\nAll Enforcement Boundary Tests Passed Successfully!\n');
}

if (require.main === module) {
  runEnforcementTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runEnforcementTests };
