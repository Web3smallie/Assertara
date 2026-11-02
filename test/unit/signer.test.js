const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { issueApproval, operatorSignature } = require('../../src/services/approvals');
const { digestTx } = require('../../extension/shared/txDigest');
const { createSigner } = require('../../src/signer/signerService');

// Controlled signer: verification battery and execute path with injected
// fake chain clients. Real Anvil execution lives in the e2e suite.

const APPROVAL_SECRET = 'signer-test-approval-secret-0123456789ab';
const OPERATOR_SECRET = 'signer-test-operator-secret-0123456789ab';
// Fresh random key per run (no chain here): mandate and approvals derive
// from the same generated address, so no hardcoded key material exists.
const SIGNER_KEY = generatePrivateKey();
const SIGNER_ADDR = privateKeyToAccount(SIGNER_KEY).address;
// Test-only operator sealing key (never touches a chain): every fixture
// mandate is sealed so construction exercises the verified path.
const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const NOW = 1780000000000;

function fixtureMandate(overrides) {
  return {
    id: 'signer-test-mandate', version: 2, issuer: 'test-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: SIGNER_ADDR, senders: [SIGNER_ADDR],
    chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:9', name: 'fake' }],
    recipients: { allow: [RECIPIENT], deny: [] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [],
    reviewRules: [],
    ...(overrides || {})
  };
}

function loadFixture(overrides) {
  const base = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(base, { recursive: true });
  const dir = fs.mkdtempSync(path.join(base, 'signer-test-'));
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

function baseTx(overrides) {
  return { from: SIGNER_ADDR, to: RECIPIENT, data: '0x', value: '0x2386f26fc10000', chainId: '0x7a69', ...(overrides || {}) };
}

function treeHashFor(tx) {
  const { decodeTransactionCalldata } = require('../../src/services/decoderService');
  const { hashSubcallTree } = require('../../src/services/nestedCalls');
  return hashSubcallTree(decodeTransactionCalldata({ to: tx.to, data: tx.data, value: tx.value }));
}

function approvalFor(signer, tx, overrides) {
  void signer;
  return issueApproval({
    secret: APPROVAL_SECRET, requestId: 'agent_sig-1', txDigest: digestTx(tx),
    chainId: tx.chainId, sender: tx.from,
    mandateId: 'signer-test-mandate', mandateVersion: 2, policyId: 'assertara-agent-mvp-1',
    requiresOperator: false, ttlMs: 300000, nowMs: NOW, nonce: 'sig-nonce-1',
    subcallTreeHash: treeHashFor(tx),
    ...(overrides || {})
  });
}

async function sealLoaded(mandate) {
  if (!mandate.seal) mandate.seal = await sealMandateObject(mandate, OPERATOR_KEY);
  return mandate;
}

async function makeSigner(overrides, clients) {
  const { mandate: overrideMandate, ...rest } = overrides || {};
  const explicitNull = overrides && Object.hasOwn(overrides, 'mandate') && overrideMandate === null;
  const mandate = explicitNull ? null : await sealLoaded(overrideMandate || loadFixture());
  return createSigner({
    approvalSecret: APPROVAL_SECRET,
    operatorSecret: OPERATOR_SECRET,
    mandate,
    mandateAuthorities: [OPERATOR_ADDR],
    privateKey: SIGNER_KEY,
    consumedFile: null,
    policyCallbackUrl: null,
    nowFn: () => NOW,
    clients,
    ...rest
  });
}

function fakeClients(overrides) {
  const calls = { send: 0, nonce: 0, balance: 0, receipt: 0 };
  return {
    calls,
    clients: {
      wallet: {
        sendTransaction: async (tx) => {
          calls.send += 1;
          if (overrides && overrides.sendThrows) throw new Error('mock broadcast failure');
          if (!tx.to || tx.value === undefined || tx.nonce === undefined || tx.chainId === undefined) {
            throw new Error('mock chain: incomplete tx assembly');
          }
          return `0x${'ab'.repeat(31)}01`;
        }
      },
      public: {
        getTransactionCount: async () => { calls.nonce += 1; return 7; },
        getBalance: async ({ address }) => {
          calls.balance += 1;
          const base = 1000000000000000000000n;
          if (overrides && overrides.balanceAfter === true && calls.balance > 1) return base + 10n ** 16n;
          return base;
        },
        waitForTransactionReceipt: async () => {
          calls.receipt += 1;
          if (overrides && overrides.receiptThrows) throw new Error('mock receipt timeout');
          return { status: (overrides && overrides.receiptStatus) || '0x1', blockNumber: '0x5', gasUsed: '0x5208' };
        }
      }
    }
  };
}

async function runSignerTests() {
  console.log('Testing controlled signer (verify + execute)...\n');

  // Test 1: creation guards; key never exposed.
  {
    await assert.rejects(() => makeSigner({ approvalSecret: 'short' }), /APPROVAL_SECRET/);
    await assert.rejects(() => makeSigner({ privateKey: '0x1234' }), /SIGNER_PRIVATE_KEY/);
    await assert.rejects(() => makeSigner({ privateKey: '0x' + '11'.repeat(32) }), /does not match the mandate/);
    await assert.rejects(() => makeSigner({ mandate: null }), /active mandate/);
    await assert.rejects(() => makeSigner({ mandateAuthorities: [] }), /authority is not configured/);
    await assert.rejects(() => createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: loadFixture(), mandateAuthorities: [OPERATOR_ADDR],
      privateKey: SIGNER_KEY, consumedFile: null, policyCallbackUrl: null, nowFn: () => NOW
    }), /not sealed/, 'unsealed mandate refuses construction');
    const s = await makeSigner();
    assert.strictEqual(s.address, SIGNER_ADDR.toLowerCase());
    assert.ok(!('privateKey' in s) && !JSON.stringify(s).includes(SIGNER_KEY.slice(2, 12)), 'key material never exposed');
    console.log('✔ Test 1 Passed: Creation guards exact.');
  }

  // Test 2: verification battery — every refusal path.
  {
    const s = await makeSigner();
    const tx = baseTx();
    const good = approvalFor(s, tx);
    assert.strictEqual(s.verify({ requestId: 'agent_sig-1', transaction: tx, approval: good }).ok, true, 'valid approval verifies');
    const badCases = [
      ['bad hmac', { requestId: 'agent_sig-1', transaction: tx, approval: `${good.slice(0, -1)}${good.endsWith('0') ? '1' : '0'}` }],
      ['wrong request', { requestId: 'agent_other', transaction: tx, approval: good }],
      ['mutated value', { requestId: 'agent_sig-1', transaction: baseTx({ value: '0x2386f26fc10001' }), approval: good }],
      ['mutated recipient', { requestId: 'agent_sig-1', transaction: baseTx({ to: SIGNER_ADDR }), approval: good }],
      ['added field', { requestId: 'agent_sig-1', transaction: baseTx({ gasPrice: '0x1' }), approval: good }],
      ['wrong chain tx', { requestId: 'agent_sig-1', transaction: baseTx({ chainId: '0x1' }), approval: good }],
      ['wrong sender', { requestId: 'agent_sig-1', transaction: baseTx({ from: RECIPIENT }), approval: good }],
      ['bad to', { requestId: 'agent_sig-1', transaction: baseTx({ to: '0x123' }), approval: good }],
      ['null tx', { requestId: 'agent_sig-1', transaction: null, approval: good }],
      ['null approval', { requestId: 'agent_sig-1', transaction: tx, approval: null }],
      ['missing tree binding', {
        requestId: 'agent_sig-1', transaction: tx,
        approval: approvalFor(s, tx, { subcallTreeHash: null })
      }],
      ['malformed tree binding', {
        requestId: 'agent_sig-1', transaction: tx,
        approval: approvalFor(s, tx, { subcallTreeHash: 'not-a-hash' })
      }],
      ['tree binding mismatch', {
        requestId: 'agent_sig-1', transaction: tx,
        approval: approvalFor(s, tx, { subcallTreeHash: '00'.repeat(32) })
      }]
    ];
    for (const [label, args] of badCases) {
      const v = s.verify(args);
      assert.strictEqual(v.ok, false, `${label} must be refused`);
      assert.ok(v.code === 'REFUSED' || v.code === 'BAD_REQUEST', `${label}: coded refusal`);
    }
    // Expired approval.
    const old = approvalFor(s, tx, { nonce: 'sig-nonce-old' });
    const sLate = await makeSigner({}, null);
    const sLate2 = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET, mandate: await sealLoaded(loadFixture()),
      mandateAuthorities: [OPERATOR_ADDR],
      privateKey: SIGNER_KEY, consumedFile: null, policyCallbackUrl: null, nowFn: () => NOW + 300001
    });
    assert.strictEqual(sLate2.verify({ requestId: 'agent_sig-1', transaction: tx, approval: old }).ok, false, 'expired refused');
    void sLate;
    // Operator-gated approval without/with countersignature.
    const gated = approvalFor(s, tx, { requiresOperator: true, nonce: 'sig-nonce-op' });
    assert.strictEqual(s.verify({ requestId: 'agent_sig-1', transaction: tx, approval: gated }).ok, false, 'missing countersignature refused');
    const sig = operatorSignature({ operatorSecret: OPERATOR_SECRET, nonce: 'sig-nonce-op' });
    const noSig = operatorSignature({ operatorSecret: 'wrong-operator-secret-000000000000', nonce: 'sig-nonce-op' });
    void noSig;
    // Countersignature travels inside a re-issued token (see approvals suite);
    // here we verify the signer checks it by minting through countersign.
    const { countersignApproval } = require('../../src/services/approvals');
    const signed = countersignApproval({ secret: APPROVAL_SECRET, token: gated, operatorSecret: OPERATOR_SECRET, nowMs: NOW });
    assert.strictEqual(signed.ok, true);
    assert.strictEqual(s.verify({ requestId: 'agent_sig-1', transaction: tx, approval: signed.token }).ok, true, 'countersigned approval verifies');
    assert.ok(sig.length === 64, 'operator signature shape');
    // Mandate drift.
    const otherMandate = await makeSigner({ mandate: loadFixture({ version: 3 }) });
    assert.strictEqual(otherMandate.verify({ requestId: 'agent_sig-1', transaction: tx, approval: good }).ok, false, 'rotated mandate refuses old approval');
    console.log('✔ Test 2 Passed: Every refusal path exact.');
  }

  // Test 3: execute success, replay, and ordering with fake chain.
  {
    const f = fakeClients({ balanceAfter: true });
    const s = await makeSigner({}, f.clients);
    const tx = baseTx();
    const token = approvalFor(s, tx, { nonce: 'sig-exec-1' });
    const out = await s.execute({ requestId: 'agent_sig-1', transaction: tx, approval: token });
    assert.strictEqual(out.ok, true, JSON.stringify(out.error || 'ok'));
    assert.ok(/^0x[0-9a-f]+$/.test(out.txHash), 'tx hash returned');
    assert.strictEqual(out.receipt.status, '0x1');
    assert.strictEqual(out.verification.balanceDeltaOk, true, 'recipient delta verified');
    assert.strictEqual(f.calls.send, 1);
    const replay = await s.execute({ requestId: 'agent_sig-1', transaction: tx, approval: token });
    assert.strictEqual(replay.ok, false, 'replay refused');
    assert.ok(/already consumed/.test(replay.error));
    assert.strictEqual(f.calls.send, 1, 'replay never re-broadcasts');
    // Mutated retry never reaches the chain.
    const f2 = fakeClients({});
    const s2 = await makeSigner({}, f2.clients);
    const mut = await s2.execute({ requestId: 'agent_sig-1', transaction: baseTx({ value: '0x2' }), approval: token });
    assert.strictEqual(mut.ok, false);
    assert.strictEqual(f2.calls.send, 0, 'mutated payload never broadcasts');
    console.log('✔ Test 3 Passed: Execute, replay, mutation ordering.');
  }

  // Test 4: broadcast failure burns the approval (fail closed, no retry).
  {
    const f = fakeClients({ sendThrows: true });
    const s = await makeSigner({}, f.clients);
    const tx = baseTx();
    const token = approvalFor(s, tx, { nonce: 'sig-exec-2' });
    const out = await s.execute({ requestId: 'agent_sig-1', transaction: tx, approval: token });
    assert.strictEqual(out.ok, false);
    assert.strictEqual(out.code, 'CHAIN_ERROR');
    const retry = await s.execute({ requestId: 'agent_sig-1', transaction: tx, approval: token });
    assert.strictEqual(retry.ok, false, 'failed broadcast cannot be retried with the same approval');
    assert.ok(/already consumed/.test(retry.error));
    console.log('✔ Test 4 Passed: Broadcast failure burns approval.');
  }

  // Test 5: receipt wait failure still reports the broadcast honestly.
  {
    const f = fakeClients({ receiptThrows: true });
    const s = await makeSigner({}, f.clients);
    const out = await s.execute({ requestId: 'agent_sig-1', transaction: baseTx(), approval: approvalFor(s, baseTx(), { nonce: 'sig-exec-3' }) });
    assert.strictEqual(out.ok, true, 'broadcast happened');
    assert.strictEqual(out.broadcast, true);
    assert.strictEqual(out.receipt, null, 'no receipt invented');
    assert.strictEqual(out.verification.receiptVerified, false);
    // Status-0 receipts are reported, not hidden.
    const f0 = fakeClients({ receiptStatus: '0x0' });
    const s0 = await makeSigner({}, f0.clients);
    const out0 = await s0.execute({ requestId: 'agent_sig-1', transaction: baseTx(), approval: approvalFor(s0, baseTx(), { nonce: 'sig-exec-4' }) });
    assert.strictEqual(out0.receipt.status, '0x0', 'revert status surfaced');
    console.log('✔ Test 5 Passed: Receipt outcomes honest.');
  }

  // Test 6: consumed nonces persist across restarts; corrupt log fails startup.
  {
    const base = path.join(__dirname, '..', 'tmp');
    fs.mkdirSync(base, { recursive: true });
    const dir = fs.mkdtempSync(path.join(base, 'signer-consumed-'));
    try {
      const file = path.join(dir, 'consumed.jsonl');
      const f = fakeClients({});
      const s = await makeSigner({ consumedFile: file }, f.clients);
      const tx = baseTx();
      const token = approvalFor(s, tx, { nonce: 'sig-exec-5' });
      assert.strictEqual((await s.execute({ requestId: 'agent_sig-1', transaction: tx, approval: token })).ok, true);
      const s2 = await makeSigner({ consumedFile: file }, fakeClients({}).clients);
      const replay = await s2.execute({ requestId: 'agent_sig-1', transaction: tx, approval: token });
      assert.strictEqual(replay.ok, false, 'restart does not resurrect approvals');
      fs.appendFileSync(file, 'corrupt-line{{{\n', 'utf8');
      await assert.rejects(() => makeSigner({ consumedFile: file }), /refusing to start/, 'corrupt log fails startup');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    console.log('✔ Test 6 Passed: Single-use survives restarts.');
  }

  // Test 7 (Capability 5 B1): subcall-tree binding on batched calls.
  {
    const { encodeFunctionData } = require('viem');
    const { UNISWAP_V3_ROUTER_ABI, ERC20_ABI } = require('../../src/utils/abiSignatures');
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const inner = (to, amount) => encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [to, amount] });
    const batchOf = (inners) => encodeFunctionData({ abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [inners] });
    const s = await makeSigner();
    const batchTx = { from: SIGNER_ADDR, to: ROUTER, data: batchOf([inner(RECIPIENT, 100n)]), value: '0x0', chainId: '0x7a69' };
    const bound = issueApproval({
      secret: APPROVAL_SECRET, requestId: 'agent_sig-7', txDigest: digestTx(batchTx),
      chainId: batchTx.chainId, sender: batchTx.from,
      mandateId: 'signer-test-mandate', mandateVersion: 2, policyId: 'assertara-agent-mvp-1',
      requiresOperator: false, ttlMs: 300000, nowMs: NOW, nonce: 'sig-nonce-7',
      subcallTreeHash: treeHashFor(batchTx)
    });
    assert.strictEqual(s.verify({ requestId: 'agent_sig-7', transaction: batchTx, approval: bound }).ok, true, 'batch with matching tree binding verifies');
    // Inner mutation changes the approved bytes: the digest layer
    // refuses first (documenting defense order); the tree layer is the
    // backstop pinned by the mismatch case in Test 2.
    const mutated = { ...batchTx, data: batchOf([inner(RECIPIENT, 101n)]) };
    const v = s.verify({ requestId: 'agent_sig-7', transaction: mutated, approval: bound });
    assert.strictEqual(v.ok, false, 'mutated batch refused');
    assert.ok(/digest/.test(v.error), 'digest layer fires first on mutated bytes');
    console.log('✔ Test 7 Passed: Batched approval bound to authorized subcall tree.');
  }

  console.log('\nAll Controlled Signer Tests Passed Successfully!\n');
}

if (require.main === module) {
  runSignerTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSignerTests };
