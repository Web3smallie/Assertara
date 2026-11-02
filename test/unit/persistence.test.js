const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { loadMandate, evaluateMandate, checkMandateContinuity, sealMandateObject } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentStore } = require('../../src/services/agentStore');
const { createAgentController } = require('../../src/controllers/agentController');
const { issueApproval } = require('../../src/services/approvals');
const { digestTx } = require('../../extension/shared/txDigest');
const { createSigner } = require('../../src/signer/signerService');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Persistence + restart recovery: security state must survive process
// restarts (requests, decisions, approvals, nonces, mandate continuity,
// spending, receipts), and corrupt or missing state must fail closed.
// Restarts are simulated by constructing fresh services over the same
// files — the same code path a real process restart executes. Chain RPC
// is stubbed at the fetch layer (MOCKED); Anvil-level proof stays in e2e.
const ORIGINAL_KEY = config.modelApiKey;

const SIGNER_KEY = generatePrivateKey();
const SIGNER = privateKeyToAccount(SIGNER_KEY).address;
const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const APPROVAL_SECRET = 'persist-test-approval-secret-0123456789ab';
const OPERATOR_SECRET = 'persist-test-operator-secret-0123456789ab';

function fixtureMandate(overrides) {
  return {
    id: 'persist-mandate', version: 2, issuer: 'test-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: SIGNER, senders: [SIGNER],
    chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:9', name: 'stub' }],
    recipients: { allow: [RECIPIENT], deny: [] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [{ windowMs: 86400000, maxNativeWei: '1000000000000000000' }],
    reviewRules: [{ when: 'nativeValueAboveWei', value: '10000000000000000' }],
    ...(overrides || {})
  };
}

function scratchDir(label) {
  const base = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(base, { recursive: true });
  return fs.mkdtempSync(path.join(base, `${label}-`));
}

async function writeMandate(dir, overrides) {
  const file = path.join(dir, 'mandate.json');
  fs.writeFileSync(file, JSON.stringify(fixtureMandate(overrides)), 'utf8');
  const loaded = loadMandate(file);
  assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
  loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
  return { file, mandate: loaded.mandate };
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

// Store + controller pair over one directory; rebuilding the pair over the
// same directory simulates a restart.
function bootPolicy(dir, { mandate, ledger } = {}) {
  const store = createAgentStore({
    ledgerFile: path.join(dir, 'agent-ledger.jsonl'),
    snapshotFile: path.join(dir, 'agent-requests.json')
  });
  const loaded = store.load();
  assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
  const controller = createAgentController({
    mandate: mandate || null,
    mandateError: mandate ? null : 'no mandate',
    mandateAuthorities: [OPERATOR_ADDR],
    approvalSecret: APPROVAL_SECRET,
    operatorSecret: OPERATOR_SECRET,
    approvalTtlMs: 300000,
    requestTtlMs: 900000,
    store,
    spendingLedger: ledger || createSpendingLedger({})
  });
  return { store, controller };
}

// Model transport canned (MOCKED verdict); chain RPC answered from a script:
// { receipts: {hash: receipt|null}, txs: {hash: tx|null} }.
function routedFetch(modelVerdict, chain) {
  return async (url, opts) => {
    if (typeof url === 'string' && url.startsWith(config.metaApiBaseUrl)) {
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: JSON.stringify({
          verdict: modelVerdict, confidence: 0.9, summary: `canned ${modelVerdict}`,
          discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
        }) } }] })
      };
    }
    let method = '';
    let hash = '';
    try {
      const body = JSON.parse(opts.body);
      method = body.method;
      hash = body.params && body.params[0];
    } catch { /* fall through to empty result */ }
    const result = method === 'eth_getTransactionReceipt'
      ? ((chain.receipts || {})[hash] ?? null)
      : method === 'eth_getTransactionByHash'
        ? ((chain.txs || {})[hash] ?? null)
        : null;
    return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) };
  };
}

function validTx(overrides) {
  return { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x2386f26fc10000', chainId: '0x7a69', ...(overrides || {}) };
}

function treeHashFor(tx) {
  const { decodeTransactionCalldata } = require('../../src/services/decoderService');
  const { hashSubcallTree } = require('../../src/services/nestedCalls');
  return hashSubcallTree(decodeTransactionCalldata({ to: tx.to, data: tx.data, value: tx.value }));
}

async function proposeOk(controller, tx) {
  const { req, res, done } = mockReqRes({ agentId: 'persist-agent', transaction: tx || validTx() });
  await controller.handlePropose(req, res);
  const out = await done;
  assert.strictEqual(out.status, 200, JSON.stringify(out.body));
  return out.body;
}

function fakeClients() {
  const calls = { send: 0 };
  return {
    calls,
    clients: {
      wallet: {
        sendTransaction: async (tx) => {
          calls.send += 1;
          if (!tx.to || tx.value === undefined || tx.nonce === undefined || tx.chainId === undefined) {
            throw new Error('mock chain: incomplete tx assembly');
          }
          return `0x${'cd'.repeat(32)}`;
        }
      },
      public: {
        getTransactionCount: async () => 7,
        getBalance: async () => 1000000000000000000000n,
        waitForTransactionReceipt: async () => ({ status: '0x1', blockNumber: '0x5', gasUsed: '0x5208' })
      }
    }
  };
}

async function runPersistenceTests() {
  console.log('Testing persistence + restart recovery...\n');
  config.modelApiKey = 'test-live-key';
  const realFetch = global.fetch;

  // Test 1: approval + decision survive a policy restart with correct status.
  {
    const dir = scratchDir('persist-t1');
    const { mandate } = await writeMandate(dir);
    global.fetch = routedFetch('MATCH', {});
    let id;
    let token;
    try {
      const first = bootPolicy(dir, { mandate });
      const out = await proposeOk(first.controller);
      assert.strictEqual(out.decision, 'ALLOW');
      id = out.requestId;
      token = out.approval;
      assert.ok(token, 'ALLOW issues a token');
      assert.strictEqual(first.store.create({ id, createdAt: Date.now(), normalizedTx: {}, txDigest: 'x' }), null, 'duplicate request id rejected');
    } finally {
      global.fetch = realFetch;
    }
    assert.ok(fs.existsSync(path.join(dir, 'agent-requests.json')), 'snapshot written');
    const second = bootPolicy(dir, { mandate });
    assert.strictEqual(second.store.size(), 1, 'request restored');
    const st = mockReqRes(null, { id });
    await second.controller.handleStatus(st.req, st.res);
    const status = await st.done;
    assert.strictEqual(status.status, 200);
    assert.strictEqual(status.body.status, 'APPROVED');
    assert.strictEqual(status.body.decision, 'ALLOW');
    assert.strictEqual(status.body.approvalToken, token, 'same approval token after restart');
    assert.strictEqual(status.body.execution, null, 'no execution invented by restart');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 1 Passed: Approval status survives restart.');
  }

  // Test 2: consumed approval replay rejected after a signer restart.
  {
    const dir = scratchDir('persist-t2');
    const { mandate } = await writeMandate(dir);
    const consumedFile = path.join(dir, 'consumed.jsonl');
    const stateFile = path.join(dir, 'signer-state.json');
    const tx = validTx();
    const approval = issueApproval({
      secret: APPROVAL_SECRET, requestId: 'agent_persist-2', txDigest: digestTx(tx),
      chainId: tx.chainId, sender: tx.from, mandateId: 'persist-mandate',
      mandateVersion: 2, policyId: 'assertara-agent-mvp-1', subcallTreeHash: treeHashFor(tx),
      requiresOperator: false, ttlMs: 300000, nowMs: Date.now(), nonce: 'persist-nonce-2'
    });
    const mk = (clients) => createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY, consumedFile, stateFile,
      policyCallbackUrl: null, clients
    });
    const f1 = fakeClients();
    const first = await mk(f1.clients);
    const exec = await first.execute({ requestId: 'agent_persist-2', transaction: tx, approval });
    assert.strictEqual(exec.ok, true, JSON.stringify(exec.error || 'executed'));
    assert.strictEqual(f1.calls.send, 1);
    const second = await mk(fakeClients().clients); // restart over the same files
    assert.strictEqual(second.consumedCount(), 1, 'consumed nonce reloaded');
    const replay = await second.execute({ requestId: 'agent_persist-2', transaction: tx, approval });
    assert.strictEqual(replay.ok, false);
    assert.ok(/already consumed/.test(replay.error), 'replay refused after restart');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 2 Passed: Replay rejected after signer restart.');
  }

  // Test 3: mandate version + revocation persist; rollback refused.
  {
    const dir = scratchDir('persist-t3');
    const v2 = (await writeMandate(dir)).mandate;
    const store = createAgentStore({ ledgerFile: path.join(dir, 'a.jsonl'), snapshotFile: path.join(dir, 's.json') });
    assert.strictEqual(store.load().ok, true);
    assert.strictEqual(store.setLastMandate({ id: v2.id, version: 2 }), true);
    const store2 = createAgentStore({ ledgerFile: path.join(dir, 'a.jsonl'), snapshotFile: path.join(dir, 's.json') });
    assert.strictEqual(store2.load().ok, true);
    assert.deepStrictEqual(store2.getLastMandate(), { id: 'persist-mandate', version: 2 }, 'version survives restart');
    const v1 = { ...v2, version: 1 };
    v1.seal = await sealMandateObject(v1, OPERATOR_KEY); // properly sealed as v1: reaches continuity, not seal failure
    assert.strictEqual(checkMandateContinuity({ last: store2.getLastMandate(), current: v1 }).ok, false, 'rollback refused');
    assert.strictEqual(checkMandateContinuity({ last: store2.getLastMandate(), current: v2 }).ok, true, 'same version boots');
    assert.strictEqual(checkMandateContinuity({ last: store2.getLastMandate(), current: { ...v2, version: 3 } }).ok, true, 'upgrade boots');
    assert.strictEqual(checkMandateContinuity({ last: store2.getLastMandate(), current: { ...v2, id: 'other', version: 1 } }).ok, true, 'rotation boots');
    // Revocation lives in the operator file re-read at boot: a restarted
    // service loading a revoked version must enforce it everywhere.
    const revoked = (await writeMandate(dir, { revokedVersions: [2] })).mandate;
    assert.strictEqual(
      evaluateMandate({ mandate: revoked, mandateError: null, tx: validTx(), decodedTx: { functionName: 'unknownFunction' }, nowMs: Date.now(), ledger: null }).decision,
      'BLOCK', 'revoked version blocks after reload');
    const signer = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: revoked, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY, consumedFile: null, stateFile: null,
      policyCallbackUrl: null, clients: fakeClients().clients
    });
    const tx = validTx();
    const bad = signer.verify({
      requestId: 'agent_rev', transaction: tx,
      approval: issueApproval({
        secret: APPROVAL_SECRET, requestId: 'agent_rev', txDigest: digestTx(tx),
        chainId: tx.chainId, sender: tx.from, mandateId: 'persist-mandate',
        mandateVersion: 2, policyId: 'assertara-agent-mvp-1',
        requiresOperator: false, ttlMs: 300000, nowMs: Date.now()
      })
    });
    assert.strictEqual(bad.ok, false, 'signer refuses revoked mandate');
    // Signer boot itself rejects a version rollback on disk.
    const stateFile = path.join(dir, 'signer-state.json');
    await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: v2, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY, consumedFile: null, stateFile,
      policyCallbackUrl: null, clients: fakeClients().clients
    });
    await assert.rejects(() => createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: v1, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY, consumedFile: null, stateFile,
      policyCallbackUrl: null, clients: fakeClients().clients
    }), /rollback/, 'signer refuses rollback at boot');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 3 Passed: Mandate version/revocation enforced across restarts.');
  }

  // Test 4: spending survives restart; limits never reset silently.
  {
    const dir = scratchDir('persist-t4');
    const { mandate } = await writeMandate(dir);
    const file = path.join(dir, 'spending.jsonl');
    const a = createSpendingLedger({ filePath: file });
    assert.strictEqual(a.load().ok, true);
    a.record({ chainId: '0x7a69', wei: '995000000000000000', requestId: 'r-old', txHash: '0xaaa', atMs: Date.now() - 1000 });
    const b = createSpendingLedger({ filePath: file }); // restart
    assert.strictEqual(b.load().ok, true);
    assert.strictEqual(b.spentWithin({ chainId: '0x7a69', windowMs: 86400000, nowMs: Date.now() }), '995000000000000000');
    const verdict = evaluateMandate({
      mandate, mandateError: null, tx: validTx(), decodedTx: { functionName: 'unknownFunction' },
      nowMs: Date.now(), ledger: b
    });
    assert.strictEqual(verdict.decision, 'BLOCK', 'reloaded spending still overflows the window');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 4 Passed: Spending limits survive restart.');
  }

  // Test 5: transaction hash + verified receipt survive restart accurately.
  {
    const dir = scratchDir('persist-t5');
    const { mandate } = await writeMandate(dir);
    const hash = `0x${'ee'.repeat(32)}`;
    const tx = validTx();
    const chain = {
      receipts: { [hash]: { status: '0x1', blockNumber: '0x9', gasUsed: '0x5208', logs: [] } },
      txs: { [hash]: { from: tx.from, to: tx.to, value: tx.value } }
    };
    global.fetch = routedFetch('MATCH', chain);
    let id;
    try {
      const first = bootPolicy(dir, { mandate });
      const out = await proposeOk(first.controller, tx);
      assert.strictEqual(out.decision, 'ALLOW');
      id = out.requestId;
      const rc = mockReqRes({ txHash: hash }, { id });
      await first.controller.handleReceipt(rc.req, rc.res);
      const recorded = await rc.done;
      assert.strictEqual(recorded.status, 200, JSON.stringify(recorded.body));
      assert.strictEqual(recorded.body.execution.outcome, 'EXECUTED');
    } finally {
      global.fetch = realFetch;
    }
    const second = bootPolicy(dir, { mandate }); // restart
    const st = mockReqRes(null, { id });
    await second.controller.handleStatus(st.req, st.res);
    const status = await st.done;
    assert.strictEqual(status.body.execution.outcome, 'EXECUTED', 'outcome survives restart');
    assert.strictEqual(status.body.execution.txHash, hash);
    assert.strictEqual(status.body.execution.receiptStatus, '0x1');
    assert.strictEqual(status.body.execution.blockNumber, '0x9');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 5 Passed: Execution record survives restart.');
  }

  // Test 6: interrupted execution recovers truthfully; no duplicate broadcast.
  {
    const dir = scratchDir('persist-t6');
    const { mandate } = await writeMandate(dir);
    global.fetch = routedFetch('MATCH', {});
    let id;
    try {
      const first = bootPolicy(dir, { mandate });
      const out = await proposeOk(first.controller);
      assert.strictEqual(out.decision, 'ALLOW');
      id = out.requestId;
    } finally {
      global.fetch = realFetch;
    }
    const second = bootPolicy(dir, { mandate }); // restart before any execution
    const st = mockReqRes(null, { id });
    await second.controller.handleStatus(st.req, st.res);
    const status = await st.done;
    assert.strictEqual(status.body.status, 'APPROVED', 'approval intact after restart');
    assert.strictEqual(status.body.execution, null, 'interrupted execution stays NOT_RUN, never EXECUTED');
    // Unknown outcome reconciles against the chain before any claim: the
    // receipt is absent, so recording reports pending instead of executing.
    global.fetch = routedFetch('MATCH', { receipts: {}, txs: {} });
    try {
      const rc = mockReqRes({ txHash: `0x${'ff'.repeat(32)}` }, { id });
      await second.controller.handleReceipt(rc.req, rc.res);
      const pending = await rc.done;
      assert.strictEqual(pending.status, 404, 'absent receipt stays unrecorded');
    } finally {
      global.fetch = realFetch;
    }
    // Signer side: a burned approval (broadcast failed mid-flight) cannot
    // broadcast a duplicate after restart — replay is refused pre-chain.
    const consumedFile = path.join(dir, 'consumed.jsonl');
    const tx = validTx();
    const approval = issueApproval({
      secret: APPROVAL_SECRET, requestId: 'agent_persist-6', txDigest: digestTx(tx),
      chainId: tx.chainId, sender: tx.from, mandateId: 'persist-mandate',
      mandateVersion: 2, policyId: 'assertara-agent-mvp-1', subcallTreeHash: treeHashFor(tx),
      requiresOperator: false, ttlMs: 300000, nowMs: Date.now(), nonce: 'persist-nonce-6'
    });
    const failing = {
      wallet: { sendTransaction: async () => { throw new Error('mock broadcast failure'); } },
      public: {
        getTransactionCount: async () => 7,
        getBalance: async () => 1n,
        waitForTransactionReceipt: async () => ({ status: '0x1', blockNumber: '0x1', gasUsed: '0x1' })
      }
    };
    const s1 = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY, consumedFile, stateFile: null,
      policyCallbackUrl: null, clients: failing
    });
    const burned = await s1.execute({ requestId: 'agent_persist-6', transaction: tx, approval });
    assert.strictEqual(burned.ok, false, 'failed broadcast burns the approval');
    const f2 = fakeClients();
    const s2 = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY, consumedFile, stateFile: null,
      policyCallbackUrl: null, clients: f2.clients
    });
    const replay = await s2.execute({ requestId: 'agent_persist-6', transaction: tx, approval });
    assert.strictEqual(replay.ok, false);
    assert.ok(/already consumed/.test(replay.error));
    assert.strictEqual(f2.calls.send, 0, 'refused replay touches no chain');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 6 Passed: Interrupted execution recovers without duplicates.');
  }

  // Test 7: duplicate + concurrent receipt callbacks are idempotent.
  {
    const dir = scratchDir('persist-t7');
    const { mandate } = await writeMandate(dir);
    const spendingFile = path.join(dir, 'spending.jsonl');
    const spending = createSpendingLedger({ filePath: spendingFile });
    assert.strictEqual(spending.load().ok, true);
    const hash = `0x${'dd'.repeat(32)}`;
    const tx = validTx();
    const chain = {
      receipts: { [hash]: { status: '0x1', blockNumber: '0x3', gasUsed: '0x5208', logs: [] } },
      txs: { [hash]: { from: tx.from, to: tx.to, value: tx.value } }
    };
    global.fetch = routedFetch('MATCH', chain);
    try {
      const booted = bootPolicy(dir, { mandate, ledger: spending });
      const out = await proposeOk(booted.controller, tx);
      assert.strictEqual(out.decision, 'ALLOW');
      const fire = () => {
        const rc = mockReqRes({ txHash: hash }, { id: out.requestId });
        const p = booted.controller.handleReceipt(rc.req, rc.res);
        return p.then(() => rc.done);
      };
      const [r1, r2] = await Promise.all([fire(), fire()]);
      assert.strictEqual(r1.status, 200);
      assert.strictEqual(r2.status, 200);
      assert.strictEqual(r1.body.execution.outcome, 'EXECUTED');
      assert.strictEqual(r2.body.execution.outcome, 'EXECUTED');
      assert.ok(r1.body.duplicate !== r2.body.duplicate, 'exactly one path records, the other dedupes');
      assert.strictEqual(
        spending.spentWithin({ chainId: '0x7a69', windowMs: 86400000, nowMs: Date.now() }),
        BigInt(tx.value).toString(), 'verified value counted exactly once');
    } finally {
      global.fetch = realFetch;
    }
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 7 Passed: Duplicate receipts idempotent, spending counted once.');
  }

  // Test 8: corrupt or removed state fails safely, never a clean slate.
  {
    const dir = scratchDir('persist-t8');
    const { mandate } = await writeMandate(dir);
    global.fetch = routedFetch('MATCH', {});
    try {
      const booted = bootPolicy(dir, { mandate });
      await proposeOk(booted.controller);
    } finally {
      global.fetch = realFetch;
    }
    const snap = path.join(dir, 'agent-requests.json');
    assert.ok(fs.existsSync(snap) && fs.statSync(snap).size > 0, 'snapshot exists before corruption');
    const saved = fs.readFileSync(snap, 'utf8');
    // (a) corrupt snapshot: endpoints 503, nothing served.
    fs.writeFileSync(snap, '{nope,not-json', 'utf8');
    {
      const store = createAgentStore({ ledgerFile: path.join(dir, 'agent-ledger.jsonl'), snapshotFile: snap });
      assert.strictEqual(store.load().ok, false, 'corrupt snapshot fails load');
      const c = createAgentController({
        mandate, mandateError: null, approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
        approvalTtlMs: 300000, requestTtlMs: 900000, store, spendingLedger: createSpendingLedger({})
      });
      const { req, res, done } = mockReqRes({ transaction: validTx() });
      global.fetch = routedFetch('MATCH', {});
      try {
        await c.handlePropose(req, res);
      } finally {
        global.fetch = realFetch;
      }
      const out = await done;
      assert.strictEqual(out.status, 503, 'proposals refuse on corrupt state');
      const st = mockReqRes(null, { id: 'agent_anything' });
      await c.handleStatus(st.req, st.res);
      assert.strictEqual((await st.done).status, 503, 'status refuses on corrupt state');
    }
    // (b) snapshot removed while audit exists: refuse, do not reboot empty.
    fs.rmSync(snap);
    {
      const store = createAgentStore({ ledgerFile: path.join(dir, 'agent-ledger.jsonl'), snapshotFile: snap });
      const loaded = store.load();
      assert.strictEqual(loaded.ok, false, 'missing snapshot + live audit refuses');
      assert.ok(/clean slate/.test(loaded.error), 'reason names the hazard');
    }
    // (c) corrupt signer nonce log: signer refuses to start.
    const consumedFile = path.join(dir, 'consumed.jsonl');
    fs.writeFileSync(consumedFile, '{"nonce":"a"}\n{broken\n', 'utf8');
    await assert.rejects(() => createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY, consumedFile, stateFile: null,
      policyCallbackUrl: null, clients: fakeClients().clients
    }), /refusing to start/, 'corrupt nonce log refuses startup');
    // (d) corrupt signer continuity state: signer refuses to start.
    fs.writeFileSync(consumedFile, '', 'utf8');
    const stateFile = path.join(dir, 'signer-state.json');
    fs.writeFileSync(stateFile, 'garbage', 'utf8');
    await assert.rejects(() => createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY, consumedFile, stateFile,
      policyCallbackUrl: null, clients: fakeClients().clients
    }), /continuity failed/, 'corrupt signer state refuses startup');
    void saved;
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 8 Passed: Corrupt/removed state fails safely.');
  }

  config.modelApiKey = ORIGINAL_KEY;
  await closeOcrWorker();
  console.log('\nAll Persistence + Restart Tests Passed Successfully!\n');
}

if (require.main === module) {
  runPersistenceTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runPersistenceTests };
