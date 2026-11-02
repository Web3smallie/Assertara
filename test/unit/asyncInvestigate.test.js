const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentStore } = require('../../src/services/agentStore');
const { createAgentController } = require('../../src/controllers/agentController');
const { createCapacityGuard } = require('../../src/middleware/rateLimit');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');

const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();

// Asynchronous investigation submission: 202 with ids, background
// completion through the SAME core as sync propose, genuine progress
// while running, capacity gating, recovery, TTL fail-closed, and the
// evidence envelope. Model transport canned.

const SIGNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

function fixtureMandate() {
  return {
    id: 'async-test-mandate', version: 1, issuer: 'test-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: SIGNER, senders: [SIGNER],
    chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:18545', name: 'anvil-test' }],
    recipients: { allow: [RECIPIENT], deny: [] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [], reviewRules: []
  };
}

async function loadSealedMandate() {
  const dir = path.join(__dirname, '..', 'tmp', `async-mand-${Date.now()}-${Math.floor(Math.random() * 1e6)}`);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'mandate.json');
  fs.writeFileSync(file, JSON.stringify(fixtureMandate()), 'utf8');
  const loaded = loadMandate(file);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
  loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
  return loaded.mandate;
}

function mockReqRes(body, opts) {
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const req = { body, params: (opts && opts.params) || {}, headers: (opts && opts.headers) || {} };
  if (opts && opts.agentKey !== undefined) req.agentKey = opts.agentKey;
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    set() { return this; },
    json(payload) { resolve({ status: this.statusCode, body: payload }); }
  };
  return { req, res, done };
}

async function makeController(overrides) {
  const mandate = await loadSealedMandate();
  const store = (overrides && overrides.store) || createAgentStore({ ledgerFile: null });
  const controller = createAgentController({
    mandate,
    mandateError: null,
    mandateAuthorities: [OPERATOR_ADDR],
    approvalSecret: 'async-test-approval-secret-0123456789ab',
    operatorSecret: 'async-test-operator-secret-0123456789ab',
    approvalTtlMs: 300000,
    requestTtlMs: (overrides && overrides.requestTtlMs) || 900000,
    store,
    spendingLedger: createSpendingLedger({}),
    capacity: overrides && overrides.capacity !== undefined ? overrides.capacity : null,
    nowFn: overrides && overrides.nowFn
  });
  return { controller, store };
}

function canned(verdict) {
  return {
    ok: true,
    json: async () => ({ choices: [{ message: { content: JSON.stringify({
      verdict, confidence: 0.9, summary: `canned ${verdict}`,
      discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
    }) } }] })
  };
}

function validTx(overrides) {
  return { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x1000', chainId: '0x7a69', ...(overrides || {}) };
}

function waitFor(fn, timeoutMs, label) {
  const start = Date.now();
  return (async () => {
    for (;;) {
      if (fn()) return;
      if (Date.now() - start > (timeoutMs || 10000)) throw new Error(`timed out waiting for ${label}`);
      await new Promise((r) => setTimeout(r, 10));
    }
  })();
}

async function statusOf(controller, id, agentKey) {
  const s = mockReqRes(null, { params: { id }, agentKey });
  await controller.handleStatus(s.req, s.res);
  return s.done;
}

async function runAsyncInvestigateTests() {
  console.log('Testing async investigation submit, progress, recovery...\n');
  const realFetch = global.fetch;
  const origKey = config.modelApiKey;
  config.modelApiKey = 'test-live-key';

  // Test 1: 202 answers immediately with ids while the run continues in background.
  {
    const { controller, store } = await makeController();
    let releaseModel = null;
    let modelReached = false;
    global.fetch = async (url) => {
      if (String(url).includes('chat/completions')) {
        modelReached = true;
        await new Promise((r) => { releaseModel = r; });
      }
      return canned('MATCH');
    };
    const body = { transaction: validTx(), intent: { purpose: 'async one' } };
    const sub = mockReqRes(body);
    await controller.handleInvestigate(sub.req, sub.res);
    const accepted = await sub.done;
    assert.strictEqual(accepted.status, 202, JSON.stringify(accepted.body));
    assert.ok(/^agent_/.test(accepted.body.requestId), 'requestId returned');
    assert.ok(typeof accepted.body.traceId === 'string' && accepted.body.traceId.length > 0, 'traceId returned');
    assert.strictEqual(accepted.body.status, 'INVESTIGATING');
    assert.ok(typeof accepted.body.txDigest === 'string');
    await waitFor(() => modelReached, 10000, 'background run to reach the model');
    const mid = store.get(accepted.body.requestId);
    assert.ok(mid && !mid.decision, 'still undecided while the model runs');
    assert.strictEqual(mid.status, 'INVESTIGATING');
    releaseModel();
    await waitFor(() => {
      const r = store.get(accepted.body.requestId);
      return r && r.decision;
    }, 10000, 'background completion');
    const done = store.get(accepted.body.requestId);
    assert.strictEqual(done.decision, 'ALLOW', 'background run decides through the shared core');
    assert.ok(done.approval && done.approval.token, 'ALLOW issues its approval in background');
    console.log('✔ Test 1 Passed: 202 with ids; background run completes through the shared core.');
  }

  // Test 2: status shows genuine progress mid-run, then the published decision.
  {
    const { controller } = await makeController();
    let releaseModel = null;
    global.fetch = async (url) => {
      if (String(url).includes('chat/completions')) {
        await new Promise((r) => { releaseModel = r; });
      }
      return canned('MATCH');
    };
    const sub = mockReqRes({ transaction: validTx(), intent: { purpose: 'progress' } });
    await controller.handleInvestigate(sub.req, sub.res);
    const accepted = await sub.done;
    await waitFor(() => releaseModel !== null, 10000, 'model fetch to start');
    const mid = await statusOf(controller, accepted.body.requestId);
    assert.strictEqual(mid.status, 200);
    assert.strictEqual(mid.body.decision, null, 'no decision published yet');
    assert.ok(typeof mid.body.stage === 'string' && mid.body.stage.length > 0, 'real stage reported');
    assert.ok(mid.body.progress && typeof mid.body.progress === 'object', 'progress object present');
    assert.strictEqual(mid.body.progress.museSpark.state, 'running', 'model invocation genuinely running');
    releaseModel();
    const fin = await waitForDecision(controller, accepted.body.requestId);
    assert.strictEqual(fin.decision, 'ALLOW');
    assert.strictEqual(fin.stage, undefined, 'terminal status keeps its exact shape (no stage)');
    assert.strictEqual(fin.progress, undefined, 'terminal status keeps its exact shape (no progress)');
    console.log('✔ Test 2 Passed: Live progress mid-run; terminal shape unchanged.');
  }

  // Test 3: async and sync agree on the same proposal (shared core, shared semantics).
  {
    const { controller } = await makeController();
    global.fetch = async () => canned('MATCH');
    const body = () => ({ transaction: validTx(), intent: { purpose: 'equivalence' } });
    const s = mockReqRes(body());
    await controller.handlePropose(s.req, s.res);
    const syncOut = await s.done;
    const a = mockReqRes(body());
    await controller.handleInvestigate(a.req, a.res);
    const asyncAccepted = await a.done;
    const fin = await waitForDecision(controller, asyncAccepted.body.requestId);
    assert.strictEqual(syncOut.body.decision, fin.decision, 'same decision both paths');
    assert.deepStrictEqual(syncOut.body.reasons, fin.reasons, 'same reasons both paths');
    assert.strictEqual(syncOut.body.txDigest, fin.txDigest);
    const evReq = mockReqRes(null, { params: { id: asyncAccepted.body.requestId } });
    await controller.handleEvidence(evReq.req, evReq.res);
    const asyncEvidence = await evReq.done;
    assert.deepStrictEqual(
      (asyncEvidence.body.mandateChecks || []).map((c) => c.id),
      (syncOut.body.mandateChecks || []).map((c) => c.id),
      'mandate check coverage identical'
    );
    console.log('✔ Test 3 Passed: Async and sync produce the same decision, reasons, and digest.');
  }

  // Test 4: async BLOCK completes BLOCK with no approval; chain-facing paths untouched.
  {
    const { controller, store } = await makeController();
    global.fetch = async () => canned('MATCH');
    const sub = mockReqRes({ transaction: validTx({ to: SIGNER }), intent: { purpose: 'blocked' } });
    await controller.handleInvestigate(sub.req, sub.res);
    const accepted = await sub.done;
    assert.strictEqual(accepted.status, 202);
    const fin = await waitForDecision(controller, accepted.body.requestId);
    assert.strictEqual(fin.decision, 'BLOCK', 'mandate violation blocks in background too');
    assert.strictEqual(fin.approvalToken, null, 'BLOCK issues nothing');
    assert.strictEqual(store.get(accepted.body.requestId).approval, undefined, 'no approval stored');
    console.log('✔ Test 4 Passed: Async BLOCK issues no approval.');
  }

  // Test 5: capacity exhaustion is a 429 without a record; slots release on completion.
  {
    const capacity = createCapacityGuard({ maxTotal: 1, maxPerKey: 1 });
    const { controller, store } = await makeController({ capacity });
    let releaseModel = null;
    global.fetch = async (url) => {
      if (String(url).includes('chat/completions')) {
        await new Promise((r) => { releaseModel = r; });
      }
      return canned('MATCH');
    };
    const first = mockReqRes({ transaction: validTx(), intent: { purpose: 'slot holder' } });
    await controller.handleInvestigate(first.req, first.res);
    assert.strictEqual((await first.done).status, 202);
    await waitFor(() => releaseModel !== null, 10000, 'first run to hold its slot');
    assert.strictEqual(store.size(), 1);
    const second = mockReqRes({ transaction: validTx(), intent: { purpose: 'overflow' } });
    await controller.handleInvestigate(second.req, second.res);
    const denied = await second.done;
    assert.strictEqual(denied.status, 429, JSON.stringify(denied.body));
    assert.strictEqual(typeof denied.body.retryAfterMs, 'number');
    assert.strictEqual(store.size(), 1, 'denied submit creates no record');
    releaseModel();
    await waitFor(() => capacity.stats().inFlight === 0, 10000, 'slot release');
    releaseModel = null;
    const third = mockReqRes({ transaction: validTx(), intent: { purpose: 'after release' } });
    await controller.handleInvestigate(third.req, third.res);
    const thirdAccepted = await third.done;
    assert.strictEqual(thirdAccepted.status, 202, 'capacity reusable after release');
    // Finish the third run inside this test: no detached run may leak
    // into later tests (its model fetch would arm their gates).
    await waitFor(() => releaseModel !== null, 10000, 'third run to reach the model');
    releaseModel();
    await waitForDecision(controller, thirdAccepted.body.requestId);
    console.log('✔ Test 5 Passed: 429 without a record; slots release exactly once.');
  }

  // Test 6: idempotency across the async path (running 409, terminal replay).
  {
    const { controller } = await makeController();
    let releaseModel = null;
    global.fetch = async (url) => {
      if (String(url).includes('chat/completions')) {
        await new Promise((r) => { releaseModel = r; });
      }
      return canned('MATCH');
    };
    const headers = { 'idempotency-key': 'async-key-6' };
    const body = () => ({ transaction: validTx(), intent: { purpose: 'idem async' } });
    const a = mockReqRes(body(), { headers });
    await controller.handleInvestigate(a.req, a.res);
    const accepted = await a.done;
    assert.strictEqual(accepted.status, 202);
    await waitFor(() => releaseModel !== null, 10000, 'run to start');
    const b = mockReqRes(body(), { headers });
    await controller.handleInvestigate(b.req, b.res);
    const running = await b.done;
    assert.strictEqual(running.status, 409, JSON.stringify(running.body));
    assert.strictEqual(running.body.requestId, accepted.body.requestId);
    releaseModel();
    await waitForDecision(controller, accepted.body.requestId);
    const c = mockReqRes(body(), { headers });
    await controller.handleInvestigate(c.req, c.res);
    const replay = await c.done;
    assert.strictEqual(replay.status, 200, JSON.stringify(replay.body));
    assert.strictEqual(replay.body.replayed, true);
    assert.strictEqual(replay.body.requestId, accepted.body.requestId);
    assert.strictEqual(replay.body.decision, 'ALLOW');
    console.log('✔ Test 6 Passed: Async running-409 and terminal replay exact.');
  }

  // Test 7: startup recovery fail-closes undecided records, leaves decided ones alone.
  {
    const { controller, store } = await makeController();
    const base = { normalizedTx: validTx(), txDigest: 'recv', purpose: '', visual: null };
    store.create({ id: 'agent_recv', createdAt: Date.now(), updatedAt: Date.now(), status: 'RECEIVED', ...base });
    store.create({ id: 'agent_invest', createdAt: Date.now(), updatedAt: Date.now(), status: 'INVESTIGATING', ...base });
    store.create({
      id: 'agent_done', createdAt: Date.now(), updatedAt: Date.now(), status: 'DECIDED',
      decision: 'BLOCK', reasons: ['x'], ...base
    });
    const out = controller.recoverInterrupted();
    assert.strictEqual(out.recovered, 2);
    for (const id of ['agent_recv', 'agent_invest']) {
      const r = store.get(id);
      assert.strictEqual(r.decision, 'UNCERTAIN', `${id} fail-closed`);
      assert.ok(/re-propose/.test((r.reasons || []).join(' ')), `${id} tells the agent to re-propose`);
    }
    assert.strictEqual(store.get('agent_done').decision, 'BLOCK', 'decided records untouched');
    console.log('✔ Test 7 Passed: Recovery fail-closes only undecided records.');
  }

  // Test 8: read-path TTL closes a stale running record as UNCERTAIN.
  {
    const NOW = 1767225600000;
    const store = createAgentStore({ ledgerFile: null });
    store.create({
      id: 'agent_stale', createdAt: NOW - 5000, updatedAt: NOW - 5000,
      status: 'INVESTIGATING', normalizedTx: validTx(), txDigest: 'stale', purpose: '', visual: null
    });
    const { controller } = await makeController({ store, requestTtlMs: 1000, nowFn: () => NOW });
    const s = mockReqRes(null, { params: { id: 'agent_stale' } });
    await controller.handleStatus(s.req, s.res);
    const out = await s.done;
    assert.strictEqual(out.status, 200);
    assert.strictEqual(out.body.decision, 'UNCERTAIN', 'stale run fail-closed on read');
    assert.strictEqual(store.get('agent_stale').decision, 'UNCERTAIN', 'durable, not just displayed');
    console.log('✔ Test 8 Passed: Stale investigations fail closed on status read.');
  }

  // Test 9: evidence envelope (409 while running, full 200 after, 404 foreign/unknown).
  {
    const { controller } = await makeController();
    let releaseModel = null;
    global.fetch = async (url) => {
      if (String(url).includes('chat/completions')) {
        await new Promise((r) => { releaseModel = r; });
      }
      return canned('MATCH');
    };
    const keyA = { keyId: 'alpha', development: false };
    const sub = mockReqRes({ transaction: validTx(), intent: { purpose: 'evidenced' } }, { agentKey: keyA });
    await controller.handleInvestigate(sub.req, sub.res);
    const accepted = await sub.done;
    const id = accepted.body.requestId;
    await waitFor(() => releaseModel !== null, 10000, 'run to start');
    const early = mockReqRes(null, { params: { id }, agentKey: keyA });
    await controller.handleEvidence(early.req, early.res);
    const earlyOut = await early.done;
    assert.strictEqual(earlyOut.status, 409, JSON.stringify(earlyOut.body));
    assert.strictEqual(earlyOut.body.requestId, id);
    releaseModel();
    await waitForDecision(controller, id);
    const done = mockReqRes(null, { params: { id }, agentKey: keyA });
    await controller.handleEvidence(done.req, done.res);
    const ev = await done.done;
    assert.strictEqual(ev.status, 200, JSON.stringify(ev.body));
    assert.strictEqual(ev.body.v, 1);
    assert.strictEqual(ev.body.decision, 'ALLOW');
    assert.ok(Array.isArray(ev.body.reasons) && ev.body.reasons.length > 0, 'reasons included');
    assert.ok(Array.isArray(ev.body.mandateChecks) && ev.body.mandateChecks.length > 0, 'mandate checks included');
    assert.strictEqual(typeof ev.body.traceId, 'string', 'trace link included');
    const foreign = mockReqRes(null, { params: { id }, agentKey: { keyId: 'beta', development: false } });
    await controller.handleEvidence(foreign.req, foreign.res);
    assert.strictEqual((await foreign.done).status, 404, 'foreign key sees 404');
    const missing = mockReqRes(null, { params: { id: 'agent_nope' }, agentKey: keyA });
    await controller.handleEvidence(missing.req, missing.res);
    assert.strictEqual((await missing.done).status, 404, 'unknown id is 404');
    console.log('✔ Test 9 Passed: Evidence envelope timing, shape, and isolation exact.');
  }

  global.fetch = realFetch;
  config.modelApiKey = origKey;
  console.log('\nAll async investigation tests passed.');
}

async function waitForDecision(controller, id) {
  let last = null;
  const start = Date.now();
  for (;;) {
    const s = mockReqRes(null, { params: { id } });
    await controller.handleStatus(s.req, s.res);
    const out = await s.done;
    last = out.body;
    if (last.decision) return last;
    if (Date.now() - start > 10000) throw new Error('timed out waiting for decision');
    await new Promise((r) => setTimeout(r, 25));
  }
}

if (require.main === module) {
  runAsyncInvestigateTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAsyncInvestigateTests };
