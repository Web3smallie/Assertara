const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentStore } = require('../../src/services/agentStore');
const { createAgentController } = require('../../src/controllers/agentController');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');

const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();

// Propose idempotency: same key + same proposal replays without spending a
// second investigation; same key + different proposal conflicts; absent keys
// keep the existing one-record-per-call behavior. Model transport canned.

const SIGNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const APPROVAL_SECRET = 'idem-test-approval-secret-0123456789ab';
const OPERATOR_SECRET = 'idem-test-operator-secret-0123456789ab';

function fixtureMandate() {
  return {
    id: 'idem-test-mandate', version: 1, issuer: 'test-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: SIGNER, senders: [SIGNER],
    chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:18545', name: 'anvil-test' }],
    recipients: { allow: [RECIPIENT], deny: [] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [],
    reviewRules: [{ when: 'nativeValueAboveWei', value: '10000000000000000' }]
  };
}

function mockReqRes(body, opts) {
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const headers = (opts && opts.headers) || {};
  const req = {
    body,
    params: (opts && opts.params) || {},
    headers,
    get(name) {
      const v = headers[String(name).toLowerCase()];
      return v === undefined ? null : v;
    }
  };
  const res = {
    statusCode: 200,
    headers: {},
    status(code) { this.statusCode = code; return this; },
    set(k, v) { this.headers[k] = v; return this; },
    json(payload) { resolve({ status: this.statusCode, headers: this.headers, body: payload }); }
  };
  return { req, res, done };
}

async function makeController(storeOverrides) {
  const dir = path.join(__dirname, '..', 'tmp', `idem-ctl-${Date.now()}-${Math.floor(Math.random() * 1e6)}`);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'mandate.json');
  fs.writeFileSync(file, JSON.stringify(fixtureMandate()), 'utf8');
  const loaded = loadMandate(file);
  assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
  fs.rmSync(dir, { recursive: true, force: true });
  loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
  const store = (storeOverrides && storeOverrides.store)
    || createAgentStore({ ledgerFile: null });
  return {
    controller: createAgentController({
      mandate: loaded.mandate,
      mandateError: null,
      mandateAuthorities: [OPERATOR_ADDR],
      approvalSecret: APPROVAL_SECRET,
      operatorSecret: OPERATOR_SECRET,
      approvalTtlMs: 300000,
      requestTtlMs: 900000,
      store,
      spendingLedger: createSpendingLedger({})
    }),
    store
  };
}

function cannedFetch(verdict) {
  return async () => ({
    ok: true,
    json: async () => ({ choices: [{ message: { content: JSON.stringify({
      verdict, confidence: 0.9,
      summary: `canned ${verdict}`, discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
    }) } }] })
  });
}

function validTx(overrides) {
  return { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x2386f26fc10000', chainId: '0x7a69', ...(overrides || {}) };
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

async function runIdempotencyTests() {
  console.log('Testing propose idempotency (keys, replays, conflicts)...\n');
  const realFetch = global.fetch;
  const origKey = config.modelApiKey;
  config.modelApiKey = 'test-live-key';

  // Test 1: same key + same proposal replays identically with one investigation.
  {
    const { controller, store } = await makeController();
    let modelCalls = 0;
    global.fetch = async (url) => {
      if (String(url).includes('chat/completions')) modelCalls += 1;
      return cannedFetch('MATCH')(url);
    };
    const body = () => ({ transaction: validTx(), intent: { purpose: 'replay me' } });
    const first = mockReqRes(body(), { headers: { 'idempotency-key': 'key-aaa-1' } });
    await controller.handlePropose(first.req, first.res);
    const out1 = await first.done;
    assert.strictEqual(out1.status, 200, JSON.stringify(out1.body));
    assert.strictEqual(out1.body.replayed, undefined, 'fresh response carries no replayed flag');
    const second = mockReqRes(body(), { headers: { 'idempotency-key': 'key-aaa-1' } });
    await controller.handlePropose(second.req, second.res);
    const out2 = await second.done;
    assert.strictEqual(out2.status, 200, JSON.stringify(out2.body));
    assert.strictEqual(out2.body.replayed, true, 'replay is labeled');
    assert.strictEqual(out2.body.requestId, out1.body.requestId, 'same record replayed');
    assert.strictEqual(out2.body.txDigest, out1.body.txDigest);
    assert.strictEqual(out2.body.traceId, out1.body.traceId, 'original trace id kept');
    assert.strictEqual(out2.headers['Idempotent-Replayed'], 'true');
    assert.strictEqual(store.size(), 1, 'no second record created');
    assert.strictEqual(modelCalls, 1, 'no second model investigation spent');
    console.log('✔ Test 1 Passed: Identical replay returns the stored record with one investigation.');
  }

  // Test 2: same key + different transaction conflicts.
  {
    const { controller } = await makeController();
    global.fetch = cannedFetch('MATCH');
    const a = mockReqRes({ transaction: validTx(), intent: { purpose: 'p' } }, { headers: { 'idempotency-key': 'key-bbb-2' } });
    await controller.handlePropose(a.req, a.res);
    assert.strictEqual((await a.done).status, 200);
    const b = mockReqRes(
      { transaction: validTx({ value: '0x1000' }), intent: { purpose: 'p' } },
      { headers: { 'idempotency-key': 'key-bbb-2' } }
    );
    await controller.handlePropose(b.req, b.res);
    const out = await b.done;
    assert.strictEqual(out.status, 409, JSON.stringify(out.body));
    assert.ok(/different proposal/.test(out.body.error));
    console.log('✔ Test 2 Passed: Key reuse with a different transaction is a 409 conflict.');
  }

  // Test 3: same key + different purpose conflicts.
  {
    const { controller } = await makeController();
    global.fetch = cannedFetch('MATCH');
    const a = mockReqRes({ transaction: validTx(), intent: { purpose: 'one' } }, { headers: { 'idempotency-key': 'key-ccc-3' } });
    await controller.handlePropose(a.req, a.res);
    assert.strictEqual((await a.done).status, 200);
    const b = mockReqRes({ transaction: validTx(), intent: { purpose: 'two' } }, { headers: { 'idempotency-key': 'key-ccc-3' } });
    await controller.handlePropose(b.req, b.res);
    const out = await b.done;
    assert.strictEqual(out.status, 409, JSON.stringify(out.body));
    console.log('✔ Test 3 Passed: Key reuse with a different purpose is a 409 conflict.');
  }

  // Test 4: absent keys keep one-record-per-call behavior.
  {
    const { controller, store } = await makeController();
    global.fetch = cannedFetch('MATCH');
    const body = () => ({ transaction: validTx(), intent: { purpose: 'no key' } });
    const a = mockReqRes(body());
    await controller.handlePropose(a.req, a.res);
    const b = mockReqRes(body());
    await controller.handlePropose(b.req, b.res);
    const [outA, outB] = [await a.done, await b.done];
    assert.strictEqual(outA.status, 200);
    assert.strictEqual(outB.status, 200);
    assert.notStrictEqual(outA.body.requestId, outB.body.requestId, 'distinct records without keys');
    assert.strictEqual(store.size(), 2);
    console.log('✔ Test 4 Passed: Proposals without keys are unaffected (distinct records).');
  }

  // Test 5: malformed keys are 400 client errors.
  {
    const { controller } = await makeController();
    global.fetch = cannedFetch('MATCH');
    for (const bad of ['x'.repeat(129), 'has space', 'semi;colon', 'quo"te']) {
      const r = mockReqRes({ transaction: validTx() }, { headers: { 'idempotency-key': bad } });
      await controller.handlePropose(r.req, r.res);
      const out = await r.done;
      assert.strictEqual(out.status, 400, `${JSON.stringify(bad)} must be rejected`);
    }
    console.log('✔ Test 5 Passed: Malformed idempotency keys are rejected with 400.');
  }

  // Test 6: REVIEW replays return no approval but keep the release path.
  {
    const { controller } = await makeController();
    global.fetch = cannedFetch('MATCH');
    const rich = () => ({ transaction: validTx({ value: '0x470de4df820000' }), intent: { purpose: 'rich' } }); // 0.02 ETH > 0.01 review
    const a = mockReqRes(rich(), { headers: { 'idempotency-key': 'key-ddd-6' } });
    await controller.handlePropose(a.req, a.res);
    const out1 = await a.done;
    assert.strictEqual(out1.status, 200, JSON.stringify(out1.body));
    assert.strictEqual(out1.body.decision, 'REVIEW', 'over-threshold value holds for review');
    assert.strictEqual(out1.body.approval, null, 'REVIEW issues no usable token');
    const b = mockReqRes(rich(), { headers: { 'idempotency-key': 'key-ddd-6' } });
    await controller.handlePropose(b.req, b.res);
    const out2 = await b.done;
    assert.strictEqual(out2.body.requestId, out1.body.requestId);
    assert.strictEqual(out2.body.replayed, true);
    assert.strictEqual(out2.body.approval, null);
    assert.strictEqual(out2.body.operatorAuthorizationRequired, true);
    console.log('✔ Test 6 Passed: REVIEW replays preserve the operator-release shape.');
  }

  // Test 7: replay while the first investigation is still running is a 409 with the live requestId.
  {
    const { controller, store } = await makeController();
    let releaseModel = null;
    global.fetch = async (url) => {
      if (String(url).includes('chat/completions')) {
        await new Promise((r) => { releaseModel = r; });
      }
      return cannedFetch('MATCH')(url);
    };
    const body = () => ({ transaction: validTx(), intent: { purpose: 'race' } });
    const first = mockReqRes(body(), { headers: { 'idempotency-key': 'key-eee-7' } });
    const p1 = controller.handlePropose(first.req, first.res);
    await waitFor(() => releaseModel !== null, 10000, 'model fetch to start');
    const second = mockReqRes(body(), { headers: { 'idempotency-key': 'key-eee-7' } });
    const p2 = controller.handlePropose(second.req, second.res);
    const out2 = await second.done;
    assert.strictEqual(out2.status, 409, JSON.stringify(out2.body));
    assert.ok(/^agent_/.test(out2.body.requestId || ''), 'running requestId returned for polling');
    releaseModel();
    await p1;
    await p2;
    const out1 = await first.done;
    assert.strictEqual(out1.status, 200);
    assert.strictEqual(out2.body.requestId, out1.body.requestId, 'same live record');
    assert.strictEqual(store.size(), 1, 'single record overall');
    console.log('✔ Test 7 Passed: In-flight key replay returns 409 with the running requestId.');
  }

  // Test 8: the idempotency index survives a snapshot reload.
  {
    const dir = path.join(__dirname, '..', 'tmp', `idem-snap-${Date.now()}`);
    fs.mkdirSync(dir, { recursive: true });
    const snap = path.join(dir, 'agent-requests.json');
    try {
      const store = createAgentStore({ ledgerFile: null, snapshotFile: snap });
      assert.strictEqual(store.load().ok, true);
      const { controller } = await makeController({ store });
      global.fetch = cannedFetch('MATCH');
      const a = mockReqRes(
        { transaction: validTx(), intent: { purpose: 'durable' } },
        { headers: { 'idempotency-key': 'key-fff-8' } }
      );
      await controller.handlePropose(a.req, a.res);
      const out1 = await a.done;
      assert.strictEqual(out1.status, 200);
      const store2 = createAgentStore({ ledgerFile: null, snapshotFile: snap });
      assert.strictEqual(store2.load().ok, true);
      const found = store2.findByIdempotencyKey('key-fff-8');
      assert.ok(found, 'reloaded store resolves the key');
      assert.strictEqual(found.id, out1.body.requestId);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    console.log('✔ Test 8 Passed: Idempotency mapping persists across restarts.');
  }

  global.fetch = realFetch;
  config.modelApiKey = origKey;
  console.log('\nAll idempotency tests passed.');
}

if (require.main === module) {
  runIdempotencyTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runIdempotencyTests };
