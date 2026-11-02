const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { readAgentConfig } = require('../../src/config/agentConfig');
const { resolveAuthMode, requireAgentKey, allowOwner } = require('../../src/middleware/agentAuth');
const { createCapacityGuard } = require('../../src/middleware/rateLimit');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentStore } = require('../../src/services/agentStore');
const { createAgentController } = require('../../src/controllers/agentController');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');

const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();

// Agent authentication, ownership isolation, and investigation capacity.
// Keys identify integrations only; nothing here authorizes transactions.

const SIGNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

function mwReqRes(headers) {
  const req = { headers: headers || {}, agentKey: undefined };
  let status = null;
  let body = null;
  let nexted = false;
  const res = {
    status(c) { status = c; return this; },
    json(p) { body = p; return this; }
  };
  const out = { req, res, next: () => { nexted = true; }, status: () => status, body: () => body, nexted: () => nexted };
  return out;
}

function ctlReqRes(body, params, agentKey) {
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const req = { body, params: params || {}, headers: {} };
  if (agentKey !== undefined) req.agentKey = agentKey;
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    set() { return this; },
    json(payload) { resolve({ status: this.statusCode, body: payload }); }
  };
  return { req, res, done };
}

async function runAgentAuthTests() {
  console.log('Testing agent auth, ownership isolation, capacity...\n');

  // Test 1: key parsing from CSV and file; invalid entries dropped, never trusted.
  {
    const cfg = readAgentConfig({ AGENT_API_KEYS: 'alpha:aaaaaaaaaaaaaaaa,bad:short,nope,beta:bbbbbbbbbbbbbbbb' });
    assert.ok(cfg.agentApiKeys instanceof Map);
    assert.strictEqual(cfg.agentApiKeys.size, 2);
    assert.ok(/2 agent API key/.test(cfg.agentApiKeysError));
    const dir = path.join(__dirname, '..', 'tmp', `authkeys-${Date.now()}`);
    fs.mkdirSync(dir, { recursive: true });
    try {
      const file = path.join(dir, 'keys.json');
      fs.writeFileSync(file, JSON.stringify({ gamma: 'cccccccccccccccc', weak: 'x' }), 'utf8');
      const cfg2 = readAgentConfig({ AGENT_API_KEYS_FILE: file });
      assert.strictEqual(cfg2.agentApiKeys.size, 1);
      assert.ok(cfg2.agentApiKeys.has('gamma'));
      assert.ok(/1 agent API key/.test(cfg2.agentApiKeysError));
      const cfg3 = readAgentConfig({ AGENT_API_KEYS_FILE: path.join(dir, 'missing.json') });
      assert.strictEqual(cfg3.agentApiKeys, null);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    assert.strictEqual(readAgentConfig({}).agentApiKeys, null);
    assert.strictEqual(readAgentConfig({}).agentAuthMode, 'production');
    assert.strictEqual(readAgentConfig({ AGENT_AUTH_MODE: 'development' }).agentAuthMode, 'development');
    assert.strictEqual(readAgentConfig({}).maxConcurrentInvestigations, 8);
    assert.strictEqual(readAgentConfig({ MAX_CONCURRENT_INVESTIGATIONS: '0' }).maxConcurrentInvestigations, 1);
    assert.strictEqual(readAgentConfig({ MAX_CONCURRENT_INVESTIGATIONS: 'nonsense' }).maxConcurrentInvestigations, 8);
    assert.strictEqual(readAgentConfig({ MAX_CONCURRENT_INVESTIGATIONS: '3' }).maxConcurrentInvestigations, 3);
    assert.strictEqual(readAgentConfig({}).maxInflightPerKey, 2);
    console.log('✔ Test 1 Passed: Key sources parse; invalid entries dropped; caps/mode default safely.');
  }

  // Test 2: mode resolution across the three states.
  {
    const keys = new Map([['a', 'aaaaaaaaaaaaaaaa']]);
    const enforced = resolveAuthMode({ agentApiKeys: keys, agentAuthMode: 'production' });
    assert.deepStrictEqual({ e: enforced.enforced, d: enforced.disabled }, { e: true, d: false });
    const dev = resolveAuthMode({ agentApiKeys: null, agentAuthMode: 'development' });
    assert.deepStrictEqual({ e: dev.enforced, d: dev.disabled }, { e: false, d: false });
    const off = resolveAuthMode({ agentApiKeys: null, agentAuthMode: 'production' });
    assert.deepStrictEqual({ e: off.enforced, d: off.disabled }, { e: false, d: true });
    console.log('✔ Test 2 Passed: Enforced / development / disabled modes resolve exactly.');
  }

  // Test 3: middleware accepts valid keys, rejects everything else, gates dev/disabled.
  {
    const mw = requireAgentKey({ agentApiKeys: new Map([['alpha', 'aaaaaaaaaaaaaaaa']]), agentAuthMode: 'production' }, {});
    const good = mwReqRes({ authorization: 'Bearer alpha:aaaaaaaaaaaaaaaa' });
    mw(good.req, good.res, good.next);
    assert.strictEqual(good.nexted(), true);
    assert.deepStrictEqual(good.req.agentKey, { keyId: 'alpha', development: false });
    for (const [label, headers] of [
      ['missing', {}],
      ['wrong scheme', { authorization: 'Basic alpha:aaaaaaaaaaaaaaaa' }],
      ['wrong secret', { authorization: 'Bearer alpha:bbbbbbbbbbbbbbbb' }],
      ['unknown id', { authorization: 'Bearer ghost:aaaaaaaaaaaaaaaa' }],
      ['no separator', { authorization: 'Bearer alpha' }]
    ]) {
      const t = mwReqRes(headers);
      mw(t.req, t.res, t.next);
      assert.strictEqual(t.nexted(), false, label);
      assert.strictEqual(t.status(), 401, label);
    }
    const devMw = requireAgentKey({ agentApiKeys: null, agentAuthMode: 'development' }, {});
    const dev = mwReqRes({});
    devMw(dev.req, dev.res, dev.next);
    assert.strictEqual(dev.nexted(), true);
    assert.deepStrictEqual(dev.req.agentKey, { keyId: null, development: true });
    const offMw = requireAgentKey({ agentApiKeys: null, agentAuthMode: 'production' }, {});
    const off = mwReqRes({ authorization: 'Bearer alpha:aaaaaaaaaaaaaaaa' });
    offMw(off.req, off.res, off.next);
    assert.strictEqual(off.status(), 503);
    console.log('✔ Test 3 Passed: Bearer verification, dev passthrough, and disabled-503 exact.');
  }

  // Test 4: ownership matrix.
  {
    const dev = { agentKey: { keyId: null, development: true } };
    const a = { agentKey: { keyId: 'alpha', development: false } };
    const b = { agentKey: { keyId: 'beta', development: false } };
    assert.strictEqual(allowOwner(dev, 'alpha'), true, 'dev sees everything');
    assert.strictEqual(allowOwner(dev, null), true);
    assert.strictEqual(allowOwner(a, 'alpha'), true, 'owner reads own');
    assert.strictEqual(allowOwner(a, 'beta'), false, 'foreign denied');
    assert.strictEqual(allowOwner(a, null), false, 'ownerless hidden from keys');
    assert.strictEqual(allowOwner({}, 'alpha'), true, 'direct (legacy) callers unaffected');
    assert.strictEqual(allowOwner(b, 'alpha'), false);
    console.log('✔ Test 4 Passed: Ownership allows owner/dev, denies foreign and ownerless.');
  }

  // Test 5: controller stamps the owner and scopes status reads (404, no oracle).
  {
    const dir = path.join(__dirname, '..', 'tmp', `authctl-${Date.now()}-${Math.floor(Math.random() * 1e6)}`);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'mandate.json');
    fs.writeFileSync(file, JSON.stringify({
      id: 'auth-test-mandate', version: 1, issuer: 'test-operator',
      notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
      revokedVersions: [],
      signerAddress: SIGNER, senders: [SIGNER],
      chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:18545', name: 'anvil-test' }],
      recipients: { allow: [RECIPIENT], deny: [] },
      contracts: { allow: [] }, selectors: { allow: [] },
      allowNativeTransfer: true, maxNativePerTxWei: '100000000000000000',
      approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
      spendingLimits: [], reviewRules: []
    }), 'utf8');
    const loaded = loadMandate(file);
    fs.rmSync(dir, { recursive: true, force: true });
    assert.strictEqual(loaded.ok, true);
    loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
    const store = createAgentStore({ ledgerFile: null });
    const controller = createAgentController({
      mandate: loaded.mandate, mandateError: null, mandateAuthorities: [OPERATOR_ADDR],
      approvalSecret: 'auth-test-approval-secret-0123456789ab',
      operatorSecret: 'auth-test-operator-secret-0123456789ab',
      approvalTtlMs: 300000, requestTtlMs: 900000,
      store, spendingLedger: createSpendingLedger({})
    });
    const realFetch = global.fetch;
    const origKey = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    global.fetch = async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify({
        verdict: 'MATCH', confidence: 0.9, summary: 'canned MATCH',
        discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
      }) } }] })
    });
    try {
      const body = { transaction: { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x1000', chainId: '0x7a69' } };
      const p = ctlReqRes(body, {}, { keyId: 'alpha', development: false });
      await controller.handlePropose(p.req, p.res);
      const created = await p.done;
      assert.strictEqual(created.status, 200, JSON.stringify(created.body));
      const id = created.body.requestId;
      assert.strictEqual(store.get(id).ownerKeyId, 'alpha', 'owner stamped at submit');
      const own = ctlReqRes(null, { id }, { keyId: 'alpha', development: false });
      await controller.handleStatus(own.req, own.res);
      assert.strictEqual((await own.done).status, 200, 'owner reads own request');
      const foreign = ctlReqRes(null, { id }, { keyId: 'beta', development: false });
      await controller.handleStatus(foreign.req, foreign.res);
      const denied = await foreign.done;
      assert.strictEqual(denied.status, 404, 'foreign key gets 404, not the record');
      assert.strictEqual(denied.body.error, 'Unknown request id.');
      const legacy = ctlReqRes(null, { id });
      await controller.handleStatus(legacy.req, legacy.res);
      assert.strictEqual((await legacy.done).status, 200, 'direct callers unaffected');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = origKey;
    }
    console.log('✔ Test 5 Passed: Owner stamped at submit; foreign reads 404; legacy callers pass.');
  }

  // Test 6: capacity guard enforces global and per-key caps; release is idempotent.
  {
    const guard = createCapacityGuard({ maxTotal: 2, maxPerKey: 1 });
    const ra = { agentKey: { keyId: 'alpha', development: false } };
    const rb = { agentKey: { keyId: 'beta', development: false } };
    const s1 = guard.acquire(ra);
    assert.strictEqual(s1.ok, true);
    const s2 = guard.acquire(ra);
    assert.strictEqual(s2.ok, false, 'per-key cap holds');
    assert.strictEqual(typeof s2.retryAfterMs, 'number');
    const s3 = guard.acquire(rb);
    assert.strictEqual(s3.ok, true, 'second key admitted under global cap');
    const s4 = guard.acquire({ agentKey: { keyId: 'gamma', development: false } });
    assert.strictEqual(s4.ok, false, 'global cap holds');
    s1.release();
    s1.release();
    const s5 = guard.acquire(ra);
    assert.strictEqual(s5.ok, true, 'released slot reusable exactly once');
    assert.deepStrictEqual(guard.stats(), { inFlight: 2, maxTotal: 2, maxPerKey: 1 });
    console.log('✔ Test 6 Passed: Capacity caps and release semantics exact.');
  }

  console.log('\nAll agent auth tests passed.');
}

if (require.main === module) {
  runAgentAuthTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentAuthTests };
