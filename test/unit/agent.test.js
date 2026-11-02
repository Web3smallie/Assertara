const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentStore } = require('../../src/services/agentStore');
const { createAgentController, combineDecisions } = require('../../src/controllers/agentController');
const { verifyApproval } = require('../../src/services/approvals');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { closeOcrWorker } = require('../../src/services/ocrService');

const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();

// Agent controller: proposal validation, investigation wiring, decision
// lattice, operator authorization. Model responses are canned (MOCKED);
// chain-dependent receipt tests live in the e2e suite with real Anvil.
const ORIGINAL_KEY = config.modelApiKey;

const SIGNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const APPROVAL_SECRET = 'agent-test-approval-secret-0123456789ab';
const OPERATOR_SECRET = 'agent-test-operator-secret-0123456789ab';

function fixtureMandate() {
  return {
    id: 'agent-test-mandate', version: 1, issuer: 'test-operator',
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

async function makeController(overrides) {
  const dir = path.join(__dirname, '..', 'tmp', `agent-ctl-${Date.now()}-${Math.floor(Math.random() * 1e6)}`);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'mandate.json');
  fs.writeFileSync(file, JSON.stringify(fixtureMandate()), 'utf8');
  const loaded = loadMandate(file);
  assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
  fs.rmSync(dir, { recursive: true, force: true });
  loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
  return createAgentController({
    mandate: loaded.mandate,
    mandateError: null,
    mandateAuthorities: [OPERATOR_ADDR],
    approvalSecret: APPROVAL_SECRET,
    operatorSecret: OPERATOR_SECRET,
    approvalTtlMs: 300000,
    requestTtlMs: 900000,
    store: createAgentStore({ ledgerFile: null }),
    spendingLedger: createSpendingLedger({}),
    ...(overrides || {})
  });
}

function cannedFetch(verdict, confidence) {
  return async (url) => ({
    ok: true,
    json: async () => ({ choices: [{ message: { content: JSON.stringify({
      verdict, confidence: confidence === undefined ? 0.9 : confidence,
      summary: `canned ${verdict}`, discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
    }) } }] })
  });
}

function validTx(overrides) {
  return { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x2386f26fc10000', chainId: '0x7a69', ...(overrides || {}) };
}

async function runAgentTests() {
  console.log('Testing agent controller (propose, decide, authorize)...\n');
  config.modelApiKey = 'test-live-key';
  const realFetch = global.fetch;

  // Test 1: malformed proposals rejected with 400, nothing stored.
  {
    const c = await makeController();
    const bad = [
      [null, 'null body'], ['str', 'non-object'],
      [{}, 'missing transaction'],
      [{ transaction: null }, 'null transaction'],
      [{ transaction: { to: RECIPIENT, chainId: '0x7a69' } }, 'missing from'],
      [{ transaction: { from: '0x123', to: RECIPIENT, chainId: '0x7a69' } }, 'bad from'],
      [{ transaction: { from: SIGNER, chainId: '0x7a69' } }, 'missing to'],
      [{ transaction: { from: SIGNER, to: null, chainId: '0x7a69' } }, 'contract creation'],
      [{ transaction: { from: SIGNER, to: '0x123', chainId: '0x7a69' } }, 'bad to'],
      [{ transaction: { from: SIGNER, to: RECIPIENT } }, 'missing chainId'],
      [{ transaction: { from: SIGNER, to: RECIPIENT, chainId: 'abc' } }, 'bad chainId'],
      [{ transaction: { from: SIGNER, to: RECIPIENT, chainId: '0x7a69', value: 'lots' } }, 'bad value'],
      [{ transaction: { from: SIGNER, to: RECIPIENT, chainId: '0x7a69', data: 'zzz' } }, 'bad data'],
      [{ transaction: { from: SIGNER, to: RECIPIENT, chainId: '0x7a69' }, screenshot: 'abc' }, 'agent screenshot refused'],
      [{ transaction: { from: SIGNER, to: RECIPIENT, chainId: '0x7a69' }, intent: 'x' }, 'bad intent'],
      [{ transaction: { from: SIGNER, to: RECIPIENT, chainId: '0x7a69' }, intent: { purpose: 'x'.repeat(2001) } }, 'oversize purpose']
    ];
    for (const [body, label] of bad) {
      const { req, res, done } = mockReqRes(body);
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.status, 400, `${label} must be rejected`);
    }
    console.log('✔ Test 1 Passed: Malformed proposals rejected.');
  }

  // Test 2: in-mandate transfer with model MATCH allows and issues a token.
  {
    const c = await makeController();
    global.fetch = cannedFetch('MATCH', 0.95);
    try {
      const { req, res, done } = mockReqRes({ agentId: 'demo-agent', intent: { purpose: 'Pay contributor 0.01 ETH' }, transaction: validTx() });
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.status, 200);
      assert.strictEqual(out.body.decision, 'ALLOW');
      assert.ok(out.body.approval, 'ALLOW issues an approval token');
      assert.strictEqual(out.body.visual.status, 'NOT_APPLICABLE', 'code-only visual branch marked');
      assert.ok(Array.isArray(out.body.mandateChecks) && out.body.mandateChecks.every((k) => k.pass), 'all mandate checks pass');
      assert.ok(out.body.reasons.some((r) => r.startsWith('mandate:')), 'mandate reasons cited');
      const v = verifyApproval({ secret: APPROVAL_SECRET, token: out.body.approval, nowMs: Date.now() });
      assert.strictEqual(v.ok, true, 'issued token verifies');
      assert.strictEqual(v.payload.requestId, out.body.requestId);
      assert.strictEqual(v.payload.requiresOperator, false);
      const st = mockReqRes(null, { id: out.body.requestId });
      await c.handleStatus(st.req, st.res);
      const status = await st.done;
      assert.strictEqual(status.body.status, 'APPROVED');
      assert.strictEqual(status.body.approvalToken, out.body.approval);
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 2 Passed: ALLOW issues a verifiable token.');
  }

  // Test 3: mandate violation blocks despite model MATCH (mandate supremacy).
  {
    const c = await makeController();
    global.fetch = cannedFetch('MATCH', 0.99);
    try {
      const { req, res, done } = mockReqRes({ transaction: validTx({ to: SIGNER }) });
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.body.decision, 'BLOCK', 'non-allowlisted recipient blocks');
      assert.strictEqual(out.body.approval, null, 'BLOCK issues no token');
      assert.ok(out.body.reasons.some((r) => /allowlist/.test(r)), 'mandate reason cited');
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 3 Passed: Mandate BLOCK dominates model MATCH.');
  }

  // Test 4: above-threshold value holds for operator; authorize releases a token.
  {
    const c = await makeController();
    global.fetch = cannedFetch('MATCH', 0.95);
    try {
      const { req, res, done } = mockReqRes({ transaction: validTx({ value: '0x470de4df820000' }) }); // 0.02 ETH
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.body.decision, 'REVIEW');
      assert.strictEqual(out.body.approval, null, 'REVIEW issues no usable token yet');
      assert.strictEqual(out.body.operatorAuthorizationRequired, true);
      const id = out.body.requestId;
      const bad = mockReqRes({ operatorSecret: 'wrong' }, { id });
      await c.handleAuthorize(bad.req, bad.res);
      assert.strictEqual((await bad.done).status, 403, 'wrong operator secret rejected');
      const good = mockReqRes({ operatorSecret: OPERATOR_SECRET }, { id });
      await c.handleAuthorize(good.req, good.res);
      const auth = await good.done;
      assert.strictEqual(auth.status, 200);
      assert.ok(auth.body.approval, 'operator authorization mints a token');
      const v = verifyApproval({ secret: APPROVAL_SECRET, token: auth.body.approval, nowMs: Date.now() });
      assert.strictEqual(v.ok, true);
      assert.strictEqual(v.payload.requiresOperator, true);
      assert.ok(v.payload.operatorSig, 'countersignature embedded');
      // Idempotent re-authorization returns the same live token.
      const again = mockReqRes({ operatorSecret: OPERATOR_SECRET }, { id });
      await c.handleAuthorize(again.req, again.res);
      assert.strictEqual((await again.done).body.approval, auth.body.approval);
      // Non-REVIEW requests cannot be authorized.
      const other = mockReqRes({ transaction: validTx() });
      await c.handlePropose(other.req, other.res);
      const otherOut = await other.done;
      const nope = mockReqRes({ operatorSecret: OPERATOR_SECRET }, { id: otherOut.body.requestId });
      await c.handleAuthorize(nope.req, nope.res);
      assert.strictEqual((await nope.done).status, 409, 'ALLOW request needs no operator');
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 4 Passed: Operator authorization exact.');
  }

  // Test 5: undecodable calldata holds as UNCERTAIN with no token.
  {
    const c = await makeController();
    global.fetch = cannedFetch('MATCH', 0.9);
    try {
      // Recipient allowlisted for nothing: use a contract-shaped call the
      // mandate cannot clear AND the decoder cannot parse.
      const { req, res, done } = mockReqRes({
        transaction: validTx({ to: RECIPIENT, data: '0xdeadbeef00000000000000000000000000000000000000000000000000000000', value: '0x0' })
      });
      await c.handlePropose(req, res);
      const out = await done;
      // Mandate blocks non-allowlisted contract calls; investigation is
      // UNCERTAIN via the unknown-function safeguard. Either way: no token.
      assert.ok(out.body.decision === 'BLOCK' || out.body.decision === 'UNCERTAIN');
      assert.strictEqual(out.body.approval, null);
      assert.strictEqual(out.body.investigation.verdict, 'UNCERTAIN', 'unknown selector downgraded');
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 5 Passed: Undecodable calldata never approves.');
  }

  // Test 6: decision lattice exact (BLOCK > UNCERTAIN > REVIEW > ALLOW).
  {
    assert.strictEqual(combineDecisions('ALLOW', 'ALLOW'), 'ALLOW');
    assert.strictEqual(combineDecisions('ALLOW', 'BLOCK'), 'BLOCK');
    assert.strictEqual(combineDecisions('MATCH', 'ALLOW'), 'UNCERTAIN', 'unknown inputs fail closed');
    assert.strictEqual(combineDecisions('REVIEW', 'ALLOW'), 'REVIEW');
    assert.strictEqual(combineDecisions('UNCERTAIN', 'REVIEW'), 'UNCERTAIN', 'uncertainty dominates review');
    assert.strictEqual(combineDecisions('REVIEW', 'UNCERTAIN'), 'UNCERTAIN');
    assert.strictEqual(combineDecisions('BLOCK', 'UNCERTAIN'), 'BLOCK');
    assert.strictEqual(combineDecisions(null, null), 'UNCERTAIN');
    console.log('✔ Test 6 Passed: Decision lattice exact.');
  }

  // Test 7: missing mandate fails closed; missing secrets disable endpoints.
  {
    const c = await makeController({ mandate: null, mandateError: 'MANDATE_FILE is not configured' });
    global.fetch = cannedFetch('MATCH', 0.95);
    try {
      const { req, res, done } = mockReqRes({ transaction: validTx() });
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.body.decision, 'UNCERTAIN', 'no mandate cannot authorize');
      assert.strictEqual(out.body.approval, null);
      assert.strictEqual(out.body.mandate, null);
    } finally {
      global.fetch = realFetch;
    }
    const c2 = await makeController({ approvalSecret: null });
    const r2 = mockReqRes({ transaction: validTx() });
    await c2.handlePropose(r2.req, r2.res);
    assert.strictEqual((await r2.done).status, 503, 'missing approval secret disables proposing');
    const c3 = await makeController({ operatorSecret: null });
    global.fetch = cannedFetch('MATCH', 0.95);
    try {
      const p3 = mockReqRes({ transaction: validTx({ value: '0x470de4df820000' }) });
      await c3.handlePropose(p3.req, p3.res);
      const out3 = await p3.done;
      assert.strictEqual(out3.body.operatorAvailable, false);
      const a3 = mockReqRes({ operatorSecret: 'x' }, { id: out3.body.requestId });
      await c3.handleAuthorize(a3.req, a3.res);
      assert.strictEqual((await a3.done).status, 503, 'missing operator secret disables authorize');
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 7 Passed: Missing authority fails closed.');
  }

  // Test 8: receipt/callback guards that need no chain.
  {
    const c = await makeController();
    const unknown = mockReqRes({ txHash: `0x${'ab'.repeat(32)}` }, { id: 'agent_nope' });
    await c.handleReceipt(unknown.req, unknown.res);
    assert.strictEqual((await unknown.done).status, 404);
    const badHash = mockReqRes({ txHash: 'nope' }, { id: 'agent_nope' });
    await c.handleReceipt(badHash.req, badHash.res);
    assert.strictEqual((await badHash.done).status, 400, 'malformed hash rejected before lookup');
    const badCb = mockReqRes({ requestId: 'x', nonce: 'y', txHash: `0x${'ab'.repeat(32)}`, sig: 'zz' });
    await c.handleSignerCallback(badCb.req, badCb.res);
    assert.strictEqual((await badCb.done).status, 401, 'forged callback rejected');
    const info = mockReqRes(null, {});
    await c.handleMandateInfo(info.req, info.res);
    const infoOut = await info.done;
    assert.strictEqual(infoOut.body.configured, true);
    assert.strictEqual(infoOut.body.version, 1);
    assert.ok(!('spenderAllowlist' in infoOut.body) && !('recipients' in infoOut.body), 'no policy details leaked');
    console.log('✔ Test 8 Passed: Receipt/callback guards exact.');
  }

  // Test 9 (Capability 5 B1): allowlisted batch with an unauthorized
  // inner approval is BLOCKed end to end (mandate sees inners).
  {
    const { encodeFunctionData } = require('viem');
    const { UNISWAP_V3_ROUTER_ABI, ERC20_ABI } = require('../../src/utils/abiSignatures');
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const STRANGER = '0x000000000000000000000000000000000000dEaD';
    const inner = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [STRANGER, 100n] });
    const data = encodeFunctionData({ abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [[inner]] });
    const raw = fixtureMandate();
    raw.contracts = { allow: [ROUTER] };
    raw.selectors = { allow: [data.slice(0, 10).toLowerCase(), '0x095ea7b3'] };
    raw.recipients = { allow: [RECIPIENT, ROUTER], deny: [] };
    const dir = path.join(__dirname, '..', 'tmp', `agent-ctl-b1-${Date.now()}`);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'mandate.json');
    fs.writeFileSync(file, JSON.stringify(raw), 'utf8');
    const loaded = loadMandate(file);
    assert.strictEqual(loaded.ok, true);
    fs.rmSync(dir, { recursive: true, force: true });
    loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
    const c = createAgentController({
      mandate: loaded.mandate, mandateError: null, mandateAuthorities: [OPERATOR_ADDR],
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      approvalTtlMs: 300000, requestTtlMs: 900000,
      store: createAgentStore({ ledgerFile: null }), spendingLedger: createSpendingLedger({})
    });
    global.fetch = cannedFetch('MATCH', 0.99);
    try {
      const { req, res, done } = mockReqRes({
        transaction: { from: SIGNER, to: ROUTER, data, value: '0x0', chainId: '0x7a69' },
        intent: { purpose: 'batch rebalance' }
      });
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.body.decision, 'BLOCK', 'inner unauthorized spender blocks the batch');
      assert.strictEqual(out.body.approval, null, 'BLOCK issues no token');
      assert.ok(out.body.reasons.some((r) => /SC-001/.test(r)), 'inner provenance cited');
      assert.ok((out.body.mandateChecks || []).some((k) => k.id === 'inner-SC-001-approval-spender' && !k.pass));
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 9 Passed: Inner mandate violation blocks end to end.');
  }

  config.modelApiKey = ORIGINAL_KEY;
  await closeOcrWorker();
  console.log('\nAll Agent Controller Tests Passed Successfully!\n');
}

if (require.main === module) {
  runAgentTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentTests };
