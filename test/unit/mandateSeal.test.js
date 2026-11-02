const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { loadMandate, evaluateMandate, checkMandateContinuity, sealMandateObject, verifyMandateSeal } = require('../../src/services/mandate');
const { createAgentStore } = require('../../src/services/agentStore');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentController } = require('../../src/controllers/agentController');
const { issueApproval } = require('../../src/services/approvals');
const { digestTx } = require('../../extension/shared/txDigest');
const { createSigner } = require('../../src/signer/signerService');
const { sealMandateFile } = require('../../src/signer/signMandate');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Mandate authenticity: EIP-191 seals over the canonical mandate body.
// Only mandates sealed by a trusted authority boot the signer or
// authorize policy decisions; file presence alone authorizes nothing.

const ORIGINAL_KEY = config.modelApiKey;
const SIGNER_KEY = generatePrivateKey();
const SIGNER = privateKeyToAccount(SIGNER_KEY).address;
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();
const FOREIGN_KEY = generatePrivateKey();
const APPROVAL_SECRET = 'seal-test-approval-secret-0123456789ab';
const OPERATOR_SECRET = 'seal-test-operator-secret-0123456789ab';

function fixtureMandate(overrides) {
  return {
    id: 'seal-mandate', version: 2, issuer: 'test-operator',
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
    reviewRules: [],
    ...(overrides || {})
  };
}

function scratchDir(label) {
  const base = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(base, { recursive: true });
  return fs.mkdtempSync(path.join(base, `${label}-`));
}

async function sealedMandate(overrides, key) {
  const dir = scratchDir('seal-mandate');
  try {
    const file = path.join(dir, 'mandate.json');
    fs.writeFileSync(file, JSON.stringify(fixtureMandate(overrides)), 'utf8');
    const loaded = loadMandate(file);
    assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
    loaded.mandate.seal = await sealMandateObject(loaded.mandate, key || OPERATOR_KEY);
    return loaded.mandate;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function tx(overrides) {
  return { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x2386f26fc10000', chainId: '0x7a69', ...(overrides || {}) };
}

function treeHashFor(t) {
  const { decodeTransactionCalldata } = require('../../src/services/decoderService');
  const { hashSubcallTree } = require('../../src/services/nestedCalls');
  return hashSubcallTree(decodeTransactionCalldata({ to: t.to, data: t.data, value: t.value }));
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

function makeController(mandate, authorities) {
  return createAgentController({
    mandate, mandateError: null, mandateAuthorities: authorities,
    approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
    approvalTtlMs: 300000, requestTtlMs: 900000,
    store: createAgentStore({}), spendingLedger: createSpendingLedger({})
  });
}

function cannedMatch() {
  return async () => ({
    ok: true,
    json: async () => ({ choices: [{ message: { content: JSON.stringify({
      verdict: 'MATCH', confidence: 0.9, summary: 'canned MATCH',
      discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
    }) } }] })
  });
}

async function runMandateSealTests() {
  console.log('Testing mandate authenticity (seals + authorities)...\n');
  config.modelApiKey = 'test-live-key';
  const realFetch = global.fetch;

  // Test 11: correctly signed, active mandate accepted (file round-trip,
  // signer boot, and policy authorization).
  {
    const dir = scratchDir('seal-t11');
    const file = path.join(dir, 'mandate.json');
    fs.writeFileSync(file, JSON.stringify(fixtureMandate()), 'utf8');
    const sealed = await sealMandateFile(file, OPERATOR_KEY);
    assert.strictEqual(sealed.authority, OPERATOR_ADDR);
    assert.ok(fs.existsSync(`${file}.bak`), 'sealing preserves a backup');
    const loaded = loadMandate(file);
    assert.strictEqual(loaded.ok, true);
    const check = await verifyMandateSeal({ mandate: loaded.mandate, authorities: [OPERATOR_ADDR] });
    assert.strictEqual(check.ok, true, JSON.stringify(check.error || 'verified'));
    assert.strictEqual(check.authority, OPERATOR_ADDR);
    const signer = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: loaded.mandate, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
      consumedFile: null, stateFile: null, policyCallbackUrl: null, clients: null
    });
    assert.strictEqual(signer.sealAuthority, OPERATOR_ADDR);
    global.fetch = cannedMatch();
    try {
      const c = makeController(loaded.mandate, [OPERATOR_ADDR]);
      const { req, res, done } = mockReqRes({ transaction: tx() });
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.body.decision, 'ALLOW', 'sealed active mandate authorizes');
      assert.ok(out.body.approval, 'ALLOW issues a token');
    } finally {
      global.fetch = realFetch;
    }
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 11 Passed: Sealed active mandate accepted.');
  }

  // Test 12: tampered mandate rejected (any byte change breaks the seal).
  {
    const base = await sealedMandate();
    const tampers = [
      ['recipient', (m) => { m.recipientsAllow.push('0x000000000000000000000000000000000000dead'); }],
      ['limit', (m) => { m.maxNativePerTxWei = '999999999999999999999'; }],
      ['version', (m) => { m.version = 99; }],
      ['sender', (m) => { m.senders.push(RECIPIENT.toLowerCase()); }],
      ['revocation', (m) => { m.revokedVersions.push(2); }]
    ];
    for (const [label, mutate] of tampers) {
      const copy = JSON.parse(JSON.stringify(base));
      mutate(copy);
      const check = await verifyMandateSeal({ mandate: copy, authorities: [OPERATOR_ADDR] });
      assert.strictEqual(check.ok, false, `${label} tamper must fail verification`);
      assert.ok(/do not match the seal/.test(check.error), `${label}: reason names mismatch`);
      await assert.rejects(() => createSigner({
        approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
        mandate: copy, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
        consumedFile: null, stateFile: null, policyCallbackUrl: null, clients: null
      }), /do not match the seal/, `${label}: signer refuses tampered mandate`);
    }
    console.log('✔ Test 12 Passed: Tampered mandates rejected.');
  }

  // Test 13: signature from an untrusted key rejected.
  {
    const foreign = await sealedMandate(null, FOREIGN_KEY);
    const check = await verifyMandateSeal({ mandate: foreign, authorities: [OPERATOR_ADDR] });
    assert.strictEqual(check.ok, false);
    assert.ok(/not trusted/.test(check.error));
    await assert.rejects(() => createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: foreign, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
      consumedFile: null, stateFile: null, policyCallbackUrl: null, clients: null
    }), /not trusted/);
    console.log('✔ Test 13 Passed: Untrusted authority rejected.');
  }

  // Test 14: expired mandate rejected at enforcement (seal proves origin,
  // liveness checks prove currency — both required).
  {
    const expired = await sealedMandate({ notBefore: '2024-01-01T00:00:00Z', expiresAt: '2024-06-01T00:00:00Z' });
    const check = await verifyMandateSeal({ mandate: expired, authorities: [OPERATOR_ADDR] });
    assert.strictEqual(check.ok, true, 'genuine but expired seal still verifies as authentic');
    assert.strictEqual(
      evaluateMandate({ mandate: expired, mandateError: null, tx: tx(), decodedTx: { functionName: 'unknownFunction' }, nowMs: Date.now(), ledger: null }).decision,
      'BLOCK', 'expired mandate blocks');
    const signer = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: expired, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
      consumedFile: null, stateFile: null, policyCallbackUrl: null, clients: null
    });
    const t = tx();
    const v = signer.verify({
      requestId: 'agent_seal-14', transaction: t,
      approval: issueApproval({
        secret: APPROVAL_SECRET, requestId: 'agent_seal-14', txDigest: digestTx(t),
        chainId: t.chainId, sender: t.from, mandateId: 'seal-mandate',
        mandateVersion: 2, policyId: 'assertara-agent-mvp-1',
        requiresOperator: false, ttlMs: 300000, nowMs: Date.now()
      })
    });
    assert.strictEqual(v.ok, false);
    assert.ok(/expired/.test(v.error));
    console.log('✔ Test 14 Passed: Expired mandate rejected.');
  }

  // Test 15: revoked mandate rejected at enforcement.
  {
    const revoked = await sealedMandate({ revokedVersions: [2] });
    assert.strictEqual((await verifyMandateSeal({ mandate: revoked, authorities: [OPERATOR_ADDR] })).ok, true, 'revocation is sealed in, not a seal break');
    assert.strictEqual(
      evaluateMandate({ mandate: revoked, mandateError: null, tx: tx(), decodedTx: { functionName: 'unknownFunction' }, nowMs: Date.now(), ledger: null }).decision,
      'BLOCK', 'revoked mandate blocks');
    const signer = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: revoked, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
      consumedFile: null, stateFile: null, policyCallbackUrl: null, clients: null
    });
    const t = tx();
    const v = signer.verify({
      requestId: 'agent_seal-15', transaction: t,
      approval: issueApproval({
        secret: APPROVAL_SECRET, requestId: 'agent_seal-15', txDigest: digestTx(t),
        chainId: t.chainId, sender: t.from, mandateId: 'seal-mandate',
        mandateVersion: 2, policyId: 'assertara-agent-mvp-1',
        requiresOperator: false, ttlMs: 300000, nowMs: Date.now()
      })
    });
    assert.strictEqual(v.ok, false);
    assert.ok(/revoked/.test(v.error));
    console.log('✔ Test 15 Passed: Revoked mandate rejected.');
  }

  // Test 16: older sealed version cannot replace a newer one.
  {
    const dir = scratchDir('seal-t16');
    const v2 = await sealedMandate();
    const v1 = await sealedMandate({ version: 1 });
    assert.strictEqual(checkMandateContinuity({ last: { id: v2.id, version: 2 }, current: v1 }).ok, false);
    const stateFile = path.join(dir, 'signer-state.json');
    await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: v2, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
      consumedFile: null, stateFile, policyCallbackUrl: null, clients: null
    });
    await assert.rejects(() => createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: v1, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
      consumedFile: null, stateFile, policyCallbackUrl: null, clients: null
    }), /rollback/);
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 16 Passed: Version rollback refused.');
  }

  // Test 17: approval bound to one version cannot authorize another.
  {
    const v2 = await sealedMandate();
    const v3 = await sealedMandate({ version: 3 });
    const t = tx();
    const tokenV2 = issueApproval({
      secret: APPROVAL_SECRET, requestId: 'agent_seal-17', txDigest: digestTx(t),
      chainId: t.chainId, sender: t.from, mandateId: 'seal-mandate',
      mandateVersion: 2, policyId: 'assertara-agent-mvp-1', subcallTreeHash: treeHashFor(t),
      requiresOperator: false, ttlMs: 300000, nowMs: Date.now()
    });
    const s3 = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: v3, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
      consumedFile: null, stateFile: null, policyCallbackUrl: null, clients: null
    });
    assert.strictEqual(s3.verify({ requestId: 'agent_seal-17', transaction: t, approval: tokenV2 }).ok, false, 'v2 approval cannot authorize v3 signer');
    const s2 = await createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate: v2, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
      consumedFile: null, stateFile: null, policyCallbackUrl: null, clients: null
    });
    assert.strictEqual(s2.verify({ requestId: 'agent_seal-17', transaction: t, approval: tokenV2 }).ok, true, 'matching version verifies');
    void v2;
    console.log('✔ Test 17 Passed: Cross-version approvals refused.');
  }

  // Test 18: agent-supplied seal material cannot bypass verification.
  {
    const mandate = await sealedMandate();
    // Even a GENUINE operator seal over an allow-all mandate, smuggled in
    // the proposal body, is ignored: only the operator file authorizes.
    const smuggled = await sealedMandate({
      recipients: { allow: ['0x000000000000000000000000000000000000dEaD'], deny: [] }
    });
    global.fetch = cannedMatch();
    try {
      const c = makeController(mandate, [OPERATOR_ADDR]);
      const { req, res, done } = mockReqRes({
        seal: smuggled.seal,
        mandate: { id: 'smuggled' },
        transaction: tx({ to: '0x000000000000000000000000000000000000dEaD' })
      });
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.body.decision, 'BLOCK', 'smuggled seal cannot allowlist');
      assert.strictEqual(out.body.mandate.id, 'seal-mandate', 'operator file stays authoritative');
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 18 Passed: Smuggled seals ignored.');
  }

  // Test 19: unsupported or malformed seal formats rejected.
  {
    const base = await sealedMandate();
    const cases = [
      ['missing seal', null, /not sealed/],
      ['bad format', { ...base.seal, format: 'evil-1' }, /unsupported.*format/],
      ['bad algorithm', { ...base.seal, algorithm: 'rot13' }, /unsupported.*algorithm/],
      ['bad authority', { ...base.seal, authority: '0x123' }, /authority is malformed/],
      ['bad signature', { ...base.seal, signature: '0xdead' }, /signature is malformed/],
      ['non-object seal', 'signed-trust-me', /not sealed/]
    ];
    for (const [label, seal, re] of cases) {
      const copy = JSON.parse(JSON.stringify(base));
      copy.seal = seal;
      const check = await verifyMandateSeal({ mandate: copy, authorities: [OPERATOR_ADDR] });
      assert.strictEqual(check.ok, false, `${label} must fail`);
      assert.ok(re.test(check.error), `${label}: named reason (${check.error})`);
    }
    console.log('✔ Test 19 Passed: Malformed seals rejected.');
  }

  // Test 20: missing signing configuration fails closed everywhere.
  {
    const mandate = await sealedMandate();
    await assert.rejects(() => createSigner({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
      mandate, privateKey: SIGNER_KEY,
      consumedFile: null, stateFile: null, policyCallbackUrl: null, clients: null
    }), /authority is not configured/, 'signer needs authorities');
    global.fetch = cannedMatch();
    try {
      const c = makeController(mandate, null);
      const p = mockReqRes({ transaction: tx() });
      await c.handlePropose(p.req, p.res);
      const proposed = await p.done;
      assert.strictEqual(proposed.body.decision, 'UNCERTAIN', 'unverifiable mandate cannot authorize');
      assert.strictEqual(proposed.body.approval, null);
      const a = mockReqRes({ operatorSecret: OPERATOR_SECRET }, { id: 'agent_nope' });
      await c.handleAuthorize(a.req, a.res);
      assert.strictEqual((await a.done).status, 503, 'authorize refuses without verified mandate');
      const r = mockReqRes({ txHash: `0x${'ab'.repeat(32)}` }, { id: 'agent_nope' });
      await c.handleReceipt(r.req, r.res);
      assert.strictEqual((await r.done).status, 503, 'receipts refuse without verified mandate');
    } finally {
      global.fetch = realFetch;
    }
    console.log('✔ Test 20 Passed: Missing config fails closed.');
  }

  config.modelApiKey = ORIGINAL_KEY;
  await closeOcrWorker();
  console.log('\nAll Mandate Seal Tests Passed Successfully!\n');
}

if (require.main === module) {
  runMandateSealTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runMandateSealTests };
