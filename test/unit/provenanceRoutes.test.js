// Provenance-route tests: the HTTP controller over temp stores with a
// stub agent store. Direct handler invocation (no HTTP server, no
// chain, no model). Live publish/verify-PASS paths are covered by
// test/e2e/sdkProvenance.test.js against Anvil.
process.env.INVESTIGATIONS_FILE = require('path').join(__dirname, '..', 'tmp', `route-inv-${process.pid}.jsonl`);

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const T0 = 1793600000000; // 2026-11-02, inside the 2020–2100 window
const hex = (c) => String(c).repeat(64);
const TXHASH = `0x${'ab'.repeat(32)}`;
const ALPHA = 'alpha';
const BETA = 'beta';

function baseRecord() {
  return {
    recordId: 'inv_route_1', id: 'eval_route_1', traceId: 'tr_route_1',
    requestId: 'agent_route_1', recordedAt: T0, receivedAt: T0 - 1000,
    durationMs: 1000, investigationPath: 'agent', chainId: '31337',
    sender: '0xaaaa', to: '0xbbbb', verdict: 'MATCH', confidence: 0.9,
    recommendedAction: 'PROCEED',
    policyDecision: { decision: 'ALLOW', reasons: ['within mandate'] },
    verdictSafeguards: [],
    txBinding: { receivedTxDigest: hex('a'), evaluatedTxDigest: hex('b'), match: true },
    decodedTransaction: { contract: '0xbbbb', contractName: 'T', functionName: 'transfer', standard: 'ERC20', valueEth: '0.005', isUnlimitedApproval: false },
    ruleFindings: [{ ruleId: 'R1' }],
    museProvenance: {
      status: 'success', provider: 'meta-model-api', endpoint: 'chat/completions',
      requested: 'muse-spark-1.3', served: 'muse-spark-1.3', responseId: 'resp_1',
      invokedAt: T0, completedAt: T0 + 1000, inputDigest: hex('c'), outputDigest: hex('d'),
      latencyMs: 1000, usage: { prompt_tokens: 5, completion_tokens: 6, total_tokens: 11 }
    },
    samProvenance: {
      status: 'skipped', provider: 'meta-model-api', requested: 'sam-3.1', observed: null,
      invokedAt: null, completedAt: null, attempts: 0, usage: null,
      outputDigest: null, screenshotDigest: null, submittedImageDigest: null,
      detectedCount: 0, perPrompt: []
    },
    investigation: { verdict: 'MATCH' },
    visualEvidence: { regions: [] },
    evidencePacking: { truncations: [] },
    referenceValidation: { present: true, ok: true },
    reasoningOrigin: 'model',
    ownerKeyId: ALPHA
  };
}

function baseRequest() {
  return {
    id: 'agent_route_1', traceId: 'tr_route_1', evalId: 'eval_route_1',
    status: 'EXECUTED', decision: 'ALLOW', reasons: ['within mandate'],
    txDigest: hex('b'), evalVerdict: 'MATCH',
    normalizedTx: { chainId: 31337 },
    execution: { outcome: 'EXECUTED', txHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x10' },
    ownerKeyId: ALPHA
  };
}

function fakeRes() {
  const res = { statusCode: 200, body: undefined };
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (o) => { res.body = o; return res; };
  return res;
}

const reqAs = (keyId, { body, params } = {}) => ({
  body: body || {},
  params: params || {},
  agentKey: { keyId, development: false }
});

async function runProvenanceRouteTests() {
  console.log('Testing provenance HTTP routes (temp stores)...\n');
  const { createProvenanceController } = require('../../src/controllers/provenanceController');
  const { persistInvestigation } = require('../../src/services/investigationStore');
  const A = require('../../src/services/provenanceAttestation');
  const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');

  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'unit-routes-'));
  const manifestStore = path.join(tmp, 'manifests.jsonl');
  const storeDir = path.join(tmp, 'ceremony');
  fs.mkdirSync(storeDir, { recursive: true });
  const registryFile = path.join(tmp, 'registry.json');

  const dayKey = generatePrivateKey();
  const dayAddr = privateKeyToAccount(dayKey).address.toLowerCase();
  const rootKey = generatePrivateKey();
  const rootAddr = privateKeyToAccount(rootKey).address.toLowerCase();
  const skeleton = A.buildRegistrySkeleton({ version: 0, publishedAt: T0 });
  skeleton.keys[dayAddr] = { reason: 'route test key', status: 'ACTIVE', statusChangedAt: T0, supersededBy: null, validFrom: T0 };
  const registry = await A.signRegistry({ registry: skeleton, rootPrivateKey: rootKey });
  fs.writeFileSync(registryFile, JSON.stringify(registry), 'utf8');

  persistInvestigation(baseRecord(), process.env.INVESTIGATIONS_FILE);
  const requests = new Map([['agent_route_1', baseRequest()]]);
  const store = { get: (id) => requests.get(id) || null };
  const OPERATOR = 'route-operator-secret';

  const cfg = {
    manifestStore, storeDir, registryFile,
    trustedRoot: rootAddr, trustedAuthoritiesRaw: dayAddr, denyListRaw: null,
    signingEnabled: true, signingKey: dayKey,
    publishEnabled: false, publisherKey: null,
    rpcUrl: null, contractAddress: null, chainId: null, contractVersion: 2,
    minRegistryVersion: null, maxRegistryAgeDays: null
  };
  const c = createProvenanceController({ store, operatorSecret: OPERATOR, config: cfg });
  const savedDigestHolder = { digest: null };

  // Test 1: buildManifest gating + success + idempotence.
  {
    let res = fakeRes();
    await c.handleBuildManifest(reqAs(ALPHA, { body: {} }), res);
    assert.strictEqual(res.statusCode, 400, 'missing requestId 400');
    res = fakeRes();
    await c.handleBuildManifest(reqAs(ALPHA, { body: { requestId: 'nope' } }), res);
    assert.strictEqual(res.statusCode, 404, 'unknown request 404');
    res = fakeRes();
    await c.handleBuildManifest(reqAs(BETA, { body: { requestId: 'agent_route_1' } }), res);
    assert.strictEqual(res.statusCode, 404, 'foreign owner 404');
    requests.set('agent_noeval', { ...baseRequest(), id: 'agent_noeval', evalId: null });
    res = fakeRes();
    await c.handleBuildManifest(reqAs(ALPHA, { body: { requestId: 'agent_noeval' } }), res);
    assert.strictEqual(res.statusCode, 409, 'no persisted investigation 409');
    res = fakeRes();
    await c.handleBuildManifest(reqAs(ALPHA, { body: { requestId: 'agent_route_1' } }), res);
    assert.strictEqual(res.statusCode, 200, `build ok (got ${res.statusCode}: ${JSON.stringify(res.body)})`);
    assert.ok(/^[0-9a-f]{64}$/.test(res.body.manifestDigest), 'digest returned');
    assert.strictEqual(res.body.manifest.investigationId, 'eval_route_1', 'manifest binds investigation');
    const first = res.body.manifestDigest;
    res = fakeRes();
    await c.handleBuildManifest(reqAs(ALPHA, { body: { requestId: 'agent_route_1' } }), res);
    assert.strictEqual(res.body.manifestDigest, first, 'idempotent rebuild, same digest');
    console.log('✔ Test 1 Passed: buildManifest gating + deterministic rebuild.');
    savedDigestHolder.digest = first;
  }
  const savedDigest = savedDigestHolder.digest;

  // Test 2: getManifest + getExport gating; export 409 before ceremony.
  {
    let res = fakeRes();
    await c.handleGetManifest(reqAs(ALPHA, { params: { digest: 'zzz' } }), res);
    assert.strictEqual(res.statusCode, 400, 'bad digest 400');
    res = fakeRes();
    await c.handleGetManifest(reqAs(ALPHA, { params: { digest: hex('9') } }), res);
    assert.strictEqual(res.statusCode, 404, 'unknown digest 404');
    res = fakeRes();
    await c.handleGetManifest(reqAs(BETA, { params: { digest: savedDigest } }), res);
    assert.strictEqual(res.statusCode, 404, 'foreign owner 404');
    res = fakeRes();
    await c.handleGetManifest(reqAs(ALPHA, { params: { digest: savedDigest } }), res);
    assert.strictEqual(res.statusCode, 200, 'owner reads manifest');
    res = fakeRes();
    await c.handleGetExport(reqAs(ALPHA, { params: { digest: savedDigest } }), res);
    assert.strictEqual(res.statusCode, 409, 'export before ceremony 409');
    assert.strictEqual(res.body.code, 'NOT_ATTESTED', 'NOT_ATTESTED code');
    console.log('✔ Test 2 Passed: manifest/export reads; NOT_ATTESTED before ceremony.');
  }

  // Test 3: ceremony gating (operator + opt-in).
  {
    let res = fakeRes();
    await c.handleCeremony(reqAs(ALPHA, { body: { digest: savedDigest, expectDigest: savedDigest, confirm: true } }), res);
    assert.strictEqual(res.statusCode, 403, 'missing operator credential 403');
    res = fakeRes();
    await c.handleCeremony(reqAs(ALPHA, { body: { digest: savedDigest, expectDigest: savedDigest, confirm: true, operatorSecret: 'wrong' } }), res);
    assert.strictEqual(res.statusCode, 403, 'wrong operator credential 403');
    const disabled = createProvenanceController({ store, operatorSecret: OPERATOR, config: { ...cfg, signingEnabled: false } });
    res = fakeRes();
    await disabled.handleCeremony(reqAs(ALPHA, { body: { digest: savedDigest, expectDigest: savedDigest, confirm: true, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.statusCode, 503, 'disabled ceremony 503');
    const noKey = createProvenanceController({ store, operatorSecret: OPERATOR, config: { ...cfg, signingKey: null } });
    res = fakeRes();
    await noKey.handleCeremony(reqAs(ALPHA, { body: { digest: savedDigest, expectDigest: savedDigest, confirm: true, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.statusCode, 503, 'missing signing key 503');
    res = fakeRes();
    await c.handleCeremony(reqAs(ALPHA, { body: { digest: savedDigest, confirm: true, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.statusCode, 400, 'missing expectDigest 400');
    console.log('✔ Test 3 Passed: ceremony operator + opt-in gates.');
  }

  // Test 4: ceremony preview then sign; no key material in responses.
  {
    const { buildVerificationPackage, buildManifest } = require('../../src/services/provenanceManifest');
    const { findByEvalId } = require('../../src/services/investigationStore');
    const record = findByEvalId('eval_route_1').record;
    const built = buildManifest({ record, request: baseRequest() });
    const tampered = buildVerificationPackage(built);
    tampered.manifest.decision.agent = 'BLOCK';
    // Fresh identity + tampered package: refusal reported as
    // attested:false (mirrors the CLI result object; no throw).
    let res = fakeRes();
    await c.handleCeremony(reqAs(ALPHA, { body: { package: tampered, expectDigest: savedDigest, confirm: true, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.statusCode, 200, 'tamper refusal is a 200 result');
    assert.strictEqual(res.body.attested, false, 'tampered package not attested');
    assert.strictEqual(res.body.code, 'ATTEST_PACKAGE_INVALID', 'tamper refusal code');
    res = fakeRes();
    await c.handleCeremony(reqAs(ALPHA, { body: { digest: savedDigest, expectDigest: savedDigest, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.statusCode, 200, 'preview 200');
    assert.strictEqual(res.body.attested, false, 'preview does not attest');
    assert.ok(res.body.preview && res.body.preview.manifestDigest === savedDigest, 'preview carries digest');
    res = fakeRes();
    await c.handleCeremony(reqAs(ALPHA, { body: { digest: savedDigest, expectDigest: savedDigest, confirm: true, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.statusCode, 200, `sign 200 (got ${res.statusCode}: ${JSON.stringify(res.body)})`);
    assert.strictEqual(res.body.attested, true, 'ceremony attests');
    assert.ok(res.body.attestation && res.body.attestation.body, 'attestation returned');
    const blob = JSON.stringify(res.body);
    assert.ok(!blob.includes(dayKey.slice(2)), 'signing key absent from response');
    assert.ok(!blob.includes(OPERATOR), 'operator credential absent from response');
    // Idempotent retry adopts the existing attestation (no duplicate).
    res = fakeRes();
    await c.handleCeremony(reqAs(ALPHA, { body: { digest: savedDigest, expectDigest: savedDigest, confirm: true, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.body.attested, true, 'retry still attested');
    assert.ok(res.body.adopted && res.body.adopted.attestation, 'retry adopts prior completion');
    const lines = fs.readFileSync(path.join(storeDir, 'attestations.jsonl'), 'utf8').trim().split('\n');
    assert.strictEqual(lines.length, 1, 'exactly one attestation line (no duplicate)');
    // Retry with a mismatched package is refused outright (the core
    // validates the supplied package; adoption only applies to the
    // matching completion). No new signature is minted.
    res = fakeRes();
    await c.handleCeremony(reqAs(ALPHA, { body: { package: tampered, expectDigest: savedDigest, confirm: true, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.body.attested, false, 'mismatched retry refused');
    const lines2 = fs.readFileSync(path.join(storeDir, 'attestations.jsonl'), 'utf8').trim().split('\n');
    assert.strictEqual(lines2.length, 1, 'refused retry mints nothing');
    console.log('✔ Test 4 Passed: tamper refused; preview → sign → adopt; no secret leakage.');
  }

  // Test 5: export works after ceremony.
  {
    const ex = fakeRes();
    await c.handleGetExport(reqAs(ALPHA, { params: { digest: savedDigest } }), ex);
    assert.strictEqual(ex.statusCode, 200, 'export after ceremony 200');
    assert.strictEqual(ex.body.format, 'assertara-attestation-export-1', 'export format tag');
    assert.strictEqual(ex.body.manifestDigest, savedDigest, 'export digest binds');
    assert.ok(ex.body.package.attestation, 'export carries attestation');
    const blob = JSON.stringify(ex.body);
    assert.ok(!blob.includes(dayKey.slice(2)), 'signing key absent from export');
    console.log('✔ Test 5 Passed: export served after ceremony; no secret leakage.');
  }

  // Test 6: publish + verify gating (live paths in e2e).
  {
    let res = fakeRes();
    await c.handlePublish(reqAs(ALPHA, { body: { digest: savedDigest, operatorSecret: 'wrong' } }), res);
    assert.strictEqual(res.statusCode, 403, 'publish wrong operator 403');
    res = fakeRes();
    await c.handlePublish(reqAs(ALPHA, { body: { digest: savedDigest, operatorSecret: OPERATOR } }), res);
    assert.strictEqual(res.statusCode, 503, 'publish disabled 503');
    res = fakeRes();
    await c.handleVerify(reqAs(ALPHA, { body: { digest: savedDigest } }), res);
    assert.strictEqual(res.statusCode, 503, 'verify without rpc 503');
    const withRpc = createProvenanceController({
      store, operatorSecret: OPERATOR,
      config: { ...cfg, rpcUrl: 'http://127.0.0.1:9', contractAddress: '0x0000000000000000000000000000000000000001' }
    });
    res = fakeRes();
    await withRpc.handleVerify(reqAs(ALPHA, { body: { exported: { format: 'nope' } } }), res);
    assert.strictEqual(res.statusCode, 200, 'shape failure is a verdict, not a 500');
    assert.strictEqual(res.body.verdict, 'FAIL', 'bad export shape FAILs');
    assert.strictEqual(res.body.checks[0].name, 'export-shape', 'first check names the shape');
    console.log('✔ Test 6 Passed: publish/verify gates; shape FAIL without chain.');
  }

  // Cleanup temp stores (do not pollute data/).
  fs.rmSync(tmp, { recursive: true, force: true });
  try { fs.unlinkSync(process.env.INVESTIGATIONS_FILE); } catch { /* already gone */ }
  console.log('\nAll provenance route tests passed.');
}

if (require.main === module) {
  runProvenanceRouteTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runProvenanceRouteTests };
