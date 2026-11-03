const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

// SDK provenance end-to-end: REAL policy app (HTTP), REAL signer
// process, REAL Anvil chain, REAL V2 contract, REAL SDK client
// driving manifest → ceremony → publish → verify. The ONLY mock is
// the model transport (canned MATCH verdicts, labeled MOCK): every
// provenance property — digest binding, signature, registry trust,
// bitmap derivation, ownership, operator gating, idempotence — runs
// against genuine components. No Arc Testnet, no production keys.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const STRANGER = '0x000000000000000000000000000000000000dEaD';
const ANVIL_MNEMONIC = 'test test test test test test test test test test test junk';
const T0 = 1793600000000;

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

async function rpc(rpcUrl, method, params) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params || [] })
  });
  if (!res.ok) throw new Error(`rpc http ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(body.error.message || 'rpc error');
  return body.result;
}

async function waitFor(fn, timeoutMs, label) {
  const start = Date.now();
  for (;;) {
    try {
      const out = await fn();
      if (out) return out;
    } catch { /* keep waiting */ }
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

function foundryBin(name) {
  const exe = process.platform === 'win32' ? `${name}.exe` : name;
  const candidates = [
    process.env[name.toUpperCase() + '_BIN'],
    path.join(os.homedir(), '.foundry', 'bin', exe),
    name
  ].filter(Boolean);
  return candidates.find((c) => { try { return fs.existsSync(c); } catch { return false; } }) || name;
}

function provMandate(anvilRpc) {
  return {
    id: 'sdk-prov-e2e-mandate', version: 1, issuer: 'sdk-prov-e2e-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: A0, senders: [A0],
    chains: [{ id: 31337, rpcUrl: anvilRpc, name: 'anvil-sdk-prov-e2e' }],
    recipients: { allow: [A1], deny: [STRANGER] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [{ windowMs: 86400000, maxNativeWei: '1000000000000000000' }],
    reviewRules: []
  };
}

async function runSdkProvenanceTests() {
  console.log('Testing SDK provenance end-to-end (app + signer + Anvil + V2; MOCK model)...\n');
  const realFetch = global.fetch;
  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'sdk-prov-e2e-'));
  const repoRoot = path.join(__dirname, '..', '..');
  let policyServer = null;
  let signerProc = null;
  let anvil = null;
  let failed = false;

  try {
    const { mnemonicToAccount, generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
    const anvilAccount = mnemonicToAccount(ANVIL_MNEMONIC);
    const SIGNER_KEY = `0x${Buffer.from(anvilAccount.getHdKey().privateKey).toString('hex')}`;
    const APPROVAL_SECRET = crypto.randomBytes(32).toString('hex');
    const OPERATOR_SECRET = crypto.randomBytes(32).toString('hex');
    const ALPHA_SECRET = crypto.randomBytes(32).toString('hex');
    const BETA_SECRET = crypto.randomBytes(32).toString('hex');
    const OPERATOR_KEY = generatePrivateKey();
    const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address;

    // Temp attestation trust: day key + root-signed registry.
    const A = require('../../src/services/provenanceAttestation');
    const dayKey = generatePrivateKey();
    const dayAddr = privateKeyToAccount(dayKey).address.toLowerCase();
    const rootKey = generatePrivateKey();
    const rootAddr = privateKeyToAccount(rootKey).address.toLowerCase();
    const pubKey = generatePrivateKey();
    const pubAddr = privateKeyToAccount(pubKey).address.toLowerCase();
    assert.notStrictEqual(pubAddr, dayAddr, 'publisher differs from attester');
    const skeleton = A.buildRegistrySkeleton({ version: 0, publishedAt: T0 });
    skeleton.keys[dayAddr] = { reason: 'sdk prov e2e', status: 'ACTIVE', statusChangedAt: T0, supersededBy: null, validFrom: T0 };
    const registry = await A.signRegistry({ registry: skeleton, rootPrivateKey: rootKey });
    const registryFile = path.join(tmp, 'registry.json');
    fs.writeFileSync(registryFile, JSON.stringify(registry), 'utf8');

    // Forge build + Anvil + V2 deploy + fund publisher.
    const forgeDir = path.join(tmp, 'forge-proj');
    fs.mkdirSync(path.join(forgeDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(forgeDir, 'foundry.toml'), "[profile.default]\nsrc = 'src'\nout = 'out'\nsolc_version = '0.8.20'\n", 'utf8');
    fs.copyFileSync(path.join(repoRoot, 'contracts', 'ProvenanceAttestationV2.sol'), path.join(forgeDir, 'src', 'ProvenanceAttestationV2.sol'));
    try {
      execFileSync(foundryBin('forge'), ['build', '--root', forgeDir], { stdio: 'pipe', timeout: 180000 });
    } catch (err) {
      throw new Error(`forge build failed: ${(err && err.stderr) || err.message}`);
    }
    const artV2 = JSON.parse(fs.readFileSync(path.join(forgeDir, 'out', 'ProvenanceAttestationV2.sol', 'ProvenanceAttestationV2.json'), 'utf8'));
    const anvilPort = await freePort();
    const signerPort = await freePort();
    const anvilRpc = `http://127.0.0.1:${anvilPort}`;
    anvil = spawn(foundryBin('anvil'), ['--port', String(anvilPort)], { stdio: ['ignore', 'ignore', 'pipe'] });
    anvil.on('error', () => {});
    await waitFor(async () => (await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69', 30000, 'anvil boot');
    const { encodeDeployData } = require('viem');
    const deployHash = await rpc(anvilRpc, 'eth_sendTransaction', [{ from: A0, data: encodeDeployData({ abi: artV2.abi, bytecode: artV2.bytecode.object, args: [] }) }]);
    const deployReceipt = await waitFor(async () => rpc(anvilRpc, 'eth_getTransactionReceipt', [deployHash]), 30000, 'V2 deploy receipt');
    assert.strictEqual(deployReceipt.status, '0x1', 'V2 deploy mined');
    const contractV2 = deployReceipt.contractAddress;
    const fundHash = await rpc(anvilRpc, 'eth_sendTransaction', [{ from: A0, to: pubAddr, value: '0xde0b6b3a7640000' }]);
    const fundReceipt = await waitFor(async () => rpc(anvilRpc, 'eth_getTransactionReceipt', [fundHash]), 30000, 'fund receipt');
    assert.strictEqual(fundReceipt.status, '0x1', 'publisher funded');

    // Server env (agent + provenance), then boot app + signer.
    const mandateFile = path.join(tmp, 'mandate.json');
    fs.writeFileSync(mandateFile, JSON.stringify(provMandate(anvilRpc)), 'utf8');
    const { sealMandateFile } = require('../../src/signer/signMandate');
    await sealMandateFile(mandateFile, OPERATOR_KEY);
    process.env.MANDATE_FILE = mandateFile;
    process.env.APPROVAL_SECRET = APPROVAL_SECRET;
    process.env.OPERATOR_SECRET = OPERATOR_SECRET;
    process.env.TRUSTED_MANDATE_AUTHORITIES = OPERATOR_ADDR;
    process.env.AGENT_API_KEYS = `alpha:${ALPHA_SECRET},beta:${BETA_SECRET}`;
    delete process.env.AGENT_AUTH_MODE;
    process.env.AGENT_LEDGER_FILE = path.join(tmp, 'agent-ledger.jsonl');
    process.env.SPENDING_LEDGER_FILE = path.join(tmp, 'agent-spending.jsonl');
    process.env.AGENT_SNAPSHOT_FILE = path.join(tmp, 'agent-requests.json');
    process.env.INVESTIGATIONS_FILE = path.join(tmp, 'investigations.jsonl');
    process.env.MODEL_API_KEY = 'sdk-prov-e2e-key';
    process.env.ATTESTATION_MANIFEST_STORE = path.join(tmp, 'manifests.jsonl');
    process.env.ATTESTATION_STORE_DIR = path.join(tmp, 'ceremony');
    process.env.ATTESTATION_REGISTRY_FILE = registryFile;
    process.env.TRUSTED_REGISTRY_ROOT = rootAddr;
    process.env.TRUSTED_ATTESTATION_AUTHORITIES = dayAddr;
    process.env.ATTESTATION_SERVER_SIGNING = 'enabled';
    process.env.ATTESTATION_SIGNING_KEY = dayKey;
    process.env.ATTESTATION_SERVER_PUBLISH = 'enabled';
    process.env.PUBLISHER_TX_KEY = pubKey;
    process.env.ATTESTATION_RPC_URL = anvilRpc;
    process.env.ATTESTATION_CONTRACT_ADDRESS = contractV2;
    process.env.ATTESTATION_CHAIN_ID = '31337';
    process.env.ATTESTATION_CONTRACT_VERSION = '2';
    const appConfig = require('../../src/config/env');
    global.fetch = async (url, opts) => {
      if (typeof url === 'string' && url.startsWith(appConfig.metaApiBaseUrl)) {
        return {
          ok: true,
          json: async () => ({ choices: [{ message: { content: JSON.stringify({
            verdict: 'MATCH', confidence: 0.95, summary: 'sdk-prov-e2e MOCK MATCH',
            discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
          }) } }] })
        };
      }
      return realFetch(url, opts);
    };
    const app = require('../../src/server.js');
    const policyPort = await new Promise((resolve, reject) => {
      policyServer = app.listen(0, '127.0.0.1', () => resolve(policyServer.address().port));
      policyServer.on('error', reject);
    });
    const policyBase = `http://127.0.0.1:${policyPort}`;
    signerProc = spawn('node', [path.join(repoRoot, 'src', 'signer', 'server.js')], {
      env: {
        ...process.env,
        APPROVAL_SECRET, OPERATOR_SECRET, MANDATE_FILE: mandateFile,
        SIGNER_TRUSTED_MANDATE_AUTHORITIES: OPERATOR_ADDR,
        SIGNER_PRIVATE_KEY: SIGNER_KEY, SIGNER_PORT: String(signerPort),
        SIGNER_CONSUMED_FILE: path.join(tmp, 'signer-consumed.jsonl'),
        POLICY_CALLBACK_URL: `${policyBase}/api/v1/internal/signer-callback`
      },
      stdio: ['ignore', 'ignore', 'pipe']
    });
    signerProc.on('error', () => {});
    const signerBase = `http://127.0.0.1:${signerPort}`;
    await waitFor(async () => {
      const h = await (await realFetch(`${signerBase}/health`)).json();
      return h && h.ok === true ? h : null;
    }, 30000, 'signer boot');

    const { AssertaraClient, isCleanExecution, CODES } = require('../../sdk/index');
    const { deriveModelBitmap, deriveModelMetadata } = require('../../src/services/attestationPublisher');
    const alpha = new AssertaraClient({ policyBase, signerBase, apiKey: `alpha:${ALPHA_SECRET}`, fetchImpl: realFetch });
    const beta = new AssertaraClient({ policyBase, signerBase, apiKey: `beta:${BETA_SECRET}`, fetchImpl: realFetch });
    const raw = async (method, p, { key, body } = {}) => {
      const res = await realFetch(`${policyBase}${p}`, {
        method,
        headers: {
          ...(key ? { Authorization: `Bearer ${key}` } : {}),
          ...(body !== undefined ? { 'content-type': 'application/json' } : {})
        },
        body: body !== undefined ? JSON.stringify(body) : undefined
      });
      return { status: res.status, body: await res.json().catch(() => ({})) };
    };
    const alphaKey = `alpha:${ALPHA_SECRET}`;
    const betaKey = `beta:${BETA_SECRET}`;
    const TX_A = { from: A0, to: A1, value: '0x11c37937e08000', data: '0x', chainId: '0x7a69' }; // 0.005 ETH
    const TX_B = { from: A0, to: STRANGER, value: '0x11c37937e08000', data: '0x', chainId: '0x7a69' };

    // Test 1: ALLOW full lifecycle via SDK — investigate, execute,
    // manifest, ceremony, publish, verify PASS with model metadata.
    let allowDigest;
    {
      const inv = await alpha.submit({ transaction: TX_A, purpose: 'sdk prov e2e contributor payout' });
      const decided = await inv.wait();
      assert.strictEqual(decided.decision, 'ALLOW', 'MOCK MATCH + mandate allow → ALLOW');
      const signed = await inv.execute(TX_A, { status: decided });
      const execution = await inv.waitForExecution();
      assert.strictEqual(isCleanExecution(execution), true, 'clean EXECUTED outcome');
      assert.ok(/^0x[0-9a-f]{64}$/.test(signed.txHash), 'execution hash returned');
      const built = await alpha.buildManifest(inv.requestId);
      allowDigest = built.manifestDigest;
      assert.ok(/^[0-9a-f]{64}$/.test(allowDigest), 'manifest digest issued');
      assert.strictEqual(built.manifest.decision.agent, 'ALLOW', 'manifest carries ALLOW');
      const preview = await alpha.requestAttestation({ digest: allowDigest, expectDigest: allowDigest, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(preview.attested, false, 'preview does not attest');
      assert.ok(preview.preview, 'preview object returned');
      const ceremony = await alpha.requestAttestation({ digest: allowDigest, expectDigest: allowDigest, confirm: true, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(ceremony.attested, true, 'ceremony attests');
      const exported = await alpha.getExportPackage(allowDigest);
      assert.strictEqual(exported.format, 'assertara-attestation-export-1', 'export envelope');
      const pub = await alpha.publishAttestation({ digest: allowDigest, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(pub.ok, true, 'publish ok');
      assert.strictEqual(pub.submitted, true, 'publish submitted');
      assert.ok(/^0x[0-9a-f]{64}$/.test(pub.txHash), 'submission hash returned');
      const verdict = await alpha.verifyAttestation({ digest: allowDigest });
      assert.strictEqual(verdict.verdict, 'PASS', `judge PASS (${JSON.stringify(verdict.checks.filter((x) => !x.ok))})`);
      // Models + bitmap equal the local derivation from the verified
      // manifest: the API displays genuine pipeline output, never
      // invented names.
      assert.deepStrictEqual(verdict.models.map((m) => [m.name, m.status, m.contribution]),
        deriveModelMetadata(exported.package.manifest).map((m) => [m.name, m.status, m.contribution]),
        'served models match manifest derivation');
      assert.strictEqual(pub.modelBitmap, deriveModelBitmap(exported.package.manifest), 'on-chain bitmap matches derivation');
      assert.ok(verdict.models.length >= 1, 'at least one model represented');
      console.log('✔ Test 1 Passed: ALLOW investigate→execute→manifest→attest→publish→verify PASS.');
    }

    // Test 2: BLOCK full lifecycle — no execution, zero-hash
    // publication, judge PASS with the no-payment statement.
    {
      const inv = await alpha.submit({ transaction: TX_B, purpose: 'sdk prov e2e off-books request' });
      const decided = await inv.wait();
      assert.strictEqual(decided.decision, 'BLOCK', 'deny-listed recipient → BLOCK');
      await assert.rejects(inv.execute(TX_B, { status: decided }),
        (e) => e.code === CODES.NOT_EXECUTABLE, 'BLOCK never executes');
      const built = await alpha.buildManifest(inv.requestId);
      assert.strictEqual(built.manifest.decision.agent, 'BLOCK', 'BLOCK manifest');
      assert.strictEqual(built.manifest.transaction.transactionHash, null, 'BLOCK manifest carries no hash');
      const ceremony = await alpha.requestAttestation({ digest: built.manifestDigest, expectDigest: built.manifestDigest, confirm: true, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(ceremony.attested, true, 'BLOCK ceremony attests');
      const pub = await alpha.publishAttestation({ digest: built.manifestDigest, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(pub.ok, true, 'BLOCK publish ok');
      const verdict = await alpha.verifyAttestation({ digest: built.manifestDigest });
      assert.strictEqual(verdict.verdict, 'PASS', `BLOCK judge PASS (${JSON.stringify(verdict.checks.filter((x) => !x.ok))})`);
      const noPay = verdict.checks.find((x) => x.name === 'no-payment');
      assert.ok(noPay && noPay.ok, 'no-payment statement holds');
      // Duplicate publication is idempotent (no resubmission).
      const dup = await alpha.publishAttestation({ digest: built.manifestDigest, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(dup.ok, true, 'duplicate publish ok');
      assert.strictEqual(dup.duplicate, true, 'duplicate flagged');
      assert.strictEqual(dup.submitted, false, 'duplicate not resubmitted');
      console.log('✔ Test 2 Passed: BLOCK manifests + publishes honestly; duplicate idempotent.');
    }

    // Test 3: ownership isolation + operator gates over HTTP.
    {
      await assert.rejects(beta.getManifest(allowDigest),
        (e) => e.code === CODES.NOT_FOUND, 'foreign manifest read 404');
      await assert.rejects(beta.getExportPackage(allowDigest),
        (e) => e.code === CODES.NOT_FOUND, 'foreign export read 404');
      const noOp = await raw('POST', '/api/v1/attestations', { key: alphaKey, body: { digest: allowDigest, expectDigest: allowDigest, confirm: true } });
      assert.strictEqual(noOp.status, 403, 'ceremony without credential 403');
      const badOp = await raw('POST', '/api/v1/attestations/publish', { key: alphaKey, body: { digest: allowDigest, operatorSecret: 'wrong' } });
      assert.strictEqual(badOp.status, 403, 'publish with wrong credential 403');
      const noKey = await raw('GET', `/api/v1/provenance/manifests/${allowDigest}`);
      assert.strictEqual(noKey.status, 401, 'manifest without api key 401');
      console.log('✔ Test 3 Passed: ownership isolation + operator/API gates enforced.');
    }

    // Test 4: tampered export FAILs verification (decision flip).
    {
      const exported = await alpha.getExportPackage(allowDigest);
      exported.package.manifest.decision.agent = 'BLOCK';
      const verdict = await alpha.verifyAttestation({ exported });
      assert.strictEqual(verdict.verdict, 'FAIL', 'tampered export FAILs');
      assert.ok(verdict.checks.some((x) => !x.ok), 'at least one check names the failure');
      console.log('✔ Test 4 Passed: tampered manifest rejected by verification.');
    }

    // Test 5: agent integration captures provenance through the
    // packaged SDK (PROVENANCE_RECORDED + outcome digest).
    {
      const { createAssertaraIntegration } = require('../../agent/integrations/assertara.js');
      const integration = createAssertaraIntegration({ client: alpha, agentId: 'sdk-prov-e2e-agent' });
      const events = [];
      const out = await integration.executeAction(
        { from: A0, to: A1, value: '0x38d7ea4c68000', data: '0x', chainId: '0x7a69' },
        { purpose: 'sdk prov e2e agent capture', onEvent: (event, detail, extra) => events.push({ event, detail, extra }) }
      );
      assert.strictEqual(out.decision, 'ALLOW', 'agent flow ALLOWs');
      assert.ok(out.provenance && /^[0-9a-f]{64}$/.test(out.provenance.manifestDigest), 'outcome carries manifest digest');
      assert.ok(events.some((e) => e.event === 'PROVENANCE_RECORDED'), 'PROVENANCE_RECORDED emitted');
      const again = await alpha.getManifest(out.provenance.manifestDigest);
      assert.strictEqual(again.manifestDigest, out.provenance.manifestDigest, 'agent digest resolves server-side');
      console.log('✔ Test 5 Passed: agent captures provenance via the packaged SDK.');
    }
  } catch (err) {
    failed = true;
    throw err;
  } finally {
    global.fetch = realFetch;
    try { if (policyServer) await new Promise((r) => policyServer.close(r)); } catch { /* closing */ }
    try { if (signerProc) signerProc.kill('SIGKILL'); } catch { /* closing */ }
    try { if (anvil) anvil.kill('SIGKILL'); } catch { /* closing */ }
    if (!failed) console.log('\nAll SDK provenance e2e tests passed.');
  }
}

if (require.main === module) {
  runSdkProvenanceTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSdkProvenanceTests };
