const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

// Published-SDK end-to-end: the SAME full lifecycle as
// sdkProvenance.test.js, but driven exclusively through the
// assertara@0.1.1 package installed FROM THE NPM REGISTRY (never the
// local sdk/ source). The agent integration is also exercised with a
// client constructed from the published package. The ONLY mock is the
// model transport (canned MATCH verdicts, labeled MOCK).
//
// This suite needs registry access (one install, cached under
// test/tmp) plus the usual Anvil/forge/loopback requirements, so it
// runs under `npm run test:e2e:published`, not the default e2e chain.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const STRANGER = '0x000000000000000000000000000000000000dEaD';
const ANVIL_MNEMONIC = 'test test test test test test test test test test test junk';
const T0 = 1793600000000;
const PUBLISHED_VERSION = '0.1.1';

const FIXTURE_DIR = path.join(__dirname, '..', 'tmp', 'published-sdk');
const PUB_ROOT = path.join(FIXTURE_DIR, 'node_modules', 'assertara');

function ensurePublishedInstall() {
  try {
    const pkg = require(path.join(PUB_ROOT, 'package.json'));
    if (pkg && pkg.name === 'assertara' && pkg.version === PUBLISHED_VERSION) return;
  } catch { /* fall through to install */ }
  fs.mkdirSync(FIXTURE_DIR, { recursive: true });
  if (!fs.existsSync(path.join(FIXTURE_DIR, 'package.json'))) {
    fs.writeFileSync(path.join(FIXTURE_DIR, 'package.json'), JSON.stringify({ name: 'sdk-published-fixture', private: true }));
  }
  const cacheDir = path.join(__dirname, '..', 'tmp', 'published-sdk-cache');
  fs.mkdirSync(cacheDir, { recursive: true });
  const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  execFileSync(npmBin, ['install', `assertara@${PUBLISHED_VERSION}`, '--cache', cacheDir, '--no-audit', '--no-fund'],
    { cwd: FIXTURE_DIR, stdio: 'pipe', timeout: 180000 });
  const pkg = require(path.join(PUB_ROOT, 'package.json'));
  assert.strictEqual(pkg.name, 'assertara', 'installed package name');
  assert.strictEqual(pkg.version, PUBLISHED_VERSION, 'installed package version');
}

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
    id: 'sdk-pub-e2e-mandate', version: 1, issuer: 'sdk-pub-e2e-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: A0, senders: [A0],
    chains: [{ id: 31337, rpcUrl: anvilRpc, name: 'anvil-sdk-pub-e2e' }],
    recipients: { allow: [A1], deny: [STRANGER] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [{ windowMs: 86400000, maxNativeWei: '1000000000000000000' }],
    reviewRules: []
  };
}

async function runSdkPublishedTests() {
  console.log('Testing published SDK end-to-end (registry install + app + signer + Anvil + V2; MOCK model)...\n');

  // Test 0: prove the published bytes (before touching any stack).
  ensurePublishedInstall();
  const repoRoot = path.join(__dirname, '..', '..');
  {
    const files = ['index.js', 'client.js', 'investigation.js', 'guardedWallet.js', 'errors.js',
      'digest.js', 'sse.js', 'internal/txDigest.js', 'internal/canonicalJson.js', 'README.md', 'package.json'];
    for (const f of files) {
      const a = fs.readFileSync(path.join(PUB_ROOT, f));
      const b = fs.readFileSync(path.join(repoRoot, 'sdk', f));
      assert.ok(a.equals(b), `published ${f} byte-identical to reviewed sdk/ source`);
    }
    const pub = require(PUB_ROOT);
    assert.ok(pub.AssertaraClient && pub.Investigation && pub.createGuardedWallet, 'published surface exports');
    const resolved = require.resolve(PUB_ROOT);
    assert.ok(resolved.startsWith(FIXTURE_DIR), `suite drives the registry copy (${resolved})`);
    assert.ok(!resolved.startsWith(path.join(repoRoot, 'sdk')), 'suite never loads local sdk/ source');
    console.log('✔ Test 0 Passed: published 0.1.1 installed from registry; 11/11 files byte-identical.');
  }
  const { AssertaraClient, isCleanExecution, CODES } = require(PUB_ROOT);

  const realFetch = global.fetch;
  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'sdk-pub-e2e-'));
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
    const OPERATOR_KEY = generatePrivateKey();
    const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address;

    const A = require('../../src/services/provenanceAttestation');
    const dayKey = generatePrivateKey();
    const dayAddr = privateKeyToAccount(dayKey).address.toLowerCase();
    const rootKey = generatePrivateKey();
    const rootAddr = privateKeyToAccount(rootKey).address.toLowerCase();
    const pubKey = generatePrivateKey();
    const pubAddr = privateKeyToAccount(pubKey).address.toLowerCase();
    const skeleton = A.buildRegistrySkeleton({ version: 0, publishedAt: T0 });
    skeleton.keys[dayAddr] = { reason: 'sdk pub e2e', status: 'ACTIVE', statusChangedAt: T0, supersededBy: null, validFrom: T0 };
    const registry = await A.signRegistry({ registry: skeleton, rootPrivateKey: rootKey });
    const registryFile = path.join(tmp, 'registry.json');
    fs.writeFileSync(registryFile, JSON.stringify(registry), 'utf8');

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

    const mandateFile = path.join(tmp, 'mandate.json');
    fs.writeFileSync(mandateFile, JSON.stringify(provMandate(anvilRpc)), 'utf8');
    const { sealMandateFile } = require('../../src/signer/signMandate');
    await sealMandateFile(mandateFile, OPERATOR_KEY);
    process.env.MANDATE_FILE = mandateFile;
    process.env.APPROVAL_SECRET = APPROVAL_SECRET;
    process.env.OPERATOR_SECRET = OPERATOR_SECRET;
    process.env.TRUSTED_MANDATE_AUTHORITIES = OPERATOR_ADDR;
    process.env.AGENT_API_KEYS = `alpha:${ALPHA_SECRET}`;
    delete process.env.AGENT_AUTH_MODE;
    process.env.AGENT_LEDGER_FILE = path.join(tmp, 'agent-ledger.jsonl');
    process.env.SPENDING_LEDGER_FILE = path.join(tmp, 'agent-spending.jsonl');
    process.env.AGENT_SNAPSHOT_FILE = path.join(tmp, 'agent-requests.json');
    process.env.INVESTIGATIONS_FILE = path.join(tmp, 'investigations.jsonl');
    process.env.MODEL_API_KEY = 'sdk-pub-e2e-key';
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
            verdict: 'MATCH', confidence: 0.95, summary: 'sdk-pub-e2e MOCK MATCH',
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

    // Every client below is constructed from the PUBLISHED package.
    const alpha = new AssertaraClient({ policyBase, signerBase, apiKey: `alpha:${ALPHA_SECRET}`, fetchImpl: realFetch });
    const TX_A = { from: A0, to: A1, value: '0x11c37937e08000', data: '0x', chainId: '0x7a69' };
    const TX_B = { from: A0, to: STRANGER, value: '0x11c37937e08000', data: '0x', chainId: '0x7a69' };

    // Test 1: ALLOW full lifecycle through the published SDK.
    {
      const inv = await alpha.submit({ transaction: TX_A, purpose: 'sdk pub e2e payout' });
      const decided = await inv.wait();
      assert.strictEqual(decided.decision, 'ALLOW', 'published client reaches ALLOW');
      const signed = await inv.execute(TX_A, { status: decided });
      const execution = await inv.waitForExecution();
      assert.strictEqual(isCleanExecution(execution), true, 'clean EXECUTED outcome');
      const built = await alpha.buildManifest(inv.requestId);
      assert.ok(/^[0-9a-f]{64}$/.test(built.manifestDigest), 'manifest digest issued');
      const preview = await alpha.requestAttestation({ digest: built.manifestDigest, expectDigest: built.manifestDigest, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(preview.attested, false, 'preview does not attest');
      const ceremony = await alpha.requestAttestation({ digest: built.manifestDigest, expectDigest: built.manifestDigest, confirm: true, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(ceremony.attested, true, 'ceremony attests');
      const exported = await alpha.getExportPackage(built.manifestDigest);
      assert.strictEqual(exported.format, 'assertara-attestation-export-1', 'export envelope');
      const pub = await alpha.publishAttestation({ digest: built.manifestDigest, operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(pub.ok, true, 'publish ok');
      assert.strictEqual(pub.submitted, true, 'publish submitted');
      const verdict = await alpha.verifyAttestation({ digest: built.manifestDigest });
      assert.strictEqual(verdict.verdict, 'PASS', `judge PASS (${JSON.stringify(verdict.checks.filter((x) => !x.ok))})`);
      assert.ok(verdict.models.length >= 1, 'model metadata served');
      console.log('✔ Test 1 Passed: published SDK drives ALLOW investigate→execute→attest→publish→verify.');
    }

    // Test 2: BLOCK guard + manifest through the published SDK.
    {
      const inv = await alpha.submit({ transaction: TX_B, purpose: 'sdk pub e2e off-books' });
      const decided = await inv.wait();
      assert.strictEqual(decided.decision, 'BLOCK', 'deny-listed recipient → BLOCK');
      await assert.rejects(inv.execute(TX_B, { status: decided }),
        (e) => e.code === CODES.NOT_EXECUTABLE, 'BLOCK never executes');
      const built = await alpha.buildManifest(inv.requestId);
      assert.strictEqual(built.manifest.decision.agent, 'BLOCK', 'BLOCK manifest honest');
      console.log('✔ Test 2 Passed: published SDK enforces BLOCK + records honest provenance.');
    }

    // Test 3: agent integration driven by a published-package client.
    {
      const { createAssertaraIntegration } = require('../../agent/integrations/assertara.js');
      const integration = createAssertaraIntegration({ client: alpha, agentId: 'sdk-pub-e2e-agent' });
      const events = [];
      const out = await integration.executeAction(
        { from: A0, to: A1, value: '0x38d7ea4c68000', data: '0x', chainId: '0x7a69' },
        { purpose: 'sdk pub e2e agent run', onEvent: (event, detail, extra) => events.push({ event, extra }) }
      );
      assert.strictEqual(out.decision, 'ALLOW', 'agent flow ALLOWs via published client');
      assert.ok(out.provenance && /^[0-9a-f]{64}$/.test(out.provenance.manifestDigest), 'agent captures provenance digest');
      assert.ok(events.some((e) => e.event === 'PROVENANCE_RECORDED'), 'PROVENANCE_RECORDED emitted');
      console.log('✔ Test 3 Passed: agent + published SDK interoperate end to end.');
    }
  } catch (err) {
    failed = true;
    throw err;
  } finally {
    global.fetch = realFetch;
    try { if (policyServer) await new Promise((r) => policyServer.close(r)); } catch { /* closing */ }
    try { if (signerProc) signerProc.kill('SIGKILL'); } catch { /* closing */ }
    try { if (anvil) anvil.kill('SIGKILL'); } catch { /* closing */ }
    if (!failed) console.log('\nAll published-SDK e2e tests passed.');
  }
}

if (require.main === module) {
  runSdkPublishedTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSdkPublishedTests };
