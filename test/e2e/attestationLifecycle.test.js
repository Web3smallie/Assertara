const assert = require('assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

// Step 6 attestation-lifecycle e2e: REAL forge build, REAL Anvil chain,
// REAL deployment, REAL publisher submission over RPC, REAL export files,
// REAL judge CLI runs. Fixtures are synthetic (temp keys, local Anvil);
// they prove lifecycle mechanics, never genuine model provenance.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const T0 = Date.UTC(2026, 0, 15, 12, 0, 0);
const NOW = T0 + 60000;
const ZERO_HASH = `0x${'00'.repeat(32)}`;

const { buildManifest, buildVerificationPackage, verifyPackage } = require('../../src/services/provenanceManifest');
const A = require('../../src/services/provenanceAttestation');
const { publishAttestation, PublisherError } = require('../../src/services/attestationPublisher');
const { canonicalStringify, sha256Hex } = require('../../src/utils/canonicalJson');

function hex(ch) { return ch.repeat(64); }
const TXHASH = `0x${'ab'.repeat(32)}`;

function baseRecord() {
  return {
    recordId: 'inv_life_allow', id: 'eval_life_allow', traceId: 'tr_life_allow',
    requestId: 'agent_life_allow', recordedAt: T0, receivedAt: T0 - 1000,
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
    reasoningOrigin: 'model'
  };
}

function baseRequest() {
  return {
    id: 'agent_life_allow', traceId: 'tr_life_allow', evalId: 'eval_life_allow',
    status: 'EXECUTED', decision: 'ALLOW', reasons: ['within mandate'],
    txDigest: hex('b'), evalVerdict: 'MATCH',
    normalizedTx: { chainId: 31337 },
    execution: { outcome: 'EXECUTED', txHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x10' }
  };
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
    } catch {
      /* keep waiting */
    }
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

function runCli(script, args) {
  try {
    const out = execFileSync(process.execPath, [script, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, stdout: out, stderr: '' };
  } catch (err) {
    return { code: typeof err.status === 'number' ? err.status : 1, stdout: String((err && err.stdout) || ''), stderr: String((err && err.stderr) || '') };
  }
}

async function runLifecycleTests() {
  console.log('Testing Step 6 attestation lifecycle e2e (real Anvil + real judge CLI)...\n');
  const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
  const dayKey = generatePrivateKey();
  const dayAddr = privateKeyToAccount(dayKey).address.toLowerCase();
  const rootKey = generatePrivateKey();
  const rootAddr = privateKeyToAccount(rootKey).address.toLowerCase();
  const otherKey = generatePrivateKey();
  const pubKey = generatePrivateKey();
  const pubAddr = privateKeyToAccount(pubKey).address.toLowerCase();
  assert.notStrictEqual(pubAddr, dayAddr, 'temp publisher differs from attester');

  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'e2e-lifecycle-'));
  let failed = false;
  const killAll = [];
  const repoRoot = path.join(__dirname, '..', '..');

  async function signedFixture(record, request) {
    const built = buildManifest({ record, request });
    const v1 = buildVerificationPackage(built);
    assert.strictEqual(verifyPackage(v1).ok, true, 'v1 package verifies');
    const digest = sha256Hex(canonicalStringify(built.manifest));
    const body = A.buildAttestationBody({
      manifestDigest: digest,
      investigationId: built.manifest.investigationId,
      traceId: built.manifest.traceId,
      requestId: built.manifest.requestId,
      keyId: dayAddr,
      issuedAt: NOW
    });
    const attestation = await A.signAttestation({ body, privateKey: dayKey });
    return { built, v1, attestation, digest, v2: A.attachAttestation(v1, attestation) };
  }

  try {
    // -- 1. Signed fixtures: ALLOW (executed) + BLOCK (no execution). --
    const allow = await signedFixture(baseRecord(), baseRequest());
    const recB = baseRecord();
    recB.recordId = 'inv_life_block'; recB.id = 'eval_life_block'; recB.traceId = 'tr_life_block';
    recB.requestId = 'agent_life_block';
    recB.policyDecision = { decision: 'BLOCK', reasons: ['outside mandate'] };
    const reqB = baseRequest();
    reqB.id = 'agent_life_block'; reqB.traceId = 'tr_life_block'; reqB.evalId = 'eval_life_block';
    reqB.decision = 'BLOCK'; reqB.status = 'BLOCKED'; reqB.execution = null;
    const block = await signedFixture(recB, reqB);
    assert.strictEqual(allow.v2.manifest.transaction.transactionHash, TXHASH, 'ALLOW binds receipt hash');
    assert.strictEqual(block.v2.manifest.transaction.transactionHash, null, 'BLOCK carries no hash');
    assert.strictEqual(block.v2.manifest.modelCalls.sam.contribution, 'NOT_INVOKED', 'Step 5 posture: SAM NOT_INVOKED');
    const allowInv = allow.built.manifest.investigationId;
    const blockInv = block.built.manifest.investigationId;
    assert.notStrictEqual(allowInv, blockInv, 'distinct investigation ids');
    console.log('✔ ALLOW + BLOCK fixtures built, signed with temp attestation key.');

    // -- 2. Registry + export files (content-addressed, no overwrite). --
    const skeleton = A.buildRegistrySkeleton({ version: 0, publishedAt: NOW });
    skeleton.keys[dayAddr] = { reason: 'e2e day key', status: 'ACTIVE', statusChangedAt: NOW, supersededBy: null, validFrom: NOW };
    const registry = await A.signRegistry({ registry: skeleton, rootPrivateKey: rootKey });
    const registryFile = path.join(tmp, 'registry.json');
    fs.writeFileSync(registryFile, JSON.stringify(registry), 'utf8');
    const exportScript = path.join(repoRoot, 'src', 'attestation', 'exportPackage.js');
    const exportOne = (fix, name) => {
      const v1File = path.join(tmp, `${name}.v1.json`);
      const attFile = path.join(tmp, `${name}.att.json`);
      const outFile = path.join(tmp, `${name}.export.json`);
      fs.writeFileSync(v1File, JSON.stringify(fix.v1), 'utf8');
      fs.writeFileSync(attFile, JSON.stringify(fix.attestation), 'utf8');
      const r = runCli(exportScript, ['--package', v1File, '--attestation', attFile, '--expect-digest', fix.digest, '--out', outFile]);
      assert.strictEqual(r.code, 0, `export ${name} exits 0 (stderr: ${r.stderr})`);
      return outFile;
    };
    const allowExport = exportOne(allow, 'allow');
    const blockExport = exportOne(block, 'block');
    const reExport = runCli(exportScript, ['--package', path.join(tmp, 'allow.v1.json'), '--attestation', path.join(tmp, 'allow.att.json'), '--expect-digest', allow.digest, '--out', allowExport]);
    assert.notStrictEqual(reExport.code, 0, 'export refuses to overwrite');
    const wrongDigest = runCli(exportScript, ['--package', path.join(tmp, 'allow.v1.json'), '--attestation', path.join(tmp, 'allow.att.json'), '--expect-digest', block.digest, '--out', path.join(tmp, 'wrong.export.json')]);
    assert.notStrictEqual(wrongDigest.code, 0, 'export refuses digest mismatch');
    console.log('✔ Exports written; overwrite + digest-mismatch refusals verified.');

    // -- 3. Forge build + Anvil + deploy + fund publisher. --
    const forgeDir = path.join(tmp, 'forge-proj');
    fs.mkdirSync(path.join(forgeDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(forgeDir, 'foundry.toml'), "[profile.default]\nsrc = 'src'\nout = 'out'\nsolc_version = '0.8.20'\n", 'utf8');
    fs.copyFileSync(path.join(repoRoot, 'contracts', 'ProvenanceAttestation.sol'), path.join(forgeDir, 'src', 'ProvenanceAttestation.sol'));
    try {
      execFileSync(foundryBin('forge'), ['build', '--root', forgeDir], { stdio: 'pipe', timeout: 180000 });
    } catch (err) {
      throw new Error(`forge build failed: ${(err && err.stderr) || err.message}`);
    }
    const art = JSON.parse(fs.readFileSync(path.join(forgeDir, 'out', 'ProvenanceAttestation.sol', 'ProvenanceAttestation.json'), 'utf8'));
    const anvilPort = await freePort();
    const anvilRpc = `http://127.0.0.1:${anvilPort}`;
    const anvil = spawn(foundryBin('anvil'), ['--port', String(anvilPort)], { stdio: ['ignore', 'ignore', 'pipe'] });
    let anvilStderr = '';
    if (anvil.stderr) anvil.stderr.on('data', (d) => { anvilStderr += String(d).slice(-2000); });
    killAll.push(() => { try { anvil.kill('SIGKILL'); } catch {} });
    await waitFor(async () => (await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69', 30000, 'anvil boot')
      .catch((err) => { throw new Error(`${err.message}. anvil stderr: ${anvilStderr}`); });
    const { encodeDeployData } = require('viem');
    const deployHash = await rpc(anvilRpc, 'eth_sendTransaction', [{ from: A0, data: encodeDeployData({ abi: art.abi, bytecode: art.bytecode.object, args: [] }) }]);
    const deployReceipt = await waitFor(async () => rpc(anvilRpc, 'eth_getTransactionReceipt', [deployHash]), 30000, 'deploy receipt');
    assert.strictEqual(deployReceipt.status, '0x1', 'deploy mined');
    const contract = deployReceipt.contractAddress;
    const fundHash = await rpc(anvilRpc, 'eth_sendTransaction', [{ from: A0, to: pubAddr, value: '0xde0b6b3a7640000' }]);
    const fundReceipt = await waitFor(async () => rpc(anvilRpc, 'eth_getTransactionReceipt', [fundHash]), 30000, 'fund receipt');
    assert.strictEqual(fundReceipt.status, '0x1', 'publisher funded');
    console.log(`✔ Anvil up; contract at ${contract}; temp publisher funded.`);

    const pubOpts = (pkg) => ({
      signedPackage: pkg, registry, trustedRoot: rootAddr, trustedAuthorities: [dayAddr],
      denyList: [], rpcUrl: anvilRpc, chainId: 31337, contractAddress: contract,
      publisherKey: pubKey, now: NOW + 1000
    });

    // -- 4. Key separation holds on the real path (pre-submission). --
    try {
      await publishAttestation({ ...pubOpts(allow.v2), publisherKey: dayKey });
      assert.fail('publisher==attester must refuse');
    } catch (err) {
      assert.ok(err instanceof PublisherError && err.code === 'PUBLISH_KEY_CONFLICT', `key-conflict refusal (${err.code})`);
    }
    console.log('✔ Publisher==attester refused before any submission.');

    // -- 5. ALLOW lifecycle: publish over RPC, judge PASS. --
    const rA = await publishAttestation(pubOpts(allow.v2));
    assert.strictEqual(rA.ok, true, 'ALLOW publish ok');
    assert.strictEqual(rA.submitted, true, 'ALLOW submitted');
    assert.strictEqual(rA.modelBitmap, 1, 'ALLOW bitmap: muse only');
    assert.ok(/^0x[0-9a-f]{64}$/.test(rA.txHash), 'submit hash returned');
    const judgeScript = path.join(repoRoot, 'src', 'attestation', 'judge.js');
    const judgeArgs = (investigation, attester, manifestFile, extra) => [
      '--rpc', anvilRpc, '--contract', contract,
      '--investigation', investigation, '--attester', attester,
      '--manifest-file', manifestFile,
      '--registry', registryFile, '--trusted-root', rootAddr,
      '--min-version', '0', '--max-age-days', '30', '--now', String(NOW + 1000),
      ...(extra || [])
    ];
    const jA = runCli(judgeScript, judgeArgs(allowInv, dayAddr, allowExport, ['--submit-tx', rA.txHash]));
    assert.strictEqual(jA.code, 0, `judge ALLOW exits 0:\n${jA.stdout}\n${jA.stderr}`);
    assert.ok(jA.stdout.includes('VERDICT PASS'), 'judge ALLOW verdict PASS');
    console.log('✔ ALLOW published on-chain; judge VERDICT PASS.');

    // -- 6. Duplicate publish skips resubmission; judge still passes. --
    const rA2 = await publishAttestation(pubOpts(allow.v2));
    assert.strictEqual(rA2.duplicate, true, 'identical flagged duplicate');
    assert.strictEqual(rA2.submitted, false, 'identical skips submission');
    console.log('✔ Identical republication skips submission (read-back match).');

    // -- 7. BLOCK lifecycle: zero hash on-chain, judge PASS + no-payment. --
    const rB = await publishAttestation(pubOpts(block.v2));
    assert.strictEqual(rB.ok && rB.submitted, true, 'BLOCK publish ok');
    const jB = runCli(judgeScript, judgeArgs(blockInv, dayAddr, blockExport));
    assert.strictEqual(jB.code, 0, `judge BLOCK exits 0:\n${jB.stdout}\n${jB.stderr}`);
    assert.ok(jB.stdout.includes('VERDICT PASS'), 'judge BLOCK verdict PASS');
    assert.ok(jB.stdout.includes('no-payment'), 'judge BLOCK states no-payment');
    console.log('✔ BLOCK published with zero hash; judge VERDICT PASS + no-payment.');

    // -- 8. Judge refusals: tampered, wrong-key, stale-registry,
    // swapped-attester, cross-record, and missing-receipt cases. --
    const expectJudgeFail = (args, needle, label) => {
      const r = runCli(judgeScript, args);
      assert.notStrictEqual(r.code, 0, `${label}: judge exits non-zero`);
      assert.ok(r.stdout.includes('VERDICT FAIL'), `${label}: verdict FAIL`);
      assert.ok(r.stdout.includes(needle), `${label}: names ${needle}`);
    };
    const tamperedExport = JSON.parse(fs.readFileSync(allowExport, 'utf8'));
    tamperedExport.package.manifest.transaction.blockNumber = '0x9999';
    const tamperedFile = path.join(tmp, 'tampered.export.json');
    fs.writeFileSync(tamperedFile, JSON.stringify(tamperedExport), 'utf8');
    expectJudgeFail(judgeArgs(allowInv, dayAddr, tamperedFile), 'digest-recompute', 'tampered manifest');

    const otherAddrForKey = privateKeyToAccount(otherKey).address.toLowerCase();
    const wrongKeyBody = A.buildAttestationBody({
      manifestDigest: allow.digest,
      investigationId: allow.built.manifest.investigationId,
      traceId: allow.built.manifest.traceId,
      requestId: allow.built.manifest.requestId,
      keyId: otherAddrForKey,
      issuedAt: NOW
    });
    const wrongKeyAtt = await A.signAttestation({ body: wrongKeyBody, privateKey: otherKey });
    const wrongKeyExport = { format: 'assertara-attestation-export-1', exportedAt: NOW, manifestDigest: allow.digest, package: A.attachAttestation(JSON.parse(JSON.stringify(allow.v1)), wrongKeyAtt) };
    const wrongKeyFile = path.join(tmp, 'wrongkey.export.json');
    fs.writeFileSync(wrongKeyFile, JSON.stringify(wrongKeyExport), 'utf8');
    expectJudgeFail(judgeArgs(allowInv, dayAddr, wrongKeyFile), 'signature', 'wrong-key signature');

    const staleSkeleton = A.buildRegistrySkeleton({ version: 0, publishedAt: NOW - 90 * 86400000 });
    staleSkeleton.keys[dayAddr] = { reason: 'e2e day key', status: 'ACTIVE', statusChangedAt: NOW - 90 * 86400000, supersededBy: null, validFrom: NOW - 90 * 86400000 };
    const staleRegistry = await A.signRegistry({ registry: staleSkeleton, rootPrivateKey: rootKey });
    const staleFile = path.join(tmp, 'stale-registry.json');
    fs.writeFileSync(staleFile, JSON.stringify(staleRegistry), 'utf8');
    const staleArgs = judgeArgs(allowInv, dayAddr, allowExport);
    staleArgs.splice(staleArgs.indexOf('--registry') + 1, 1, staleFile);
    expectJudgeFail(staleArgs, 'stale-registry', 'stale registry');

    const otherAddr = '0x1111111111111111111111111111111111111111';
    expectJudgeFail(judgeArgs(allowInv, otherAddr, allowExport), 'chain-record', 'swapped attester');
    expectJudgeFail(judgeArgs(allowInv, dayAddr, blockExport), 'digest-onchain', 'cross-record export');
    expectJudgeFail(
      judgeArgs(allowInv, dayAddr, allowExport, ['--submit-tx', `0x${'de'.repeat(32)}`]),
      'receipt', 'missing receipt'
    );
    console.log('✔ Judge rejects tampered/wrong-key/stale/swapped/cross-record/missing-receipt cases.');

    console.log('\nAll Step 6 attestation-lifecycle e2e scenarios passed.');
  } catch (err) {
    failed = true;
    throw err;
  } finally {
    for (const kill of killAll) kill();
    await new Promise((r) => setTimeout(r, 500));
    if (!failed) {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    } else {
      console.log(`e2e artifacts preserved at: ${tmp}`);
    }
  }
}

if (require.main === module) {
  runLifecycleTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runLifecycleTests };
