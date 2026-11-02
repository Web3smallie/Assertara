const assert = require('assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

// Step 4 attestation-contract e2e: REAL forge compilation, REAL forge
// unit tests (test/forge/ProvenanceAttestation.t.sol), REAL Anvil chain,
// REAL deployment and submission. All attestation contents are SYNTHETIC
// fixtures ( digests of test strings, local Anvil addresses): they prove
// contract mechanics, never genuine model provenance.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

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

async function runAttestationContractTests() {
  console.log('Testing Step 4 attestation contract e2e (real forge + real Anvil; SYNTHETIC fixtures)...\n');

  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'e2e-attcontract-'));
  let failed = false;
  const killAll = [];

  const {
    encodeDeployData, encodeFunctionData, decodeFunctionResult, decodeEventLog,
    keccak256, toHex, parseAbi
  } = require('viem');

  try {
    // -- 1. Forge build + unit tests in a temp project. --
    const forgeDir = path.join(tmp, 'forge-proj');
    fs.mkdirSync(path.join(forgeDir, 'src'), { recursive: true });
    fs.mkdirSync(path.join(forgeDir, 'test'), { recursive: true });
    fs.writeFileSync(
      path.join(forgeDir, 'foundry.toml'),
      "[profile.default]\nsrc = 'src'\nout = 'out'\ntest = 'test'\nsolc_version = '0.8.20'\n",
      'utf8'
    );
    fs.copyFileSync(
      path.join(__dirname, '..', '..', 'contracts', 'ProvenanceAttestation.sol'),
      path.join(forgeDir, 'src', 'ProvenanceAttestation.sol')
    );
    fs.copyFileSync(
      path.join(__dirname, '..', 'forge', 'ProvenanceAttestation.t.sol'),
      path.join(forgeDir, 'test', 'ProvenanceAttestation.t.sol')
    );
    let forgeTestOut;
    try {
      forgeTestOut = execFileSync(foundryBin('forge'), ['test', '--root', forgeDir], {
        encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 180000
      });
    } catch (err) {
      throw new Error(`forge test failed:\n${(err && err.stdout) || ''}\n${(err && err.stderr) || err.message}`);
    }
    const suiteLine = (forgeTestOut.match(/(\d+) passed; (\d+) failed; (\d+) skipped/) || []).slice(1).map(Number);
    assert.strictEqual(suiteLine.length, 3, `forge test summary parseable:\n${forgeTestOut}`);
    assert.strictEqual(suiteLine[1], 0, 'zero forge failures');
    assert.ok(suiteLine[0] >= 19, `forge unit tests ran (${suiteLine[0]} passed)`);
    console.log(`✔ Forge unit tests passed (${suiteLine[0]} passed, 0 failed).`);

    // -- 2. Build artifact + deploy to spawned Anvil. --
    try {
      execFileSync(foundryBin('forge'), ['build', '--root', forgeDir], { stdio: 'pipe', timeout: 180000 });
    } catch (err) {
      throw new Error(`forge build failed: ${(err && err.stderr) || err.message}`);
    }
    const art = JSON.parse(fs.readFileSync(
      path.join(forgeDir, 'out', 'ProvenanceAttestation.sol', 'ProvenanceAttestation.json'), 'utf8'
    ));
    assert.ok(art.bytecode && art.bytecode.object && art.bytecode.object.length > 100, 'bytecode present');
    assert.ok(Array.isArray(art.abi) && art.abi.length > 0, 'abi present');

    const anvilPort = await freePort();
    const anvilRpc = `http://127.0.0.1:${anvilPort}`;
    const anvil = spawn(foundryBin('anvil'), ['--port', String(anvilPort)], { stdio: ['ignore', 'ignore', 'pipe'] });
    let anvilStderr = '';
    if (anvil.stderr) anvil.stderr.on('data', (d) => { anvilStderr += String(d).slice(-2000); });
    killAll.push(() => { try { anvil.kill('SIGKILL'); } catch {} });
    await waitFor(async () => (await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69', 30000, 'anvil boot')
      .catch((err) => { throw new Error(`${err.message}. anvil stderr: ${anvilStderr}`); });
    console.log(`  anvil up on ${anvilPort} (chain 31337)`);

    const waitReceipt = (hash) => waitFor(async () => rpc(anvilRpc, 'eth_getTransactionReceipt', [hash]), 30000, 'receipt');
    const deployData = encodeDeployData({ abi: art.abi, bytecode: art.bytecode.object, args: [] });
    const deployHash = await rpc(anvilRpc, 'eth_sendTransaction', [{ from: A0, data: deployData }]);
    const deployReceipt = await waitReceipt(deployHash);
    assert.strictEqual(deployReceipt.status, '0x1', 'deploy mined');
    const contract = deployReceipt.contractAddress;
    assert.ok(/^0x[0-9a-fA-F]{40}$/.test(contract), 'contract address returned');
    console.log(`✔ Contract deployed to Anvil at ${contract}.`);

    const abi = parseAbi([
      'function attest(string investigationId, bytes32 manifestDigest, uint8 modelBitmap, uint8 decision, bytes32 txHash, address attester)',
      'function getAttestation(string investigationId, address attester) view returns (string, bytes32, uint8, uint8, bytes32, address)',
      'event Attested(string indexed investigationId, bytes32 indexed manifestDigest, address indexed attester, uint8 modelBitmap, uint8 decision, bytes32 txHash)'
    ]);
    const call = (functionName, args) => rpc(anvilRpc, 'eth_call', [{
      to: contract,
      data: encodeFunctionData({ abi, functionName, args })
    }, 'latest']);
    const send = async (functionName, args) => {
      const hash = await rpc(anvilRpc, 'eth_sendTransaction', [{
        from: A0, to: contract, data: encodeFunctionData({ abi, functionName, args })
      }]);
      return waitReceipt(hash);
    };
    const expectRevert = async (functionName, args, label) => {
      let threw = null;
      try {
        await call(functionName, args);
      } catch (err) {
        threw = err;
      }
      assert.ok(threw, `${label} reverts`);
      assert.ok(/revert/i.test(threw.message), `${label} revert reason (${threw.message})`);
    };

    // Synthetic fixtures: digests of test strings, local addresses.
    // Attester A1 differs from sender A0: the publisher/signer split.
    const invId = 'e2e-inv-1';
    const digest = keccak256(toHex('synthetic-manifest'));
    const txHash = keccak256(toHex('synthetic-tx'));
    const attester = A1;

    // -- 3. Successful ALLOW attestation + getter + event. --
    const r1 = await send('attest', [invId, digest, 3, 0, txHash, attester]);
    assert.strictEqual(r1.status, '0x1', 'attest mined');
    assert.strictEqual(r1.logs.length, 1, 'exactly one event log');
    const evt = decodeEventLog({ abi, data: r1.logs[0].data, topics: r1.logs[0].topics });
    assert.strictEqual(evt.eventName, 'Attested', 'event name');
    assert.strictEqual(evt.args.manifestDigest.toLowerCase(), digest.toLowerCase(), 'event digest');
    assert.strictEqual(evt.args.attester.toLowerCase(), attester.toLowerCase(), 'event attester');
    assert.strictEqual(Number(evt.args.modelBitmap), 3, 'event bitmap');
    assert.strictEqual(Number(evt.args.decision), 0, 'event decision');
    assert.strictEqual(evt.args.txHash.toLowerCase(), txHash.toLowerCase(), 'event txhash');
    assert.strictEqual(
      r1.logs[0].topics[1].toLowerCase(), keccak256(toHex(invId)).toLowerCase(), 'indexed id topic'
    );
    const got = decodeFunctionResult({
      abi, functionName: 'getAttestation', data: await call('getAttestation', [invId, attester])
    });
    assert.deepStrictEqual(
      [got[0], got[1].toLowerCase(), Number(got[2]), Number(got[3]), got[4].toLowerCase(), got[5].toLowerCase()],
      [invId, digest.toLowerCase(), 3, 0, txHash.toLowerCase(), attester.toLowerCase()],
      'getter round-trip'
    );
    console.log('✔ ALLOW attestation submitted; getter and decoded event verified.');

    // -- 4. BLOCK / REVIEW zero-hash rules on-chain. --
    const rB = await send('attest', ['e2e-inv-block', digest, 1, 1, `0x${'00'.repeat(32)}`, attester]);
    assert.strictEqual(rB.status, '0x1', 'BLOCK with zero hash mined');
    const rR = await send('attest', ['e2e-inv-review', digest, 2, 2, `0x${'00'.repeat(32)}`, attester]);
    assert.strictEqual(rR.status, '0x1', 'REVIEW with zero hash mined');
    await expectRevert('attest', ['e2e-inv-block2', digest, 1, 1, txHash, attester], 'BLOCK + hash');
    await expectRevert('attest', ['e2e-inv-review2', digest, 1, 2, txHash, attester], 'REVIEW + hash');
    await expectRevert('attest', ['', digest, 1, 0, txHash, attester], 'empty id');
    await expectRevert('attest', [invId, `0x${'00'.repeat(32)}`, 1, 0, txHash, attester], 'zero digest');
    await expectRevert('attest', [invId, digest, 4, 0, txHash, attester], 'bitmap 4');
    await expectRevert('attest', [invId, digest, 1, 3, txHash, attester], 'decision 3');
    console.log('✔ BLOCK/REVIEW zero-hash rules and input validation enforced on-chain.');

    // -- 5. Duplicate policy on-chain. --
    const rDup = await send('attest', [invId, digest, 3, 0, txHash, attester]);
    assert.strictEqual(rDup.status, '0x1', 'identical resubmission succeeds');
    assert.strictEqual(rDup.logs.length, 0, 'identical resubmission emits no second event');
    await expectRevert('attest', [invId, keccak256(toHex('other')), 3, 0, txHash, attester], 'conflicting digest');
    const stillGot = decodeFunctionResult({
      abi, functionName: 'getAttestation', data: await call('getAttestation', [invId, attester])
    });
    assert.strictEqual(stillGot[1].toLowerCase(), digest.toLowerCase(), 'original record intact after conflict');
    console.log('✔ Duplicate policy verified: idempotent resubmit, conflicting revert.');

    console.log('\nAll Step 4 attestation-contract e2e scenarios passed.');
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
  runAttestationContractTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAttestationContractTests };
