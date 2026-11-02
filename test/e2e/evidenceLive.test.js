const assert = require('assert');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const { fetchChainState } = require('../../src/services/chainStateService');
const { keccak256 } = require('viem');

// Live evidence test: genuine Anvil chain-state reads (NO mocks — real RPC,
// real balances/nonces/code). Requires Anvil + localhost; run via test:e2e.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

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

async function runEvidenceLiveTests() {
  console.log('Testing live chain-state evidence (real Anvil, NO mocks)...\n');

  const anvilPort = await freePort();
  const anvilRpc = `http://127.0.0.1:${anvilPort}`;
  const anvilCandidates = [
    process.env.ANVIL_BIN,
    path.join(os.homedir(), '.foundry', 'bin', process.platform === 'win32' ? 'anvil.exe' : 'anvil'),
    'anvil'
  ].filter(Boolean);
  const anvilBin = anvilCandidates.find((c) => { try { return fs.existsSync(c); } catch { return false; } }) || 'anvil';
  const anvil = spawn(anvilBin, ['--port', String(anvilPort)], { stdio: ['ignore', 'ignore', 'pipe'] });
  anvil.on('error', () => {});
  const kill = () => { try { anvil.kill('SIGKILL'); } catch {} };

  try {
    const start = Date.now();
    for (;;) {
      try {
        if ((await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69') break;
      } catch { /* booting */ }
      if (Date.now() - start > 30000) throw new Error('anvil did not boot');
      await new Promise((r) => setTimeout(r, 500));
    }
    console.log(`  anvil up on ${anvilPort}`);

    // Live read: funded EOA + empty account.
    const state = await fetchChainState({
      rpcUrl: anvilRpc, chainId: '0x7a69',
      addresses: [
        { role: 'sender', address: A0 },
        { role: 'empty', address: `0xAb${'0'.repeat(36)}99` }
      ],
      timeoutMs: 10000
    });
    assert.strictEqual(state.status, 'ok', JSON.stringify(state.error || 'ok'));
    assert.strictEqual(state.rpcChainId, '31337');
    assert.strictEqual(state.chainVerified, true);
    assert.ok(/^0x[0-9a-f]+$/.test(state.blockNumber), 'live block number recorded');
    assert.strictEqual(state.states.sender.balanceWei, '10000000000000000000000', 'genuine Anvil endowment (10000 ETH)');
    assert.strictEqual(state.states.sender.nonce, '0', 'genuine nonce');
    assert.strictEqual(state.states.sender.hasCode, false, 'EOA has no code');
    assert.strictEqual(state.states.sender.codeHash, null);
    assert.strictEqual(state.states.empty.balanceWei, '0');
    console.log('✔ Live Test 1 Passed: Genuine balances/nonces/code-absence.');

    // Live code presence + codehash via Anvil-supported state override.
    const contractAddr = `0xCc${'0'.repeat(36)}11`;
    const runtime = '0x60003560001c8060201b9115156000526001601cf3';
    await rpc(anvilRpc, 'anvil_setCode', [contractAddr, runtime]);
    const coded = await fetchChainState({
      rpcUrl: anvilRpc, chainId: 31337,
      addresses: [{ role: 'target', address: contractAddr }],
      timeoutMs: 10000
    });
    assert.strictEqual(coded.status, 'ok');
    assert.strictEqual(coded.states.target.hasCode, true);
    assert.strictEqual(coded.states.target.codeHash, keccak256(runtime), 'codehash derived from live code');
    console.log('✔ Live Test 2 Passed: Genuine code presence + codehash.');

    // Wrong-chain reads are discarded live.
    const wrong = await fetchChainState({ rpcUrl: anvilRpc, chainId: '0x1', addresses: [], timeoutMs: 10000 });
    assert.strictEqual(wrong.status, 'wrong-chain');
    assert.strictEqual(wrong.rpcChainId, '31337');
    assert.strictEqual(wrong.states, undefined, 'no mixed-chain state');
    console.log('✔ Live Test 3 Passed: Wrong-chain detection live.');

    // Unreachable RPC fails closed with a recorded status.
    const dead = await fetchChainState({ rpcUrl: 'http://127.0.0.1:9', chainId: '0x7a69', addresses: [], timeoutMs: 2000 });
    assert.ok(['timeout', 'rpc-error'].includes(dead.status), `dead RPC recorded (${dead.status})`);
    console.log('✔ Live Test 4 Passed: Dead RPC fails closed.');

    console.log('\nAll Live Evidence Tests Passed Successfully!\n');
    kill();
    await new Promise((r) => setTimeout(r, 300));
  } catch (err) {
    kill();
    throw err;
  }
}

if (require.main === module) {
  runEvidenceLiveTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runEvidenceLiveTests };
