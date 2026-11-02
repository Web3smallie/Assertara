const assert = require('assert');
const {
  normalizeTx, valueToHex, chainIdToHex,
  createGuardedWallet, wrapViemWallet, wrapEthersSigner
} = require('../../sdk/guardedWallet');
const { CODES } = require('../../sdk/errors');
const sdkIndex = require('../../sdk/index');

// Guarded wallet: normalization, framework adapters, full guarded flow,
// and the no-bypass surface audit. The client is faked; transport,
// policy, and signer behavior are covered by the e2e suite.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

function fakeClient({ decision, executeImpl, waitImpl } = {}) {
  const calls = { submits: [], executes: [], waits: [], operatorWaits: [] };
  const investigation = {
    requestId: 'agent_fake', traceId: 'tr_fake',
    wait: async (opts) => {
      calls.waits.push(opts || {});
      if (typeof waitImpl === 'function') return waitImpl();
      return { requestId: 'agent_fake', status: 'DECIDED', decision: decision || 'ALLOW', reasons: ['ok'] };
    },
    execute: async (tx) => {
      calls.executes.push(tx);
      if (typeof executeImpl === 'function') return executeImpl(tx);
      return { requestId: 'agent_fake', txHash: '0xsigned', receipt: { status: '0x1' } };
    },
    waitForExecution: async () => ({ outcome: 'EXECUTED', txHash: '0xsigned' })
  };
  return {
    calls,
    client: {
      submit: async (args) => { calls.submits.push(args); return investigation; },
      waitForOperatorApproval: async (id, opts) => {
        calls.operatorWaits.push({ id, opts });
        return { requestId: id, status: 'APPROVED', decision: 'REVIEW', approvalToken: 'apv1.op.mac' };
      }
    }
  };
}

async function runGuardedWalletTests() {
  console.log('Testing guarded wallet (normalize, adapters, flow, no-bypass)...\n');

  // Test 1: normalization defaults, conversions, and fail-fast validation.
  {
    const tx = normalizeTx({ to: A1, from: A0, value: 1000n, chainId: 31337 });
    assert.deepStrictEqual(tx, { from: A0, to: A1, value: '0x3e8', data: '0x', chainId: '0x7a69' });
    assert.strictEqual(normalizeTx({ to: A1 }).data, '0x');
    assert.strictEqual(normalizeTx({ to: A1 }).value, '0x0');
    assert.strictEqual(valueToHex({ toString: () => '42' }), '42', 'BigNumber-like accepted');
    assert.strictEqual(chainIdToHex('31337'), '0x7a69');
    assert.strictEqual(chainIdToHex('0x7A69'), '0x7a69');
    for (const [label, bad] of [
      ['bad to', { to: '0x123' }],
      ['missing to', {}],
      ['bad from', { to: A1, from: 'nope' }],
      ['bad data', { to: A1, data: 'zzz' }],
      ['bad chain', { to: A1, chainId: 'lots' }],
      ['bad value', { to: A1, value: -1 }],
      ['bad accessList', { to: A1, accessList: {} }]
    ]) {
      assert.throws(() => normalizeTx(bad), /./, label);
    }
    console.log('✔ Test 1 Passed: Normalization exact with fail-fast validation.');
  }

  // Test 2: guarded send investigates the EXACT bytes, then executes once on ALLOW.
  {
    const { client, calls } = fakeClient({ decision: 'ALLOW' });
    const wallet = createGuardedWallet({ client, account: A0, chainId: 31337 });
    const out = await wallet.sendTransaction({ to: A1, value: 5000 });
    assert.strictEqual(out.decision, 'ALLOW');
    assert.strictEqual(out.txHash, '0xsigned');
    assert.strictEqual(out.execution.outcome, 'EXECUTED');
    assert.strictEqual(calls.submits.length, 1, 'one submission');
    assert.strictEqual(calls.executes.length, 1, 'one execution');
    assert.deepStrictEqual(calls.executes[0], calls.submits[0].transaction, 'executed bytes are the submitted bytes');
    assert.strictEqual(calls.submits[0].transaction.from, A0, 'wallet account stamped');
    assert.strictEqual(calls.submits[0].transaction.chainId, '0x7a69', 'wallet chain default applied');
    assert.ok(typeof calls.submits[0].purpose === 'string' && calls.submits[0].purpose.length > 0, 'purpose always present');
    console.log('✔ Test 2 Passed: ALLOW flow submits exact bytes and executes once.');
  }

  // Test 3: BLOCK/UNCERTAIN stop before execution, with reasons preserved.
  {
    for (const decision of ['BLOCK', 'UNCERTAIN']) {
      const { client, calls } = fakeClient({ decision });
      const wallet = createGuardedWallet({ client, account: A0, chainId: 31337 });
      const err = await wallet.sendTransaction({ to: A1 }).then(() => null, (e) => e);
      assert.ok(err && err.code === CODES.NOT_EXECUTABLE, `${decision} refused`);
      assert.strictEqual(err.detail.decision, decision);
      assert.strictEqual(calls.executes.length, 0, `${decision} never executes`);
    }
    console.log('✔ Test 3 Passed: BLOCK and UNCERTAIN stop unsigned.');
  }

  // Test 4: REVIEW waits for the out-of-band operator release, then executes.
  {
    const { client, calls } = fakeClient({ decision: 'REVIEW' });
    const wallet = createGuardedWallet({ client, account: A0, chainId: 31337 });
    const out = await wallet.sendTransaction({ to: A1 }, { operatorTimeoutMs: 5000 });
    assert.strictEqual(calls.operatorWaits.length, 1, 'release awaited, never submitted');
    assert.strictEqual(calls.operatorWaits[0].opts.timeoutMs, 5000);
    assert.strictEqual(calls.executes.length, 1, 'executes after release');
    assert.strictEqual(out.decision, 'REVIEW');
    console.log('✔ Test 4 Passed: REVIEW executes only after operator release.');
  }

  // Test 5: idempotency keys and progress callbacks pass through to the client.
  {
    const { client, calls } = fakeClient({ decision: 'ALLOW' });
    const wallet = createGuardedWallet({ client, account: A0, chainId: 31337 });
    const onProgress = () => {};
    await wallet.sendTransaction({ to: A1 }, { idempotencyKey: 'wall-key-1', onProgress, purpose: 'rent' });
    assert.strictEqual(calls.submits[0].idempotencyKey, 'wall-key-1');
    assert.strictEqual(calls.submits[0].purpose, 'rent');
    assert.strictEqual(calls.waits[0].onProgress, onProgress);
    console.log('✔ Test 5 Passed: Idempotency, purpose, and progress pass through.');
  }

  // Test 6: viem adapter maps call shapes; writeContract needs data or encode().
  {
    const { client, calls } = fakeClient({ decision: 'ALLOW' });
    const wallet = createGuardedWallet({ client, account: A0, chainId: 31337 });
    const adapted = wrapViemWallet({ wallet, chain: { id: 31337 } });
    await adapted.sendTransaction({ account: A0, to: A1, value: 100n, chain: { id: 1 } });
    assert.strictEqual(calls.submits[0].transaction.value, '0x64');
    assert.strictEqual(calls.submits[0].transaction.chainId, '0x1', 'per-call chain wins');
    await adapted.writeContract({ address: A1, data: '0xdeadbeef' });
    assert.strictEqual(calls.submits[1].transaction.to, A1);
    assert.strictEqual(calls.submits[1].transaction.data, '0xdeadbeef');
    const withEncode = wrapViemWallet({ wallet, encode: () => '0xabc' });
    await withEncode.writeContract({ address: A1 });
    assert.strictEqual(calls.submits[2].transaction.data, '0xabc');
    await assert.rejects(() => adapted.writeContract({ address: A1 }), /pre-encoded data/);
    console.log('✔ Test 6 Passed: Viem call shapes map without a viem dependency.');
  }

  // Test 7: ethers adapter maps call shapes including gasLimit.
  {
    const { client, calls } = fakeClient({ decision: 'ALLOW' });
    const wallet = createGuardedWallet({ client, account: A0, chainId: 31337 });
    const adapted = wrapEthersSigner({ wallet });
    assert.strictEqual(await adapted.getAddress(), A0);
    await adapted.sendTransaction({ to: A1, value: '1000', gasLimit: 21000, chainId: 31337 });
    assert.strictEqual(calls.submits[0].transaction.value, '1000');
    assert.strictEqual(calls.submits[0].transaction.gas, '0x5208', 'gasLimit mapped to gas');
    assert.strictEqual(calls.submits[0].transaction.from, A0);
    console.log('✔ Test 7 Passed: Ethers call shapes map without an ethers dependency.');
  }

  // Test 8: no-bypass surface audit — the SDK exposes no key, signing,
  // broadcast, raw-send, force, or override surface.
  {
    const { client } = fakeClient({});
    const wallet = createGuardedWallet({ client, account: A0, chainId: 1 });
    const denied = /privatekey|secretkey|mnemonic|seed|sendraw|broadcast|signtransaction|signmessage|signer\.sign|force|override|unsafe|skipchecks/i;
    assert.deepStrictEqual(Object.keys(wallet).sort(), ['account', 'getAddress', 'sendTransaction'].sort(), 'wallet surface is exactly the guarded API');
    assert.deepStrictEqual(Object.keys(wrapViemWallet({ wallet })).sort(), ['sendTransaction', 'writeContract'].sort());
    assert.deepStrictEqual(Object.keys(wrapEthersSigner({ wallet })).sort(), ['getAddress', 'sendTransaction'].sort());
    for (const name of Object.keys(sdkIndex)) {
      assert.ok(!denied.test(name), `export ${name} is not a bypass surface`);
    }
    for (const name of ['sendTransaction', 'getAddress', 'writeContract']) {
      assert.ok(!denied.test(name), `method ${name} is not a bypass surface`);
    }
    assert.throws(() => createGuardedWallet({}), /AssertaraClient/, 'wallet cannot exist without a client');
    assert.throws(() => createGuardedWallet({ client, account: 'nope' }), /account/, 'wallet cannot exist without an address');
    console.log('✔ Test 8 Passed: Exported surface contains no bypass mechanism.');
  }

  console.log('\nAll guarded wallet tests passed.');
}

if (require.main === module) {
  runGuardedWalletTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runGuardedWalletTests };
