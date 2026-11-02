const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { issueApproval } = require('../../src/services/approvals');
const { digestTx } = require('../../extension/shared/txDigest');
const { createSigner } = require('../../src/signer/signerService');
const { getStatus, reanchor } = require('../../src/signer/recover');
const { anchorMac } = require('../../src/signer/replayStore');

// Replay continuity: the HMAC-chained consumption log plus its integrity
// anchor. Deletion, rollback, truncation, or corruption of either file
// refuses signing until an operator verifies and recovers — a consumed
// approval is never silently resurrected.

const SIGNER_KEY = generatePrivateKey();
const SIGNER = privateKeyToAccount(SIGNER_KEY).address;
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();
const APPROVAL_SECRET = 'replay-test-approval-secret-0123456789ab';
const OPERATOR_SECRET = 'replay-test-operator-secret-0123456789ab';
const NOW = 1780000000000;

function fixtureMandate(overrides) {
  return {
    id: 'replay-mandate', version: 2, issuer: 'test-operator',
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

async function sealedMandate(overrides) {
  const dir = scratchDir('replay-mandate');
  try {
    const file = path.join(dir, 'mandate.json');
    fs.writeFileSync(file, JSON.stringify(fixtureMandate(overrides)), 'utf8');
    const loaded = loadMandate(file);
    assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
    loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
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

function approvalFor(t, { requestId, nonce, nowMs, ttlMs } = {}) {
  return issueApproval({
    secret: APPROVAL_SECRET, requestId: requestId || 'agent_replay-1', txDigest: digestTx(t),
    chainId: t.chainId, sender: t.from, mandateId: 'replay-mandate',
    mandateVersion: 2, policyId: 'assertara-agent-mvp-1',
    requiresOperator: false, ttlMs: ttlMs || 300000, nowMs: nowMs === undefined ? NOW : nowMs,
    nonce: nonce || `replay-nonce-${Math.floor(Math.random() * 1e9)}`,
    subcallTreeHash: treeHashFor(t)
  });
}

function fakeClients(calls) {
  return {
    wallet: {
      sendTransaction: async (t) => {
        calls.send += 1;
        if (!t.to || t.value === undefined || t.nonce === undefined || t.chainId === undefined) {
          throw new Error('mock chain: incomplete tx assembly');
        }
        return `0x${'ef'.repeat(32)}`;
      }
    },
    public: {
      getTransactionCount: async () => 7,
      getBalance: async () => 1000000000000000000000n,
      waitForTransactionReceipt: async () => ({ status: '0x1', blockNumber: '0x5', gasUsed: '0x5208' })
    }
  };
}

function bootOpts(dir, mandate, extra) {
  return {
    approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET,
    mandate, mandateAuthorities: [OPERATOR_ADDR], privateKey: SIGNER_KEY,
    consumedFile: path.join(dir, 'consumed.jsonl'),
    anchorFile: path.join(dir, 'replay-anchor.json'),
    stateFile: null, policyCallbackUrl: null, nowFn: () => NOW,
    ...(extra || {})
  };
}

async function runReplayTests() {
  console.log('Testing replay continuity (chained log + anchor)...\n');

  // Test 1: consumed approval stays rejected after restart.
  {
    const dir = scratchDir('replay-t1');
    const mandate = await sealedMandate();
    const t = tx();
    const token = approvalFor(t, { nonce: 'replay-t1' });
    const calls = { send: 0 };
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients(calls) });
    assert.strictEqual((await s1.execute({ requestId: 'agent_replay-1', transaction: t, approval: token })).ok, true);
    const s2 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual(s2.consumedCount(), 1);
    const replay = await s2.execute({ requestId: 'agent_replay-1', transaction: t, approval: token });
    assert.strictEqual(replay.ok, false);
    assert.ok(/already consumed/.test(replay.error));
    assert.strictEqual(calls.send, 1);
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 1 Passed: Consumption survives restart.');
  }

  // Test 2: deleting the nonce log refuses startup (no silent reset).
  {
    const dir = scratchDir('replay-t2');
    const mandate = await sealedMandate();
    const t = tx();
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual((await s1.execute({ requestId: 'agent_replay-2', transaction: t, approval: approvalFor(t, { nonce: 'replay-t2', requestId: 'agent_replay-2' }) })).ok, true);
    fs.rmSync(path.join(dir, 'consumed.jsonl'));
    await assert.rejects(() => createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) }), /behind its anchor/, 'log deletion refuses startup');
    const status = getStatus({ approvalSecret: APPROVAL_SECRET, consumedFile: path.join(dir, 'consumed.jsonl'), anchorFile: path.join(dir, 'replay-anchor.json') });
    assert.strictEqual(status.verdict, 'REFUSED');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 2 Passed: Deleted log refuses startup.');
  }

  // Test 3: restoring an older log is detected via the anchor.
  {
    const dir = scratchDir('replay-t3');
    const mandate = await sealedMandate();
    const t = tx();
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual((await s1.execute({ requestId: 'agent_r3a', transaction: t, approval: approvalFor(t, { nonce: 'replay-t3a', requestId: 'agent_r3a' }) })).ok, true);
    const backup = fs.readFileSync(path.join(dir, 'consumed.jsonl'), 'utf8');
    assert.strictEqual((await s1.execute({ requestId: 'agent_r3b', transaction: t, approval: approvalFor(t, { nonce: 'replay-t3b', requestId: 'agent_r3b' }) })).ok, true);
    fs.writeFileSync(path.join(dir, 'consumed.jsonl'), backup, 'utf8'); // restore older log
    await assert.rejects(() => createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) }), /behind its anchor/, 'rolled-back log refuses startup');
    // Operator recovery re-anchors only forward: restoring the full log boots cleanly.
    const s2 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) }).catch(() => null);
    assert.strictEqual(s2, null, 'still refused while the log is short');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 3 Passed: Rolled-back log detected.');
  }

  // Test 4: corrupting log or anchor prevents unsafe signing.
  {
    const dir = scratchDir('replay-t4');
    const mandate = await sealedMandate();
    const t = tx();
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual((await s1.execute({ requestId: 'agent_replay-4', transaction: t, approval: approvalFor(t, { nonce: 'replay-t4', requestId: 'agent_replay-4' }) })).ok, true);
    const logPath = path.join(dir, 'consumed.jsonl');
    const anchorPath = path.join(dir, 'replay-anchor.json');
    const savedLog = fs.readFileSync(logPath, 'utf8');
    const savedAnchor = fs.readFileSync(anchorPath, 'utf8');
    fs.appendFileSync(logPath, 'truncated-garbage{{{\n', 'utf8');
    await assert.rejects(() => createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) }), /integrity|start/, 'corrupt log refuses startup');
    fs.writeFileSync(logPath, savedLog, 'utf8');
    const tampered = JSON.parse(savedAnchor);
    tampered.tipMac = 'f'.repeat(64);
    fs.writeFileSync(anchorPath, JSON.stringify(tampered), 'utf8');
    await assert.rejects(() => createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) }), /integrity check|does not match/, 'corrupt anchor refuses startup');
    fs.writeFileSync(anchorPath, savedAnchor, 'utf8');
    const s2 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual(s2.consumedCount(), 1, 'intact state still boots');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 4 Passed: Corruption fails closed.');
  }

  // Test 5: concurrent consumption attempts yield at most one success.
  {
    const dir = scratchDir('replay-t5');
    const mandate = await sealedMandate();
    const t = tx();
    const token = approvalFor(t, { nonce: 'replay-t5', requestId: 'agent_replay-5' });
    const calls = { send: 0 };
    const s = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients(calls) });
    const results = await Promise.all([
      s.execute({ requestId: 'agent_replay-5', transaction: t, approval: token }),
      s.execute({ requestId: 'agent_replay-5', transaction: t, approval: token })
    ]);
    const wins = results.filter((r) => r.ok);
    const losses = results.filter((r) => !r.ok && /already consumed/.test(r.error));
    assert.strictEqual(wins.length, 1, 'exactly one consumption succeeds');
    assert.strictEqual(losses.length, 1, 'the loser is refused as consumed');
    assert.strictEqual(calls.send, 1, 'single broadcast');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 5 Passed: Concurrent consume serializes.');
  }

  // Test 6: interrupted broadcast reconciles without duplicate execution.
  {
    const dir = scratchDir('replay-t6');
    const mandate = await sealedMandate();
    const t = tx();
    const token = approvalFor(t, { nonce: 'replay-t6', requestId: 'agent_replay-6' });
    const failing = {
      wallet: { sendTransaction: async () => { throw new Error('mock outage'); } },
      public: { getTransactionCount: async () => 7, getBalance: async () => 1n, waitForTransactionReceipt: async () => ({ status: '0x1' }) }
    };
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: failing });
    const burned = await s1.execute({ requestId: 'agent_replay-6', transaction: t, approval: token });
    assert.strictEqual(burned.ok, false);
    assert.strictEqual(burned.code, 'CHAIN_ERROR');
    const calls = { send: 0 };
    const s2 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients(calls) });
    const replay = await s2.execute({ requestId: 'agent_replay-6', transaction: t, approval: token });
    assert.strictEqual(replay.ok, false, 'burned approval never retries');
    assert.strictEqual(calls.send, 0);
    // A fresh approval for the same action proceeds: the ledger is healthy,
    // only the burned nonce is dead.
    const retry = await s2.execute({ requestId: 'agent_replay-6b', transaction: t, approval: approvalFor(t, { nonce: 'replay-t6b', requestId: 'agent_replay-6b' }) });
    assert.strictEqual(retry.ok, true, 'fresh approval executes after recovery');
    assert.strictEqual(calls.send, 1);
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 6 Passed: Interruption reconciles without duplicates.');
  }

  // Test 7: valid approvals keep expiry + consumption status across restart.
  {
    const dir = scratchDir('replay-t7');
    const mandate = await sealedMandate();
    const t = tx();
    const used = approvalFor(t, { nonce: 'replay-t7-used', requestId: 'agent_r7a' });
    const fresh = approvalFor(t, { nonce: 'replay-t7-fresh', requestId: 'agent_r7b' });
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual((await s1.execute({ requestId: 'agent_r7a', transaction: t, approval: used })).ok, true);
    const s2 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual(s2.verify({ requestId: 'agent_r7b', transaction: t, approval: fresh }).ok, true, 'unconsumed approval still valid');
    const replay = await s2.execute({ requestId: 'agent_r7a', transaction: t, approval: used });
    assert.strictEqual(replay.ok, false, 'consumed approval still refused');
    const sLate = await createSigner({ ...bootOpts(dir, mandate, { nowFn: () => NOW + 300001 }), clients: fakeClients({ send: 0 }) });
    assert.strictEqual(sLate.verify({ requestId: 'agent_r7b', transaction: t, approval: fresh }).ok, false, 'expiry still enforced after restart');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 7 Passed: Expiry + consumption status preserved.');
  }

  // Test 8: operator recovery re-anchors a verified log — never down.
  {
    const dir = scratchDir('replay-t8');
    const mandate = await sealedMandate();
    const t = tx();
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual((await s1.execute({ requestId: 'agent_replay-8', transaction: t, approval: approvalFor(t, { nonce: 'replay-t8', requestId: 'agent_replay-8' }) })).ok, true);
    const anchorPath = path.join(dir, 'replay-anchor.json');
    const savedAnchor = fs.readFileSync(anchorPath, 'utf8');
    fs.rmSync(anchorPath); // anchor lost, log intact
    await assert.rejects(() => createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) }), /anchor is missing/, 'anchor loss refuses startup');
    assert.throws(() => reanchor({
      approvalSecret: APPROVAL_SECRET, operatorSecret: 'wrong', expectedOperatorSecret: OPERATOR_SECRET,
      consumedFile: path.join(dir, 'consumed.jsonl'), anchorFile: anchorPath, mandate
    }), /authentication failed/, 'recovery needs the operator');
    const out = reanchor({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET, expectedOperatorSecret: OPERATOR_SECRET,
      consumedFile: path.join(dir, 'consumed.jsonl'), anchorFile: anchorPath, mandate
    });
    assert.strictEqual(out.tipSeq, 1, 're-anchored to the verified tip');
    const s2 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual(s2.consumedCount(), 1, 'consumption preserved through recovery');
    assert.ok(fs.existsSync(path.join(dir, 'recovery-audit.jsonl')), 'recovery leaves an audit trail');
    // Re-anchoring DOWN (forgetting consumptions) is refused even by the operator path.
    fs.writeFileSync(anchorPath, savedAnchor, 'utf8');
    fs.writeFileSync(path.join(dir, 'consumed.jsonl'), '', 'utf8');
    assert.throws(() => reanchor({
      approvalSecret: APPROVAL_SECRET, operatorSecret: OPERATOR_SECRET, expectedOperatorSecret: OPERATOR_SECRET,
      consumedFile: path.join(dir, 'consumed.jsonl'), anchorFile: anchorPath, mandate
    }), /re-anchor down/, 'recovery never forgets consumptions');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 8 Passed: Recovery re-anchors forward only.');
  }

  // Test 9: crash between log append and anchor update catches up safely.
  {
    const dir = scratchDir('replay-t9');
    const mandate = await sealedMandate();
    const t = tx();
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual((await s1.execute({ requestId: 'agent_replay-9', transaction: t, approval: approvalFor(t, { nonce: 'replay-t9', requestId: 'agent_replay-9' }) })).ok, true);
    const anchorPath = path.join(dir, 'replay-anchor.json');
    // Simulate the crash window: HMAC-valid log line present, anchor
    // still at the previous HMAC-valid tip. Boot must adopt forward.
    fs.writeFileSync(anchorPath, JSON.stringify({
      format: 'assertara-replay-anchor-1', tipSeq: 0, tipMac: 'GENESIS',
      mandateId: 'replay-mandate', mandateVersion: 2, updatedAt: NOW,
      mac: anchorMac(APPROVAL_SECRET, { tipSeq: 0, tipMac: 'GENESIS' })
    }), 'utf8');
    const s2 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual(s2.consumedCount(), 1, 'crash-window consumption adopted, not lost');
    const adopted = JSON.parse(fs.readFileSync(anchorPath, 'utf8'));
    assert.strictEqual(adopted.tipSeq, 1, 'anchor caught up to the log');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 9 Passed: Crash-window state recovers forward.');
  }

  // Test 10: ambiguous state never yields an empty trusted ledger —
  // except total fresh boot, which is explicit and documented.
  {
    const dir = scratchDir('replay-t10');
    const mandate = await sealedMandate();
    const t = tx();
    const s1 = await createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual((await s1.execute({ requestId: 'agent_replay-10', transaction: t, approval: approvalFor(t, { nonce: 'replay-t10', requestId: 'agent_replay-10' }) })).ok, true);
    // Anchor gone, log present → refuse (never re-trust silently).
    fs.rmSync(path.join(dir, 'replay-anchor.json'));
    await assert.rejects(() => createSigner({ ...bootOpts(dir, mandate), clients: fakeClients({ send: 0 }) }), /anchor is missing/);
    // Log gone, anchor present → refuse (never reboot empty).
    const s2dir = scratchDir('replay-t10b');
    const sA = await createSigner({ ...bootOpts(s2dir, mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual((await sA.execute({ requestId: 'agent_r10b', transaction: t, approval: approvalFor(t, { nonce: 'replay-t10b', requestId: 'agent_r10b' }) })).ok, true);
    fs.rmSync(path.join(s2dir, 'consumed.jsonl'));
    await assert.rejects(() => createSigner({ ...bootOpts(s2dir, mandate), clients: fakeClients({ send: 0 }) }), /behind its anchor/);
    // Both absent → first boot (explicit residual: indistinguishable from
    // a fresh install; contained by short approval TTLs + mandate
    // rotation, documented in the trust model).
    const fresh = await createSigner({ ...bootOpts(scratchDir('replay-t10c'), mandate), clients: fakeClients({ send: 0 }) });
    assert.strictEqual(fresh.consumedCount(), 0);
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(s2dir, { recursive: true, force: true });
    console.log('✔ Test 10 Passed: Ambiguity fails closed; fresh boot explicit.');
  }

  console.log('\nAll Replay Continuity Tests Passed Successfully!\n');
}

if (require.main === module) {
  runReplayTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runReplayTests };
