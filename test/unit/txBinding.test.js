const assert = require('assert');
const nodeCrypto = require('crypto');
const config = require('../../src/config/env');
const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Phase 2 payload binding: the released transaction must be exactly the
// evaluated and approved one. Deterministic only — page/store/backend
// logic with real digests; no live browser, no live model.
const ORIGINAL_KEY = config.modelApiKey;
config.modelApiKey = 'mock_binding';

function freshLibs() {
  delete require.cache[require.resolve('../../extension/shared/gate.js')];
  delete require.cache[require.resolve('../../extension/shared/txDigest.js')];
  delete require.cache[require.resolve('../../extension/content/provider.js')];
  delete globalThis.window;
  require('../../extension/shared/gate.js');
  require('../../extension/shared/txDigest.js');
  require('../../extension/content/provider.js'); // auto-init: no window => no-op
  return { Gate: globalThis.AssertaraGate, TxDigest: globalThis.AssertaraTxDigest, factory: globalThis.__assertaraGatePageFactory };
}

function makeWindow() {
  // Real timers (unlike provider.test.js manual registry): every request in
  // this suite is decided within milliseconds, so no ACK timer ever fires —
  // and the expiry test needs a live clock. Without setTimeout, awaitAck
  // would fail open immediately instead of holding.
  return {
    posted: [], listeners: {},
    postMessage(m) { this.posted.push(m); },
    addEventListener(t, f) { this.listeners[t] = f; },
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id)
  };
}

function awaitSettled(promise) {
  return promise.then(
    (value) => ({ status: 'resolved', value }),
    (error) => ({ status: 'rejected', error })
  );
}

const isoMsg = (data) => ({ __assertara: 'gate-v1', direction: 'iso-to-main', ...data });
const tick = () => new Promise((r) => setImmediate(r));

const ADDR_A = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ADDR_B = '0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0';

function baseTx() {
  return {
    from: ADDR_A, to: ADDR_B, data: '0x1234', value: '0x1',
    chainId: '0x1', nonce: '0x5', gas: '0x5208',
    maxFeePerGas: '0x59682f00', maxPriorityFeePerGas: '0x59682f00', type: '0x2'
  };
}

// Hold one tx request on a fresh page; returns { page, win, args, posted, seen }.
async function holdTx(Gate, factory, txOverrides) {
  const seen = { count: 0, args: null };
  const provider = { async request(a) { seen.count += 1; seen.args = a; return '0xhash'; } };
  const win = makeWindow();
  const page = factory.createGatePage({ window: win, gate: Gate });
  page.wrapProvider(provider, {});
  const args = { method: 'eth_sendTransaction', params: [{ ...baseTx(), ...(txOverrides || {}) }] };
  const result = awaitSettled(provider.request(args));
  await tick();
  const posted = win.posted.find((m) => m.type === 'INTERCEPTED');
  assert.ok(posted, 'INTERCEPTED must be posted');
  return { page, win, args, posted, seen, result };
}

function decideContinue(page, win, posted, approvedDigest) {
  page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: posted.requestId, decision: 'continue', approvedDigest }) });
}

function evaluate(body) {
  return new Promise((resolve) => {
    const req = { body };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); }
    };
    handleEvaluateTransaction(req, res);
  });
}

async function runTxBindingTests() {
  console.log('Testing Phase 2 Payload Binding: digests, snapshots, mutation refusal...\n');
  const { Gate, factory, TxDigest } = freshLibs();

  // Test 1: unmodified tx releases with the verified snapshot.
  {
    const t = await holdTx(Gate, factory);
    assert.ok(TxDigest.isValidDigest(t.posted.txDigest), 'intercept must carry a valid digest');
    decideContinue(t.page, t.win, t.posted, t.posted.txDigest);
    const out = await t.result;
    assert.strictEqual(out.status, 'resolved', 'unmodified approved tx must release');
    assert.strictEqual(t.seen.count, 1);
    console.log('✔ Test 1 Passed: Unmodified approval releases.');
  }

  // Tests 2-8: mutating any security-relevant field refuses release.
  for (const [label, mutate] of [
    ['to', (tx) => { tx.to = ADDR_A; }],
    ['data', (tx) => { tx.data = '0xdeadbeef'; }],
    ['value', (tx) => { tx.value = '0x2'; }],
    ['from', (tx) => { tx.from = ADDR_B; }],
    ['chainId', (tx) => { tx.chainId = '0x89'; }],
    ['nonce', (tx) => { tx.nonce = '0x6'; }],
    ['maxFeePerGas', (tx) => { tx.maxFeePerGas = '0x1'; }],
    ['type', (tx) => { tx.type = '0x0'; }],
    ['gas', (tx) => { tx.gas = '0x10000'; }],
    ['maxPriorityFeePerGas', (tx) => { delete tx.maxPriorityFeePerGas; }],
    ['added chainId', (tx) => { tx.chainId = '0x1'; }, { chainId: undefined }],
  ]) {
    const t = await holdTx(Gate, factory, label === 'added chainId' ? { chainId: undefined } : undefined);
    // Note: spread of { chainId: undefined } keeps the key; drop it to model absence.
    if (label === 'added chainId') delete t.args.params[0].chainId;
    mutate(t.args.params[0]);
    decideContinue(t.page, t.win, t.posted, t.posted.txDigest);
    const out = await t.result;
    assert.strictEqual(out.status, 'rejected', `${label} mutation must refuse release`);
    assert.strictEqual(out.error && out.error.code, 4001);
    assert.ok(/changed after evaluation/.test(out.error.message), `${label}: distinct mutation error`);
    assert.strictEqual(t.seen.count, 0, `${label}: nothing forwarded on mutation`);
    assert.ok(t.win.posted.some((m) => m.type === 'TX_MUTATED' && m.requestId === t.posted.requestId),
      `${label}: mutation must be reported to the worker`);
  }
  console.log('✔ Tests 2-8 Passed: Field mutations refused (to/data/value/from/chainId/nonce/fees/type).');

  // Test 9: missing or malformed security-relevant fields never release.
  {
    // (a) params[0] is null: no snapshot, no digest.
    const seen = { count: 0 };
    const provider = { async request() { seen.count += 1; return '0xhash'; } };
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    page.wrapProvider(provider, {});
    const result = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [null] }));
    await tick();
    const posted = win.posted.find((m) => m.type === 'INTERCEPTED');
    assert.deepStrictEqual(posted.tx, {});
    assert.strictEqual(posted.txDigest, null);
    decideContinue(page, win, posted, null);
    const out = await result;
    assert.strictEqual(out.status, 'rejected', 'undigestible tx must not release');
    assert.strictEqual(seen.count, 0);

    // (b) circular params: snapshot fails closed.
    const cyclic = { to: ADDR_B };
    cyclic.self = cyclic;
    // Drive through the real wrapProvider path:
    const seen2 = { count: 0 };
    const provider3 = { async request(a) { seen2.count += 1; seen2.args = a; return '0xhash'; } };
    const win3 = makeWindow();
    const page3 = factory.createGatePage({ window: win3, gate: Gate });
    page3.wrapProvider(provider3, {});
    const result3 = awaitSettled(provider3.request({ method: 'eth_sendTransaction', params: [cyclic] }));
    await tick();
    const posted3 = win3.posted.find((m) => m.type === 'INTERCEPTED');
    assert.strictEqual(posted3.txDigest, null, 'circular params cannot be digested');
    decideContinue(page3, win3, posted3, posted3.txDigest);
    const out3 = await result3;
    assert.strictEqual(out3.status, 'rejected', 'circular params must not release');
    assert.strictEqual(seen2.count, 0);
    console.log('✔ Test 9 Passed: Missing/malformed fields never release.');
  }

  // Test 10: approval replay rejected (store level).
  {
    const store = Gate.createGateStore();
    const msg = Gate.validateMainMessage({
      __assertara: 'gate-v1', direction: 'main-to-iso', type: 'INTERCEPTED',
      requestId: 'replay-1', method: 'eth_sendTransaction', kind: 'tx',
      tx: baseTx(), txDigest: TxDigest.digestTx(baseTx()),
      chainId: '0x1', wallet: { source: 'window.ethereum' }, pageContext: { url: '', title: '', visibleText: '' }
    });
    const { record } = store.register(msg, 7, 'https://x/');
    assert.ok(TxDigest.isValidDigest(record.txDigest), 'register must store the digest');
    store.setStatus(record, Gate.STATES.AWAITING_USER_DECISION);
    const first = store.decide('replay-1', 'continue');
    assert.strictEqual(first.accepted, true);
    assert.strictEqual(record.approvedDigest, record.txDigest, 'approval binds the digest');
    const second = store.decide('replay-1', 'continue');
    assert.strictEqual(second.accepted, false);
    assert.strictEqual(second.reason, 'already-decided', 'consumed approval cannot be reused');
    console.log('✔ Test 10 Passed: Approval replay rejected.');
  }

  // Test 11: expired approval rejected (store level).
  {
    const store = Gate.createGateStore();
    const msg = Gate.validateMainMessage({
      __assertara: 'gate-v1', direction: 'main-to-iso', type: 'INTERCEPTED',
      requestId: 'expire-1', method: 'eth_sendTransaction', kind: 'tx',
      tx: baseTx(), txDigest: TxDigest.digestTx(baseTx()),
      chainId: '0x1', wallet: { source: 'window.ethereum' }, pageContext: { url: '', title: '', visibleText: '' }
    });
    const { record } = store.register(msg, 7, 'https://x/');
    store.setStatus(record, Gate.STATES.AWAITING_USER_DECISION);
    record.updatedAt = Date.now() - (Gate.LIMITS.DECISION_TIMEOUT_MS + 1000);
    assert.deepStrictEqual(store.sweepExpired(), ['expire-1']);
    assert.strictEqual(record.status, Gate.STATES.EXPIRED);
    const late = store.decide('expire-1', 'continue');
    assert.strictEqual(late.accepted, false, 'expired approval must be rejected');
    console.log('✔ Test 11 Passed: Expired approval rejected.');
  }

  // Test 12: approval for request A cannot release request B.
  {
    const seen = { count: 0 };
    const provider = { async request() { seen.count += 1; return '0xhash'; } };
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    page.wrapProvider(provider, {});
    const argsA = { method: 'eth_sendTransaction', params: [{ ...baseTx(), nonce: '0x5' }] };
    const argsB = { method: 'eth_sendTransaction', params: [{ ...baseTx(), nonce: '0x6' }] };
    const resA = awaitSettled(provider.request(argsA));
    const resB = awaitSettled(provider.request(argsB));
    await tick();
    const postedA = win.posted[0];
    const postedB = win.posted[1];
    assert.notStrictEqual(postedA.txDigest, postedB.txDigest, 'distinct payloads, distinct digests');
    // Attacker replays A's approval digest against B's request id.
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: postedB.requestId, decision: 'continue', approvedDigest: postedA.txDigest }) });
    const outB = await resB;
    assert.strictEqual(outB.status, 'rejected', 'cross-request digest must be refused');
    assert.strictEqual(seen.count, 0);
    // A still releases normally with its own approval.
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: postedA.requestId, decision: 'continue', approvedDigest: postedA.txDigest }) });
    const outA = await resA;
    assert.strictEqual(outA.status, 'resolved');
    assert.strictEqual(seen.count, 1);
    console.log('✔ Test 12 Passed: Cross-request approval rejected.');
  }

  // Test 13: cancel and timeout never release (manual clock: ACK both to
  // stop retries, cancel one, fire the other's expiry, then replay
  // digest-carrying late continues — all must be dropped).
  {
    const timers = [];
    let timerSeq = 0;
    const win = {
      ...makeWindow(),
      setTimeout(cb, ms) { timerSeq += 1; timers.push({ id: timerSeq, cb, ms: ms || 0 }); return timerSeq; },
      clearTimeout(id) { const i = timers.findIndex((t) => t.id === id); if (i !== -1) timers.splice(i, 1); },
      runTimers(max, maxMs) {
        const cap = maxMs === undefined ? Infinity : maxMs;
        let n = 0;
        const deferred = [];
        while (timers.length > 0 && n < max) {
          const t = timers.shift();
          if (t.ms <= cap) { n += 1; t.cb(); } else { deferred.push(t); }
        }
        for (let i = deferred.length - 1; i >= 0; i -= 1) timers.unshift(deferred[i]);
        return n;
      }
    };
    const seen = { count: 0 };
    const provider = { async request() { seen.count += 1; return '0xhash'; } };
    const page = factory.createGatePage({ window: win, gate: Gate });
    page.wrapProvider(provider, {});
    const resCancel = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [baseTx()] }));
    const resTimeout = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [baseTx()] }));
    await tick();
    const postedCancel = win.posted.find((m) => m.type === 'INTERCEPTED');
    const postedTimeout = win.posted.filter((m) => m.type === 'INTERCEPTED')[1];
    page.onPageMessage({ source: win, data: isoMsg({ type: 'ACK', requestId: postedCancel.requestId }) });
    page.onPageMessage({ source: win, data: isoMsg({ type: 'ACK', requestId: postedTimeout.requestId }) });
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: postedCancel.requestId, decision: 'cancel' }) });
    assert.strictEqual((await resCancel).status, 'rejected');
    win.runTimers(5); // fire the decision-timeout timer
    assert.strictEqual((await resTimeout).status, 'rejected');
    assert.ok(/expired/.test((await resTimeout).error.message));
    // Late continue after cancel/timeout is dropped (unknown ids), even
    // with the correct approval digests attached.
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: postedCancel.requestId, decision: 'continue', approvedDigest: postedCancel.txDigest }) });
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: postedTimeout.requestId, decision: 'continue', approvedDigest: postedTimeout.txDigest }) });
    await tick();
    assert.strictEqual(seen.count, 0, 'cancel/timeout must never release');
    console.log('✔ Test 13 Passed: Cancel/timeout never release.');
  }

  // Test 14: canonicalization deterministic across equivalent representations.
  {
    const d = (tx) => TxDigest.digestTx(tx);
    const addr = '0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD';
    assert.strictEqual(d({ to: addr }), d({ to: addr.toLowerCase() }), 'address case-insensitive');
    assert.strictEqual(d({ value: '0x0a' }), d({ value: '10' }), 'hex/decimal equivalent');
    assert.strictEqual(d({ value: '0x0a' }), d({ value: 10 }), 'string/number equivalent');
    assert.strictEqual(d({ value: '0x00a' }), d({ value: '0xa' }), 'leading zeros equivalent');
    assert.strictEqual(d({ to: ADDR_A, value: '0x1' }), d({ value: '0x1', to: ADDR_A }), 'key order irrelevant');
    assert.strictEqual(d({ to: ADDR_A }), d({ to: ADDR_A, value: null }), 'explicit null equals absent');
    assert.strictEqual(d({ data: '0XAB' }), d({ data: '0xab' }), 'data hex case-insensitive');
    assert.strictEqual(d({ type: 2 }), d({ type: '0x2' }), 'type number/string equivalent');
    assert.strictEqual(d({ type: '0x02' }), d({ type: '0x2' }), 'type leading zeros equivalent');
    assert.strictEqual(d({ chainId: '1' }), d({ chainId: '0x1' }), 'chainId decimal/hex equivalent');
    // Every security-relevant field flips the digest.
    const base = d(baseTx());
    const flips = {
      to: ADDR_A, from: ADDR_B, data: '0x00', value: '0x2', chainId: '0x2',
      nonce: '0x6', type: '0x0', gas: '0x5209', gasPrice: '0x1',
      maxFeePerGas: '0x2', maxPriorityFeePerGas: '0x2'
    };
    for (const [field, val] of Object.entries(flips)) {
      assert.notStrictEqual(d({ ...baseTx(), [field]: val }), base, `${field} must flip the digest`);
    }
    assert.notStrictEqual(
      d({ ...baseTx(), accessList: [{ address: ADDR_A, storageKeys: ['0x01'] }] }), base, 'accessList flips the digest');
    assert.notStrictEqual(d({ ...baseTx(), extraField: 'x' }), base, 'extra fields are bound');
    assert.notStrictEqual(d({}), d({ chainId: '0x1' }), 'absent vs present differs');
    assert.strictEqual(d({ value: undefined }), d({}), 'undefined equals absent');
    console.log('✔ Test 14 Passed: Canonicalization deterministic and field-sensitive.');
  }

  // Test 15: forwarded object IS the verified frozen snapshot.
  {
    const t = await holdTx(Gate, factory);
    decideContinue(t.page, t.win, t.posted, t.posted.txDigest);
    const out = await t.result;
    assert.strictEqual(out.status, 'resolved');
    assert.strictEqual(t.seen.args.params[0], t.posted.tx, 'forwarded params must be the approved snapshot object');
    assert.ok(Object.isFrozen(t.seen.args.params[0]), 'forwarded snapshot frozen');
    assert.notStrictEqual(t.seen.args, t.args, 'live args object never forwarded');
    console.log('✔ Test 15 Passed: Release forwards the verified snapshot.');
  }

  // Test 16: SHA-256 verified against platform crypto + NIST vectors.
  {
    const vectors = ['', 'abc', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'a'.repeat(1000), 'x'.repeat(100000)];
    for (const v of vectors) {
      const expected = nodeCrypto.createHash('sha256').update(v, 'utf8').digest('hex');
      assert.strictEqual(TxDigest.sha256Hex(v), expected, `sha256 must match node:crypto (len ${v.length})`);
    }
    assert.strictEqual(TxDigest.sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.strictEqual(TxDigest.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    // WebCrypto agrees on canonical bytes (async platform primitive).
    const subtle = (globalThis.crypto && globalThis.crypto.subtle) || nodeCrypto.webcrypto.subtle;
    const canonical = TxDigest.canonicalizeTx(baseTx());
    const ab = await subtle.digest('SHA-256', Buffer.from(canonical, 'utf8'));
    const webHex = Buffer.from(ab).toString('hex');
    assert.strictEqual(webHex, TxDigest.digestTx(baseTx()), 'WebCrypto must agree with vendored SHA-256');
    // Digest of a real tx equals node:crypto over the canonical string.
    const nodeHex = nodeCrypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
    assert.strictEqual(TxDigest.digestTx(baseTx()), nodeHex, 'digestTx must equal node:crypto over canonical bytes');
    console.log('✔ Test 16 Passed: SHA-256 cross-checked (node:crypto, WebCrypto, NIST).');
  }

  // Test 17: snapshot/canonical fail-closed edges.
  {
    assert.strictEqual(TxDigest.snapshotTx(null), null);
    assert.strictEqual(TxDigest.snapshotTx([]), null);
    assert.strictEqual(TxDigest.snapshotTx('str'), null);
    assert.strictEqual(TxDigest.digestTx(null), null);
    assert.strictEqual(TxDigest.digestTx('str'), null);
    assert.strictEqual(TxDigest.digestTx([]), null);
    assert.strictEqual(TxDigest.snapshotTx({ v: 10n }), null, 'bigint fails the snapshot');
    assert.strictEqual(TxDigest.digestTx({ value: 10n }), null, 'bigint fails canonicalization');
    const snap = TxDigest.snapshotTx({ to: ADDR_A, nested: { arr: [1, { x: 'y' }] } });
    assert.ok(Object.isFrozen(snap) && Object.isFrozen(snap.nested) && Object.isFrozen(snap.nested.arr), 'deep freeze');
    const dropped = TxDigest.snapshotTx({ a: undefined, b: () => 1, c: NaN, d: Infinity, e: 'x' });
    assert.deepStrictEqual(dropped, { c: null, d: null, e: 'x' }, 'JSON transport semantics');
    assert.strictEqual(TxDigest.sha256Hex(123), null);
    assert.strictEqual(TxDigest.isValidDigest('zz'), false);
    assert.strictEqual(TxDigest.digestsEqual('ab'.repeat(32), 'ab'.repeat(32)), true);
    assert.strictEqual(TxDigest.digestsEqual('ab'.repeat(32), null), false);
    console.log('✔ Test 17 Passed: Snapshot/canonical fail-closed edges.');
  }

  // Test 18: validation preserves bindable fields, drops unrepresentable ones.
  {
    const full = {
      __assertara: 'gate-v1', direction: 'main-to-iso', type: 'INTERCEPTED',
      requestId: 'val-1', method: 'eth_sendTransaction', kind: 'tx',
      tx: { ...baseTx(), extra: 'kept', accessList: [{ address: ADDR_A, storageKeys: ['0x01'] }] },
      txDigest: TxDigest.digestTx(baseTx()),
      chainId: '0x1', wallet: { source: 'w' }, pageContext: { url: '', title: '', visibleText: '' }
    };
    const clean = Gate.validateMainMessage(full);
    assert.deepStrictEqual(clean.tx, full.tx, 'all bindable fields preserved exactly');
    assert.strictEqual(clean.txDigest, full.txDigest);
    const big = Gate.validateMainMessage({ ...full, requestId: 'val-2', tx: { ...baseTx(), data: '0x' + 'ab'.repeat(40000) } });
    assert.ok(!('data' in big.tx), 'oversized field dropped whole');
    const badDigest = Gate.validateMainMessage({ ...full, requestId: 'val-3', txDigest: 'not-a-digest' });
    assert.strictEqual(badDigest.txDigest, null, 'malformed digest becomes null, never passes through');
    const mutated = Gate.validateMainMessage({ __assertara: 'gate-v1', direction: 'main-to-iso', type: 'TX_MUTATED', requestId: 'val-4' });
    assert.deepStrictEqual(mutated, { type: 'TX_MUTATED', requestId: 'val-4' });
    const dec = Gate.validateIsoMessage({ __assertara: 'gate-v1', direction: 'iso-to-main', type: 'DECISION', requestId: 'val-5', decision: 'continue', reason: null, approvedDigest: 'cd'.repeat(32) });
    assert.strictEqual(dec.approvedDigest, 'cd'.repeat(32));
    const decBad = Gate.validateIsoMessage({ __assertara: 'gate-v1', direction: 'iso-to-main', type: 'DECISION', requestId: 'val-6', decision: 'continue', reason: null, approvedDigest: 'bogus' });
    assert.strictEqual(decBad.approvedDigest, null, 'malformed approval digest becomes null');
    console.log('✔ Test 18 Passed: Validation preserves binding, rejects malformed digests.');
  }

  // Test 19: backend binds the evaluated bytes (tri-state match).
  {
    const tx = { from: ADDR_A, to: ADDR_B, data: '0x', value: '0x1' };
    const expected = nodeCrypto.createHash('sha256').update(TxDigest.canonicalizeTx(tx), 'utf8').digest('hex');
    const plain = await evaluate({ pageContext: { title: 't', url: 'https://x/' }, transaction: tx });
    assert.strictEqual(plain.status, 200);
    assert.strictEqual(plain.body.txBinding.evaluatedTxDigest, expected, 'backend digest equals canonical bytes hash');
    assert.strictEqual(plain.body.txBinding.receivedTxDigest, null);
    assert.strictEqual(plain.body.txBinding.match, null, 'no claim means not comparable, not false');
    const claimed = await evaluate({ pageContext: { title: 't', url: 'https://x/' }, transaction: tx, txDigest: expected });
    assert.strictEqual(claimed.body.txBinding.match, true);
    const forged = await evaluate({ pageContext: { title: 't', url: 'https://x/' }, transaction: tx, txDigest: 'ff'.repeat(32) });
    assert.strictEqual(forged.body.txBinding.match, false, 'wrong claim detected');
    assert.strictEqual(forged.body.txBinding.receivedTxDigest, 'ff'.repeat(32));
    const garbage = await evaluate({ pageContext: { title: 't', url: 'https://x/' }, transaction: tx, txDigest: 'garbage' });
    assert.strictEqual(garbage.body.txBinding.receivedTxDigest, null);
    assert.strictEqual(garbage.body.txBinding.match, null);
    console.log('✔ Test 19 Passed: Backend txBinding tri-state exact.');
  }

  config.modelApiKey = ORIGINAL_KEY;
  await closeOcrWorker();
  console.log('\nAll Transaction Binding Tests Passed Successfully!\n');
}

if (require.main === module) {
  runTxBindingTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runTxBindingTests };
