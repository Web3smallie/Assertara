const assert = require('assert');

// Unit tests for the pre-sign gate page observer (MAIN world) and the
// shared gate protocol/state machine. Deterministic mocks only — these
// prove holding, forwarding, cancellation, validation, and race safety
// of the extension's own logic, NOT real wallet interception.

function freshLibs() {
  delete require.cache[require.resolve('../../extension/shared/gate.js')];
  delete require.cache[require.resolve('../../extension/shared/txDigest.js')];
  delete require.cache[require.resolve('../../extension/content/provider.js')];
  delete globalThis.window;
  require('../../extension/shared/gate.js');
  require('../../extension/shared/txDigest.js');
  require('../../extension/content/provider.js'); // auto-init: no window => no-op
  return { Gate: globalThis.AssertaraGate, factory: globalThis.__assertaraGatePageFactory, TxDigest: globalThis.AssertaraTxDigest };
}

function makeWindow() {
  const timers = [];
  let timerSeq = 0;
  const win = {
    posted: [],
    listeners: {},
    location: { href: 'https://dapp.example/swap' },
    document: { title: 'Example Swap', body: { innerText: 'Swap 1 ETH' } },
    postMessage(msg) { this.posted.push(msg); },
    addEventListener(type, fn) { this.listeners[type] = fn; },
    setTimeout(cb, ms) { timerSeq += 1; timers.push({ id: timerSeq, cb, ms: ms || 0 }); return timerSeq; },
    clearTimeout(id) { const i = timers.findIndex((t) => t.id === id); if (i !== -1) timers.splice(i, 1); },
    runTimers(max, maxMs) {
      const cap = maxMs === undefined ? Infinity : maxMs;
      let n = 0;
      const deferred = [];
      while (timers.length > 0 && n < max) {
        const t = timers.shift();
        if (t.ms <= cap) {
          n += 1;
          t.cb();
        } else {
          deferred.push(t);
        }
      }
      for (let i = deferred.length - 1; i >= 0; i -= 1) timers.unshift(deferred[i]);
      return n;
    },
    pendingTimers: () => timers.length
  };
  return win;
}

function isoMsg(data) {
  return { __assertara: 'gate-v1', direction: 'iso-to-main', ...data };
}

function awaitSettled(promise) {
  return promise.then(
    (value) => ({ status: 'resolved', value }),
    (error) => ({ status: 'rejected', error })
  );
}

async function runProviderTests() {
  console.log('Testing Assertara pre-sign gate (holding, decisions, races)...\n');
  const { Gate, factory, TxDigest } = freshLibs();

  // Test 1: interception HOLDS — original not called, evaluation payload posted.
  {
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    let calls = 0;
    const provider = { chainId: '0x1', async request() { calls += 1; return '0xhash'; } };
    assert.strictEqual(page.wrapProvider(provider, { source: 'window.ethereum' }), 'wrapped');
    const args = { method: 'eth_sendTransaction', params: [{ to: '0xto', from: '0xfrom', data: '0xdata', value: '0x1' }] };
    const pending = page.pendingIds();
    assert.deepStrictEqual(pending, []);
    const result = awaitSettled(provider.request(args));
    await new Promise((r) => setImmediate(r));
    assert.strictEqual(calls, 0, 'Original provider must NOT be called while held');
    assert.strictEqual(win.posted.length, 1, 'One INTERCEPTED must be posted');
    const posted = win.posted[0];
    assert.strictEqual(posted.type, 'INTERCEPTED');
    assert.strictEqual(posted.kind, 'tx');
    assert.deepStrictEqual(posted.tx, { to: '0xto', from: '0xfrom', data: '0xdata', value: '0x1' });
    assert.strictEqual(posted.complete, true);
    assert.strictEqual(posted.chainId, '0x1');
    assert.ok(Gate.LIMITS.REQUEST_ID_RE.test(posted.requestId), 'requestId must be a safe unique id');
    assert.strictEqual(page.pendingIds().length, 1, 'Request stays pending');
    // Bridge ACK keeps it held (evaluation runs in the worker).
    page.onPageMessage({ source: win, data: isoMsg({ type: 'ACK', requestId: posted.requestId }) });
    await new Promise((r) => setImmediate(r));
    assert.strictEqual(calls, 0, 'ACK must not release the request');
    assert.strictEqual(page.pendingIds().length, 1);
    // Continue releases exactly once with the verified snapshot (never the
    // mutable live args), after the approval digest is re-verified.
    let seenArgs = null;
    let seenCount = 0;
    const provider2 = { async request(a) { seenArgs = a; seenCount += 1; return '0xhash2'; } };
    const page2win = makeWindow();
    const page2 = factory.createGatePage({ window: page2win, gate: Gate });
    page2.wrapProvider(provider2, {});
    const args2 = { method: 'eth_sendTransaction', params: [{ to: '0xt' }] };
    const r2 = awaitSettled(provider2.request(args2));
    await new Promise((r) => setImmediate(r));
    const intercepted2 = page2win.posted[0];
    const id2 = intercepted2.requestId;
    assert.ok(TxDigest.isValidDigest(intercepted2.txDigest), 'INTERCEPTED must carry a valid snapshot digest');
    page2.onPageMessage({ source: win, data: isoMsg({ type: 'ACK', requestId: id2 }) }); // wrong source: dropped
    page2.onPageMessage({ source: page2win, data: isoMsg({ type: 'ACK', requestId: id2 }) });
    page2.onPageMessage({ source: page2win, data: isoMsg({ type: 'DECISION', requestId: id2, decision: 'continue', approvedDigest: intercepted2.txDigest }) });
    const out2 = await r2;
    assert.strictEqual(out2.status, 'resolved');
    assert.strictEqual(out2.value, '0xhash2', 'Original resolution must reach the dApp');
    assert.notStrictEqual(seenArgs, args2, 'Live args object must never be forwarded');
    assert.deepStrictEqual(seenArgs, { method: 'eth_sendTransaction', params: [{ to: '0xt' }] }, 'Verified snapshot must be forwarded');
    assert.ok(Object.isFrozen(seenArgs.params[0]), 'Forwarded snapshot must be frozen');
    assert.strictEqual(page2.pendingIds().length, 0, 'Released request must be forgotten');
    // Double decision: second DECISION is dropped, original called once.
    page2.onPageMessage({ source: page2win, data: isoMsg({ type: 'DECISION', requestId: id2, decision: 'continue', approvedDigest: intercepted2.txDigest }) });
    await new Promise((r) => setImmediate(r));
    assert.strictEqual(seenCount, 1, 'Double decision must not re-forward');
    void result;
    console.log('✔ Test 1 Passed: Holding + single release of the verified snapshot.');
  }

  // Test 2: cancellation never touches the wallet; 4001 reaches the dApp.
  {
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    let calls = 0;
    const provider = { async request() { calls += 1; return 'nope'; } };
    page.wrapProvider(provider, {});
    const r = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [{ to: '0xt' }] }));
    await new Promise((r2) => setImmediate(r2));
    const id = win.posted[0].requestId;
    page.onPageMessage({ source: win, data: isoMsg({ type: 'ACK', requestId: id }) });
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: id, decision: 'cancel' }) });
    const out = await r;
    assert.strictEqual(out.status, 'rejected');
    assert.strictEqual(out.error.code, 4001);
    assert.ok(/cancelled the request before wallet review/.test(out.error.message));
    assert.strictEqual(calls, 0, 'Cancelled request must never reach the wallet');
    console.log('✔ Test 2 Passed: Cancellation rejects locally with 4001.');
  }

  // Test 3: provider outcome semantics preserved (rejection, sync throw).
  {
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    const walletErr = new Error('wallet-rejected');
    const provider = { async request() { throw walletErr; } };
    page.wrapProvider(provider, {});
    const r = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [{ to: '0xt' }] }));
    await new Promise((r2) => setImmediate(r2));
    const id = win.posted[0].requestId;
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: id, decision: 'continue', approvedDigest: win.posted[0].txDigest }) });
    const out = await r;
    assert.strictEqual(out.status, 'rejected');
    assert.strictEqual(out.error, walletErr, 'Wallet rejection must propagate identically');
    // Synchronous provider throw.
    const syncErr = new Error('sync-boom');
    const provider2 = { request() { throw syncErr; } };
    const win2 = makeWindow();
    const page2 = factory.createGatePage({ window: win2, gate: Gate });
    page2.wrapProvider(provider2, {});
    const r2 = awaitSettled(provider2.request({ method: 'eth_sendTransaction', params: [{ to: '0xt' }] }));
    await new Promise((r3) => setImmediate(r3));
    page2.onPageMessage({ source: win2, data: isoMsg({ type: 'DECISION', requestId: win2.posted[0].requestId, decision: 'continue', approvedDigest: win2.posted[0].txDigest }) });
    const out2 = await r2;
    assert.strictEqual(out2.status, 'rejected');
    assert.strictEqual(out2.error, syncErr, 'Sync provider error must reject with the same error');
    console.log('✔ Test 3 Passed: Wallet outcomes propagate unchanged.');
  }

  // Test 4: readonly untouched; messages held as unsupported; malformed safe.
  {
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    let calls = 0;
    const provider = { async request() { calls += 1; return '0x1'; } };
    page.wrapProvider(provider, {});
    const ro = await provider.request({ method: 'eth_chainId', params: [] });
    assert.strictEqual(ro, '0x1');
    assert.strictEqual(win.posted.length, 0, 'Read-only calls must not be gated');
    const r = awaitSettled(provider.request({ method: 'personal_sign', params: ['0xmsg', '0xaddr'] }));
    await new Promise((r2) => setImmediate(r2));
    assert.strictEqual(calls, 1, 'Message signing must be held, not forwarded');
    assert.strictEqual(win.posted[0].kind, 'message');
    assert.ok(!('complete' in win.posted[0]) || win.posted[0].complete === false);
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: win.posted[0].requestId, decision: 'cancel' }) });
    const out = await r;
    assert.strictEqual(out.status, 'rejected');
    assert.strictEqual(out.error.code, 4001);
    assert.strictEqual(calls, 1, 'Cancelled message must never reach the wallet');
    // Malformed tx params: still held, nothing invented.
    const r2 = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [null] }));
    await new Promise((r3) => setImmediate(r3));
    const last = win.posted[win.posted.length - 1];
    assert.deepStrictEqual(last.tx, {});
    assert.strictEqual(last.complete, false);
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: last.requestId, decision: 'cancel' }) });
    await r2;
    // Double-wrap guard.
    assert.strictEqual(page.wrapProvider(provider, {}), 'already');
    assert.strictEqual(page.wrapProvider({}, {}), 'no-request');
    console.log('✔ Test 4 Passed: Readonly passthrough; messages + malformed held safely.');
  }

  // Test 5: forged/foreign page messages cannot release or confuse requests.
  {
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    let calls = 0;
    const provider = { async request() { calls += 1; return 'x'; } };
    page.wrapProvider(provider, {});
    const r = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [{ to: '0xt' }] }));
    await new Promise((r2) => setImmediate(r2));
    const id = win.posted[0].requestId;
    // Forged DECISION for unknown id.
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: 'forged-id-123', decision: 'continue' }) });
    // Wrong protocol / direction / source.
    page.onPageMessage({ source: win, data: { __assertara: 'evil', direction: 'iso-to-main', type: 'DECISION', requestId: id, decision: 'continue' } });
    page.onPageMessage({ source: win, data: { __assertara: 'gate-v1', direction: 'main-to-iso', type: 'DECISION', requestId: id, decision: 'continue' } });
    page.onPageMessage({ source: {}, data: isoMsg({ type: 'DECISION', requestId: id, decision: 'continue' }) });
    page.onPageMessage({ source: win, data: null });
    await new Promise((r2) => setImmediate(r2));
    assert.strictEqual(calls, 0, 'Forged decisions must not release the request');
    assert.strictEqual(page.pendingIds().length, 1);
    // Genuine decision still works afterwards.
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: id, decision: 'cancel' }) });
    const out = await r;
    assert.strictEqual(out.status, 'rejected');
    assert.strictEqual(out.error.code, 4001);
    console.log('✔ Test 5 Passed: Forged page messages are dropped.');
  }

  // Test 6: missing bridge fails open (forwards) and reports BYPASSED.
  {
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    let calls = 0;
    const provider = { async request() { calls += 1; return '0xopen'; } };
    page.wrapProvider(provider, {});
    const r = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [{ to: '0xt' }] }));
    await new Promise((r2) => setImmediate(r2));
    assert.strictEqual(calls, 0, 'Held until ACK retries exhaust');
    win.runTimers(10, 5000); // exhaust short ACK timers only; expiry stays armed
    const out = await r;
    assert.strictEqual(out.status, 'resolved');
    assert.strictEqual(out.value, '0xopen', 'Fail-open must preserve the dApp call');
    assert.strictEqual(calls, 1, 'Fail-open forwards exactly once');
    const types = win.posted.map((m) => m.type);
    assert.ok(types.includes('INTERCEPTED') && types.includes('BYPASSED'), 'Bypass must be reported honestly');
    assert.strictEqual(page.pendingIds().length, 0);
    assert.strictEqual(win.pendingTimers(), 0, 'Release must disarm the expiry timer');
    console.log('✔ Test 6 Passed: Missing bridge fails open with honest bypass report.');
  }

  // Test 7: HELLO/BRIDGE_READY handshake and provider lifecycle hooks.
  {
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    assert.strictEqual(page.isBridgeReady(), false);
    page.hello();
    assert.strictEqual(win.posted[0].type, 'HELLO');
    page.onPageMessage({ source: win, data: isoMsg({ type: 'BRIDGE_READY' }) });
    assert.strictEqual(page.isBridgeReady(), true);
    assert.deepStrictEqual(factory.classifyMethod('eth_signTypedData_v4'), 'message');
    assert.deepStrictEqual(factory.extractTx([{ to: '0xa' }]), { tx: { to: '0xa' }, complete: true });
    console.log('✔ Test 7 Passed: Handshake + helper surface intact.');
  }

  // Test 8: page-side decision timeout — held requests cannot hang forever.
  // Expiry rejects locally with 4001-expired, never forwards, and notifies
  // the worker to close the card. Normal decisions disarm the timer.
  {
    const win = makeWindow();
    const page = factory.createGatePage({ window: win, gate: Gate });
    let calls = 0;
    const provider = { async request() { calls += 1; return 'x'; } };
    page.wrapProvider(provider, {});
    const r = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [{ to: '0xt' }] }));
    await new Promise((r2) => setImmediate(r2));
    const id = win.posted[0].requestId;
    page.onPageMessage({ source: win, data: isoMsg({ type: 'ACK', requestId: id }) });
    assert.strictEqual(page.pendingIds().length, 1, 'Still held after ACK');
    assert.strictEqual(win.pendingTimers(), 1, 'Only the expiry timer remains');
    win.runTimers(5); // fire the decision-timeout timer
    const out = await r;
    assert.strictEqual(out.status, 'rejected');
    assert.strictEqual(out.error.code, 4001);
    assert.ok(/expired/.test(out.error.message), 'Expiry rejection must say expired');
    assert.strictEqual(calls, 0, 'Expired request must never reach the wallet');
    assert.strictEqual(page.pendingIds().length, 0);
    const expired = win.posted.find((m) => m.type === 'GATE_EXPIRED');
    assert.ok(expired && expired.requestId === id, 'Expiry must notify the worker with the exact id');
    // A late DECISION after expiry is dropped, not forwarded.
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: id, decision: 'continue' }) });
    await new Promise((r2) => setImmediate(r2));
    assert.strictEqual(calls, 0, 'Late continue after expiry must not forward');
    // A normal decision disarms the expiry timer.
    const r2 = awaitSettled(provider.request({ method: 'eth_sendTransaction', params: [{ to: '0xt' }] }));
    await new Promise((r3) => setImmediate(r3));
    const id2 = win.posted[win.posted.length - 1].requestId;
    page.onPageMessage({ source: win, data: isoMsg({ type: 'DECISION', requestId: id2, decision: 'cancel' }) });
    await r2;
    assert.strictEqual(win.pendingTimers(), 0, 'Decided requests must disarm the expiry timer');
    console.log('✔ Test 8 Passed: Decision timeout rejects locally, never forwards.');
  }

  console.log('\nAll Pre-sign Gate Page Tests Passed Successfully!\n');
}

if (require.main === module) {
  runProviderTests().catch((e) => { console.error(e); process.exit(1); });
}

module.exports = { runProviderTests };
