const assert = require('assert');

// Unit tests for the shared gate protocol validation and the race-safe
// pending-request state machine used by the service worker. Deterministic;
// time is injected. These prove store/validation logic, not a live wallet.

function freshGate() {
  delete require.cache[require.resolve('../../extension/shared/gate.js')];
  require('../../extension/shared/gate.js');
  return globalThis.AssertaraGate;
}

function intercepted(id, overrides) {
  return {
    __assertara: 'gate-v1',
    direction: 'main-to-iso',
    type: 'INTERCEPTED',
    requestId: id,
    method: 'eth_sendTransaction',
    kind: 'tx',
    tx: { to: '0xto', from: '0xfrom', data: '0xdata', value: '0x1' },
    chainId: '0x1',
    wallet: { source: 'window.ethereum' },
    pageContext: { url: 'https://dapp.example/', title: 'D', visibleText: 'Swap' },
    ...(overrides || {})
  };
}

function runGateTests() {
  console.log('Testing Assertara gate protocol + state machine...\n');
  const Gate = freshGate();

  // Test 1: MAIN->ISO validation — allowlist + bounds, nothing else.
  {
    const good = Gate.validateMainMessage(intercepted('abc-123_XY'));
    assert.strictEqual(good.type, 'INTERCEPTED');
    assert.strictEqual(good.requestId, 'abc-123_XY');
    assert.deepStrictEqual(good.tx, { to: '0xto', from: '0xfrom', data: '0xdata', value: '0x1' });
    assert.deepStrictEqual(Gate.validateMainMessage({ __assertara: 'gate-v1', direction: 'main-to-iso', type: 'HELLO' }), { type: 'HELLO' });
    const bypassed = Gate.validateMainMessage({ __assertara: 'gate-v1', direction: 'main-to-iso', type: 'BYPASSED', requestId: 'r1', method: 'eth_sendTransaction' });
    assert.deepStrictEqual(bypassed, { type: 'BYPASSED', requestId: 'r1', method: 'eth_sendTransaction' });
    const expired = Gate.validateMainMessage({ __assertara: 'gate-v1', direction: 'main-to-iso', type: 'GATE_EXPIRED', requestId: 'r1' });
    assert.deepStrictEqual(expired, { type: 'GATE_EXPIRED', requestId: 'r1' });
    assert.strictEqual(Gate.validateMainMessage({ __assertara: 'gate-v1', direction: 'main-to-iso', type: 'GATE_EXPIRED' }), null, 'Expiry without id must be dropped');
    for (const bad of [
      null, undefined, 'x', {},
      { __assertara: 'gate-v1', direction: 'iso-to-main', type: 'HELLO' },
      intercepted('bad id!!'),
      intercepted('r1', { method: 'x'.repeat(65) }),
      intercepted('r1', { kind: 'evil' }),
      intercepted('r1', { type: 'DECISION' }),
      { __assertara: 'gate-v1', direction: 'main-to-iso', type: 'BYPASSED', requestId: 'r1' }
    ]) {
      assert.strictEqual(Gate.validateMainMessage(bad), null, `Must reject: ${JSON.stringify(bad)}`);
    }
    // Oversized fields are contained, not passed through.
    const big = Gate.validateMainMessage(intercepted('r1', { tx: { to: '0x' + 'a'.repeat(70000) } }));
    assert.deepStrictEqual(big.tx, {}, 'Oversized tx fields must be dropped');
    const bigText = Gate.validateMainMessage(intercepted('r1', { pageContext: { url: 'u', title: 't', visibleText: 'z'.repeat(9000) } }));
    assert.strictEqual(bigText.pageContext.visibleText, '', 'Oversized text must be contained');
    console.log('✔ Test 1 Passed: Page-message validation is strict.');
  }

  // Test 2: ISO->MAIN validation — only READY/ACK/well-formed DECISION.
  {
    const iso = (d) => ({ __assertara: 'gate-v1', direction: 'iso-to-main', ...d });
    assert.deepStrictEqual(Gate.validateIsoMessage(iso({ type: 'BRIDGE_READY' })), { type: 'BRIDGE_READY' });
    assert.deepStrictEqual(Gate.validateIsoMessage(iso({ type: 'ACK', requestId: 'r1' })), { type: 'ACK', requestId: 'r1' });
    assert.deepStrictEqual(
      Gate.validateIsoMessage(iso({ type: 'DECISION', requestId: 'r1', decision: 'continue', reason: 'x' })),
      { type: 'DECISION', requestId: 'r1', decision: 'continue', reason: 'x', approvedDigest: null }
    );
    for (const bad of [
      null, {},
      iso({ type: 'DECISION', requestId: 'r1', decision: 'maybe' }),
      iso({ type: 'DECISION', requestId: 'r1' }),
      iso({ type: 'ACK' }),
      iso({ type: 'INTERCEPTED', requestId: 'r1' }),
      { __assertara: 'gate-v1', direction: 'main-to-iso', type: 'ACK', requestId: 'r1' },
      { direction: 'iso-to-main', type: 'ACK', requestId: 'r1' }
    ]) {
      assert.strictEqual(Gate.validateIsoMessage(bad), null, `Must reject: ${JSON.stringify(bad)}`);
    }
    const cancel = Gate.cancellationError('cancelled');
    const expired = Gate.cancellationError('expired');
    assert.strictEqual(cancel.code, 4001);
    assert.strictEqual(expired.code, 4001);
    assert.ok(/cancelled the request before wallet review/.test(cancel.message));
    assert.ok(/expired/.test(expired.message));
    assert.ok(Gate.LIMITS.REQUEST_ID_RE.test(Gate.makeRequestId()));
    assert.deepStrictEqual(Gate.TX_METHODS, ['eth_sendTransaction', 'eth_signTransaction']);
    assert.ok(Gate.MSG_METHODS.includes('personal_sign') && Gate.MSG_METHODS.includes('eth_signTypedData_v4'));
    console.log('✔ Test 2 Passed: Bridge-message validation + cancellation errors.');
  }

  // Test 3: register — duplicates collapse, per-tab cap bounds memory.
  {
    const store = Gate.createGateStore({ now: () => 1000, maxPerTab: 2 });
    const first = store.register(Gate.validateMainMessage(intercepted('r1')), 7, 'https://dapp.example/');
    assert.strictEqual(first.duplicate, false);
    assert.strictEqual(first.record.status, 'DETECTED');
    const dup = store.register(Gate.validateMainMessage(intercepted('r1')), 7, 'https://dapp.example/');
    assert.strictEqual(dup.duplicate, true, 'Duplicate delivery must not re-register');
    assert.strictEqual(dup.record, first.record);
    store.register(Gate.validateMainMessage(intercepted('r2')), 7, 'https://dapp.example/');
    const full = store.register(Gate.validateMainMessage(intercepted('r3')), 7, 'https://dapp.example/');
    assert.strictEqual(full.rejected, 'tab-full', 'Per-tab pending cap must hold');
    assert.strictEqual(full.record, null);
    const otherTab = store.register(Gate.validateMainMessage(intercepted('r3')), 8, 'https://other.example/');
    assert.strictEqual(otherTab.rejected, undefined, 'Cap is per-tab, not global');
    assert.strictEqual(store.pendingCount(7), 2);
    console.log('✔ Test 3 Passed: Registration dedups and bounds per-tab state.');
  }

  // Test 4: decide — cancel anytime pre-terminal; continue only when
  // awaiting; first valid decision wins; nothing else releases.
  {
    const store = Gate.createGateStore({ now: () => 1000 });
    store.register(Gate.validateMainMessage(intercepted('r1')), 7, '');
    assert.deepStrictEqual(store.decide('r1', 'continue'), { accepted: false, reason: 'not-awaiting-decision' }, 'Cannot continue before assessment');
    assert.deepStrictEqual(store.decide('nope', 'cancel'), { accepted: false, reason: 'unknown-request' });
    const rec = store.get('r1');
    store.setStatus(rec, 'EVALUATING');
    assert.deepStrictEqual(store.decide('r1', 'continue'), { accepted: false, reason: 'not-awaiting-decision' }, 'Cannot continue while evaluating');
    // Cancel mid-evaluation is safe (never forwards): accepted, and the
    // late backend result must then be dropped as stale.
    assert.deepStrictEqual(store.decide('r1', 'cancel'), { accepted: true }, 'Cancel while evaluating must be accepted');
    assert.strictEqual(store.get('r1').status, 'USER_CANCELLED');
    assert.strictEqual(store.applyAssessment('r1', { ok: true }), false, 'Late result for cancelled record must be dropped');
    assert.deepStrictEqual(store.decide('r1', 'continue'), { accepted: false, reason: 'already-decided' }, 'Cancel+continue race: first wins');
    store.register(Gate.validateMainMessage(intercepted('r1b')), 7, '');
    store.setStatus(store.get('r1b'), 'AWAITING_USER_DECISION');
    assert.deepStrictEqual(store.decide('r1b', 'maybe'), { accepted: false, reason: 'bad-decision' });
    assert.deepStrictEqual(store.decide('r1b', 'continue'), { accepted: true });
    assert.strictEqual(store.get('r1b').status, 'FORWARDED_TO_WALLET');
    assert.deepStrictEqual(store.decide('r1b', 'cancel'), { accepted: false, reason: 'already-decided' }, 'Continue+cancel race: first wins');
    // Failed/unsupported assessments are still explicitly decidable.
    store.register(Gate.validateMainMessage(intercepted('r2')), 7, '');
    store.setStatus(store.get('r2'), 'EVALUATION_FAILED');
    assert.deepStrictEqual(store.decide('r2', 'cancel'), { accepted: true });
    assert.strictEqual(store.get('r2').status, 'USER_CANCELLED');
    store.register(Gate.validateMainMessage(intercepted('r3', { kind: 'message', method: 'personal_sign' })), 7, '');
    store.setStatus(store.get('r3'), 'UNSUPPORTED');
    assert.deepStrictEqual(store.decide('r3', 'continue'), { accepted: true });
    console.log('✔ Test 4 Passed: Cancel anytime; continue when awaiting; first wins.');
  }

  // Test 5: stale results dropped; expiry + navigation invalidate; prune bounds.
  {
    let t = 1000;
    const store = Gate.createGateStore({ now: () => t, decisionTimeoutMs: 60000 });
    store.register(Gate.validateMainMessage(intercepted('r1')), 7, '');
    store.setStatus(store.get('r1'), 'EVALUATING');
    assert.strictEqual(store.applyAssessment('r1', { ok: true, evidence: { verdict: 'MATCH' } }), true);
    assert.strictEqual(store.get('r1').status, 'AWAITING_USER_DECISION');
    assert.strictEqual(store.applyAssessment('r1', { ok: true, evidence: { verdict: 'MISMATCH' } }), false, 'Second result must not overwrite');
    store.register(Gate.validateMainMessage(intercepted('r2')), 7, '');
    store.setStatus(store.get('r2'), 'EVALUATING');
    store.invalidateTab(7); // navigation: page promises are dead
    assert.strictEqual(store.get('r1').status, 'EXPIRED');
    assert.strictEqual(store.applyAssessment('r2', { ok: true }), false, 'Late backend result after navigation must be dropped');
    // Expiry only touches awaiting states.
    store.register(Gate.validateMainMessage(intercepted('r3')), 9, '');
    store.setStatus(store.get('r3'), 'EVALUATING');
    store.register(Gate.validateMainMessage(intercepted('r4')), 9, '');
    store.setStatus(store.get('r4'), 'AWAITING_USER_DECISION');
    t += 61000;
    assert.deepStrictEqual(store.sweepExpired(), ['r4'], 'Only awaiting requests expire');
    assert.strictEqual(store.get('r3').status, 'EVALUATING', 'Evaluating requests never expire into forwarding');
    // Prune bounds terminal memory.
    t += 400000;
    assert.strictEqual(store.pruneTerminal(300000), 3, 'r1, r2, r4 pruned; r3 still live');
    assert.strictEqual(store.size(), 1);
    assert.strictEqual(store.tabRequests(9).length, 1);
    console.log('✔ Test 5 Passed: Stale/expiry/navigation/prune semantics exact.');
  }

  console.log('\nAll Gate Protocol + State Machine Tests Passed Successfully!\n');
}

if (require.main === module) {
  runGateTests();
}

module.exports = { runGateTests };
