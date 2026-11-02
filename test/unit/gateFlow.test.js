const assert = require('assert');
const path = require('path');
const TxDigest = require('../../extension/shared/txDigest.js');

// End-to-end flow tests through the REAL service worker with stubbed
// browser APIs and backend. These prove automatic investigation
// initiation, request/assessment correlation, verdict handling, and
// decision gating of the worker's own logic — NOT a live browser run.

const EXT_DIR = path.resolve(__dirname, '../../extension');

function loadWorker(harness) {
  delete require.cache[require.resolve('../../extension/shared/gate.js')];
  delete require.cache[require.resolve('../../extension/shared/format.js')];
  delete require.cache[require.resolve('../../extension/service-worker.js')];
  globalThis.chrome = harness.chrome;
  globalThis.fetch = harness.fetch;
  globalThis.importScripts = (...files) => {
    for (const f of files) require(path.join(EXT_DIR, f));
  };
  require('../../extension/service-worker.js');
  delete globalThis.importScripts;
}

function makeHarness() {
  const tabMessages = []; // { tabId, message }
  const badgeText = [];
  const badgeColor = [];
  const fetchCalls = []; // { url, options, resolve, reject }
  const listeners = {};
  const h = {
    tabMessages, badgeText, badgeColor, fetchCalls, listeners,
    chrome: {
      runtime: {
        id: 'test-extension-id',
        onMessage: { addListener(fn) { listeners.runtime = fn; } }
      },
      tabs: {
        async sendMessage(tabId, message) { tabMessages.push({ tabId, message }); return { ok: true }; },
        async get(tabId) { return { id: tabId, windowId: 1, url: 'https://dapp.example/swap' }; },
        async captureVisibleTab() { throw new Error('no capture grant'); },
        onRemoved: { addListener(fn) { listeners.removed = fn; } },
        onUpdated: { addListener(fn) { listeners.updated = fn; } }
      },
      action: {
        async setBadgeText({ tabId, text }) { badgeText.push({ tabId, text }); },
        async setBadgeBackgroundColor({ tabId, color }) { badgeColor.push({ tabId, color }); }
      }
    },
    fetch: async (url, options) => new Promise((resolve, reject) => {
      fetchCalls.push({ url, options, resolve, reject });
    }),
    emit(message, sender) {
      return new Promise((resolve) => {
        listeners.runtime(message, sender || { tab: { id: 7, url: 'https://dapp.example/swap' } }, resolve);
      });
    },
    flush: async (n) => {
      for (let i = 0; i < (n || 8); i += 1) await new Promise((r) => setImmediate(r));
    },
    resolveFetch(index, status, bodyObj) {
      const call = fetchCalls[index];
      assert.ok(call, `fetch call ${index} must exist`);
      call.resolve({ ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(bodyObj) });
    },
    // Resolve a backend evaluation with a bundle bound to the exact
    // transaction the worker posted (mirrors the real backend digest).
    resolveEval(index, verdict, extra) {
      const call = fetchCalls[index];
      assert.ok(call, `fetch call ${index} must exist`);
      const sent = JSON.parse(call.options.body).transaction;
      const evaluatedTxDigest = TxDigest.digestTx(sent);
      assert.ok(TxDigest.isValidDigest(evaluatedTxDigest), 'posted transaction must be digestible');
      this.resolveFetch(index, 200, bundle(verdict, {
        txBinding: { receivedTxDigest: evaluatedTxDigest, evaluatedTxDigest, match: true },
        ...(extra || {})
      }));
    },
    rejectFetch(index, err) {
      fetchCalls[index].reject(err);
    },
    updatesFor(tabId, requestId) {
      return tabMessages
        .filter((m) => m.tabId === tabId && m.message.type === 'ASSERTARA_GATE_UPDATE'
          && (!requestId || m.message.view.requestId === requestId))
        .map((m) => m.message.view);
    },
    decisionsFor(tabId, requestId) {
      return tabMessages
        .filter((m) => m.tabId === tabId && m.message.type === 'ASSERTARA_GATE_DECISION'
          && (!requestId || m.message.requestId === requestId))
        .map((m) => m.message);
    }
  };
  return h;
}

function gatedRequest(id, overrides) {
  const msg = {
    type: 'ASSERTARA_GATED_REQUEST',
    requestId: id,
    method: 'eth_sendTransaction',
    kind: 'tx',
    tx: { to: '0xRouter', from: '0xUser', data: '0x1234', value: '0x1' },
    chainId: '0x1',
    wallet: { source: 'window.ethereum' },
    pageContext: { url: 'https://dapp.example/swap', title: 'Swap', visibleText: 'Swap 1 ETH' },
    ...(overrides || {})
  };
  // Page-claimed digest over the exact posted tx (as the page observer sends).
  msg.txDigest = TxDigest.digestTx(msg.tx || {});
  return msg;
}

function bundle(verdict, extra) {
  return {
    verdict,
    summary: `${verdict} summary`,
    confidence: verdict === 'MATCH' ? 0.9 : 0.5,
    decodedTransaction: { contract: '0xRouter', functionName: 'swap', isUnlimitedApproval: false },
    ruleFindings: [],
    ...(extra || {})
  };
}

async function runGateFlowTests() {
  console.log('Testing Assertara worker gate flow (auto-investigate, correlate, gate)...\n');
  const h = makeHarness();
  loadWorker(h);
  const sender7 = { tab: { id: 7, url: 'https://dapp.example/swap' } };

  // Test 1: interception auto-starts investigation; MATCH view correlates.
  {
    const before = h.fetchCalls.length;
    const res = await h.emit(gatedRequest('flow-match-1'), sender7);
    assert.deepStrictEqual(res, { ok: true });
    await h.flush();
    assert.strictEqual(h.fetchCalls.length, before + 1, 'Exactly one backend call must start automatically');
    const call = h.fetchCalls[before];
    assert.strictEqual(call.url, 'http://localhost:3001/api/v1/evaluate');
    const payload = JSON.parse(call.options.body);
    assert.strictEqual(payload.transaction.to, '0xRouter', 'Observed tx must reach the backend');
    assert.strictEqual(payload.pageContext.title, 'Swap');
    assert.ok(!('screenshot' in payload), 'No capture grant means no screenshot field');
    assert.ok(TxDigest.isValidDigest(payload.txDigest), 'Backend payload must carry the intercept digest');
    assert.strictEqual(payload.txDigest, TxDigest.digestTx(payload.transaction), 'Posted digest must match posted tx');
    const loading = h.updatesFor(7, 'flow-match-1');
    assert.strictEqual(loading.length, 1, 'Loading card view must push immediately');
    assert.strictEqual(loading[0].status, 'EVALUATING');
    assert.strictEqual(loading[0].assessment, null);
    assert.strictEqual(h.decisionsFor(7, 'flow-match-1').length, 0, 'Nothing forwarded while evaluating');
    h.resolveEval(before, 'MATCH');
    await h.flush();
    const views = h.updatesFor(7, 'flow-match-1');
    assert.strictEqual(views.length, 2, 'Assessment view must follow automatically');
    assert.strictEqual(views[1].status, 'AWAITING_USER_DECISION');
    assert.strictEqual(views[1].assessment.evidence.verdict, 'MATCH');
    assert.strictEqual(views[1].assessment.screenshotIncluded, false);
    assert.strictEqual(h.decisionsFor(7, 'flow-match-1').length, 0, 'MATCH must not auto-forward');
    const decide = await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-match-1', decision: 'continue' }, sender7);
    assert.deepStrictEqual(decide, { ok: true, decision: 'continue' });
    await h.flush();
    const pushed = h.decisionsFor(7, 'flow-match-1');
    assert.strictEqual(pushed.length, 1, 'Continue must release exactly once');
    assert.strictEqual(pushed[0].decision, 'continue');
    console.log('✔ Test 1 Passed: Auto-investigate, correlate, hold-until-decided.');
  }

  // Test 2: MISMATCH and UNCERTAIN flow verbatim; MISMATCH badge is red.
  {
    await h.emit(gatedRequest('flow-mismatch-1'), sender7);
    await h.flush();
    h.resolveEval(h.fetchCalls.length - 1, 'MISMATCH');
    await h.flush();
    const views = h.updatesFor(7, 'flow-mismatch-1');
    assert.strictEqual(views[views.length - 1].assessment.evidence.verdict, 'MISMATCH');
    assert.ok(h.badgeColor.some((b) => b.tabId === 7 && b.color === '#b91c1c'), 'MISMATCH must raise the red badge');
    assert.strictEqual(h.decisionsFor(7, 'flow-mismatch-1').length, 0, 'MISMATCH must not auto-cancel');
    await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-mismatch-1', decision: 'cancel' }, sender7);
    await h.flush();
    assert.strictEqual(h.decisionsFor(7, 'flow-mismatch-1')[0].decision, 'cancel');
    await h.emit(gatedRequest('flow-uncertain-1'), sender7);
    await h.flush();
    h.resolveEval(h.fetchCalls.length - 1, 'UNCERTAIN');
    await h.flush();
    const uviews = h.updatesFor(7, 'flow-uncertain-1');
    assert.strictEqual(uviews[uviews.length - 1].assessment.evidence.verdict, 'UNCERTAIN');
    console.log('✔ Test 2 Passed: MISMATCH/UNCERTAIN verbatim, no auto-decisions.');
  }

  // Test 3: cancel mid-evaluation; late backend result dropped as stale.
  {
    await h.emit(gatedRequest('flow-cancel-1'), sender7);
    await h.flush();
    const idx = h.fetchCalls.length - 1;
    const decide = await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-cancel-1', decision: 'cancel' }, sender7);
    assert.deepStrictEqual(decide, { ok: true, decision: 'cancel' });
    await h.flush();
    assert.strictEqual(h.decisionsFor(7, 'flow-cancel-1').length, 1);
    const viewsBefore = h.updatesFor(7, 'flow-cancel-1').length;
    h.resolveEval(idx, 'MATCH');
    await h.flush();
    assert.strictEqual(h.updatesFor(7, 'flow-cancel-1').length, viewsBefore, 'Late result for cancelled record must be dropped');
    assert.deepStrictEqual(
      await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-cancel-1', decision: 'continue' }, sender7),
      { ok: false, error: 'Decision rejected: already-decided.' }, 'Post-cancel continue must be rejected'
    );
    console.log('✔ Test 3 Passed: Mid-evaluation cancel wins; stale result dropped.');
  }

  // Test 4: backend failures stay held; continue is explicitly unverified.
  {
    await h.emit(gatedRequest('flow-fail-1'), sender7);
    await h.flush();
    h.rejectFetch(h.fetchCalls.length - 1, new TypeError('fetch failed'));
    await h.flush();
    const views = h.updatesFor(7, 'flow-fail-1');
    const last = views[views.length - 1];
    assert.strictEqual(last.status, 'EVALUATION_FAILED');
    assert.strictEqual(last.assessment.ok, false);
    assert.ok(/Cannot reach the backend/.test(last.assessment.error));
    assert.strictEqual(h.decisionsFor(7, 'flow-fail-1').length, 0, 'Backend-down must not auto-forward');
    const decide = await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-fail-1', decision: 'continue' }, sender7);
    assert.deepStrictEqual(decide, { ok: true, decision: 'continue' }, 'Explicit unverified continue must work');
    // Invalid bundle (200 without verdict) is a failure, not a verdict.
    await h.emit(gatedRequest('flow-fail-2'), sender7);
    await h.flush();
    h.resolveFetch(h.fetchCalls.length - 1, 200, { summary: 'no verdict here' });
    await h.flush();
    const v2 = h.updatesFor(7, 'flow-fail-2');
    assert.strictEqual(v2[v2.length - 1].status, 'EVALUATION_FAILED');
    assert.strictEqual(h.decisionsFor(7, 'flow-fail-2').length, 0);
    // HTTP 500 surfaces the backend message honestly.
    await h.emit(gatedRequest('flow-fail-3'), sender7);
    await h.flush();
    h.resolveFetch(h.fetchCalls.length - 1, 500, { error: 'boom' });
    await h.flush();
    const v3 = h.updatesFor(7, 'flow-fail-3');
    assert.ok(/boom/.test(v3[v3.length - 1].assessment.error));
    console.log('✔ Test 4 Passed: Failures held honestly; explicit unverified continue.');
  }

  // Test 5: message + missing-to requests held as unassessed; no backend call.
  {
    const before = h.fetchCalls.length;
    await h.emit(gatedRequest('flow-msg-1', { kind: 'message', method: 'personal_sign', tx: {} }), sender7);
    await h.flush();
    assert.strictEqual(h.fetchCalls.length, before, 'Message signing must not hit the tx backend');
    const views = h.updatesFor(7, 'flow-msg-1');
    assert.strictEqual(views[views.length - 1].status, 'UNSUPPORTED');
    assert.strictEqual(views[views.length - 1].assessment.unsupported, true);
    await h.emit(gatedRequest('flow-noto-1', { tx: { from: '0xUser' } }), sender7);
    await h.flush();
    assert.strictEqual(h.fetchCalls.length, before, 'Missing-to must not hit the backend');
    const v2 = h.updatesFor(7, 'flow-noto-1');
    assert.strictEqual(v2[v2.length - 1].status, 'EVALUATION_FAILED');
    assert.strictEqual(h.decisionsFor(7, 'flow-msg-1').length + h.decisionsFor(7, 'flow-noto-1').length, 0);
    console.log('✔ Test 5 Passed: Unsupported/incomplete held without backend verdicts.');
  }

  // Test 6: duplicates, forged, malformed, and out-of-order traffic safe.
  {
    const before = h.fetchCalls.length;
    await h.emit(gatedRequest('flow-dup-1'), sender7);
    await h.flush();
    const dup = await h.emit(gatedRequest('flow-dup-1'), sender7);
    assert.deepStrictEqual(dup, { ok: true, duplicate: true });
    assert.strictEqual(h.fetchCalls.length, before + 1, 'Duplicate delivery must not re-evaluate');
    h.resolveEval(before, 'MATCH');
    await h.flush();
    assert.deepStrictEqual(
      await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'no-such-id', decision: 'continue' }, sender7),
      { ok: false, error: 'Decision rejected: unknown-request.' }
    );
    assert.deepStrictEqual(
      await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-dup-1', decision: 'maybe' }, sender7),
      { ok: false, error: 'Decision rejected: bad-decision.' }
    );
    assert.deepStrictEqual(
      await h.emit(gatedRequest('flow-dup-2'), sender7).then(() => h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-dup-2', decision: 'continue' }, sender7)),
      { ok: false, error: 'Decision rejected: not-awaiting-decision.' }, 'Continue during evaluation must be rejected'
    );
    const bad = await h.emit({ type: 'ASSERTARA_GATED_REQUEST', requestId: 'x', method: 'eth_sendTransaction' }, sender7);
    assert.strictEqual(bad.ok, false, 'Malformed gated request must be rejected');
    const unknown = await h.emit({ type: 'ASSERTARA_NOPE' }, sender7);
    assert.strictEqual(unknown.ok, false);
    console.log('✔ Test 6 Passed: Duplicates collapse; forged/malformed rejected.');
  }

  // Test 7: simultaneous requests isolated per id and per tab.
  {
    const sender9 = { tab: { id: 9, url: 'https://other.example/' } };
    await h.emit(gatedRequest('flow-iso-a'), sender7);
    await h.emit(gatedRequest('flow-iso-b'), sender9);
    await h.flush();
    const aIdx = h.fetchCalls.length - 2;
    h.resolveEval(aIdx + 1, 'MISMATCH'); // resolve B first (out of order)
    await h.flush();
    assert.strictEqual(h.updatesFor(9, 'flow-iso-b')[1].assessment.evidence.verdict, 'MISMATCH');
    assert.strictEqual(h.updatesFor(7, 'flow-iso-a').length, 1, 'A must still be evaluating');
    h.resolveEval(aIdx, 'MATCH');
    await h.flush();
    assert.strictEqual(h.updatesFor(7, 'flow-iso-a')[1].assessment.evidence.verdict, 'MATCH');
    await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-iso-a', decision: 'continue' }, sender7);
    await h.flush();
    assert.strictEqual(h.decisionsFor(7, 'flow-iso-a').length, 1);
    assert.strictEqual(h.decisionsFor(9, 'flow-iso-b').length, 0, 'Deciding A must not release B');
    console.log('✔ Test 7 Passed: Concurrent requests never cross results.');
  }

  // Test 8: navigation invalidates; expiry notice closes the card.
  {
    await h.emit(gatedRequest('flow-nav-1'), sender7);
    await h.flush();
    const idx = h.fetchCalls.length - 1;
    h.listeners.updated(7, { status: 'loading' });
    await h.flush();
    h.resolveEval(idx, 'MATCH');
    await h.flush();
    const views = h.updatesFor(7, 'flow-nav-1');
    assert.ok(views.every((v) => v.status !== 'AWAITING_USER_DECISION'), 'Post-navigation result must never surface');
    const state = await h.emit({ type: 'ASSERTARA_GET_TAB_STATE', tabId: 7 }, sender7);
    assert.strictEqual(state.state.pending.find((v) => v.requestId === 'flow-nav-1').status, 'EXPIRED');
    await h.emit(gatedRequest('flow-exp-1'), sender7);
    await h.flush();
    const exp = await h.emit({ type: 'ASSERTARA_GATE_EXPIRED', requestId: 'flow-exp-1' }, sender7);
    assert.deepStrictEqual(exp, { ok: true });
    await h.flush();
    const closed = h.updatesFor(7, 'flow-exp-1');
    assert.strictEqual(closed[closed.length - 1].closed, true, 'Expiry must close the card');
    assert.strictEqual(closed[closed.length - 1].status, 'EXPIRED');
    assert.strictEqual(h.decisionsFor(7, 'flow-exp-1').filter((d) => d.decision === 'continue').length, 0, 'Expiry must never forward');
    console.log('✔ Test 8 Passed: Navigation + expiry invalidate without forwarding.');
  }

  // Test 9: forged page digest fails closed before any evaluation.
  {
    const h = makeHarness();
    loadWorker(h);
    const sender7 = { tab: { id: 7 } };
    const good = gatedRequest('flow-forge-1');
    const forged = { ...good, txDigest: 'ff'.repeat(32) };
    assert.notStrictEqual(forged.txDigest, good.txDigest, 'Harness must actually forge a mismatching digest');
    await h.emit(forged, sender7);
    await h.flush();
    assert.strictEqual(h.fetchCalls.length, 0, 'Unverifiable payload must never reach the backend');
    const views = h.updatesFor(7, 'flow-forge-1');
    assert.strictEqual(views[views.length - 1].status, 'EVALUATION_FAILED');
    assert.ok(/integrity check failed/.test(views[views.length - 1].assessment.error), 'Failure must name integrity');
    // Backend disagreement fails closed the same way.
    await h.emit(gatedRequest('flow-forge-2'), sender7);
    await h.flush();
    const idx = h.fetchCalls.length - 1;
    h.resolveFetch(idx, 200, bundle('MATCH', { txBinding: { receivedTxDigest: 'ee'.repeat(32), evaluatedTxDigest: 'ee'.repeat(32), match: false } }));
    await h.flush();
    const views2 = h.updatesFor(7, 'flow-forge-2');
    assert.strictEqual(views2[views2.length - 1].status, 'EVALUATION_FAILED');
    console.log('✔ Test 9 Passed: Digest disagreement fails closed.');
  }

  // Test 10: mutation report closes the record; approval carries the digest.
  {
    const h = makeHarness();
    loadWorker(h);
    const sender7 = { tab: { id: 7 } };
    await h.emit(gatedRequest('flow-mut-1'), sender7);
    await h.flush();
    h.resolveEval(h.fetchCalls.length - 1, 'MATCH');
    await h.flush();
    const mut = await h.emit({ type: 'ASSERTARA_TX_MUTATED', requestId: 'flow-mut-1' }, sender7);
    assert.deepStrictEqual(mut, { ok: true });
    await h.flush();
    const views = h.updatesFor(7, 'flow-mut-1');
    assert.strictEqual(views[views.length - 1].closed, true, 'Mutation must close the card');
    assert.strictEqual(views[views.length - 1].status, 'EXPIRED');
    const tabState = await h.emit({ type: 'ASSERTARA_GET_TAB_STATE', tabId: 7 }, sender7);
    assert.ok(tabState.state.notes.some((n) => /changed after evaluation/.test(n.text)), 'Mutation note must explain the cause');
    assert.strictEqual(h.decisionsFor(7, 'flow-mut-1').filter((d) => d.decision === 'continue').length, 0, 'Mutated record must never forward');
    // Unknown-id mutation reports are ignored, never crash.
    assert.deepStrictEqual(await h.emit({ type: 'ASSERTARA_TX_MUTATED', requestId: 'no-such' }, sender7), { ok: true });

    await h.emit(gatedRequest('flow-appr-1'), sender7);
    await h.flush();
    h.resolveEval(h.fetchCalls.length - 1, 'MATCH');
    await h.flush();
    await h.emit({ type: 'ASSERTARA_DECIDE', requestId: 'flow-appr-1', decision: 'continue' }, sender7);
    await h.flush();
    const raw = h.decisionsFor(7, 'flow-appr-1')[0];
    const posted = JSON.parse(h.fetchCalls[h.fetchCalls.length - 1].options.body);
    assert.strictEqual(raw.decision, 'continue');
    assert.strictEqual(raw.approvedDigest, posted.txDigest, 'Approval must carry the evaluated digest');
    assert.strictEqual(raw.approvedDigest, TxDigest.digestTx(posted.transaction), 'Approved digest must match evaluated bytes');
    console.log('✔ Test 10 Passed: Mutation closes honestly; approvals carry digests.');
  }

  console.log('\nAll Worker Gate Flow Tests Passed Successfully!\n');
}

if (require.main === module) {
  runGateFlowTests().catch((e) => { console.error(e); process.exit(1); });
}

module.exports = { runGateFlowTests };
