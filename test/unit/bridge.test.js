const assert = require('assert');

// Tests for the isolated gate bridge: page-relay validation plus automatic
// on-page card presentation (loading -> assessment -> decision/close).
// A minimal fake DOM drives the REAL bridge.js. Deterministic only — this
// proves the bridge's own rendering/routing logic, NOT a live browser run.

function makeFakeDom() {
  const byId = new Map();
  function makeNode(tag) {
    const node = {
      tag, children: [], parent: null,
      className: '', text: '', disabled: false,
      handlers: {},
      set id(v) { this._id = v; if (v) byId.set(v, this); },
      get id() { return this._id; },
      set innerHTML(v) { if (v === '') { for (const c of this.children) c.parent = null; this.children = []; } },
      get innerHTML() { return ''; },
      set textContent(v) { this.text = String(v); },
      get textContent() {
        let out = this.text || '';
        for (const c of this.children) out += c.textContent;
        return out;
      },
      appendChild(c) { c.parent = this; this.children.push(c); return c; },
      prepend(c) { c.parent = this; this.children.unshift(c); return c; },
      remove() {
        if (this.parent) {
          const i = this.parent.children.indexOf(this);
          if (i !== -1) this.parent.children.splice(i, 1);
          this.parent = null;
        }
        if (this._id) byId.delete(this._id);
      },
      addEventListener(type, fn) { (this.handlers[type] = this.handlers[type] || []).push(fn); },
      querySelectorAll(sel) {
        const out = [];
        const walk = (n) => {
          for (const c of n.children) {
            if (sel === 'button' && c.tag === 'button') out.push(c);
            if (sel.startsWith('#') && c.id === sel.slice(1)) out.push(c);
            walk(c);
          }
        };
        walk(this);
        return out;
      },
      querySelector(sel) { return this.querySelectorAll(sel)[0] || null; },
      attachShadow() {
        const shadow = makeNode('#shadow');
        shadow.host = this;
        return shadow;
      },
      click() { for (const fn of this.handlers.click || []) fn(); },
      findButtons() { return this.querySelectorAll('button'); }
    };
    node._id = null;
    return node;
  }
  const documentElement = makeNode('html');
  const document = {
    getElementById: (id) => byId.get(id) || null,
    createElement: (tag) => makeNode(tag),
    documentElement
  };
  return { document, byId };
}

function loadBridge() {
  delete require.cache[require.resolve('../../extension/shared/gate.js')];
  delete require.cache[require.resolve('../../extension/shared/format.js')];
  delete require.cache[require.resolve('../../extension/content/bridge.js')];
  const { document, byId } = makeFakeDom();
  const posted = []; // bridge -> page
  const relayed = []; // bridge -> worker
  const listeners = {};
  const win = {
    postMessage(msg) { posted.push(msg); },
    addEventListener(type, fn) { listeners[type] = fn; }
  };
  let workerListener = null;
  globalThis.window = win;
  globalThis.document = document;
  globalThis.chrome = {
    runtime: {
      id: 'test-extension-id',
      onMessage: { addListener(fn) { workerListener = fn; } },
      sendMessage(msg) { relayed.push(msg); return Promise.resolve({ ok: true }); }
    }
  };
  require('../../extension/shared/gate.js');
  require('../../extension/shared/format.js');
  require('../../extension/content/bridge.js');
  return {
    win, document, byId, posted, relayed, listeners,
    workerMessage(message, senderId) {
      let responded = null;
      const ret = workerListener(message, { id: senderId || 'test-extension-id' }, (r) => { responded = r; });
      return { ret, responded };
    },
    pageMessage(data, source) {
      listeners.message({ source: source === undefined ? win : source, data });
    },
    shadow() {
      const host = document.getElementById('assertara-gate-host');
      return host ? host.__assertaraShadow || null : null;
    },
    cardText() {
      const shadow = this.shadow();
      return shadow ? shadow.textContent : null;
    },
    cleanup() { delete globalThis.window; delete globalThis.document; delete globalThis.chrome; }
  };
}

function mainMsg(data) {
  return { __assertara: 'gate-v1', direction: 'main-to-iso', ...data };
}

function intercepted(id, overrides) {
  return mainMsg({
    type: 'INTERCEPTED', requestId: id, method: 'eth_sendTransaction', kind: 'tx',
    tx: { to: '0xRouter', from: '0xUser', data: '0x1234', value: '0x1' },
    chainId: '0x1', wallet: { source: 'window.ethereum' },
    pageContext: { url: 'https://dapp.example/swap', title: 'Swap', visibleText: 'Swap 1 ETH' },
    ...(overrides || {})
  });
}

function view(id, overrides) {
  return {
    requestId: id, pageUrl: 'https://dapp.example/swap', method: 'eth_sendTransaction',
    kind: 'tx', wallet: { source: 'window.ethereum' }, chainId: '0x1',
    tx: { to: '0xRouter', from: '0xUser' }, status: 'EVALUATING', assessment: null,
    ...(overrides || {})
  };
}

function assessment(verdict) {
  return {
    ok: true,
    evidence: {
      verdict, summary: `${verdict} summary`, confidence: 0.9,
      reasoningOrigin: 'model',
      decodedTransaction: { contract: '0xRouter', contractName: 'SwapRouter', functionName: 'swap', isUnlimitedApproval: false },
      verdictSafeguards: [], confidenceCap: null, ruleFindings: [{ ruleId: 'r1', severity: 'info', description: 'note' }],
      visualEvidence: { ocrMode: 'regions', samDetections: [{}, {}], textSources: [{ source: 'DOM_TEXT', available: true }] },
      simulation: null, recommendedAction: 'review', safetyNotice: 'Advisory only.'
    },
    screenshotIncluded: false, visibleTextChars: 10
  };
}

function runBridgeTests() {
  console.log('Testing Assertara gate bridge (relay + auto card)...\n');

  // Test 1: page relay validates, ACKs, and forwards sanitized payloads.
  {
    const b = loadBridge();
    try {
      assert.strictEqual(b.cardText(), null, 'No card before any request');
      b.pageMessage({ __assertara: 'gate-v1', direction: 'main-to-iso', type: 'HELLO' });
      assert.deepStrictEqual(b.posted[0], { __assertara: 'gate-v1', direction: 'iso-to-main', type: 'BRIDGE_READY' });
      b.pageMessage(intercepted('card-relay-1'));
      const ack = b.posted.find((m) => m.type === 'ACK');
      assert.ok(ack && ack.requestId === 'card-relay-1', 'INTERCEPTED must be ACKed immediately');
      assert.strictEqual(b.relayed.length, 2, 'TAB_OBSERVED + GATED_REQUEST relayed');
      const relay = b.relayed[1];
      assert.strictEqual(relay.type, 'ASSERTARA_GATED_REQUEST');
      assert.strictEqual(relay.requestId, 'card-relay-1');
      assert.strictEqual(relay.tx.to, '0xRouter');
      // Forged / foreign / malformed page traffic is dropped.
      const n = b.relayed.length;
      b.pageMessage(intercepted('card-forged-1'), {}); // wrong source
      b.pageMessage({ direction: 'main-to-iso', type: 'INTERCEPTED', requestId: 'x' }); // no protocol
      b.pageMessage(intercepted('bad id!!')); // invalid id
      b.pageMessage(null);
      assert.strictEqual(b.relayed.length, n, 'Invalid page messages must be dropped');
      assert.ok(!b.posted.some((m) => m.requestId === 'card-forged-1'), 'Forged ids must never be ACKed');
      console.log('✔ Test 1 Passed: Relay validates, ACKs, forwards sanitized.');
    } finally {
      b.cleanup();
    }
  }

  // Test 2: loading card appears automatically on the evaluating view.
  {
    const b = loadBridge();
    try {
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-load-1') });
      const text = b.cardText();
      assert.ok(text, 'Card must render without any user click');
      assert.ok(text.includes('eth_sendTransaction'), 'Card must identify the request');
      assert.ok(text.includes('NOT been contacted'), 'Card must state the wallet is untouched');
      assert.ok(text.includes('Evaluating with the local backend'), 'Loading state must show');
      assert.ok(text.includes('0xRouter') || text.includes('to:'), 'Card must show tx details');
      const buttons = b.shadow().findButtons();
      assert.strictEqual(buttons.length, 2);
      assert.strictEqual(buttons[0].disabled, true, 'Continue must be disabled while evaluating');
      assert.strictEqual(buttons[1].disabled, false, 'Cancel must be available while evaluating');
      console.log('✔ Test 2 Passed: Loading card auto-presents with safe buttons.');
    } finally {
      b.cleanup();
    }
  }

  // Test 3: MATCH card shows evidence; Continue click decides for that id.
  {
    const b = loadBridge();
    try {
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-match-1', {
        status: 'AWAITING_USER_DECISION', assessment: assessment('MATCH')
      }) });
      const text = b.cardText();
      assert.ok(text.includes('MATCH'), 'Verdict must show');
      assert.ok(text.includes('MATCH summary'), 'Summary must show');
      assert.ok(text.includes('SwapRouter'), 'Decoded contract must show');
      assert.ok(text.includes('swap'), 'Decoded function must show');
      assert.ok(text.includes('Security findings:'), 'Findings section must show');
      assert.ok(text.includes('page context only'), 'Screenshot status must be honest');
      const buttons = b.shadow().findButtons();
      assert.strictEqual(buttons[0].textContent, 'CONTINUE TO WALLET');
      assert.strictEqual(buttons[0].disabled, false);
      assert.strictEqual(buttons[1].textContent, 'CANCEL REQUEST');
      buttons[0].click();
      const decide = b.relayed.find((m) => m.type === 'ASSERTARA_DECIDE');
      assert.deepStrictEqual(decide, { type: 'ASSERTARA_DECIDE', requestId: 'card-match-1', decision: 'continue' });
      assert.strictEqual(buttons[0].disabled, true, 'Buttons must disable after click (double-click safe)');
      assert.strictEqual(buttons[1].disabled, true);
      console.log('✔ Test 3 Passed: Assessment card + Continue wiring exact.');
    } finally {
      b.cleanup();
    }
  }

  // Test 4: MISMATCH/UNCERTAIN badges, failure + unsupported honesty.
  {
    const b = loadBridge();
    try {
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-mm-1', {
        status: 'AWAITING_USER_DECISION', assessment: assessment('MISMATCH')
      }) });
      assert.ok(b.cardText().includes('MISMATCH'));
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-un-1', {
        status: 'AWAITING_USER_DECISION', assessment: assessment('UNCERTAIN')
      }) });
      assert.ok(b.cardText().includes('UNCERTAIN'));
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-fail-1', {
        status: 'EVALUATION_FAILED', assessment: { ok: false, error: 'backend down' }
      }) });
      const text = b.cardText();
      assert.ok(text.includes('backend down'), 'Failure reason must show');
      assert.ok(text.includes('UNVERIFIED'), 'Failure continue must be labeled unverified');
      b.workerMessage({
        type: 'ASSERTARA_GATE_UPDATE',
        view: view('card-unsup-1', {
          status: 'UNSUPPORTED', kind: 'message', method: 'personal_sign', tx: null,
          assessment: { ok: true, unsupported: true, method: 'personal_sign' }
        })
      });
      assert.ok(b.cardText().includes('personal_sign'), 'Unsupported method must be named');
      console.log('✔ Test 4 Passed: Verdicts, failures, unsupported all honest.');
    } finally {
      b.cleanup();
    }
  }

  // Test 5: worker decisions route to the exact page request; sender checked.
  {
    const b = loadBridge();
    try {
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-dec-1', {
        status: 'AWAITING_USER_DECISION', assessment: assessment('MATCH')
      }) });
      assert.ok(b.cardText(), 'Card present before decision');
      const foreign = b.workerMessage({ type: 'ASSERTARA_GATE_DECISION', requestId: 'card-dec-1', decision: 'continue' }, 'evil-id');
      assert.strictEqual(foreign.ret, false, 'Foreign sender must be ignored');
      assert.strictEqual(b.posted.length, 0, 'Nothing posted for foreign sender');
      b.workerMessage({ type: 'ASSERTARA_GATE_DECISION', requestId: 'card-dec-1', decision: 'cancel', reason: null, approvedDigest: 'd'.repeat(64) });
      assert.deepStrictEqual(b.posted[0], {
        __assertara: 'gate-v1', direction: 'iso-to-main',
        type: 'DECISION', requestId: 'card-dec-1', decision: 'cancel', reason: null, approvedDigest: 'd'.repeat(64)
      });
      assert.strictEqual(b.cardText(), null, 'Decided card must be removed');
      // Closed views remove cards without decisions.
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-close-1') });
      assert.ok(b.cardText(), 'Card present');
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: { ...view('card-close-1'), closed: true } });
      assert.strictEqual(b.cardText(), null, 'Closed view must remove the card');
      console.log('✔ Test 5 Passed: Decisions routed exactly; sender enforced.');
    } finally {
      b.cleanup();
    }
  }

  // Test 6: simultaneous cards isolated; expiry notice relayed.
  {
    const b = loadBridge();
    try {
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-multi-a', {
        status: 'AWAITING_USER_DECISION', assessment: assessment('MATCH')
      }) });
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-multi-b') });
      let text = b.cardText();
      assert.ok(text.includes('MATCH summary'), 'Card A shows its assessment');
      assert.ok(text.includes('Evaluating with the local backend'), 'Card B still loading');
      b.workerMessage({ type: 'ASSERTARA_GATE_UPDATE', view: view('card-multi-b', {
        status: 'AWAITING_USER_DECISION', assessment: assessment('MISMATCH')
      }) });
      text = b.cardText();
      assert.ok(text.includes('MATCH summary') && text.includes('MISMATCH summary'), 'Each card keeps its own result');
      b.workerMessage({ type: 'ASSERTARA_GATE_DECISION', requestId: 'card-multi-a', decision: 'continue', reason: null });
      text = b.cardText();
      const dim = b.shadow().querySelector('#assertara-gate-dim');
      assert.strictEqual(dim.children.length, 1, 'Deciding A must remove exactly one card');
      assert.ok(text.includes('MISMATCH summary'), "Deciding A must not touch B's result");
      b.pageMessage({ __assertara: 'gate-v1', direction: 'main-to-iso', type: 'GATE_EXPIRED', requestId: 'card-multi-b' });
      assert.deepStrictEqual(
        b.relayed.find((m) => m.type === 'ASSERTARA_GATE_EXPIRED'),
        { type: 'ASSERTARA_GATE_EXPIRED', requestId: 'card-multi-b' }, 'Expiry notice must relay'
      );
      console.log('✔ Test 6 Passed: Multi-card isolation + expiry relay.');
    } finally {
      b.cleanup();
    }
  }

  // Test 7: payload-binding fields relayed; mutation notice relayed.
  {
    const b = loadBridge();
    try {
      const digest = 'ab'.repeat(32);
      b.pageMessage(intercepted('bind-relay-1', { txDigest: digest }));
      assert.deepStrictEqual(
        b.relayed.find((m) => m.type === 'ASSERTARA_GATED_REQUEST'),
        {
          type: 'ASSERTARA_GATED_REQUEST', requestId: 'bind-relay-1',
          method: 'eth_sendTransaction', kind: 'tx',
          tx: { to: '0xRouter', from: '0xUser', data: '0x1234', value: '0x1' },
          txDigest: digest, chainId: '0x1', wallet: { source: 'window.ethereum' },
          pageContext: { url: 'https://dapp.example/swap', title: 'Swap', visibleText: 'Swap 1 ETH' }
        },
        'Intercept digest must reach the worker'
      );
      b.pageMessage({ __assertara: 'gate-v1', direction: 'main-to-iso', type: 'TX_MUTATED', requestId: 'bind-relay-1' });
      assert.deepStrictEqual(
        b.relayed.find((m) => m.type === 'ASSERTARA_TX_MUTATED'),
        { type: 'ASSERTARA_TX_MUTATED', requestId: 'bind-relay-1' }, 'Mutation notice must relay'
      );
      b.workerMessage({ type: 'ASSERTARA_GATE_DECISION', requestId: 'bind-relay-1', decision: 'continue', reason: null, approvedDigest: digest });
      assert.deepStrictEqual(b.posted.find((m) => m.type === 'DECISION'), {
        __assertara: 'gate-v1', direction: 'iso-to-main',
        type: 'DECISION', requestId: 'bind-relay-1', decision: 'continue', reason: null, approvedDigest: digest
      }, 'Approved digest must reach the page');
      console.log('✔ Test 7 Passed: Binding relay + mutation notice.');
    } finally {
      b.cleanup();
    }
  }

  console.log('\nAll Gate Bridge Tests Passed Successfully!\n');
}

if (require.main === module) {
  runBridgeTests();
}

module.exports = { runBridgeTests };
