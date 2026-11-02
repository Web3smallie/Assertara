/**
 * Assertara provider gate. Manifest V3 content script, MAIN world,
 * run_at document_start (see manifest.json content_scripts).
 *
 * Intercepts supported EIP-1193 wallet requests BEFORE the wallet sees
 * them, holds the dApp-side promise pending, and releases it only after
 * an explicit user decision (CONTINUE TO WALLET / CANCEL) delivered
 * through the isolated bridge. Read-only holding:
 *
 * - Supported requests are NOT forwarded until the user continues.
 * - The original method and parameters are preserved untouched and, on
 *   continue, invoked exactly once with the original arguments.
 * - On cancel, the dApp promise rejects locally with an EIP-1193 4001
 *   user-cancellation error; the wallet never sees the request.
 * - Read-only RPC methods are never intercepted.
 * - Wallet recovery material is never requested, read, or stored.
 * - Assertara never signs, approves, rejects-in-wallet, or broadcasts.
 *
 * MAIN-world code never touches extension APIs here by design: all
 * extension communication goes through window.postMessage to the isolated bridge
 * (content/bridge.js), using the validated gate-v1 protocol from
 * shared/gate.js. Incoming bridge messages are validated before any
 * pending request is touched, so page scripts cannot forge a
 * continuation: a forged DECISION for an unknown requestId is dropped,
 * and decisions for known requests only arrive from the isolated
 * bridge after the service worker accepts a real UI decision.
 *
 * Testable surface at globalThis.__assertaraGatePage. Auto-init runs
 * only when a real page window exists.
 */
(function () {
  const root = typeof globalThis !== 'undefined' ? globalThis : {};
  const Gate = root.AssertaraGate;
  // Digest library (shared/txDigest.js, loaded before this file). Absence
  // fails closed: tx requests cannot be snapshotted or bound, so every
  // release path refuses to forward them.
  const TxDigest = root.AssertaraTxDigest;

  const MAX_TEXT_CHARS = 4000;
  const PROVIDER_POLL_MS = 500;
  const PROVIDER_POLLS = 12;

  function getWindow() {
    if (root.window && typeof root.window === 'object') return root.window;
    if (typeof window !== 'undefined') return window;
    return undefined;
  }

  function classifyMethod(method) {
    if (typeof method !== 'string') return 'readonly';
    if (Gate && Gate.TX_METHODS.indexOf(method) !== -1) return 'tx';
    if (Gate && Gate.MSG_METHODS.indexOf(method) !== -1) return 'message';
    return 'readonly';
  }

  function extractTx(params) {
    const out = { tx: {}, complete: false };
    try {
      const first = Array.isArray(params) ? params[0] : undefined;
      if (!first || typeof first !== 'object') return out;
      for (const key of ['to', 'from', 'data', 'value']) {
        if (typeof first[key] === 'string' && first[key].length > 0) out.tx[key] = first[key];
      }
      out.complete = typeof out.tx.to === 'string' && out.tx.to.length > 0;
    } catch {
      /* malformed params: report incomplete, still gate the call */
    }
    return out;
  }

  function collectPageContext(w) {
    const ctx = { url: '', title: '', visibleText: '' };
    try {
      ctx.url = (w.location && w.location.href) || '';
      ctx.title = w.document ? w.document.title || '' : '';
      const body = w.document ? w.document.body : null;
      const text = (body && body.innerText) || '';
      ctx.visibleText = text.replace(/\s+/g, ' ').trim().slice(0, MAX_TEXT_CHARS);
    } catch {
      /* restricted page: return what we have */
    }
    return ctx;
  }

  function createGatePage(deps) {
    const w = deps.window;
    const gate = deps.gate;
    const pending = new Map(); // requestId -> {resolve, reject, method, original, args, wallet}
    const ackWaiters = new Map(); // requestId -> {resolve, attempts, timer}
    let bridgeReady = false;
    let seq = 0;

    function postToBridge(message) {
      try {
        if (w && typeof w.postMessage === 'function') {
          w.postMessage({ __assertara: gate.PROTOCOL, direction: 'main-to-iso', ...message }, '*');
        }
      } catch {
        /* page messaging failure: caller applies fail-open path */
      }
    }

    function onPageMessage(event) {
      let msg = null;
      try {
        if (!event || event.source !== w) return;
        msg = gate.validateIsoMessage(event.data);
      } catch {
        return;
      }
      if (!msg) return;
      if (msg.type === 'BRIDGE_READY') {
        bridgeReady = true;
        return;
      }
      if (msg.type === 'ACK') {
        const waiter = ackWaiters.get(msg.requestId);
        if (waiter) {
          ackWaiters.delete(msg.requestId);
          try {
            if (waiter.timer && typeof w.clearTimeout === 'function') w.clearTimeout(waiter.timer);
          } catch {
            /* ignore */
          }
          waiter.resolve(true);
        }
        return;
      }
      if (msg.type === 'DECISION') {
        const held = pending.get(msg.requestId);
        if (!held) return; // unknown/stale request: forged or late; drop it
        pending.delete(msg.requestId);
        settleHeld(held, msg.decision, msg.reason, msg.approvedDigest);
      }
    }

    // Verify the live arguments against the bound digests. Returns true
    // only when the release-time snapshot matches the intercept snapshot
    // AND the worker-approved digest. Any failure, error, or missing
    // binding refuses: integrity problems must never fail open.
    function verifyRelease(held, approvedDigest) {
      try {
        if (!TxDigest || !held.snapshot || !held.txDigest) return false;
        if (!TxDigest.isValidDigest(approvedDigest)) return false;
        if (approvedDigest !== held.txDigest) return false;
        const live = held.args && Array.isArray(held.args.params) ? held.args.params[0] : undefined;
        const resnapshot = TxDigest.snapshotTx(live);
        if (!resnapshot) return false;
        const releaseDigest = TxDigest.digestTx(resnapshot);
        if (!releaseDigest || releaseDigest !== held.txDigest) return false;
        if (!held.args || held.args.method !== held.method) return false;
        return true;
      } catch {
        return false;
      }
    }

    function refuseRelease(held, reason) {
      postToBridge({ type: 'TX_MUTATED', requestId: held.requestId });
      held.reject(gate.cancellationError(reason));
    }

    // Release exactly one held request. Continue re-verifies the live
    // arguments against the bound digests, then invokes the original
    // provider exactly once with the frozen verified snapshot — never
    // the mutable live args. Cancel rejects locally.
    function settleHeld(held, decision, reason, approvedDigest) {
      if (held.settled) return;
      held.settled = true;
      try {
        if (held.expiryTimer && typeof w.clearTimeout === 'function') w.clearTimeout(held.expiryTimer);
      } catch {
        /* ignore */
      }
      try {
        const waiter = held.requestId ? ackWaiters.get(held.requestId) : null;
        if (waiter) {
          ackWaiters.delete(held.requestId);
          if (waiter.timer && typeof w.clearTimeout === 'function') w.clearTimeout(waiter.timer);
        }
      } catch {
        /* ignore */
      }
      if (decision === 'continue') {
        if (held.kind === 'tx' && !held.unverifiedForward) {
          if (!verifyRelease(held, approvedDigest)) {
            refuseRelease(held, 'mutation-detected');
            return;
          }
        }
        let outcome;
        try {
          // Forward the frozen intercept snapshot for tx requests: the
          // exact bytes that were evaluated and approved. Message-kind
          // and unverified-forward requests keep existing behavior.
          const forwardArgs = held.kind === 'tx' && held.snapshot
            ? { method: held.method, params: [held.snapshot] }
            : held.args;
          outcome = held.original(forwardArgs);
        } catch (err) {
          // Synchronous provider throw: preserve sync-error semantics by
          // rejecting the dApp promise with the same error object.
          held.reject(err);
          return;
        }
        if (outcome && typeof outcome.then === 'function') {
          outcome.then(held.resolve, held.reject);
        } else {
          held.resolve(outcome);
        }
      } else {
        held.reject(gate.cancellationError(reason === 'expired' ? 'expired' : 'cancelled'));
      }
    }

    // Wait for the bridge ACK with bounded retries. Resolves true when the
    // gate path is live, false when the bridge is missing (fail-open: the
    // caller forwards immediately and reports the request as unprotected).
    function awaitAck(message) {
      return new Promise((resolve) => {
        let attempts = 0;
        const waiter = { resolve, timer: null };
        ackWaiters.set(message.requestId, waiter);
        const attempt = () => {
          attempts += 1;
          postToBridge(message);
          if (attempts > gate.LIMITS.ACK_RETRIES) {
            ackWaiters.delete(message.requestId);
            resolve(false);
            return;
          }
          try {
            waiter.timer = w.setTimeout(() => {
              if (ackWaiters.get(message.requestId) === waiter) attempt();
            }, gate.LIMITS.ACK_TIMEOUT_MS);
          } catch {
            ackWaiters.delete(message.requestId);
            resolve(false);
          }
        };
        attempt();
      });
    }

    function holdRequest(original, args, wallet) {
      const method = args ? args.method : undefined;
      const kind = classifyMethod(method);
      // Frozen full snapshot at intercept: every field of params[0], so
      // later mutation of the live args cannot change what was evaluated.
      // A null snapshot (unrepresentable params) or missing digest lib
      // fails closed downstream: nothing verified can be released.
      let snapshot = null;
      let txDigest = null;
      if (kind === 'tx' && TxDigest) {
        const first = args && Array.isArray(args.params) ? args.params[0] : undefined;
        snapshot = TxDigest.snapshotTx(first);
        if (snapshot) txDigest = TxDigest.digestTx(snapshot);
      }
      const tx = snapshot || {};
      const complete = typeof tx.to === 'string' && tx.to.length > 0;
      const requestId = `${gate.makeRequestId()}-${(seq += 1).toString(36)}`;
      const message = {
        type: 'INTERCEPTED',
        requestId,
        method: typeof method === 'string' ? method : 'unknown',
        kind,
        tx,
        txDigest,
        complete,
        chainId: null,
        wallet: wallet || { source: 'window.ethereum' },
        pageContext: collectPageContext(w)
      };
      try {
        const holder = args && args.__assertaraProviderRef;
        if (holder && typeof holder.chainId === 'string') message.chainId = holder.chainId;
      } catch {
        /* chainId is best-effort */
      }
      return new Promise((resolve, reject) => {
        const held = { resolve, reject, method: message.method, kind, original, args, snapshot, txDigest, wallet: message.wallet, settled: false, requestId, expiryTimer: null, unverifiedForward: false };
        // Register synchronously so a decision can never arrive for an
        // unknown id; requestIds are unique per interception.
        pending.set(requestId, held);
        // Page-side decision timeout: the page is alive exactly while the
        // dApp waits, so this bound always enforces even if the worker
        // never sends another message. Expiry rejects locally (4001) and
        // notifies the worker to close the card; it never forwards.
        try {
          if (typeof w.setTimeout === 'function') {
            held.expiryTimer = w.setTimeout(() => {
              if (pending.get(requestId) !== held || held.settled) return;
              pending.delete(requestId);
              postToBridge({ type: 'GATE_EXPIRED', requestId });
              settleHeld(held, 'cancel', 'expired');
            }, gate.LIMITS.DECISION_TIMEOUT_MS);
          }
        } catch {
          /* timers unavailable: worker-side sweep remains as backup */
        }
        awaitAck(message).then((acked) => {
          if (!acked) {
            // Bridge missing on this page: fail open so the dApp keeps
            // working, and report the bypass honestly (best-effort). No
            // approval exists, so no digest verification applies — but
            // the frozen snapshot is still forwarded instead of the
            // mutable live args.
            pending.delete(requestId);
            postToBridge({ type: 'BYPASSED', requestId, method: message.method, kind });
            held.unverifiedForward = true;
            settleHeld(held, 'continue');
          }
        });
      });
    }

    function wrapProvider(provider, wallet) {
      if (!provider || typeof provider.request !== 'function') return 'no-request';
      if (provider.__assertaraGated === true) return 'already';
      let original;
      try {
        original = provider.request.bind(provider);
      } catch {
        return 'unbindable';
      }
      const wrapped = function (args) {
        const kind = classifyMethod(args ? args.method : undefined);
        if (kind === 'readonly') {
          return original(args); // never intercept read-only calls
        }
        try {
          if (args && typeof args === 'object' && !args.__assertaraProviderRef) {
            try {
              Object.defineProperty(args, '__assertaraProviderRef', { value: provider, enumerable: false, configurable: true });
            } catch {
              /* non-extensible args: chainId simply stays null */
            }
          }
        } catch {
          /* ignore */
        }
        return holdRequest(original, args, wallet);
      };
      try {
        provider.request = wrapped;
      } catch {
        return 'unwritable';
      }
      try {
        provider.__assertaraGated = true;
      } catch {
        /* marker is best-effort only */
      }
      return 'wrapped';
    }

    function walletFrom6963(info) {
      const wallet = { source: 'eip-6963' };
      if (info && typeof info === 'object') {
        if (typeof info.name === 'string') wallet.name = info.name;
        if (typeof info.rdns === 'string') wallet.rdns = info.rdns;
      }
      return wallet;
    }

    // Test/bridge hook: release one held request as if the user decided.
    // Only the validated DECISION path calls this in production.
    function testDecision(requestId, decision, approvedDigest) {
      const held = pending.get(requestId);
      if (!held) return false;
      pending.delete(requestId);
      settleHeld(held, decision, null, approvedDigest);
      return true;
    }

    return {
      wrapProvider,
      classifyMethod,
      extractTx,
      collectPageContext: () => collectPageContext(w),
      testDecision,
      pendingIds: () => Array.from(pending.keys()),
      isBridgeReady: () => bridgeReady,
      onPageMessage,
      hello: () => postToBridge({ type: 'HELLO' })
    };
  }

  function init() {
    const w = getWindow();
    if (!w) return 'no-window';
    if (!Gate) return 'no-gate-lib';
    let api;
    try {
      api = createGatePage({ window: w, gate: Gate });
    } catch {
      return 'init-failed';
    }
    root.__assertaraGatePage = api;
    try {
      if (typeof w.addEventListener === 'function') {
        w.addEventListener('message', api.onPageMessage);
        w.addEventListener('eip6963:announceProvider', (event) => {
          try {
            const detail = event ? event.detail : null;
            if (detail && detail.provider) {
              const info = detail.info && typeof detail.info === 'object' ? detail.info : null;
              const wallet = { source: 'eip-6963' };
              if (info) {
                if (typeof info.name === 'string') wallet.name = info.name;
                if (typeof info.rdns === 'string') wallet.rdns = info.rdns;
              }
              api.wrapProvider(detail.provider, wallet);
            }
          } catch {
            /* malformed announcement: ignore */
          }
        });
        if (typeof w.CustomEvent === 'function' && typeof w.dispatchEvent === 'function') {
          w.dispatchEvent(new w.CustomEvent('eip6963:requestProvider'));
        }
      }
    } catch {
      /* event wiring unavailable */
    }
    const scanWindow = () => {
      try {
        const eth = w.ethereum;
        if (!eth) return;
        if (Array.isArray(eth.providers) && eth.providers.length > 0) {
          eth.providers.forEach((p) => api.wrapProvider(p, { source: 'window.ethereum.providers[]' }));
        } else if (typeof eth.request === 'function') {
          api.wrapProvider(eth, { source: 'window.ethereum' });
        }
      } catch {
        /* inaccessible provider object: skip */
      }
    };
    scanWindow();
    if (typeof w.setInterval === 'function') {
      let polls = 0;
      try {
        const timer = w.setInterval(() => {
          scanWindow();
          polls += 1;
          if (polls >= PROVIDER_POLLS) {
            try {
              if (typeof w.clearInterval === 'function') w.clearInterval(timer);
            } catch {
              /* ignore */
            }
          }
        }, PROVIDER_POLL_MS);
      } catch {
        /* polling unavailable */
      }
    }
    api.hello();
    return 'observing';
  }

  root.__assertaraGatePageFactory = { createGatePage, classifyMethod, extractTx, collectPageContext };

  try {
    init();
  } catch {
    /* auto-init must never break page load */
  }
})();
