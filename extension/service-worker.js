/**
 * Assertara service worker (Manifest V3): pre-sign request gate.
 * Holds supported wallet requests intercepted by the MAIN-world observer,
 * evaluates transactions through the local backend, and releases each
 * request only after an explicit per-request user decision (CONTINUE TO
 * WALLET / CANCEL) from the interstitial or popup. Never auto-forwards,
 * never auto-cancels, never signs or broadcasts.
 */
importScripts('shared/format.js', 'shared/gate.js', 'shared/txDigest.js');

const BACKEND_BASE_URL = 'http://localhost:3001';
const EVALUATE_TIMEOUT_MS = 120000;
const TERMINAL_PRUNE_MS = 300000;

const Gate = globalThis.AssertaraGate;
const TxDigest = globalThis.AssertaraTxDigest;
const store = Gate.createGateStore();
const observedTabs = new Map(); // tabId -> { url, observedAt }
const tabNotes = new Map(); // tabId -> [{ text, at }]

function note(tabId, text) {
  if (tabId === null || tabId === undefined) return;
  const list = tabNotes.get(tabId) || [];
  list.push({ text, at: Date.now() });
  while (list.length > 10) list.shift();
  tabNotes.set(tabId, list);
}

function setBadge(tabId, text, color) {
  try {
    if (chrome.action && typeof chrome.action.setBadgeText === 'function') {
      chrome.action.setBadgeText({ tabId, text });
      if (color && typeof chrome.action.setBadgeBackgroundColor === 'function') {
        chrome.action.setBadgeBackgroundColor({ tabId, color });
      }
    }
  } catch {
    /* badge is best-effort only */
  }
}

function refreshBadge(tabId) {
  const pending = store.tabRequests(tabId).filter((r) => !Gate.isTerminal(r.status));
  if (pending.length === 0) {
    setBadge(tabId, '', null);
    return;
  }
  const mismatch = pending.some((r) => r.assessment && r.assessment.evidence && r.assessment.evidence.verdict === 'MISMATCH');
  setBadge(tabId, pending.length > 9 ? '9+' : String(pending.length), mismatch ? '#b91c1c' : '#1d4ed8');
}

function viewFromRecord(record) {
  return {
    requestId: record.requestId,
    pageUrl: record.pageUrl,
    method: record.method,
    kind: record.kind,
    wallet: record.wallet,
    chainId: record.chainId,
    tx: record.tx,
    status: record.status,
    assessment: record.assessment
  };
}

async function pushView(record) {
  try {
    await chrome.tabs.sendMessage(record.tabId, { type: 'ASSERTARA_GATE_UPDATE', view: viewFromRecord(record) });
  } catch {
    /* bridge gone (navigation/closed tab): invalidateTab handles cleanup */
  }
  refreshBadge(record.tabId);
}

async function pushClosedView(record) {
  try {
    await chrome.tabs.sendMessage(record.tabId, {
      type: 'ASSERTARA_GATE_UPDATE',
      view: { ...viewFromRecord(record), closed: true }
    });
  } catch {
    /* bridge gone: nothing to close */
  }
  refreshBadge(record.tabId);
}

async function pushDecision(record, decision, reason) {
  try {
    await chrome.tabs.sendMessage(record.tabId, {
      type: 'ASSERTARA_GATE_DECISION',
      requestId: record.requestId,
      decision,
      reason: reason || null,
      approvedDigest: record.approvedDigest || null
    });
  } catch {
    /* page gone: nothing held anymore */
  }
  refreshBadge(record.tabId);
}

function sweepAndRelease() {
  const expired = store.sweepExpired();
  for (const id of expired) {
    const record = store.get(id);
    if (record) {
      // Expired requests are released as cancellations: nothing is
      // forwarded; the dApp promise rejects locally in the page.
      pushDecision(record, 'cancel', 'expired');
    }
  }
  store.pruneTerminal(TERMINAL_PRUNE_MS);
}

async function captureScreenshot(windowId) {
  try {
    const dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: 'png' });
    return typeof dataUrl === 'string' && dataUrl.startsWith('data:image/') ? dataUrl : null;
  } catch {
    return null;
  }
}

async function postEvaluation(payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), EVALUATE_TIMEOUT_MS);
  try {
    const res = await fetch(`${BACKEND_BASE_URL}/api/v1/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    const text = await res.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(`Backend returned invalid JSON (HTTP ${res.status}). Is ${BACKEND_BASE_URL} the Assertara backend?`);
    }
    if (!res.ok) {
      throw new Error(body && body.error ? `Backend error (HTTP ${res.status}): ${body.error}` : `Backend error (HTTP ${res.status}).`);
    }
    if (!body || typeof body.verdict !== 'string') {
      throw new Error('Backend response is not a valid evidence bundle (missing verdict).');
    }
    return body;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error(`Backend timed out after ${EVALUATE_TIMEOUT_MS / 1000}s. The request is still held; nothing was forwarded.`);
    }
    if (err instanceof TypeError) {
      throw new Error(`Cannot reach the backend at ${BACKEND_BASE_URL}. The request is still held; nothing was forwarded.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function evaluateGatedRequest(record) {
  let screenshot = null;
  try {
    const tab = await chrome.tabs.get(record.tabId);
    if (tab && typeof tab.windowId === 'number') screenshot = await captureScreenshot(tab.windowId);
  } catch {
    screenshot = null;
  }
  const page = record.pageContext || {};
  const pageContextOut = { title: page.title || '', url: page.url || '' };
  if (typeof page.visibleText === 'string' && page.visibleText) {
    pageContextOut.visibleText = page.visibleText;
  }
  const payload = { pageContext: pageContextOut, transaction: { ...record.tx }, txDigest: record.txDigest || null };
  if (screenshot) payload.screenshot = screenshot;
  try {
    const evidence = await postEvaluation(payload);
    // Backend agreement: the backend recomputes the digest over the
    // transaction it actually evaluated. If it does not match the
    // intercept digest, the assessment cannot be bound — fail closed.
    const evaluated = evidence && evidence.txBinding && evidence.txBinding.evaluatedTxDigest;
    if (!TxDigest || !TxDigest.digestsEqual(evaluated, record.txDigest)) {
      const applied = store.applyEvalFailure(record.requestId,
        'Transaction integrity check failed: the evaluated payload digest does not match the intercepted transaction. Continuing is UNVERIFIED.');
      if (applied) await pushView(store.get(record.requestId));
      persist();
      return;
    }
    const applied = store.applyAssessment(record.requestId, {
      ok: true,
      evidence,
      screenshotIncluded: Boolean(screenshot),
      visibleTextChars: typeof page.visibleText === 'string' ? page.visibleText.length : 0
    });
    if (applied) await pushView(store.get(record.requestId));
    // If not applied, the record moved on (navigation/expiry): stale result dropped.
  } catch (err) {
    const applied = store.applyEvalFailure(record.requestId, err.message || 'Evaluation failed.');
    if (applied) await pushView(store.get(record.requestId));
  }
  persist();
}

function handleGatedRequest(message, sender) {
  const tabId = sender && sender.tab ? sender.tab.id : null;
  if (tabId === null || tabId === undefined) {
    return { ok: false, error: 'Request could not be associated with a dApp tab.' };
  }
  // Defensive re-validation: the bridge validates, the worker trusts nothing.
  const clean = Gate.validateMainMessage({
    __assertara: Gate.PROTOCOL,
    direction: 'main-to-iso',
    type: 'INTERCEPTED',
    requestId: message.requestId,
    method: message.method,
    kind: message.kind,
    tx: message.tx,
    txDigest: message.txDigest,
    chainId: message.chainId,
    wallet: message.wallet,
    pageContext: message.pageContext
  });
  if (!clean) return { ok: false, error: 'Invalid gated-request payload.' };
  sweepAndRelease();
  const pageUrl = sender.tab.url || clean.pageContext.url || '';
  const { record, duplicate, rejected } = store.register(clean, tabId, pageUrl);
  if (rejected === 'tab-full') {
    note(tabId, 'A request bypassed the gate: too many pending requests on this tab.');
    // Fail open for overflow only: the dApp keeps working, nothing is
    // claimed as protected, and the bypass is shown in the popup. The
    // page-claimed digest still travels so the page can refuse a mutated
    // release even on the bypass path.
    chrome.tabs.sendMessage(tabId, { type: 'ASSERTARA_GATE_DECISION', requestId: clean.requestId, decision: 'continue', reason: 'overflow-bypass', approvedDigest: clean.txDigest || null }).catch(() => {});
    return { ok: true, bypassed: true };
  }
  if (duplicate) {
    pushView(record);
    return { ok: true, duplicate: true };
  }
  if (record.kind === 'tx') {
    // Integrity prerequisite: recompute the digest over our own validated
    // copy and require agreement with the page-claimed digest before any
    // evaluation. A forged claim or a drifted copy fails closed here —
    // nothing is ever presented as verified without this agreement.
    const recomputed = TxDigest ? TxDigest.digestTx(record.tx) : null;
    const verified = TxDigest ? TxDigest.digestsEqual(recomputed, record.txDigest) : false;
    if (!verified) {
      store.setStatus(record, Gate.STATES.EVALUATION_FAILED);
      record.assessment = { ok: false, error: 'Transaction integrity check failed: the intercepted payload could not be verified against its digest. Continuing is UNVERIFIED.' };
      pushView(record);
      persist();
      return { ok: true };
    }
  }
  if (record.kind === 'message') {
    store.setStatus(record, Gate.STATES.UNSUPPORTED);
    record.assessment = { ok: true, unsupported: true, method: record.method };
    pushView(record);
    persist();
    return { ok: true };
  }
  if (!record.tx || !record.tx.to) {
    store.setStatus(record, Gate.STATES.EVALUATION_FAILED);
    record.assessment = { ok: false, error: 'The request did not include a recipient address, so it cannot be evaluated as a transaction. Continuing is UNVERIFIED.' };
    pushView(record);
    persist();
    return { ok: true };
  }
  store.setStatus(record, Gate.STATES.EVALUATING);
  pushView(record);
  evaluateGatedRequest(record).catch(() => {});
  persist();
  return { ok: true };
}

function handleDecide(message) {
  sweepAndRelease();
  const requestId = typeof message.requestId === 'string' ? message.requestId : '';
  const decision = message.decision;
  const result = store.decide(requestId, decision);
  if (!result.accepted) {
    return { ok: false, error: `Decision rejected: ${result.reason}.` };
  }
  const record = store.get(requestId);
  pushDecision(record, decision, null);
  persist();
  return { ok: true, decision };
}

function tabStatePayload(tabId) {
  const observed = observedTabs.get(tabId) || null;
  return {
    observed: Boolean(observed),
    observedUrl: observed ? observed.url : null,
    pending: store.tabRequests(tabId).map(viewFromRecord),
    notes: tabNotes.get(tabId) || []
  };
}

// Best-effort persistence across service-worker restarts. On restart,
// in-flight evaluations are marked failed (their backend result will
// never arrive); held page promises stay held and the UI keeps working.
function persist() {
  try {
    if (!chrome.storage || !chrome.storage.session) return;
    const records = [];
    const all = [];
    // Collect via tabRequests over observed tabs.
    const seen = new Set();
    for (const tabId of observedTabs.keys()) {
      for (const r of store.tabRequests(tabId)) {
        if (!seen.has(r.requestId)) {
          seen.add(r.requestId);
          all.push(r);
        }
      }
    }
    for (const r of all) {
      if (!Gate.isTerminal(r.status)) records.push(r);
    }
    chrome.storage.session.set({ assertaraGate: records.slice(0, 100) }).catch(() => {});
  } catch {
    /* persistence unavailable: memory-only */
  }
}

async function rehydrate() {
  try {
    if (!chrome.storage || !chrome.storage.session) return;
    const data = await chrome.storage.session.get('assertaraGate');
    const records = data && Array.isArray(data.assertaraGate) ? data.assertaraGate : [];
    for (const r of records) {
      if (!r || typeof r.requestId !== 'string') continue;
      const clean = Gate.validateMainMessage({
        __assertara: Gate.PROTOCOL, direction: 'main-to-iso', type: 'INTERCEPTED',
        requestId: r.requestId, method: r.method, kind: r.kind, tx: r.tx,
        txDigest: r.txDigest, chainId: r.chainId, wallet: r.wallet, pageContext: r.pageContext
      });
      if (!clean || typeof r.tabId !== 'number') continue;
      const { record, duplicate } = store.register(clean, r.tabId, r.pageUrl || '');
      if (duplicate) continue;
      if (r.status === Gate.STATES.EVALUATING) {
        store.setStatus(record, Gate.STATES.EVALUATION_FAILED);
        record.assessment = { ok: false, error: 'The extension service worker restarted during evaluation. Continuing is UNVERIFIED, or cancel.' };
      } else if (r.status === Gate.STATES.AWAITING_USER_DECISION && r.assessment) {
        store.setStatus(record, Gate.STATES.AWAITING_USER_DECISION);
        record.assessment = r.assessment;
      } else if (r.status === Gate.STATES.UNSUPPORTED) {
        store.setStatus(record, Gate.STATES.UNSUPPORTED);
        record.assessment = r.assessment || { ok: true, unsupported: true, method: record.method };
      } else if (r.status === Gate.STATES.EVALUATION_FAILED) {
        store.setStatus(record, Gate.STATES.EVALUATION_FAILED);
        record.assessment = r.assessment || { ok: false, error: 'Evaluation failed before the restart.' };
      } else {
        continue;
      }
      pushView(record);
    }
  } catch {
    /* start empty */
  }
}

async function handleShowOverlay({ tabId, evidence }) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['shared/format.js', 'content/overlay.js']
    });
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (bundle) => globalThis.__assertaraOverlay.show(bundle),
      args: [evidence]
    });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not display the overlay on this page: ${err.message}` };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (!message || typeof message.type !== 'string') {
        return { ok: false, error: 'Unknown extension message.' };
      }
      const tabId = sender && sender.tab ? sender.tab.id : null;
      if (message.type === 'ASSERTARA_TAB_OBSERVED') {
        if (tabId !== null && tabId !== undefined) {
          observedTabs.set(tabId, { url: (sender.tab && sender.tab.url) || '', observedAt: Date.now() });
        }
        return { ok: true };
      }
      if (message.type === 'ASSERTARA_GATED_REQUEST') {
        return handleGatedRequest(message, sender);
      }
      if (message.type === 'ASSERTARA_GATE_BYPASSED') {
        if (tabId !== null && tabId !== undefined) {
          note(tabId, `A ${message.method || 'wallet'} request bypassed the gate (bridge unreachable on this page). It was forwarded without assessment.`);
        }
        return { ok: true };
      }
      if (message.type === 'ASSERTARA_GATE_EXPIRED') {
        const requestId = typeof message.requestId === 'string' ? message.requestId : '';
        const record = requestId ? store.get(requestId) : null;
        if (record && !Gate.isTerminal(record.status)) {
          // The page already rejected locally with 4001-expired; mark the
          // record EXPIRED and close the card. Never forwards.
          store.setStatus(record, Gate.STATES.EXPIRED);
          pushClosedView(record);
          persist();
        }
        return { ok: true };
      }
      if (message.type === 'ASSERTARA_TX_MUTATED') {
        const requestId = typeof message.requestId === 'string' ? message.requestId : '';
        const record = requestId ? store.get(requestId) : null;
        if (record && !Gate.isTerminal(record.status)) {
          // The page refused release: live arguments no longer match the
          // approved digest. Nothing was forwarded. Mark EXPIRED so the
          // record can never release, note the real cause, close the card.
          note(record.tabId, 'Release refused: the transaction changed after evaluation, so the approval no longer applies. Nothing was forwarded.');
          store.setStatus(record, Gate.STATES.EXPIRED);
          pushClosedView(record);
          persist();
        }
        return { ok: true };
      }
      if (message.type === 'ASSERTARA_DECIDE') {
        return handleDecide(message);
      }
      if (message.type === 'ASSERTARA_GET_TAB_STATE') {
        const id = typeof message.tabId === 'number' ? message.tabId : tabId;
        sweepAndRelease();
        return { ok: true, state: tabStatePayload(id) };
      }
      if (message.type === 'ASSERTARA_SHOW_OVERLAY') {
        if (!message.evidence) return { ok: false, error: 'No evidence bundle to display.' };
        return await handleShowOverlay(message);
      }
      return { ok: false, error: `Unknown message type: ${message.type}` };
    } catch (err) {
      return { ok: false, error: err.message || 'Request failed.' };
    }
  })().then(sendResponse);
  return true; // async response
});

try {
  if (chrome.tabs && chrome.tabs.onRemoved && typeof chrome.tabs.onRemoved.addListener === 'function') {
    chrome.tabs.onRemoved.addListener((tabId) => {
      store.invalidateTab(tabId);
      observedTabs.delete(tabId);
      tabNotes.delete(tabId);
      setBadge(tabId, '', null);
      persist();
    });
  }
  if (chrome.tabs && chrome.tabs.onUpdated && typeof chrome.tabs.onUpdated.addListener === 'function') {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
      if (changeInfo && changeInfo.status === 'loading') {
        store.invalidateTab(tabId);
        observedTabs.delete(tabId);
        refreshBadge(tabId);
        persist();
      }
    });
  }
} catch {
  /* tab cleanup is best-effort only */
}

rehydrate().catch(() => {});
