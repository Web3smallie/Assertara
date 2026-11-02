/**
 * Assertara gate bridge. Manifest V3 content script, ISOLATED world
 * (see manifest.json content_scripts). Requires shared/gate.js (protocol
 * + validation) and shared/format.js (safe rendering) loaded first in
 * the same isolated world.
 *
 * Two jobs:
 * 1. Relay validated MAIN-world gate messages to the service worker and
 *    route service-worker decisions/updates back to the page. Page
 *    messages are validated (type, direction, lengths, requestId) and
 *    page scripts can never call extension APIs through this bridge.
 * 2. Render the extension-controlled interstitial: the decision UI that
 *    holds each pending request. Continue/Cancel clicks go to the
 *    service worker, which accepts the first decision per requestId.
 */
(function () {
  const Gate = globalThis.AssertaraGate;
  const F = globalThis.AssertaraFormat;
  const HOST_ID = 'assertara-gate-host';

  const STYLE = `
    :host { all: initial; }
    .dim {
      position: fixed; inset: 0; z-index: 2147483647;
      background: rgba(2, 6, 23, 0.72);
      display: flex; align-items: flex-start; justify-content: center;
      overflow-y: auto; padding: 24px 16px;
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .card {
      width: 560px; max-width: 100%; margin-bottom: 16px;
      background: #0f172a; color: #f8fafc;
      border: 1px solid #334155; border-radius: 14px;
      box-shadow: 0 12px 32px rgba(0,0,0,0.5);
    }
    .head { display: flex; align-items: center; gap: 8px; padding: 12px 14px 0; }
    .brand { font-weight: 800; font-size: 13px; letter-spacing: 0.06em; text-transform: uppercase; color: #93c5fd; }
    .badge { margin-left: auto; padding: 2px 12px; border-radius: 20px; font-weight: 800; font-size: 13px; }
    .badge.match { background: #dbeafe; color: #1d4ed8; }
    .badge.mismatch { background: #fee2e2; color: #b91c1c; }
    .badge.uncertain { background: #fef3c7; color: #92400e; }
    .body { padding: 8px 14px 14px; }
    .summary { margin: 4px 0 8px; }
    .facts { margin: 0 0 8px; font-size: 12px; }
    .facts > div { display: flex; gap: 8px; padding: 3px 0; border-top: 1px solid #1e293b; }
    .facts dt { color: #94a3b8; min-width: 150px; flex-shrink: 0; }
    .facts dd { margin: 0; word-break: break-all; }
    .rules { margin: 0 0 8px; padding-left: 18px; font-size: 12px; }
    .rules li { margin: 2px 0; }
    .warn {
      background: #451a1a; border: 1px solid #7f1d1d; border-radius: 8px;
      padding: 8px 10px; font-size: 13px; margin: 0 0 8px;
    }
    .actions { display: flex; gap: 8px; margin: 10px 0 8px; }
    .actions button {
      flex: 1; border-radius: 8px; padding: 10px; cursor: pointer;
      font-size: 14px; font-weight: 700; border: 1px solid #475569;
    }
    .continue { background: #1d4ed8; color: #fff; border-color: #1d4ed8; }
    .cancel { background: transparent; color: #e2e8f0; }
    .actions button:disabled { opacity: 0.5; cursor: default; }
    .disclaimer { font-size: 11px; color: #94a3b8; margin: 0; }
    .spinner {
      width: 22px; height: 22px; border-radius: 50%;
      border: 3px solid #334155; border-top-color: #93c5fd;
      animation: spin 0.9s linear infinite; margin: 8px auto;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  `;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function factRow(term, value) {
    const wrap = el('div');
    wrap.appendChild(el('dt', null, term));
    wrap.appendChild(el('dd', null, value));
    return wrap;
  }

  function walletLabel(wallet) {
    if (!wallet || typeof wallet !== 'object') return 'detected wallet';
    if (wallet.name) return wallet.source === 'eip-6963' ? `${wallet.name} (EIP-6963)` : wallet.name;
    if (wallet.source === 'eip-6963') return 'EIP-6963 wallet';
    if (wallet.source === 'window.ethereum.providers[]') return 'injected provider (multi-wallet)';
    return 'injected provider (window.ethereum)';
  }

  function siteLabel(url) {
    try {
      return new URL(url).hostname || url || 'unknown site';
    } catch {
      return url || 'unknown site';
    }
  }

  function txLines(tx) {
    if (!tx || typeof tx !== 'object') return ['unavailable'];
    const lines = [];
    lines.push(`to: ${tx.to || 'MISSING — cannot verify recipient'}`);
    if (tx.from) lines.push(`from: ${tx.from}`);
    if (tx.value) lines.push(`value: ${tx.value}`);
    if (tx.data) lines.push(`data: ${tx.data.length > 280 ? tx.data.slice(0, 280) + '…' : tx.data}`);
    return lines.length > 0 ? lines : ['(empty transaction object)'];
  }

  function renderAssessment(body, assessment) {
    if (!assessment) {
      body.appendChild(el('div', 'spinner'));
      body.appendChild(el('p', 'summary', 'Evaluating with the local backend. The wallet has NOT been contacted yet.'));
      return;
    }
    if (assessment.ok === false) {
      body.appendChild(el('p', 'warn', `Assessment failed: ${assessment.error || 'unknown error'}`));
      body.appendChild(el('p', 'summary', 'You may continue UNVERIFIED to the wallet, or cancel. Nothing has been forwarded.'));
      return;
    }
    if (assessment.unsupported) {
      body.appendChild(el('p', 'warn', `Unsupported request: ${assessment.method || 'message signature'}. Assertara cannot evaluate its authorization.`));
      body.appendChild(el('p', 'summary', 'You may continue UNVERIFIED to the wallet, or cancel. Nothing has been forwarded.'));
      return;
    }
    const ev = assessment.evidence || {};
    body.appendChild(el('p', 'summary', ev.summary || 'No summary returned.'));
    const facts = el('dl', 'facts');
    facts.appendChild(factRow('Confidence', F.formatConfidence(ev.confidence)));
    facts.appendChild(factRow('Analysis', F.reasoningOriginLabel(ev.reasoningOrigin)));
    const decoded = ev.decodedTransaction || {};
    facts.appendChild(factRow('Contract', decoded.contractName
      ? `${decoded.contractName} (${F.shortAddress(decoded.contract)})`
      : F.shortAddress(decoded.contract)));
    facts.appendChild(factRow('Function', decoded.functionName || '—'));
    facts.appendChild(factRow('Unlimited approval', decoded.isUnlimitedApproval ? 'YES' : 'No'));
    facts.appendChild(factRow('Verdict safeguards', F.safeguardText(
      ev.verdictSafeguards !== undefined ? ev.verdictSafeguards : ev.verdictSafeguard
    )));
    facts.appendChild(factRow('Confidence cap', F.confidenceCapText(ev.confidenceCap)));
    const visual = ev.visualEvidence || {};
    const sources = Array.isArray(visual.textSources) ? visual.textSources : [];
    facts.appendChild(factRow('Screenshot', assessment.screenshotIncluded ? 'captured' : 'unavailable — page context only'));
    facts.appendChild(factRow('OCR mode', visual.ocrMode || 'unavailable'));
    facts.appendChild(factRow('SAM detections', Array.isArray(visual.samDetections) ? String(visual.samDetections.length) : 'unavailable'));
    if (sources.length > 0) {
      facts.appendChild(factRow('Text sources', sources.map((s) => `${s.source || '?'}: ${s.available ? 'available' : 'unavailable'}`).join('; ')));
    }
    facts.appendChild(factRow('Simulation', F.simulationStatus(ev.simulation)));
    body.appendChild(facts);
    const findings = Array.isArray(ev.ruleFindings) ? ev.ruleFindings : [];
    body.appendChild(el('p', 'summary', findings.length > 0 ? 'Security findings:' : 'Security findings: none.'));
    if (findings.length > 0) {
      const list = el('ul', 'rules');
      for (const r of findings) {
        list.appendChild(el('li', null, `${r.ruleId || 'finding'} [${r.severity || 'info'}]: ${r.description || ''}`));
      }
      body.appendChild(list);
    }
    const cmp = ev.intentComparison;
    if (cmp && typeof cmp === 'object') {
      body.appendChild(el('p', 'summary', `Displayed-vs-decoded comparison: ${cmp.outcome || JSON.stringify(cmp).slice(0, 200)}`));
    }
    body.appendChild(el('p', 'summary', `Recommended: ${ev.recommendedAction || 'review the evidence above before proceeding'}.`));
    body.appendChild(el('p', 'disclaimer', ev.safetyNotice || 'Advisory only — not a guarantee of safety.'));
  }

  const cards = new Map(); // requestId -> card element

  function ensureHost() {
    let host = document.getElementById(HOST_ID);
    if (!host) {
      host = document.createElement('div');
      host.id = HOST_ID;
      document.documentElement.appendChild(host);
    }
    let shadow = host.__assertaraShadow;
    if (!shadow) {
      shadow = host.attachShadow({ mode: 'closed' });
      shadow.appendChild(el('style', null, STYLE));
      const dim = el('div', 'dim');
      dim.id = 'assertara-gate-dim';
      shadow.appendChild(dim);
      host.__assertaraShadow = shadow;
    }
    return host;
  }

  function dimOf(host) {
    return host.__assertaraShadow.querySelector('#assertara-gate-dim');
  }

  function removeCard(requestId) {
    const card = cards.get(requestId);
    if (card) {
      cards.delete(requestId);
      card.remove();
    }
    const host = document.getElementById(HOST_ID);
    if (host && cards.size === 0) host.remove();
  }

  function sendDecision(requestId, decision, card) {
    try {
      for (const btn of card.querySelectorAll('button')) btn.disabled = true;
    } catch {
      /* ignore */
    }
    try {
      chrome.runtime.sendMessage({ type: 'ASSERTARA_DECIDE', requestId, decision });
    } catch {
      /* service worker unreachable: buttons stay disabled, request stays held */
    }
  }

  function renderView(view) {
    if (!view || typeof view.requestId !== 'string') return;
    if (view.closed) {
      removeCard(view.requestId);
      return;
    }
    const host = ensureHost();
    const dim = dimOf(host);
    let card = cards.get(view.requestId);
    if (!card) {
      card = el('div', 'card');
      cards.set(view.requestId, card);
      dim.prepend(card);
    }
    card.innerHTML = '';
    const head = el('div', 'head');
    head.appendChild(el('span', 'brand', 'Assertara gate'));
    const verdict = view.assessment && view.assessment.evidence ? view.assessment.evidence.verdict : null;
    head.appendChild(el('span', `badge ${F.verdictClass(verdict || 'uncertain')}`,
      verdict ? F.verdictLabel(verdict) : (view.status === 'AWAITING_USER_DECISION' || view.status === 'EVALUATION_FAILED' || view.status === 'UNSUPPORTED' ? 'DECIDE' : 'HELD')));
    head.appendChild(el('span', 'brand', siteLabel(view.pageUrl)));
    card.appendChild(head);

    const body = el('div', 'body');
    body.appendChild(el('p', 'summary', `Held ${view.method || 'request'} from this page. The wallet has NOT been contacted.`));
    const facts = el('dl', 'facts');
    facts.appendChild(factRow('Request type', `${view.method || 'unknown'}${view.kind === 'message' ? ' (message signature)' : ''}`));
    facts.appendChild(factRow('Wallet', walletLabel(view.wallet)));
    facts.appendChild(factRow('Chain', view.chainId || 'not reported'));
    if (view.kind !== 'message' && view.tx) {
      for (const line of txLines(view.tx)) {
        facts.appendChild(factRow('Transaction', line));
      }
    } else if (view.kind === 'message') {
      facts.appendChild(factRow('Signing payload', 'shown to the wallet only — Assertara cannot evaluate message authorizations'));
    }
    body.appendChild(facts);
    renderAssessment(body, view.assessment);

    const actions = el('div', 'actions');
    const btnContinue = el('button', 'continue', view.assessment && view.assessment.ok === false ? 'CONTINUE TO WALLET (UNVERIFIED)' : 'CONTINUE TO WALLET');
    const btnCancel = el('button', 'cancel', 'CANCEL REQUEST');
    const decided = view.status === 'FORWARDED_TO_WALLET' || view.status === 'USER_CANCELLED' || view.status === 'EXPIRED';
    btnContinue.disabled = decided || !(view.status === 'AWAITING_USER_DECISION' || view.status === 'EVALUATION_FAILED' || view.status === 'UNSUPPORTED');
    btnCancel.disabled = decided || view.status === 'EXPIRED';
    btnContinue.addEventListener('click', () => sendDecision(view.requestId, 'continue', card));
    btnCancel.addEventListener('click', () => sendDecision(view.requestId, 'cancel', card));
    actions.appendChild(btnContinue);
    actions.appendChild(btnCancel);
    body.appendChild(actions);
    if (view.status === 'EXPIRED') {
      body.appendChild(el('p', 'warn', 'This request expired and was never forwarded. Reload the page to try again.'));
    }
    body.appendChild(el('p', 'disclaimer', 'Assertara never approves inside your wallet. Continuing opens the wallet\u2019s normal confirmation, where you decide again.'));
    card.appendChild(body);
  }

  function postToPage(message) {
    try {
      window.postMessage({ __assertara: Gate.PROTOCOL, direction: 'iso-to-main', ...message }, '*');
    } catch {
      /* page gone */
    }
  }

  function onPageMessage(event) {
    try {
      if (!Gate || !event || event.source !== window) return;
      const msg = Gate.validateMainMessage(event.data);
      if (!msg) return;
      if (msg.type === 'HELLO') {
        postToPage({ type: 'BRIDGE_READY' });
        return;
      }
      if (msg.type === 'BYPASSED') {
        try {
          chrome.runtime.sendMessage({ type: 'ASSERTARA_GATE_BYPASSED', requestId: msg.requestId, method: msg.method });
        } catch {
          /* ignore */
        }
        return;
      }
      if (msg.type === 'GATE_EXPIRED') {
        // The page already rejected locally; tell the worker to mark the
        // record EXPIRED and close the card.
        try {
          chrome.runtime.sendMessage({ type: 'ASSERTARA_GATE_EXPIRED', requestId: msg.requestId });
        } catch {
          /* worker unreachable: card stays until next contact */
        }
        return;
      }
      if (msg.type === 'TX_MUTATED') {
        // The page refused release: live arguments no longer match the
        // approved digest. Tell the worker to close the record honestly.
        try {
          chrome.runtime.sendMessage({ type: 'ASSERTARA_TX_MUTATED', requestId: msg.requestId });
        } catch {
          /* worker unreachable: card stays until next contact */
        }
        return;
      }
      // INTERCEPTED: ACK immediately so the page holds the request, then
      // hand the sanitized payload to the service worker for gating.
      postToPage({ type: 'ACK', requestId: msg.requestId });
      try {
        chrome.runtime.sendMessage({
          type: 'ASSERTARA_GATED_REQUEST',
          requestId: msg.requestId,
          method: msg.method,
          kind: msg.kind,
          tx: msg.tx,
          txDigest: msg.txDigest || null,
          chainId: msg.chainId,
          wallet: msg.wallet,
          pageContext: msg.pageContext
        });
      } catch {
        /* SW unreachable: request stays held; timeout path in SW cannot run,
           so release the UI honestly via expiry sweep on next contact */
      }
    } catch {
      /* never let page messages break the bridge */
    }
  }

  function onWorkerMessage(message, sender, sendResponse) {
    try {
      if (!Gate || !sender || sender.id !== chrome.runtime.id) return false;
      if (!message || typeof message.type !== 'string') return false;
      if (message.type === 'ASSERTARA_GATE_UPDATE') {
        renderView(message.view);
        if (typeof sendResponse === 'function') sendResponse({ ok: true });
        return true;
      }
      if (message.type === 'ASSERTARA_GATE_DECISION') {
        const requestId = typeof message.requestId === 'string' ? message.requestId : '';
        if (requestId && (message.decision === 'continue' || message.decision === 'cancel')) {
          postToPage({ type: 'DECISION', requestId, decision: message.decision, reason: typeof message.reason === 'string' ? message.reason : null, approvedDigest: typeof message.approvedDigest === 'string' ? message.approvedDigest : null });
          removeCard(requestId);
        }
        if (typeof sendResponse === 'function') sendResponse({ ok: true });
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  try {
    window.addEventListener('message', onPageMessage);
    if (chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener(onWorkerMessage);
    }
    if (chrome.runtime && typeof chrome.runtime.sendMessage === 'function') {
      chrome.runtime.sendMessage({ type: 'ASSERTARA_TAB_OBSERVED' }).catch(() => {});
    }
  } catch {
    /* bridge wiring failed: gate cannot run on this page */
  }
})();
