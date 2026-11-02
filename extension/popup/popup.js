/**
 * Assertara popup: protection status, held wallet requests with working
 * Continue/Cancel decisions, and the backend's own evidence bundle.
 * Detection and holding happen in the page; the service worker owns the
 * gate state. This popup mirrors the on-page interstitial: deciding here
 * releases the exact pending request, first decision wins. Never handles
 * API keys.
 */
(function () {
  const F = globalThis.AssertaraFormat;
  const BACKEND_BASE_URL = 'http://localhost:3001';

  const $ = (id) => document.getElementById(id);
  let activeTab = null;
  let lastEvidence = null;
  let pendingViews = [];

  function showOnly(sectionId) {
    for (const id of ['pendingSection', 'resultSection', 'errorSection']) {
      $(id).classList.toggle('hidden', id !== sectionId);
    }
  }

  function showNone() {
    for (const id of ['pendingSection', 'resultSection', 'errorSection']) {
      $(id).classList.add('hidden');
    }
  }

  function setProtection(status, detail) {
    $('protectionStatus').textContent = status;
    $('protectionDetail').textContent = detail;
  }

  async function refreshBackendStatus() {
    const badge = $('backendStatus');
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(`${BACKEND_BASE_URL}/health`, { signal: controller.signal });
      clearTimeout(timer);
      const healthy = res.ok;
      badge.textContent = healthy ? 'Backend online' : 'Backend error';
      badge.className = `backend-status ${healthy ? 'online' : 'offline'}`;
      return healthy;
    } catch {
      badge.textContent = 'Backend offline';
      badge.className = 'backend-status offline';
      return false;
    }
  }

  async function loadActiveTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tab || null;
    if (!tab || !tab.url) {
      $('pageDomain').textContent = 'No accessible page';
      $('pageUrl').textContent = 'Open a dApp page, then reopen Assertara.';
      $('pageTitle').textContent = '—';
      return;
    }
    let domain = tab.url;
    try {
      domain = new URL(tab.url).hostname || tab.url;
    } catch {
      /* keep raw url */
    }
    $('pageDomain').textContent = domain;
    $('pageUrl').textContent = tab.url;
    $('pageTitle').textContent = tab.title || '—';
  }

  function walletLabel(wallet) {
    if (!wallet || typeof wallet !== 'object') return 'detected wallet';
    if (wallet.name) return wallet.source === 'eip-6963' ? `${wallet.name} (EIP-6963)` : wallet.name;
    if (wallet.source === 'eip-6963') return 'EIP-6963 wallet';
    if (wallet.source === 'window.ethereum.providers[]') return 'injected provider (multi-wallet)';
    return 'injected provider (window.ethereum)';
  }

  function verdictFor(view) {
    if (view.assessment && view.assessment.evidence) return view.assessment.evidence.verdict;
    return null;
  }

  async function sendDecision(requestId, decision) {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'ASSERTARA_DECIDE', requestId, decision });
      if (!response || response.ok !== true) {
        $('errorText').textContent = (response && response.error) ? response.error : 'The decision was rejected (the request may already be decided or expired).';
        showOnly('errorSection');
        return;
      }
      await refresh();
    } catch (err) {
      $('errorText').textContent = `Could not reach the extension service worker: ${err.message}`;
      showOnly('errorSection');
    }
  }

  function renderPendingList() {
    const list = $('pendingList');
    list.innerHTML = '';
    for (const view of pendingViews) {
      const card = document.createElement('div');
      card.className = 'page-card';
      const title = document.createElement('div');
      title.className = 'page-domain';
      const verdict = verdictFor(view);
      title.textContent = `${view.method || 'request'}${verdict ? ` — ${F.verdictLabel(verdict)}` : ''}`;
      card.appendChild(title);
      const sub = document.createElement('div');
      sub.className = 'page-title';
      const parts = [];
      if (view.kind === 'message') parts.push('message signature (cannot be evaluated)');
      else if (view.tx && view.tx.to) parts.push(`to ${F.shortAddress(view.tx.to)}`);
      else parts.push('recipient missing');
      parts.push(walletLabel(view.wallet));
      if (view.chainId) parts.push(`chain ${view.chainId}`);
      sub.textContent = parts.join(' · ');
      card.appendChild(sub);
      const state = document.createElement('div');
      state.className = 'page-title';
      if (view.status === 'EVALUATING' || view.status === 'DETECTED') {
        state.textContent = 'Evaluating — the wallet has NOT been contacted.';
      } else if (view.assessment && view.assessment.ok === false) {
        state.textContent = `Assessment failed: ${view.assessment.error || 'unknown error'} Continuing is UNVERIFIED.`;
      } else if (view.assessment && view.assessment.unsupported) {
        state.textContent = 'Unsupported request type — Assertara cannot evaluate it. Continuing is UNVERIFIED.';
      } else if (view.assessment && view.assessment.evidence) {
        state.textContent = view.assessment.evidence.summary || 'Assessment ready.';
      } else {
        state.textContent = `Status: ${view.status}`;
      }
      card.appendChild(state);
      const row = document.createElement('div');
      row.className = 'row';
      const canContinue = view.status === 'AWAITING_USER_DECISION' || view.status === 'EVALUATION_FAILED' || view.status === 'UNSUPPORTED';
      const terminal = view.status === 'FORWARDED_TO_WALLET' || view.status === 'USER_CANCELLED' || view.status === 'EXPIRED';
      if (canContinue) {
        const btnContinue = document.createElement('button');
        btnContinue.type = 'button';
        btnContinue.textContent = (view.assessment && view.assessment.ok === false) || (view.assessment && view.assessment.unsupported)
          ? 'Continue unverified'
          : 'Continue to wallet';
        btnContinue.addEventListener('click', () => sendDecision(view.requestId, 'continue'));
        row.appendChild(btnContinue);
      }
      if (!terminal) {
        // Cancel never forwards, so it is safe while evaluating too.
        const btnCancel = document.createElement('button');
        btnCancel.type = 'button';
        btnCancel.textContent = 'Cancel request';
        btnCancel.addEventListener('click', () => sendDecision(view.requestId, 'cancel'));
        row.appendChild(btnCancel);
      }
      if (view.assessment && view.assessment.evidence) {
        const btnDetails = document.createElement('button');
        btnDetails.type = 'button';
        btnDetails.textContent = 'Details';
        btnDetails.addEventListener('click', () => renderResult(view.assessment.evidence, view.assessment, view));
        row.appendChild(btnDetails);
      }
      if (row.children.length > 0) card.appendChild(row);
      list.appendChild(card);
    }
  }

  function renderResult(evidence, meta, view) {
    lastEvidence = evidence;
    const badge = $('verdictBadge');
    badge.textContent = F.verdictLabel(evidence.verdict);
    badge.className = `verdict-badge ${F.verdictClass(evidence.verdict)}`;
    $('resultSummary').textContent = evidence.summary || 'No summary returned.';
    $('resultConfidence').textContent = F.formatConfidence(evidence.confidence);
    const decoded = evidence.decodedTransaction || {};
    $('resultContract').textContent = decoded.contractName
      ? `${decoded.contractName} (${F.shortAddress(decoded.contract)})`
      : F.shortAddress(decoded.contract);
    $('resultFunction').textContent = decoded.functionName || '—';
    $('resultSafeguards').textContent = F.safeguardText(
      evidence.verdictSafeguards !== undefined ? evidence.verdictSafeguards : evidence.verdictSafeguard
    );
    $('resultCap').textContent = F.confidenceCapText(evidence.confidenceCap);
    $('resultAction').textContent = evidence.recommendedAction || 'See summary above';
    const parts = [];
    parts.push(meta.screenshotIncluded ? 'Screenshot: captured.' : 'Screenshot: unavailable — page context only.');
    parts.push(`Page text collected: ${meta.visibleTextChars || 0} chars.`);
    parts.push(`Wallet request: ${view.method || 'unknown'} via ${walletLabel(view.wallet)}.`);
    parts.push(`Analysis: ${F.reasoningOriginLabel(evidence.reasoningOrigin)}.`);
    $('evidenceNote').textContent = parts.join(' ');
    showOnly('resultSection');
  }

  function renderState(state) {
    lastEvidence = null;
    pendingViews = Array.isArray(state.pending) ? state.pending : [];
    const notes = Array.isArray(state.notes) ? state.notes : [];
    if (pendingViews.length > 0) {
      const awaiting = pendingViews.filter((v) => v.status === 'AWAITING_USER_DECISION' || v.status === 'EVALUATION_FAILED' || v.status === 'UNSUPPORTED').length;
      setProtection(
        awaiting > 0 ? `${pendingViews.length} held request${pendingViews.length === 1 ? '' : 's'} — decision needed` : `${pendingViews.length} held request${pendingViews.length === 1 ? '' : 's'} — evaluating`,
        'The wallet has NOT been contacted for these requests. Nothing continues without your explicit choice.'
      );
      renderPendingList();
      showOnly('pendingSection');
      return;
    }
    if (!state.observed) {
      setProtection('Not protected on this tab', 'The gate did not load here (restricted page or unsupported scheme). nothing is held.');
      showNone();
      return;
    }
    if (notes.length > 0) {
      setProtection('Watching this tab', notes[notes.length - 1].text);
    } else {
      setProtection('Watching this tab', 'Supported wallet requests will be held here for your decision before reaching the wallet.');
    }
    showNone();
  }

  async function refresh() {
    await refreshBackendStatus().catch(() => false);
    await loadActiveTab().catch(() => {});
    if (!activeTab || typeof activeTab.id !== 'number') {
      setProtection('No accessible tab', 'Open a dApp page, then reopen Assertara.');
      showNone();
      return;
    }
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ASSERTARA_GET_TAB_STATE',
        tabId: activeTab.id
      });
      if (!response || response.ok !== true) {
        setProtection('Service worker unreachable', 'Could not load protection state. Try reopening the popup.');
        showNone();
        return;
      }
      renderState(response.state || { observed: false, pending: [], notes: [] });
    } catch (err) {
      setProtection('Service worker unreachable', `Could not load protection state: ${err.message}`);
      showNone();
    }
  }

  async function showOverlay() {
    if (!lastEvidence || !activeTab || typeof activeTab.id !== 'number') return;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ASSERTARA_SHOW_OVERLAY',
        tabId: activeTab.id,
        evidence: lastEvidence
      });
      if (!response || response.ok !== true) {
        $('errorText').textContent = response && response.error ? response.error : 'Could not display the on-page overlay.';
        showOnly('errorSection');
      } else {
        window.close();
      }
    } catch (err) {
      $('errorText').textContent = `Could not display the on-page overlay: ${err.message}`;
      showOnly('errorSection');
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    refresh().catch(() => {});
    $('retryBtn').addEventListener('click', refresh);
    $('refreshBtn').addEventListener('click', refresh);
    $('overlayBtn').addEventListener('click', showOverlay);
    $('backBtn').addEventListener('click', () => {
      renderPendingList();
      showOnly('pendingSection');
    });
  });
})();
