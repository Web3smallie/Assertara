/**
 * Assertara popup: page display, transaction form, inspection trigger, results.
 * Sends inspection work to the service worker; renders the backend's own
 * evidence bundle. Never handles API keys.
 */
(function () {
  const F = globalThis.AssertaraFormat;
  const BACKEND_BASE_URL = 'http://localhost:3001';

  // The repository's own established demo transactions (see test/unit/integration.test.js).
  // Clearly labeled as demos; evaluated for real by the backend, never mocked here.
  const DEMO_TRANSACTIONS = {
    phishing: {
      label: 'Demo: airdrop claim',
      from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      data: '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      value: '0x0'
    },
    swap: {
      label: 'Demo: DEX swap',
      from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
      data: '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4',
      value: '0xde0b6b3a7640000'
    },
    ambiguous: {
      label: 'Demo: unknown contract',
      from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      to: '0x1234567890123456789012345678901234567890',
      data: '0x79c65092000000000000000000000000000000000000000000000000000000000000002a',
      value: '0x0'
    }
  };

  const $ = (id) => document.getElementById(id);
  let activeTab = null;
  let lastEvidence = null;

  function showOnly(sectionId) {
    for (const id of ['formSection', 'loadingSection', 'errorSection', 'resultSection']) {
      $(id).classList.toggle('hidden', id !== sectionId);
    }
  }

  function showFormError(message) {
    const el = $('formError');
    el.textContent = message;
    el.classList.toggle('hidden', !message);
  }

  function showError(message) {
    $('errorText').textContent = message;
    showOnly('errorSection');
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
    } catch {
      badge.textContent = 'Backend offline';
      badge.className = 'backend-status offline';
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

  function readTransactionForm() {
    return {
      to: $('txTo').value.trim(),
      data: $('txData').value.trim() || undefined,
      value: $('txValue').value.trim() || undefined,
      from: $('txFrom').value.trim() || undefined
    };
  }

  function fillDemo(name) {
    const demo = DEMO_TRANSACTIONS[name];
    if (!demo) return;
    $('txTo').value = demo.to;
    $('txData').value = demo.data;
    $('txValue').value = demo.value;
    $('txFrom').value = demo.from;
    $('txSourceNote').innerHTML = `Transaction source: <strong>${F.escapeHtml(demo.label)}</strong> — repository fixture, evaluated for real by the backend.`;
    showFormError('');
  }

  async function runInspection() {
    showFormError('');
    const tx = readTransactionForm();
    if (!F.isValidAddress(tx.to)) {
      showFormError('Enter a valid 0x recipient address (40 hex characters).');
      return;
    }
    if (!activeTab || !activeTab.id) {
      showFormError('No accessible active tab. Open a dApp page and try again.');
      return;
    }
    $('inspectBtn').disabled = true;
    $('loadingText').textContent = 'Collecting page evidence…';
    showOnly('loadingSection');
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ASSERTARA_INSPECT',
        tabId: activeTab.id,
        transaction: tx
      });
      if (!response || response.ok !== true) {
        showError(response && response.error ? response.error : 'Inspection failed without details.');
        return;
      }
      renderResult(response.evidence, response.meta || {});
    } catch (err) {
      showError(`Could not reach the extension service worker: ${err.message}`);
    } finally {
      $('inspectBtn').disabled = false;
    }
  }

  function renderResult(evidence, meta) {
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
    $('resultAction').textContent = evidence.recommendedAction || 'See summary above';
    const parts = [];
    parts.push(meta.screenshotIncluded ? 'Screenshot: captured.' : 'Screenshot: unavailable — page context only.');
    parts.push(`Page text collected: ${meta.visibleTextChars || 0} chars.`);
    parts.push(`Source: ${meta.txSource === 'demo' ? 'labeled demo transaction' : 'manually supplied — verify against your wallet'}.`);
    parts.push(`Analysis: ${F.reasoningOriginLabel(evidence.reasoningOrigin)}.`);
    $('evidenceNote').textContent = parts.join(' ');
    showOnly('resultSection');
  }

  async function showOverlay() {
    if (!lastEvidence || !activeTab || !activeTab.id) return;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ASSERTARA_SHOW_OVERLAY',
        tabId: activeTab.id,
        evidence: lastEvidence
      });
      if (!response || response.ok !== true) {
        showError(response && response.error ? response.error : 'Could not display the on-page overlay.');
      } else {
        window.close();
      }
    } catch (err) {
      showError(`Could not display the on-page overlay: ${err.message}`);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    loadActiveTab().catch(() => {});
    refreshBackendStatus().catch(() => {});
    $('inspectBtn').addEventListener('click', runInspection);
    $('retryBtn').addEventListener('click', () => showOnly('formSection'));
    $('newBtn').addEventListener('click', () => showOnly('formSection'));
    $('overlayBtn').addEventListener('click', showOverlay);
    for (const btn of document.querySelectorAll('.demo-btn')) {
      btn.addEventListener('click', () => fillDemo(btn.dataset.demo));
    }
    for (const id of ['txTo', 'txData', 'txValue', 'txFrom']) {
      $(id).addEventListener('input', () => {
        $('txSourceNote').innerHTML = 'Transaction source: <strong>manual entry</strong> — verify every field against your wallet.';
      });
    }
  });
})();
