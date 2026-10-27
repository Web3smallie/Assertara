/**
 * Assertara service worker (Manifest V3).
 * Orchestrates user-initiated inspections: collects page context, captures a
 * screenshot when possible, posts the backend's own request schema, and shows
 * the on-page overlay. No wallet interaction, no signing, no API keys here.
 */
importScripts('shared/format.js');

const BACKEND_BASE_URL = 'http://localhost:3001';
const EVALUATE_TIMEOUT_MS = 120000;

async function collectPageContext(tabId) {
  const [injection] = await chrome.scripting.executeScript({
    target: { tabId },
    files: ['content/context.js']
  });
  const ctx = (injection && injection.result) || {};
  return {
    url: typeof ctx.url === 'string' ? ctx.url : '',
    title: typeof ctx.title === 'string' ? ctx.title : '',
    visibleText: typeof ctx.visibleText === 'string' ? ctx.visibleText : ''
  };
}

async function captureScreenshot(windowId) {
  try {
    const dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: 'png' });
    return typeof dataUrl === 'string' && dataUrl.startsWith('data:image/') ? dataUrl : null;
  } catch {
    return null; // e.g. chrome:// pages or denied capture: proceed without a screenshot
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
      throw new Error(`Backend timed out after ${EVALUATE_TIMEOUT_MS / 1000}s. It may still be running SAM/OCR/reasoning; try again.`);
    }
    if (err instanceof TypeError) {
      throw new Error(`Cannot reach the backend at ${BACKEND_BASE_URL}. Start it with "npm start" and try again.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function handleInspect({ tabId, transaction }) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab) throw new Error('Active tab is no longer available.');

  let pageContext = { url: tab.url || '', title: tab.title || '', visibleText: '' };
  try {
    const collected = await collectPageContext(tabId);
    pageContext = {
      url: collected.url || tab.url || '',
      title: collected.title || tab.title || '',
      visibleText: collected.visibleText
    };
  } catch {
    // Restricted pages (chrome://, web store): fall back to tab metadata.
  }

  const screenshot = await captureScreenshot(tab.windowId);

  // Exact backend schema: { screenshot?, pageContext?, transaction }.
  // Collected DOM text travels as pageContext.visibleText (provenance DOM_TEXT).
  const pageContextOut = { title: pageContext.title, url: pageContext.url };
  if (pageContext.visibleText) pageContextOut.visibleText = pageContext.visibleText;
  const payload = {
    pageContext: pageContextOut,
    transaction: {
      to: transaction.to,
      ...(transaction.from ? { from: transaction.from } : {}),
      ...(transaction.data ? { data: transaction.data } : {}),
      ...(transaction.value ? { value: transaction.value } : {})
    }
  };
  if (screenshot) payload.screenshot = screenshot;

  const evidence = await postEvaluation(payload);
  return {
    ok: true,
    evidence,
    meta: {
      screenshotIncluded: Boolean(screenshot),
      visibleTextChars: pageContext.visibleText.length
    }
  };
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

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      if (!message || typeof message.type !== 'string') {
        return { ok: false, error: 'Unknown extension message.' };
      }
      if (message.type === 'ASSERTARA_INSPECT') {
        if (!message.transaction || typeof message.transaction.to !== 'string') {
          return { ok: false, error: 'A transaction recipient address (to) is required.' };
        }
        return await handleInspect(message);
      }
      if (message.type === 'ASSERTARA_SHOW_OVERLAY') {
        if (!message.evidence) return { ok: false, error: 'No evidence bundle to display.' };
        return await handleShowOverlay(message);
      }
      return { ok: false, error: `Unknown message type: ${message.type}` };
    } catch (err) {
      return { ok: false, error: err.message || 'Inspection failed.' };
    }
  })().then(sendResponse);
  return true; // async response
});
