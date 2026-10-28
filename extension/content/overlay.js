/**
 * Assertara on-page advisory overlay. Injected on demand after an inspection.
 * Renders inside a shadow root so page styles cannot break it (and vice versa).
 * Requires shared/format.js to be injected first (same isolated world).
 */
(function () {
  const HOST_ID = 'assertara-overlay-host';

  const STYLE = `
    :host { all: initial; }
    .panel {
      position: fixed; right: 16px; bottom: 16px; width: 360px; max-width: calc(100vw - 32px);
      max-height: calc(100vh - 32px); overflow-y: auto;
      background: #0f172a; color: #f8fafc;
      border: 1px solid #334155; border-radius: 14px;
      box-shadow: 0 12px 32px rgba(0,0,0,0.5);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      z-index: 2147483647;
    }
    .head { display: flex; align-items: center; gap: 8px; padding: 12px 12px 0; }
    .brand { font-weight: 800; font-size: 13px; letter-spacing: 0.06em; text-transform: uppercase; color: #93c5fd; }
    .badge {
      margin-left: auto; padding: 2px 12px; border-radius: 20px;
      font-weight: 800; font-size: 13px; letter-spacing: 0.04em;
    }
    .badge.match { background: #dcfce7; color: #15803d; }
    .badge.mismatch { background: #fee2e2; color: #b91c1c; }
    .badge.uncertain { background: #fef3c7; color: #92400e; }
    .close {
      border: 1px solid #475569; background: transparent; color: #e2e8f0;
      border-radius: 8px; padding: 2px 9px; cursor: pointer; font-size: 13px;
    }
    .body { padding: 8px 12px 12px; }
    .summary { margin: 4px 0 8px; }
    .facts { margin: 0 0 8px; font-size: 12px; }
    .facts > div { display: flex; gap: 8px; padding: 3px 0; border-top: 1px solid #1e293b; }
    .facts dt { color: #94a3b8; min-width: 118px; }
    .facts dd { margin: 0; word-break: break-all; }
    .rules { margin: 0 0 8px; padding-left: 18px; font-size: 12px; }
    .rules li { margin: 2px 0; }
    .action {
      background: #1e293b; border-radius: 8px; padding: 8px 10px;
      font-size: 13px; margin: 0 0 8px;
    }
    .disclaimer { font-size: 11px; color: #94a3b8; margin: 0; }
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

  function render(host, evidence) {
    const F = globalThis.AssertaraFormat;
    host.innerHTML = '';
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = el('style', null, STYLE);
    const panel = el('div', 'panel');
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-label', 'Assertara transaction advisory');

    const head = el('div', 'head');
    head.appendChild(el('span', 'brand', 'Assertara advisory'));
    const badge = el('span', `badge ${F.verdictClass(evidence.verdict)}`, F.verdictLabel(evidence.verdict));
    head.appendChild(badge);
    const close = el('button', 'close', '✕ Close');
    close.setAttribute('aria-label', 'Close Assertara advisory');
    close.addEventListener('click', () => host.remove());
    head.appendChild(close);
    panel.appendChild(head);

    const body = el('div', 'body');
    body.appendChild(el('p', 'summary', evidence.summary || 'No summary returned.'));

    const decoded = evidence.decodedTransaction || {};
    const facts = el('dl', 'facts');
    facts.appendChild(factRow('Confidence', F.formatConfidence(evidence.confidence)));
    facts.appendChild(factRow('Analysis', F.reasoningOriginLabel(evidence.reasoningOrigin)));
    facts.appendChild(factRow('Contract', decoded.contractName
      ? `${decoded.contractName} (${F.shortAddress(decoded.contract)})`
      : F.shortAddress(decoded.contract)));
    facts.appendChild(factRow('Function', decoded.functionName || '—'));
    facts.appendChild(factRow('Unlimited approval', decoded.isUnlimitedApproval ? 'YES' : 'No'));
    body.appendChild(facts);

    const findings = Array.isArray(evidence.ruleFindings) ? evidence.ruleFindings : [];
    const rulesTitle = el('p', 'summary', findings.length > 0 ? 'Security findings:' : 'Security findings: none.');
    body.appendChild(rulesTitle);
    if (findings.length > 0) {
      const list = el('ul', 'rules');
      for (const r of findings) {
        list.appendChild(el('li', null, `${r.ruleId || 'finding'} [${r.severity || 'info'}]: ${r.description || ''}`));
      }
      body.appendChild(list);
    }

    body.appendChild(el('p', 'action', `Simulation: ${F.simulationStatus(evidence.simulation)}`));
    body.appendChild(el('p', 'action', `Recommended: ${evidence.recommendedAction || 'review the evidence above before proceeding'}.`));

    const visual = evidence.visualEvidence || {};
    const sources = Array.isArray(visual.textSources) ? visual.textSources : [];
    if (sources.length > 0) {
      body.appendChild(el('p', 'summary', 'Page text evidence:'));
      const sourceList = el('ul', 'rules');
      for (const s of sources) {
        const shown = s.available ? ((s.text || '').slice(0, 160) || '(empty)') : 'unavailable';
        sourceList.appendChild(el('li', null, `${s.source || 'UNKNOWN'}: ${shown}`));
      }
      body.appendChild(sourceList);
    }
    body.appendChild(el('p', 'disclaimer', `Page evidence: ${(visual.extractedText || 'no text extracted').slice(0, 160)}`));
    body.appendChild(el('p', 'disclaimer', evidence.safetyNotice || 'Advisory only — not a guarantee of safety.'));

    panel.appendChild(body);
    shadow.appendChild(style);
    shadow.appendChild(panel);
  }

  function show(evidence) {
    if (!globalThis.AssertaraFormat) {
      throw new Error('Assertara format helpers are not loaded.');
    }
    let host = document.getElementById(HOST_ID);
    if (!host) {
      host = document.createElement('div');
      host.id = HOST_ID;
      document.documentElement.appendChild(host);
    }
    render(host, evidence);
    return true;
  }

  function hide() {
    const host = document.getElementById(HOST_ID);
    if (host) host.remove();
  }

  globalThis.__assertaraOverlay = { show, hide };
})();
