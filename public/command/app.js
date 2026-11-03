/* Assertara Command Centre — read-only live telemetry client.
 * Every rendered state comes from real backend events (trace snapshot
 * + SSE stream + status/record endpoints). Nothing here is simulated:
 * components appear only when the backend records them, and every
 * label falls back to an honest "not available" when its source is
 * absent. This UI cannot influence any authorization decision. */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const SHIELD_SVG = '<svg viewBox="0 0 36 36"><path d="M18 3 31 9v9c0 8-6 12.5-13 15C11 30.5 5 26 5 18V9z" fill="#eff6ff" stroke="#2563eb" stroke-width="2.5" stroke-linejoin="round"/><path d="M12 24 18 11l6 13" stroke="#06b6d4" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/><circle cx="18" cy="11" r="2.4" fill="#0d9488"/></svg>';

  const state = {
    traces: [],
    activeId: null,
    snap: null,
    spans: new Map(), // key -> span (key: component#index for repeats)
    appliedSeq: new Set(), // SSE event seqs already applied (replay guard)
    source: null,
    status: null,
    record: null,
    health: null,
    lastProposal: null, // { scenario, objective, transaction, approval, requestId, mandateChecks, mandate, txDigest, proposeMs }
    signMs: null,
    receiptMs: null,
    signerBase: new URLSearchParams(window.location.search).get('signer') || '',
    pollTimer: null,
    listTimer: null,
    running: false,
    selectedStage: null,
    activeScenario: null
  };

  /* Investigation journey: telemetry components grouped into the ten
   * user-facing stages. Stages derive their state ONLY from recorded
   * spans (plus request status for decision/execution). */
  const STAGES = [
    { id: 'request', label: 'Request received', comps: ['agent-receiver'] },
    { id: 'evidence', label: 'Evidence assembled', comps: ['agent-evidence', 'evidence-packer', 'chainstate', 'counterparty-labels', 'freshness', 'sam', 'ocr', 'visual-association'] },
    { id: 'analysis', label: 'Transaction analysed', comps: ['decoder', 'proxy-resolution', 'contract-identity', 'subcalls', 'effects', 'composition', 'bridge', 'approval-necessity', 'deadlines', 'comparison', 'history', 'chain-verification', 'simulation-pre', 'explicit-intent', 'evidence-graph'] },
    { id: 'ai', label: 'AI investigation', comps: ['prompt-select', 'muse-spark'] },
    { id: 'verify', label: 'Security verification', comps: ['reasoning-validation', 'reference-validation', 'support-validation', 'reconciliation', 'semantic-claims', 'visual-role-check', 'safeguards', 'simulation-post'] },
    { id: 'mandate', label: 'Mandate & policy', comps: ['mandate-eval', 'subcall-bind', 'policy-decision'] },
    { id: 'decide', label: 'Authorization decision', comps: ['approval-issue'], decision: true },
    { id: 'execute', label: 'Transaction execution', comps: ['signer-call'], execution: true },
    { id: 'receipt', label: 'Receipt verification', comps: ['receipt-verify', 'effect-verify'] },
    { id: 'respond', label: 'Agent response', comps: ['persistence', 'agent-response', 'evidence-bundle'] }
  ];

  /* Technical inspector groupings (§4): backend span groups mapped to
   * the six logical inspection groups. */
  const INSPECTOR_GROUPS = [
    'Evidence & input processing',
    'Transaction analysis',
    'AI reasoning',
    'Security verification',
    'Authorization & execution',
    'Persistence & response',
    'Other'
  ];
  const AUTHZ_COMPS = new Set(['mandate-eval', 'subcall-bind', 'policy-decision', 'approval-issue', 'signer-call', 'receipt-verify', 'effect-verify']);
  const FINISH_COMPS = new Set(['persistence', 'agent-response', 'evidence-bundle']);
  function inspectorGroup(s) {
    if (FINISH_COMPS.has(s.component)) return 'Persistence & response';
    if (AUTHZ_COMPS.has(s.component)) return 'Authorization & execution';
    if (s.group === 'Evidence & input') return 'Evidence & input processing';
    if (s.group === 'Transaction analysis') return 'Transaction analysis';
    if (s.group === 'AI reasoning') return 'AI reasoning';
    if (s.group === 'Verification & security') return 'Security verification';
    if (s.group === 'Completion') return 'Persistence & response';
    return 'Other';
  }

  /* Scenario presentation: short cards derived from the served scenario
   * fields (name/note/expect). Risk categories are display labels keyed
   * by scenario id; expected behaviour is the backend's own `expect`. */
  const SCENARIO_RISK = {
    'legitimate-transfer': ['Baseline', 'safe'],
    'execute-and-verify': ['Baseline', 'safe'],
    'unauthorized-recipient': ['Access control', 'danger'],
    'unlimited-approval': ['Approval risk', 'danger'],
    'hidden-multicall-approval': ['Hidden behavior', 'danger'],
    'unauthorized-inner': ['Nested operation', 'danger'],
    'exceeds-mandate': ['Limit breach', 'caution'],
    'misleading-description': ['Intent mismatch', 'caution'],
    'unknown-contract': ['Unknown contract', 'unknown'],
    'ambiguous-evidence': ['Unclear intent', 'unknown']
  };

  const DECISION_EXPLAIN = {
    ALLOW: 'Passed every deterministic check. Eligible for signing through the controlled signer only — the browser never holds keys.',
    BLOCK: 'A mandatory safeguard or mandate rule failed. The transaction will not execute under any path.',
    REVIEW: 'Held for a human operator. All checks completed but judgment is required; this browser cannot release it.',
    UNCERTAIN: 'The investigation could not reach a confident verdict, so Assertara held the transaction rather than guess.'
  };

  const fmtT = (ms) => {
    if (!Number.isFinite(ms)) return '—';
    const d = new Date(ms);
    const p = (n, l) => String(n).padStart(l || 2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
  };
  const fmtDur = (ms) => {
    if (ms === null || ms === undefined || !Number.isFinite(ms)) return '—';
    if (ms < 1000) return `${Math.round(ms)}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  };
  const pill = (text) => `<span class="pill ${esc(text)}">${esc(text)}</span>`;
  const shortId = (id) => (typeof id === 'string' && id.length > 22 ? `${id.slice(0, 10)}…${id.slice(-6)}` : (id === null || id === undefined ? '—' : id));
  const shortAddr = (a) => (typeof a === 'string' && /^0x[0-9a-fA-F]{40}$/.test(a) ? `${a.slice(0, 6)}…${a.slice(-4)}` : a);
  const oneLine = (v, max) => {
    const t = typeof v === 'string' ? v : JSON.stringify(v);
    if (t === null || t === undefined) return '—';
    return t.length > (max || 160) ? `${t.slice(0, max || 160)}…` : t;
  };
  function chainLabel(chainId) {
    if (chainId === null || chainId === undefined || chainId === '') return '—';
    const s = String(chainId);
    const num = s.startsWith('0x') ? parseInt(s, 16) : Number(s);
    if (!Number.isFinite(num)) return s;
    return num === 31337 ? 'Chain 31337 · local Anvil' : `Chain ${num}`;
  }
  function weiToEth(value) {
    if (value === null || value === undefined) return null;
    try {
      const b = typeof value === 'bigint' ? value : BigInt(String(value).trim());
      const neg = b < 0n;
      const abs = neg ? -b : b;
      const whole = abs / 1000000000000000000n;
      const frac = (abs % 1000000000000000000n).toString().padStart(18, '0').replace(/0+$/, '');
      return `${neg ? '-' : ''}${whole.toString()}${frac ? `.${frac}` : ''}`;
    } catch { return null; }
  }

  function decisionOf() {
    const st = state.status;
    const out = (state.snap && state.snap.outcome) || {};
    return (st && st.decision) || out.decision || null;
  }

  async function api(path, opts) {
    const res = await fetch(path, opts);
    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try { const b = await res.json(); if (b && b.error) detail = b.error; } catch { /* keep status */ }
      throw new Error(detail);
    }
    return res.json();
  }

  async function checkHealth() {
    try {
      const h = await api('/health');
      state.health = h;
      $('healthDot').className = 'dot ok';
      $('healthText').textContent = `server ok · ${h.models ? h.models.muse : ''}`;
    } catch {
      $('healthDot').className = 'dot bad';
      $('healthText').textContent = 'server unreachable';
    }
  }

  function scenarioCard(s) {
    const [risk, cls] = SCENARIO_RISK[s.id] || ['Scenario', 'unknown'];
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'scenario' + (state.activeScenario === s.id ? ' active' : '');
    b.title = `${s.note || ''}\nExpected: ${s.expect || ''}`;
    const desc = document.createElement('span');
    desc.className = 'sc-desc';
    desc.textContent = (s.note || s.expect || '').length > 110 ? `${(s.note || s.expect || '').slice(0, 110)}…` : (s.note || s.expect || '');
    b.innerHTML = `<span class="sc-name">${esc(s.name)}</span>`;
    b.appendChild(desc);
    const tags = document.createElement('span');
    tags.className = 'sc-tags';
    tags.innerHTML = `<span class="risk ${cls}">${esc(risk)}</span>`;
    b.appendChild(tags);
    b.addEventListener('click', () => runScenario(s));
    return b;
  }

  async function loadScenarios() {
    const box = $('scenarioList');
    try {
      const { scenarios } = await api('/api/v1/observations/scenarios');
      state.scenarioDefs = scenarios || [];
      box.innerHTML = '';
      for (const s of state.scenarioDefs) box.appendChild(scenarioCard(s));
    } catch (err) {
      box.innerHTML = `<p class="muted">Scenarios unavailable: ${esc(err.message)}</p>`;
    }
  }

  function markActiveScenario() {
    const defs = state.scenarioDefs || [];
    const box = $('scenarioList');
    if (!box || defs.length === 0) return;
    box.innerHTML = '';
    for (const s of defs) box.appendChild(scenarioCard(s));
  }

  async function refreshTraceList(keepSelection) {
    try {
      const { traces } = await api('/api/v1/observations/traces');
      state.traces = traces || [];
      const sel = $('tracePicker');
      const prev = keepSelection ? (sel.value || state.activeId) : state.activeId;
      sel.innerHTML = '';
      if (state.traces.length === 0) {
        const o = document.createElement('option');
        o.value = '';
        o.textContent = '(no traces yet — run a scenario)';
        sel.appendChild(o);
        return;
      }
      for (const t of state.traces.slice().reverse()) {
        const o = document.createElement('option');
        o.value = t.id;
        o.textContent = `${new Date(t.createdAt).toLocaleTimeString()} · ${t.kind} · ${t.status} · ${shortId(t.requestId || t.id)}`;
        sel.appendChild(o);
      }
      if (prev && state.traces.some((t) => t.id === prev)) sel.value = prev;
      else if (!state.activeId) sel.value = state.traces[state.traces.length - 1].id;
      else if (!state.traces.some((t) => t.id === state.activeId)) state.activeId = null;
    } catch {
      /* list failures leave the picker as-is; health dot reports */
    }
  }

  function closeStream() {
    if (state.source) { try { state.source.close(); } catch { /* ignore */ } state.source = null; }
  }

  function showContent(on) {
    $('content').hidden = !on;
    $('emptyState').hidden = on;
  }

  async function selectTrace(id) {
    if (!id) { state.activeId = null; state.snap = null; showContent(false); return; }
    closeStream();
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
    state.activeId = id;
    state.spans = new Map();
    state.appliedSeq = new Set();
    state.status = null;
    state.record = null;
    state.selectedStage = null;
    state.signMs = null;
    state.receiptMs = null;
    $('tracePicker').value = id;
    try {
      state.snap = await api(`/api/v1/observations/traces/${encodeURIComponent(id)}`);
    } catch (err) {
      showContent(false);
      $('emptyState').hidden = false;
      $('emptyState').innerHTML = `<div class="empty-mark" aria-hidden="true">${SHIELD_SVG}</div><h2>Investigation unavailable</h2><p>${esc(err.message)}</p>`;
      return;
    }
    // Restore the default empty state in case a previous error replaced it.
    $('emptyState').innerHTML = `<div class="empty-mark" aria-hidden="true">${SHIELD_SVG}</div><h2>No investigation selected</h2><p>Run a scenario from the left panel, or pick a previous investigation from the selector above, to watch Assertara investigate it live.</p>`;
    const counts = {};
    for (const s of state.snap.spans || []) {
      const k = `${s.component}#${counts[s.component] || 0}`;
      counts[s.component] = (counts[s.component] || 0) + 1;
      state.spans.set(k, { ...s, key: k });
    }
    showContent(true);
    renderAll();
    // Static mode (?static=1) renders one snapshot without the live stream —
    // for captures and evaluators. Identical content, no polling.
    if (new URLSearchParams(window.location.search).has('static')) {
      if (state.snap.requestId) void pollStatus(state.snap.requestId, true);
      return;
    }
    // Live tail: the server replays buffered events, then streams.
    const src = new EventSource(`/api/v1/observations/traces/${encodeURIComponent(id)}/stream`);
    state.source = src;
    src.onmessage = (ev) => {
      let e;
      try { e = JSON.parse(ev.data); } catch { return; }
      applyEvent(e);
    };
    src.onerror = () => { /* finished traces close the stream; EventSource retries harmlessly */ };
    // Pull request status + persisted record for the security/evidence views.
    if (state.snap.requestId) void pollStatus(state.snap.requestId, true);
  }

  /* The SSE endpoint replays every buffered event on (re)connect, and the
   * snapshot already contains those spans — applying replays blindly would
   * duplicate every component (and every model invocation). Replays are
   * recognised by exact identity: same component, same original timestamp
   * (starts) or same duration + result text (finishes). A genuine repeat
   * invocation never shares all of those with an earlier span. */
  function isReplayStart(e) {
    const detail = e.detail || '';
    for (const [, s] of state.spans) {
      if (s.component !== e.component) continue;
      // A replayed start carries the original timestamp, so it matches the
      // snapshot's span exactly (RUNNING or finished). A genuine new start
      // always carries a fresh timestamp.
      if (s.t0 === e.ts && (s.detail || '') === detail) return true;
    }
    return false;
  }

  function isReplayFinish(e) {
    const text = e.summary || e.error || '';
    for (const [, s] of state.spans) {
      if (s.component !== e.component || s.status === 'RUNNING') continue;
      if (s.durationMs === e.durationMs && (s.summary || s.error || '') === text && s.status === e.status) return true;
    }
    return false;
  }

  function applyEvent(e) {
    if (!e || e.traceId !== state.activeId) return;
    if (e.seq !== undefined && e.seq !== null) {
      if (state.appliedSeq.has(e.seq)) return;
      state.appliedSeq.add(e.seq);
    }
    if (e.type === 'span-start') {
      if (isReplayStart(e)) return;
      let i = 0;
      while (state.spans.has(`${e.component}#${i}`)) i += 1;
      const k = `${e.component}#${i}`;
      state.spans.set(k, {
        key: k, component: e.component, name: e.name || e.component,
        group: e.group || 'Other', status: 'RUNNING', t0: e.ts, t1: null,
        durationMs: null, detail: e.detail || '', summary: '', error: null, extra: null
      });
      renderFlow();
      renderComponents();
      renderTimeline();
    } else if (e.type === 'span-finish') {
      if (isReplayFinish(e)) return;
      for (const [, s] of state.spans) {
        if (s.component === e.component && s.status === 'RUNNING') {
          s.status = e.status; s.t1 = e.ts; s.durationMs = e.durationMs;
          s.summary = e.summary || ''; s.error = e.error || null; s.extra = e.extra || null;
          break;
        }
      }
      renderFlow();
      renderComponents();
      renderTimeline();
      renderPerf();
      renderAI();
    } else if (e.type === 'trace-finish') {
      if (state.snap) {
        state.snap.status = e.error ? 'FAILED' : 'COMPLETED';
        state.snap.finishedAt = e.ts;
        if (e.outcome) state.snap.outcome = e.outcome;
      }
      for (const [, s] of state.spans) {
        if (s.status === 'RUNNING') { s.status = 'COMPLETED'; s.t1 = e.ts; s.durationMs = e.ts - s.t0; s.summary = s.summary || 'closed at trace finish'; }
      }
      renderAll();
      if (state.snap && state.snap.requestId) void pollStatus(state.snap.requestId, true);
    }
  }

  function renderAll() {
    renderOverview();
    renderFlow();
    renderAI();
    renderSecurity();
    renderPerf();
    renderComponents();
    renderTimeline();
    renderEvidence();
  }

  /* ---------- AREA A: investigation overview ---------- */

  function proposalTx() {
    const lp = state.lastProposal;
    if (lp && state.snap && lp.requestId === state.snap.requestId) return lp.transaction || null;
    return null;
  }

  function renderOverview() {
    const snap = state.snap;
    if (!snap) return;
    const st = state.status;
    const rec = state.record;
    const tx = (rec && rec.decodedTransaction) || null;
    const ptx = proposalTx();

    const decision = decisionOf();
    const decCls = decision ? `decision-${decision}` : 'decision-pending';
    let decHtml = `<div class="decision-badge ${decCls}"><span class="decision-dot" aria-hidden="true"></span><span class="decision-word">${esc(decision || 'INVESTIGATING')}</span></div>`;
    if (decision && DECISION_EXPLAIN[decision]) decHtml += `<p class="decision-explain">${esc(DECISION_EXPLAIN[decision])}</p>`;
    else if (!decision) decHtml += '<p class="decision-explain">The investigation is still running. The decision appears here when Assertara reaches it.</p>';
    decHtml += `<p class="decision-sub">${esc(snap.kind)} · ${esc(snap.status)} · ${esc(fmtDur(snap.durationMs))}</p>`;

    // Execution state: part of the overview, not buried in tabs.
    const lp = state.lastProposal;
    if (st && st.execution) {
      const x = st.execution;
      decHtml += `<div>${pill(x.outcome || 'recorded')}</div>`
        + `<p class="decision-sub">tx ${esc(x.txHash || '')}${x.receiptStatus ? ` · receipt ${esc(x.receiptStatus)}` : ''}${x.blockNumber ? ` · block ${esc(x.blockNumber)}` : ''}</p>`
        + (x.verification ? `<p class="hint">effects: ${esc(x.verification.effects || '')}${x.verification.reason ? ` — ${esc(x.verification.reason)}` : ''}</p>` : '');
    } else if (lp && lp.approval && st && st.decision === 'ALLOW' && lp.requestId === st.requestId) {
      decHtml += `<div class="exec-row"><button type="button" class="btn-primary" id="execBtn">Sign &amp; execute</button></div>`
        + `<p class="hint" id="execHint">${state.signerBase ? `via controlled signer (${esc(state.signerBase)})` : 'signer URL missing: open the command URL printed by demo/command-stack.js (?signer=…)'}</p>`;
    } else if (st && st.decision === 'REVIEW') {
      decHtml += '<p class="hint">HELD for operator release. This browser cannot release it (no operator secret here).</p>';
    }
    const out = snap.outcome || {};
    if (out.rejected) decHtml += `<p class="hint">Rejected before investigation: ${esc(out.rejected)}</p>`;
    $('ovDecision').innerHTML = decHtml;
    const execBtn = $('execBtn');
    if (execBtn) execBtn.addEventListener('click', executeAllowed);

    // Transaction summary: most important details only, never raw payloads.
    // The agent's stated purpose is the exact proposed intent (session) or
    // the verbatim explicit-intent quotes — never the model's own
    // investigation.objective, which is model-framed, not agent-stated.
    const eiQuotes = rec && rec.explicitIntent && Array.isArray(rec.explicitIntent.statements)
      ? rec.explicitIntent.statements.map((s) => s && s.quote).filter((q) => typeof q === 'string' && q)
      : [];
    const objective = (lp && lp.requestId === snap.requestId && lp.objective) || eiQuotes[0] || null;
    const actionName = tx && tx.functionName
      ? (tx.functionName === 'unknownFunction' ? 'Unknown contract call' : (tx.functionName === 'nativeTransfer' ? 'Native transfer' : `${tx.functionName}`))
      : (ptx && (!ptx.data || ptx.data === '0x') ? 'Native transfer' : (ptx ? 'Contract call' : null));
    const target = (tx && tx.contract) || (ptx && ptx.to) || null;
    const rawName = (tx && tx.contractName) || null;
    const targetName = rawName && !/^unknown/i.test(rawName) ? rawName : null;
    const nativeEth = (tx && (tx.valueEth !== null && tx.valueEth !== undefined) && String(tx.valueEth))
      || (ptx ? weiToEth(ptx.value) : null);
    let txHtml = '<h3>Under investigation</h3>';
    txHtml += objective ? `<p class="ov-objective">“${esc(objective)}”</p>` : '<p class="ov-objective muted" style="font-weight:400">Objective text unavailable for this trace.</p>';
    txHtml += '<dl class="kvline" style="margin:0">';
    txHtml += `<dt>Proposed action</dt><dd>${esc(actionName || '—')}${targetName ? ` · ${esc(targetName)}` : ''}</dd>`;
    txHtml += `<dt>Target</dt><dd class="mono">${esc(target || '—')}</dd>`;
    txHtml += `<dt>Native value</dt><dd>${nativeEth !== null && nativeEth !== undefined && nativeEth !== '' ? `${esc(nativeEth)} ETH` : '—'}</dd>`;
    const txDigest = (st && st.txDigest) || (lp && lp.requestId === snap.requestId && lp.txDigest) || null;
    txHtml += `<dt>Binding</dt><dd class="mono">${esc(txDigest ? shortId(txDigest) : '—')}</dd>`;
    txHtml += '</dl>';
    $('ovTx').innerHTML = txHtml;

    // Meta column: identity, network, timing.
    const chainId = (rec && rec.chainId !== null && rec.chainId !== undefined && String(rec.chainId)) || (ptx && ptx.chainId) || null;
    const agent = (lp && lp.requestId === snap.requestId && lp.agentId) || null;
    const mandate = (lp && lp.requestId === snap.requestId && lp.mandate) || (st && st.mandate) || null;
    $('ovMeta').innerHTML = '<h3>Details</h3>'
      + `<div class="metarow"><span class="k">Investigation</span><span class="v mono">${esc(shortId(snap.requestId || snap.id))}</span></div>`
      + `<div class="metarow"><span class="k">Agent</span><span class="v">${esc(agent || '—')}</span></div>`
      + `<div class="metarow"><span class="k">Network</span><span class="v">${esc(chainLabel(chainId))}</span></div>`
      + `<div class="metarow"><span class="k">Type</span><span class="v">${esc(snap.kind === 'agent' ? 'Agent proposal' : snap.kind)}</span></div>`
      + `<div class="metarow"><span class="k">Mandate</span><span class="v mono">${esc(mandate ? `${mandate.id} v${mandate.version}` : '—')}</span></div>`
      + `<div class="metarow"><span class="k">Total duration</span><span class="v">${esc(fmtDur(snap.durationMs))}</span></div>`;
  }

  async function executeAllowed() {
    const lp = state.lastProposal;
    const btn = $('execBtn');
    const hint = $('execHint');
    if (!lp || !lp.approval) return;
    if (!state.signerBase) {
      if (hint) hint.textContent = 'Cannot execute: no signer URL (?signer=…).';
      return;
    }
    if (btn) btn.disabled = true;
    if (hint) hint.textContent = 'Signing via controlled signer…';
    const t0 = performance.now();
    try {
      const res = await fetch(`${state.signerBase}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requestId: lp.requestId, transaction: lp.transaction, approval: lp.approval })
      });
      const ms = Math.round(performance.now() - t0);
      state.signMs = ms;
      const body = await res.json().catch(() => ({}));
      if (!res.ok || !body.ok) {
        if (hint) hint.textContent = `Signer refused after ${ms}ms (browser-measured): ${body.error || res.status}`;
        // eslint-disable-next-line no-console
        console.warn('signer refused', body);
        return;
      }
      if (hint) hint.textContent = `Broadcast in ${ms}ms (browser-measured round-trip): ${body.txHash}. Waiting for receipt verification…`;
      const r0 = performance.now();
      const origPoll = state.pollTimer;
      void origPoll;
      await pollStatus(lp.requestId, false);
      state.receiptMs = Math.round(performance.now() - r0);
    } catch (err) {
      const ms = Math.round(performance.now() - t0);
      if (hint) hint.textContent = `Signer call failed after ${ms}ms: ${err.message}`;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  /* ---------- AREA B: live investigation flow ---------- */

  function stageState(stage) {
    const spans = [...state.spans.values()].filter((s) => stage.comps.includes(s.component));
    const finished = state.snap && state.snap.status !== 'RUNNING';
    const decision = decisionOf();
    if (stage.execution) {
      if (state.status && state.status.execution) {
        const x = state.status.execution;
        return { status: x.outcome === 'EXECUTED' ? 'done' : (x.outcome === 'MISMATCH' || x.outcome === 'EFFECTS_DIVERGED' || x.outcome === 'FAILED' ? 'failed' : 'done'), spans, note: `Outcome ${x.outcome}${x.txHash ? ` · ${shortId(x.txHash)}` : ''}` };
      }
      if (spans.length > 0) return spans.some((s) => s.status === 'RUNNING') ? { status: 'running', spans } : { status: 'done', spans };
      if (decision === 'ALLOW') return { status: 'pending', spans, note: 'Approved — awaiting Sign & execute.' };
      if (decision) return { status: 'blocked', spans, note: `No execution for a ${decision} decision.` };
      return { status: finished ? 'blocked' : 'pending', spans, note: finished ? 'Not invoked on this path.' : 'Awaiting decision.' };
    }
    if (stage.decision) {
      if (decision) return { status: 'done', spans, note: `Decision: ${decision}.` };
      return { status: finished ? 'blocked' : 'pending', spans, note: finished ? 'No decision recorded.' : 'Decision pending.' };
    }
    if (spans.length === 0) {
      if (finished) return { status: 'blocked', spans, note: 'Not invoked on this path.' };
      return { status: 'pending', spans, note: 'Waiting for backend events.' };
    }
    if (spans.some((s) => s.status === 'RUNNING')) return { status: 'running', spans };
    if (spans.some((s) => s.status === 'FAILED')) {
      const f = spans.find((s) => s.status === 'FAILED');
      return { status: 'failed', spans, note: f.error || f.summary || 'A component failed.' };
    }
    if (spans.every((s) => s.status === 'SKIPPED')) {
      return { status: 'skipped', spans, note: spans[0].summary || 'Skipped.' };
    }
    return { status: 'done', spans };
  }

  function stageDuration(spans) {
    const ds = spans.map((s) => s.durationMs).filter((n) => Number.isFinite(n));
    if (ds.length === 0) return null;
    return ds.reduce((a, b) => a + b, 0);
  }

  function renderFlow() {
    const ol = $('flowSteps');
    ol.innerHTML = '';
    STAGES.forEach((stage, i) => {
      const st = stageState(stage);
      const dur = stageDuration(st.spans);
      const li = document.createElement('li');
      li.style.cssText = 'display:contents';
      const b = document.createElement('button');
      b.type = 'button';
      b.className = `flowstep ${st.status}${state.selectedStage === stage.id ? ' selected' : ''}`;
      const glyph = st.status === 'done' ? '✓' : st.status === 'failed' ? '✕' : st.status === 'skipped' ? '○' : st.status === 'blocked' ? '—' : String(i + 1);
      b.innerHTML = `<span class="rail"><span class="node" aria-hidden="true">${esc(glyph)}</span></span>`
        + `<span class="ftext"><span class="flabel">${esc(stage.label)}</span><span class="fdur">${esc(fmtDur(dur))}</span></span>`;
      b.setAttribute('aria-label', `${stage.label}: ${st.status}${dur !== null ? `, ${fmtDur(dur)}` : ''}`);
      b.addEventListener('click', () => {
        state.selectedStage = state.selectedStage === stage.id ? null : stage.id;
        renderFlow();
        renderComponents();
        if (state.selectedStage) {
          $('inspClear').hidden = false;
          $('inspectorPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
          $('inspClear').hidden = true;
        }
      });
      li.appendChild(b);
      ol.appendChild(li);
    });

    // Stage detail strip.
    const box = $('flowDetail');
    if (!state.selectedStage) { box.hidden = true; box.innerHTML = ''; return; }
    const stage = STAGES.find((s) => s.id === state.selectedStage);
    const st = stageState(stage);
    const rows = st.spans.map((s) => `<li><b>${esc(s.name)}</b> — ${esc(s.status)}${Number.isFinite(s.durationMs) ? ` (${esc(fmtDur(s.durationMs))})` : ''}${s.summary ? ` · ${esc(oneLine(s.summary, 120))}` : ''}${s.error ? ` · <span style="color:var(--bad)">${esc(oneLine(s.error, 120))}</span>` : ''}</li>`).join('');
    box.innerHTML = `<h4>${esc(stage.label)} <span class="hint">${esc(st.status)}${st.spans.length ? ` · ${st.spans.length} component${st.spans.length === 1 ? '' : 's'}` : ''}</span></h4>`
      + (st.note ? `<p>${esc(st.note)}</p>` : '')
      + (rows ? `<ul>${rows}</ul>` : '<p class="hint">No component events recorded for this stage yet. Matching components in the inspector below are highlighted.</p>');
    box.hidden = false;
  }

  /* ---------- AREA C: AI intelligence ---------- */

  function providerLabel() {
    const h = state.health;
    const base = h && h.metaApiBaseUrl;
    if (typeof base === 'string' && base) {
      try { return new URL(base).hostname; } catch { return base; }
    }
    return '—';
  }

  function renderAI() {
    const body = $('aiBody');
    const sparks = [...state.spans.values()].filter((s) => s.component === 'muse-spark');
    const sams = [...state.spans.values()].filter((s) => s.component === 'sam');
    const rec = state.record;
    const origin = (rec && rec.reasoningOrigin)
      || (state.status && state.status.investigation && state.status.investigation.reasoningOrigin) || null;
    $('aiHint').textContent = origin === 'model' ? 'live model reasoning' : (origin === 'heuristic-fallback' ? 'heuristic fallback path' : '');

    if (sparks.length === 0) {
      body.innerHTML = '<p class="muted">No model invocation recorded for this trace yet.</p>';
      return;
    }
    const inv = rec && rec.investigation;
    let html = sparks.map((s, i) => {
      const x = (s.extra && typeof s.extra === 'object') ? s.extra : {};
      const usage = (x.usage && typeof x.usage === 'object') ? x.usage : ((rec && rec.usage) || {});
      const title = sparks.length > 1 ? `Muse Spark · invocation ${i + 1} of ${sparks.length}` : 'Muse Spark';
      const rows = [
        ['Role', 'security investigator (never authorizes)'],
        ['Requested model', x.model || (state.health && state.health.models && state.health.models.muse) || '—'],
        ['Serving model id', x.servingModelId || (s.status === 'SKIPPED' ? '(not invoked)' : '—')],
        ['Provider', providerLabel()],
        ['Prompt version', x.promptVersion || (rec && rec.promptVersion) || '—'],
        ['Status', s.status],
        ['Inference duration', fmtDur(s.durationMs)],
        ['Input tokens', usage.promptTokens ?? usage.prompt_tokens ?? '—'],
        ['Output tokens', usage.completionTokens ?? usage.completion_tokens ?? '—'],
        ['Attempts / retries / timeouts', `${x.attempts ?? '—'} / ${x.retries ?? '—'} / ${x.timeouts ?? '—'}`],
        ['Time to first token', 'unavailable (non-streaming API)'],
        ['Fallback used', x.fallbackUsed === true ? 'yes' : (s.status === 'FAILED' || s.status === 'SKIPPED' ? 'yes (heuristic)' : 'no')]
      ];
      const note = s.status === 'SKIPPED' ? s.summary : (s.error || s.summary);
      return `<div class="modelcard"><h3>${esc(title)} ${pill(s.status)}</h3>`
        + `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join('')}</dl>`
        + (note ? `<p class="hint">${esc(note)}</p>` : '')
        + (i === 0 && rec && origin === 'model'
          ? `<p class="finding-line">Findings: verdict <b>${esc(rec.verdict || '—')}</b>${typeof rec.confidence === 'number' ? ` (confidence ${esc(String(rec.confidence))})` : ''} — ${esc(oneLine(rec.summary || '', 220))}</p>`
          : '')
        + (i === 0 && origin === 'heuristic-fallback'
          ? '<p class="finding-line">Findings: heuristic fallback — deterministic rules only, no model interpretation. The persisted bundle is not written on this path.</p>'
          : '')
        + (i === 0 && inv && Array.isArray(inv.conclusions) && inv.conclusions.length > 0 && origin === 'model'
          ? `<p class="finding-line">${esc(String(inv.conclusions.length))} structured conclusion${inv.conclusions.length === 1 ? '' : 's'} recorded — see the evidence record below for the full text.</p>`
          : '')
        + '</div>';
    }).join('');

    // SAM appears only when actually invoked; otherwise an honest note.
    if (sams.length > 0) {
      html += sams.map((s, i) => {
        const title = sams.length > 1 ? `SAM 3.1 · invocation ${i + 1} of ${sams.length}` : 'SAM 3.1 segmentation';
        return `<div class="modelcard"><h3>${esc(title)} ${pill(s.status)}</h3>`
          + `<dl class="kv"><dt>Role</dt><dd>visual-region segmentation</dd>`
          + `<dt>Requested model</dt><dd>${esc((state.health && state.health.models && state.health.models.sam) || 'sam-3.1')}</dd>`
          + `<dt>Status</dt><dd>${esc(s.status)}</dd><dt>Duration</dt><dd>${esc(fmtDur(s.durationMs))}</dd></dl>`
          + (s.summary || s.error ? `<p class="hint">${esc(s.error || s.summary)}</p>` : '') + '</div>';
      }).join('');
    } else {
      const visualReason = state.status && state.status.visual && state.status.visual.reason;
      html += `<div class="skipped-note"><b>SAM 3.1</b> — not invoked on this investigation. ${esc(visualReason || 'No screenshot was supplied, so there was nothing to segment.')}</div>`;
    }
    html += '<p class="hint">Planner model: UI scenarios use fixed transactions (no planner call). The demo agent planner runs out-of-process; see demo logs.</p>';
    body.innerHTML = html;
  }

  /* ---------- AREA D: security analysis ---------- */

  function secBlock(title, inner) {
    return `<div class="secblock"><h3>${esc(title)}</h3>${inner}</div>`;
  }

  /* Human-readable one-liner for a reconstructed effect (EF-xxx shape:
   * effectId/kind/asset/amount/from/to/spender/unlimited). Falls back to
   * compact JSON only for shapes this UI does not recognise. */
  function formatEffect(e) {
    if (typeof e === 'string') return e;
    if (!e || typeof e !== 'object') return '—';
    if (e.summary || e.description) return e.summary || e.description;
    const id = e.effectId ? `${e.effectId} · ` : '';
    const kind = e.kind || e.operation || 'effect';
    let amount = '';
    if (e.amount !== null && e.amount !== undefined) {
      const dec = e.asset && Number.isInteger(e.asset.decimals) ? e.asset.decimals : null;
      const sym = (e.asset && e.asset.symbol) || ((e.asset && e.asset.standard === 'native') ? 'ETH' : null);
      let human = null;
      try {
        const raw = BigInt(String(e.amount));
        if (dec !== null && dec <= 77) {
          const base = 10n ** BigInt(dec);
          const whole = raw / base;
          const frac = (raw % base).toString().padStart(dec, '0').replace(/0+$/, '');
          human = `${whole.toString()}${frac ? `.${frac}` : ''}`;
        }
      } catch { /* fall through to raw */ }
      amount = ` ${human !== null ? human : String(e.amount)}${sym ? ` ${sym}` : ''}`;
    }
    const flow = e.from || e.to ? ` ${shortAddr(e.from) || '?'} → ${shortAddr(e.to) || '?'}` : '';
    const extra = e.unlimited === true ? ' UNLIMITED' : (e.spender ? ` spender ${shortAddr(e.spender)}` : '');
    const conf = e.confidence && e.confidence !== 'exact' ? ` [${e.confidence}]` : '';
    const line = `${id}${kind}:${amount}${flow}${extra}${conf}`;
    return line.trim() === '' || line === 'effect:' ? oneLine(e, 180) : line;
  }

  function renderSecurity() {
    const body = $('secBody');
    const st = state.status;
    const rec = state.record;
    const snap = state.snap;
    if (!snap) return;
    $('secHint').textContent = rec ? `verdict ${rec.verdict || '—'} · ${rec.reasoningOrigin || ''}` : '';

    let html = '';

    // 1. Transaction intent: explicit statements vs model inference.
    const statements = rec && rec.explicitIntent && Array.isArray(rec.explicitIntent.statements) ? rec.explicitIntent.statements : [];
    const modelObjective = rec && rec.investigation && typeof rec.investigation.objective === 'string' ? rec.investigation.objective : null;
    const lp = state.lastProposal;
    const sessionObjective = lp && lp.requestId === snap.requestId ? lp.objective : null;
    let intentHtml = '';
    if (statements.length > 0) {
      intentHtml += `<p>Explicit statements from the agent:</p>`
        + statements.slice(0, 6).map((s) => `<div class="quote"><span class="qid">${esc(s.id || 'EI')}</span>${esc(s.quote || s.text || JSON.stringify(s))}</div>`).join('')
        + (statements.length > 6 ? `<p class="hint">+${statements.length - 6} further statement(s) in the evidence record.</p>` : '');
    } else if (sessionObjective) {
      intentHtml += `<p>Agent-stated purpose:</p><div class="quote">${esc(sessionObjective)}</div>`;
    } else {
      intentHtml += '<p class="muted">Stated intent unavailable — the persisted bundle has not loaded (model-origin runs) and this trace was not started in this session.</p>';
    }
    if (modelObjective) {
      intentHtml += `<p class="hint">Model's investigation objective (model-framed, not agent-stated): ${esc(oneLine(modelObjective, 220))}</p>`;
    }
    if (rec && rec.investigation && Array.isArray(rec.investigation.conclusions) && rec.investigation.conclusions.length > 0) {
      intentHtml += `<p class="hint">Model-inferred reading: see ${rec.investigation.conclusions.length} structured conclusion(s) in the evidence record. The model interprets; it never authorizes.</p>`;
    }
    html += secBlock('Transaction intent', intentHtml);

    // 2. Actual transaction effects.
    const fx = rec && rec.effects;
    const fxList = fx && Array.isArray(fx.effects) ? fx.effects : [];
    let fxHtml = '';
    if (fxList.length > 0) {
      fxHtml += `<p>Decoded effects <span class="tier DETERMINISTIC">DETERMINISTIC</span>:</p><ul>`
        + fxList.slice(0, 8).map((e) => `<li>${esc(formatEffect(e))}</li>`).join('') + '</ul>'
        + (fxList.length > 8 ? `<p class="hint">+${fxList.length - 8} further effect(s) in the evidence record.</p>` : '');
    } else if (rec && rec.decodedTransaction) {
      const d = rec.decodedTransaction;
      fxHtml += `<p>Effects unavailable; decoded call <span class="tier VERIFIED">VERIFIED</span>: <span class="mono">${esc(d.contractName || 'Unknown')} · ${esc(d.functionName || '?')}</span>`
        + (d.valueEth ? ` · ${esc(String(d.valueEth))} ETH` : '') + '.</p>';
    } else {
      fxHtml += '<p class="muted">Effect reconstruction loads with the persisted bundle (model-origin runs).</p>';
    }
    const sub = rec && rec.subcalls;
    if (sub && sub.hasNested) {
      fxHtml += `<p class="hint">Nested operations: ${sub.subcalls ? sub.subcalls.length : '?'} inner call(s), depth ${sub.maxDepth ?? '?'}, ${sub.unknownCount ?? '?'} unknown.</p>`;
    }
    html += secBlock('Actual transaction effects', fxHtml);

    // 3. Discrepancies.
    const inv = rec && rec.investigation;
    const disc = inv && Array.isArray(inv.discrepancies) ? inv.discrepancies : [];
    const contra = inv && Array.isArray(inv.contradictions) ? inv.contradictions : [];
    let discHtml = '';
    if (disc.length === 0 && contra.length === 0) {
      discHtml = rec
        ? `<p>No discrepancies reported ${rec.verdict ? `(verdict ${esc(rec.verdict)})` : ''} — the stated objective and the decoded effects were not found to conflict.</p>`
        : '<p class="muted">Discrepancy analysis loads with the persisted bundle (model-origin runs).</p>';
    } else {
      const discLine = (d) => {
        if (typeof d === 'string') return d;
        const text = d.statement || d.summary || d.description || oneLine(d, 200);
        const sev = d.severity ? ` [${d.severity}]` : '';
        return `${text}${sev}`;
      };
      discHtml = '<ul>'
        + disc.slice(0, 8).map((d) => `<li>${esc(discLine(d))}</li>`).join('')
        + contra.slice(0, 4).map((d) => `<li>Contradiction: ${esc(discLine(d))}</li>`).join('')
        + '</ul>';
    }
    html += secBlock('Discrepancies', discHtml);

    // 4. Risk findings: backend-classified via the policy decision record.
    const findings = (st && st.investigation && st.investigation.ruleFindings) || (rec && rec.ruleFindings) || [];
    const blocking = new Set(rec && rec.policyDecision && Array.isArray(rec.policyDecision.blockingFindings) ? rec.policyDecision.blockingFindings : []);
    const reviewing = new Set(rec && rec.policyDecision && Array.isArray(rec.policyDecision.reviewFindings) ? rec.policyDecision.reviewFindings : []);
    let riskHtml = '';
    if (findings.length === 0) {
      riskHtml = '<p>No risk findings — no deterministic rule fired on this transaction.</p>';
    } else {
      riskHtml = findings.slice(0, 10).map((f) => {
        const id = typeof f === 'string' ? f : (f.ruleId || 'UNKNOWN');
        const detail = typeof f === 'string' ? '' : (f.message || f.detail || f.description || '');
        const cls = blocking.has(id) ? 'block' : 'review';
        const tag = blocking.has(id) ? 'BLOCK' : (reviewing.has(id) ? 'REVIEW' : 'flagged');
        return `<div class="finding ${cls}"><span class="fr">${esc(id)}</span> ${pill(tag)}<div class="fd">${esc(oneLine(detail || 'See the evidence record for full detail.', 240))}</div></div>`;
      }).join('')
        + (findings.length > 10 ? `<p class="hint">+${findings.length - 10} further finding(s) in the evidence record.</p>` : '');
    }
    // Mandate violations surface through the decision reasons.
    const mandateReasons = ((st && st.reasons) || []).filter((r) => typeof r === 'string' && r.startsWith('mandate:'));
    if (mandateReasons.length > 0) {
      riskHtml += `<p class="hint">Mandate evaluation:</p><ul>${mandateReasons.slice(0, 6).map((r) => `<li>${esc(r.replace(/^mandate:\s*/, ''))}</li>`).join('')}</ul>`;
    }
    html += secBlock('Risk findings', riskHtml);

    // 5. Authorization: safeguards + mandate + policy, with the authority line.
    const guards = (st && st.investigation && st.investigation.safeguardTriggers) || (rec && Array.isArray(rec.verdictSafeguards) ? rec.verdictSafeguards.map((s) => (s && s.trigger) || s) : []) || [];
    const pol = rec && rec.policyDecision;
    let authHtml = '<ul>';
    authHtml += `<li>Deterministic safeguards: ${guards.length > 0 ? esc(guards.join(', ')) : 'none triggered'}.</li>`;
    const lpMandate = lp && lp.requestId === snap.requestId ? lp.mandateChecks : null;
    if (Array.isArray(lpMandate) && lpMandate.length > 0) {
      const fails = lpMandate.filter((c) => c && c.pass === false);
      authHtml += `<li>Agent mandate: ${lpMandate.length} check(s), ${fails.length} failed${fails.length ? ` (${esc(fails.map((c) => c.id || '?').join(', '))})` : ''}.</li>`;
    } else {
      authHtml += '<li>Agent mandate: evaluated at decision time (per-check detail travels with the propose response; reasons above carry the outcome).</li>';
    }
    authHtml += `<li>Investigation policy: ${pol ? `${esc(pol.decision || '—')} (${esc(pol.policyId || 'assertara-mvp-1')})` : 'pending bundle load'} — combined with the mandate verdict above into the final decision.</li>`;
    authHtml += '</ul><p class="hint">Authority: deterministic safeguards and the independently authorised mandate decide. Muse Spark investigates but cannot authorize any transaction.</p>';
    html += secBlock('Authorization', authHtml);

    // 6. Final explanation.
    const reasons = (st && st.reasons) || [];
    let finalHtml = '';
    if (reasons.length > 0) {
      finalHtml = `<ol class="reasons">${reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ol>`;
    } else if (snap.status === 'RUNNING') {
      finalHtml = '<p class="muted">The investigation is still running — the explanation appears with the decision.</p>';
    } else {
      finalHtml = '<p class="muted">No decision reasons recorded for this trace.</p>';
    }
    if (rec && rec.summary) finalHtml += `<p class="hint">Investigation summary: ${esc(oneLine(rec.summary, 300))}</p>`;
    html += secBlock('Why this decision', finalHtml);

    body.innerHTML = html;
  }

  /* ---------- Performance ---------- */

  function sumDurations(pred) {
    return [...state.spans.values()]
      .filter((s) => Number.isFinite(s.durationMs) && (!pred || pred(s)))
      .reduce((a, s) => a + s.durationMs, 0);
  }

  function perfStats() {
    const xs = [...state.spans.values()].map((s) => s.durationMs).filter((n) => Number.isFinite(n)).sort((a, b) => a - b);
    if (xs.length === 0) return null;
    const q = (p) => xs[Math.min(xs.length - 1, Math.floor(p * xs.length))];
    return { n: xs.length, avg: Math.round(xs.reduce((a, b) => a + b, 0) / xs.length), p50: q(0.5), p95: q(0.95), min: xs[0], max: xs[xs.length - 1] };
  }

  function renderPerf() {
    const total = state.snap ? state.snap.durationMs : null;
    $('perfTotal').textContent = total ? `end-to-end ${fmtDur(total)}` : '';
    const aiMs = sumDurations((s) => s.component === 'muse-spark');
    const verifyMs = sumDurations((s) => ['reasoning-validation', 'reference-validation', 'support-validation', 'reconciliation', 'semantic-claims', 'visual-role-check', 'safeguards'].includes(s.component));
    const authMs = sumDurations((s) => ['mandate-eval', 'subcall-bind', 'policy-decision', 'approval-issue'].includes(s.component));
    const execMs = state.signMs !== null ? state.signMs : (state.status && state.status.execution ? 0 : null);
    const stats = [
      ['Total investigation', fmtDur(total)],
      ['AI inference', fmtDur(aiMs) + (aiMs === 0 ? ' (none)' : '')],
      ['Security verification', fmtDur(verifyMs)],
      ['Authorization', fmtDur(authMs)],
      ['Execution', execMs === null ? '—' : (execMs === 0 ? 'recorded' : `${fmtDur(execMs)} (browser)`)]
    ];
    $('perfHead').innerHTML = stats.map(([k, v]) => `<div class="perfstat"><div class="pv">${esc(v)}</div><div class="pk">${esc(k)}</div></div>`).join('');

    // Detailed breakdown.
    const spans = [...state.spans.values()].filter((s) => Number.isFinite(s.durationMs));
    const dist = perfStats();
    let html = '';
    if (spans.length === 0) {
      html = '<p class="muted">Timings appear as components complete.</p>';
    } else {
      const t0 = Math.min(...[...state.spans.values()].map((s) => s.t0));
      const span = Math.max((state.snap && state.snap.durationMs) || 1, 1);
      for (const s of spans.slice().sort((a, b) => b.durationMs - a.durationMs).slice(0, 24)) {
        const left = Math.max(0, ((s.t0 - t0) / span) * 100);
        const width = Math.max(0.6, (s.durationMs / span) * 100);
        const cls = s.component === 'muse-spark' ? 'model' : (s.status === 'FAILED' ? 'failed' : '');
        html += `<div class="perfrow"><span class="cn" title="${esc(s.name)}">${esc(s.name)}</span>`
          + `<span class="bar"><span class="fill ${cls}" style="left:${left.toFixed(1)}%;width:${Math.min(100 - left, width).toFixed(1)}%"></span></span>`
          + `<span class="ms">${fmtDur(s.durationMs)}</span></div>`;
      }
      if (spans.length > 24) html += `<p class="hint">Showing the 24 longest of ${spans.length} timed spans.</p>`;
    }
    if (dist) {
      html += `<p class="perfstats">Component durations in this investigation (n=${dist.n}): avg ${fmtDur(dist.avg)} · P50 ${fmtDur(dist.p50)} · P95 ${fmtDur(dist.p95)} · min ${fmtDur(dist.min)} · max ${fmtDur(dist.max)}. `
        + 'Single-investigation distribution only — not a benchmark. Cold-vs-warm and repeat statistics come from the benchmark script (<span class="mono">demo/agent-scenarios.js --bench</span>).</p>';
    }
    const sparks = [...state.spans.values()].filter((s) => s.component === 'muse-spark');
    const tok = sparks.map((s) => (s.extra && s.extra.usage) || null).find((u) => u && (u.promptTokens !== null || u.completionTokens !== null))
      || (state.record && state.record.usage) || null;
    if (tok) {
      html += `<p class="perfstats">Model tokens: input ${esc(String(tok.promptTokens ?? tok.prompt_tokens ?? '—'))} · output ${esc(String(tok.completionTokens ?? tok.completion_tokens ?? '—'))}`
        + `${tok.totalTokens ?? tok.total_tokens ? ` · total ${esc(String(tok.totalTokens ?? tok.total_tokens))}` : ''}.</p>`;
    }
    const retryInfo = sparks.map((s) => s.extra || {}).find((x) => x.attempts !== undefined || x.timeouts);
    if (retryInfo) {
      html += `<p class="perfstats">Model transport: attempts ${esc(String(retryInfo.attempts ?? '—'))} · retries ${esc(String(retryInfo.retries ?? '—'))} · timeouts ${esc(String(retryInfo.timeouts ?? '—'))}. Production makes exactly one attempt per investigation; the UI never silently retries.</p>`;
    }
    if (state.status && state.status.execution) {
      html += '<p class="perfstats">Investigation latency above excludes blockchain confirmation: mining/inclusion time is chain behavior, not Assertara reasoning time.</p>';
    }
    $('perfBody').innerHTML = html;
  }

  /* ---------- AREA E: technical inspector ---------- */

  function inspFilters() {
    return {
      q: ($('inspSearch').value || '').toLowerCase(),
      status: $('inspStatus').value || '',
      group: $('inspGroup').value || '',
      stage: state.selectedStage ? new Set((STAGES.find((s) => s.id === state.selectedStage) || { comps: [] }).comps) : null
    };
  }

  function renderComponents() {
    const board = $('componentBoard');
    const spans = [...state.spans.values()];
    $('inspCount').textContent = `${spans.length} recorded`;
    const gsel = $('inspGroup');
    if (gsel.options.length <= 1) {
      for (const g of INSPECTOR_GROUPS) {
        const o = document.createElement('option');
        o.value = g; o.textContent = g;
        gsel.appendChild(o);
      }
    }
    if (spans.length === 0) {
      board.innerHTML = '<p class="muted">No component events yet — they appear here as the backend records them.</p>';
      return;
    }
    const f = inspFilters();
    const match = (s) => {
      if (f.status && s.status !== f.status) return false;
      if (f.group && inspectorGroup(s) !== f.group) return false;
      if (f.stage && !f.stage.has(s.component)) return false;
      if (f.q) {
        const hay = `${s.name} ${s.component} ${s.summary || ''} ${s.error || ''} ${s.detail || ''}`.toLowerCase();
        if (!hay.includes(f.q)) return false;
      }
      return true;
    };
    const groups = {};
    for (const s of spans) {
      if (!match(s)) continue;
      const g = inspectorGroup(s);
      (groups[g] = groups[g] || []).push(s);
    }
    const ordered = INSPECTOR_GROUPS.filter((g) => groups[g]);
    if (ordered.length === 0) {
      board.innerHTML = '<p class="muted">No components match the current search / filters.</p>';
    } else {
      let html = '';
      for (const g of ordered) {
        const list = groups[g];
        html += `<div class="grouphead">${esc(g)} <span class="gcount">${list.length}</span></div>`;
        for (const s of list) {
          const live = s.status === 'RUNNING' ? ' pulse' : '';
          const flash = f.stage && f.stage.has(s.component) ? ' flash' : '';
          html += `<div class="comp${flash}"><div class="row"><span class="nm${live}">${esc(s.name)}</span>${pill(s.status)}</div>`
            + `<div class="meta">${fmtT(s.t0)} → ${s.t1 ? fmtT(s.t1) : '…'} · ${fmtDur(s.durationMs)}${s.detail ? ` · ${esc(s.detail)}` : ''}</div>`;
          if (s.summary) html += `<div class="sum">${esc(s.summary)}</div>`;
          if (s.error) html += `<div class="err">${esc(s.error)}</div>`;
          if (s.extra && typeof s.extra === 'object') {
            html += `<details><summary>details</summary><pre>${esc(JSON.stringify(s.extra, null, 1))}</pre></details>`;
          }
          html += '</div>';
        }
      }
      board.innerHTML = html;
    }
    // Honest remainder: catalog components never observed on a
    // FINISHED trace are listed as not invoked — never as activity.
    const box = $('notObserved');
    if (state.snap && state.snap.status !== 'RUNNING' && state.snap.catalog) {
      const seen = new Set(spans.map((s) => s.component));
      const missing = Object.entries(state.snap.catalog).filter(([id]) => !seen.has(id));
      if (missing.length > 0) {
        box.hidden = false;
        $('notObservedList').innerHTML = missing.map(([id, c]) =>
          `<div class="comp"><div class="row"><span class="nm">${esc(c.name)}</span>${pill('SKIPPED')}</div>`
          + `<div class="meta">${esc(c.group)} · no event recorded — not invoked on this path</div></div>`).join('');
      } else { box.hidden = true; }
    } else { box.hidden = true; }
  }

  function renderTimeline() {
    const ol = $('timeline');
    const spans = [...state.spans.values()];
    const rows = [];
    for (const s of spans) {
      rows.push({ t: s.t0, cls: 'RUNNING', text: `${s.name} started${s.detail ? ` — ${s.detail}` : ''}` });
      if (s.t1) {
        const what = s.status === 'COMPLETED' ? (s.summary || 'done')
          : s.status === 'SKIPPED' ? `skipped — ${s.summary || ''}`
            : (s.error || 'failed');
        rows.push({ t: s.t1, cls: s.status, text: `${s.name} → ${s.status} (${fmtDur(s.durationMs)}) — ${what}` });
      }
    }
    rows.sort((a, b) => a.t - b.t);
    $('tlCount').textContent = `· ${rows.length} events`;
    ol.innerHTML = rows.map((r) => `<li><span class="t">${fmtT(r.t)}</span> <span class="${esc(r.cls)}">${esc(r.cls)}</span> ${esc(r.text)}</li>`).join('');
  }

  const TABS = [
    ['overview', 'Objective & transaction'],
    ['decoded', 'Decoded'],
    ['effects', 'Effects'],
    ['findings', 'Findings & safeguards'],
    ['validation', 'Validation'],
    ['model', 'Model investigation'],
    ['bundle', 'Full record']
  ];
  let activeTab = 'overview';

  function tierPill(t) {
    return `<span class="tier ${esc(t)}">${esc(t)}</span>`;
  }

  function renderEvidence() {
    const tabs = $('evTabs');
    tabs.innerHTML = '';
    for (const [id, label] of TABS) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'tab';
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', id === activeTab ? 'true' : 'false');
      b.textContent = label;
      b.addEventListener('click', () => { activeTab = id; renderEvidence(); });
      tabs.appendChild(b);
    }
    const body = $('evBody');
    const st = state.status;
    const rec = state.record;
    $('evHint').textContent = rec ? `· persisted record ${shortId(rec.recordId || '')} · ${rec.reasoningOrigin || ''} · ${rec.modelId || ''}`
      : (st ? '· live request status (persisted bundle pending or heuristic path)' : '');
    if (!st && !rec) {
      body.innerHTML = '<p class="muted">Run or select an investigation to inspect its evidence.</p>';
      return;
    }
    const tx = (rec && rec.decodedTransaction) || null;
    const card = (title, inner) => `<div class="evcard"><h3>${esc(title)}</h3>${inner}</div>`;
    const pre = (v) => `<pre>${esc(typeof v === 'string' ? v : JSON.stringify(v, null, 1))}</pre>`;
    if (activeTab === 'overview') {
      const lp = state.lastProposal;
      const eiFirst = rec && rec.explicitIntent && Array.isArray(rec.explicitIntent.statements) && rec.explicitIntent.statements[0]
        ? rec.explicitIntent.statements[0].quote : null;
      const purpose = (lp && state.snap && lp.requestId === state.snap.requestId ? lp.objective : null)
        || eiFirst
        || '(agent-stated purpose unavailable: run a scenario in-session or wait for the model-origin bundle)';
      body.innerHTML = `<div class="evgrid">`
        + card('Agent objective ' + tierPill('UNTRUSTED'), `<pre>${esc((st && st.requestId) || '')}\n${esc(purpose)}</pre>`)
        + card('Submitted transaction ' + tierPill('UNTRUSTED'), pre((st && st.txDigest ? { txDigest: st.txDigest } : { note: 'payload hash only; full bytes stay in the signed request' })))
        + card('Decision ' + tierPill('DETERMINISTIC'), pre({ decision: st ? st.decision : null, reasons: st ? st.reasons : [], mandate: st ? st.mandate : null }))
        + card('Execution ' + tierPill('VERIFIED'), pre(st && st.execution ? st.execution : { note: 'no execution recorded' }))
        + `</div>`;
    } else if (activeTab === 'decoded') {
      body.innerHTML = tx ? `<div class="evgrid">`
        + card('Call ' + tierPill('VERIFIED'), pre({ contract: tx.contract, contractName: tx.contractName, functionName: tx.functionName, standard: tx.standard, valueEth: tx.valueEth }))
        + card('Parameters ' + tierPill('VERIFIED'), pre(tx.parameters || {}))
        + card('Subcalls ' + tierPill('DETERMINISTIC'), pre((rec && rec.subcalls) || { note: 'no nested calls' }))
        + `</div>`
        : '<p class="muted">Decoded transaction available once the persisted bundle loads (model-origin runs).</p>';
    } else if (activeTab === 'effects') {
      const fx = rec && rec.effects;
      body.innerHTML = fx ? `<div class="evgrid">`
        + card('Reconstructed effects ' + tierPill('DETERMINISTIC'), pre(fx.effects || []))
        + card('Summary', pre(fx.summary || {}))
        + card('Composition ' + tierPill('DETERMINISTIC'), pre((rec && rec.composition) || {}))
        + `</div>`
        : '<p class="muted">Effect reconstruction available once the persisted bundle loads (model-origin runs).</p>';
    } else if (activeTab === 'findings') {
      const findings = (st && st.investigation && st.investigation.ruleFindings) || ((rec && rec.ruleFindings) || []);
      const guards = (st && st.investigation && st.investigation.safeguardTriggers) || ((rec && rec.verdictSafeguards) || []);
      const lp = state.lastProposal;
      const mandateChecks = (lp && state.snap && lp.requestId === state.snap.requestId && lp.mandateChecks)
        || { note: 'per-check detail travels with the propose response; mandate outcome is in the decision reasons' };
      body.innerHTML = `<div class="evgrid">`
        + card('Security findings ' + tierPill('DETERMINISTIC'), pre(findings.length ? findings : { note: 'no findings' }))
        + card('Safeguard triggers ' + tierPill('DETERMINISTIC'), pre(guards.length ? guards : { note: 'no safeguard triggered' }))
        + card('Mandate checks ' + tierPill('DETERMINISTIC'), pre(mandateChecks))
        + `</div>`;
    } else if (activeTab === 'validation') {
      body.innerHTML = rec ? `<div class="evgrid">`
        + card('Reference validation ' + tierPill('DETERMINISTIC'), pre(rec.referenceValidation || {}))
        + card('Support validation ' + tierPill('DETERMINISTIC'), pre((rec.supportValidation) || {}))
        + card('Semantic claims ' + tierPill('DETERMINISTIC'), pre((rec.semanticClaims && rec.semanticClaims.summary) || {}))
        + card('Reconciliation ' + tierPill('DETERMINISTIC'), pre(rec.reconciliation || {}))
        + `</div>`
        : '<p class="muted">Validation results available once the persisted bundle loads (model-origin runs).</p>';
    } else if (activeTab === 'model') {
      const inv = rec && rec.investigation;
      body.innerHTML = inv ? `<div class="evgrid">`
        + card(`Investigation ${tierPill('MODEL')} `, pre({ verdict: rec.verdict, confidence: rec.confidence, summary: rec.summary, recommendedAction: rec.recommendedAction }))
        + card('Conclusions', pre(inv.conclusions || []))
        + card('Discrepancies', pre(inv.discrepancies || []))
        + card('Contradictions', pre(inv.contradictions || []))
        + card('Uncertainty', pre(inv.uncertainty || {}))
        + card('Missing evidence', pre(inv.missingEvidence || []))
        + `</div>`
        : '<p class="muted">Model investigation available once the persisted bundle loads (model-origin runs). Heuristic-fallback runs carry no model interpretation.</p>';
    } else {
      body.innerHTML = rec ? `<div class="evgrid">${card('Full persisted record (redacted at persist time)', pre(rec))}</div>`
        : '<p class="muted">No persisted record for this evaluation (model-origin records only).</p>';
    }
  }

  async function pollStatus(requestId, once) {
    const tick = async () => {
      try {
        const st = await api(`/api/v1/agent/requests/${encodeURIComponent(requestId)}`);
        if (state.snap && st.requestId !== state.snap.requestId && state.snap.requestId) return false;
        state.status = st;
        renderOverview();
        renderFlow();
        renderSecurity();
        renderEvidence();
        const rec = state.record;
        if (!rec && st.investigation && st.investigation.evalId) {
          try {
            const found = await api(`/api/v1/observations/investigations/by-eval/${encodeURIComponent(st.investigation.evalId)}`);
            state.record = found.record;
            renderOverview();
            renderAI();
            renderSecurity();
            renderEvidence();
          } catch { /* heuristic path or not yet persisted; status view stands */ }
        }
        if (st.execution) {
          if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
          if (state.snap) { try { state.snap = await api(`/api/v1/observations/traces/${encodeURIComponent(state.activeId)}`); renderAll(); } catch { /* ignore */ } }
          return true;
        }
      } catch { /* keep polling */ }
      return false;
    };
    if (once) { await tick(); return; }
    await tick();
    if (state.pollTimer) clearInterval(state.pollTimer);
    const started = Date.now();
    state.pollTimer = setInterval(async () => {
      const done = await tick();
      if (done || Date.now() - started > 90000) {
        clearInterval(state.pollTimer); state.pollTimer = null;
        if (!done) $('runStatus').textContent = 'Status polling stopped after 90s (no execution recorded).';
      }
    }, 2000);
  }

  async function runScenario(s) {
    if (state.running) return;
    state.running = true;
    state.activeScenario = s.id;
    markActiveScenario();
    setButtonsDisabled(true);
    $('runStatus').textContent = `Running ${s.name}… proposing to /api/v1/agent/propose.`;
    try {
      const t0 = performance.now();
      const out = await api('/api/v1/agent/propose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentId: 'command-centre',
          intent: { purpose: s.objective },
          transaction: s.transaction
        })
      });
      const proposeMs = Math.round(performance.now() - t0);
      $('runStatus').textContent = `${s.name}: decision ${out.decision} in ${fmtDur(proposeMs)} (browser-measured). Following live trace…`;
      state.lastProposal = {
        scenario: s.id, objective: s.objective, agentId: 'command-centre',
        transaction: s.transaction, approval: out.approval || null, requestId: out.requestId,
        mandateChecks: out.mandateChecks || null, mandate: out.mandate || null,
        txDigest: out.txDigest || null, proposeMs
      };
      await refreshTraceList(false);
      const traceId = out.traceId || (state.traces.find((t) => t.requestId === out.requestId) || {}).id;
      if (traceId) {
        await selectTrace(traceId);
        void pollStatus(out.requestId, false);
      } else {
        $('runStatus').textContent = `${s.name}: decision ${out.decision} (trace not found in ring).`;
      }
    } catch (err) {
      $('runStatus').textContent = `${s.name} failed: ${err.message}`;
    } finally {
      state.running = false;
      setButtonsDisabled(false);
    }
  }

  function setButtonsDisabled(disabled) {
    document.querySelectorAll('#scenarioList button').forEach((b) => { b.disabled = disabled; });
  }

  function tickClock() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    $('clock').textContent = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} local`;
  }

  async function boot() {
    setInterval(tickClock, 1000);
    tickClock();
    await checkHealth();
    await loadScenarios();
    await refreshTraceList(false);
    const sel = $('tracePicker');
    // Deep-link: ?trace=<id> opens one investigation directly (read-only).
    const want = new URLSearchParams(window.location.search).get('trace');
    if (want && state.traces.some((t) => t.id === want)) await selectTrace(want);
    else if (sel.value) await selectTrace(sel.value);
    else showContent(false);
    $('refreshBtn').addEventListener('click', async () => {
      await checkHealth();
      await refreshTraceList(true);
      const cur = $('tracePicker').value;
      if (cur) await selectTrace(cur);
      else { state.activeId = null; showContent(false); }
    });
    sel.addEventListener('change', () => selectTrace(sel.value));
    $('inspSearch').addEventListener('input', renderComponents);
    $('inspStatus').addEventListener('change', renderComponents);
    $('inspGroup').addEventListener('change', renderComponents);
    $('inspClear').addEventListener('click', () => {
      state.selectedStage = null;
      $('inspClear').hidden = true;
      renderFlow();
      renderComponents();
    });
    if (!new URLSearchParams(window.location.search).has('static')) {
      state.listTimer = setInterval(() => refreshTraceList(true), 5000);
      setInterval(checkHealth, 15000);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    boot().catch((err) => {
      $('runStatus').textContent = `UI failed to start: ${err.message}`;
    });
  });

  // Bridge for the multi-view shell (views.js): reuses this core's
  // backend integration (api, trace selection, live state) unchanged.
  window.AssertaraCC = {
    api,
    selectTrace,
    refreshTraceList,
    getState: () => state,
    scenarioById: (id) => state.scenarioDefs.find((s) => s && s.id === id)
  };
})();
