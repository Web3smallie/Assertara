/* Assertara multi-view shell: Agent Workspace, Investigation Centre
 * (rendered by app.js), Execution History, Mandates & Policies,
 * Settings.
 *
 * Strictly backend-driven: every dynamic value comes from a genuine
 * backend response (traces, snapshots, statuses, records, evidence,
 * mandate, health, task outcomes). Nothing is fabricated, no demo
 * controls exist, and this UI never initiates tasks or transactions.
 *
 * Two workspace modes, both read-only:
 * - task mode (?task= id): follows one in-process agent-task outcome.
 * - follow mode (default): follows the latest backend investigation,
 *   including investigations started by out-of-process agents. */

(function () {
  'use strict';

  // Build marker: bump together with the ?v= asset URLs in index.html so
  // a stale cached bundle is detectable (see boot diagnostics below).
  const VIEWS_BUILD = '20261101b';

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s === null || s === undefined ? '' : s)
    .replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function shortAddr(a) {
    if (typeof a !== 'string' || a.length < 12) return a || '—';
    return `${a.slice(0, 6)}…${a.slice(-4)}`;
  }

  function weiToEth(v) {
    try {
      const w = BigInt(v);
      const neg = w < 0n;
      const abs = neg ? -w : w;
      const whole = abs / 1000000000000000000n;
      const frac = (abs % 1000000000000000000n).toString().padStart(18, '0').replace(/0+$/, '');
      return `${neg ? '-' : ''}${whole.toString()}${frac ? `.${frac}` : ''}`;
    } catch { return '—'; }
  }

  function fmtDur(ms) {
    if (!Number.isFinite(ms)) return null;
    if (ms < 1000) return `${Math.round(ms)}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  }

  function oneLine(s, max) {
    const t = typeof s === 'string' ? s.replace(/\s+/g, ' ').trim() : '';
    return t.length > max ? `${t.slice(0, max)}…` : t;
  }

  let CC = null;
  let activePoll = null;
  let followTimer = null;
  let lastWorkspace = null;
  let lastTraceId = null;
  let followTraceId = null;
  let mode = 'idle'; // 'task' | 'follow' | 'idle'

  function setMsg(text, kind) {
    const el = $('taskMsg');
    el.textContent = text || '';
    el.className = `task-msg${kind ? ` ${kind}` : ''}`;
  }

  /* ---------- View router ---------- */

  function switchView(name) {
    document.querySelectorAll('.nav-item').forEach((b) => {
      const on = b.dataset.view === name;
      b.classList.toggle('active', on);
      if (on) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    document.querySelectorAll('.view').forEach((v) => {
      v.hidden = v.id !== `view-${name}`;
    });
    if (name === 'history') void loadHistory();
    if (name === 'mandates') void loadMandates();
    if (name === 'settings') void loadSettings();
    if (name === 'workspace') {
      if (mode === 'task' && lastWorkspace) renderTask(lastWorkspace);
      else if (mode === 'follow') void followTick();
    }
  }

  /* ---------- Status pills (genuine signals only) ---------- */

  let apiContactOk = false;

  async function contact(fn) {
    try {
      const r = await fn();
      apiContactOk = true;
      updateAgentPill();
      return r;
    } catch (err) {
      apiContactOk = false;
      updateAgentPill();
      throw err;
    }
  }

  // The core api() is api(path, init) — a thin fetch wrapper. GET passes
  // no init; POST passes a real RequestInit object. Never swap these.
  function get(path) {
    return contact(() => CC.api(path));
  }

  function updateAgentPill() {
    const dot = $('agentDot');
    const txt = $('agentPillText');
    const pill = $('agentPill');
    const healthBad = $('healthDot') && $('healthDot').className.includes('bad');
    const on = apiContactOk && !healthBad;
    dot.className = `dot ${on ? 'ok' : 'unknown'}`;
    txt.textContent = on ? 'Agent Online' : 'Agent Offline';
    pill.classList.toggle('on', on);
  }

  function mirrorHealth() {
    const dot = $('healthDot');
    const pill = $('sysHealth');
    const txt = $('sysHealthText');
    if (!dot || !pill) return;
    const cls = dot.className || '';
    if (cls.includes('ok')) {
      pill.className = 'health-pill ok';
      txt.textContent = 'System Healthy';
    } else if (cls.includes('bad')) {
      pill.className = 'health-pill bad';
      txt.textContent = $('healthText') ? oneLine($('healthText').textContent, 60) : 'System Unreachable';
    } else {
      pill.className = 'health-pill unknown';
      txt.textContent = 'Connecting…';
    }
    updateAgentPill();
  }

  async function loadNetwork() {
    try {
      const m = await get('/api/v1/agent/mandate');
      const chains = m && Array.isArray(m.chains) ? m.chains : [];
      const c = chains[0];
      // Chain ids arrive as hex strings ("0x7a69" = 31337).
      const rawId = c ? c.id : null;
      const numId = typeof rawId === 'string' && rawId.startsWith('0x') ? parseInt(rawId, 16)
        : (rawId === null || rawId === undefined ? NaN : Number(rawId));
      $('netPillText').textContent = numId === 31337
        ? 'Local (Anvil)'
        : (c && (c.name || (rawId !== null && rawId !== undefined ? `Chain ${rawId}` : null))) || 'Network unknown';
    } catch {
      $('netPillText').textContent = 'Network unknown';
    }
  }

  /* ---------- Shared workspace rendering primitives ---------- */

  function stopAll() {
    if (activePoll) { clearInterval(activePoll); activePoll = null; }
    if (followTimer) { clearInterval(followTimer); followTimer = null; }
  }

  function resetWorkspace() {
    lastWorkspace = null;
    lastTraceId = null;
    setSteps({});
    setBadge('IDLE', '');
    $('agentName').textContent = 'demo-agent';
    $('propTxDetail').textContent = 'No action proposed yet.';
    $('copyTxBtn').hidden = true;
    $('copyTxBtn').onclick = null;
    $('planReasonBox').hidden = true;
    $('planReasonText').textContent = '';
    $('invStatus').textContent = 'Awaiting an agent action.';
    setCheck('intent', '', 'No task submitted');
    setCheck('mandate', '', 'No evaluation yet');
    setCheck('policy', '', 'No evaluation yet');
    setDecision('pending', 'Decision: —', 'No investigation to display yet.');
    $('wsOpenWrap').hidden = true;
  }

  function setSteps(map) {
    document.querySelectorAll('#agentSteps li').forEach((li) => {
      li.className = map[li.dataset.step] || '';
    });
  }

  function setBadge(text, cls) {
    const b = $('agentBadge');
    b.textContent = text;
    b.className = `agent-badge${cls ? ` ${cls}` : ''}`;
  }

  function setCheck(name, cls, sub) {
    const li = document.querySelector(`#invChecks li[data-check="${name}"]`);
    if (!li) return;
    li.className = cls;
    const subEl = li.querySelector('.check-sub');
    if (subEl) subEl.textContent = sub;
  }

  function setDecision(cls, title, sub) {
    $('wsDecision').className = `decision-panel ${cls}`;
    $('wsDecisionTitle').textContent = title;
    $('wsDecisionSub').textContent = sub;
  }

  function showTx(tx) {
    if (tx && tx.to) {
      $('propTxDetail').textContent = `${weiToEth(tx.value)} ETH → ${shortAddr(tx.to)}`;
      $('copyTxBtn').hidden = false;
      $('copyTxBtn').onclick = () => {
        const txt = JSON.stringify(tx, null, 2);
        if (navigator.clipboard && navigator.clipboard.writeText) void navigator.clipboard.writeText(txt);
      };
      return true;
    }
    return false;
  }

  function decisionSub(decision, reasons, action, terminal) {
    const first = Array.isArray(reasons) && reasons.length > 0 ? oneLine(reasons[0], 140) : null;
    if (decision === 'ALLOW') {
      let sub = 'The action is authorized to execute.';
      if (action && action.txHash) {
        sub += ` Executed ${shortAddr(action.txHash)}`;
        if (action.execution && action.execution.receiptStatus) sub += ' · receipt verified';
        sub += '.';
      } else if (!terminal) sub += ' Awaiting execution…';
      return sub;
    }
    if (decision === 'BLOCK') return first || 'Execution prohibited — nothing was signed or broadcast.';
    if (decision === 'REVIEW') return action && action.released ? 'Released by the operator.' : 'Held for operator release.';
    if (decision === 'UNCERTAIN') return first || 'Authorization not established.';
    return first || '';
  }

  function apiErrorText(err) {
    const m = String((err && err.message) || err || 'request failed');
    if (/not attached/i.test(m)) return 'Agent runtime is not attached to this server.';
    if (/already running/i.test(m)) return 'Another agent task is already running.';
    if (/Unknown task id/i.test(m)) return 'Task not found on the server (it may predate a server restart).';
    return `Request failed: ${oneLine(m, 180)}`;
  }

  /* ---------- Task mode: follow one runtime task (?task=) ---------- */

  async function attachTask(taskId) {
    stopAll();
    mode = 'task';
    resetWorkspace();
    setMsg(`Following task ${taskId}…`);
    let first = true;
    const tick = async () => {
      try {
        const o = await get(`/api/v1/agent/tasks/${encodeURIComponent(taskId)}`);
        if (first) setMsg(`Task ${taskId} — showing live server state.`, 'ok');
        first = false;
        lastWorkspace = o;
        renderTask(o);
        if (o.status === 'COMPLETED' || o.status === 'STOPPED' || o.status === 'FAILED') {
          stopAll();
          setMsg(`Task ${taskId} ${o.status.toLowerCase()}.`, o.status === 'COMPLETED' ? 'ok' : '');
          void CC.refreshTraceList(false);
          return false;
        }
        return true;
      } catch (err) {
        first = false;
        setMsg(apiErrorText(err), 'err');
        return true;
      }
    };
    if (await tick()) activePoll = setInterval(() => { void tick(); }, 1000);
  }

  function renderTask(o) {
    if (!o || typeof o !== 'object') return;
    lastWorkspace = o;
    const steps = Array.isArray(o.steps) ? o.steps : [];
    const seen = new Set(steps.map((s) => s && s.event).filter(Boolean));
    const action = Array.isArray(o.actions) && o.actions.length > 0 ? o.actions[0] : null;
    const findings = action && action.findings && typeof action.findings === 'object' ? action.findings : null;
    const decided = seen.has('DECIDED');
    const decisionEntry = steps.find((s) => s && s.event === 'DECIDED');
    const decision = (action && action.decision) || (decisionEntry && decisionEntry.decision) || o.decision || null;
    const terminal = o.status === 'COMPLETED' || o.status === 'STOPPED' || o.status === 'FAILED';

    const map = {};
    if (seen.has('TASK_RECEIVED')) map.received = 'done';
    if (seen.has('PLANNED')) map.planned = 'done';
    else if (seen.has('PLANNING')) map.planned = 'active';
    if (decided) map.investigating = 'done';
    else if (seen.has('ACTION_SUBMITTED') || seen.has('INVESTIGATION_PROGRESS')) map.investigating = 'active';
    if (seen.has('EXECUTED')) map.executing = 'done';
    else if (decided && decision === 'ALLOW') map.executing = 'active';
    if (o.status === 'COMPLETED') map.completed = 'done';
    else if (terminal) map.completed = 'failed';
    setSteps(map);

    if (o.status === 'COMPLETED') setBadge('COMPLETED', 'good');
    else if (o.status === 'FAILED') setBadge('FAILED', 'bad');
    else if (o.status === 'STOPPED') {
      const r = String(o.stoppedReason || '');
      if (r.startsWith('BLOCKED')) setBadge('BLOCKED', 'bad');
      else if (r.startsWith('HELD')) setBadge('AWAITING APPROVAL', 'warn');
      else setBadge('STOPPED', 'warn');
    } else if (seen.has('EXECUTED')) setBadge('EXECUTING', 'live');
    else if (decided && decision === 'ALLOW') setBadge('EXECUTING', 'live');
    else if (decided) setBadge('DECIDED', 'live');
    else if (seen.has('ACTION_SUBMITTED')) setBadge('INVESTIGATING', 'live');
    else if (seen.has('PLANNING')) setBadge('PLANNING', 'live');
    else setBadge('RUNNING', 'live');

    $('agentName').textContent = o.agent || 'demo-agent';
    if (action && action.transaction) showTx(action.transaction);
    else $('propTxDetail').textContent = 'No action proposed yet.';

    if (typeof o.reasoning === 'string' && o.reasoning.trim()) {
      $('planReasonBox').hidden = false;
      const meta = [o.plannerModel ? `Model ${o.plannerModel}` : null,
        Number.isInteger(o.planAttempts) ? `plan attempts ${o.planAttempts}` : null].filter(Boolean).join(' · ');
      $('planReasonText').textContent = o.reasoning.trim() + (meta ? `\n\n${meta}` : '');
    } else {
      $('planReasonBox').hidden = true;
    }

    if (!decided) {
      $('invStatus').textContent = seen.has('ACTION_SUBMITTED')
        ? 'Analyzing intent, mandate and policy…'
        : (terminal ? 'Investigation did not complete.' : 'Waiting for the agent action…');
    }
    if (typeof o.task === 'string' && o.task.trim()) {
      setCheck('intent', 'active', `“${oneLine(o.task, 90)}” (agent-stated, untrusted)`);
    } else if (!terminal) {
      setCheck('intent', 'active', 'Waiting for task…');
    }

    const checks = findings && Array.isArray(findings.mandateChecks) ? findings.mandateChecks : null;
    if (checks) {
      const fails = checks.filter((c) => c && c.pass === false);
      if (fails.length === 0) setCheck('mandate', 'pass', `All ${checks.length} mandate checks satisfied`);
      else {
        const f = fails[0];
        setCheck('mandate', 'fail', oneLine((f && (f.message || f.id)) || 'Mandate constraint violated', 90));
      }
    } else if (decided) {
      setCheck('mandate', '', 'Mandate detail not reported');
    }

    const rules = findings && findings.investigation && Array.isArray(findings.investigation.ruleFindings)
      ? findings.investigation.ruleFindings : null;
    if (rules) {
      if (rules.length === 0) setCheck('policy', 'pass', 'No findings — compliant');
      else if (decision === 'ALLOW') setCheck('policy', 'pass', `${rules.length} advisory finding${rules.length === 1 ? '' : 's'}`);
      else setCheck('policy', 'fail', `${rules.length} rule finding${rules.length === 1 ? '' : 's'}`);
    } else if (decided) {
      setCheck('policy', '', 'Policy detail not reported');
    }

    if (decided && decision) {
      $('invStatus').textContent = `Investigation complete — Assertara decided ${decision}.`;
      const reasons = action && Array.isArray(action.reasons) ? action.reasons : [];
      let sub = decisionSub(decision, reasons, action, terminal);
      const inv = findings && findings.investigation && typeof findings.investigation === 'object' ? findings.investigation : null;
      if (inv && typeof inv.verdict === 'string') sub += ` Model: ${inv.verdict}.`;
      setDecision(String(decision).toLowerCase(), `Decision: ${decision}`, sub);
    } else if (terminal) {
      setDecision('uncertain', 'Decision: —', oneLine(o.stoppedReason || 'Task ended before a decision.', 160));
    }

    const traceId = (action && action.traceId)
      || (steps.find((s) => s && s.traceId) || {}).traceId || null;
    if (traceId) {
      lastTraceId = traceId;
      $('wsOpenWrap').hidden = false;
    }
  }

  /* ---------- Follow mode: mirror the latest backend investigation ---------- */

  function pickLatest(traces) {
    let best = null;
    for (const t of traces) {
      if (!t || !t.id) continue;
      if (!best || (Number.isFinite(t.createdAt) && t.createdAt > (best.createdAt || 0))) best = t;
    }
    return best;
  }

  function spanBy(snap, component) {
    const spans = snap && Array.isArray(snap.spans) ? snap.spans : [];
    return spans.find((s) => s && s.component === component) || null;
  }

  async function followTick() {
    let traces;
    try {
      await CC.refreshTraceList(true);
      traces = CC.getState().traces;
    } catch (err) {
      setMsg(`Backend unavailable: ${oneLine(String((err && err.message) || err), 140)}`, 'err');
      return;
    }
    if (!traces || traces.length === 0) {
      if (mode !== 'follow' || followTraceId) {
        mode = 'follow';
        followTraceId = null;
        resetWorkspace();
      }
      setMsg('No investigations recorded yet.');
      return;
    }
    const latest = pickLatest(traces);
    if (!latest) {
      setMsg('No investigations recorded yet.');
      return;
    }
    mode = 'follow';
    if (followTraceId !== latest.id) {
      followTraceId = latest.id;
      resetWorkspace();
      setMsg(`Following investigation ${latest.id}.`, 'ok');
      void CC.refreshTraceList(true);
    }
    // Snapshot (spans + outcome), status, record: all existing endpoints.
    let snap = null;
    let status = null;
    let record = null;
    try {
      snap = await get(`/api/v1/observations/traces/${encodeURIComponent(latest.id)}`);
    } catch {
      snap = null;
    }
    if (latest.requestId) {
      try {
        status = await get(`/api/v1/agent/requests/${encodeURIComponent(latest.requestId)}`);
      } catch {
        status = null;
      }
      const evalId = status && status.investigation && status.investigation.evalId;
      if (evalId) {
        try {
          const found = await get(`/api/v1/observations/investigations/by-eval/${encodeURIComponent(evalId)}`);
          record = found && found.record ? found.record : null;
        } catch {
          record = null;
        }
      }
    }
    renderFollow({ trace: latest, snap, status, record });
  }

  function startFollow() {
    stopAll();
    mode = 'follow';
    followTraceId = null;
    resetWorkspace();
    void followTick();
    followTimer = setInterval(() => {
      if (!$('view-workspace').hidden) void followTick();
    }, 2000);
  }

  function renderFollow({ trace, snap, status, record }) {
    const spans = snap && Array.isArray(snap.spans) ? snap.spans : [];
    const running = snap ? snap.status === 'RUNNING' : trace.status === 'RUNNING';
    const decision = (status && status.decision) || (snap && snap.outcome && snap.outcome.decision) || null;
    const decided = Boolean(decision);
    const reasons = (status && Array.isArray(status.reasons) ? status.reasons : []);
    const exec = (status && status.execution && typeof status.execution === 'object') ? status.execution : null;
    const executed = exec && exec.outcome === 'EXECUTED' && exec.receiptStatus;
    const signerSpan = spanBy(snap, 'signer-call');
    const executing = decided && decision === 'ALLOW' && !executed;
    const terminal = !running && decided;
    const txDigest = (status && status.txDigest) || null;
    const tx = record && record.decodedTransaction && typeof record.decodedTransaction === 'object'
      ? record.decodedTransaction : null;

    // Steps from genuine backend lifecycle state.
    const map = { received: 'done' };
    if (txDigest || tx) map.planned = 'done';
    else map.planned = 'active';
    if (decided || !running) map.investigating = 'done';
    else map.investigating = 'active';
    if (executed) map.executing = 'done';
    else if ((signerSpan && signerSpan.status === 'RUNNING') || executing) map.executing = 'active';
    if (executed) map.completed = 'done';
    else if (terminal) map.completed = 'failed';
    setSteps(map);

    if (executed) setBadge('COMPLETED', 'good');
    else if (snap && snap.status === 'FAILED') setBadge('FAILED', 'bad');
    else if (decided && decision === 'BLOCK') setBadge('BLOCKED', 'bad');
    else if (decided && decision === 'REVIEW') {
      const released = status && status.operatorAuthorized === true;
      setBadge(released ? 'RELEASED' : 'AWAITING APPROVAL', 'warn');
    }
    else if (decided && decision === 'UNCERTAIN') setBadge('UNCERTAIN', 'warn');
    else if ((signerSpan && signerSpan.status === 'RUNNING') || executing) setBadge('EXECUTING', 'live');
    else if (decided) setBadge('DECIDED', 'live');
    else if (running) setBadge('INVESTIGATING', 'live');
    else setBadge('IDLE', '');

    // Agent identity: same-session proposal echo, else honestly absent.
    const st8 = CC.getState();
    const lp = st8.lastProposal;
    const agent = (lp && trace.requestId && lp.requestId === trace.requestId && lp.agentId) || null;
    $('agentName').textContent = agent || 'not reported';

    // The record carries the recipient at top level (record.to) and the
    // decoded value as valueEth/valueWei — all genuine record fields.
    const dtx = tx && typeof tx === 'object' ? tx : null;
    const to = (record && record.to)
      || (dtx && (dtx.contract || (dtx.parameters && dtx.parameters.recipient))) || null;
    const valEth = (dtx && (dtx.valueEth || (dtx.valueWei ? weiToEth(dtx.valueWei) : null))) || null;
    if (to) {
      $('propTxDetail').textContent = `${valEth || '—'} ETH → ${shortAddr(to)}`;
      $('copyTxBtn').hidden = false;
      const clip = { to, valueEth: (dtx && dtx.valueEth) || null, valueWei: (dtx && dtx.valueWei) || null };
      $('copyTxBtn').onclick = () => {
        if (navigator.clipboard && navigator.clipboard.writeText) void navigator.clipboard.writeText(JSON.stringify(clip, null, 2));
      };
    } else {
      $('propTxDetail').textContent = 'No action details reported yet.';
      $('copyTxBtn').hidden = true;
      $('copyTxBtn').onclick = null;
    }
    $('planReasonBox').hidden = true;

    if (!decided) {
      $('invStatus').textContent = running
        ? 'Analyzing intent, mandate and policy…'
        : 'Waiting for the investigation…';
    } else {
      const dur = fmtDur(snap && Number.isFinite(snap.durationMs) ? snap.durationMs : NaN);
      $('invStatus').textContent = `Investigation complete — Assertara decided ${decision}${dur ? ` in ${dur}` : ''}.`;
    }

    // The persisted record carries the agent-stated purpose inside
    // pageEvidence.title ("[agent-asserted] ..."). Shown verbatim with
    // its untrusted provenance — never as a verified fact.
    const purpose = record && record.pageEvidence && typeof record.pageEvidence === 'object'
      ? (record.pageEvidence.title || null) : null;
    if (typeof purpose === 'string' && purpose.trim()) {
      setCheck('intent', 'active', `“${oneLine(purpose, 90)}” (agent-stated, untrusted)`);
    } else {
      setCheck('intent', '', 'Recorded purpose not exposed by backend');
    }

    const mSpan = spanBy(snap, 'mandate-eval');
    if (mSpan) {
      if (mSpan.status === 'COMPLETED') setCheck('mandate', 'pass', oneLine(mSpan.summary || 'Mandate evaluation completed', 90));
      else if (mSpan.status === 'FAILED') setCheck('mandate', 'fail', oneLine(mSpan.error || mSpan.summary || 'Mandate evaluation failed', 90));
      else if (mSpan.status === 'RUNNING') setCheck('mandate', 'active', 'Evaluating mandate…');
      else setCheck('mandate', '', oneLine(mSpan.summary || 'Mandate evaluation not recorded', 90));
    } else {
      setCheck('mandate', '', 'Mandate evaluation not recorded');
    }

    const rules = status && status.investigation && Array.isArray(status.investigation.ruleFindings)
      ? status.investigation.ruleFindings : null;
    if (rules) {
      if (rules.length === 0) setCheck('policy', 'pass', 'No findings — compliant');
      else if (decision === 'ALLOW') setCheck('policy', 'pass', `${rules.length} advisory finding${rules.length === 1 ? '' : 's'}`);
      else if (decided) setCheck('policy', 'fail', `${rules.length} rule finding${rules.length === 1 ? '' : 's'}`);
      else setCheck('policy', 'active', 'Evaluating policy…');
    } else if (decided) {
      setCheck('policy', '', 'Policy detail not reported');
    } else {
      setCheck('policy', '', 'No evaluation yet');
    }

    if (decided) {
      const action = { txHash: exec && exec.txHash, execution: exec, released: status && status.operatorAuthorized === true };
      let sub = decisionSub(decision, reasons, action, terminal);
      const verdict = status && status.investigation && status.investigation.verdict;
      const mSpark = spanBy(snap, 'muse-spark');
      const usage = mSpark && mSpark.extra && typeof mSpark.extra === 'object' ? mSpark.extra.usage : null;
      if (typeof verdict === 'string') {
        sub += ` Model verdict: ${verdict}.`;
        if (usage && (Number.isInteger(usage.promptTokens) || Number.isInteger(usage.completionTokens))) {
          const p = Number.isInteger(usage.promptTokens) ? usage.promptTokens : '—';
          const c = Number.isInteger(usage.completionTokens) ? usage.completionTokens : '—';
          sub += ` Tokens ${p}/${c}.`;
        }
      }
      setDecision(String(decision).toLowerCase(), `Decision: ${decision}`, sub);
    } else if (!running && trace.status) {
      setDecision('uncertain', 'Decision: —', 'No decision recorded for this investigation.');
    }

    lastTraceId = trace.id;
    $('wsOpenWrap').hidden = false;
  }

  async function openInInvestigations() {
    if (!lastTraceId) return;
    try {
      await CC.refreshTraceList(false);
      await CC.selectTrace(lastTraceId);
      switchView('investigations');
    } catch (err) {
      setMsg(`Could not open investigation: ${oneLine(String((err && err.message) || err), 140)}`, 'err');
    }
  }

  /* ---------- Execution history (traces + statuses, all genuine) ---------- */

  async function loadHistory() {
    const body = $('historyBody');
    body.innerHTML = '<tr><td colspan="6" class="muted">Loading history…</td></tr>';
    try {
      await contact(() => CC.refreshTraceList(true));
    } catch (err) {
      body.innerHTML = `<tr><td colspan="6" class="muted">History unavailable: backend unreachable (${esc(oneLine(String((err && err.message) || err), 120))}).</td></tr>`;
      return;
    }
    const traces = CC.getState().traces.slice(0, 25);
    if (traces.length === 0) {
      body.innerHTML = '<tr><td colspan="6" class="muted">No investigations recorded yet.</td></tr>';
      return;
    }
    body.innerHTML = '';
    for (const t of traces) {
      const tr = document.createElement('tr');
      const time = t.createdAt ? new Date(t.createdAt).toLocaleString() : '—';
      let who = `<span class="mono">${esc(t.kind || 'trace')}</span>`;
      let dec = '<span class="muted">—</span>';
      let exe = '<span class="muted">—</span>';
      let hash = '<span class="muted">—</span>';
      if (t.requestId) {
        try {
          const st = await get(`/api/v1/agent/requests/${encodeURIComponent(t.requestId)}`);
          who = `<span class="mono">${esc(shortAddr(st.txDigest || t.requestId))}</span><br><span class="hint mono">${esc(String(t.requestId).slice(0, 18))}…</span>`;
          dec = st.decision ? `<span class="pill ${esc(st.decision)}">${esc(st.decision)}</span>` : dec;
          if (st.execution && st.execution.outcome) {
            exe = `<span class="pill ${st.execution.outcome === 'EXECUTED' ? 'EXECUTED' : ''}">${esc(st.execution.outcome)}</span>`;
            if (st.execution.receiptStatus) exe += ' <span class="hint">verified</span>';
          } else if (st.decision === 'BLOCK') exe = '<span class="hint">not executed</span>';
          else if (st.decision === 'REVIEW') exe = '<span class="hint">awaiting release</span>';
          if (st.execution && st.execution.txHash) hash = `<span class="mono">${esc(shortAddr(st.execution.txHash))}</span>`;
        } catch {
          dec = '<span class="muted">unavailable</span>';
        }
      }
      tr.innerHTML = `<td>${esc(time)}</td><td>${who}</td><td>${dec}</td><td>${exe}</td><td>${hash}</td>`
        + `<td><button type="button" class="btn-ghost" data-trace="${esc(t.id)}">Open</button></td>`;
      body.appendChild(tr);
    }
    body.querySelectorAll('button[data-trace]').forEach((b) => {
      b.addEventListener('click', async () => {
        try {
          await CC.selectTrace(b.dataset.trace);
          switchView('investigations');
        } catch (err) {
          setMsg(`Could not open investigation: ${oneLine(String((err && err.message) || err), 140)}`, 'err');
        }
      });
    });
  }

  /* ---------- Mandates & policies ---------- */

  function defrow(k, v) {
    return `<div class="defrow"><span class="dk">${esc(k)}</span><span class="dv">${v}</span></div>`;
  }

  async function loadMandates() {
    const box = $('mandateBody');
    box.innerHTML = '<p class="muted">Loading mandate…</p>';
    try {
      const m = await get('/api/v1/agent/mandate');
      if (!m || m.configured === false) {
        box.innerHTML = '<p class="muted">No mandate is configured on this server.</p>';
        return;
      }
      const fmtT = (v) => (v === null || v === undefined || v === '' ? '—' : esc(String(v)));
      const chains = Array.isArray(m.chains) && m.chains.length > 0
        ? m.chains.map((c) => esc(c && (c.name || (c.id !== undefined ? `Chain ${c.id}` : '?')) || '?')).join(', ')
        : '—';
      box.innerHTML = `<div class="defrows">`
        + defrow('Mandate ID', `<span class="mono">${fmtT(m.id)}</span>`)
        + defrow('Version', fmtT(m.version))
        + defrow('Issuer', `<span class="mono">${fmtT(m.issuer)}</span>`)
        + defrow('Valid from', fmtT(m.notBefore))
        + defrow('Expires', fmtT(m.expiresAt))
        + defrow('Policy ID', `<span class="mono">${fmtT(m.policyId)}</span>`)
        + defrow('Seal', m.sealVerified === true
          ? '<span class="seal-ok">verified</span>'
          : (m.sealVerified === false ? '<span class="seal-bad">INVALID</span>' : `<span class="mono">${fmtT(m.seal)}</span>`))
        + defrow('Seal authority', `<span class="mono">${fmtT(m.sealAuthority)}</span>`)
        + defrow('Supported chains', chains)
        + `</div><p class="hint" style="margin-top:14px">Mandates are issued out-of-band. The agent cannot modify its own authorization, and this interface offers no mandate controls.</p>`;
    } catch (err) {
      box.innerHTML = `<p class="muted">Mandate unavailable: backend unreachable (${esc(oneLine(String((err && err.message) || err), 120))}).</p>`;
    }
  }

  /* ---------- Settings ---------- */

  async function loadSettings() {
    const box = $('settingsBody');
    box.innerHTML = '<p class="muted">Loading settings…</p>';
    const rows = [];
    try {
      const h = await get('/health');
      const healthy = h && h.status === 'healthy';
      rows.push(defrow('Backend status', healthy ? '<span class="seal-ok">healthy</span>' : `<span class="seal-bad">${esc((h && h.status) || 'degraded')}</span>`));
      rows.push(defrow('Service', esc((h && h.service) || 'not reported')));
      rows.push(defrow('Version', esc((h && h.version) || 'not reported')));
      rows.push(defrow('Environment', esc((h && h.nodeEnv) || 'not reported')));
      const models = h && h.models && typeof h.models === 'object'
        ? [`Muse: ${h.models.muse || '—'}`, `SAM: ${h.models.sam || '—'}`].join(' · ') : 'not reported';
      rows.push(defrow('Requested models', esc(models)));
      rows.push(defrow('Model endpoint', `<span class="mono">${esc((h && h.metaApiBaseUrl) || 'not reported')}</span>`));
    } catch (err) {
      rows.push(defrow('Backend status', `<span class="seal-bad">unreachable (${esc(oneLine(String((err && err.message) || err), 80))})</span>`));
    }
    const signer = new URLSearchParams(window.location.search).get('signer');
    rows.push(defrow('Controlled signer', signer
      ? `<span class="mono">${esc(signer)}</span>`
      : 'not configured — execution disabled (add ?signer=URL)'));
    rows.push(defrow('Policy API', `<span class="mono">${esc(window.location.origin)}</span>`));
    try {
      await get('/api/v1/agent/tasks/__probe__');
      rows.push(defrow('Agent tasks', 'attached'));
    } catch (err) {
      const m = String((err && err.message) || '');
      rows.push(defrow('Agent tasks', /Unknown task id/.test(m)
        ? 'attached (task monitoring enabled)'
        : (/not attached/i.test(m) ? 'not attached' : `unknown (${esc(oneLine(m, 80))})`)));
    }
    const n = CC.getState().traces.length;
    rows.push(defrow('Investigations this session', esc(String(n))));
    box.innerHTML = `<div class="defrows">${rows.join('')}</div>`
      + '<p class="hint" style="margin-top:14px">Read-only: this interface cannot change server configuration.</p>';
  }

  /* ---------- Boot ---------- */

  function boot() {
    try { console.info(`[Assertara] views.js build ${VIEWS_BUILD}`); } catch { /* ignore */ }
    if (window.location && window.location.protocol === 'file:') {
      setMsg('This page must be opened through the local Assertara server (http://127.0.0.1:3001/command/), not as a local file — browsers block its API requests otherwise.', 'err');
      return;
    }
    CC = window.AssertaraCC;
    if (!CC || typeof CC.api !== 'function' || typeof CC.refreshTraceList !== 'function') {
      setMsg('Workspace core failed to load (outdated cached app.js). Hard-refresh with Ctrl+Shift+R, then reload the page.', 'err');
      return;
    }
    const required = ['agentSteps', 'wsDecision', 'invChecks', 'historyBody', 'mandateBody', 'settingsBody', 'tracePicker'];
    const missing = required.filter((id) => !$(id));
    if (missing.length > 0) {
      setMsg(`Page structure is outdated (cached index.html, missing: ${missing.join(', ')}). Hard-refresh with Ctrl+Shift+R, then reload the page.`, 'err');
      return;
    }
    document.querySelectorAll('.nav-item').forEach((b) => {
      b.addEventListener('click', () => switchView(b.dataset.view));
    });
    $('wsOpenInvBtn').addEventListener('click', () => { void openInInvestigations(); });
    $('historyRefresh').addEventListener('click', () => { void loadHistory(); });

    mirrorHealth();
    setInterval(mirrorHealth, 2000);
    void loadNetwork();

    // Task mode only when a ?task= id names a real runtime task;
    // otherwise the workspace follows the latest backend investigation.
    let tid = null;
    try {
      tid = new URLSearchParams(window.location.search).get('task');
    } catch { tid = null; }
    if (tid) void attachTask(tid);
    else startFollow();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
