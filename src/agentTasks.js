/**
 * Agent task HTTP surface (browser trigger for the autonomous agent).
 *
 * Boundary design: this module lives in src/ but NEVER imports the agent
 * subsystem. A runner is injected by the hosting process (demo
 * command-stack), which owns the agent runtime, model credentials, and
 * signer wiring. Without an injected runner the endpoints honestly answer
 * 503. With one, they submit tasks and project live outcomes.
 *
 * Runner contract: { submit(taskText) -> { taskId }, get(taskId) ->
 * outcome|null }. submit throws { code: 'TASK_RUNNING' } when busy.
 */

let runner = null;

function setAgentTaskRunner(r) {
  runner = r || null;
}

function isAttached() {
  return Boolean(runner);
}

function str(v, max) {
  if (typeof v !== 'string') return null;
  return v.length > max ? v.slice(0, max) : v;
}

function projectStep(s) {
  if (!s || typeof s !== 'object') return null;
  return {
    at: Number.isFinite(s.at) ? s.at : null,
    event: typeof s.event === 'string' ? s.event : null,
    detail: str(s.detail, 500),
    actionIndex: Number.isInteger(s.actionIndex) ? s.actionIndex : null,
    requestId: typeof s.requestId === 'string' ? s.requestId : null,
    traceId: typeof s.traceId === 'string' ? s.traceId : null,
    decision: typeof s.decision === 'string' ? s.decision : null,
    txHash: typeof s.txHash === 'string' ? s.txHash : null
  };
}

function projectTimings(t, keys) {
  if (!t || typeof t !== 'object') return null;
  const out = {};
  for (const k of keys) {
    out[k] = Number.isFinite(t[k]) && t[k] >= 0 ? t[k] : null;
  }
  return out;
}

function projectAction(a) {
  if (!a || typeof a !== 'object') return null;
  const tx = a.transaction && typeof a.transaction === 'object' ? {
    from: a.transaction.from || null,
    to: a.transaction.to || null,
    value: a.transaction.value !== undefined && a.transaction.value !== null ? String(a.transaction.value) : null,
    data: typeof a.transaction.data === 'string' ? a.transaction.data.slice(0, 4096) : null,
    chainId: a.transaction.chainId !== undefined && a.transaction.chainId !== null ? String(a.transaction.chainId) : null
  } : null;
  return {
    index: Number.isInteger(a.index) ? a.index : null,
    transaction: tx,
    digestPreview: typeof a.digestPreview === 'string' ? a.digestPreview : null,
    requestId: typeof a.requestId === 'string' ? a.requestId : null,
    traceId: typeof a.traceId === 'string' ? a.traceId : null,
    txDigest: typeof a.txDigest === 'string' ? a.txDigest : null,
    decision: typeof a.decision === 'string' ? a.decision : null,
    reasons: Array.isArray(a.reasons) ? a.reasons.filter((r) => typeof r === 'string').map((r) => r.slice(0, 1000)).slice(0, 25) : [],
    released: Boolean(a.released),
    txHash: typeof a.txHash === 'string' ? a.txHash : null,
    execution: a.execution && typeof a.execution === 'object' ? a.execution : null,
    findings: a.findings && typeof a.findings === 'object' ? a.findings : null,
    timings: projectTimings(a.timings, ['submitMs', 'waitMs', 'executeMs'])
  };
}

function projectTask(t) {
  if (!t || typeof t !== 'object') return null;
  return {
    taskId: typeof t.taskId === 'string' ? t.taskId : null,
    agent: typeof t.agent === 'string' ? t.agent : null,
    task: str(t.task, 2000),
    status: typeof t.status === 'string' ? t.status : null,
    reasoning: str(t.reasoning, 2000),
    plannerModel: typeof t.plannerModel === 'string' ? t.plannerModel : null,
    planAttempts: Number.isInteger(t.planAttempts) ? t.planAttempts : null,
    decision: typeof t.decision === 'string' ? t.decision : null,
    txHash: typeof t.txHash === 'string' ? t.txHash : null,
    stoppedReason: str(t.stoppedReason, 500),
    timings: projectTimings(t.timings, ['planMs', 'totalMs']),
    actions: Array.isArray(t.actions) ? t.actions.map(projectAction).filter(Boolean).slice(0, 25) : [],
    steps: Array.isArray(t.steps) ? t.steps.slice(-500).map(projectStep).filter(Boolean) : []
  };
}

function handleCreateTask(req, res) {
  try {
    if (!runner) {
      return res.status(503).json({ error: 'Agent runtime not attached to this server. Start the demo command stack with a real MODEL_API_KEY.' });
    }
    const task = req.body && req.body.task;
    if (typeof task !== 'string' || task.trim().length === 0) {
      return res.status(400).json({ error: 'task must be a non-empty string.' });
    }
    if (task.length > 2000) {
      return res.status(400).json({ error: 'task must be at most 2000 characters.' });
    }
    let out;
    try {
      out = runner.submit(task);
    } catch (err) {
      if (err && err.code === 'TASK_RUNNING') {
        return res.status(409).json({ error: 'Another agent task is already running.' });
      }
      throw err;
    }
    if (!out || typeof out.taskId !== 'string') {
      return res.status(500).json({ error: 'Agent runner returned no task id.' });
    }
    return res.status(202).json({ taskId: out.taskId, status: 'RUNNING' });
  } catch (err) {
    return res.status(500).json({ error: `Task submission failed: ${err && err.message ? err.message : String(err)}` });
  }
}

function handleGetTask(req, res) {
  try {
    if (!runner) {
      return res.status(503).json({ error: 'Agent runtime not attached to this server. Start the demo command stack with a real MODEL_API_KEY.' });
    }
    const id = req.params && req.params.id;
    if (typeof id !== 'string' || id.length === 0 || id.length > 128) {
      return res.status(404).json({ error: 'Unknown task id.' });
    }
    const t = runner.get(id);
    if (!t) return res.status(404).json({ error: 'Unknown task id.' });
    return res.status(200).json(projectTask(t));
  } catch (err) {
    return res.status(500).json({ error: `Task lookup failed: ${err && err.message ? err.message : String(err)}` });
  }
}

module.exports = { setAgentTaskRunner, isAttached, handleCreateTask, handleGetTask, projectTask };
