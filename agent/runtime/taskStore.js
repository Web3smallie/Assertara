/**
 * Agent task store: durable intake journal for the autonomous agent.
 *
 * Persists task records (intake, plan summary, action outcomes, final
 * status) across restarts in an atomic JSON snapshot plus an
 * append-only JSONL event log. This is the AGENT's own bookkeeping —
 * it duplicates no Assertara state (requestIds link out to it) and
 * failures here throw loudly rather than silently losing history.
 */

const fs = require('fs');
const path = require('path');

function validTask(t) {
  if (!t || typeof t !== 'object' || Array.isArray(t)) return false;
  if (typeof t.taskId !== 'string' || !t.taskId) return false;
  if (typeof t.task !== 'string') return false;
  return true;
}

function createTaskStore({ snapshotFile, ledgerFile } = {}) {
  const tasks = new Map();

  function persist() {
    if (!snapshotFile) return;
    const body = JSON.stringify({ format: 'assertara-agent-tasks-1', savedAt: Date.now(), tasks: [...tasks.values()] });
    fs.mkdirSync(path.dirname(snapshotFile), { recursive: true });
    const tmp = `${snapshotFile}.tmp`;
    fs.writeFileSync(tmp, body, 'utf8');
    fs.renameSync(tmp, snapshotFile);
  }

  function appendEvent(event) {
    if (!ledgerFile) return;
    try {
      fs.mkdirSync(path.dirname(ledgerFile), { recursive: true });
      fs.appendFileSync(ledgerFile, `${JSON.stringify({ ts: Date.now(), ...event })}\n`, 'utf8');
    } catch {
      /* audit logging must never break task handling */
    }
  }

  function load() {
    tasks.clear();
    if (!snapshotFile || !fs.existsSync(snapshotFile)) return { ok: true, fresh: true };
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(snapshotFile, 'utf8'));
    } catch (err) {
      throw new Error(`agent task snapshot unreadable: ${err.message}`);
    }
    if (!parsed || !Array.isArray(parsed.tasks) || !parsed.tasks.every(validTask)) {
      throw new Error('agent task snapshot structurally invalid');
    }
    for (const t of parsed.tasks) tasks.set(t.taskId, t);
    return { ok: true, fresh: false, count: tasks.size };
  }

  function createTask(record) {
    if (!validTask(record)) throw new Error('createTask requires { taskId, task }.');
    if (tasks.has(record.taskId)) throw new Error(`duplicate taskId ${record.taskId}`);
    const full = { status: 'RUNNING', createdAt: Date.now(), updatedAt: Date.now(), ...record };
    tasks.set(full.taskId, full);
    persist();
    appendEvent({ event: 'TASK_CREATED', taskId: full.taskId });
    return { ...full };
  }

  function updateTask(taskId, patch) {
    const cur = tasks.get(taskId);
    if (!cur) return null;
    const next = { ...cur, ...(patch || {}), taskId, updatedAt: Date.now() };
    tasks.set(taskId, next);
    persist();
    return { ...next };
  }

  function getTask(taskId) {
    const t = tasks.get(taskId);
    return t ? { ...t } : null;
  }

  function listTasks() {
    return [...tasks.values()].map((t) => ({ ...t }));
  }

  return { load, createTask, updateTask, getTask, listTasks, size: () => tasks.size };
}

module.exports = { createTaskStore };
