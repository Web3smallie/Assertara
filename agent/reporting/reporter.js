/**
 * Agent reporter: genuine stage log for one task.
 *
 * Every entry is something that actually happened (planner output,
 * SDK progress events, published decisions, verified receipts). The
 * reporter never invents activity: it records, timestamps, and fans
 * out to an optional observer (demo harness, future Command Centre
 * feed). Observer failures never break the run.
 */

function createReporter({ taskId, onEvent } = {}) {
  const steps = [];
  const emit = typeof onEvent === 'function' ? onEvent : null;

  function log(event, detail, extra) {
    const entry = { at: Date.now(), taskId: taskId || null, event, detail: detail || null, ...(extra || {}) };
    steps.push(entry);
    if (emit) {
      try { emit(entry); } catch { /* observability must not break the run */ }
    }
    return entry;
  }

  return { steps, log };
}

module.exports = { createReporter };
