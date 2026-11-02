/**
 * Investigation capacity guard (SDK/API milestone).
 *
 * In-memory, single-instance accounting for concurrent investigations
 * (each holds a 25-60s model call plus trace buffers). Two caps:
 * - Global in-flight cap (MAX_CONCURRENT_INVESTIGATIONS, default 8):
 *   protects the process and the shared model budget.
 * - Per-key in-flight cap (AGENT_MAX_INFLIGHT_PER_KEY, default 2):
 *   one integration cannot starve the others. Dev-mode callers share
 *   one 'dev' bucket.
 *
 * Applies in every mode (it guards resources, not identity). Multi-
 * process deployments need a shared store — documented, not built here.
 */

function createCapacityGuard({ maxTotal, maxPerKey } = {}) {
  const total = Number.isSafeInteger(maxTotal) && maxTotal > 0 ? maxTotal : 8;
  const perKey = Number.isSafeInteger(maxPerKey) && maxPerKey > 0 ? maxPerKey : 2;
  let inFlight = 0;
  const perKeyCounts = new Map();

  function bucket(req) {
    const k = req && req.agentKey && typeof req.agentKey.keyId === 'string' && req.agentKey.keyId
      ? req.agentKey.keyId : 'dev';
    return k;
  }

  // Returns { ok:true, release } or { ok:false, retryAfterMs }.
  // The caller MUST call release() exactly once on completion.
  function acquire(req) {
    const b = bucket(req);
    const keyed = perKeyCounts.get(b) || 0;
    if (inFlight >= total || keyed >= perKey) {
      return { ok: false, retryAfterMs: 5000 };
    }
    inFlight += 1;
    perKeyCounts.set(b, keyed + 1);
    let released = false;
    return {
      ok: true,
      release() {
        if (released) return;
        released = true;
        inFlight = Math.max(0, inFlight - 1);
        perKeyCounts.set(b, Math.max(0, (perKeyCounts.get(b) || 1) - 1));
      }
    };
  }

  function stats() {
    return { inFlight, maxTotal: total, maxPerKey: perKey };
  }

  return { acquire, stats };
}

module.exports = { createCapacityGuard };
