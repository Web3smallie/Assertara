/**
 * Investigation handle: the object an agent holds from submission to
 * execution. Thin convenience over AssertaraClient bound to one
 * requestId/traceId pair; every read re-fetches, so handles never go
 * stale and decisions are never cached across the execute boundary.
 */

class Investigation {
  constructor(client, { requestId, traceId, txDigest, snapshot } = {}) {
    if (!client) throw new Error('Investigation requires an AssertaraClient.');
    if (!requestId) throw new Error('Investigation requires a requestId.');
    this.client = client;
    this.requestId = requestId;
    this.traceId = traceId || null;
    this.txDigest = txDigest || null;
    this.snapshot = snapshot || null; // optional terminal snapshot (idempotent replay)
  }

  async status() {
    return this.client.getStatus(this.requestId);
  }

  // Terminal record (decision set) or REJECTED record. Uses the stored
  // snapshot when this handle came from an idempotent replay. Follows
  // the live trace stream when a traceId is known (polling fallback
  // inside); polls when it is not.
  async wait(opts) {
    if (this.snapshot && (this.snapshot.decision || this.snapshot.status === 'REJECTED')) {
      return this.snapshot;
    }
    const st = this.traceId
      ? await this.client.waitForDecisionLive(this.requestId, { ...(opts || {}), traceId: this.traceId })
      : await this.client.waitForDecision(this.requestId, opts);
    this.snapshot = st;
    return st;
  }

  async evidence() {
    return this.client.getEvidence(this.requestId);
  }

  async trace() {
    if (!this.traceId) throw new Error('No traceId for this investigation.');
    return this.client.getTrace(this.traceId);
  }

  // Genuine live span events (see client.streamProgress). Requires the
  // traceId returned at submission.
  async stream(onEvent, opts) {
    if (!this.traceId) throw new Error('No traceId for this investigation.');
    return this.client.streamProgress(this.traceId, onEvent, opts);
  }

  // Guarded execution of the exact investigated bytes (see
  // client.execute for the full guard list). The caller may hand over
  // the terminal record it has just observed to skip the redundant
  // status re-read; every guard still runs.
  async execute(transaction, { status } = {}) {
    return this.client.execute({ requestId: this.requestId, transaction, status });
  }

  async waitForExecution(opts) {
    return this.client.waitForExecution(this.requestId, opts);
  }
}

module.exports = { Investigation };
