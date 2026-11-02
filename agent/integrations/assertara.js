/**
 * Assertara integration: the agent's ONLY touchpoint with Assertara.
 *
 * This is the single file in agent/ allowed to import the SDK
 * (enforced by test/unit/agentBoundary.test.js). It sequences SDK
 * calls per action — submit, observe genuine progress, await the
 * published decision, execute only through client.execute() guards —
 * and returns plain outcome records. It holds no keys, mints no
 * approvals, and cannot override any decision.
 */

const { AssertaraClient, isCleanExecution } = require('../../sdk/index');

function createAssertaraIntegration({ client, agentId } = {}) {
  if (!client || typeof client.submit !== 'function') {
    throw new Error('createAssertaraIntegration requires an AssertaraClient (submit/wait/execute).');
  }
  const agent = typeof agentId === 'string' && agentId ? agentId.slice(0, 128) : 'autonomous-agent';

  async function connect() {
    return client.connect();
  }

  // Full guarded flow for ONE action's exact bytes. Resolves (never
  // throws for decisions) to a plain outcome carrying the shared ids:
  // { requestId, traceId, txDigest, decision, reasons, released,
  //   txHash, execution, findings, timings }. Transport/timeout errors
  // propagate. Timings are genuine measured client-side durations.
  async function executeAction(tx, { purpose, idempotencyKey, evidence, operatorTimeoutMs, onProgress, onEvent } = {}) {
    const emit = typeof onEvent === 'function'
      ? (event, detail, extra) => { try { onEvent(event, detail, extra); } catch { /* observability never breaks the run */ } }
      : () => {};
    const timings = { submitMs: null, waitMs: null, executeMs: null };
    let t0 = Date.now();
    const inv = await client.submit({ transaction: tx, purpose, agentId, idempotencyKey, evidence });
    timings.submitMs = Date.now() - t0;
    emit('ACTION_SUBMITTED', `requestId=${inv.requestId} traceId=${inv.traceId}`, { requestId: inv.requestId, traceId: inv.traceId, txDigest: inv.txDigest });
    t0 = Date.now();
    const decided = await inv.wait({
      onProgress: (p) => {
        const museState = p.progress && p.progress.museSpark ? p.progress.museSpark.state : null;
        emit('INVESTIGATION_PROGRESS', museState === null ? `stage=${p.stage}` : `stage=${p.stage} model=${museState}`, { requestId: inv.requestId, traceId: inv.traceId });
        if (typeof onProgress === 'function') {
          try { onProgress(p, { requestId: inv.requestId, traceId: inv.traceId }); } catch { /* observer errors never break the run */ }
        }
      }
    });
    timings.waitMs = Date.now() - t0;
    const reasons = Array.isArray(decided.reasons) ? decided.reasons : [];
    emit('DECIDED', `${decided.decision} reasons=${reasons.length}`, { requestId: inv.requestId, traceId: inv.traceId, decision: decided.decision });
    let findings = null;
    try {
      findings = await inv.evidence();
    } catch {
      findings = null; // status reasons already recorded above; evidence is additive detail
    }

    if (decided.decision === 'REVIEW') {
      emit('HELD_FOR_OPERATOR', 'awaiting out-of-band operator release; no signing without a token', { requestId: inv.requestId, traceId: inv.traceId });
      const released = await client.waitForOperatorApproval(inv.requestId, { timeoutMs: operatorTimeoutMs });
      emit('RELEASED', 'operator approval observed; executing exact approved bytes', { requestId: inv.requestId, traceId: inv.traceId });
      t0 = Date.now();
      const signed = await inv.execute(tx, { status: released });
      const execution = await inv.waitForExecution();
      timings.executeMs = Date.now() - t0;
      emit('EXECUTED', `outcome=${execution ? execution.outcome : 'unknown'} txHash=${signed.txHash}`, { requestId: inv.requestId, traceId: inv.traceId, txHash: signed.txHash });
      return {
        requestId: inv.requestId, traceId: inv.traceId, txDigest: inv.txDigest || decided.txDigest || null,
        decision: released.decision || 'REVIEW', reasons, released: true,
        txHash: signed.txHash, receipt: signed.receipt || null, execution, findings, timings
      };
    }
    if (decided.decision !== 'ALLOW') {
      return {
        requestId: inv.requestId, traceId: inv.traceId, txDigest: inv.txDigest || decided.txDigest || null,
        decision: decided.decision, reasons, released: false,
        txHash: null, receipt: null, execution: null, findings, stopped: true, timings
      };
    }
    t0 = Date.now();
    const signed = await inv.execute(tx, { status: decided });
    const execution = await inv.waitForExecution();
    timings.executeMs = Date.now() - t0;
    emit('EXECUTED', `outcome=${execution ? execution.outcome : 'unknown'} txHash=${signed.txHash}`, { requestId: inv.requestId, traceId: inv.traceId, txHash: signed.txHash });
    return {
      requestId: inv.requestId, traceId: inv.traceId, txDigest: inv.txDigest || decided.txDigest || null,
      decision: 'ALLOW', reasons, released: false,
      txHash: signed.txHash, receipt: signed.receipt || null, execution, findings, timings
    };
  }

  return { client, agentId: agent, connect, executeAction, isCleanExecution };
}

function createClient(opts) {
  return new AssertaraClient(opts || {});
}

module.exports = { createAssertaraIntegration, createClient };
