/**
 * Autonomous agent controller (agent execution system).
 *
 * Agent-facing interface: propose an action, poll its status, obtain
 * operator authorization for REVIEW decisions, and report execution.
 * Reuses the investigation pipeline (decoder, Muse, safeguards,
 * Phase-1 policy composer) by invoking it in-process, then composes
 * its decision with the independently authorised mandate.
 *
 * Trust model: the agent is untrusted. Its intent labels are treated
 * as untrusted claims (compared against decoded facts, never believed).
 * It cannot supply its own mandate, approve itself, or see any secret.
 * Execution authority comes only from approval tokens the policy
 * service issues — verified independently by the signer process.
 */

const crypto = require('crypto');
const { handleEvaluateTransaction } = require('./evaluateController');
const { evaluateMandate, verifyMandateSeal } = require('../services/mandate');
const { fetchChainState } = require('../services/chainStateService');
const { issueApproval, countersignApproval, safeEqualSecret } = require('../services/approvals');
const { digestTx } = require('../../extension/shared/txDigest');
const { requestKey, allowOwner } = require('../middleware/agentAuth');
const telemetry = require('../services/investigationTelemetry');

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;
const DEC_RE = /^[0-9]+$/;
const QUANTITY_FIELDS = ['chainId', 'nonce', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'value', 'type'];

function isQuantity(v) {
  if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0;
  if (typeof v !== 'string') return false;
  const s = v.trim();
  return HEX_RE.test(s) && s.length > 2 ? true : DEC_RE.test(s);
}

async function jsonRpc(rpcUrl, method, params, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || 10000);
  try {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`rpc http ${res.status}`);
    const body = await res.json();
    if (body && body.error) throw new Error(body.error.message || 'rpc error');
    return body ? body.result : null;
  } finally {
    clearTimeout(timer);
  }
}

// BLOCK dominates everything; UNCERTAIN dominates REVIEW because a
// missing check or inconclusive verification cannot be cured by an
// operator click — only REVIEW (all checks complete, human judgment
// required) can be authorized. ALLOW needs both sides clean.
function combineDecisions(first, second) {
  const known = (d) => (d === 'BLOCK' || d === 'REVIEW' || d === 'UNCERTAIN' || d === 'ALLOW' ? d : 'UNCERTAIN');
  const a = known(first);
  const b = known(second);
  if (a === 'BLOCK' || b === 'BLOCK') return 'BLOCK';
  if (a === 'UNCERTAIN' || b === 'UNCERTAIN') return 'UNCERTAIN';
  if (a === 'REVIEW' || b === 'REVIEW') return 'REVIEW';
  return 'ALLOW';
}

function createAgentController(deps) {
  const {
    mandate, mandateError, mandateAuthorities, approvalSecret, operatorSecret,
    approvalTtlMs, requestTtlMs, store, spendingLedger,
    capacity,
    nowFn
  } = deps;
  const now = typeof nowFn === 'function' ? nowFn : Date.now;

  // Mandate authenticity: verified once (memoized), awaited by every
  // authorizing path. Until verification succeeds the mandate is treated
  // as unavailable — proposals degrade to UNCERTAIN, releases and
  // receipts refuse. Status stays readable (transparency, no authority).
  let sealPromise = null;
  const sealSync = { status: 'pending' };
  function sealStatus() {
    if (!sealPromise) {
      const input = mandate
        ? verifyMandateSeal({ mandate, authorities: mandateAuthorities })
        : Promise.resolve({ ok: false, error: mandateError || 'no mandate configured' });
      sealPromise = input.then((r) => {
        if (r.ok) {
          sealSync.status = 'verified';
          sealSync.authority = r.authority;
        } else {
          sealSync.status = 'failed';
          sealSync.error = r.error;
        }
        return r;
      });
    }
    return sealPromise;
  }

  function serviceUnavailable(res) {
    return res.status(503).json({ error: 'Agent execution unavailable: APPROVAL_SECRET is not configured.' });
  }

  function storeUnavailable(res) {
    const reason = (store && typeof store.unavailableReason === 'function' && store.unavailableReason())
      || 'request store unavailable';
    return res.status(503).json({ error: `Agent execution unavailable: ${reason}.` });
  }

  function storeDown() {
    return !store || (typeof store.available === 'function' && !store.available());
  }

  // Serializes receipt recording per request so two receipt paths racing on
  // the same request cannot double-record (the async RPC gap between the
  // idempotency check and the write would otherwise admit both).
  const recordChains = new Map();
  function withRecordLock(requestId, fn) {
    const prev = recordChains.get(requestId) || Promise.resolve();
    const run = prev.then(fn);
    recordChains.set(requestId, run.catch(() => {}));
    return run;
  }

  function validateProposal(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'Proposal body must be an object.' };
    if ('screenshot' in body) {
      return { error: 'Agent proposals do not carry visual evidence in v1: genuine visual capture is Assertara-operated. Omit screenshot.' };
    }
    const tx = body.transaction;
    if (!tx || typeof tx !== 'object' || Array.isArray(tx)) return { error: 'Proposal must include a transaction object.' };
    if (typeof tx.from !== 'string' || !ADDRESS_RE.test(tx.from)) return { error: 'Transaction.from must be a valid address.' };
    if (tx.to === null || tx.to === undefined) return { error: 'Contract creation is unsupported in v1: transaction.to is required.' };
    if (typeof tx.to !== 'string' || !ADDRESS_RE.test(tx.to)) return { error: 'Transaction.to must be a valid address.' };
    if (tx.chainId === undefined || tx.chainId === null || !isQuantity(tx.chainId)) {
      return { error: 'Transaction.chainId is required and must be a numeric quantity.' };
    }
    for (const f of QUANTITY_FIELDS) {
      if (tx[f] !== undefined && tx[f] !== null && !isQuantity(tx[f])) {
        return { error: `Transaction.${f} must be a numeric quantity when present.` };
      }
    }
    if (tx.data !== undefined && tx.data !== null && !(typeof tx.data === 'string' && HEX_RE.test(tx.data))) {
      return { error: 'Transaction.data must be a 0x hex string when present.' };
    }
    if (tx.accessList !== undefined && tx.accessList !== null && !Array.isArray(tx.accessList)) {
      return { error: 'Transaction.accessList must be an array when present.' };
    }
    let purpose = '';
    if (body.intent !== undefined && body.intent !== null) {
      if (typeof body.intent !== 'object' || Array.isArray(body.intent)) return { error: 'Proposal.intent must be an object.' };
      if (body.intent.purpose !== undefined && body.intent.purpose !== null) {
        if (typeof body.intent.purpose !== 'string' || body.intent.purpose.length > 2000) {
          return { error: 'Proposal.intent.purpose must be a string of at most 2000 characters.' };
        }
        purpose = body.intent.purpose;
      }
    }
    if (body.evidence !== undefined && body.evidence !== null && !Array.isArray(body.evidence)) {
      return { error: 'Proposal.evidence must be an array of evidence envelopes when present.' };
    }
    // Bounded for durability: admitted evidence persists on the request
    // record so asynchronous processing can run after the HTTP body is
    // gone. Raw (pre-admission) envelopes are client-controlled, so the
    // array itself is capped here; per-envelope caps stay in admission.
    if (Array.isArray(body.evidence)) {
      if (body.evidence.length > 50) {
        return { error: 'Proposal.evidence must hold at most 50 envelopes.' };
      }
      try {
        if (JSON.stringify(body.evidence).length > 262144) {
          return { error: 'Proposal.evidence must total at most 256 KiB.' };
        }
      } catch {
        return { error: 'Proposal.evidence must be JSON-serializable.' };
      }
    }
    return { tx, purpose, evidence: Array.isArray(body.evidence) ? body.evidence : null };
  }

  // Idempotency-Key for propose/submit: lets SDK clients safely retry
  // (each fresh proposal otherwise spends a full model investigation).
  // Same key + same proposal (digest + purpose) replays the original
  // record; same key + different proposal is a 409 conflict, never a
  // silent second investigation. Header read is defensive: direct
  // controller callers (unit tests) pass no headers at all.
  function idempotencyKeyFrom(req) {
    let raw = null;
    try {
      if (req && typeof req.get === 'function') raw = req.get('Idempotency-Key');
      else if (req && req.headers && typeof req.headers === 'object') {
        raw = req.headers['idempotency-key'];
      }
    } catch {
      raw = null;
    }
    if (raw === undefined || raw === null || raw === '') return { key: null };
    if (typeof raw !== 'string' || raw.length > 128 || !/^[A-Za-z0-9._~:-]+$/.test(raw)) {
      return { key: null, error: 'Idempotency-Key must be 1-128 chars of [A-Za-z0-9._~:-] when present.' };
    }
    return { key: raw };
  }

  // Single builder for the propose response shape, used by the fresh
  // path and by idempotent replays so both return identical fields.
  function proposeResponse(record, { traceId, replayed } = {}) {
    const out = {
      requestId: record.id,
      traceId: traceId || record.traceId || null,
      decision: record.decision,
      reasons: record.reasons || [],
      txDigest: record.txDigest,
      mandate: record.mandateId ? { id: record.mandateId, version: record.mandateVersion } : null,
      policyId: record.mandatePolicyId || null,
      approval: record.decision === 'ALLOW' && record.approval && record.approval.token
        ? record.approval.token : null,
      operatorAuthorizationRequired: record.decision === 'REVIEW',
      operatorAvailable: Boolean(operatorSecret),
      investigation: {
        evalId: record.evalId || null, verdict: record.evalVerdict || null,
        reasoningOrigin: record.reasoningOrigin || null,
        ruleFindings: record.ruleFindings || [], safeguardTriggers: record.safeguardTriggers || []
      },
      mandateChecks: record.mandateChecks || [],
      visual: record.visual || null,
      createdAt: record.createdAt
    };
    if (replayed) out.replayed = true;
    return out;
  }

  // Capability 3 B6 admission, run once at submit time: typed agent
  // evidence is validated, bounded, server-ID'd, and forced UNTRUSTED
  // before the record is created, and the bounded result persists on
  // the record so background processing never needs the HTTP body.
  // Admission failure degrades to no-evidence with a recorded
  // rejection, never a 500: the tx+purpose path still investigates.
  function admitProposalEvidence(evidence, trace) {
    let agentEvidence = { admitted: [], rejected: [] };
    const evSpan = telemetry.startSpan(trace, 'agent-evidence', Array.isArray(evidence) ? `${evidence.length} submitted` : 'none submitted');
    try {
      const { admitAgentEvidence } = require('../services/agentEvidence');
      if (Array.isArray(evidence)) {
        const res2 = admitAgentEvidence(evidence);
        agentEvidence = res2.ok
          ? { admitted: res2.admitted, rejected: res2.rejected }
          : { admitted: [], rejected: [{ index: -1, clientId: null, error: res2.error }] };
      }
      if (evSpan) evSpan.finish(`admitted=${agentEvidence.admitted.length} rejected=${agentEvidence.rejected.length}`);
    } catch (err) {
      agentEvidence = { admitted: [], rejected: [{ index: -1, clientId: null, error: `admission threw: ${String((err && err.message) || err).slice(0, 120)}` }] };
      if (evSpan) evSpan.fail('admission threw; degraded to no-evidence with rejection recorded');
    }
    return agentEvidence;
  }

  function runInvestigation({ normalizedTx, txDigest, purpose, admittedEvidence, ownerKeyId, trace }) {
    return new Promise((resolve) => {
      (async () => {
        // Agent-path chain state uses the mandate's own RPC for the exact
        // investigated chain — never the browser-path configured endpoint.
        let chainState = null;
        const csSpan = telemetry.startSpan(trace, 'chainstate', 'mandate RPC');
        try {
          const chains = mandate && Array.isArray(mandate.chains) ? mandate.chains : [];
          const entry = chains.find((c) => String(c.id).toLowerCase() === String(normalizedTx.chainId).toLowerCase());
          chainState = entry && entry.rpcUrl
            ? await fetchChainState({
              rpcUrl: entry.rpcUrl, chainId: normalizedTx.chainId,
              addresses: [
                { role: 'target', address: normalizedTx.to },
                { role: 'sender', address: normalizedTx.from }
              ],
              timeoutMs: 8000
            })
            : { status: 'unavailable', error: 'no mandate chain RPC for the investigated chain', fetchedAt: Date.now() };
          if (csSpan) csSpan.finish(`status=${chainState.status || 'unknown'}`);
        } catch (err) {
          chainState = { status: 'rpc-error', error: String((err && err.message) || err).slice(0, 200), fetchedAt: Date.now() };
          if (csSpan) csSpan.fail('mandate RPC failed; chain state unavailable');
        }
        return chainState;
      })().then((chainState) => {
      const req = {
        body: {
          pageContext: {
            // Agent labels are untrusted claims: the comparison machinery
            // checks them against decoded facts instead of believing them.
            title: `[agent-asserted] ${(purpose || 'agent proposal').slice(0, 200)}`,
            url: 'agent:proposal',
            visibleText: purpose.slice(0, 2000)
          },
          transaction: normalizedTx,
          txDigest
        }
      };
      const res = {
        statusCode: 200,
        status(code) { this.statusCode = code; return this; },
        json(payload) { resolve({ status: this.statusCode, body: payload }); }
      };
      // Agent evidence arrives pre-admitted at submit time (durable on
      // the record). A missing or malformed bundle degrades to
      // no-evidence with a recorded note, never a 500.
      let agentEvidence = admittedEvidence && typeof admittedEvidence === 'object'
        ? admittedEvidence : { admitted: [], rejected: [] };
      if (!Array.isArray(agentEvidence.admitted) || !Array.isArray(agentEvidence.rejected)) {
        agentEvidence = { admitted: [], rejected: [{ index: -1, clientId: null, error: 'stored evidence bundle malformed; degraded to no-evidence' }] };
      }
      const evSpan = telemetry.startSpan(trace, 'agent-evidence', `pre-admitted at submit (${agentEvidence.admitted.length} admitted, ${agentEvidence.rejected.length} rejected)`);
      if (evSpan) evSpan.finish(`admitted=${agentEvidence.admitted.length} rejected=${agentEvidence.rejected.length}`);
      try {
        const out = handleEvaluateTransaction(req, res, { chainState, investigationType: 'agent', agentEvidence, ownerKeyId: ownerKeyId || null, trace });
        if (out && typeof out.catch === 'function') out.catch((err) => resolve({ status: 500, body: null, error: err }));
      } catch (err) {
        resolve({ status: 500, body: null, error: err });
      }
      }).catch((err) => resolve({ status: 500, body: null, error: err }));
    });
  }

  // Shared submission core for the synchronous (`propose`) and
  // asynchronous (`investigations`) endpoints: validate, bind, dedupe,
  // admit evidence, persist the record. Returns { http } for terminal
  // HTTP outcomes (identical for both endpoints), { replay } for a
  // terminal idempotent replay (each endpoint formats it), or
  // { record, slot } for a fresh submission. Never runs the
  // investigation itself — that is processProposal below.
  async function submitProposal(req, trace) {
    const recvSpan = telemetry.startSpan(trace, 'agent-receiver', '');
    const http = (status, body) => ({ http: { status, body } });
    if (!approvalSecret) { if (recvSpan) recvSpan.fail('service unavailable: no approval secret'); telemetry.failTrace(trace, 'service unavailable'); return http(503, { error: 'Agent execution unavailable: APPROVAL_SECRET is not configured.' }); }
    if (storeDown()) {
      const reason = (store && typeof store.unavailableReason === 'function' && store.unavailableReason()) || 'request store unavailable';
      if (recvSpan) recvSpan.fail('request store unavailable'); telemetry.failTrace(trace, 'store unavailable');
      return http(503, { error: `Agent execution unavailable: ${reason}.` });
    }
    const seal = await sealStatus();
    const valid = validateProposal(req.body || {});
    if (valid.error) {
      if (recvSpan) recvSpan.fail(`invalid proposal: ${valid.error}`);
      telemetry.finishTrace(trace, { decision: null, rejected: 'malformed proposal' });
      return http(400, { error: `Invalid proposal: ${valid.error}` });
    }
    const normalizedTx = {
      from: valid.tx.from,
      to: valid.tx.to,
      data: valid.tx.data === undefined || valid.tx.data === null ? '0x' : valid.tx.data,
      value: valid.tx.value === undefined || valid.tx.value === null ? '0x0' : valid.tx.value,
      chainId: valid.tx.chainId
    };
    for (const k of Object.keys(valid.tx)) {
      if (!(k in normalizedTx)) normalizedTx[k] = valid.tx[k];
    }
    const txDigest = digestTx(normalizedTx);
    if (!txDigest) {
      if (recvSpan) recvSpan.fail('transaction cannot be faithfully represented for binding');
      telemetry.finishTrace(trace, { decision: null, rejected: 'unrepresentable transaction' });
      return http(400, { error: 'Invalid proposal: transaction cannot be faithfully represented for binding.' });
    }
    const idem = idempotencyKeyFrom(req);
    if (idem.error) {
      if (recvSpan) recvSpan.fail(`invalid idempotency key: ${idem.error}`);
      telemetry.finishTrace(trace, { decision: null, rejected: 'invalid idempotency key' });
      return http(400, { error: `Invalid proposal: ${idem.error}` });
    }
    if (idem.key) {
      const prior = store.findByIdempotencyKey(idem.key);
      if (prior) {
        if (prior.txDigest !== txDigest || (prior.purpose || '') !== valid.purpose) {
          if (recvSpan) recvSpan.fail('idempotency key already used for a different proposal');
          telemetry.finishTrace(trace, { decision: null, rejected: 'idempotency key conflict' });
          return http(409, { error: 'Idempotency key was already used for a different proposal.' });
        }
        if (!prior.decision) {
          if (recvSpan) recvSpan.fail('idempotency key already has an investigation running');
          telemetry.finishTrace(trace, { decision: null, replayed: prior.id });
          return http(409, { error: 'An investigation for this idempotency key is already running.', requestId: prior.id });
        }
        store.appendEvent({ event: 'PROPOSE_REPLAYED', requestId: prior.id });
        if (recvSpan) recvSpan.finish(`idempotent replay of ${prior.id}`);
        telemetry.finishTrace(trace, { decision: prior.decision, replayed: prior.id });
        return { replay: prior };
      }
    }
    let slot = null;
    if (capacity && typeof capacity.acquire === 'function') {
      const attempt = capacity.acquire(req);
      if (!attempt.ok) {
        if (recvSpan) recvSpan.fail('investigation capacity exhausted');
        telemetry.finishTrace(trace, { decision: null, rejected: 'capacity exhausted' });
        return http(429, { error: 'Investigation capacity exhausted; retry shortly.', retryAfterMs: attempt.retryAfterMs });
      }
      slot = attempt;
    }
    if (recvSpan) recvSpan.finish(`to=${normalizedTx.to} chain=${String(normalizedTx.chainId)}`, { seal: seal.ok ? (seal.authority || 'verified') : `failed: ${seal.error}` });
    const agentEvidence = admitProposalEvidence(valid.evidence, trace);
    const id = `agent_${crypto.randomUUID()}`;
    trace.requestId = id;
    const record = store.create({
      id, createdAt: now(), updatedAt: now(), status: 'RECEIVED',
      agentId: typeof req.body.agentId === 'string' ? req.body.agentId.slice(0, 128) : null,
      purpose: valid.purpose,
      normalizedTx, txDigest,
      agentEvidence,
      idempotencyKey: idem.key,
      ownerKeyId: requestKey(req).keyId,
      traceId: trace.id,
      visual: { status: 'NOT_APPLICABLE', reason: 'Code-only agent proposal carries no visual interface.' }
    });
    if (!record) {
      if (slot) slot.release();
      telemetry.failTrace(trace, 'request could not be persisted');
      return http(500, { error: 'Agent proposal failed: request could not be persisted.' });
    }
    return { record, slot };
  }

  // Shared investigation + authorization core. Runs the reused
  // pipeline, mandate evaluation, decision combination, subcall
  // binding, and approval issuance for a submitted record. Used
  // identically by the sync endpoint (awaited) and the async endpoint
  // (detached): one code path, one decision semantics. Never throws:
  // unexpected failures are recorded UNCERTAIN (fail closed) and
  // reported via the outcome. The capacity slot releases in `finally`.
  async function processProposal(recordId, { trace, slot } = {}) {
    const release = () => { try { if (slot && typeof slot.release === 'function') slot.release(); } catch { /* release is best-effort */ } };
    try {
      const record = store.get(recordId);
      if (!record) {
        if (trace) telemetry.failTrace(trace, 'request record missing');
        return { outcome: 'thrown', error: 'Request record is missing.' };
      }
      if (record.decision || record.status === 'REJECTED') return { outcome: 'completed', already: true };
      const id = record.id;
      const normalizedTx = record.normalizedTx;
      const txDigest = record.txDigest;
      const seal = await sealStatus();
      const activeMandate = seal.ok ? mandate : null;
      const activeMandateError = seal.ok ? mandateError : seal.error;
      store.update(id, { status: 'INVESTIGATING' });
      store.appendEvent({ event: 'INVESTIGATION_STARTED', requestId: id });

      // Investigation (reused pipeline). A 500 here means the
      // investigation itself failed — recorded as UNCERTAIN, never
      // retried silently, never approved.
      const investigated = await runInvestigation({
        normalizedTx, txDigest, purpose: record.purpose || '',
        admittedEvidence: record.agentEvidence, ownerKeyId: record.ownerKeyId, trace
      });
      if (investigated.status === 400) {
        store.update(id, { status: 'REJECTED', decision: null });
        store.appendEvent({ event: 'REJECTED_MALFORMED', requestId: id, detail: investigated.body && investigated.body.error });
        telemetry.finishTrace(trace, { decision: null, rejected: 'malformed transaction' });
        return { outcome: 'rejected', error: investigated.body && investigated.body.error ? String(investigated.body.error) : 'Invalid transaction.' };
      }
      const bundle = investigated.body || null;
      const investigationFailed = investigated.status !== 200 || !bundle;
      const evalDecision = !investigationFailed && bundle.policyDecision && typeof bundle.policyDecision.decision === 'string'
        ? bundle.policyDecision.decision
        : 'UNCERTAIN';
      const decodedTx = !investigationFailed && bundle.decodedTransaction ? bundle.decodedTransaction : { functionName: 'unknownFunction' };

      const mandateResult = telemetry.timed(trace, 'mandate-eval', activeMandate ? `v${activeMandate.version}` : 'no mandate', () => evaluateMandate({ mandate: activeMandate, mandateError: activeMandateError, tx: normalizedTx, decodedTx, nowMs: now(), ledger: spendingLedger || null }),
        (r) => `decision=${r.decision} checks=${((r && r.checks) || []).length}`);
      const reasons = [];
      if (investigationFailed) {
        reasons.push('investigation: evaluation pipeline failed; held as UNCERTAIN.');
      } else if (bundle.policyDecision && Array.isArray(bundle.policyDecision.reasons)) {
        for (const r of bundle.policyDecision.reasons) reasons.push(`investigation: ${r}`);
      } else {
        reasons.push('investigation: no policy decision produced; held as UNCERTAIN.');
      }
      for (const r of mandateResult.reasons) reasons.push(`mandate: ${r}`);

      let decision = combineDecisions(investigationFailed ? 'UNCERTAIN' : evalDecision, mandateResult.decision);
      // Capability 5 B1: bind the approval to the exact authorized
      // subcall tree. A missing hash cannot be authorized: without the
      // binding the signer would refuse anyway, so hold here with an
      // explicit reason instead of issuing an unbound approval.
      let subcallTreeHash = null;
      try {
        subcallTreeHash = telemetry.timed(trace, 'subcall-bind', '', () => require('../services/nestedCalls').hashSubcallTree(decodedTx),
          (h) => (typeof h === 'string' && h.length > 0 ? `bound (${h.slice(0, 16)}…)` : 'no binding produced'));
      } catch {
        subcallTreeHash = null;
      }
      if ((decision === 'ALLOW' || decision === 'REVIEW') && (typeof subcallTreeHash !== 'string' || subcallTreeHash.length === 0)) {
        reasons.push('mandate: subcall-tree binding unavailable; cannot authorize without inner-operation binding.');
        decision = 'UNCERTAIN';
      }
      // Capability 5 B7: persist the authorized effect list so
      // post-execution receipt reconciliation compares against what
      // was authorized at decision time, not a later recomputation.
      let authorizedEffects = null;
      try {
        const { reconstructEffects } = require('../services/effectReconstruction');
        authorizedEffects = telemetry.timed(trace, 'effects', 'authorization-time binding', () => reconstructEffects({
          tx: { from: normalizedTx.from, to: normalizedTx.to, value: normalizedTx.value },
          decodedTx,
          chainId: normalizedTx.chainId
        }), (r) => `${((r && r.effects) || []).length} authorized effects`);
      } catch {
        authorizedEffects = null;
      }
      store.update(id, {
        status: 'DECIDED', decision, reasons,
        authorizedEffects,
        evalId: bundle && bundle.id ? bundle.id : null,
        evalVerdict: bundle && bundle.verdict ? bundle.verdict : null,
        reasoningOrigin: bundle && bundle.reasoningOrigin ? bundle.reasoningOrigin : null,
        ruleFindings: bundle && Array.isArray(bundle.ruleFindings) ? bundle.ruleFindings : [],
        safeguardTriggers: bundle && Array.isArray(bundle.verdictSafeguards) ? bundle.verdictSafeguards.map((s) => s.trigger) : [],
        mandateChecks: mandateResult.checks,
        mandateVersion: activeMandate ? activeMandate.version : null,
        mandateId: activeMandate ? activeMandate.id : null,
        mandatePolicyId: activeMandate ? activeMandate.policyId : null,
        subcallTreeHash
      });
      store.appendEvent({ event: 'DECIDED', requestId: id, decision, evalId: bundle && bundle.id ? bundle.id : null });

      // Approval issuance: ALLOW now, REVIEW pending operator, else never.
      let approvalToken = null;
      if (decision === 'ALLOW') {
        const token = telemetry.timed(trace, 'approval-issue', 'single-use, no operator', () => issueApproval({
          secret: approvalSecret, requestId: id, txDigest,
          chainId: normalizedTx.chainId, sender: normalizedTx.from,
          mandateId: activeMandate.id, mandateVersion: activeMandate.version, policyId: activeMandate.policyId,
          requiresOperator: false, ttlMs: approvalTtlMs, nowMs: now(), subcallTreeHash
        }), () => 'approval issued');
        const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
        store.update(id, { status: 'APPROVED', approval: { token, nonce: payload.nonce, expiresAt: payload.expiresAt, requiresOperator: false, operatorSig: null } });
        store.appendEvent({ event: 'APPROVAL_ISSUED', requestId: id, nonce: payload.nonce });
        approvalToken = token;
      } else if (decision === 'REVIEW') {
        if (!activeMandate) telemetry.markSkipped(trace, 'approval-issue', 'REVIEW without an active mandate issues nothing');
        if (activeMandate) {
          const token = telemetry.timed(trace, 'approval-issue', 'pending operator countersign', () => issueApproval({
            secret: approvalSecret, requestId: id, txDigest,
            chainId: normalizedTx.chainId, sender: normalizedTx.from,
            mandateId: activeMandate.id, mandateVersion: activeMandate.version, policyId: activeMandate.policyId,
            requiresOperator: true, ttlMs: approvalTtlMs, nowMs: now(), subcallTreeHash
          }), () => 'pending approval issued');
          const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
          store.update(id, { approval: { token: null, pendingToken: token, nonce: payload.nonce, expiresAt: payload.expiresAt, requiresOperator: true, operatorSig: null } });
          store.appendEvent({ event: 'APPROVAL_PENDING_OPERATOR', requestId: id, nonce: payload.nonce });
        }
      }

      if (decision !== 'ALLOW' && decision !== 'REVIEW') telemetry.markSkipped(trace, 'approval-issue', `${decision}: no approval is issued`);
      const record2 = store.get(id);
      const respSpan = telemetry.startSpan(trace, 'agent-response', decision);
      if (respSpan) respSpan.finish(`${reasons.length} reasons, approval=${approvalToken ? 'yes' : 'no'}`);
      // The trace stays open for post-response execution recording
      // (receipt/effect verification appends to it); it is finished
      // when execution records, or left RUNNING on non-executed paths.
      // Close it here only when no execution can follow.
      if (decision === 'BLOCK' || decision === 'UNCERTAIN') {
        telemetry.finishTrace(trace, { decision, evalVerdict: record2.evalVerdict, reasoningOrigin: record2.reasoningOrigin });
      } else {
        trace.outcome = { decision, evalVerdict: record2.evalVerdict, reasoningOrigin: record2.reasoningOrigin };
      }
      return { outcome: 'completed' };
    } catch (err) {
      // Fail closed and durably: an unexpected throw must never leave
      // a record in limbo (RECEIVED forever). The sync endpoint still
      // answers 500; the stored decision is UNCERTAIN either way.
      try {
        const cur = store.get(recordId);
        if (cur && !cur.decision) {
          store.update(recordId, {
            status: 'DECIDED', decision: 'UNCERTAIN',
            reasons: [`Investigation failed unexpectedly (${String((err && err.message) || err).slice(0, 160)}); held as UNCERTAIN.`],
            ruleFindings: cur.ruleFindings || [], safeguardTriggers: cur.safeguardTriggers || [],
            mandateChecks: cur.mandateChecks || []
          });
          store.appendEvent({ event: 'DECIDED', requestId: recordId, decision: 'UNCERTAIN' });
        }
      } catch { /* store failure already marks the store failed; nothing further to do */ }
      try { telemetry.failTrace(trace, err); } catch { /* telemetry never breaks recording */ }
      return { outcome: 'thrown', error: err && err.message ? err.message : String(err) };
    } finally {
      release();
    }
  }

  // Genuine progress projection for a running investigation, derived
  // ONLY from the live trace's real spans. Never synthesized: an
  // evicted or missing trace reports 'unknown' with null progress
  // rather than invented activity. Live span events (start/finish)
  // are progress; decisions, findings, and usage are published
  // results and appear only on the terminal record.
  function runningProgress(record) {
    const trace = telemetry.findByRequest(record.id);
    if (!trace) return { stage: 'unknown', progress: null };
    const spans = Array.isArray(trace.spans) ? trace.spans : [];
    const running = [...spans].reverse().find((s) => s && s.status === 'RUNNING');
    const muse = spans.find((s) => s && s.component === 'muse-spark');
    let museState = 'pending';
    if (muse) {
      museState = muse.status === 'RUNNING' ? 'running'
        : muse.status === 'COMPLETED' ? 'completed'
        : muse.status === 'FAILED' ? 'failed'
        : muse.status === 'SKIPPED' ? 'skipped' : 'pending';
    }
    const extra = muse && muse.extra && typeof muse.extra === 'object' ? muse.extra : null;
    return {
      stage: running ? running.component : 'finalizing',
      progress: {
        spansCompleted: spans.filter((s) => s && s.status !== 'RUNNING').length,
        spansTotal: spans.length,
        traceStatus: trace.status,
        museSpark: {
          state: museState,
          ms: muse && Number.isFinite(muse.durationMs) ? muse.durationMs : null,
          summary: muse ? (muse.summary || muse.error || null) : null,
          usage: extra && extra.usage ? extra.usage : null,
          servingModelId: extra && typeof extra.servingModelId === 'string' ? extra.servingModelId : null,
          attempts: extra && Number.isSafeInteger(extra.attempts) ? extra.attempts : null,
          timeouts: extra && Number.isSafeInteger(extra.timeouts) ? extra.timeouts : null
        }
      }
    };
  }

  // Single builder for the status response shape. Terminal records keep
  // their exact existing fields; running records additionally carry a
  // genuine stage/progress projection (trace-derived, never invented).
  function statusResponse(record, req) {
    void req;
    const body = {
      requestId: record.id,
      status: record.status,
      decision: record.decision || null,
      reasons: record.reasons || [],
      txDigest: record.txDigest,
      traceId: record.traceId || null,
      investigation: {
        evalId: record.evalId || null, verdict: record.evalVerdict || null,
        reasoningOrigin: record.reasoningOrigin || null,
        ruleFindings: record.ruleFindings || [], safeguardTriggers: record.safeguardTriggers || []
      },
      mandate: record.mandateId ? { id: record.mandateId, version: record.mandateVersion } : null,
      approvalToken: approvalComplete(record) ? record.approval.token : null,
      approvalExpiresAt: record.approval ? record.approval.expiresAt : null,
      operatorAuthorizationRequired: Boolean(record.approval && record.approval.requiresOperator),
      operatorAuthorized: Boolean(record.approval && record.approval.operatorSig),
      execution: record.execution || null,
      visual: record.visual || null,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    };
    if (!record.decision && record.status !== 'REJECTED') {
      const prog = runningProgress(record);
      body.stage = prog.stage;
      body.progress = prog.progress;
    }
    return body;
  }

  // Durably close an undecided record as UNCERTAIN (interruption,
  // restart, or TTL expiry). Never touches decided records.
  function finalizeInterrupted(recordId, reason) {
    const cur = store.get(recordId);
    if (!cur || cur.decision) return cur;
    store.update(recordId, {
      status: 'DECIDED', decision: 'UNCERTAIN',
      reasons: [reason],
      ruleFindings: cur.ruleFindings || [], safeguardTriggers: cur.safeguardTriggers || [],
      mandateChecks: cur.mandateChecks || []
    });
    store.appendEvent({ event: 'INVESTIGATION_INTERRUPTED', requestId: recordId });
    return store.get(recordId);
  }

  // Startup recovery: background runs do not survive a restart, so any
  // record left undecided (RECEIVED/INVESTIGATING) is fail-closed to
  // UNCERTAIN with an explicit re-propose reason. Decided records are
  // untouched. Called once from server boot; safe to call in tests.
  function recoverInterrupted() {
    const all = typeof store.all === 'function' ? store.all() : null;
    if (!all) return { recovered: 0 };
    let recovered = 0;
    for (const r of all) {
      if (!r.decision && (r.status === 'RECEIVED' || r.status === 'INVESTIGATING')) {
        finalizeInterrupted(r.id, 'Investigation did not complete before the service restarted; re-propose. Held as UNCERTAIN.');
        recovered += 1;
      }
    }
    return { recovered };
  }

  // Synchronous proposal endpoint (backward compatible): submit via
  // the shared core, await it, answer with the decision. Same request
  // validation and response contract as before the async milestone.
  async function handlePropose(req, res) {
    // The trace is created for every proposal that reaches validation;
    // earlier 503s (unconfigured service) have no request to observe.
    // Telemetry records outcomes only and cannot alter any decision.
    const trace = telemetry.createTrace({ kind: 'agent', label: `propose ${req.body && req.body.transaction ? String(req.body.transaction.to || '').slice(0, 42) : '(no tx)'}` });
    try {
      const sub = await submitProposal(req, trace);
      if (sub.http) return res.status(sub.http.status).json(sub.http.body);
      if (sub.replay) {
        try { res.set('Idempotent-Replayed', 'true'); } catch { /* header is best-effort observability */ }
        return res.status(200).json(proposeResponse(sub.replay, { replayed: true }));
      }
      const requestId = sub.record.id;

      const out = await processProposal(requestId, { trace, slot: sub.slot });
      if (out.outcome === 'rejected') {
        return res.status(400).json({ error: out.error });
      }
      if (out.outcome === 'thrown') {
        return res.status(500).json({ error: `Agent proposal failed: ${out.error}` });
      }
      try { res.set('X-Assertara-Trace', trace.id); } catch { /* header is best-effort observability */ }
      return res.status(200).json(proposeResponse(store.get(requestId), { traceId: trace.id }));
    } catch (err) {
      telemetry.failTrace(trace, err);
      return res.status(500).json({ error: `Agent proposal failed: ${err && err.message ? err.message : String(err)}` });
    }
  }

  // Asynchronous investigation submission (SDK primary path): submit via
  // the shared core, answer 202 immediately with the ids, and run the
  // SAME processProposal detached. Progress is observable through the
  // trace stream and status polling while the model works; the final
  // decision lands on the record exactly as the sync path produces it.
  async function handleInvestigate(req, res) {
    const trace = telemetry.createTrace({ kind: 'agent', label: `investigate ${req.body && req.body.transaction ? String(req.body.transaction.to || '').slice(0, 42) : '(no tx)'}` });
    try {
      const sub = await submitProposal(req, trace);
      if (sub.http) return res.status(sub.http.status).json(sub.http.body);
      if (sub.replay) {
        try { res.set('Idempotent-Replayed', 'true'); } catch { /* header is best-effort observability */ }
        const body = statusResponse(sub.replay, req);
        body.replayed = true;
        return res.status(200).json(body);
      }
      try { res.set('X-Assertara-Trace', trace.id); } catch { /* header is best-effort observability */ }
      res.status(202).json({
        requestId: sub.record.id, traceId: trace.id, txDigest: sub.record.txDigest,
        status: 'INVESTIGATING', replayed: false
      });
      processProposal(sub.record.id, { trace, slot: sub.slot }).catch(() => {});
      return undefined;
    } catch (err) {
      telemetry.failTrace(trace, err);
      return res.status(500).json({ error: `Agent investigation failed: ${err && err.message ? err.message : String(err)}` });
    }
  }

  // Stable SDK evidence envelope for a decided request. Additive
  // surface only: every field reuses stored record values, and the
  // full bundle stays available through observations by-eval.
  function handleEvidence(req, res) {
    try {
      if (!approvalSecret) return serviceUnavailable(res);
      if (storeDown()) return storeUnavailable(res);
      const record = store.get(req.params && req.params.id);
      if (!record || !allowOwner(req, record.ownerKeyId)) {
        return res.status(404).json({ error: 'Unknown request id.' });
      }
      if (!record.decision) {
        return res.status(409).json({ error: 'Investigation not complete.', requestId: record.id, status: record.status });
      }
      return res.status(200).json({
        v: 1,
        requestId: record.id,
        decision: record.decision,
        reasons: record.reasons || [],
        txDigest: record.txDigest,
        traceId: record.traceId || null,
        evalId: record.evalId || null,
        investigation: {
          evalId: record.evalId || null, verdict: record.evalVerdict || null,
          reasoningOrigin: record.reasoningOrigin || null,
          ruleFindings: record.ruleFindings || [], safeguardTriggers: record.safeguardTriggers || []
        },
        mandateChecks: record.mandateChecks || []
      });
    } catch (err) {
      return res.status(500).json({ error: `Evidence lookup failed: ${err && err.message ? err.message : String(err)}` });
    }
  }

  function approvalComplete(record) {
    const a = record && record.approval;
    if (!a || !a.token) return false;
    if (a.requiresOperator && !a.operatorSig) return false;
    return true;
  }

  function handleStatus(req, res) {
    try {
      if (!approvalSecret) return serviceUnavailable(res);
      if (storeDown()) return storeUnavailable(res);
      let record = store.get(req.params && req.params.id);
      // Ownership: foreign keys get the same 404 as unknown ids so
      // request ids are not oracle-able across integrations.
      if (!record || !allowOwner(req, record.ownerKeyId)) {
        return res.status(404).json({ error: 'Unknown request id.' });
      }
      // Read-path TTL: an investigation still undecided past the request
      // lifetime means its background run is gone (every stage inside is
      // bounded far below the TTL, and the core fail-closes on throw),
      // so close it UNCERTAIN instead of reporting "running" forever.
      // finalizeInterrupted re-checks for a decision, so a genuinely
      // racing completion keeps its real outcome.
      if (!record.decision && record.status !== 'REJECTED' && now() - record.createdAt > requestTtlMs) {
        record = finalizeInterrupted(record.id, 'Investigation did not complete within the request lifetime; re-propose. Held as UNCERTAIN.') || record;
      }
      return res.status(200).json(statusResponse(record, req));
    } catch (err) {
      return res.status(500).json({ error: `Status lookup failed: ${err && err.message ? err.message : String(err)}` });
    }
  }

  function mandateStillActive(record) {
    if (!mandate) return { ok: false, error: 'no active mandate' };
    if (record.mandateId !== mandate.id || record.mandateVersion !== mandate.version) {
      return { ok: false, error: 'mandate changed since evaluation; re-propose' };
    }
    const t = now();
    if (!(t >= mandate.notBeforeMs && t < mandate.expiresAtMs)) return { ok: false, error: 'mandate expired' };
    if (mandate.revokedVersions.indexOf(mandate.version) !== -1) return { ok: false, error: 'mandate revoked' };
    return { ok: true };
  }

  async function handleAuthorize(req, res) {
    // Operator release authenticates ONLY by OPERATOR_SECRET (ownership
    // intentionally not checked): the operator is the trusted human
    // acting out-of-band across integrations. This endpoint is never
    // part of the agent SDK surface.
    try {
      if (!approvalSecret) return serviceUnavailable(res);
      if (storeDown()) return storeUnavailable(res);
      const seal = await sealStatus();
      if (!seal.ok) return res.status(503).json({ error: `Operator authorization unavailable: ${seal.error}.` });
      if (!operatorSecret) return res.status(503).json({ error: 'Operator authorization unavailable: OPERATOR_SECRET is not configured.' });
      const presented = req.body && req.body.operatorSecret;
      if (!safeEqualSecret(presented, operatorSecret)) return res.status(403).json({ error: 'Operator authentication failed.' });
      const record = store.get(req.params && req.params.id);
      if (!record) return res.status(404).json({ error: 'Unknown request id.' });
      if (record.decision !== 'REVIEW') {
        return res.status(409).json({ error: 'Request is not awaiting operator authorization.' });
      }
      const live = mandateStillActive(record);
      if (!live.ok) return res.status(409).json({ error: `Cannot authorize: ${live.error}.` });
      if (!record.approval || !record.approval.requiresOperator) {
        return res.status(409).json({ error: 'Request has no pending operator approval.' });
      }
      if (now() - record.createdAt > requestTtlMs) {
        return res.status(410).json({ error: 'Request expired; re-propose.' });
      }
      // Idempotent when a live countersigned token already exists.
      if (record.approval.token && record.approval.operatorSig && record.approval.expiresAt > now()) {
        return res.status(200).json({ requestId: record.id, authorized: true, approval: record.approval.token });
      }
      // Countersign the pending approval (or mint a fresh one if it lapsed).
      let pending = record.approval.pendingToken;
      if (!pending || record.approval.expiresAt <= now()) {
        pending = issueApproval({
          secret: approvalSecret, requestId: record.id, txDigest: record.txDigest,
          chainId: record.normalizedTx.chainId, sender: record.normalizedTx.from,
          mandateId: mandate.id, mandateVersion: mandate.version, policyId: mandate.policyId,
          requiresOperator: true, ttlMs: approvalTtlMs, nowMs: now(), subcallTreeHash: record.subcallTreeHash
        });
        const payload = JSON.parse(Buffer.from(pending.split('.')[1], 'base64url').toString('utf8'));
        record.approval.nonce = payload.nonce;
        record.approval.expiresAt = payload.expiresAt;
        record.approval.pendingToken = pending;
      }
      const signed = countersignApproval({ secret: approvalSecret, token: pending, operatorSecret, nowMs: now() });
      if (!signed.ok) return res.status(500).json({ error: `Authorization failed: ${signed.error}` });
      store.update(record.id, {
        status: 'APPROVED',
        approval: { ...record.approval, token: signed.token, operatorSig: signed.payload.operatorSig, pendingToken: null }
      });
      store.appendEvent({ event: 'OPERATOR_AUTHORIZED', requestId: record.id, nonce: signed.payload.nonce });
      return res.status(200).json({ requestId: record.id, authorized: true, approval: signed.token });
    } catch (err) {
      return res.status(500).json({ error: `Authorization failed: ${err && err.message ? err.message : String(err)}` });
    }
  }

  function chainRpcUrl(chainIdHex) {
    if (!mandate) return null;
    const entry = mandate.chains.find((c) => c.id === chainIdHex);
    return entry ? entry.rpcUrl : null;
  }

  // Shared execution recorder: verifies from chain RPC (never trusts the
  // reporter), records idempotently, credits spending only on success.
  async function recordExecution({ record, txHash }) {
    // Post-response spans append to the proposal's trace when it is
    // still resident (bounded ring); eviction degrades silently.
    const trace = telemetry.findByRequest(record.id);
    if (record.execution && record.execution.txHash === txHash) return { recorded: true, execution: record.execution, duplicate: true };
    if (record.execution && record.execution.txHash !== txHash) {
      store.appendEvent({ event: 'EXECUTION_CONFLICT', requestId: record.id, txHash });
      return { recorded: false, conflict: true, execution: record.execution };
    }
    const rvSpan = telemetry.startSpan(trace, 'receipt-verify', txHash.slice(0, 18));
    const chainIdHex = `0x${BigInt(record.normalizedTx.chainId).toString(16)}`;
    const rpcUrl = chainRpcUrl(chainIdHex);
    if (!rpcUrl) {
      if (rvSpan) rvSpan.fail('no chain RPC configured for execution verification');
      return { recorded: false, error: 'no chain RPC configured for execution verification' };
    }
    let receipt = null;
    let remoteTx = null;
    try {
      receipt = await jsonRpc(rpcUrl, 'eth_getTransactionReceipt', [txHash], 15000);
      remoteTx = await jsonRpc(rpcUrl, 'eth_getTransactionByHash', [txHash], 15000);
    } catch (err) {
      if (rvSpan) rvSpan.fail(`chain RPC unavailable: ${err.message}`);
      return { recorded: false, unavailable: true, error: `chain RPC unavailable: ${err.message}` };
    }
    if (!receipt || !remoteTx) {
      if (rvSpan) rvSpan.fail('receipt not found yet; retry after inclusion');
      return { recorded: false, pending: true };
    }
    const want = record.normalizedTx;
    const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
    let valueOk = false;
    try {
      valueOk = BigInt(remoteTx.value || '0x0') === BigInt(want.value || '0x0');
    } catch {
      valueOk = false;
    }
    if (!same(remoteTx.from, want.from) || !same(remoteTx.to, want.to) || !valueOk) {
      const execution = { outcome: 'MISMATCH', txHash, receiptStatus: receipt.status || null, blockNumber: receipt.blockNumber || null, recordedAt: now() };
      store.update(record.id, { status: 'EXECUTION_MISMATCH', execution });
      store.appendEvent({ event: 'EXECUTION_MISMATCH', requestId: record.id, txHash });
      if (rvSpan) rvSpan.fail('on-chain fields differ from the approved transaction');
      telemetry.finishTrace(trace, { decision: record.decision, execution: 'MISMATCH' });
      return { recorded: true, execution };
    }
    if (rvSpan) rvSpan.finish(`status=${receipt.status} block=${receipt.blockNumber || '?'}`);
    if (receipt.status === '0x1') {
      // Capability 5 B7: reconcile receipt logs against the
      // authorized effect list. Divergence never receives an
      // ordinary clean status; anything unverifiable is labeled.
      let effectsCheck = null;
      const efSpan = telemetry.startSpan(trace, 'effect-verify', '');
      try {
        const { verifyEffectsAgainstReceipt } = require('../utils/effectVerification');
        let authorized = record.authorizedEffects;
        if (!authorized || !Array.isArray(authorized.effects)) {
          const { decodeTransactionCalldata } = require('../services/decoderService');
          const { reconstructEffects } = require('../services/effectReconstruction');
          const reDecoded = decodeTransactionCalldata({
            to: want.to, data: want.data, value: want.value, from: want.from, chainId: want.chainId
          });
          authorized = reconstructEffects({
            tx: { from: want.from, to: want.to, value: want.value },
            decodedTx: reDecoded, chainId: want.chainId
          });
        }
        effectsCheck = verifyEffectsAgainstReceipt({ effects: authorized, receipt, sender: want.from });
      } catch (err) {
        effectsCheck = {
          status: 'EFFECTS_UNVERIFIED',
          reason: `verification failed: ${String((err && err.message) || err).slice(0, 160)}`,
          matches: [], missing: [], unexpected: [], notes: [], summary: {}
        };
      }
      const verification = {
        effects: effectsCheck.status,
        reason: effectsCheck.reason || null,
        matched: (effectsCheck.matches || []).map((m) => m.effectId),
        missing: (effectsCheck.missing || []).map((m) => m.effectId),
        unexpectedLogs: (effectsCheck.unexpected || []).map((u) => u.logIndex),
        notes: (effectsCheck.notes || []).slice(0, 6)
      };
      const diverged = effectsCheck.status === 'EFFECTS_DIVERGED';
      const unverified = effectsCheck.status === 'EFFECTS_UNVERIFIED';
      if (efSpan) {
        if (diverged) efSpan.fail('receipt logs diverge from authorized effects');
        else if (unverified) efSpan.finish('effects unverifiable against receipt logs');
        else efSpan.finish(`matched=${((effectsCheck.matches) || []).length}`);
      }
      const execution = {
        outcome: diverged ? 'EFFECTS_DIVERGED' : (unverified ? 'EXECUTED_UNVERIFIED' : 'EXECUTED'),
        txHash, receiptStatus: receipt.status,
        blockNumber: receipt.blockNumber || null, gasUsed: receipt.gasUsed || null,
        verification, recordedAt: now()
      };
      telemetry.finishTrace(trace, { decision: record.decision, execution: execution.outcome, txHash });
      const execStatus = diverged ? 'EXECUTION_DIVERGED' : (unverified ? 'EXECUTED_UNVERIFIED' : 'EXECUTED');
      const execEvent = diverged ? 'EXECUTION_DIVERGED' : (unverified ? 'EXECUTED_UNVERIFIED' : 'EXECUTED');
      store.update(record.id, { status: execStatus, execution });
      store.appendEvent({ event: execEvent, requestId: record.id, txHash, blockNumber: execution.blockNumber });
      try {
        const wei = BigInt(want.value || '0x0');
        if (wei > 0n && spendingLedger && typeof spendingLedger.record === 'function') {
          spendingLedger.record({ chainId: chainIdHex, wei: wei.toString(), requestId: record.id, txHash, atMs: now() });
        }
      } catch {
        /* accounting failure must not unsettle a verified execution */
      }
      return { recorded: true, execution };
    }
    const execution = {
      outcome: 'FAILED', txHash, receiptStatus: receipt.status || null,
      blockNumber: receipt.blockNumber || null, gasUsed: receipt.gasUsed || null,
      verification: { effects: 'EFFECTS_UNVERIFIED', reason: 'execution reverted; no logs to reconcile' },
      recordedAt: now()
    };
    telemetry.markSkipped(trace, 'effect-verify', 'execution reverted; no logs to reconcile');
    telemetry.finishTrace(trace, { decision: record.decision, execution: 'FAILED', txHash });
    store.update(record.id, { status: 'FAILED', execution });
    store.appendEvent({ event: 'EXECUTION_FAILED', requestId: record.id, txHash });
    return { recorded: true, execution };
  }

  async function handleReceipt(req, res) {
    try {
      if (!approvalSecret) return serviceUnavailable(res);
      if (storeDown()) return storeUnavailable(res);
      const seal = await sealStatus();
      if (!seal.ok) return res.status(503).json({ error: `Receipt recording unavailable: ${seal.error}.` });
      const txHash = req.body && req.body.txHash;
      if (typeof txHash !== 'string' || !HASH_RE.test(txHash)) {
        return res.status(400).json({ error: 'Body must include txHash (0x 32-byte hash).' });
      }
      const record = store.get(req.params && req.params.id);
      if (!record || !allowOwner(req, record.ownerKeyId)) {
        return res.status(404).json({ error: 'Unknown request id.' });
      }
      if (!approvalComplete(record)) return res.status(409).json({ error: 'Request has no complete approval.' });
      const out = await withRecordLock(record.id, () => recordExecution({ record: store.get(record.id), txHash }));
      if (out.conflict) return res.status(409).json({ error: 'A different execution is already recorded for this request.', execution: out.execution });
      if (out.unavailable) return res.status(502).json({ error: out.error });
      if (out.pending) return res.status(404).json({ error: 'Receipt not found yet; retry after inclusion.' });
      return res.status(200).json({ requestId: record.id, execution: out.execution, duplicate: Boolean(out.duplicate) });
    } catch (err) {
      return res.status(500).json({ error: `Receipt recording failed: ${err && err.message ? err.message : String(err)}` });
    }
  }

  async function handleSignerCallback(req, res) {
    try {
      if (!approvalSecret) return serviceUnavailable(res);
      if (storeDown()) return storeUnavailable(res);
      const seal = await sealStatus();
      if (!seal.ok) return res.status(503).json({ error: `Signer callback unavailable: ${seal.error}.` });
      const { requestId, nonce, txHash, sig } = (req.body && typeof req.body === 'object') ? req.body : {};
      if (typeof requestId !== 'string' || typeof nonce !== 'string' || typeof txHash !== 'string' || !HASH_RE.test(txHash)) {
        return res.status(400).json({ error: 'Callback must include requestId, nonce, and txHash.' });
      }
      const expected = crypto.createHmac('sha256', approvalSecret).update(`signer-delivery:${nonce}:${txHash}`, 'utf8').digest('hex');
      const ok = safeEqualSecret(typeof sig === 'string' ? sig : '', expected);
      if (!ok) return res.status(401).json({ error: 'Signer callback authentication failed.' });
      const record = store.get(requestId);
      if (!record || !record.approval || record.approval.nonce !== nonce) {
        return res.status(404).json({ error: 'No matching approval for this delivery.' });
      }
      const out = await withRecordLock(requestId, () => recordExecution({ record: store.get(requestId), txHash }));
      if (out.conflict) return res.status(409).json({ error: 'Conflicting execution recorded.', execution: out.execution });
      if (out.unavailable) return res.status(502).json({ error: out.error });
      if (out.pending) return res.status(404).json({ error: 'Receipt not found yet.' });
      return res.status(200).json({ requestId, execution: out.execution, duplicate: Boolean(out.duplicate) });
    } catch (err) {
      return res.status(500).json({ error: `Signer callback failed: ${err && err.message ? err.message : String(err)}` });
    }
  }

  function handleMandateInfo(req, res) {
    try {
      if (!mandate) return res.status(200).json({ configured: false, error: mandateError || 'no mandate configured' });
      return res.status(200).json({
        configured: true, id: mandate.id, version: mandate.version, issuer: mandate.issuer,
        notBefore: mandate.notBefore, expiresAt: mandate.expiresAt, policyId: mandate.policyId,
        seal: sealSync.status,
        sealAuthority: sealSync.authority || null,
        chains: mandate.chains.map((c) => ({ id: c.id, name: c.name }))
      });
    } catch (err) {
      return res.status(500).json({ error: `Mandate info failed: ${err && err.message ? err.message : String(err)}` });
    }
  }

  // Ownership probe for the observation routes in server.js: a trace
  // is accessible when its linked request record is owned by the caller
  // (traces without a request link are dev-visible only).
  function traceAccessible(req, trace) {
    if (!trace) return false;
    if (!trace.requestId) return requestKey(req).development;
    const record = store.get(trace.requestId);
    if (!record) return false;
    return allowOwner(req, record.ownerKeyId);
  }

  function recordAccessible(req, record) {
    if (!record) return false;
    return allowOwner(req, record.ownerKeyId);
  }

  return {
    handlePropose, handleInvestigate, handleStatus, handleEvidence, handleAuthorize, handleReceipt,
    handleSignerCallback, handleMandateInfo, recoverInterrupted,
    traceAccessible, recordAccessible
  };
}

module.exports = { createAgentController, combineDecisions };
