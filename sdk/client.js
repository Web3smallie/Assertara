/**
 * Assertara SDK client (agent-agnostic, zero dependencies).
 *
 * The client is a policy-service/signer driver with decision guards. It
 * can submit proposals, observe genuine investigation progress, read
 * published decisions/evidence, and route execution through the
 * controlled signer. It cannot authorize anything: execution requires
 * a fresh ALLOW record with a complete policy-issued approval for the
 * exact investigated bytes, and the signer re-verifies everything.
 *
 * Live vs published, by construction:
 * - streamProgress() forwards ONLY genuine server SSE span events.
 * - getStatus()/getEvidence()/waitFor*() return published results.
 * The SDK never synthesizes reasoning text, progress, or telemetry.
 */

const crypto = require('crypto');
const { fromHttp, timeout, notExecutable, digestMismatch, CODES } = require('./errors');
const { digestTx, digestsEqual, isValidDigest } = require('./digest');
const { streamSSE } = require('./sse');
const { canonicalStringify, sha256Hex } = require('./internal/canonicalJson');

const DEFAULT_TIMEOUTS = {
  submit: 30000, // async submit answers 202 immediately
  propose: 180000, // sync propose holds the connection for the full run
  status: 15000,
  sign: 90000, // broadcast + receipt wait + callback
  pollInterval: 2000,
  decision: 180000, // waitForDecision ceiling
  execution: 90000, // waitForExecution ceiling
  operator: 120000 // waitForOperatorApproval ceiling
};

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function isCleanExecution(execution) {
  return Boolean(execution && execution.outcome === 'EXECUTED');
}

// Recompute the manifest digest of an export envelope locally and
// refuse envelopes that fail binding. Mirrors the server/export
// semantics: canonical bytes of package.manifest, SHA-256.
function assertExportDigest(exported) {
  if (!exported || exported.format !== 'assertara-attestation-export-1'
    || !exported.package || !exported.package.manifest) {
    throw digestMismatch();
  }
  let recomputed;
  try {
    recomputed = sha256Hex(canonicalStringify(exported.package.manifest));
  } catch {
    throw digestMismatch();
  }
  if (recomputed !== exported.manifestDigest) throw digestMismatch();
  const att = exported.package.attestation;
  if (!att || !att.body || att.body.manifestDigest !== recomputed) throw digestMismatch();
  return recomputed;
}

class AssertaraClient {
  constructor({ policyBase, signerBase, apiKey, timeouts, fetchImpl, nowFn } = {}) {
    if (!policyBase || typeof policyBase !== 'string') {
      throw new Error('AssertaraClient requires policyBase (e.g. http://127.0.0.1:3001).');
    }
    this.policyBase = policyBase.replace(/\/$/, '');
    this.signerBase = typeof signerBase === 'string' && signerBase ? signerBase.replace(/\/$/, '') : null;
    this.apiKey = typeof apiKey === 'string' && apiKey ? apiKey : null;
    this.timeouts = { ...DEFAULT_TIMEOUTS, ...(timeouts || {}) };
    this.fetchImpl = fetchImpl || null;
    this.nowFn = typeof nowFn === 'function' ? nowFn : Date.now;
  }

  authHeaders(extra) {
    const headers = { ...(extra || {}) };
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
    return headers;
  }

  async requestJson(method, path, { base, body, headers, timeoutMs } = {}) {
    const doFetch = this.fetchImpl || fetch;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs || this.timeouts.status);
    try {
      const res = await doFetch(`${base || this.policyBase}${path}`, {
        method,
        headers: this.authHeaders({
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...(headers || {})
        }),
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: ctrl.signal
      });
      const parsed = await res.json().catch(() => ({}));
      if (!res.ok) throw fromHttp(res.status, parsed);
      return parsed;
    } catch (err) {
      if (err && err.name === 'AbortError') throw timeout(`Assertara request timed out (${method} ${path}).`);
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  newIdempotencyKey() {
    return `sdk_${crypto.randomUUID()}`;
  }

  // Fail-fast connectivity + mandate sanity. Throws when the service is
  // unreachable, unauthenticated, or has no active mandate.
  async connect() {
    const health = await this.requestJson('GET', '/health', { timeoutMs: this.timeouts.status });
    const mandate = await this.requestJson('GET', '/api/v1/agent/mandate', { timeoutMs: this.timeouts.status });
    if (!mandate || mandate.configured !== true) {
      throw fromHttp(503, { error: `No active mandate: ${(mandate && mandate.error) || 'none configured'}.` });
    }
    return { policy: health, mandate };
  }

  async getMandateInfo() {
    return this.requestJson('GET', '/api/v1/agent/mandate', { timeoutMs: this.timeouts.status });
  }

  // Synchronous proposal (backward-compatible endpoint): resolves with
  // the full decision record. Prefer submit()+waitForDecision() for
  // progress visibility during long investigations.
  async propose({ transaction, purpose, agentId, idempotencyKey, evidence } = {}) {
    const { Investigation } = require('./investigation');
    const rec = await this.requestJson('POST', '/api/v1/agent/propose', {
      body: {
        ...(agentId !== undefined ? { agentId } : {}),
        ...(purpose !== undefined ? { intent: { purpose } } : {}),
        transaction,
        ...(evidence !== undefined ? { evidence } : {})
      },
      headers: { 'Idempotency-Key': idempotencyKey || this.newIdempotencyKey() },
      timeoutMs: this.timeouts.propose
    });
    return new Investigation(this, {
      requestId: rec.requestId, traceId: rec.traceId, txDigest: rec.txDigest, snapshot: rec
    });
  }

  // Asynchronous submission (primary SDK path): resolves 202-fast with
  // ids; the investigation runs on the server. Terminal idempotent
  // replays resolve with the stored status snapshot instead.
  async submit({ transaction, purpose, agentId, idempotencyKey, evidence } = {}) {
    const { Investigation } = require('./investigation');
    const rec = await this.requestJson('POST', '/api/v1/agent/investigations', {
      body: {
        ...(agentId !== undefined ? { agentId } : {}),
        ...(purpose !== undefined ? { intent: { purpose } } : {}),
        transaction,
        ...(evidence !== undefined ? { evidence } : {})
      },
      headers: { 'Idempotency-Key': idempotencyKey || this.newIdempotencyKey() },
      timeoutMs: this.timeouts.submit
    });
    return new Investigation(this, {
      requestId: rec.requestId, traceId: rec.traceId, txDigest: rec.txDigest,
      snapshot: rec.replayed ? rec : null
    });
  }

  async getStatus(requestId) {
    return this.requestJson('GET', `/api/v1/agent/requests/${encodeURIComponent(requestId)}`, {
      timeoutMs: this.timeouts.status
    });
  }

  // Resolves with the terminal record (decision set) or the REJECTED
  // record (malformed; decision stays null). onProgress receives each
  // genuine { stage, progress } projection observed while running.
  async waitForDecision(requestId, { timeoutMs, pollIntervalMs, onProgress } = {}) {
    const deadline = this.nowFn() + (timeoutMs || this.timeouts.decision);
    const interval = pollIntervalMs || this.timeouts.pollInterval;
    for (;;) {
      const st = await this.getStatus(requestId);
      if (st.decision || st.status === 'REJECTED') return st;
      if (st.stage && typeof onProgress === 'function') {
        try { onProgress({ stage: st.stage, progress: st.progress || null }); } catch { /* progress callbacks never break the wait */ }
      }
      if (this.nowFn() >= deadline) throw timeout('Timed out waiting for the investigation decision.');
      await sleep(interval);
    }
  }

  async getEvidence(requestId) {
    return this.requestJson('GET', `/api/v1/agent/requests/${encodeURIComponent(requestId)}/evidence`, {
      timeoutMs: this.timeouts.status
    });
  }

  async getTrace(traceId) {
    return this.requestJson('GET', `/api/v1/observations/traces/${encodeURIComponent(traceId)}`, {
      timeoutMs: this.timeouts.status
    });
  }

  // Genuine live span events for a trace, forwarded untouched. Resolves
  // with the terminal event; return false from onEvent to stop early.
  async streamProgress(traceId, onEvent, { signal } = {}) {
    return streamSSE(`${this.policyBase}/api/v1/observations/traces/${encodeURIComponent(traceId)}/stream`, {
      headers: this.authHeaders(),
      onEvent,
      signal,
      fetchImpl: this.fetchImpl || undefined
    });
  }

  // Live decision wait: follows the genuine trace event stream until
  // the server publishes the decision, then reads it once. The
  // decision marker is the finished `agent-response` span: the server
  // stores the decision BEFORE finishing that span, for every
  // decision, while the trace itself may stay open afterward for
  // execution recording (so trace-finish is NOT the marker — waiting
  // for it would stall ALLOW behind the agent's own execute call).
  // Any stream failure, disconnect, or timeout falls back to bounded
  // polling with the remaining budget; the total wait never exceeds
  // timeoutMs. The waiter only ever reads (stream + GET): it cannot
  // submit or execute, so the fallback cannot duplicate anything.
  async waitForDecisionLive(requestId, { traceId, timeoutMs, pollIntervalMs, onProgress } = {}) {
    if (!traceId) {
      return this.waitForDecision(requestId, { timeoutMs, pollIntervalMs, onProgress });
    }
    const budget = timeoutMs || this.timeouts.decision;
    const start = this.nowFn();
    const remaining = () => Math.max(budget - (this.nowFn() - start), 1);
    const progress = (p) => {
      if (typeof onProgress === 'function') {
        try { onProgress(p); } catch { /* progress callbacks never break the wait */ }
      }
    };
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), budget);
    try {
      await this.streamProgress(traceId, (ev) => {
        if (!ev || typeof ev !== 'object') return;
        if (ev.type === 'span-start' && ev.component === 'muse-spark') {
          progress({ stage: 'muse-spark', progress: { museSpark: { state: 'running' } } });
          return;
        }
        if (ev.type === 'span-finish') {
          if (ev.component === 'muse-spark') {
            progress({ stage: 'muse-spark', progress: { museSpark: { state: ev.status === 'FAILED' ? 'failed' : 'completed' } } });
          } else {
            progress({ stage: ev.component, progress: null });
          }
          if (ev.component === 'agent-response') return false;
          return;
        }
        if (ev.type === 'trace-finish' || ev.type === 'stream-end') return false;
      }, { signal: ctrl.signal });
      const st = await this.getStatus(requestId);
      if (st.decision || st.status === 'REJECTED') return st;
      // Marker seen but the record is not visibly decided yet (store
      // ordering guarantees this should not happen): poll briefly
      // rather than return an undecided record.
    } catch {
      // Stream disconnected, failed, or timed out: polling fallback
      // below with the remaining budget.
    } finally {
      clearTimeout(timer);
    }
    return this.waitForDecision(requestId, { timeoutMs: remaining(), pollIntervalMs, onProgress });
  }

  // Guarded execution. Requires a FRESH record with a complete
  // approval — decision ALLOW, or REVIEW released out-of-band by the
  // operator — for the exact bytes passed here. The record is re-read
  // at call time unless the caller hands over the terminal record it
  // has JUST observed (the waiter's own return value, seconds old
  // against a minutes-long approval TTL); every guard below —
  // decision, token presence, expiry, digest — runs identically
  // either way, so a stale handover fails loudly instead of
  // executing. Anything else throws before any signer contact. The
  // signer then independently re-verifies the approval, digest,
  // mandate, operator state, chain, sender, and single-use.
  async execute({ requestId, transaction, status } = {}) {
    if (!this.signerBase) {
      throw new Error('execute() requires signerBase: the SDK signs nothing itself.');
    }
    const st = (status && typeof status === 'object') ? status : await this.getStatus(requestId);
    if (st.decision !== 'ALLOW' && st.decision !== 'REVIEW') throw notExecutable(st.decision, st.reasons);
    if (!st.approvalToken) {
      throw notExecutable(st.decision, [...(st.reasons || []),
        st.decision === 'REVIEW'
          ? 'Awaiting out-of-band operator release; refusing to execute.'
          : 'Complete approval missing; refusing to execute.']);
    }
    if (Number.isSafeInteger(st.approvalExpiresAt) && st.approvalExpiresAt <= this.nowFn()) {
      throw fromHttp(410, { error: 'Approval expired; re-propose.' });
    }
    if (!isValidDigest(st.txDigest)) {
      throw digestMismatch();
    }
    let localDigest = null;
    try {
      localDigest = digestTx(transaction);
    } catch {
      localDigest = null;
    }
    if (!digestsEqual(localDigest, st.txDigest)) throw digestMismatch();
    const signed = await this.requestJson('POST', '/sign', {
      base: this.signerBase,
      body: { requestId, transaction, approval: st.approvalToken },
      timeoutMs: this.timeouts.sign
    });
    return { requestId, txHash: signed.txHash, receipt: signed.receipt || null, verification: signed.verification || null };
  }

  // Resolves with the recorded execution (any outcome — clean or not).
  // Use isCleanExecution() to branch; only EXECUTED is a clean result.
  async waitForExecution(requestId, { timeoutMs, pollIntervalMs } = {}) {
    const deadline = this.nowFn() + (timeoutMs || this.timeouts.execution);
    const interval = pollIntervalMs || this.timeouts.pollInterval;
    for (;;) {
      const st = await this.getStatus(requestId);
      if (st.execution) return st.execution;
      if (this.nowFn() >= deadline) throw timeout('Timed out waiting for execution to be recorded.');
      await sleep(interval);
    }
  }

  // Polls until a REVIEW decision carries a usable token (released
  // out-of-band by the operator) or the decision leaves REVIEW. Never
  // submits operator material: there is no such parameter anywhere.
  async waitForOperatorApproval(requestId, { timeoutMs, pollIntervalMs } = {}) {
    const deadline = this.nowFn() + (timeoutMs || this.timeouts.operator);
    const interval = pollIntervalMs || this.timeouts.pollInterval;
    for (;;) {
      const st = await this.getStatus(requestId);
      if ((st.decision === 'ALLOW' || st.decision === 'REVIEW') && st.approvalToken) return st;
      if (st.decision && st.decision !== 'REVIEW') throw notExecutable(st.decision, st.reasons);
      if (!st.decision && st.status === 'REJECTED') {
        throw fromHttp(409, { error: 'Request was rejected as malformed.' });
      }
      if (this.nowFn() >= deadline) throw timeout('Timed out waiting for operator release.');
      await sleep(interval);
    }
  }

  // Fallback receipt path: reports a signer-returned hash for
  // server-side verification (the server re-reads chain state and
  // never trusts this report). Normally unnecessary — the signer
  // callback records execution automatically.
  async reportReceipt(requestId, txHash) {
    return this.requestJson('POST', `/api/v1/agent/requests/${encodeURIComponent(requestId)}/receipts`, {
      body: { txHash },
      timeoutMs: this.timeouts.status
    });
  }

  // ---- Provenance + attestation (SDK upgrade) ----
  //
  // Thin HTTP access to the provenance pipeline. The SDK verifies
  // digests locally where it can (vendored canonical JSON + SHA-256)
  // but performs no signing: ceremony + publication are
  // operator-authorized server-side operations. The per-call operator
  // credential is forwarded once and never stored on the client.

  // Build (or fetch, idempotently) the deterministic provenance
  // manifest for a decided agent request.
  async buildManifest(requestId) {
    if (!requestId) throw new Error('buildManifest() requires a requestId.');
    return this.requestJson('POST', '/api/v1/provenance/manifests', {
      body: { requestId },
      timeoutMs: this.timeouts.status
    });
  }

  async getManifest(digest) {
    if (!digest) throw new Error('getManifest() requires a manifest digest.');
    return this.requestJson('GET', `/api/v1/provenance/manifests/${encodeURIComponent(digest)}`, {
      timeoutMs: this.timeouts.status
    });
  }

  // Portable export envelope ({ format, exportedAt, manifestDigest,
  // package }) for off-chain publication. The manifest digest is
  // recomputed locally before return; a mismatch throws instead of
  // handing the caller untrusted bytes.
  async getExportPackage(digest) {
    if (!digest) throw new Error('getExportPackage() requires a manifest digest.');
    const exported = await this.requestJson('GET', `/api/v1/provenance/exports/${encodeURIComponent(digest)}`, {
      timeoutMs: this.timeouts.status
    });
    assertExportDigest(exported);
    return exported;
  }

  // Operator ceremony: preview (confirm !== true) or sign (confirm
  // === true with expectDigest). Either a full v1 package object or
  // a digest (server rebuilds the package) may be supplied.
  // operatorSecret is the REVIEW-release operator credential, read by
  // the caller from its environment at call time; the SDK keeps no
  // copy. Agents must never be given this credential.
  async requestAttestation({ digest, package: pkg, expectDigest, confirm, operatorSecret, allowSuperseded, allowUnverifiedExecution, allowStaleRegistry, minRegistryVersion, maxRegistryAgeDays } = {}) {
    if (!operatorSecret) throw new Error('requestAttestation() requires the per-call operator credential.');
    if (!expectDigest) throw new Error('requestAttestation() requires expectDigest.');
    return this.requestJson('POST', '/api/v1/attestations', {
      body: {
        ...(pkg !== undefined ? { package: pkg } : {}),
        ...(digest !== undefined ? { digest } : {}),
        expectDigest,
        ...(confirm !== undefined ? { confirm } : {}),
        operatorSecret,
        ...(allowSuperseded !== undefined ? { allowSuperseded } : {}),
        ...(allowUnverifiedExecution !== undefined ? { allowUnverifiedExecution } : {}),
        ...(allowStaleRegistry !== undefined ? { allowStaleRegistry } : {}),
        ...(minRegistryVersion !== undefined ? { minRegistryVersion } : {}),
        ...(maxRegistryAgeDays !== undefined ? { maxRegistryAgeDays } : {})
      },
      timeoutMs: this.timeouts.sign
    });
  }

  // Operator publication of a signed package (v2 package object, full
  // export envelope, or digest) to the configured contract.
  async publishAttestation({ digest, signedPackage, operatorSecret, confirmations } = {}) {
    if (!operatorSecret) throw new Error('publishAttestation() requires the per-call operator credential.');
    return this.requestJson('POST', '/api/v1/attestations/publish', {
      body: {
        ...(signedPackage !== undefined ? { signedPackage } : {}),
        ...(digest !== undefined ? { digest } : {}),
        operatorSecret,
        ...(confirmations !== undefined ? { confirmations } : {})
      },
      timeoutMs: this.timeouts.sign
    });
  }

  // Read-only verification (judge flow as data). Accepts a digest
  // (server rebuilds the export) or a caller-held export object.
  // Returns { verdict: 'PASS'|'FAIL', checks, models }. The models
  // array is derived server-side from the verified manifest — the
  // SDK displays it, never constructs it. Note: this convenience
  // call trusts the serving backend + RPC; fully independent
  // verification remains the judge CLI + public chain data.
  async verifyAttestation({ digest, exported, registry, trustedRoot, investigation, attester, submitTx, contractVersion, minVersion, maxAgeDays, now } = {}) {
    return this.requestJson('POST', '/api/v1/attestations/verify', {
      body: {
        ...(digest !== undefined ? { digest } : {}),
        ...(exported !== undefined ? { exported } : {}),
        ...(registry !== undefined ? { registry } : {}),
        ...(trustedRoot !== undefined ? { trustedRoot } : {}),
        ...(investigation !== undefined ? { investigation } : {}),
        ...(attester !== undefined ? { attester } : {}),
        ...(submitTx !== undefined ? { submitTx } : {}),
        ...(contractVersion !== undefined ? { contractVersion } : {}),
        ...(minVersion !== undefined ? { minVersion } : {}),
        ...(maxAgeDays !== undefined ? { maxAgeDays } : {}),
        ...(now !== undefined ? { now } : {})
      },
      timeoutMs: this.timeouts.sign
    });
  }
}

module.exports = { AssertaraClient, isCleanExecution, DEFAULT_TIMEOUTS, CODES };
