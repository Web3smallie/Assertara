/**
 * Investigation telemetry (agent-testing observability).
 *
 * In-process, read-only execution tracing for live investigations:
 * per-component spans (start/finish/duration/status/summary) plus a
 * real event feed that Server-Sent Events fan out to the command
 * centre UI. This module NEVER influences decisions: controllers
 * record what already happened; no consumer of a trace can change
 * authorization, validation, or policy outcomes.
 *
 * Integrity rules (hard):
 * - Spans are recorded only for components that actually executed.
 *   Conditional work records an explicit SKIPPED span with a reason.
 * - Summaries are short caller-supplied strings. Structured extras are
 *   screened: credential-shaped keys never reach a snapshot.
 * - Snapshots served over HTTP contain no secrets: no approval tokens,
 *   operator material, API keys, or signing keys. Callers must never
 *   pass such values into summaries or extras; the screen below is a
 *   backstop, not the primary control.
 * - Bounded memory: ring of recent traces, cap of spans per trace.
 *   Telemetry must never grow without bound on a long-lived server.
 */

const MAX_TRACES = 25;
const MAX_SPANS_PER_TRACE = 160;
const MAX_SUMMARY_CHARS = 500;
const MAX_EVENTS_PER_TRACE = 400;

// Static component catalog: id -> { name, group, blurb }. The catalog
// describes what MAY appear; a trace shows what DID. Components with
// no span in a finished trace were not observed on that path — the UI
// must render that honestly (NOT OBSERVED), never as activity.
const COMPONENTS = {
  // Evidence and input processing
  'agent-receiver': { name: 'Agent input receiver', group: 'Evidence & input', blurb: 'Validates the proposal, normalizes the transaction, binds the digest.' },
  'agent-evidence': { name: 'Agent evidence admission', group: 'Evidence & input', blurb: 'Validates typed agent evidence envelopes; forces UNTRUSTED.' },
  'chainstate': { name: 'Chain-state retrieval', group: 'Evidence & input', blurb: 'Target/sender state over the mandate RPC (agent) or evidence RPC (browser).' },
  'counterparty-labels': { name: 'Counterparty labels', group: 'Evidence & input', blurb: 'Static HINT labels for addresses in play (never identity proof).' },
  'evidence-bundle': { name: 'Evidence compilation', group: 'Completion', blurb: 'Assembles the final evidence bundle and policy record.' },
  'evidence-packer': { name: 'Evidence packer', group: 'Evidence & input', blurb: 'Packs bounded, prioritized evidence text for the model.' },
  'freshness': { name: 'Evidence freshness', group: 'Evidence & input', blurb: 'Checks capture timestamps against staleness bounds.' },
  'sam': { name: 'SAM 3.1 segmentation', group: 'Evidence & input', blurb: 'Genuine visual-region segmentation of a supplied screenshot.' },
  'ocr': { name: 'OCR extraction', group: 'Evidence & input', blurb: 'Local text extraction over genuine regions or full-scan fallback.' },
  'visual-association': { name: 'Visual association', group: 'Evidence & input', blurb: 'Binds regions/OCR to the transaction under investigation.' },
  // Transaction analysis
  'decoder': { name: 'Transaction decoder', group: 'Transaction analysis', blurb: 'Deterministic EVM calldata decoding + security rules.' },
  'proxy-resolution': { name: 'Proxy resolution', group: 'Transaction analysis', blurb: 'ERC-1967/EIP-1167 detection and implementation resolution.' },
  'contract-identity': { name: 'Contract identity', group: 'Transaction analysis', blurb: 'Chain-scoped identity and verification status.' },
  'subcalls': { name: 'Nested-call analysis', group: 'Transaction analysis', blurb: 'Subcall tree, ordering, and unknown-inner status.' },
  'effects': { name: 'Effect reconstruction', group: 'Transaction analysis', blurb: 'Deterministic economic-effect (EF-xxx) reconstruction.' },
  'composition': { name: 'Batch composition', group: 'Transaction analysis', blurb: 'Within-batch approval/spend interaction analysis.' },
  'bridge': { name: 'Bridge analysis', group: 'Transaction analysis', blurb: 'Narrow Across/CCTP route and terms extraction.' },
  'approval-necessity': { name: 'Approval necessity', group: 'Transaction analysis', blurb: 'Authorization duration, need, and excess assessment.' },
  'deadlines': { name: 'Deadline analysis', group: 'Transaction analysis', blurb: 'Swap/permit deadline and expiry interpretation.' },
  'comparison': { name: 'Requested-vs-actual comparison', group: 'Transaction analysis', blurb: 'Deterministic effect-coverage and intent comparison.' },
  'history': { name: 'Transaction history', group: 'Transaction analysis', blurb: 'Bounded prior-transaction sequence context.' },
  'chain-verification': { name: 'Chain verification', group: 'Transaction analysis', blurb: 'Balance/nonce/code/freshness checks against live state.' },
  'simulation-pre': { name: 'Pre-reasoning simulation', group: 'Transaction analysis', blurb: 'Foundry simulation evidence gathered before the model runs.' },
  'simulation-post': { name: 'Post-reasoning simulation', group: 'Transaction analysis', blurb: 'Follow-up simulation for MISMATCH verdicts.' },
  'explicit-intent': { name: 'Explicit intent extraction', group: 'Transaction analysis', blurb: 'Verbatim [EI-xxx] quote extraction with spans.' },
  'evidence-graph': { name: 'Evidence graph', group: 'Transaction analysis', blurb: 'Deterministic + model-derived evidence relationships.' },
  // AI reasoning (one span per actual model invocation)
  'prompt-select': { name: 'Prompt selection', group: 'AI reasoning', blurb: 'Investigation-type prompt choice and version.' },
  'muse-spark': { name: 'Muse Spark investigation', group: 'AI reasoning', blurb: 'Live structured investigation by the serving model.' },
  // Verification and security
  'reasoning-validation': { name: 'Reasoning validation', group: 'Verification & security', blurb: 'Schema/boundary validation of model output.' },
  'reference-validation': { name: 'Reference validation', group: 'Verification & security', blurb: 'Evidence-reference grounding and fabrication checks.' },
  'support-validation': { name: 'Support validation', group: 'Verification & security', blurb: 'Quote entailment and conclusion-support assessment.' },
  'reconciliation': { name: 'Mechanism reconciliation', group: 'Verification & security', blurb: 'Model vs deterministic precedence resolution.' },
  'semantic-claims': { name: 'Semantic-claim verification', group: 'Verification & security', blurb: 'Falsifiable claim checks against structured evidence.' },
  'visual-role-check': { name: 'Visual-role cross-check', group: 'Verification & security', blurb: 'Model-asserted roles checked against observed evidence.' },
  'safeguards': { name: 'Deterministic safeguards', group: 'Verification & security', blurb: '16 ordered verdict safeguards (MATCH-only downgrades).' },
  'mandate-eval': { name: 'Mandate evaluation', group: 'Verification & security', blurb: 'Seal verification + deterministic mandate constraint checks.' },
  'subcall-bind': { name: 'Subcall-tree binding', group: 'Verification & security', blurb: 'Canonical hash binding the approval to authorized inners.' },
  'policy-decision': { name: 'Policy decision', group: 'Verification & security', blurb: 'Centralized verdict/findings to ALLOW/BLOCK/REVIEW/UNCERTAIN.' },
  'approval-issue': { name: 'Approval issuance', group: 'Verification & security', blurb: 'Single-use approval token minting (ALLOW) or pending (REVIEW).' },
  'signer-call': { name: 'Controlled signer call', group: 'Verification & security', blurb: 'Client-observed signer request round-trip and outcome.' },
  // Completion
  'receipt-verify': { name: 'Receipt verification', group: 'Completion', blurb: 'Chain-RPC receipt check against approved fields.' },
  'effect-verify': { name: 'Effect verification', group: 'Completion', blurb: 'Receipt-log reconciliation vs authorized effects.' },
  'persistence': { name: 'Investigation persistence', group: 'Completion', blurb: 'Durable record + redaction + agent-ledger update.' },
  'agent-response': { name: 'Agent response', group: 'Completion', blurb: 'Structured decision payload returned to the agent.' }
};

const SECRET_KEY_RE = /(api[_-]?key|secret|password|private[_-]?key|operatorSig|approvalSecret|(approval|pending|access|auth|refresh|id|bearer|api|session|csrf)[_-]?token|^token$)/i;

function screenValue(value, key) {
  if (typeof key === 'string' && SECRET_KEY_RE.test(key)) return '[redacted]';
  if (typeof value === 'string') return value.length > MAX_SUMMARY_CHARS ? `${value.slice(0, MAX_SUMMARY_CHARS)}…(+${value.length - MAX_SUMMARY_CHARS})` : value;
  if (Array.isArray(value)) return value.slice(0, 25).map((v) => screenValue(v, null));
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).slice(0, 40)) out[k] = screenValue(value[k], k);
    return out;
  }
  return value;
}

function cutSummary(s) {
  const t = typeof s === 'string' ? s : '';
  return t.length > MAX_SUMMARY_CHARS ? `${t.slice(0, MAX_SUMMARY_CHARS)}…` : t;
}

let seq = 0;
const traces = new Map(); // id -> trace (insertion-ordered ring)
const listeners = new Map(); // id -> Set(fn)

function nowMs() {
  return Date.now();
}

function emit(trace, event) {
  const envelope = { seq: trace.events.length + 1, ts: nowMs(), traceId: trace.id, ...event };
  trace.events.push(envelope);
  if (trace.events.length > MAX_EVENTS_PER_TRACE) trace.events.splice(0, trace.events.length - MAX_EVENTS_PER_TRACE);
  const subs = listeners.get(trace.id);
  if (subs) {
    for (const fn of subs) {
      try { fn(envelope); } catch { /* a dead listener must not break recording */ }
    }
  }
  return envelope;
}

function createTrace({ kind, requestId, label } = {}) {
  seq += 1;
  const id = `tr_${Date.now().toString(36)}_${seq.toString(36)}${Math.floor(Math.random() * 1296).toString(36)}`;
  const trace = {
    id,
    kind: typeof kind === 'string' ? kind.slice(0, 32) : 'evaluate',
    requestId: typeof requestId === 'string' ? requestId.slice(0, 128) : null,
    label: typeof label === 'string' ? label.slice(0, 200) : '',
    createdAt: nowMs(),
    finishedAt: null,
    status: 'RUNNING',
    spans: [],
    events: [],
    outcome: null
  };
  traces.set(id, trace);
  while (traces.size > MAX_TRACES) {
    const oldest = traces.keys().next().value;
    traces.delete(oldest);
    listeners.delete(oldest);
  }
  emit(trace, { type: 'trace-start', kind: trace.kind, requestId: trace.requestId, label: trace.label });
  return trace;
}

function spanOf(trace, component) {
  if (!trace || !trace.spans) return null;
  return trace.spans.find((s) => s.component === component && s.status === 'RUNNING') || null;
}

function startSpan(trace, component, detail) {
  if (!trace || !trace.spans) return null;
  if (trace.spans.length >= MAX_SPANS_PER_TRACE) return null;
  const known = COMPONENTS[component];
  const handle = {
    component,
    name: known ? known.name : component,
    group: known ? known.group : 'Other',
    status: 'RUNNING',
    t0: nowMs(),
    t1: null,
    durationMs: null,
    detail: cutSummary(detail),
    summary: '',
    error: null,
    extra: null
  };
  trace.spans.push(handle);
  emit(trace, { type: 'span-start', component, name: handle.name, group: handle.group, detail: handle.detail });
  return {
    finish(summary, extra) {
      if (handle.status !== 'RUNNING') return handle;
      handle.status = 'COMPLETED';
      handle.t1 = nowMs();
      handle.durationMs = handle.t1 - handle.t0;
      handle.summary = cutSummary(summary);
      if (extra !== undefined) handle.extra = screenValue(extra, null);
      emit(trace, { type: 'span-finish', component, status: handle.status, durationMs: handle.durationMs, summary: handle.summary, extra: handle.extra });
      return handle;
    },
    fail(error, extra) {
      if (handle.status !== 'RUNNING') return handle;
      handle.status = 'FAILED';
      handle.t1 = nowMs();
      handle.durationMs = handle.t1 - handle.t0;
      handle.error = cutSummary(error instanceof Error ? error.message : error);
      if (extra !== undefined) handle.extra = screenValue(extra, null);
      emit(trace, { type: 'span-finish', component, status: handle.status, durationMs: handle.durationMs, error: handle.error, extra: handle.extra });
      return handle;
    },
    skip(reason) {
      if (handle.status !== 'RUNNING') return handle;
      handle.status = 'SKIPPED';
      handle.t1 = nowMs();
      handle.durationMs = handle.t1 - handle.t0;
      handle.summary = cutSummary(reason);
      emit(trace, { type: 'span-finish', component, status: handle.status, durationMs: handle.durationMs, summary: handle.summary });
      return handle;
    }
  };
}

// Synchronous helper for pure functions: times fn, finishes or fails.
function timed(trace, component, detail, fn, summarize) {
  const h = startSpan(trace, component, detail);
  if (!h) return fn();
  try {
    const out = fn();
    if (out && typeof out.then === 'function') {
      return out.then(
        (v) => { h.finish(summarize ? summarize(v) : 'ok'); return v; },
        (e) => { h.fail(e); throw e; }
      );
    }
    h.finish(summarize ? summarize(out) : 'ok');
    return out;
  } catch (e) {
    h.fail(e);
    throw e;
  }
}

function markSkipped(trace, component, reason) {
  const h = startSpan(trace, component, '');
  if (h) h.skip(reason);
}

function finishTrace(trace, outcome) {
  if (!trace || trace.status !== 'RUNNING') return trace;
  for (const s of trace.spans) {
    if (s.status === 'RUNNING') {
      s.status = 'COMPLETED';
      s.t1 = nowMs();
      s.durationMs = s.t1 - s.t0;
      s.summary = s.summary || 'closed at trace finish';
    }
  }
  trace.status = 'COMPLETED';
  trace.finishedAt = nowMs();
  trace.outcome = outcome !== undefined ? screenValue(outcome, null) : null;
  emit(trace, { type: 'trace-finish', durationMs: trace.finishedAt - trace.createdAt, outcome: trace.outcome });
  return trace;
}

function failTrace(trace, error) {
  if (!trace || trace.status !== 'RUNNING') return trace;
  trace.status = 'FAILED';
  trace.finishedAt = nowMs();
  emit(trace, { type: 'trace-finish', durationMs: trace.finishedAt - trace.createdAt, error: cutSummary(error instanceof Error ? error.message : error) });
  return trace;
}

function getTrace(id) {
  return traces.get(id) || null;
}

function findByRequest(requestId) {
  for (const t of traces.values()) {
    if (t.requestId === requestId) return t;
  }
  return null;
}

function listTraces() {
  return [...traces.values()].map((t) => ({
    id: t.id, kind: t.kind, requestId: t.requestId, label: t.label,
    createdAt: t.createdAt, finishedAt: t.finishedAt, status: t.status,
    spans: t.spans.length, outcome: t.outcome
  }));
}

function snapshot(trace) {
  if (!trace) return null;
  return {
    id: trace.id, kind: trace.kind, requestId: trace.requestId, label: trace.label,
    createdAt: trace.createdAt, finishedAt: trace.finishedAt, status: trace.status,
    durationMs: trace.finishedAt ? trace.finishedAt - trace.createdAt : nowMs() - trace.createdAt,
    outcome: trace.outcome,
    spans: trace.spans.map((s) => ({ ...s })),
    catalog: COMPONENTS
  };
}

function subscribe(id, fn) {
  if (!traces.has(id) || typeof fn !== 'function') return () => {};
  if (!listeners.has(id)) listeners.set(id, new Set());
  listeners.get(id).add(fn);
  return () => {
    const set = listeners.get(id);
    if (set) set.delete(fn);
  };
}

module.exports = {
  COMPONENTS, MAX_TRACES, MAX_SPANS_PER_TRACE,
  createTrace, startSpan, timed, markSkipped, finishTrace, failTrace,
  getTrace, findByRequest, listTraces, snapshot, subscribe, spanOf
};
