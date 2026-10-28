/**
 * Assertara Verification Engine — deterministic gates plus fresh-context
 * review adjudication. ONLY this module (wielded by the application) assigns
 * VERIFIED. Model agreement alone can never verify a finding.
 */

const STATUSES = {
  VERIFIED: 'Independent model review SUPPORTED the finding, all evidence IDs resolve, no unresolved contradictions, and every execution/test claim has a real artifact.',
  LIKELY: 'Evidence supports the finding but minor unknowns remain; no contradictions.',
  HYPOTHESIS: 'Plausible but unsupported by sufficient evidence; needs more investigation.',
  REJECTED: 'Contradicted by evidence or failed a deterministic gate.',
  INCONCLUSIVE: 'Evidence is genuinely ambiguous; neither the finding nor its negation is supported.',
  INCOMPLETE: 'Investigation stopped (budget, failure, idle) before the finding could be judged.'
};

const REVIEW_PROMPT = `You are an adversarial security reviewer. You receive ONLY an evidence graph and candidate findings — no investigation transcript.
For each finding, attempt to disprove it: missing evidence, alternative benign explanations, unresolved contradictions.
Return strict JSON: {"reviews":[{"finding_id":"...","verdict":"SUPPORTED|PARTIAL|REJECTED","reasons":["..."],"missing":["..."]}]}.
SUPPORTED requires every cited id to exist in the graph and no unresolved contradiction. Never invent evidence.`;

// Deterministic gates. Each returns null (pass) or a reason string (fail).
function gateHasSupport(finding) {
  // A finding that cites no supporting evidence cannot verify, no matter what
  // the reviewer says. Verification requires evidence, not just agreement.
  if (!Array.isArray(finding.supporting) || finding.supporting.length === 0) {
    return 'finding cites no supporting evidence';
  }
  return null;
}

function gateIdsResolve(finding, graph) {
  const ids = [...(finding.supporting || []), ...(finding.contradicting || [])];
  const { unknown } = graph.validateRefs(ids);
  if (unknown.length > 0) return `unknown evidence references: ${unknown.join(', ')}`;
  return null;
}

function gateNoUnresolvedContradictions(finding, graph) {
  // A contradiction edge FROM the finding node to evidence it cannot explain
  // blocks VERIFIED unless a later REFINES/SUPERSEDES edge resolves it.
  const findingNodes = graph.byKind('Finding').filter((n) => n.payload && n.payload.findingId === finding.id);
  for (const node of findingNodes) {
    const contradicts = graph.edgesFrom(node.id, 'CONTRADICTS');
    const resolutions = graph.edgesFrom(node.id).filter((e) => e.type === 'REFINES' || e.type === 'SUPERSEDES');
    const unresolved = contradicts.filter((c) => !resolutions.some((r) => r.to === c.to));
    if (unresolved.length > 0) return `unresolved contradictions: ${unresolved.map((e) => e.to).join(', ')}`;
  }
  return null;
}

function gateExecutionTruth(finding, graph) {
  // Any claim of executed simulation/test must cite a ToolResult node whose
  // payload shows genuine execution. Genuine artifacts: the simulator's
  // EXECUTED, a passed test (passed:true), or the harness's reproduction
  // vocabulary (VULNERABILITY_REPRODUCED / PATCH_VERIFIED per contracts §13).
  // Deliberately NOT genuine: EXECUTION_COMPLETED (completion is not
  // reproduction), NOT_REPRODUCED (absence of reproduction is not safety),
  // STATIC_ANALYSIS_ONLY, FALLBACK, and every failure status.
  const claimsExecution = /simulat\w* (executed|ran|passed)|executed simulation|test passed|reproduced/i.test(JSON.stringify(finding.claim || ''));
  if (!claimsExecution) return null;
  const cited = [...(finding.supporting || [])]
    .map((id) => graph.get(id))
    .filter((n) => n && n.kind === 'ToolResult');
  const genuine = cited.some((n) => {
    const r = n.payload && n.payload.result;
    return r && (r.status === 'EXECUTED' || r.passed === true
      || r.status === 'VULNERABILITY_REPRODUCED' || r.status === 'PATCH_VERIFIED');
  });
  if (!genuine) return 'claims execution without a genuine EXECUTED/passed/reproduced artifact';
  return null;
}

function gateModelCannotVerify(finding) {
  if (finding.proposedStatus === 'VERIFIED' && finding.proposedBy === 'MODEL') {
    return 'model-proposed VERIFIED is inadmissible; verification is application-owned';
  }
  return null;
}

// Contradiction resolution. Every id in finding.contradicting[] is a material
// counter-reading that must be ADDRESSED before VERIFIED — a reviewer verdict
// of SUPPORTED alone does not discharge it. An entry is resolved iff the
// graph records a resolution under the existing evidence rules:
//   (a) some node supersedes it (node.supersedes === id — e.g. a re-test or
//       correction record displaces the counter-reading), or
//   (b) a Finding node for this finding has a REFINES/SUPERSEDES edge to it
//       (the pre-existing edge mechanism, preserved).
// Unknown ids fail here too (gateIdsResolve also flags them, so malformed
// references reject rather than cap). Unresolved-but-listed contradictions
// cap at HYPOTHESIS via adjudicate: the finding is unproven, not disproven.
function gateContradictionsResolved(finding, graph) {
  const contra = finding.contradicting || [];
  if (contra.length === 0) return null;
  const nodes = [...(graph.nodes ? graph.nodes.values() : [])];
  const findingNodes = graph.byKind('Finding').filter((n) => n.payload && n.payload.findingId === finding.id);
  const edgeResolved = new Set();
  for (const node of findingNodes) {
    for (const e of graph.edgesFrom(node.id)) {
      if (e.type === 'REFINES' || e.type === 'SUPERSEDES') edgeResolved.add(e.to);
    }
  }
  const unresolved = contra.filter((id) => {
    if (edgeResolved.has(id)) return false;
    return !nodes.some((n) => n.supersedes === id);
  });
  if (unresolved.length > 0) {
    return `unresolved contradictions: ${unresolved.join(', ')} (list a superseding record or a REFINES/SUPERSEDES edge to resolve)`;
  }
  return null;
}

// Experimental-sourced evidence (kind 'Experimental' or payload.experimental)
// can inform investigation but can never establish a VERIFIED finding.
function gateNoExperimentalSupport(finding, graph) {
  const experimental = (finding.supporting || []).filter((id) => {
    const node = graph.get(id);
    return node && (node.kind === 'Experimental' || (node.payload && node.payload.experimental === true));
  });
  if (experimental.length > 0) {
    return `experimental-sourced evidence cannot establish VERIFIED: ${experimental.join(', ')}`;
  }
  return null;
}

// Tool-result statuses that describe a check which produced no usable evidence
// about its subject. Citing one as SUPPORT means the finding rests on a
// failure, a timeout, an absence, or a mock — that is a broken finding, not
// merely an unproven one, so this gate rejects (unlike the experimental gate,
// which caps at HYPOTHESIS). Deliberately absent: FALLBACK (genuine
// deterministic analysis, citable for what it is), NOT_RUN (citable process
// evidence), TRANSCRIPTION_PARTIAL and VIDEO_EXTRACTED (partial but real).
const FAILED_TOOL_STATUSES = new Set([
  'UNAVAILABLE',
  'EXECUTION_UNAVAILABLE', 'EXECUTION_FAILED', 'EXECUTION_TIMED_OUT',
  'TRANSCRIPTION_UNAVAILABLE', 'TRANSCRIPTION_TIMEOUT', 'BACKEND_ERROR',
  'VIDEO_PROCESSING_UNAVAILABLE',
  'FAILED'
]);

function gateNoFailedSupport(finding, graph) {
  const bad = [];
  for (const id of finding.supporting || []) {
    const node = graph.get(id);
    if (!node || node.kind !== 'ToolResult') continue;
    const payload = node.payload || {};
    if (payload.error !== undefined && payload.result === undefined) {
      bad.push(`${id} (tool error, no result)`);
      continue;
    }
    const result = payload.result || {};
    if (result.mode === 'mock') {
      bad.push(`${id} (mock result, not observed evidence)`);
      continue;
    }
    if (typeof result.status === 'string' && FAILED_TOOL_STATUSES.has(result.status)) {
      bad.push(`${id} (${result.status})`);
    }
  }
  if (bad.length > 0) {
    return `failed/unavailable/mock tool evidence cannot support a finding: ${bad.join(', ')}`;
  }
  return null;
}

const GATES = [gateHasSupport, gateIdsResolve, gateNoUnresolvedContradictions, gateExecutionTruth, gateModelCannotVerify, gateNoExperimentalSupport, gateNoFailedSupport, gateContradictionsResolved];

// Gate failures that cap at HYPOTHESIS (unproven) rather than REJECTED
// (disproven/broken) when they are the ONLY failures. Experimental support
// and open contradictions both mean "not yet established" — every other gate
// failure describes a finding that is structurally unsound.
const HYPOTHESIS_CAPPING_GATES = new Set(['gateNoExperimentalSupport', 'gateContradictionsResolved']);

function runGates(finding, graph) {
  const failures = [];
  for (const gate of GATES) {
    const reason = gate(finding, graph);
    if (reason) failures.push({ gate: gate.name, reason });
  }
  return { pass: failures.length === 0, failures };
}

/**
 * Adjudicate one finding.
 * @param {object} finding { id, claim, severity, supporting[], contradicting[], proposedStatus?, proposedBy? }
 * @param {EvidenceGraph} graph
 * @param {object|null} modelReview { verdict: SUPPORTED|PARTIAL|REJECTED, reasons[] } from a FRESH context
 */
function adjudicate(finding, graph, modelReview) {
  const gates = runGates(finding, graph);
  if (!gates.pass) {
    const reasons = gates.failures.map((f) => f.reason);
    // Capping-gate failures alone mean unproven (HYPOTHESIS); anything else
    // mixed in — or any non-capping failure — rejects.
    const onlyCapping = gates.failures.length > 0
      && gates.failures.every((f) => HYPOTHESIS_CAPPING_GATES.has(f.gate));
    if (onlyCapping) return { status: 'HYPOTHESIS', reasons, reviewer: null };
    return { status: 'REJECTED', reasons, reviewer: null };
  }
  if (!modelReview) {
    return { status: 'HYPOTHESIS', reasons: ['no independent review yet'], reviewer: null };
  }
  if (modelReview.verdict === 'REJECTED') {
    return { status: 'REJECTED', reasons: modelReview.reasons || ['reviewer rejected'], reviewer: 'MODEL' };
  }
  if (modelReview.verdict === 'PARTIAL') {
    return { status: 'LIKELY', reasons: modelReview.reasons || ['partially supported'], reviewer: 'MODEL' };
  }
  if (modelReview.verdict === 'SUPPORTED') {
    return { status: 'VERIFIED', reasons: ['independent review supported; all gates passed'], reviewer: 'MODEL' };
  }
  return { status: 'HYPOTHESIS', reasons: [`unknown reviewer verdict: ${modelReview.verdict}`], reviewer: 'MODEL' };
}

module.exports = { STATUSES, REVIEW_PROMPT, GATES, FAILED_TOOL_STATUSES, runGates, adjudicate };
