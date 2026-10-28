/**
 * Assertara feature map + implemented feature runners.
 * Retained areas: core/advanced investigation, experimental gate,
 * transaction translator, pre-sign triage, risk localizer, replay, and
 * harness power tools. Implemented runners use the orchestrator,
 * tool registry, evidence graph, and an injected model client (real
 * SparkAdapter in production, scripted stubs in tests). Anything else
 * resolves to an explicit boundary object — never a silent mock.
 *
 * Removed lanes (see cleanup history): chain-history sentinel, contract
 * dossiers, scam-call analysis, finding Q&A, audit-ledger workflows,
 * video walkthrough verification, Night Watch scheduling, and static
 * repository review. Their modules were deleted; unknown feature ids
 * throw loudly instead of resolving to a boundary.
 */

const { Orchestrator } = require('./orchestrator');
const { EvidenceGraph } = require('./evidenceGraph');
const { runTool } = require('./toolRegistry');
const { adjudicate } = require('./verifier');
const { buildInvestigationReport, buildReplayBundle, buildTranslatorOutput } = require('./reports');

const FEATURES = {
  F1_core: { id: 'F1_core', name: 'Core Intelligence', status: 'IMPLEMENTED', uses: ['orchestrator', 'evidence-graph', 'tool-registry', 'spark-adapter', 'verifier', 'live-model-driver'] },
  F2_advanced: { id: 'F2_advanced', name: 'Advanced Intelligence', status: 'PARTIAL', uses: ['orchestrator(parallel+effort-ladder)', 'verifier(fresh-review)', 'live-model-driver'], limitations: ['Staged hypothesis trees and full parallel-hypothesis campaigns are wired through the same loop but not yet packaged as a dedicated runner.'] },
  F3_experimental: { id: 'F3_experimental', name: 'Experimental Features', status: 'EXPERIMENTAL', uses: ['sandboxed-runners-only'], limitations: ['Computer-use and other frontier workflows are unevaluated; nothing here may feed verified findings.'] },
  F4_translator: { id: 'F4_translator', name: 'Plain-Language Transaction Translator', status: 'IMPLEMENTED', uses: ['decode_tx', 'spark-complete', 'quote-validation'] },
  F5_interceptor: { id: 'F5_interceptor', name: 'Pre-Sign Risk Interceptor', status: 'IMPLEMENTED', uses: ['decode_tx', 'allowance_analysis', 'spark-triage', 'escalation-to-F1'] },
  F12_localize: { id: 'F12_localize', name: 'Multilingual Risk Localizer', status: 'IMPLEMENTED', uses: ['segment-localization', 'protected-value-tripwires', 'verified-language-set'] },
  F13_replay: { id: 'F13_replay', name: 'Investigation Replay Theater', status: 'IMPLEMENTED', uses: ['execution-ledger', 'replay-bundle', 'event-recorder', 'hash-chained-replay'] },
  F15_harness: { id: 'F15_harness', name: 'Agent-Harness Power Tools', status: 'PARTIAL', uses: ['harness-interface', 'sandbox_exec'], limitations: ['No isolated executor in this environment (Docker/Podman absent); execute requests return EXECUTION_UNAVAILABLE. Request validation, adjudication, and evidence rules are implemented and tested.'] }
};

function boundary(featureId) {
  const f = FEATURES[featureId];
  if (!f) throw new Error(`unknown feature: ${featureId}`);
  return { status: f.status, feature: { id: f.id, name: f.name }, requirements: f.requirements || [], limitations: f.limitations || [] };
}

function requireModel(deps) {
  if (!deps || !deps.model || typeof deps.model.complete !== 'function') {
    throw new Error('this feature requires a model client with complete()');
  }
  return deps.model;
}

// Resolve the F1/F2 turn driver: an injected modelClient wins; otherwise
// { live: true } builds the Spark-backed driver (adapter injectable for
// tests, default SparkAdapter reads existing config). Anything else throws —
// the loops never silently run without a driver.
function resolveModelClient(feature, deps) {
  if (deps && deps.modelClient && typeof deps.modelClient.nextTurn === 'function') {
    return deps.modelClient;
  }
  if (deps && deps.live === true) {
    const { createModelDriver } = require('./modelDriver');
    return createModelDriver({ adapter: deps.adapter || null, ...(deps.driver || {}) });
  }
  throw new Error(`${feature} requires a modelClient with nextTurn() (or { live: true } for the Spark-backed driver)`);
}

// F1 — bounded core investigation loop over injected tools.
async function runCoreInvestigation({ goal, inputs, budget }, deps) {
  const modelClient = resolveModelClient('F1', deps);
  const orchestrator = new Orchestrator({ modelClient, budget });
  const record = await orchestrator.run('F1_core', { goal: goal || 'investigate', ...(inputs || {}) }, {
    effortFor: (turn) => (turn <= 1 ? 'low' : turn <= 3 ? 'high' : 'medium')
  });
  return { status: 'OK', feature: 'F1_core', record };
}

// F4 — grounded translation; every quoted fact verified against decode.
async function runTranslator({ tx, locale }, deps) {
  const model = requireModel(deps);
  if (!tx || !tx.to) throw new Error('translator requires a transaction with "to"');
  const decoded = await runTool('decode_tx', tx);
  const schema = {
    type: 'object',
    additionalProperties: false,
    required: ['action', 'assets', 'contract', 'permissions', 'boundedOrUnlimited', 'consequences', 'risks', 'unknowns', 'quoted'],
    properties: {
      action: { type: 'string' }, assets: { type: 'array', items: { type: 'string' } },
      contract: { type: 'string' }, permissions: { type: 'string' },
      boundedOrUnlimited: { type: 'string' },
      consequences: { type: 'array', items: { type: 'string' } },
      risks: { type: 'array', items: { type: 'string' } },
      unknowns: { type: 'array', items: { type: 'string' } },
      quoted: { type: 'object', additionalProperties: false, required: ['function', 'to', 'amount', 'spender'], properties: { function: { type: 'string' }, to: { type: 'string' }, amount: { type: 'string' }, spender: { type: 'string' } } }
    }
  };
  const { content } = await model.complete({
    system: `Explain EVM transactions in plain ${locale || 'English'}. Ground every quoted value in the decoded facts provided. Never invent parameters. List anything uncertain under unknowns.`,
    input: `DECODED FACTS:\n${JSON.stringify(decoded)}\n\nExplain this transaction using the schema.`,
    schema, schemaName: 'translator_output', effort: 'low'
  });
  const issues = [];
  const q = content.quoted || {};
  if (q.function !== (decoded.functionName || null)) issues.push(`function mismatch: quoted ${q.function}`);
  if (String(q.to || '').toLowerCase() !== String(decoded.contract || '').toLowerCase()) issues.push('recipient mismatch: quoted to != decoded contract');
  const decodedAmount = decoded.parameters && (decoded.parameters.amount ?? decoded.parameters.amountIn);
  if (q.amount !== undefined && String(q.amount) !== String(decodedAmount)) issues.push('amount mismatch: quoted amount != decoded amount');
  if (q.spender !== undefined && String(q.spender || '').toLowerCase() !== String((decoded.parameters || {}).spender || '').toLowerCase()) {
    issues.push('spender mismatch');
  }
  const output = buildTranslatorOutput({ decoded, explanation: content, risks: content.risks, unknowns: content.unknowns });
  return { status: issues.length === 0 ? 'OK' : 'UNVERIFIED_QUOTES', feature: 'F4_translator', output, issues };
}

// F5 — fast deterministic screen + bounded model triage. Advisory only.
const TRIAGE_ORDER = ['GREEN', 'AMBER', 'INCONCLUSIVE', 'RED'];
async function runTriage({ tx, claims }, deps) {
  if (!tx || !tx.to) throw new Error('triage requires a transaction with "to"');
  const decoded = await runTool('decode_tx', tx);
  const allowance = await runTool('allowance_analysis', { decoded });
  const rules = decoded.ruleFindings || [];
  const hasHigh = rules.some((r) => r.severity === 'HIGH' || r.severity === 'CRITICAL');
  let signal = 'GREEN';
  const reasons = [];
  if (decoded.functionName === 'unknownFunction') { signal = 'AMBER'; reasons.push('Unrecognized function; cannot confirm intent.'); }
  if (allowance.isUnlimited) { signal = 'RED'; reasons.push('Unlimited approval requested.'); }
  if (hasHigh) { signal = 'RED'; reasons.push(`Security rules triggered: ${rules.map((r) => r.ruleId).join(',')}.`); }
  let modelTriage = null;
  if (deps && deps.model && typeof deps.model.complete === 'function') {
    const schema = {
      type: 'object',
      additionalProperties: false,
      required: ['signal', 'reasons', 'needsDeepDive'],
      properties: {
        signal: { type: 'string', enum: ['GREEN', 'AMBER', 'RED', 'INCONCLUSIVE'] },
        reasons: { type: 'array', items: { type: 'string' } },
        needsDeepDive: { type: 'boolean' }
      }
    };
    const { content } = await deps.model.complete({
      system: 'Triage EVM transactions fast. Use only the decoded facts and claims provided. Never invent parameters.',
      input: `DECODED: ${JSON.stringify(decoded)}\nCLAIMS: ${JSON.stringify(claims || {})}`,
      schema, schemaName: 'triage', effort: 'minimal'
    });
    modelTriage = content;
    if (TRIAGE_ORDER.indexOf(content.signal) > TRIAGE_ORDER.indexOf(signal)) signal = content.signal;
    for (const r of content.reasons || []) reasons.push(`model: ${r}`);
  } else {
    reasons.push('Model triage unavailable; deterministic screen only.');
    if (signal === 'GREEN') signal = 'INCONCLUSIVE';
  }
  return {
    status: 'OK', feature: 'F5_interceptor', signal, reasons,
    escalate: signal === 'RED' || (signal === 'AMBER' && reasons.length > 1) || signal === 'INCONCLUSIVE',
    decodedFunction: decoded.functionName, ruleIds: rules.map((r) => r.ruleId)
  };
}

// F12 — translate a validated finding; protected values reattached verbatim.
// Text fields are localized by segment; protected fields never pass through
// the model as editable output, so alteration is structurally impossible.
const PROTECTED_FIELDS = ['contract', 'functionName', 'parameters', 'severity', 'supporting', 'contradicting'];
const LOCALIZABLE_TEXT = [['claim', 'fact'], ['summary', 'fact'], ['description', 'fact'], ['warning', 'warning'], ['uncertaintyNote', 'uncertainty'], ['recommendedAction', 'guidance'], ['remediation', 'guidance']];
async function runLocalize({ finding, targetLang }, deps) {
  if (!finding || typeof finding !== 'object') throw new Error('localize requires a finding object');
  if (!targetLang || typeof targetLang !== 'string') throw new Error('localize requires a target language');
  const { localizeAssessment } = require('./localize');
  const segments = [];
  for (const [key, tone] of LOCALIZABLE_TEXT) {
    if (typeof finding[key] === 'string' && finding[key].length > 0) segments.push({ id: key, text: finding[key], tone });
  }
  if (segments.length === 0) throw new Error('localize requires at least one text field (claim, warning, recommendedAction, ...)');
  const prot = {};
  for (const k of PROTECTED_FIELDS) {
    if (finding[k] !== undefined) prot[k] = finding[k];
  }
  const res = await localizeAssessment(
    { assessment: { segments, protected: prot }, targetLang },
    { model: deps && deps.model }
  );
  if (res.status !== 'OK') {
    return { status: res.status, feature: 'F12_localize', language: res.language || null, error: res.error || res.note || null, supported: res.supported || null, original: finding };
  }
  const translated = { ...finding };
  for (const s of res.localized.segments) translated[s.id] = s.text;
  for (const k of Object.keys(res.localized.protected)) translated[k] = res.localized.protected[k];
  return { status: 'OK', feature: 'F12_localize', language: res.language, finding: translated, protectedValues: res.protectedValues, original: finding };
}

// F13 — hash-chained recordings + historical replay. The legacy bundle path
// is preserved byte-for-byte; new callers build a recording once and replay
// it without re-executing anything.
function runReplay({ record, graph, recording, evidence, build, assessments, model } = {}) {
  const { recordFromRun, replayRecording } = require('./replay');
  if (recording !== undefined) {
    const res = replayRecording(recording, { evidence: evidence || null });
    return { status: res.status, feature: 'F13_replay', mode: 'historical', replay: res };
  }
  if (build === true) {
    if (!record || !graph) throw new Error('replay build requires a record and graph');
    return { status: 'OK', feature: 'F13_replay', mode: 'build', recording: recordFromRun({ record, graph, assessments: assessments || [], model: model || null }) };
  }
  if (!record || !graph) throw new Error('replay requires a record and graph, build:true, or a recording');
  return { status: 'OK', feature: 'F13_replay', bundle: buildReplayBundle({ record, graph }) };
}

// F2 — advanced: core loop, then competing hypotheses, then fresh-review adjudication.
async function runAdvanced({ goal, inputs, hypotheses }, deps) {
  resolveModelClient('F2', deps); // validates the driver seam (core run re-resolves it)
  const core = await runCoreInvestigation({ goal, inputs }, deps);
  const graph = core.record.graph;
  const proposed = Array.isArray(hypotheses) ? hypotheses : [];
  const reviewer = deps.reviewer && typeof deps.reviewer.complete === 'function'
    ? deps.reviewer
    : (deps.live === true ? (deps.adapter || require('./modelDriver').defaultAdapter()) : null);
  const reviewed = [];
  for (const h of proposed) {
    const node = graph.append({ kind: 'Hypothesis', producer: 'MODEL', payload: { hypothesisId: h.id, claim: h.claim }, created_turn: core.record.turns.length });
    void node;
    let review = null;
    if (reviewer && typeof reviewer.complete === 'function') {
      // The graph export may embed raw caller inputs: scrub secrets before
      // the reviewer model ever sees them.
      const { redactSensitive } = require('./replay');
      const { value: safeGraph } = redactSensitive(graph.export());
      const out = await reviewer.complete({
        system: 'Adversarial review. Attempt to disprove the hypothesis from the evidence graph only.',
        input: `GRAPH: ${JSON.stringify(safeGraph).slice(0, 20000)}\nHYPOTHESIS: ${JSON.stringify(h)}`,
        schema: { type: 'object', additionalProperties: false, required: ['verdict', 'reasons'], properties: { verdict: { type: 'string', enum: ['SUPPORTED', 'PARTIAL', 'REJECTED'] }, reasons: { type: 'array', items: { type: 'string' } } } },
        schemaName: 'adversarial_review', effort: 'high'
      });
      review = out.content;
    }
    reviewed.push({ id: h.id, adjudication: adjudicate({ id: h.id, claim: h.claim, supporting: h.supporting || [], contradicting: h.contradicting || [] }, graph, review) });
  }
  return { status: 'OK', feature: 'F2_advanced', record: core.record, reviewed };
}

// F3 — experimental gate. Nothing runs without explicit opt-in; nothing here
// may feed verified findings.
function runExperimental({ allowExperimental }) {
  if (allowExperimental !== true) {
    return { status: 'GATED', feature: 'F3_experimental', error: 'Experimental runners require explicit allowExperimental:true and are labeled experimental.' };
  }
  return { status: 'EXPERIMENTAL', feature: 'F3_experimental', note: 'No experimental runners are enabled. Frontier workflows land here only after evaluation.' };
}

// F15 — thin wrapper over the harness interface for isolated exploit
// reproduction, fix verification, and regression runs.
async function runHarnessExecute(inputs, deps) {
  const { submitHarnessRun } = require('./harness');
  return submitHarnessRun(inputs || {}, { executor: deps && deps.executor, workspaceRoot: deps && deps.workspaceRoot });
}

async function runFeature(id, inputs, deps) {
  const f = FEATURES[id];
  if (!f) throw new Error(`unknown feature: ${id}`);
  switch (id) {
    case 'F1_core': return runCoreInvestigation(inputs || {}, deps || {});
    case 'F2_advanced': return runAdvanced(inputs || {}, deps || {});
    case 'F3_experimental': return runExperimental(inputs || {});
    case 'F4_translator': return runTranslator(inputs || {}, deps || {});
    case 'F5_interceptor': return runTriage(inputs || {}, deps || {});
    case 'F12_localize': return runLocalize(inputs || {}, deps || {});
    case 'F13_replay': return runReplay(inputs || {});
    case 'F15_harness': return runHarnessExecute(inputs || {}, deps || {});
    default: return boundary(id);
  }
}

module.exports = {
  FEATURES, boundary, runFeature,
  runCoreInvestigation, runTranslator, runTriage, runLocalize, runReplay,
  runAdvanced, runExperimental, runHarnessExecute
};
