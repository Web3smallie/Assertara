/**
 * Meta Muse Spark investigative reasoning engine (Capability 2).
 * Runs a structured multi-evidence investigation per the versioned
 * methodology in reasoningPrompts, then validates that the response is
 * evidence-grounded (reasoningValidation) as well as well-formed.
 *
 * The model investigates and explains. It never authorizes: verdicts
 * flow through deterministic safeguards and policy, confidence never
 * promotes a decision, and recommendations can only escalate to human
 * review, never permit execution.
 */

const config = require('../config/env');
const { packEvidence } = require('./evidencePacker');
const { canonicalStringify, sha256Hex, safeProvenance } = require('../utils/canonicalJson');
const { selectSystemPrompt, MODEL_REQUEST_CONFIG } = require('./reasoningPrompts');
const { buildEvidenceRegistry, validateInvestigation } = require('./reasoningValidation');
const telemetry = require('./investigationTelemetry');

function fallbackInvestigation(visualText, pageContext, decodedTx, verdict, summary) {
  const vText = (visualText || pageContext?.visibleText || pageContext?.title || '').slice(0, 200);
  return {
    objective: 'Heuristic fallback comparison of stated intent against decoded transaction (limited analysis; not a model investigation).',
    evidenceInventory: [
      { key: 'title', tier: 'UNTRUSTED', available: Boolean(pageContext?.title) },
      { key: 'dom', tier: 'UNTRUSTED', available: Boolean(pageContext?.visibleText) },
      { key: 'tx', tier: 'VERIFIED', available: true },
      { key: 'params', tier: 'VERIFIED', available: true },
      { key: 'ocr', tier: 'OBSERVED', available: false, note: 'heuristic path does not process OCR' }
    ],
    sourceAssessments: [
      { source: 'heuristic keyword matcher', reliability: 'low', note: 'Pattern keywords only; unverified interpretation, never observed fact.' }
    ],
    intentInterpretation: { statement: vText || '(no stated intent supplied)', basisRefs: ['dom'], kind: 'inferred' },
    executionAnalysis: { statement: `${decodedTx.contractName || 'Unknown'}.${decodedTx.functionName || 'unknown'}`, basisRefs: ['tx'] },
    parameterAnalysis: { statement: 'Parameter analysis is not performed by the heuristic fallback.', basisRefs: [] },
    discrepancies: verdict === 'MISMATCH'
      ? [{ statement: summary, severity: 'major', supportingRefs: ['dom', 'tx'], contradictingRefs: [] }]
      : [],
    contradictions: [],
    competingExplanations: [],
    suspiciousBehaviours: [],
    missingEvidence: ['live model reasoning (fallback path active)'],
    uncertainty: {
      level: verdict === 'MATCH' ? 'medium' : 'high',
      explanation: 'Heuristic fallback output; interpretation is unverified.'
    },
    conclusions: [{ statement: summary, supportingRefs: ['dom', 'tx'], contradictingRefs: [] }],
    recommendations: [{ action: 'Re-run the investigation with live model reasoning.', rationale: 'The fallback cannot analyze evidence deeply.', basisRefs: [] }],
    furtherInvestigation: ['Obtain a live model investigation for this evidence set.'],
    evidenceRelationships: []
  };
}

function fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType = 'browser') {
  const vTextLower = (visualText || pageContext?.visibleText || pageContext?.title || '').toLowerCase();
  const fn = decodedTx.functionName || '';
  const isApproval = fn === 'approve' || fn === 'increaseAllowance' || fn === 'setApprovalForAll';
  const hasInfinite = decodedTx.isUnlimitedApproval || decodedTx.ruleFindings.some(r => r.ruleId === 'INFINITE_APPROVAL');
  const withInvestigation = (result) => ({
    ...result,
    investigation: fallbackInvestigation(visualText, pageContext, decodedTx, result.verdict, result.summary),
    referenceValidation: { present: true, ok: true, shapeErrors: [], fabricated: [], synthetic: [], malformed: [], normalized: [], unsupportedConclusions: [] },
    promptVersion: require('./reasoningPrompts').PROMPT_VERSION,
    investigationType
  });

  // Deceptive Airdrop/Claim Phishing Pattern
  if (vTextLower.includes('airdrop') || vTextLower.includes('claim') || vTextLower.includes('free') || vTextLower.includes('reward')) {
    if (isApproval || hasInfinite) {
      return withInvestigation({
        verdict: 'MISMATCH',
        confidence: 0.96,
        summary: `The visual interface promises an airdrop or free reward, but the transaction calldata executes an unconstrained approval (${decodedTx.symbol || 'token'} ${fn}) granting full access to your existing balance.`,
        discrepancyDetails: {
          visualIntent: 'Claim free reward or tokens',
          actualExecution: `Grant unlimited allowance to spender ${decodedTx.parameters?.spender || decodedTx.parameters?.operator || 'unknown'}`,
          criticalMismatch: true
        },
        recommendedAction: 'BLOCK_TRANSACTION',
        origin: 'heuristic-fallback'
      });
    }
  }

  // Legitimate DEX Swap Pattern
  if (vTextLower.includes('swap') || pageContext?.url?.includes('uniswap')) {
    if (fn === 'exactInputSingle' || fn === 'multicall' || (fn === 'approve' && vTextLower.includes('approve'))) {
      return withInvestigation({
        verdict: 'MATCH',
        confidence: 0.88,
        summary: 'The visual swap interface aligns with the decoded transaction parameters. Note that visual alignment does not guarantee contract security.',
        discrepancyDetails: {
          visualIntent: 'Execute token swap on decentralized exchange',
          actualExecution: `Call ${fn} on ${decodedTx.contractName}`,
          criticalMismatch: false
        },
        recommendedAction: 'PROCEED_WITH_CAUTION',
        origin: 'heuristic-fallback'
      });
    }
  }

  // Unknown / Ambiguous
  if (decodedTx.standard === 'Unknown' || fn === 'unknownFunction') {
    return withInvestigation({
      verdict: 'UNCERTAIN',
      confidence: 0.70,
      summary: 'The transaction calls an unverified function or proxy contract whose intent cannot be mapped with certainty to the visible page content.',
      discrepancyDetails: {
        visualIntent: 'Uncertain page context',
        actualExecution: `Execute unparsed function ${decodedTx.parameters?.selector || 'unknown'}`,
        criticalMismatch: false
      },
      recommendedAction: 'VERIFY_RECIPIENT',
      origin: 'heuristic-fallback'
    });
  }

  return withInvestigation({
    verdict: 'UNCERTAIN',
    confidence: 0.65,
    summary: 'Visual context and transaction data could not be conclusively reconciled.',
    discrepancyDetails: {
      visualIntent: vTextLower.slice(0, 100),
      actualExecution: `${decodedTx.contractName}.${fn}`,
      criticalMismatch: false
    },
    recommendedAction: 'PROCEED_WITH_CAUTION',
    origin: 'heuristic-fallback'
  });
}

async function evaluateSemanticDiscrepancy(visualText, pageContext, decodedTx, visualMeta = {}, extraEvidence = {}, options = {}) {
  const investigationType = options && options.investigationType === 'agent' ? 'agent' : 'browser';
  const trace = options && options.trace ? options.trace : null;
  // Evidence packing runs on every path (even fallback) so the packing
  // record — what would reach the model and what was cut — is always
  // auditable. `sent` distinguishes delivered prompts from local
  // fallback decisions.
  const packed = telemetry.timed(trace, 'evidence-packer', '', () => packEvidence({ visualText, pageContext, decodedTx, visualMeta, extra: extraEvidence || {} }),
    (p) => `chars=${p && p.accounting ? p.accounting.totalChars : '?'} truncations=${p && p.accounting && Array.isArray(p.accounting.truncations) ? p.accounting.truncations.length : 0}`);
  const userPrompt = packed.text;
  const system = telemetry.timed(trace, 'prompt-select', investigationType, () => selectSystemPrompt(investigationType),
    (s) => `${s.version} (${investigationType})`);
  const registry = buildEvidenceRegistry({ pageContext, decodedTx, visualMeta, extra: extraEvidence || {} });
  const maxTokens = Number.isInteger(config.museMaxTokens) && config.museMaxTokens > 0 ? config.museMaxTokens : 24000;
  const contextEstimate = {
    systemChars: system.text.length,
    userChars: userPrompt.length,
    estInputTokens: Math.ceil((system.text.length + userPrompt.length) / 4),
    maxOutputTokens: maxTokens,
    promptVersion: system.version
  };
  // Phase 1 provenance: observer-only invocation evidence. Attempt
  // fields (invokedAt, inputDigest) are set only when a real provider
  // request begins; completion fields at each termination point;
  // output fields only when valid output exists. Skipped invocations
  // carry status alone — never attempt artifacts.
  const prov = {
    provenanceStatus: 'skipped',
    invokedAt: null,
    completedAt: null,
    inputDigest: null,
    outputDigest: null,
    responseId: null,
    responseCreated: null
  };
  const withPacking = (result, sent) => ({
    ...result,
    evidencePacking: { ...packed.accounting, sent },
    promptVersion: system.version,
    investigationType,
    contextEstimate,
    provider: 'meta-model-api',
    apiEndpoint: 'chat/completions',
    modelRequested: config.museModel,
    museProvenance: { ...prov }
  });

  if (!config.modelApiKey || config.modelApiKey.startsWith('mock_') || config.modelApiKey.includes('your_meta')) {
    telemetry.markSkipped(trace, 'muse-spark', 'no model API key configured; heuristic fallback decides');
    return withPacking(fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType), false);
  }

  // Hoisted above the try: the catch branch reports this value, and catch
  // cannot see const/let declarations from inside its try block.
  const timeoutMs = config.museTimeoutMs;
  // Production makes exactly one model attempt per investigation (no
  // retry loop): attempts=1 always; retries happen only in test
  // harnesses, never silently inside the production path.
  const modelSpan = telemetry.startSpan(trace, 'muse-spark', `${config.museModel} (attempt 1 of 1)`);

  try {

    // Fix 3: bounded request. The abort signal covers the fetch and the
    // response-body read; the inner finally guarantees timer cleanup on
    // every path, including the early returns below.
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const t0 = Date.now();
      prov.invokedAt = t0;
      prov.inputDigest = safeProvenance(() => sha256Hex(canonicalStringify({ system: system.text, user: userPrompt })));
      const response = await fetch(`${config.metaApiBaseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${config.modelApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: config.museModel,
          messages: [
            { role: 'system', content: system.text },
            { role: 'user', content: userPrompt }
          ],
          response_format: MODEL_REQUEST_CONFIG.responseFormat,
          // Greedy decoding: identical evidence must yield an identical verdict.
          temperature: MODEL_REQUEST_CONFIG.temperature,
          max_tokens: maxTokens
        }),
        signal: ctrl.signal
      });
      const latencyMs = Date.now() - t0;

      if (!response.ok) {
        console.warn(`[Muse Spark Warning] Status ${response.status}. Using fallback reasoner.`);
        prov.provenanceStatus = 'http-error';
        prov.completedAt = Date.now();
        if (modelSpan) modelSpan.fail(`model HTTP ${response.status}; heuristic fallback used`, { attempts: 1, retries: 0, latencyMs, ...prov });
        return withPacking(fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType), true);
      }

      const data = await response.json();
      prov.completedAt = Date.now();
      const content = data.choices?.[0]?.message?.content;
      if (content === null || content === undefined) {
        // Reasoning models can exhaust max_tokens on hidden reasoning
        // and return finish_reason=length with no content at all.
        console.warn(`[Muse Spark Warning] Empty model content (finish_reason=${data.choices?.[0]?.finish_reason || 'unknown'}). Using fallback reasoner.`);
        prov.provenanceStatus = 'empty-content';
        if (modelSpan) modelSpan.fail(`empty model content (finish_reason=${data.choices?.[0]?.finish_reason || 'unknown'}); heuristic fallback used`, { attempts: 1, retries: 0, latencyMs, ...prov });
        return withPacking(fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType), true);
      }
      let parsed;
      try {
        parsed = JSON.parse(content);
      } catch {
        // Unparseable content is invalid output, not a transport
        // failure; same fallback as before, truthfully labeled.
        console.warn('[Muse Spark Warning] Invalid model output (unparseable JSON). Using fallback reasoner.');
        prov.provenanceStatus = 'invalid-output';
        if (modelSpan) modelSpan.fail('invalid model output (unparseable JSON); heuristic fallback used', { attempts: 1, retries: 0, latencyMs, ...prov });
        return withPacking(fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType), true);
      }
      const validation = telemetry.timed(trace, 'reasoning-validation', '', () => validateModelResult(parsed),
        (v) => (v && v.ok ? 'schema valid' : `rejected: ${v && v.reason ? v.reason : 'unknown'}`));
      if (!validation.ok) {
        console.warn(`[Muse Spark Warning] Invalid model output (${validation.reason}). Using fallback reasoner.`);
        prov.provenanceStatus = 'invalid-output';
        if (modelSpan) modelSpan.fail(`invalid model output (${validation.reason}); heuristic fallback used`, { attempts: 1, retries: 0, latencyMs, ...prov });
        return withPacking(fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType), true);
      }
      // Evidence grounding: a well-formed response can still cite
      // evidence that was never supplied. The reference record rides
      // the result so safeguards and the bundle can act on it.
      let referenceValidation = { present: false, ok: true, shapeErrors: [], fabricated: [], synthetic: [], malformed: [], normalized: [], unsupportedConclusions: [] };
      if (parsed.investigation !== undefined) {
        const inv = telemetry.timed(trace, 'reference-validation', '', () => validateInvestigation(parsed.investigation, registry),
          (v) => (v && v.ok ? `grounded (${(v.normalized || []).length} refs)` : `fabricated=${(v && v.fabricated || []).length}`));
        referenceValidation = { present: true, ...inv };
        if (inv.shapeErrors.length > 0) {
          console.warn(`[Muse Spark Warning] Malformed investigation object (${inv.shapeErrors[0]}). Using fallback reasoner.`);
          prov.provenanceStatus = 'invalid-output';
          if (modelSpan) modelSpan.fail(`malformed investigation object (${inv.shapeErrors[0]}); heuristic fallback used`, { attempts: 1, retries: 0, latencyMs, ...prov });
          return withPacking(fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType), true);
        }
      } else {
        telemetry.markSkipped(trace, 'reference-validation', 'no investigation object in model output');
      }
      parsed.origin = 'model';
      parsed.modelId = typeof data.model === 'string' ? data.model : null;
      prov.provenanceStatus = 'success';
      prov.responseId = typeof data.id === 'string' ? data.id.slice(0, 128) : null;
      prov.responseCreated = Number.isInteger(data.created) ? data.created : null;
      prov.outputDigest = safeProvenance(() => sha256Hex(content));
      parsed.latencyMs = latencyMs;
      parsed.usage = data.usage && typeof data.usage === 'object' ? {
        promptTokens: Number.isInteger(data.usage.prompt_tokens) ? data.usage.prompt_tokens : null,
        completionTokens: Number.isInteger(data.usage.completion_tokens) ? data.usage.completion_tokens : null,
        totalTokens: Number.isInteger(data.usage.total_tokens) ? data.usage.total_tokens : null
      } : null;
      parsed.referenceValidation = referenceValidation;
      // Time-to-first-token is unavailable: the provider API is
      // non-streaming (one JSON response), so only total latency and
      // token usage are measurable. Recorded explicitly as null.
      if (modelSpan) modelSpan.finish(`verdict=${parsed.verdict} conf=${parsed.confidence}`, {
        model: config.museModel, servingModelId: parsed.modelId, promptVersion: system.version,
        latencyMs, timeToFirstTokenMs: null, usage: parsed.usage,
        attempts: 1, retries: 0, timeouts: 0, fallbackUsed: false, timeoutMs, ...prov
      });
      return withPacking(parsed, true);
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    if (err && err.name === 'AbortError') {
      console.warn(`[Muse Spark Timeout] Reasoning timed out after ${timeoutMs}ms. Using fallback reasoner.`);
      prov.provenanceStatus = 'timeout';
      prov.completedAt = Date.now();
      if (modelSpan) modelSpan.fail(`model timeout after ${timeoutMs}ms; heuristic fallback used`, { attempts: 1, retries: 0, timeouts: 1, latencyMs: timeoutMs, ...prov });
      return withPacking({ ...fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType), timeout: true }, true);
    }
    console.warn(`[Muse Spark Error] Reasoning failed: ${err.message}. Using fallback.`);
    prov.provenanceStatus = 'transport-error';
    prov.completedAt = Date.now();
    if (modelSpan) modelSpan.fail(`model call failed (${err.message}); heuristic fallback used`, { attempts: 1, retries: 0, ...prov });
    return withPacking(fallbackHeuristicReasoner(visualText, pageContext, decodedTx, investigationType), true);
  }
}

/**
 * Boundary validation for untrusted model output. The verdict must be a
 * non-empty string, confidence a finite number in [0, 1], and the remaining
 * schema fields present with their documented types. Anything else is
 * rejected so the caller falls back — invalid output is never labeled a
 * successful model result, and out-of-range confidence is never clamped.
 *
 * Verdict *vocabulary* is deliberately not enforced here: unknown strings
 * and case variants flow to the controller's INVALID_VERDICT normalization,
 * which coerces them explicitly with a safeguard record (never silently).
 * NaN/Infinity cannot arise from JSON parsing but are rejected anyway so a
 * future transport cannot smuggle them in.
 *
 * The deep investigation object is optional for backward compatibility
 * (canned fixtures and older callers omit it); when present it must be
 * an object, and full grounding validation happens in
 * evaluateSemanticDiscrepancy against the evidence registry.
 */
function validateModelResult(parsed) {
  const fail = (reason) => ({ ok: false, reason });
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return fail('response is not a JSON object');
  }
  if (typeof parsed.verdict !== 'string' || parsed.verdict.length === 0) {
    return fail('verdict must be a non-empty string');
  }
  if (typeof parsed.confidence !== 'number' || !Number.isFinite(parsed.confidence)
      || parsed.confidence < 0 || parsed.confidence > 1) {
    return fail('confidence must be a finite number in [0, 1]');
  }
  if (typeof parsed.summary !== 'string') {
    return fail('summary must be a string');
  }
  if (!parsed.discrepancyDetails || typeof parsed.discrepancyDetails !== 'object'
      || Array.isArray(parsed.discrepancyDetails)) {
    return fail('discrepancyDetails must be an object');
  }
  if (typeof parsed.recommendedAction !== 'string') {
    return fail('recommendedAction must be a string');
  }
  if (parsed.visualClaims !== undefined && !Array.isArray(parsed.visualClaims)) {
    return fail('visualClaims must be an array when present');
  }
  if (parsed.investigation !== undefined
      && (typeof parsed.investigation !== 'object' || parsed.investigation === null || Array.isArray(parsed.investigation))) {
    return fail('investigation must be an object when present');
  }
  return { ok: true };
}

module.exports = { evaluateSemanticDiscrepancy, fallbackHeuristicReasoner, validateModelResult };
