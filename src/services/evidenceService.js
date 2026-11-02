/**
 * Evidence Bundle Compiler & Serializer
 */

const crypto = require('crypto');
const { associateRegions } = require('../utils/association');
const { validateVisualClaims } = require('../utils/grounding');
const { buildIntentComparison } = require('./intentComparisonAdapter');

const MANDATORY_SAFETY_NOTICE = 'A MATCH verdict indicates visual alignment with transaction calldata, NOT that the target contract or protocol is secure or bug-free.';

/**
 * Build the visual-evidence inputs shared by the bundle and the Phase C
 * safeguard precompute: genuine region entries joined with OCR, geometric
 * associations, and validated visual claims. Pure and deterministic; the
 * single implementation both call sites use, so the comparison the
 * safeguard evaluates is exactly what the bundle displays.
 */
function prepareComparisonInputs(visualResult, visualClaims) {
  const genuineRegions = (visualResult?.regions || []).filter((r) => r && r.genuine !== false);
  const ocrRecords = visualResult?.regionTexts || [];
  const ocrById = new Map(ocrRecords.filter((r) => r && r.regionId).map((r) => [r.regionId, r]));
  const regionEntries = genuineRegions.map((r, i) => {
    const ocr = ocrById.get(r.regionId) || ocrRecords[i];
    return {
      regionId: r.regionId || (ocr && ocr.regionId) || null,
      label: r.label,
      boundingBox: r.boundingBox,
      confidence: r.confidence === undefined ? null : r.confidence,
      prompts: r.prompts || undefined,
      genuine: true,
      ocr: ocr
        ? { text: ocr.text, empty: ocr.empty === true, error: ocr.ocrError || null }
        : { text: null, empty: false, error: { code: 'OCR_NOT_RUN', message: 'No OCR record for this region' } }
    };
  });
  const shot = visualResult?.screenshot;
  const associations = associateRegions(regionEntries, {
    dims: shot && Number.isInteger(shot.width) && Number.isInteger(shot.height)
      ? { width: shot.width, height: shot.height }
      : null
  });
  const fbRecords = visualResult?.fallbackRecords || [];
  const fbOcr = fbRecords[0];
  const fallbackId = (fbOcr && fbOcr.regionId) || 'R-FALLBACK';
  const grounding = validateVisualClaims(visualClaims, {
    regions: regionEntries,
    associations,
    syntheticRegionIds: visualResult?.fallbackUsed === true ? [fallbackId] : []
  });
  return { regionEntries, associations, grounding, fbRecords, fbOcr };
}

function compileEvidenceBundle({
  visualResult,
  decodedTx,
  reasoningResult,
  simulationResult,
  pageContext = {},
  screenshotProvided = false,
  verdictSafeguard = null,
  verdictSafeguards = null,
  confidenceCap = null,
  policyDecision = null,
  txBinding = null,
  sender = null,
  intentComparison: precomputedComparison = null,
  assemblyEvidence = null
}) {
  const evalId = `eval_${crypto.randomBytes(4).toString('hex')}`;
  const timestamp = new Date().toISOString();

  // Phase 1: genuine detections only. Synthetic fallback geometry never
  // counts as a detection and is surfaced separately with its reason.
  const genuineRegions = (visualResult?.regions || []).filter((r) => r && r.genuine !== false);
  const detectedCount = Number.isInteger(visualResult?.detectedCount)
    ? visualResult.detectedCount
    : genuineRegions.length;
  const visualAvailable = typeof visualResult?.visualAvailable === 'boolean'
    ? visualResult.visualAvailable
    : detectedCount > 0;
  const fallbackUsed = visualResult?.fallbackUsed === true;
  const primaryRegion = genuineRegions[0] || {
    boundingBox: { x: 0, y: 0, width: 800, height: 600 }
  };

  const ocrText = visualResult.combinedText || '';
  const ocrSynthetic = visualResult?.combinedTextSynthetic === true;
  const domText = pageContext.visibleText || '';

  // Shared visual inputs (region entries, associations, grounding) via
  // the single implementation the safeguard precompute also uses.
  const { regionEntries, associations, grounding, fbRecords, fbOcr } = prepareComparisonInputs(
    visualResult, reasoningResult.visualClaims
  );
  const ocrMode = detectedCount > 0 ? 'regions' : (fallbackUsed ? 'fallback-scan' : 'none');

  // Safeguard records: `verdictSafeguards` is the full ordered list (every
  // trigger preserved, nothing overwritten); `verdictSafeguard` is the first
  // entry, kept for backward compatibility. A legacy single-object caller is
  // still accepted and normalized to a one-entry list.
  const safeguardList = Array.isArray(verdictSafeguards)
    ? verdictSafeguards
    : (verdictSafeguard ? [verdictSafeguard] : []);

  // Phase B/C: deterministic intent comparison. The controller passes
  // the precomputed result the safeguard evaluated so the displayed
  // comparison is identical to it; direct callers compute it fresh here.
  // Informational evidence only — verdict effects happen in the
  // controller's safeguard pipeline, never here. The adapter never throws
  // (failures become an explicit ERROR record).
  const intentComparison = precomputedComparison ?? buildIntentComparison({
    regionEntries,
    grounding,
    associations,
    decodedTx,
    sender
  });

  return {
    id: evalId,
    timestamp,
    verdict: reasoningResult.verdict || 'UNCERTAIN',
    // Nullish (not falsy) default: a validated model confidence of 0 is a
    // real value and must survive; only missing confidence defaults to 0.5.
    confidence: reasoningResult.confidence ?? 0.5,
    summary: reasoningResult.summary || 'Transaction analysis complete.',
    recommendedAction: reasoningResult.recommendedAction || null,
    // Capability 2: the model's structured analysis is preserved, never
    // discarded. Null for direct callers that never ran reasoning.
    discrepancyDetails: reasoningResult.discrepancyDetails || null,
    investigation: reasoningResult.investigation || null,
    promptVersion: reasoningResult.promptVersion || null,
    investigationType: reasoningResult.investigationType || null,
    modelId: reasoningResult.modelId || null,
    latencyMs: Number.isInteger(reasoningResult.latencyMs) ? reasoningResult.latencyMs : null,
    usage: reasoningResult.usage || null,
    contextEstimate: reasoningResult.contextEstimate || null,
    referenceValidation: reasoningResult.referenceValidation || null,
    // Provenance: 'model' (Muse Spark) vs 'heuristic-fallback'
    // (deterministic rules; unverified interpretation, never observed fact).
    reasoningOrigin: reasoningResult.origin || 'unknown',
    // True only when the Muse request itself timed out (the reasoner sets
    // `timeout: true` solely on abort). Strict equality keeps every older
    // or non-timeout path — including direct bundle callers that never ran
    // reasoning — safely at false.
    reasoningTimedOut: reasoningResult.timeout === true,
    // Phase 1 provenance: observer-only model-invocation evidence. Direct
    // bundle callers that never ran the reasoner get nulls (never
    // invented metadata); origin 'model' without a block still implies
    // success because only the success path sets that origin.
    museProvenance: (() => {
      const prov = reasoningResult.museProvenance && typeof reasoningResult.museProvenance === 'object'
        ? reasoningResult.museProvenance : null;
      return {
        status: (prov && prov.provenanceStatus) || (reasoningResult.origin === 'model' ? 'success' : 'unknown'),
        provider: typeof reasoningResult.provider === 'string' ? reasoningResult.provider : null,
        endpoint: typeof reasoningResult.apiEndpoint === 'string' ? reasoningResult.apiEndpoint : null,
        requested: typeof reasoningResult.modelRequested === 'string' ? reasoningResult.modelRequested : null,
        served: reasoningResult.modelId || null,
        responseId: (prov && prov.responseId) || null,
        responseCreated: (prov && Number.isInteger(prov.responseCreated)) ? prov.responseCreated : null,
        invokedAt: (prov && Number.isInteger(prov.invokedAt)) ? prov.invokedAt : null,
        completedAt: (prov && Number.isInteger(prov.completedAt)) ? prov.completedAt : null,
        inputDigest: (prov && prov.inputDigest) || null,
        outputDigest: (prov && prov.outputDigest) || null,
        latencyMs: Number.isInteger(reasoningResult.latencyMs) ? reasoningResult.latencyMs : null,
        usage: reasoningResult.usage || null
      };
    })(),
    samProvenance: (() => {
      const vr = visualResult && typeof visualResult === 'object' ? visualResult : null;
      const shot = vr && vr.screenshot && typeof vr.screenshot === 'object' ? vr.screenshot : null;
      if (!vr || typeof vr.samMode !== 'string') {
        return {
          status: 'skipped', mode: null, configured: null, observed: null,
          invokedAt: null, completedAt: null, responseId: null, usage: null,
          outputDigest: null, screenshotDigest: (shot && shot.sha256) || null,
          submittedImageDigest: null, detectedCount: 0, perPrompt: []
        };
      }
      return {
        status: vr.samStatus || (vr.samMode === 'mock' ? 'mock' : 'unknown'),
        mode: vr.samMode,
        configured: vr.samModelConfigured || null,
        observed: vr.samModelObserved || null,
        invokedAt: Number.isInteger(vr.samInvokedAt) ? vr.samInvokedAt : null,
        completedAt: Number.isInteger(vr.samCompletedAt) ? vr.samCompletedAt : null,
        responseId: vr.samResponseId || null,
        usage: vr.samUsage || null,
        outputDigest: vr.samOutputDigest || null,
        screenshotDigest: (shot && shot.sha256) || null,
        submittedImageDigest: vr.samSubmittedImageDigest || null,
        detectedCount: Number.isInteger(vr.detectedCount) ? vr.detectedCount : 0,
        perPrompt: Array.isArray(vr.samPromptResults) ? vr.samPromptResults : []
      };
    })(),
    safetyNotice: MANDATORY_SAFETY_NOTICE,
    pageEvidence: {
      title: pageContext.title || null,
      url: pageContext.url || null
    },
    visualEvidence: {
      boundingBox: primaryRegion.boundingBox,
      extractedText: ocrText || 'No text extracted',
      actionElement: genuineRegions.find(r => r.label && r.label.includes('button'))?.label || 'Action Button',
      detectedCount,
      visualAvailable,
      ocrMode,
      screenshot: visualResult?.screenshot || null,
      screenshotError: visualResult?.screenshotError || null,
      regions: regionEntries,
      fallback: fallbackUsed
        ? {
            reason: visualResult.fallbackReason || 'unknown',
            regionId: (fbOcr && fbOcr.regionId) || 'R-FALLBACK',
            boundingBox: (visualResult.fallbackRegion && visualResult.fallbackRegion.boundingBox) || null,
            ocr: fbOcr
              ? { text: fbOcr.text, empty: fbOcr.empty === true, error: fbOcr.ocrError || null }
              : { text: null, empty: false, error: { code: 'OCR_NOT_RUN', message: 'No OCR record for the fallback scan' } }
          }
        : (visualResult.fallbackReason
          ? {
              reason: visualResult.fallbackReason,
              regionId: null,
              boundingBox: null,
              ocr: { text: null, empty: false, error: { code: 'FALLBACK_NOT_RUN', message: 'Fallback scan did not run' } }
            }
          : null),
      samError: visualResult?.samError || null,
      samPartialFailure: visualResult?.partialFailure === true,
      samIncomplete: visualResult?.incomplete === true,
      samPromptResults: visualResult?.samPromptResults || [],
      associations,
      grounding,
      summaryText: visualResult?.summaryText || null,
      intentTextSource: visualResult?.intentSource || null,
      intentComparison,
      textSources: [
        { source: 'OCR_TEXT', available: Boolean(screenshotProvided), synthetic: ocrSynthetic, text: ocrText },
        { source: 'DOM_TEXT', available: domText.length > 0, synthetic: false, text: domText }
      ]
    },
    decodedTransaction: {
      contract: decodedTx.contract,
      contractName: decodedTx.contractName,
      functionName: decodedTx.functionName,
      standard: decodedTx.standard || null,
      standardAmbiguous: decodedTx.standardAmbiguous === true,
      standardCandidates: Array.isArray(decodedTx.standardCandidates) ? decodedTx.standardCandidates : [],
      parameters: decodedTx.parameters,
      isUnlimitedApproval: decodedTx.isUnlimitedApproval,
      valueWei: decodedTx.valueWei,
      valueEth: decodedTx.valueEth
    },
    ruleFindings: decodedTx.ruleFindings || [],
    verdictSafeguard: safeguardList[0] || null,
    verdictSafeguards: safeguardList,
    confidenceCap: confidenceCap || null,
    // Final policy decision from the centralized composer (controller).
    // Null only for direct bundle callers that never ran the pipeline —
    // never fabricated here.
    policyDecision: policyDecision || null,
    // Payload binding: digests of the evaluated transaction bytes.
    // { receivedTxDigest, evaluatedTxDigest, match } with tri-state
    // match (true/false/null when not comparable). Null only for direct
    // callers that never ran the pipeline.
    txBinding: txBinding || null,
    // Phase B assembly evidence: prompt packing audit, live chain state,
    // freshness verdict, counterparty label hints (never identity proof).
    // Capability 3 B2 adds the simulation reconciliation record.
    // Null for direct callers that never ran the pipeline.
    evidencePacking: (assemblyEvidence && assemblyEvidence.evidencePacking) || null,
    chainState: (assemblyEvidence && assemblyEvidence.chainState) || null,
    freshness: (assemblyEvidence && assemblyEvidence.freshness) || null,
    counterpartyLabels: (assemblyEvidence && assemblyEvidence.counterpartyLabels) || null,
    simReconciliation: (assemblyEvidence && assemblyEvidence.simReconciliation) || null,
    chainVerification: (assemblyEvidence && assemblyEvidence.chainVerification) || null,
    proxyResolution: (assemblyEvidence && assemblyEvidence.proxyResolution) || null,
    contractIdentity: (assemblyEvidence && assemblyEvidence.contractIdentity) || null,
    deadlineAnalysis: (assemblyEvidence && assemblyEvidence.deadlineAnalysis) || null,
    semanticClaims: (assemblyEvidence && assemblyEvidence.semanticClaims) || null,
    sequenceHistory: (assemblyEvidence && assemblyEvidence.sequenceHistory) || null,
    visualRoleChecks: (assemblyEvidence && assemblyEvidence.visualRoleChecks) || null,
    effects: (assemblyEvidence && assemblyEvidence.effects) || null,
    composition: (assemblyEvidence && assemblyEvidence.composition) || null,
    bridge: (assemblyEvidence && assemblyEvidence.bridge) || null,
    approvalNecessity: (assemblyEvidence && assemblyEvidence.approvalNecessity) || null,
    explicitIntent: (assemblyEvidence && assemblyEvidence.explicitIntent) || null,
    subcalls: (() => {
      try {
        return require('./nestedCalls').buildSubcallTree(decodedTx);
      } catch {
        return { hasNested: false, subcalls: [], maxDepth: 0, unknownCount: 0, depthLimitedCount: 0 };
      }
    })(),
    supportValidation: (assemblyEvidence && assemblyEvidence.supportValidation) || null,
    reconciliation: (assemblyEvidence && assemblyEvidence.reconciliation) || null,
    agentEvidence: (assemblyEvidence && assemblyEvidence.agentEvidence) || null,
    evidenceGraph: (assemblyEvidence && assemblyEvidence.evidenceGraph) || null,
    simulation: simulationResult || {
      status: 'NOT_RUN',
      executed: false,
      success: false,
      reason: 'No simulation required for low-risk verdict.'
    }
  };
}

module.exports = { compileEvidenceBundle, prepareComparisonInputs, MANDATORY_SAFETY_NOTICE };
