/**
 * Visual Sentry Evaluation Controller
 * Orchestrates SAM 3.1 perception, OCR, EVM calldata decoding, Muse Spark reasoning, and Foundry simulation.
 */

const { segmentUiRegions, SUMMARY_PROMPT } = require('../services/samService');
const { selectSummaryText } = require('../utils/summary');
const { extractUiTexts } = require('../services/ocrService');
const { screenshotMeta } = require('../utils/imageUtils');
const { decodeTransactionCalldata, DECODE_INVALID_VALUE, DECODE_INVALID_DATA } = require('../services/decoderService');
const { evaluateSemanticDiscrepancy } = require('../services/reasonerService');
const { simulateTransactionWithFoundry } = require('../services/simulatorService');
const { compileEvidenceBundle, prepareComparisonInputs } = require('../services/evidenceService');
const { findingActionFor, composePolicyDecision } = require('../services/policyDecision');
const crypto = require('crypto');
// Single canonicalization implementation shared with the extension (which
// loads the same file via manifest/importScripts). The backend hashes the
// canonical bytes with Node's vetted crypto; the extension uses the
// file's verified-identical SHA-256 (cross-checked in txBinding tests).
const { canonicalizeTx, isValidDigest } = require('../../extension/shared/txDigest');
const { buildIntentComparison } = require('../services/intentComparisonAdapter');
const { assessVisualConfidenceCap, ZERO_VISUAL_CAP } = require('../utils/visualConfidence');
const appConfig = require('../config/env');
const { fetchChainState } = require('../services/chainStateService');
const { evaluateFreshness } = require('../services/evidenceFreshness');
const { loadCounterpartyLabels, resolveCounterparties } = require('../services/counterpartyLabels');
const { associateRegions } = require('../utils/association');
const telemetry = require('../services/investigationTelemetry');

const MAX_CLIENT_TEXT_CHARS = 8000;
const PAGE_CONTEXT_FIELDS = ['title', 'url', 'visibleText'];

/**
 * Merge the canonical `pageContext` object with the legacy/client-facing
 * `page` object into one internal representation. `pageContext` wins on
 * overlapping fields; valid fields present only in `page` are preserved.
 * Empty strings are treated as absent. Throws on malformed context.
 */
function normalizePageContext(pageContext, page) {
  for (const [name, obj] of [['pageContext', pageContext], ['page', page]]) {
    if (obj === undefined || obj === null) continue;
    if (typeof obj !== 'object' || Array.isArray(obj)) {
      throw new Error(`${name} must be an object with optional title, url, visibleText.`);
    }
  }
  const merged = {};
  for (const source of [page, pageContext]) {
    if (!source) continue;
    for (const key of PAGE_CONTEXT_FIELDS) {
      const value = source[key];
      if (value === undefined || value === null) continue;
      if (typeof value !== 'string') {
        throw new Error(`page context field "${key}" must be a string.`);
      }
      const trimmed = value.trim();
      if (!trimmed) continue;
      merged[key] = key === 'visibleText' ? trimmed.slice(0, MAX_CLIENT_TEXT_CHARS) : trimmed;
    }
  }
  return merged;
}

const CANONICAL_VERDICTS = { MATCH: 'MATCH', MISMATCH: 'MISMATCH', UNCERTAIN: 'UNCERTAIN' };

/**
 * Ordered verdict-safeguard pipeline. Runs after model/heuristic reasoning:
 *  1. INVALID_VERDICT — non-enum model verdicts coerce to UNCERTAIN.
 *  2. DETERMINISTIC_BLOCK — MATCH co-present with a mandatory
 *     deterministic block finding downgrades to UNCERTAIN. The final
 *     BLOCK itself is issued by the policy decision composer; this stage
 *     keeps the legacy verdict from standing as MATCH alongside it.
 *  3. SWAP_RECIPIENT_DIFFERS_FROM_SENDER — MATCH with an unresolved
 *     recipient discrepancy downgrades to UNCERTAIN.
 *  4. UNKNOWN_FUNCTION — MATCH on undecodable calldata downgrades to
 *     UNCERTAIN.
 *  5. DETERMINISTIC_COMPARISON_MISMATCH — MATCH with a corroborated
 *     field-level conflict between displayed intent and decoded facts
 *     downgrades to UNCERTAIN. INCONCLUSIVE fields, missing results, and
 *     adapter errors never trigger.
 *  6. FABRICATED_EVIDENCE_REFERENCE — MATCH whose investigation cites
 *     evidence that was never supplied downgrades to UNCERTAIN. A
 *     response that invents its own evidence cannot carry a MATCH.
 *  7. SIM_EXECUTION_CONTRADICTION — MATCH contradicted by measured
 *     simulation (revert, unexpected allowance) downgrades to UNCERTAIN.
 *     FAILED/FALLBACK/NOT_RUN sims never trigger: no measured execution
 *     means nothing to contradict.
 *  8. CHAIN_VERIFICATION_FAILED — MATCH co-present with a failed
 *     deterministic chain/freshness check downgrades to UNCERTAIN.
 *     Inconclusive/unavailable checks never trigger: missing state must
 *     not veto, only inform.
 *  9. RECONCILIATION_DOWNGRADE — MATCH that mechanism reconciliation
 *     rejects (citation-support fabrication, stale-only visual support)
 *     downgrades to UNCERTAIN under the specific rule recorded.
 * Every triggered safeguard appends to `safeguards` in order; nothing is
 * overwritten. The bundle exposes the full list plus the first entry as the
 * legacy `verdictSafeguard` object. Safe-direction verdicts (MISMATCH,
 * UNCERTAIN) pass through untouched and record nothing. Downgrade stages
 * all evaluate against the normalized verdict, so co-present risks each
 * record; the downgrade itself (verdict + cap) is idempotent while every
 * disclosure is kept.
 */
function applyVerdictSafeguards(decodedTx, reasoningResult, intentComparison = null) {
  const safeguards = [];
  let out = reasoningResult;
  const downgrade = (record, summarySuffix) => {
    safeguards.push(record);
    out = {
      ...out,
      verdict: 'UNCERTAIN',
      confidence: Math.min(typeof out.confidence === 'number' ? out.confidence : 0.65, 0.65),
      summary: `${out.summary || ''} ${summarySuffix}`.trim()
    };
  };

  // Stage 1 — verdict normalization: the model occasionally returns
  // non-enum strings (observed live: 'deceptive'). Canonicalize
  // case-insensitively; anything else becomes UNCERTAIN so an invalid
  // verdict can never pass through or bypass the safeguards below.
  const rawVerdict = typeof out.verdict === 'string' ? out.verdict.trim() : '';
  const canonical = CANONICAL_VERDICTS[rawVerdict.toUpperCase()] || null;
  if (!canonical) {
    downgrade(
      {
        trigger: 'INVALID_VERDICT',
        from: rawVerdict || '(missing)',
        to: 'UNCERTAIN',
        reason: `Model returned unrecognized verdict ${JSON.stringify(rawVerdict)}; treated as UNCERTAIN.`
      },
      `[Verdict normalized: unrecognized model verdict ${JSON.stringify(rawVerdict)} treated as UNCERTAIN.]`
    );
  } else if (canonical !== out.verdict) {
    // Compare against the untrimmed verdict so whitespace-padded variants
    // (' MATCH ') also normalize — otherwise they evade MATCH-equality
    // checks in the stages below.
    out = { ...out, verdict: canonical };
  }
  const matchCandidate = out.verdict === 'MATCH';

  // Stage 2 — deterministic block: a model MATCH must not stand while a
  // mandatory deterministic block finding is present. The authoritative
  // BLOCK is issued by composePolicyDecision; this stage only keeps the
  // legacy verdict honest. Safe-direction verdicts pass through untouched.
  const blockingFindings = (decodedTx.ruleFindings || [])
    .filter((r) => r && findingActionFor(r.ruleId) === 'BLOCK')
    .map((r) => r.ruleId);
  if (blockingFindings.length > 0 && matchCandidate) {
    downgrade(
      {
        trigger: 'DETERMINISTIC_BLOCK',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Mandatory deterministic block finding present (${blockingFindings.join(', ')}); MATCH downgraded pending policy decision.`
      },
      `[Verdict safeguard: MATCH downgraded to UNCERTAIN — mandatory deterministic block: ${blockingFindings.join(', ')}.]`
    );
  }

  // Stage 3 — recipient risk: a model MATCH must not stand while a
  // deterministic recipient discrepancy is unresolved. Downgrade to
  // UNCERTAIN — never auto-MISMATCH, since pay-to-other can be legitimate.
  const recipientRisk = (decodedTx.ruleFindings || []).find((r) => r.ruleId === 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER');
  if (recipientRisk && matchCandidate) {
    downgrade(
      {
        trigger: recipientRisk.ruleId,
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: 'Model returned MATCH while swap recipient differs from sender; downgraded pending recipient verification.'
      },
      `[Verdict safeguard: MATCH downgraded to UNCERTAIN — swap recipient ${recipientRisk.metadata.recipient} differs from sender ${recipientRisk.metadata.sender}.]`
    );
  }

  // Stage 4 — unknown function: a MATCH must not stand when the calldata
  // could not be decoded — there are no verified transaction facts for the
  // model to have matched against. Downgrade to UNCERTAIN; MISMATCH and
  // UNCERTAIN already err safe and pass through untouched. (Plain native
  // transfers decode as nativeTransfer/Native, never unknownFunction, so
  // they are unaffected by this stage.)
  const isUnknownTx = decodedTx.functionName === 'unknownFunction' || decodedTx.standard === 'Unknown';
  if (isUnknownTx && matchCandidate) {
    const selector = decodedTx.parameters && decodedTx.parameters.selector;
    const where = selector ? ` (selector ${selector})` : '';
    downgrade(
      {
        trigger: 'UNKNOWN_FUNCTION',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Model returned MATCH for a transaction whose function could not be decoded${where}; downgraded pending identification.`
      },
      `[Verdict safeguard: MATCH downgraded to UNCERTAIN — transaction function could not be decoded${where}.]`
    );
  }

  // Stage 5 — deterministic comparison: a MATCH must not stand while
  // corroborated UI evidence conflicts with decoded transaction facts on
  // any compared field. Downgrade to UNCERTAIN, following the same
  // MATCH-downgrade-only convention as the stages above. Only explicit
  // field-level MISMATCH triggers; INCONCLUSIVE fields, a missing result,
  // and adapter ERROR records never do. Capability 5 B3: effect:*
  // fields are owned by stage 16 with effect-specific triggers, so
  // stage 5 excludes them rather than double-reporting one cause.
  const mismatchedFields = Array.isArray(intentComparison?.fields)
    ? intentComparison.fields.filter((f) => f && f.status === 'MISMATCH' && !String(f.field || '').startsWith('effect:')).map((f) => f.field)
    : [];
  if (mismatchedFields.length > 0 && matchCandidate) {
    downgrade(
      {
        trigger: 'DETERMINISTIC_COMPARISON_MISMATCH',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Deterministic comparison found conflicting evidence on: ${mismatchedFields.join(', ')}; downgraded pending review.`
      },
      `[Verdict safeguard: MATCH downgraded to UNCERTAIN — deterministic comparison mismatch on ${mismatchedFields.join(', ')}.]`
    );
  }

  // Capability 2, stage 6: fabricated evidence references. Citing
  // evidence that was never supplied is a positively dishonest
  // investigation: the MATCH cannot stand. Missing citations are
  // quality flags for review escalation, not fabrication.
  const fabricatedRefs = Array.isArray(out.referenceValidation?.fabricated)
    ? out.referenceValidation.fabricated
    : [];
  if (fabricatedRefs.length > 0 && matchCandidate) {
    const shown = fabricatedRefs.slice(0, 3).map((f) => `${f.where || '?'} -> ${f.ref || '?'}`).join('; ');
    downgrade(
      {
        trigger: 'FABRICATED_EVIDENCE_REFERENCE',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Model cited ${fabricatedRefs.length} evidence reference(s) never supplied (${shown}); downgraded pending review.`
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — fabricated evidence reference(s) in the investigation.]'
    );
  }

  // Capability 3 B2, stage 7: measured simulation contradicts MATCH.
  // Reads the pre-reasoning reconciliation riding the result; post-
  // reasoning sims only ever accompany already-held verdicts.
  const simRec = out.simReconciliation;
  if (simRec && simRec.downgrade === true && matchCandidate) {
    downgrade(
      {
        trigger: simRec.rule || 'SIM_EXECUTION_CONTRADICTION',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Measured simulation contradicts the MATCH verdict: ${simRec.reason || 'see simReconciliation'}.`
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — measured simulation contradicts the verdict.]'
    );
  }

  // Capability 3 B3, stage 8: failed deterministic chain/freshness
  // checks. Only hard failures trigger; inconclusive and unavailable
  // results inform the prompt and bundle but never move the verdict.
  const chainFails = Array.isArray(out.chainVerification?.failures) ? out.chainVerification.failures : [];
  if (chainFails.length > 0 && matchCandidate) {
    const ids = chainFails.map((f) => f.checkId || '?').join(', ');
    downgrade(
      {
        trigger: 'CHAIN_VERIFICATION_FAILED',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Deterministic chain verification failed (${ids}); MATCH downgraded pending review.`
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — deterministic chain verification failed.]'
    );
  }

  // Capability 3 B4, stage 9: mechanism reconciliation rejects MATCH.
  const recon = out.reconciliation;
  if (recon && recon.downgrade === true && matchCandidate) {
    downgrade(
      {
        trigger: recon.downgradeRule || 'RECONCILIATION_DOWNGRADE',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Mechanism reconciliation rejects the MATCH verdict: ${recon.downgradeReason || 'see reconciliation'}.`
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — mechanism reconciliation rejects the verdict.]'
    );
  }

  // Capability 4 B1, stage 10: unresolved proxy implementation. A MATCH
  // must not stand while the target is a confirmed proxy whose behavior
  // cannot be established (unreadable or dangling implementation).
  // Unknown/unavailable reads never trigger: only a confirmed proxy
  // with a failed resolution moves the verdict.
  const proxyRes = out.proxyResolution;
  if (proxyRes && proxyRes.downgrade === true && matchCandidate) {
    downgrade(
      {
        trigger: 'UNRESOLVED_PROXY_IMPLEMENTATION',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Target is a proxy whose implementation could not be resolved: ${proxyRes.explanation || 'see proxyResolution'}.`
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — proxy implementation unresolved.]'
    );
  }

  // Capability 4 B3, stage 11: missing value protection. A MATCH must
  // not stand while the swap's enforced floor is zero or unestablished:
  // a displayed quote the transaction does not enforce is a major
  // verified discrepancy, not a routine parameter. The finding (not the
  // model's leniency) decides.
  const valueRisk = (decodedTx.ruleFindings || [])
    .find((r) => r && (r.ruleId === 'ZERO_MINIMUM_OUTPUT' || r.ruleId === 'MISSING_OUTPUT_PROTECTION'));
  if (valueRisk && matchCandidate) {
    downgrade(
      {
        trigger: valueRisk.ruleId,
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Model returned MATCH while swap output protection is ${valueRisk.ruleId === 'ZERO_MINIMUM_OUTPUT' ? 'zero (amountOutMinimum = 0)' : 'unestablished'}; downgraded pending review.`
      },
      `[Verdict safeguard: MATCH downgraded to UNCERTAIN — swap output protection ${valueRisk.ruleId === 'ZERO_MINIMUM_OUTPUT' ? 'is zero' : 'cannot be established'}.]`
    );
  }

  // Capability 4 B4, stage 12: uninterpretable nested calls. A MATCH
  // must not stand while a batch contains inner operations whose
  // behavior cannot be established — they may conceal asset movement
  // or approvals the top-level function name does not disclose.
  const innerRisk = (decodedTx.ruleFindings || [])
    .find((r) => r && r.ruleId === 'UNKNOWN_INNER_CALL');
  if (innerRisk && matchCandidate) {
    downgrade(
      {
        trigger: innerRisk.ruleId,
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: 'Model returned MATCH while the batch contains uninterpretable inner call(s); downgraded pending review.'
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — uninterpretable nested call(s) in the batch.]'
    );
  }

  // Capability 4 B6, stage 13: expired or deadline-less operations. A
  // MATCH must not stand while the operation demonstrably reverts
  // (expired past grace) or its time-sensitivity cannot be assessed
  // (expected deadline missing).
  const deadlineRisk = (decodedTx.ruleFindings || [])
    .find((r) => r && (r.ruleId === 'EXPIRED_OPERATION' || r.ruleId === 'MISSING_DEADLINE'));
  if (deadlineRisk && matchCandidate) {
    downgrade(
      {
        trigger: deadlineRisk.ruleId,
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Model returned MATCH while the operation is ${deadlineRisk.ruleId === 'EXPIRED_OPERATION' ? 'expired (submitting it reverts)' : 'missing its expected deadline (expiry unassessable)'}; downgraded pending review.`
      },
      `[Verdict safeguard: MATCH downgraded to UNCERTAIN — operation ${deadlineRisk.ruleId === 'EXPIRED_OPERATION' ? 'expired' : 'missing expected deadline'}.]`
    );
  }

  // Capability 4 B7, stage 14: contradicted semantic claims. A MATCH
  // must not stand while the model's own checkable assertions disagree
  // with verified evidence — the verdict's reasoning is unreliable.
  const semClaims = out.semanticClaims;
  if (semClaims && semClaims.summary && semClaims.summary.downgrade === true && matchCandidate) {
    const bad = (semClaims.claims || []).filter((c) => c && c.result === 'CONTRADICTED').slice(0, 3)
      .map((c) => `${c.claimId} ${c.target}`).join(', ');
    downgrade(
      {
        trigger: 'CONTRADICTED_SEMANTIC_CLAIM',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Model returned MATCH while its checkable claims contradict verified evidence (${bad || 'see semanticClaims'}); downgraded pending review.`
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — model claims contradict verified evidence.]'
    );
  }

  // Capability 4 B10, stage 15: refuted visual roles. A MATCH must
  // not stand while the model's own visual assertions concretely
  // contradict observed OCR (phantom addresses/digits) — the verdict's
  // visual reading is unreliable. INCONCLUSIVE roles never trigger.
  const roleChecks = out.visualRoleChecks;
  if (roleChecks && roleChecks.summary && roleChecks.summary.downgrade === true && matchCandidate) {
    const bad = (roleChecks.checks || []).filter((c) => c && c.result === 'REFUTED').slice(0, 3)
      .map((c) => `claim#${c.claimIndex} ${c.claimType}`).join(', ');
    downgrade(
      {
        trigger: 'REFUTED_VISUAL_ROLE',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Model returned MATCH while its visual assertions contradict observed evidence (${bad || 'see visualRoleChecks'}); downgraded pending review.`
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — model visual claims contradict observed evidence.]'
    );
  }

  // Capability 5 B3, stage 16: requested-vs-actual effect coverage. A
  // MATCH must not stand while the transaction carries effects no
  // corroborated request element covers, or leaves a corroborated
  // requested element uncarried. Stage 5 excludes effect:* fields, so
  // this stage is the sole owner of effect-level mismatch attribution.
  const cov = intentComparison && typeof intentComparison.effectCoverage === 'object'
    ? intentComparison.effectCoverage
    : null;
  const unrequested = cov && Array.isArray(cov.unrequested) ? cov.unrequested : [];
  const missing = cov && Array.isArray(cov.missing) ? cov.missing : [];
  if ((unrequested.length > 0 || missing.length > 0) && matchCandidate) {
    const shown = [...unrequested, ...missing].slice(0, 4).join(', ');
    downgrade(
      {
        trigger: unrequested.length > 0 ? 'UNREQUESTED_TRANSACTION_EFFECT' : 'MISSING_REQUESTED_EFFECT',
        from: 'MATCH',
        to: 'UNCERTAIN',
        reason: `Model returned MATCH while effect coverage disagrees (${shown || 'see effectCoverage'}); downgraded pending review.`
      },
      '[Verdict safeguard: MATCH downgraded to UNCERTAIN — requested-vs-actual effect coverage disagrees.]'
    );
  }

  return { reasoningResult: out, safeguards };
}

async function handleEvaluateTransaction(req, res, internal = null) {
  try {
    // `internal` carries in-process-only evidence (agent path chain state).
    // It is a function argument, never a request field: HTTP bodies cannot
    // supply it, so remote callers can never forge it.
    const receivedAt = Date.now();
    let preAssociations = null;
    let preActionElements = null;
    let samStatusForEvidence = null;
    // Capability 2: investigation-specific reasoning. The agent path marks
    // itself via the in-process internal arg (never a request field); the
    // default browser path is unchanged.
    const investigationType = internal && internal.investigationType === 'agent' ? 'agent' : 'browser';
    // Telemetry is owned by the trace creator (agent propose / scenario
    // runner); this controller only records spans, never finishes traces.
    const trace = internal && internal.trace ? internal.trace : null;
    const { screenshot, pageContext, page, transaction, txDigest: claimedTxDigest } = req.body || {};

    if (!transaction || !transaction.to) {
      return res.status(400).json({
        error: 'Invalid request: transaction object with "to" address is required.'
      });
    }

    let normalizedPageContext;
    try {
      normalizedPageContext = normalizePageContext(pageContext, page);
    } catch (err) {
      return res.status(400).json({
        error: `Invalid request: ${err.message}`
      });
    }

    // Step 1: Deterministic EVM calldata decoding. The sender is threaded
    // through (when supplied; the schema does not require it) so
    // recipient-relative rules can compare against a validated address.
    // Malformed transaction values, addresses, and calldata are client
    // errors (400), matching the page-context validation convention above
    // — never an internal 500.
    let decodedTx;
    const decodeSpan = telemetry.startSpan(trace, 'decoder', String(transaction.to || '').slice(0, 42));
    try {
      decodedTx = decodeTransactionCalldata({
        to: transaction.to,
        data: transaction.data || '0x',
        value: transaction.value || '0x0',
        from: transaction.from,
        // Capability 4 B5: chain context scopes static token/router
        // identity — mainnet labels never apply to other chains.
        chainId: transaction.chainId ?? null
      });
      if (decodeSpan) decodeSpan.finish(`${decodedTx.contractName || 'unknown'}.${decodedTx.functionName} (${decodedTx.standard || 'no-standard'})`, { functionName: decodedTx.functionName, standard: decodedTx.standard || null, findings: (decodedTx.ruleFindings || []).map((f) => f.ruleId) });
    } catch (err) {
      if (decodeSpan) decodeSpan.fail(err.message);
      if (err && (err.code === DECODE_INVALID_VALUE || err.code === DECODE_INVALID_DATA)) {
        return res.status(400).json({
          error: `Invalid request: ${err.message}`
        });
      }
      throw err;
    }

    // Payload binding: digest of the exact transaction bytes evaluated,
    // canonicalized with the same rules the extension uses. Compared
    // against the caller-claimed digest; match is tri-state (true/false/
    // null when not comparable). A null evaluated digest means the
    // payload could not be faithfully represented — never approved.
    let evaluatedTxDigest = null;
    try {
      const canonical = canonicalizeTx(transaction);
      if (canonical !== null) {
        evaluatedTxDigest = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
        if (!isValidDigest(evaluatedTxDigest)) evaluatedTxDigest = null;
      }
    } catch {
      evaluatedTxDigest = null;
    }
    const receivedTxDigest = isValidDigest(claimedTxDigest) ? claimedTxDigest : null;
    const txBinding = {
      receivedTxDigest,
      evaluatedTxDigest,
      match: receivedTxDigest !== null && evaluatedTxDigest !== null
        ? receivedTxDigest === evaluatedTxDigest
        : null
    };

    // Step 2: Meta SAM 3.1 Region Segmentation (if screenshot provided).
    // Phase 1: `regions` carries GENUINE detections only. The synthetic
    // fallback (if any) is OCR'd separately and labeled synthetic; it never
    // enters regionTexts and never counts as a detection.
    // Phase 2: per-region OCR records (id/geometry/text/error) flow through.
    // Phase 3: screenshot dimensions are established FIRST so the fallback
    // scan covers the true full image; unknown dims mean no runnable scan.
    let visualResult = { regions: [], combinedText: '', detectedCount: 0, visualAvailable: false };
    let intentText = '';
    let intentSource = 'full-scan (no screenshot supplied)';
    if (screenshot) {
      const meta = await telemetry.timed(trace, 'sam', 'screenshot dimensions', () => screenshotMeta(screenshot));
      const dims = meta && !meta.error && Number.isInteger(meta.width) && Number.isInteger(meta.height)
        ? { width: meta.width, height: meta.height }
        : null;
      // startSpan/finish mirrors telemetry.timed exactly (same lifecycle),
      // with room for a small provenance extra on the finished span.
      const samSpan = telemetry.startSpan(trace, 'sam', 'segment regions');
      let samResult;
      try {
        samResult = await segmentUiRegions(screenshot, undefined, { dims });
      } catch (err) {
        if (samSpan) samSpan.fail(err);
        throw err;
      }
      if (samSpan) samSpan.finish(
        `${(samResult.regions || []).length} regions, mode=${samResult.mode || 'unknown'}${samResult.error ? `, error=${samResult.error}` : ''}`,
        {
          model: samResult.samModelConfigured || null, mode: samResult.mode || null, status: samResult.status || null,
          invokedAt: samResult.invokedAt ?? null, completedAt: samResult.completedAt ?? null,
          responseId: samResult.responseId || null, outputDigest: samResult.outputDigest || null,
          detectedCount: Number.isInteger(samResult.detectedCount) ? samResult.detectedCount : null
        }
      );
      const genuine = (samResult.regions || []).filter((r) => r.genuine !== false);
      const detectedCount = Number.isInteger(samResult.detectedCount) ? samResult.detectedCount : genuine.length;

      // Step 3: OCR on genuine regions; fallback scan only when none exist.
      // Per-region failures are recorded, never thrown: one bad crop must
      // not block the remaining regions.
      const ocrResult = await telemetry.timed(trace, 'ocr', `${genuine.length} genuine regions`, () => extractUiTexts(screenshot, genuine),
        (r) => `${(r.regionTexts || []).length} texts, ${r.combinedText ? r.combinedText.length : 0} chars`);
      let fallbackRecords = [];
      let fallbackCombined = '';
      let fallbackUsed = false;
      const fbDef = samResult.fallback || null;
      if (genuine.length === 0 && fbDef && fbDef.region) {
        const fb = await extractUiTexts(screenshot, [fbDef.region]);
        fallbackRecords = fb.regionTexts;
        fallbackCombined = fb.combinedText;
        fallbackUsed = true;
      }
      const combinedText = ocrResult.combinedText || fallbackCombined;

      // Phase 3: transaction-summary isolation. The primary intent text
      // comes from summary-prompt regions when they yield usable text;
      // otherwise the full scan is used and labeled as such. Both texts
      // stay in the bundle; nothing is silently substituted.
      const ocrById = new Map((ocrResult.regionTexts || []).filter((r) => r && r.regionId).map((r) => [r.regionId, r]));
      const joined = genuine.map((g, i) => {
        const rec = ocrById.get(g.regionId) || ocrResult.regionTexts[i] || {};
        return {
          regionId: g.regionId,
          prompts: g.prompts || [],
          boundingBox: g.boundingBox,
          genuine: g.genuine,
          ocr: {
            text: typeof rec.text === 'string' ? rec.text : null,
            empty: rec.empty === true,
            error: rec.ocrError || rec.error || null
          }
        };
      });
      try {
        const dims = meta && !meta.error ? { width: meta.width, height: meta.height } : null;
        const assoc = telemetry.timed(trace, 'visual-association', `${joined.length} regions`, () => associateRegions(joined, dims ? { dims } : {}),
          (a) => `links=${(a.links || []).length} ambiguities=${(a.ambiguities || []).length}`);
        preAssociations = {
          links: (assoc.links || []).slice(0, 25),
          ambiguities: (assoc.ambiguities || []).slice(0, 10)
        };
      } catch {
        preAssociations = null;
      }
      // Capability 4 B10: action-element triples (action text + observed
      // container + linked amount/recipient) for the pre-model pack. A
      // builder failure degrades to null — never half an element list.
      try {
        // eslint-disable-next-line global-require
        const { buildActionElements } = require('../utils/visualRoles');
        preActionElements = buildActionElements({
          regions: joined,
          associations: preAssociations || { links: [] },
          decodedTx
        });
      } catch {
        preActionElements = null;
      }
      const summaryView = selectSummaryText(joined, { summaryPrompts: [SUMMARY_PROMPT] });
      const useSummary = (summaryView.status === 'targeted' || summaryView.status === 'ambiguous')
        && summaryView.text.length > 0;
      intentText = useSummary ? summaryView.text : combinedText;
      intentSource = useSummary
        ? `transaction-summary (${summaryView.status}: ${summaryView.regionIds.join(', ')})`
        : 'full-scan (no isolated summary)';
      samStatusForEvidence = {
        mode: samResult.mode || 'unknown',
        promptsQueried: samResult.promptsQueried || [],
        perPrompt: samResult.perPrompt || [],
        partialFailure: samResult.partialFailure === true,
        incomplete: samResult.incomplete === true,
        error: samResult.error || null
      };
      visualResult = {
        regions: genuine,
        detectedCount,
        visualAvailable: detectedCount > 0,
        fallbackUsed,
        fallbackReason: fbDef ? fbDef.reason : null,
        fallbackRegion: (fbDef && fbDef.region) || null,
        combinedText,
        combinedTextSynthetic: ocrResult.combinedText ? false : fallbackUsed,
        regionTexts: ocrResult.regionTexts,
        fallbackRecords,
        summaryText: { ...summaryView, usedForIntent: useSummary },
        intentText,
        intentSource,
        screenshot: meta && !meta.error ? meta : null,
        screenshotError: (meta && meta.error) || null,
        samMode: samResult.mode || 'unknown',
        samStatus: samResult.status || null,
        samModelConfigured: samResult.samModelConfigured || null,
        samModelObserved: samResult.samModelObserved || null,
        samSubmittedImageDigest: samResult.submittedImageDigest || null,
        samInvokedAt: samResult.invokedAt ?? null,
        samCompletedAt: samResult.completedAt ?? null,
        samResponseId: samResult.responseId || null,
        samUsage: samResult.usage || null,
        samOutputDigest: samResult.outputDigest || null,
        samSuccess: samResult.success !== false,
        samError: samResult.error || null,
        partialFailure: samResult.partialFailure === true,
        incomplete: samResult.incomplete === true,
        samPromptResults: samResult.perPrompt || []
      };
    }

    // Phase B assembly: chain state, freshness, identity hints, and the
    // pre-reasoning association/summary/SAM status. Every gather step is
    // infallible by contract (misses become explicit statuses); nothing
    // here can throw the evaluation into a 500 or silently degrade it.
    const txContext = {
      from: typeof transaction.from === 'string' ? transaction.from : null,
      chainId: transaction.chainId ?? null
    };
    let chainState;
    if (internal && internal.chainState && typeof internal.chainState === 'object') {
      chainState = internal.chainState;
      const injSpan = telemetry.startSpan(trace, 'chainstate', 'injected chain state (agent mandate RPC)');
      if (injSpan) injSpan.finish(`status=${chainState.status || 'unknown'}`);
    } else {
      try {
        const query = [{ role: 'target', address: transaction.to }];
        if (typeof transaction.from === 'string') query.push({ role: 'sender', address: transaction.from });
        chainState = await telemetry.timed(trace, 'chainstate', 'evidence RPC (browser path)', () => fetchChainState({
          rpcUrl: appConfig.evidenceChainRpcUrl,
          chainId: txContext.chainId,
          addresses: query,
          timeoutMs: appConfig.evidenceChainTimeoutMs
        }), (s) => `status=${s && s.status ? s.status : 'unknown'}`);
      } catch (err) {
        chainState = { status: 'rpc-error', error: String((err && err.message) || err).slice(0, 200), fetchedAt: Date.now() };
      }
    }
    const isAgentPath = normalizedPageContext && normalizedPageContext.url === 'agent:proposal';
    const freshness = isAgentPath
      ? { note: 'agent proposal: transaction evidence assembled at investigation time (current by construction); no screenshot' }
      : {
        screenshot: telemetry.timed(trace, 'freshness', '', () => evaluateFreshness({
          capturedAt: req.body ? req.body.capturedAt : undefined,
          receivedAt,
          maxAgeMs: appConfig.screenshotMaxAgeMs
        }), (f) => `screenshot=${f && f.status ? f.status : 'unknown'}`)
      };
    if (isAgentPath) {
      const fSpan = telemetry.startSpan(trace, 'freshness', 'agent path');
      if (fSpan) fSpan.finish('current by construction; no screenshot to age');
    }
    if (!screenshot) {
      telemetry.markSkipped(trace, 'sam', 'no screenshot supplied on this path');
      telemetry.markSkipped(trace, 'ocr', 'no screenshot supplied on this path');
      telemetry.markSkipped(trace, 'visual-association', 'no regions without a screenshot');
    }
    const labelLoad = loadCounterpartyLabels(appConfig.counterpartyLabelsFile);
    const labelCandidates = [transaction.to, transaction.from];
    for (const key of ['spender', 'operator', 'recipient']) {
      if (decodedTx.parameters && typeof decodedTx.parameters[key] === 'string') labelCandidates.push(decodedTx.parameters[key]);
    }
    for (const f of decodedTx.ruleFindings || []) {
      if (f && f.metadata && typeof f.metadata === 'object') {
        for (const v of Object.values(f.metadata)) {
          if (typeof v === 'string') labelCandidates.push(v);
        }
      }
    }
    const counterpartyLabels = telemetry.timed(trace, 'counterparty-labels', `${labelCandidates.length} candidates`, () => ({
      labels: resolveCounterparties(labelCandidates, labelLoad.ok ? labelLoad.labels : {}),
      labelsError: labelLoad.ok ? null : labelLoad.error,
      labelsSkipped: labelLoad.skipped || []
    }), (c) => `labels=${(c.labels || []).length}${c.labelsError ? ` error=${c.labelsError}` : ''}`);
    const summaryStatus = visualResult.summaryText && typeof visualResult.summaryText === 'object'
      ? { status: visualResult.summaryText.status || null, regionIds: visualResult.summaryText.regionIds || [], reason: visualResult.summaryText.reason || null }
      : null;

    // Capability 3 B2: simulation BEFORE reasoning when deterministic
    // triggers fire, so measured execution can inform the investigator.
    // Infallible by contract: a sim failure becomes a FAILED record,
    // never a 500 and never silent.
    const { shouldSimulatePreReasoning, runSimulationEvidence, notRunEvidence, reconcileSimulation } = require('../services/simulationEvidence');
    let simulationEvidence = notRunEvidence();
    let simulationRaw = null;
    let simRan = false;
    if (shouldSimulatePreReasoning(decodedTx)) {
      const simSpan = telemetry.startSpan(trace, 'simulation-pre', decodedTx.functionName);
      try {
        const ran = await runSimulationEvidence({ transaction, decodedTx });
        simulationEvidence = ran.evidence;
        simulationRaw = ran.raw;
        simRan = true;
        if (simSpan) simSpan.finish(`status=${ran.evidence.status} executed=${ran.evidence.executed === true}`);
      } catch (err) {
        simulationEvidence = {
          simId: 'SIM-001', status: 'FAILED', executed: false, success: null,
          escalationDetected: false, error: String((err && err.message) || err).slice(0, 300),
          reason: 'Simulation harness threw; treated as failed, not as evidence.',
          mode: 'failed', measuredNote: 'nothing measured'
        };
        simRan = true;
        if (simSpan) simSpan.fail('harness threw; recorded as FAILED, not as evidence');
      }
    } else {
      telemetry.markSkipped(trace, 'simulation-pre', 'no deterministic pre-reasoning trigger fired');
    }
    const preSimReconciliation = simRan ? reconcileSimulation({ sim: simulationEvidence, decodedTx }) : null;

    // Capability 3 B6: agent-submitted evidence arrives via the
    // in-process internal arg (admitted upstream), never the request.
    const agentEvidenceInternal = internal && internal.agentEvidence && typeof internal.agentEvidence === 'object'
      ? internal.agentEvidence : { admitted: [], rejected: [] };

    // Capability 3 B3: deterministic chain/freshness verification runs
    // pre-reasoning so its results inform the prompt, the safeguards,
    // and the policy holds below.
    const { verifyChainEvidence } = require('../services/chainVerification');
    const chainVerification = telemetry.timed(trace, 'chain-verification', '', () => verifyChainEvidence({
      transaction,
      decodedTx,
      chainState,
      freshness,
      visualMeta: {
        detectedCount: visualResult.detectedCount || 0,
        regionTexts: visualResult.regionTexts || []
      }
    }), (v) => `checks=${(v.checks || []).length} failures=${(v.failures || []).length}`);

    // Capability 4 B1: proxy detection/resolution runs pre-reasoning so
    // the investigator learns whether behavior comes from the target or
    // a separate implementation. Infallible by contract: transport
    // failures become explicit unknown/unavailable statuses, and plain
    // native transfers skip the RPC round trip (no contract to resolve).
    const { fetchProxyEvidence } = require('../services/proxyResolution');
    let proxyResolution;
    if (internal && internal.proxyResolution && typeof internal.proxyResolution === 'object') {
      proxyResolution = internal.proxyResolution;
      const injSpan = telemetry.startSpan(trace, 'proxy-resolution', 'injected');
      if (injSpan) injSpan.finish(`status=${proxyResolution.status || 'unknown'} (injected, no live resolution)`);
    } else if (decodedTx.functionName === 'nativeTransfer') {
      proxyResolution = {
        target: typeof transaction.to === 'string' ? transaction.to.toLowerCase() : null,
        status: 'skipped-native-transfer', isProxy: false, kind: null,
        implementation: null, beacon: null, downgrade: false, hold: null,
        explanation: 'Plain native transfer: no contract target to resolve as a proxy.'
      };
      telemetry.markSkipped(trace, 'proxy-resolution', 'plain native transfer: no contract target to resolve');
    } else {
      try {
        proxyResolution = await telemetry.timed(trace, 'proxy-resolution', String(transaction.to || '').slice(0, 42), () => fetchProxyEvidence({
          rpcUrl: appConfig.evidenceChainRpcUrl,
          chainId: txContext.chainId,
          address: transaction.to,
          timeoutMs: appConfig.evidenceChainTimeoutMs
        }), (p) => `isProxy=${p.isProxy} status=${p.status}`);
      } catch (err) {
        proxyResolution = {
          target: typeof transaction.to === 'string' ? transaction.to.toLowerCase() : null,
          status: 'unknown', isProxy: null, kind: null, implementation: null,
          beacon: null, downgrade: false, hold: null,
          explanation: `Proxy resolution failed (${String((err && err.message) || err).slice(0, 200)}); proxy status unknown.`
        };
      }
    }

    // Capability 4 B5: contract identity verification assembles the
    // chain-aware verification ladder from static maps, code reads,
    // proxy evidence, bytecode refs, and directory lookups. Directory
    // lookups run only when they can add information (unknown selector
    // for 4byte; live code + known chain for Sourcify); every outcome
    // is an explicit status, and failures never break evaluation.
    const { resolveContractIdentity, lookupSelectorSignature, lookupSourceVerification, loadBytecodeRefs } = require('../services/contractIdentity');
    let contractIdentity;
    if (internal && internal.contractIdentity && typeof internal.contractIdentity === 'object') {
      contractIdentity = internal.contractIdentity;
      const injSpan = telemetry.startSpan(trace, 'contract-identity', 'injected');
      if (injSpan) injSpan.finish(`status=${contractIdentity.status || 'unknown'} (injected, no live identity work)`);
    } else {
      const identSpan = telemetry.startSpan(trace, 'contract-identity', String(transaction.to || '').slice(0, 42));
      try {
        const unknownSelector = decodedTx.functionName === 'unknownFunction'
          && decodedTx.parameters && typeof decodedTx.parameters.selector === 'string'
          ? decodedTx.parameters.selector : null;
        const targetCodeKnown = Boolean(
          (chainState && chainState.states && chainState.states.target && chainState.states.target.status === 'ok' && chainState.states.target.hasCode === true)
          || (typeof proxyResolution.targetCodeHash === 'string')
        );
        const [selectorSignature, sourceVerification] = await Promise.all([
          unknownSelector
            ? lookupSelectorSignature(unknownSelector, { timeoutMs: appConfig.selectorLookupTimeoutMs, enabled: appConfig.selectorLookupEnabled })
            : Promise.resolve(null),
          targetCodeKnown && txContext.chainId !== null && txContext.chainId !== undefined && txContext.chainId !== ''
            ? lookupSourceVerification(transaction.to, txContext.chainId, { timeoutMs: appConfig.sourcifyLookupTimeoutMs, enabled: appConfig.sourcifyLookupEnabled })
            : Promise.resolve({ status: 'skipped', match: null })
        ]);
        contractIdentity = resolveContractIdentity({
          address: transaction.to,
          chainId: txContext.chainId,
          decodedTx,
          chainState,
          proxyResolution,
          bytecodeRefs: loadBytecodeRefs(appConfig.contractBytecodeRefsFile),
          selectorSignature,
          sourceVerification
        });
        if (identSpan) identSpan.finish(`status=${contractIdentity.status || 'unknown'} (selector+sourcify lookups ran concurrently where eligible)`);
      } catch (err) {
        if (identSpan) identSpan.fail('identity assembly failed; identity unverified');
        contractIdentity = {
          target: typeof transaction.to === 'string' ? transaction.to.toLowerCase() : null,
          chainId: null, status: 'verification-unavailable',
          explanation: `Identity assembly failed (${String((err && err.message) || err).slice(0, 200)}); identity unverified.`,
          staticLabel: null, code: { present: null, codeHash: null, source: null }
        };
      }
    }

    // Capability 3 B7: deterministic relationship edges are built
    // pre-reasoning (associations, chain checks, pre-sim) so the model
    // sees and may cite them; model-derived edges merge post-reasoning.
    const { buildDeterministicEdges, buildModelDerivedEdges, assignEdgeIds, validateModelEdges } = require('../services/evidenceGraph');
    // Capability 4 B4: the subcall tree derives deterministically from
    // the decoded batch; the same pure derivation feeds the packer, the
    // bundle, the registry, and these edges, so SC-xxx IDs agree.
    const { buildSubcallTree } = require('../services/nestedCalls');
    let subcallTree;
    try {
      subcallTree = telemetry.timed(trace, 'subcalls', '', () => buildSubcallTree(decodedTx),
        (t) => `nested=${t.hasNested === true} subcalls=${(t.subcalls || []).length} unknown=${t.unknownCount || 0}`);
    } catch {
      subcallTree = { hasNested: false, subcalls: [], maxDepth: 0, unknownCount: 0, depthLimitedCount: 0 };
    }
    const preGraphEdges = telemetry.timed(trace, 'evidence-graph', 'deterministic edges (pre-reasoning)', () => assignEdgeIds(buildDeterministicEdges({
      associations: preAssociations,
      chainVerification,
      simReconciliation: preSimReconciliation,
      summaryStatus,
      subcalls: subcallTree,
      actionElements: preActionElements
    })), (e) => `${(e || []).length} deterministic edges`);

    // Capability 5 B2: deterministic effect reconstruction runs
    // pre-reasoning so the effect list reaches the model prompt, the
    // registry, the bundle, and persistence. A builder failure yields
    // null (effects unavailable), never a partial list.
    let effectReconstruction = null;
    try {
      const { reconstructEffects } = require('../services/effectReconstruction');
      effectReconstruction = telemetry.timed(trace, 'effects', '', () => reconstructEffects({
        tx: { from: txContext.from, to: decodedTx.contract, value: transaction.value },
        decodedTx,
        chainId: txContext.chainId
      }), (r) => `${((r && r.effects) || []).length} effects, opaque=${r ? r.opaqueCount : 0}`);
    } catch {
      // timed() already recorded the FAILED span; null means unavailable.
      effectReconstruction = null;
    }

    // Capability 5 B4: within-batch composition runs pre-reasoning on
    // the effect list so approve-then-spend and ordering findings
    // reach the model prompt, the bundle, and policy together with
    // decode-time findings. A builder failure yields null (composition
    // unavailable), never a partial analysis.
    let batchComposition = null;
    try {
      const { analyzeBatchComposition } = require('../utils/batchComposition');
      batchComposition = telemetry.timed(trace, 'composition', '', () => analyzeBatchComposition({ effects: effectReconstruction }),
        (c) => `findings=${((c && c.findings) || []).length}`);
      for (const f of (batchComposition.findings || [])) {
        if (f && typeof f === 'object' && f.ruleId) decodedTx.ruleFindings.push(f);
      }
    } catch {
      batchComposition = null;
    }

    // Capability 5 B5: bridge-deposit analysis runs pre-reasoning on
    // the decoded call so supported-route terms (or an explicit
    // unsupported verdict) reach the model prompt, the bundle, and
    // policy. Non-bridge transactions yield null and stay silent.
    let bridgeAnalysis = null;
    try {
      const { analyzeBridge } = require('../utils/bridgeAnalysis');
      bridgeAnalysis = telemetry.timed(trace, 'bridge', '', () => analyzeBridge({ decodedTx, chainId: txContext.chainId }),
        (b) => (!b ? 'not a bridge transaction' : `status=${b.status || 'unknown'}`));
      const bf = bridgeAnalysis && bridgeAnalysis.finding;
      if (bf && typeof bf === 'object' && bf.ruleId) decodedTx.ruleFindings.push(bf);
    } catch {
      bridgeAnalysis = null;
    }

    // Capability 5 B6: approval necessity/duration runs pre-reasoning
    // on the effect list so excess, persistence, and permit-duration
    // findings reach the model prompt, the bundle, and policy. A
    // builder failure yields null, never a partial analysis.
    let approvalNecessity = null;
    try {
      const { analyzeApprovalNecessity } = require('../utils/approvalNecessity');
      approvalNecessity = telemetry.timed(trace, 'approval-necessity', '', () => analyzeApprovalNecessity({ effects: effectReconstruction }),
        (a) => `assessments=${((a && a.assessments) || []).length} findings=${((a && a.findings) || []).length}`);
      for (const f of (approvalNecessity.findings || [])) {
        if (f && typeof f === 'object' && f.ruleId) decodedTx.ruleFindings.push(f);
      }
    } catch {
      approvalNecessity = null;
    }

    // Capability 4 B6: deadline/expiry analysis runs pre-reasoning so
    // its findings reach the model prompt, the bundle, policy, and the
    // safeguards together with decode-time findings. Findings append to
    // ruleFindings (same shape, analysis provenance in metadata).
    const { analyzeDeadlines } = require('../services/deadlineAnalysis');
    let deadlineAnalysis;
    if (internal && internal.deadlineAnalysis && typeof internal.deadlineAnalysis === 'object') {
      deadlineAnalysis = internal.deadlineAnalysis;
      const injSpan = telemetry.startSpan(trace, 'deadlines', 'injected');
      if (injSpan) injSpan.finish('injected (no live deadline work)');
    } else {
      try {
        deadlineAnalysis = telemetry.timed(trace, 'deadlines', '', () => analyzeDeadlines({
          decodedTx,
          subcalls: subcallTree.subcalls,
          blockTimestamp: chainState && chainState.block ? chainState.block.timestamp : null,
          blockNumber: chainState && chainState.block ? chainState.block.number : (chainState && chainState.blockNumber) || null,
          chainId: txContext.chainId
        }), (d) => `states=${((d && d.states) || []).length} findings=${((d && d.findings) || []).length}`);
      } catch (err) {
        deadlineAnalysis = {
          checks: [], findings: [], states: [], blockTime: null, blockNumber: null,
          chainId: null, downgrade: false, hold: null,
          error: `Deadline analysis failed (${String((err && err.message) || err).slice(0, 200)}); expiry unassessed.`
        };
      }
    }
    if (deadlineAnalysis && Array.isArray(deadlineAnalysis.findings)) {
      for (const f of deadlineAnalysis.findings) {
        if (f && typeof f === 'object' && f.ruleId) decodedTx.ruleFindings.push(f);
      }
    }

    // Capability 4 B8: bounded transaction-history assembly runs
    // pre-reasoning so sequence context (chain events, prior local
    // investigations, admitted agent priors) reaches the model prompt.
    // Sender-keyed: without a sender there is no history to assemble.
    // Infallible by contract: every source degrades to an explicit
    // status, and sequence findings are informational observations.
    const { fetchSenderEvents, readPriorInvestigations, buildSequenceContext } = require('../services/transactionHistory');
    let sequenceHistory;
    if (internal && internal.sequenceHistory && typeof internal.sequenceHistory === 'object') {
      sequenceHistory = internal.sequenceHistory;
      const injSpan = telemetry.startSpan(trace, 'history', 'injected');
      if (injSpan) injSpan.finish('injected (no live history work)');
    } else if (appConfig.historyEnabled === false) {
      sequenceHistory = {
        entries: [], entryCount: 0, truncated: 0, droppedIds: [], relationships: [], findings: [],
        sender: null, chainId: null,
        sources: { chainEvents: 'disabled', priors: 'disabled', agentPriors: 0 },
        disabled: true
      };
      telemetry.markSkipped(trace, 'history', 'history disabled by configuration');
    } else {
      const histSpan = telemetry.startSpan(trace, 'history', typeof txContext.from === 'string' ? txContext.from.slice(0, 42) : '(no sender)');
      try {
        const histSender = typeof txContext.from === 'string' ? txContext.from : null;
        const anchorHex = chainState && typeof chainState.blockNumber === 'string' ? chainState.blockNumber : null;
        let fromBlock = '0x0';
        try {
          if (anchorHex !== null) {
            const anchor = BigInt(anchorHex);
            const start = anchor - BigInt(appConfig.historyBlockWindow);
            fromBlock = `0x${(start < 0n ? 0n : start).toString(16)}`;
          }
        } catch {
          fromBlock = '0x0';
        }
        const [senderEvents, priors] = await Promise.all([
          anchorHex !== null
            ? fetchSenderEvents({
              rpcUrl: appConfig.evidenceChainRpcUrl, sender: histSender,
              fromBlock, toBlock: anchorHex, timeoutMs: appConfig.evidenceChainTimeoutMs
            })
            : Promise.resolve({ status: 'unavailable', events: [], truncated: 0, note: 'no block anchor; event window uncomputable' }),
          Promise.resolve().then(() => readPriorInvestigations({
            file: appConfig.investigationsFile, sender: histSender, chainId: txContext.chainId, limit: appConfig.historyMaxEntries
          }))
        ]);
        const admitted = agentEvidenceInternal && Array.isArray(agentEvidenceInternal.admitted)
          ? agentEvidenceInternal.admitted.filter((e) => e && e.type === 'prior-result')
          : [];
        sequenceHistory = buildSequenceContext({
          decodedTx, sender: histSender, chainId: txContext.chainId,
          senderEvents, priors, admittedPriors: admitted, maxEntries: appConfig.historyMaxEntries
        });
        if (histSpan) histSpan.finish(`entries=${sequenceHistory.entryCount || 0} (chain events + priors fetched concurrently)`);
      } catch (err) {
        if (histSpan) histSpan.fail('history assembly failed; no sequence context');
        sequenceHistory = {
          entries: [], entryCount: 0, truncated: 0, droppedIds: [], relationships: [], findings: [],
          sender: null, chainId: null,
          sources: { chainEvents: 'unavailable', priors: 'unavailable', agentPriors: 0 },
          error: `History assembly failed (${String((err && err.message) || err).slice(0, 200)}); no sequence context.`
        };
      }
    }
    if (sequenceHistory && Array.isArray(sequenceHistory.findings)) {
      for (const f of sequenceHistory.findings) {
        if (f && typeof f === 'object' && f.ruleId) decodedTx.ruleFindings.push(f);
      }
    }

    // Capability 5 B8: explicit intent extraction runs pre-reasoning so
    // the quoted statements reach the model prompt (as UNTRUSTED
    // quotes, never facts), the registry, the bundle, and quote
    // validation. A builder failure yields an empty extraction with a
    // note, never a partial quote list.
    let explicitIntent = null;
    try {
      const { extractExplicitIntent } = require('../utils/explicitIntent');
      explicitIntent = telemetry.timed(trace, 'explicit-intent', investigationType === 'agent' ? 'agent-purpose' : 'page-text', () => extractExplicitIntent({
        purposeText: normalizedPageContext && typeof normalizedPageContext.visibleText === 'string'
          ? normalizedPageContext.visibleText
          : '',
        purposeSource: investigationType === 'agent' ? 'agent-purpose' : 'page-text',
        agentEvidence: agentEvidenceInternal && Array.isArray(agentEvidenceInternal.admitted)
          ? agentEvidenceInternal.admitted
          : []
      }), (e) => `${((e && e.statements) || []).length} quoted statements`);
    } catch {
      explicitIntent = { statements: [], truncated: false, total: 0, summary: { statements: 0, sources: [], truncated: false }, notes: ['explicit intent extraction failed; no quotable statements'] };
    }

    // Step 4: Meta Muse Spark Semantic Discrepancy Reasoning. The model
    // and the heuristic both compare the isolated intent text when a
    // summary was identified, else the full scan (source labeled in-prompt).
    let reasoningResult = await evaluateSemanticDiscrepancy(
      screenshot ? intentText : visualResult.combinedText,
      normalizedPageContext,
      decodedTx,
      {
        detectedCount: visualResult.detectedCount || 0,
        visualAvailable: visualResult.visualAvailable === true,
        regionTexts: visualResult.regionTexts || [],
        fallbackRecords: visualResult.fallbackRecords || [],
        intentSource: screenshot ? intentSource : 'full-scan (no screenshot supplied)'
      },
      {
        txContext,
        chainState,
        freshness,
        identity: counterpartyLabels,
        associations: preAssociations,
        summaryStatus,
        samStatus: samStatusForEvidence,
        simulation: simulationEvidence,
        chainVerification,
        proxy: proxyResolution,
        contractIdentity,
        deadlines: deadlineAnalysis,
        history: sequenceHistory,
        agentEvidence: agentEvidenceInternal,
        evidenceGraph: { edges: preGraphEdges },
        visualElements: preActionElements,
        effects: effectReconstruction,
        composition: batchComposition,
        bridge: bridgeAnalysis,
        approvalNecessity,
        explicitIntent
      },
      { investigationType, trace }
    );
    if (preSimReconciliation) reasoningResult.simReconciliation = preSimReconciliation;
    reasoningResult.chainVerification = chainVerification;
    reasoningResult.proxyResolution = proxyResolution;
    reasoningResult.contractIdentity = contractIdentity;
    reasoningResult.deadlineAnalysis = deadlineAnalysis;
    reasoningResult.sequenceHistory = sequenceHistory;

    // Phase C: precompute the deterministic comparison for the safeguard
    // pipeline, using the shared inputs the bundle displays. The result is
    // passed through to evidence compilation so the safeguard evaluates
    // exactly what the bundle shows.
    const comparisonInputs = prepareComparisonInputs(visualResult, reasoningResult.visualClaims);
    const intentComparison = telemetry.timed(trace, 'comparison', '', () => buildIntentComparison({
      ...comparisonInputs,
      decodedTx,
      sender: transaction.from,
      // Agent purpose is the complete disclosure surface on that path;
      // browser DOM omission is unprovable, so browser passes nothing.
      statedIntent: investigationType === 'agent' && normalizedPageContext && typeof normalizedPageContext.visibleText === 'string'
        ? normalizedPageContext.visibleText
        : undefined,
      agentEvidence: Array.isArray(agentEvidenceInternal.admitted) ? agentEvidenceInternal.admitted : [],
      effects: effectReconstruction
    }), (c) => `overall=${c && c.overall ? c.overall : 'unknown'} fields=${((c && c.fields) || []).length}`);

    // Capability 3 B4: evidence-support validation + mechanism
    // reconciliation run pre-safeguard so stages and holds below act on
    // them. Both ride the reasoning result like other validations.
    const { buildSourceTexts, validateSupport } = require('../services/supportValidation');
    const { reconcileMechanisms } = require('../services/reconciliation');
    const sourceTexts = buildSourceTexts({
      regionTexts: visualResult.regionTexts || [],
      pageContext: normalizedPageContext,
      decodedTx,
      chainState,
      agentEvidence: agentEvidenceInternal,
      combinedOcr: visualResult.combinedText || '',
      associationsSummary: preAssociations ? `links=${(preAssociations.links || []).length} ambiguities=${(preAssociations.ambiguities || []).length}` : '',
      extraTexts: {
        freshness: freshness && freshness.screenshot ? `${freshness.screenshot.status} ${freshness.screenshot.reason || ''}` : (freshness && freshness.note) || '',
        labels: (counterpartyLabels.labels || []).map((l) => `${l.address} ${l.label || ''}`).join('; '),
        summarySelection: summaryStatus ? `${summaryStatus.status || ''} ${(summaryStatus.regionIds || []).join(',')}` : '',
        sam: samStatusForEvidence ? `${samStatusForEvidence.mode || ''} partial=${samStatusForEvidence.partialFailure === true}` : '',
        simulation: `${simulationEvidence.status} executed=${simulationEvidence.executed === true}`,
        identity: contractIdentity ? `${contractIdentity.status || ''} ${contractIdentity.explanation || ''} ${(contractIdentity.staticLabel && contractIdentity.staticLabel.label) || ''} ${(contractIdentity.selectorSignature && contractIdentity.selectorSignature.textSignature) || ''}` : '',
        deadlines: deadlineAnalysis && Array.isArray(deadlineAnalysis.states)
          ? deadlineAnalysis.states.map((s) => `${s.label || ''} ${s.functionName || ''} ${s.outcome || ''} ${s.deadline || ''}`).join('; ')
          : '',
        history: sequenceHistory && Array.isArray(sequenceHistory.entries)
          ? [...sequenceHistory.entries.map((e) => `${e.historyId || ''} ${e.summary || ''}`),
            ...(Array.isArray(sequenceHistory.relationships) ? sequenceHistory.relationships.map((r) => `${r.type || ''} ${r.explanation || ''}`) : [])].join('; ')
          : '',
        visualRoles: preActionElements && Array.isArray(preActionElements.elements)
          ? preActionElements.elements.map((e) => `${e.elementId || ''} ${e.actionText || ''} ${e.consistencyNote || ''}`).join('; ')
          : '',
        effects: effectReconstruction && Array.isArray(effectReconstruction.effects)
          ? effectReconstruction.effects.map((e) => `${e.effectId || ''} ${e.kind || ''} ${e.operation ? e.operation.functionName || '' : ''} ${e.amount || ''} ${e.to || ''} ${e.spender || ''} ${(e.notes || []).join(' ')}`).join('; ')
          : '',
        explicitIntent: explicitIntent && Array.isArray(explicitIntent.statements)
          ? explicitIntent.statements.map((s) => `${s.id || ''} ${s.quote || ''}`).join('; ')
          : ''
      }
    });
    reasoningResult.supportValidation = telemetry.timed(trace, 'support-validation', '', () => validateSupport({ investigation: reasoningResult.investigation, sourceTexts }),
      (v) => `failures=${((v && v.failures) || []).length} needsReview=${((v && v.needsReview) || []).length}`);
    reasoningResult.reconciliation = telemetry.timed(trace, 'reconciliation', '', () => reconcileMechanisms({
      verdict: reasoningResult.verdict,
      investigation: reasoningResult.investigation,
      intentComparison,
      supportValidation: reasoningResult.supportValidation,
      chainVerification,
      simReconciliation: reasoningResult.simReconciliation || null
    }), (r) => `holds=${((r && r.holds) || []).length}`);

    // Capability 4 B7: deterministic semantic-claim verification checks
    // checkable model assertions (recipients, amounts, minimums,
    // functions, identity, deadlines, implementations) against the
    // verified record. Contradictions are verdict-grade: a MATCH resting
    // on falsehoods is unreliable.
    const { verifySemanticClaims } = require('../services/semanticClaims');
    let semanticClaims;
    try {
      semanticClaims = telemetry.timed(trace, 'semantic-claims', '', () => verifySemanticClaims({
        reasoningResult,
        decodedTx,
        chainId: txContext.chainId,
        contractIdentity,
        proxyResolution,
        deadlineAnalysis
      }), (s) => `evaluated=${s && s.summary ? s.summary.evaluated : 0} contradicted=${s && s.summary ? s.summary.CONTRADICTED : 0}`);
    } catch (err) {
      semanticClaims = {
        claims: [],
        summary: {
          statements: 0, evaluated: 0, truncated: false,
          VERIFIED: 0, CONTRADICTED: 0, INCONCLUSIVE: 0, NOT_APPLICABLE: 0,
          downgrade: false, hold: null,
          error: `Claim verification failed (${String((err && err.message) || err).slice(0, 200)}); claims unverified.`
        }
      };
    }
    reasoningResult.semanticClaims = semanticClaims;

    // Capability 4 B10: post-model cross-check of model-asserted visual
    // roles against observed OCR. VERIFIED needs observed elements;
    // REFUTED needs strict contradiction; the rest stays INCONCLUSIVE.
    const { crossCheckVisualRoles } = require('../utils/visualRoles');
    let visualRoleChecks;
    try {
      visualRoleChecks = telemetry.timed(trace, 'visual-role-check', '', () => crossCheckVisualRoles({
        grounding: comparisonInputs.grounding,
        ruleFindings: decodedTx.ruleFindings,
        decodedTx
      }), (v) => `checked=${v && v.summary ? v.summary.checked : 0} refuted=${v && v.summary ? v.summary.REFUTED : 0}`);
    } catch (err) {
      visualRoleChecks = {
        checks: [],
        summary: {
          checked: 0, VERIFIED: 0, REFUTED: 0, INCONCLUSIVE: 0,
          downgrade: false,
          error: `Role cross-check failed (${String((err && err.message) || err).slice(0, 200)}); roles unverified.`
        }
      };
    }
    reasoningResult.visualRoleChecks = visualRoleChecks;

    // Capability 3 B7: merge the full relationship graph. Model-proposed
    // edges validate against the same registry the reasoner used, so
    // only grounded endpoints join the deterministic edges.
    const { buildEvidenceRegistry, classifyRef } = require('../services/reasoningValidation');
    const graphRegistry = buildEvidenceRegistry({
      pageContext: normalizedPageContext,
      decodedTx,
      visualMeta: {
        detectedCount: visualResult.detectedCount || 0,
        regionTexts: visualResult.regionTexts || [],
        fallbackRecords: visualResult.fallbackRecords || []
      },
      extra: {
        chainVerification,
        agentEvidence: agentEvidenceInternal,
        evidenceGraph: { edges: preGraphEdges },
        visualElements: preActionElements,
        effects: effectReconstruction
      }
    });
    const proposedEdges = reasoningResult.investigation && Array.isArray(reasoningResult.investigation.evidenceRelationships)
      ? reasoningResult.investigation.evidenceRelationships : [];
    const admittedEdges = telemetry.timed(trace, 'evidence-graph', 'model edge admission (post-reasoning)', () => validateModelEdges(proposedEdges, (id) => classifyRef(id, graphRegistry) === 'ok'),
      (a) => `merged=${((a && a.merged) || []).length} rejected=${((a && a.rejected) || []).length}`);
    const postEdges = assignEdgeIds(buildModelDerivedEdges({
      grounding: comparisonInputs.grounding,
      intentComparison,
      supportValidation: reasoningResult.supportValidation,
      reconciliation: reasoningResult.reconciliation,
      modelEdges: admittedEdges.merged
    }), preGraphEdges.length + 1);
    reasoningResult.evidenceGraph = {
      edges: [...preGraphEdges, ...postEdges],
      rejectedModelEdges: admittedEdges.rejected
    };

    // Model proposal, captured before safeguards mutate the verdict, so
    // the policy decision can record what the model actually proposed.
    const modelVerdict = reasoningResult.verdict;
    const modelConfidence = reasoningResult.confidence;

    // Verdict safeguards (normalization, deterministic block, recipient
    // risk, unknown function, deterministic comparison). Every triggered
    // safeguard is preserved in order; nothing overwrites.
    const safeguarded = telemetry.timed(trace, 'safeguards', '16 ordered stages', () => applyVerdictSafeguards(decodedTx, reasoningResult, intentComparison),
      (s) => `triggered=${((s && s.safeguards) || []).length} verdict=${s && s.reasoningResult ? s.reasoningResult.verdict : '?'}`);
    reasoningResult = safeguarded.reasoningResult;
    const verdictSafeguards = safeguarded.safeguards;

    // Visual-confidence cap (Phase 5C + OCR-text extension): a MATCH may
    // rest on title/URL/transaction evidence, but when a screenshot was
    // supplied and it yields zero genuine detections OR no genuine region
    // with usable OCR text, high confidence is unjustified. MATCH-only,
    // mirroring the safeguard stages: MISMATCH/UNCERTAIN make no alignment
    // claim, and the no-screenshot contract (title/URL/tx MATCH) is
    // deliberately untouched. Synthetic fallback OCR never counts as
    // genuine. Runs after the safeguards, which already cap on downgrade;
    // safeguard records pass through unmodified.
    let confidenceCap = null;
    const visualCap = assessVisualConfidenceCap({
      screenshotProvided: Boolean(screenshot),
      detectedCount: visualResult.detectedCount || 0,
      regionTexts: visualResult.regionTexts || [],
      fallbackReason: visualResult.fallbackReason || null
    });
    if (visualCap.capped && reasoningResult.verdict === 'MATCH'
        && typeof reasoningResult.confidence === 'number' && reasoningResult.confidence > ZERO_VISUAL_CAP) {
      confidenceCap = {
        trigger: visualCap.trigger,
        previousConfidence: reasoningResult.confidence,
        cap: ZERO_VISUAL_CAP,
        reason: visualCap.reason
      };
      reasoningResult = {
        ...reasoningResult,
        confidence: ZERO_VISUAL_CAP,
        summary: `${reasoningResult.summary || ''} [Confidence capped at ${ZERO_VISUAL_CAP}: screenshot supplied but ${visualCap.detail}.]`.trim()
      };
    }

    // Step 5: Foundry simulation (plain `forge test`, no fork). Pre-
    // reasoning sims already ran above when deterministically triggered;
    // a post-reasoning run is preserved for MISMATCH verdicts that did
    // not trigger one (existing behavior), and always reconciled.
    let simulationResult = simulationRaw;
    if (!simRan && reasoningResult.verdict === 'MISMATCH') {
      const simSpan = telemetry.startSpan(trace, 'simulation-post', 'MISMATCH follow-up');
      try {
        const ran = await runSimulationEvidence({ transaction, decodedTx });
        simulationEvidence = ran.evidence;
        simulationRaw = ran.raw;
        simulationResult = ran.raw;
        simRan = true;
        if (simSpan) simSpan.finish(`status=${ran.evidence.status} executed=${ran.evidence.executed === true}`);
      } catch (err) {
        simulationEvidence = {
          simId: 'SIM-001', status: 'FAILED', executed: false, success: null,
          escalationDetected: false, error: String((err && err.message) || err).slice(0, 300),
          reason: 'Simulation harness threw; treated as failed, not as evidence.',
          mode: 'failed', measuredNote: 'nothing measured'
        };
        simRan = true;
        if (simSpan) simSpan.fail('harness threw; recorded as FAILED, not as evidence');
      }
    } else {
      telemetry.markSkipped(trace, 'simulation-post', simRan ? 'pre-reasoning simulation already ran' : 'verdict is not MISMATCH; no follow-up simulation');
    }
    const simReconciliation = simRan ? reconcileSimulation({ sim: simulationEvidence, decodedTx }) : null;
    if (simReconciliation) reasoningResult.simReconciliation = simReconciliation;

    // Capability 2: model advisory escalations. The investigator may ask
    // for human review on a would-be ALLOW, but it can never permit
    // anything: these advisories only convert ALLOW into REVIEW inside
    // the policy composer. Absent investigation output (canned fixtures,
    // older callers) yields no advisories — backward compatible.
    const advisoryEscalations = [];
    if (reasoningResult.origin === 'model') {
      // Only PROCEED_WITH_CAUTION is a clean bill: BLOCK and VERIFY are
      // both hold-requests the deterministic pass must not ignore.
      if (reasoningResult.recommendedAction === 'BLOCK_TRANSACTION'
          || reasoningResult.recommendedAction === 'VERIFY_RECIPIENT') {
        advisoryEscalations.push({ source: 'recommendedAction', reason: `model recommended ${reasoningResult.recommendedAction} despite a clean deterministic pass` });
      }
      if (reasoningResult.discrepancyDetails && reasoningResult.discrepancyDetails.criticalMismatch === true) {
        advisoryEscalations.push({ source: 'discrepancyDetails', reason: 'model flagged a critical mismatch' });
      }
      const inv = reasoningResult.investigation;
      if (inv && typeof inv === 'object') {
        const unresolved = (inv.contradictions || []).filter((c) => c && c.resolved !== true).length;
        if (unresolved > 0) {
          advisoryEscalations.push({ source: 'contradictions', reason: `${unresolved} contradiction(s) left unresolved by the investigation` });
        }
        const unsupported = Array.isArray(reasoningResult.referenceValidation?.unsupportedConclusions)
          ? reasoningResult.referenceValidation.unsupportedConclusions.length : 0;
        if (unsupported > 0) {
          advisoryEscalations.push({ source: 'conclusions', reason: `${unsupported} conclusion(s) cite no supporting evidence` });
        }
        // Note: missingEvidence is deliberately NOT an escalation. The
        // methodology requires listing absent evidence, and absence is
        // normal (the agent path has no screenshots by design):
        // escalating on it would make ALLOW unreachable.
      }
    }

    // Policy decision: the single centralized mapping from the
    // investigation outcome to ALLOW / BLOCK / REVIEW / UNCERTAIN.
    // Deterministic blocks dominate; the model can never override them.
    const supportVal = reasoningResult.supportValidation || {};
    const deterministicHolds = [
      ...(chainVerification.failures || []).map((f) => ({ source: f.checkId, reason: f.explanation })),
      ...(proxyResolution && proxyResolution.hold ? [proxyResolution.hold] : []),
      ...(deadlineAnalysis && deadlineAnalysis.hold ? [deadlineAnalysis.hold] : []),
      ...(semanticClaims && semanticClaims.summary && semanticClaims.summary.hold ? [semanticClaims.summary.hold] : []),
      ...((reasoningResult.reconciliation && reasoningResult.reconciliation.holds) || []),
      ...((supportVal.failures || []).map((n) => ({ source: `support:${n.kind}`, reason: `${n.where}: ${n.reason}` }))),
      ...((supportVal.needsReview || []))
        .filter((n) => n && n.kind === 'WEAK_FOUNDATION')
        .map((n) => ({ source: `support:${n.kind}`, reason: `${n.where}: ${n.reason}` }))
    ];
    const policyDecision = telemetry.timed(trace, 'policy-decision', `verdict=${reasoningResult.verdict} origin=${reasoningResult.origin}`, () => composePolicyDecision({
      verdict: reasoningResult.verdict,
      modelVerdict,
      modelConfidence,
      reasoningOrigin: reasoningResult.origin,
      ruleFindings: decodedTx.ruleFindings,
      safeguards: verdictSafeguards,
      advisoryEscalations,
      deterministicHolds
    }), (p) => `decision=${p && p.decision ? p.decision : '?'}`);

    // Step 6: Evidence compilation
    const bundleSpan = telemetry.startSpan(trace, 'evidence-bundle', '');
    const evidenceBundle = compileEvidenceBundle({
      visualResult,
      decodedTx,
      reasoningResult,
      simulationResult,
      pageContext: normalizedPageContext,
      screenshotProvided: Boolean(screenshot),
      verdictSafeguards,
      confidenceCap,
      policyDecision,
      txBinding,
      // Phase B: behavior-neutral sender threading for informational
      // intent comparison only; validation happens in the adapter.
      sender: transaction.from,
      // Phase C: the exact comparison the safeguard evaluated.
      intentComparison,
      assemblyEvidence: {
        evidencePacking: reasoningResult.evidencePacking || null,
        chainState: chainState || null,
        freshness: freshness || null,
        counterpartyLabels: counterpartyLabels || null,
        simReconciliation: simReconciliation || null,
        chainVerification: chainVerification || null,
        proxyResolution: proxyResolution || null,
        contractIdentity: contractIdentity || null,
        deadlineAnalysis: deadlineAnalysis || null,
        semanticClaims: semanticClaims || null,
        sequenceHistory: sequenceHistory || null,
        visualRoleChecks: reasoningResult.visualRoleChecks || null,
        effects: effectReconstruction || null,
        composition: batchComposition || null,
        bridge: bridgeAnalysis || null,
        approvalNecessity: approvalNecessity || null,
        explicitIntent: explicitIntent || null,
        supportValidation: reasoningResult.supportValidation || null,
        reconciliation: reasoningResult.reconciliation || null,
        agentEvidence: agentEvidenceInternal,
        evidenceGraph: reasoningResult.evidenceGraph || null
      }
    });
    if (bundleSpan) bundleSpan.finish(`verdict=${evidenceBundle.verdict} decision=${evidenceBundle.policyDecision && evidenceBundle.policyDecision.decision}`);

    // Capability 3 B1: persist the completed investigation for
    // qualitative review. Model-origin records only: the store exists to
    // review live reasoning, and heuristic output is unit-covered.
    // Best-effort by contract: a store failure must never break the
    // evaluation response.
    let persistSpan = null;
    try {
      if (reasoningResult.origin !== 'model') {
        telemetry.markSkipped(trace, 'persistence', 'model-origin records only; heuristic output is unit-covered');
        return res.status(200).json(evidenceBundle);
      }
      const { persistInvestigation, recordId } = require('../services/investigationStore');
      persistSpan = telemetry.startSpan(trace, 'persistence', 'investigation record');
      persistInvestigation({
        recordId: recordId(evidenceBundle.txBinding && evidenceBundle.txBinding.evaluatedTxDigest),
        // Ownership scope for the observations API: set on the agent
        // path (async or sync submit), null for browser evaluations.
        ownerKeyId: internal && typeof internal.ownerKeyId === 'string' ? internal.ownerKeyId : null,
        // Provenance linkage: the trace (and request, on the agent
        // path) this record was compiled from. Always present on the
        // trace; null only when no trace was supplied.
        traceId: trace && typeof trace.id === 'string' ? trace.id : null,
        requestId: trace && typeof trace.requestId === 'string' ? trace.requestId : null,
        recordedAt: Date.now(),
        receivedAt,
        durationMs: Date.now() - receivedAt,
        investigationPath: investigationType,
        // Capability 4 B8 sender envelope: lets later investigations
        // find same-sender priors without re-deriving identity.
        sender: typeof txContext.from === 'string' ? txContext.from.toLowerCase() : null,
        chainId: txContext.chainId === undefined || txContext.chainId === null ? null : String(txContext.chainId),
        to: decodedTx && typeof decodedTx.contract === 'string' ? decodedTx.contract : null,
        visualClaims: Array.isArray(reasoningResult.visualClaims) ? reasoningResult.visualClaims : null,
        ...evidenceBundle
      });
      if (persistSpan) persistSpan.finish('record persisted');
    } catch (err) {
      if (persistSpan) persistSpan.fail('store failure (response unaffected)');
      console.warn(`[Investigation Store] persist failed (response unaffected): ${String((err && err.message) || err).slice(0, 200)}`);
    }

    return res.status(200).json(evidenceBundle);
  } catch (err) {
    console.error('[Evaluation Error]', err);
    return res.status(500).json({
      error: 'Internal evaluation error',
      message: err.message,
      verdict: 'UNCERTAIN',
      summary: 'Evaluation failed due to an internal server error. Proceed with extreme caution.'
    });
  }
}

module.exports = { handleEvaluateTransaction, normalizePageContext, applyVerdictSafeguards };
