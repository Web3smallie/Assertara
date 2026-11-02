/**
 * Mechanism reconciliation (Capability 3, B4). Three mechanisms can
 * disagree: model contradictions, deterministic intent comparison, and
 * grounding/association safeguards. This layer records the agreement
 * state explicitly and defines precedence. Pure and deterministic.
 *
 * Precedence (highest first):
 *  P0. Deterministic BLOCK findings — decided by policy, restated here.
 *  P1. Deterministic comparison MISMATCH beats model MATCH (safeguard).
 *  P2. Measured contradictions (sim revert, chain failure, support
 *      fabrication) beat model MATCH (safeguards).
 *  P3. Model-resolved contradictions stand ONLY when no deterministic
 *      MISMATCH survives; otherwise the resolution is overridden and the
 *      item escalated for review.
 *  P4. Stale-uncorroborated visual support cannot carry MATCH.
 *  P5. Safe-direction model verdicts (MISMATCH/UNCERTAIN) are trusted
 *      over a clean deterministic sheet (recorded, no action).
 *  P6. Explanation divergence with verdict agreement is informational.
 *
 * The model never overrides deterministic restrictions. Output feeds
 * safeguard stage 9 (downgrade) and deterministic policy holds.
 */

function reconcileMechanisms({
  verdict, investigation, intentComparison, supportValidation, chainVerification, simReconciliation
}) {
  const divergences = [];
  const holds = [];
  let downgrade = false;
  let downgradeRule = null;
  let downgradeReason = null;

  const fields = (intentComparison && Array.isArray(intentComparison.fields)) ? intentComparison.fields : [];
  const detMismatch = fields.filter((f) => f && f.status === 'MISMATCH');
  const inv = investigation && typeof investigation === 'object' ? investigation : null;
  const modelContra = inv && Array.isArray(inv.contradictions) ? inv.contradictions : [];
  const resolved = modelContra.filter((c) => c && c.resolved === true);

  // P3: resolution override.
  const overridden = [];
  if (resolved.length > 0 && detMismatch.length > 0) {
    for (const c of resolved) overridden.push(typeof c.statement === 'string' ? c.statement.slice(0, 160) : '(unstated)');
    divergences.push({
      rule: 'RESOLUTION_OVERRIDE', severity: 'hold',
      detail: `${resolved.length} model-resolved contradiction(s) vs ${detMismatch.length} deterministic mismatch field(s) (${detMismatch.map((f) => f.field).join(', ')}); resolutions not accepted`
    });
    holds.push({ source: 'reconciliation', reason: 'model marked contradictions resolved while deterministic evidence still disagrees' });
  }

  // P4: stale-only visual support.
  const freshFail = chainVerification && Array.isArray(chainVerification.failures)
    && chainVerification.failures.some((f) => f && f.checkId === 'FRESHNESS_CORROBORATION');
  if (freshFail && verdict === 'MATCH' && inv && Array.isArray(inv.conclusions)) {
    let refRoot = null;
    try { refRoot = require('./reasoningRubric').refSourceRoot; } catch { refRoot = null; }
    const visualOnly = inv.conclusions.length > 0 && inv.conclusions.every((c) => {
      const refs = (c && c.supportingRefs) || [];
      return refs.length > 0 && refs.every((r) => (refRoot ? refRoot(r) : '') === 'visual');
    });
    if (visualOnly) {
      downgrade = true;
      downgradeRule = 'STALE_VISUAL_SUPPORT';
      downgradeReason = 'MATCH conclusions rest solely on stale uncorroborated visuals.';
      divergences.push({ rule: 'STALE_VISUAL_SUPPORT', severity: 'downgrade', detail: downgradeReason });
    }
  }

  // P1/P2 restatement: support fabrication on MATCH is a safeguard
  // matter; record the divergence here for the bundle trail.
  const supportFails = (supportValidation && Array.isArray(supportValidation.failures)) ? supportValidation.failures : [];
  if (supportFails.length > 0 && verdict === 'MATCH') {
    divergences.push({
      rule: 'CITATION_SUPPORT_FAILURE', severity: 'downgrade',
      detail: `${supportFails.length} conclusion(s) cite evidence that does not support them`
    });
    downgrade = true;
    downgradeRule = 'CITATION_SUPPORT_FAILURE';
    downgradeReason = `${supportFails.length} conclusion citation(s) fail support validation.`;
  }

  // P5/P6: informational agreement states.
  if ((verdict === 'MISMATCH' || verdict === 'UNCERTAIN') && detMismatch.length === 0) {
    divergences.push({ rule: 'SAFE_DIRECTION_TRUSTED', severity: 'info', detail: `model ${verdict} held despite a clean deterministic sheet` });
  }
  if (verdict === 'MATCH' && detMismatch.length === 0 && fields.length > 0) {
    divergences.push({ rule: 'VERDICT_AGREEMENT', severity: 'info', detail: 'model MATCH with no deterministic mismatch fields' });
  }
  const simDowngrade = simReconciliation && simReconciliation.downgrade === true;
  if (simDowngrade && verdict === 'MATCH') {
    divergences.push({ rule: 'SIM_CONTRADICTION_NOTED', severity: 'info', detail: 'measured simulation contradicts MATCH (handled by sim safeguard)' });
  }

  return {
    divergences,
    overridden,
    holds,
    downgrade,
    downgradeRule,
    downgradeReason,
    deterministicMismatchFields: detMismatch.map((f) => f.field),
    modelContradictions: modelContra.length,
    modelResolved: resolved.length
  };
}

module.exports = { reconcileMechanisms };
