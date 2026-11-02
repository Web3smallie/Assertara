/**
 * Reasoning-quality rubric (Capability 3, B1). Grades a persisted
 * investigation on 12 substantive criteria. Each criterion scores 0-2
 * with a stated basis and method. Deterministic criteria measure
 * structure that code can verify; heuristic criteria are labeled as
 * such and assist (never replace) human review of the persisted text.
 *
 * The rubric NEVER feeds authorization: it reads completed records for
 * review only. High model confidence never raises any score.
 */

function refSourceRoot(ref) {
  if (typeof ref !== 'string') return 'unknown';
  if (/^R-\d+$/.test(ref) || ref === 'R-FALLBACK') return 'visual';
  if (['ocr', 'sam', 'visual'].includes(ref)) return 'visual';
  if (['title', 'url', 'dom', 'page'].includes(ref)) return 'page';
  if (['tx', 'params', 'findings'].includes(ref) || ref.startsWith('param:')) return 'tx';
  if (ref === 'chain') return 'chain';
  if (ref === 'freshness') return 'freshness';
  if (ref === 'labels') return 'labels';
  if (ref === 'association') return 'association';
  if (ref === 'summarySelection') return 'summary';
  if (ref === 'simulation') return 'simulation';
  if (ref === 'agentEvidence' || /^X-\d+$/.test(ref)) return 'agentEvidence';
  if (ref === 'calldata') return 'calldata';
  if (/^EF-\d+$/.test(ref)) return 'tx'; // B2 effect nodes derive from decoded tx
  if (/^[A-Z][A-Z0-9_]*$/.test(ref)) return 'tx'; // finding rule IDs
  if (/^L-\d+$/.test(ref) || /^AMB-\d+$/.test(ref)) return 'association';
  return 'unknown';
}

function distinctRoots(refs) {
  return [...new Set((refs || []).filter((r) => typeof r === 'string').map(refSourceRoot).filter((r) => r !== 'unknown'))];
}

function grade(total) {
  if (total >= 20) return 'STRONG';
  if (total >= 14) return 'ADEQUATE';
  if (total >= 8) return 'WEAK';
  return 'POOR';
}

function reviewInvestigation(record) {
  const r = record && typeof record === 'object' ? record : {};
  const inv = r.investigation && typeof r.investigation === 'object' ? r.investigation : null;
  const scores = [];
  const push = (criterion, score, basis, method) => scores.push({ criterion, score, max: 2, basis, method });

  // 1. Evidence coverage: distinct source families present in the bundle.
  {
    const families = new Set(['tx']);
    const ve = r.visualEvidence || {};
    if ((ve.detectedCount || 0) > 0 || (ve.regions || []).length > 0) families.add('visual');
    if (r.chainState && r.chainState.status === 'ok') families.add('chain');
    if (r.simulation && r.simulation.executed === true) families.add('simulation');
    if (r.freshness && r.freshness.screenshot && r.freshness.screenshot.status === 'fresh') families.add('freshness');
    if ((r.ruleFindings || []).length > 0) families.add('findings');
    push('evidenceCoverage', families.size >= 4 ? 2 : families.size >= 2 ? 1 : 0,
      `source families present: ${[...families].join(', ')}`, 'deterministic');
  }

  if (!inv) {
    for (const c of ['crossSourceCorrelation', 'corroborationQuality', 'contradictionDetection', 'supportingAccuracy',
      'competingQuality', 'factsVsInference', 'missingEvidence', 'uncertainty', 'conclusionAccuracy',
      'recommendationRelevance', 'unsupportedSynthesis']) {
      push(c, 0, 'no investigation object in record', 'deterministic');
    }
    const total = scores.reduce((n, s) => n + s.score, 0);
    return { total, maxTotal: 24, grade: grade(total), scores };
  }

  // 2. Cross-source correlation: discrepancies/contradictions spanning roots.
  {
    const items = [...(inv.discrepancies || []), ...(inv.contradictions || []).map((c) => ({ supportingRefs: c.sources || [] }))];
    const multi = items.filter((d) => distinctRoots([...(d.supportingRefs || []), ...(d.contradictingRefs || [])]).length >= 2).length;
    const any = items.length;
    push('crossSourceCorrelation', multi > 0 ? 2 : any > 0 ? 1 : 0,
      `${multi}/${any} discrepancy/contradiction items span 2+ source roots`, 'deterministic');
  }

  // 3. Corroboration quality: conclusions backed by independent roots.
  {
    const conclusions = inv.conclusions || [];
    if (conclusions.length === 0) push('corroborationQuality', 0, 'no conclusions', 'deterministic');
    else {
      const best = Math.max(...conclusions.map((c) => distinctRoots(c.supportingRefs || []).length));
      push('corroborationQuality', best >= 2 ? 2 : best === 1 ? 1 : 0,
        `best-supported conclusion cites ${best} independent root(s)`, 'deterministic');
    }
  }

  // 4. Contradiction detection vs deterministic comparison.
  {
    const detMismatch = ((r.visualEvidence && r.visualEvidence.intentComparison && r.visualEvidence.intentComparison.fields) || [])
      .filter((f) => f && f.status === 'MISMATCH').length;
    const modelContra = (inv.contradictions || []).length;
    let score = 1;
    let basis = `deterministic mismatches: ${detMismatch}; model contradictions: ${modelContra}`;
    if (detMismatch > 0 && modelContra > 0) { score = 2; basis += ' (model caught deterministic conflict)'; } else if (detMismatch > 0) { score = 0; basis += ' (model silent on deterministic conflict)'; } else if (modelContra > 0) { score = 1; basis += ' (model-only contradictions, unverified)'; } else { score = 2; basis += ' (none on either side)'; }
    push('contradictionDetection', score, basis, 'deterministic');
  }

  // 5. Supporting-evidence accuracy (resolution-level; B4 adds support).
  {
    const rv = r.referenceValidation || {};
    const fab = (rv.fabricated || []).length;
    const unsup = (rv.unsupportedConclusions || []).length;
    push('supportingAccuracy', fab === 0 && unsup === 0 ? 2 : fab === 0 ? 1 : 0,
      `fabricated refs: ${fab}; unsupported conclusions: ${unsup} (resolution only; support semantics need B4)`, 'deterministic');
  }

  // 6. Competing-explanation quality (structural; content needs review).
  {
    const alts = inv.competingExplanations || [];
    const twoSided = alts.filter((a) => (a.supportingRefs || []).length > 0 && (a.contradictingRefs || []).length > 0).length;
    push('competingQuality', twoSided > 0 ? 2 : alts.length > 0 ? 1 : 0,
      `${twoSided}/${alts.length} alternatives argue both sides (content requires human review)`, 'deterministic');
  }

  // 7. Facts vs inference (heuristic language + structure proxy).
  {
    const text = JSON.stringify(inv.conclusions || []).toLowerCase();
    const hedged = /(may|might|appears|appears to|suggests|likely|possibly|uncertain|cannot confirm)/.test(text);
    const explained = inv.uncertainty && typeof inv.uncertainty.explanation === 'string' && inv.uncertainty.explanation.length > 20;
    push('factsVsInference', explained && hedged ? 2 : explained ? 1 : 0,
      `uncertainty explained: ${Boolean(explained)}; inference hedging present: ${hedged}`, 'heuristic');
  }

  // 8. Missing-evidence identification.
  {
    const visualsAbsent = !((r.visualEvidence && (r.visualEvidence.detectedCount || 0)) > 0);
    const listed = (inv.missingEvidence || []).length;
    push('missingEvidence', visualsAbsent ? (listed > 0 ? 2 : 0) : 2,
      visualsAbsent ? `no visuals; missing items listed: ${listed}` : 'visuals present; empty list acceptable', 'deterministic');
  }

  // 9. Uncertainty calibration table (verdict vs level).
  {
    const level = (inv.uncertainty && inv.uncertainty.level) || 'unknown';
    const table = {
      MATCH: { none: 2, low: 2, medium: 1, high: 0 },
      MISMATCH: { none: 1, low: 1, medium: 2, high: 2 },
      UNCERTAIN: { none: 0, low: 1, medium: 2, high: 2 }
    };
    const score = (table[r.verdict] && table[r.verdict][level] !== undefined) ? table[r.verdict][level] : 0;
    push('uncertainty', score, `verdict ${r.verdict} with uncertainty ${level}`, 'deterministic');
  }

  // 10. Conclusion accuracy vs deterministic comparison.
  {
    const fields = (r.visualEvidence && r.visualEvidence.intentComparison && r.visualEvidence.intentComparison.fields) || [];
    const mismatch = fields.filter((f) => f && f.status === 'MISMATCH').length;
    const match = fields.filter((f) => f && f.status === 'MATCH').length;
    let score = 1;
    let basis = `deterministic match=${match} mismatch=${mismatch}; model verdict=${r.verdict}`;
    if (r.verdict === 'MATCH' && mismatch > 0) { score = 0; basis += ' (model MATCH against deterministic conflict)'; } else if (r.verdict === 'MISMATCH' && mismatch > 0) { score = 2; basis += ' (agreement)'; } else if (r.verdict === 'MATCH' && mismatch === 0) { score = 2; basis += ' (no deterministic conflict)'; } else if (fields.length === 0) { score = 1; basis += ' (no deterministic comparison available)'; }
    push('conclusionAccuracy', score, basis, 'deterministic');
  }

  // 11. Recommendation relevance.
  {
    const recs = inv.recommendations || [];
    const grounded = recs.filter((x) => x && typeof x.rationale === 'string' && x.rationale.length > 0 && (x.basisRefs || []).length > 0).length;
    const findingsStand = (r.ruleFindings || []).length > 0;
    const cleanBill = r.recommendedAction === 'PROCEED_WITH_CAUTION';
    let score = recs.length === 0 ? 0 : grounded === recs.length ? 2 : 1;
    let basis = `${grounded}/${recs.length} recommendations grounded with rationale`;
    if (findingsStand && cleanBill) { score = 0; basis += '; clean bill despite standing findings'; }
    push('recommendationRelevance', score, basis, 'deterministic');
  }

  // 12. Unsupported-synthesis avoidance.
  {
    const conclusions = inv.conclusions || [];
    if (conclusions.length === 0) push('unsupportedSynthesis', 0, 'no conclusions to assess', 'deterministic');
    else {
      const cited = conclusions.filter((c) => (c.supportingRefs || []).length > 0).length;
      push('unsupportedSynthesis', cited === conclusions.length ? 2 : cited > 0 ? 1 : 0,
        `${cited}/${conclusions.length} conclusions cite at least one reference`, 'deterministic');
    }
  }

  const total = scores.reduce((n, s) => n + s.score, 0);
  return { total, maxTotal: 24, grade: grade(total), scores };
}

module.exports = { reviewInvestigation, refSourceRoot, grade };
