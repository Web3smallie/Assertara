/**
 * Evidence-support validation (Capability 3, B4). Answers the question
 * reference-existence checks cannot: does the cited evidence actually
 * support the statement? Deterministic spot-checks where possible;
 * anything semantic is explicitly marked needs-review, never silently
 * passed and never pretended to be entailment-proven.
 *
 * Hard failures (fabrication-adjacent, downgrade MATCH):
 * - QUOTED_NOT_IN_CITED: a quoted span is absent from every cited
 *   source's text.
 * - QUOTED_NOWHERE: a quoted span matches no supplied evidence at all.
 * Needs-review flags (hold for REVIEW, never downgrade alone):
 * - SEMANTIC_UNVERIFIED: no quotable spans; support is semantic.
 * - WEAK_FOUNDATION: support roots are page-claims only.
 * - SHARED_SOURCE: multiple citations, one underlying root.
 * - SUPPORT_COUNTER_OVERLAP: same ref backs both sides.
 * - ABSOLUTE_LANGUAGE: certainty words beyond the evidence (heuristic).
 */

const QUOTE_RE = /"([^"]{4,200})"/g;
const ABSOLUTE_RE = /\b(definitely|certainly|proves|prove|proven|guarantees|guarantee|impossible|without doubt|with certainty)\b/i;
// Capability 5 B8: speech-act verbs that present model inference as
// quotable user/agent words. Only fires without quoted spans.
const EXPLICITNESS_RE = /\bexplicitly\b|\b(users?|agents?)\b[^.!?]{0,60}\b(stated|said|states|confirmed|authorized|authorised|requested|instructed|declared|confirmed)\b/i;

function buildSourceTexts({ regionTexts, pageContext, decodedTx, chainState, combinedOcr, associationsSummary, extraTexts, agentEvidence } = {}) {
  const texts = new Map();
  for (const r of Array.isArray(regionTexts) ? regionTexts : []) {
    if (r && typeof r.regionId === 'string') texts.set(r.regionId, typeof r.text === 'string' ? r.text : '');
  }
  const findings = (decodedTx && Array.isArray(decodedTx.ruleFindings) ? decodedTx.ruleFindings : [])
    .map((f) => `${f.ruleId} [${f.severity || 'UNKNOWN'}] ${f.description || ''}`);
  for (const f of decodedTx && Array.isArray(decodedTx.ruleFindings) ? decodedTx.ruleFindings : []) {
    if (f && typeof f.ruleId === 'string') {
      texts.set(f.ruleId, `${f.ruleId} [${f.severity || 'UNKNOWN'}] ${f.description || ''}`);
    }
  }
  const params = (decodedTx && decodedTx.parameters && typeof decodedTx.parameters === 'object') ? decodedTx.parameters : {};
  for (const k of Object.keys(params)) {
    try { texts.set(`param:${k}`, JSON.stringify(params[k])); } catch { texts.set(`param:${k}`, String(params[k])); }
  }
  const page = pageContext && typeof pageContext === 'object' ? pageContext : {};
  texts.set('title', typeof page.title === 'string' ? page.title : '');
  texts.set('url', typeof page.url === 'string' ? page.url : '');
  texts.set('dom', typeof page.visibleText === 'string' ? page.visibleText : '');
  texts.set('page', `${texts.get('title')}\n${texts.get('url')}\n${texts.get('dom')}`);
  texts.set('ocr', typeof combinedOcr === 'string' ? combinedOcr : '');
  texts.set('visual', texts.get('ocr'));
  texts.set('findings', findings.join('\n'));
  try { texts.set('params', JSON.stringify(params)); } catch { texts.set('params', ''); }
  texts.set('tx', `${(decodedTx && decodedTx.contract) || ''} ${(decodedTx && decodedTx.contractName) || ''} ${(decodedTx && decodedTx.functionName) || ''} ${(decodedTx && decodedTx.valueEth) || ''}`);
  texts.set('chain', chainState && typeof chainState === 'object' ? JSON.stringify(chainState.states || chainState.status || '') : '');
  const extra = extraTexts && typeof extraTexts === 'object' ? extraTexts : {};
  for (const k of ['freshness', 'labels', 'summarySelection', 'sam', 'simulation', 'agentEvidence', 'calldata', 'identity', 'deadlines', 'history', 'visualRoles', 'effects', 'explicitIntent']) {
    texts.set(k, typeof extra[k] === 'string' ? extra[k] : '');
  }
  texts.set('association', typeof associationsSummary === 'string' ? associationsSummary : '');
  for (const e of (agentEvidence && Array.isArray(agentEvidence.admitted) ? agentEvidence.admitted : [])) {
    if (e && typeof e.evidenceId === 'string' && typeof e.content === 'string') texts.set(e.evidenceId, e.content);
  }
  // Capability 4 B4: per-subcall texts so quoted spans about nested
  // operations check against the subcall's own record.
  try {
    const tree = require('./nestedCalls').buildSubcallTree(decodedTx);
    for (const s of tree.subcalls) {
      if (s && typeof s.subcallId === 'string') {
        texts.set(s.subcallId, `${s.subcallId} path ${s.path} ${s.functionName} (${s.standard}) ${(s.effect && s.effect.summary) || ''} selector ${s.selector || 'none'}`);
      }
    }
  } catch {
    // No subcalls derivable: no subcall texts.
  }
  const capped = new Map();
  for (const [k, v] of texts) capped.set(k, typeof v === 'string' ? v.slice(0, 4000) : '');
  return capped;
}

function rootOfRef(ref) {
  try {
    return require('./reasoningRubric').refSourceRoot(ref);
  } catch {
    return 'unknown';
  }
}

function quotedSpans(statement) {
  const out = [];
  QUOTE_RE.lastIndex = 0;
  let m;
  while ((m = QUOTE_RE.exec(typeof statement === 'string' ? statement : '')) !== null) {
    out.push(m[1]);
  }
  return out;
}

function checkItem({ where, statement, supportingRefs, contradictingRefs, sourceTexts }) {
  const failures = [];
  const needsReview = [];
  const refs = Array.isArray(supportingRefs) ? supportingRefs : [];
  const citedText = refs.map((r) => sourceTexts.get(r) || '').join('\n').toLowerCase();
  const allText = [...sourceTexts.values()].join('\n').toLowerCase();
  const spans = quotedSpans(statement);
  if (spans.length > 0) {
    for (const span of spans) {
      const needle = span.toLowerCase();
      if (!citedText.includes(needle)) {
        if (allText.includes(needle)) {
          failures.push({ where, kind: 'QUOTED_NOT_IN_CITED', reason: `quoted text not found in cited sources: "${span.slice(0, 80)}"` });
        } else {
          failures.push({ where, kind: 'QUOTED_NOWHERE', reason: `quoted text matches no supplied evidence: "${span.slice(0, 80)}"` });
        }
      }
    }
  } else {
    needsReview.push({ where, kind: 'SEMANTIC_UNVERIFIED', reason: 'no quotable spans; support is semantic and unverified deterministically' });
  }
  const roots = [...new Set(refs.map(rootOfRef).filter((r) => r !== 'unknown'))];
  if (refs.length > 0 && roots.length === 1 && roots[0] === 'page') {
    needsReview.push({ where, kind: 'WEAK_FOUNDATION', reason: 'supported only by untrusted page claims' });
  }
  if (refs.length >= 2 && roots.length === 1) {
    needsReview.push({ where, kind: 'SHARED_SOURCE', reason: `${refs.length} citations share one underlying root (${roots[0]}); not independent corroboration` });
  }
  const contra = Array.isArray(contradictingRefs) ? contradictingRefs : [];
  const overlap = refs.filter((r) => contra.includes(r));
  if (overlap.length > 0) {
    needsReview.push({ where, kind: 'SUPPORT_COUNTER_OVERLAP', reason: `refs back both sides: ${overlap.slice(0, 3).join(', ')}` });
  }
  if (ABSOLUTE_RE.test(typeof statement === 'string' ? statement : '')) {
    needsReview.push({ where, kind: 'ABSOLUTE_LANGUAGE', reason: 'absolute certainty words exceed checkable evidence (heuristic)' });
  }
  return { failures, needsReview };
}

function validateSupport({ investigation, sourceTexts }) {
  const texts = sourceTexts instanceof Map ? sourceTexts : new Map();
  const failures = [];
  const needsReview = [];
  let items = 0;
  if (!investigation || typeof investigation !== 'object') {
    return { present: false, items: 0, failures, needsReview };
  }
  const visit = (where, statement, supportingRefs, contradictingRefs) => {
    items += 1;
    const r = checkItem({ where, statement, supportingRefs, contradictingRefs, sourceTexts: texts });
    failures.push(...r.failures);
    needsReview.push(...r.needsReview);
  };
  for (const [i, c] of (investigation.conclusions || []).entries()) {
    if (c && typeof c === 'object') visit(`conclusions[${i}]`, c.statement, c.supportingRefs, c.contradictingRefs);
  }
  for (const [i, d] of (investigation.discrepancies || []).entries()) {
    if (d && typeof d === 'object') visit(`discrepancies[${i}]`, d.statement, d.supportingRefs, d.contradictingRefs);
  }
  for (const [i, c] of (investigation.competingExplanations || []).entries()) {
    if (c && typeof c === 'object') visit(`competingExplanations[${i}]`, c.explanation, c.supportingRefs, c.contradictingRefs);
  }
  // Capability 5 B8: the intent statement is inference. Quoted spans
  // in it validate like any other quote; explicitness language
  // without a quote holds review (inference posing as quotation).
  // No other flags: unquoted inference is the normal case, not a
  // support failure.
  const intent = investigation.intentInterpretation;
  if (intent && typeof intent === 'object' && typeof intent.statement === 'string') {
    items += 1;
    const refs = Array.isArray(intent.basisRefs) ? intent.basisRefs : [];
    const citedText = refs.map((r) => texts.get(r) || '').join('\n').toLowerCase();
    const allText = [...texts.values()].join('\n').toLowerCase();
    const spans = quotedSpans(intent.statement);
    for (const span of spans) {
      const needle = span.toLowerCase();
      if (!citedText.includes(needle)) {
        failures.push({
          where: 'intentInterpretation',
          kind: allText.includes(needle) ? 'QUOTED_NOT_IN_CITED' : 'QUOTED_NOWHERE',
          reason: `intent quote matches ${allText.includes(needle) ? 'uncited evidence' : 'no supplied evidence'}: "${span.slice(0, 80)}"`
        });
      }
    }
    if (spans.length === 0 && EXPLICITNESS_RE.test(intent.statement)) {
      needsReview.push({
        where: 'intentInterpretation',
        kind: 'EXPLICITNESS_UNQUOTED',
        reason: 'intent statement claims explicit user/agent words without quoting any; inference may be posing as quotation'
      });
    }
  }
  return { present: true, items, failures, needsReview };
}

module.exports = { buildSourceTexts, validateSupport, quotedSpans };
