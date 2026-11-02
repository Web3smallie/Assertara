/**
 * Evidence-grounded reasoning validation (Capability 2).
 *
 * Shape validation (validateModelResult) proves a response parses; this
 * module proves it is GROUNDED: every evidence reference must resolve to
 * evidence actually supplied, conclusions must cite support, and
 * fabricated references must fail safe. Pure and deterministic — no
 * model calls, no heuristics.
 *
 * Reference vocabulary (also stated in the system schema spec):
 * - region IDs printed in the prompt ([R-001], ...), genuine only
 * - finding rule IDs from decodedTx.ruleFindings
 * - section keys: title, url, dom, ocr, params, chain, freshness,
 *   labels, association, summarySelection, sam, tx, visual, page
 * - param:<name> for decoded parameter names
 */

const SECTION_KEYS = [
  'title', 'url', 'dom', 'ocr', 'findings', 'params', 'chain', 'freshness',
  'labels', 'association', 'summarySelection', 'sam', 'tx', 'visual', 'page',
  'simulation', 'agentEvidence', 'calldata', 'proxy', 'identity', 'deadlines', 'history',
  'visualRoles', 'effects', 'explicitIntent'
];

// Closed alias map for reference tokens. Live models drift toward
// descriptive names (pageTitle, txDecoding) for printed sections; rather
// than rejecting unambiguous aliases as fabrication, they canonicalize
// here — deterministically, and every normalization is recorded in the
// validation result so nothing resolves silently. Anything outside this
// map AND the registry is fabricated.
const ALIAS_MAP = {
  pageTitle: 'title',
  pageURL: 'url',
  pageUrl: 'url',
  domText: 'dom',
  pageText: 'dom',
  visibleText: 'dom',
  txDecoding: 'tx',
  transaction: 'tx',
  decodedTx: 'tx',
  decodedTransaction: 'tx',
  securityRules: 'findings',
  ruleFindings: 'findings',
  triggeredRules: 'findings',
  chainState: 'chain',
  chainData: 'chain',
  samDetections: 'sam',
  samRegions: 'sam',
  ocrText: 'ocr',
  summary: 'summarySelection'
};

function resolveRef(ref) {
  if (typeof ref !== 'string') return { canonical: ref, aliased: false };
  if (Object.prototype.hasOwnProperty.call(ALIAS_MAP, ref)) {
    return { canonical: ALIAS_MAP[ref], aliased: true };
  }
  // Bracketed IDs ([R-001]) copy the prompt's display format; strip one
  // layer so unambiguous formatting variants canonicalize. Only one
  // layer: [[R-001]] stays unknown (fabricated if cited).
  if (ref.length >= 3) {
    const first = ref[0];
    const last = ref[ref.length - 1];
    if ((first === '[' && last === ']') || (first === '(' && last === ')')) {
      const inner = ref.slice(1, -1);
      if (inner.length > 0 && !/[[()\]]/.test(inner)) return { canonical: inner, aliased: true };
    }
  }
  return { canonical: ref, aliased: false };
}

const FALLBACK_ID_RE = /^R-FALLBACK/i;

function buildEvidenceRegistry({ pageContext, decodedTx, visualMeta, extra } = {}) {
  const regions = [];
  const syntheticRegions = [];
  const texts = visualMeta && Array.isArray(visualMeta.regionTexts) ? visualMeta.regionTexts : [];
  for (const r of texts) {
    if (r && typeof r.regionId === 'string' && r.regionId.length > 0) {
      if (r.synthetic === true || FALLBACK_ID_RE.test(r.regionId)) syntheticRegions.push(r.regionId);
      else regions.push(r.regionId);
    }
  }
  const fb = visualMeta && Array.isArray(visualMeta.fallbackRecords) ? visualMeta.fallbackRecords : [];
  for (const r of fb) {
    if (r && typeof r.regionId === 'string' && r.regionId.length > 0) syntheticRegions.push(r.regionId);
  }
  const findings = [];
  const rules = decodedTx && Array.isArray(decodedTx.ruleFindings) ? decodedTx.ruleFindings : [];
  for (const f of rules) {
    if (f && typeof f.ruleId === 'string' && f.ruleId.length > 0) findings.push(f.ruleId);
  }
  const checks = [];
  const verify = extra && extra.chainVerification;
  if (verify && Array.isArray(verify.checks)) {
    for (const c of verify.checks) {
      if (c && typeof c.checkId === 'string' && c.checkId.length > 0) checks.push(c.checkId);
    }
  }
  const params = [];
  const p = decodedTx && decodedTx.parameters && typeof decodedTx.parameters === 'object' ? decodedTx.parameters : {};
  for (const k of Object.keys(p)) {
    if (typeof k === 'string' && k.length > 0 && k.length <= 128) params.push(k);
  }
  // Capability 4 B4 live fix (CS5 record inv_mvvfynlf): the model,
  // instructed by S4 to examine every subcall, cited the inner
  // approve's spender — correctly, but the registry only knew
  // top-level parameter names and flagged it fabricated. Inner-call
  // parameter names join the registry: a param: citation proves the
  // parameter exists in the decoded batch (support validation still
  // judges whether it fits the statement).
  let treeSubs = [];
  try {
    treeSubs = require('./nestedCalls').buildSubcallTree(decodedTx).subcalls || [];
  } catch {
    treeSubs = [];
  }
  for (const s of treeSubs) {
    const sp = s && s.parameters && typeof s.parameters === 'object' ? s.parameters : {};
    for (const k of Object.keys(sp)) {
      if (typeof k === 'string' && k.length > 0 && k.length <= 128) params.push(k);
    }
  }
  void pageContext;
  const edges = [];
  const graph = extra && extra.evidenceGraph;
  const printed = graph && Array.isArray(graph.edges) ? graph.edges : [];
  for (const e of printed) {
    if (e && typeof e.edgeId === 'string' && e.edgeId.length > 0) edges.push(e.edgeId);
  }
  const external = [];
  const agentEv = extra && extra.agentEvidence;
  const adm = agentEv && Array.isArray(agentEv.admitted) ? agentEv.admitted : [];
  for (const e of adm) {
    if (e && typeof e.evidenceId === 'string' && e.evidenceId.length > 0) external.push(e.evidenceId);
  }
  // Capability 4 B4: subcall IDs derive from the same decoded batch the
  // packer prints, so model citations of printed [SC-xxx] IDs resolve.
  // Reuses the tree built above for inner parameter names.
  const subcalls = [];
  for (const s of treeSubs) {
    if (s && typeof s.subcallId === 'string') subcalls.push(s.subcallId);
  }
  // Capability 4 B10: action-element IDs come from the controller's
  // pre-model computation — the same array the packer prints — so
  // model citations of printed [AE-xxx] IDs resolve here and stay
  // fabricated when no elements were supplied.
  const visualElements = [];
  const ve = extra && extra.visualElements;
  const veList = ve && Array.isArray(ve.elements) ? ve.elements : [];
  for (const e of veList) {
    if (e && typeof e.elementId === 'string') visualElements.push(e.elementId);
  }
  // Capability 5 B2: effect IDs resolve exactly like action-element
  // IDs — the same array the packer prints, so printed [EF-xxx]
  // citations resolve and unprinted ones stay fabricated.
  const effectIds = [];
  const ef = extra && extra.effects;
  const efList = ef && Array.isArray(ef.effects) ? ef.effects : [];
  for (const e of efList) {
    if (e && typeof e.effectId === 'string') effectIds.push(e.effectId);
  }
  // Capability 5 B8: explicit-statement IDs resolve exactly like
  // effect IDs — printed [EI-xxx] citations resolve, unprinted
  // ones stay fabricated.
  const explicitIntentIds = [];
  const ei = extra && extra.explicitIntent;
  const eiList = ei && Array.isArray(ei.statements) ? ei.statements : [];
  for (const s of eiList) {
    if (s && typeof s.id === 'string') explicitIntentIds.push(s.id);
  }
  return {
    regions: [...new Set(regions)],
    syntheticRegions: [...new Set(syntheticRegions)],
    findings: [...new Set(findings)],
    checks: [...new Set(checks)],
    external: [...new Set(external)],
    edges: [...new Set(edges)],
    subcalls: [...new Set(subcalls)],
    visualElements: [...new Set(visualElements)],
    effectIds: [...new Set(effectIds)],
    explicitIntentIds: [...new Set(explicitIntentIds)],
    params,
    sections: [...SECTION_KEYS]
  };
}

// Classify one reference: ok | synthetic (supplied but fallback-tier) |
// fabricated (never supplied) | malformed (not a string).
function classifyRef(ref, registry) {
  if (typeof ref !== 'string' || ref.length === 0 || ref.length > 256) return 'malformed';
  const canonical = resolveRef(ref).canonical;
  const reg = registry || {};
  if ((reg.regions || []).includes(canonical)) return 'ok';
  if ((reg.syntheticRegions || []).includes(canonical)) return 'synthetic';
  if ((reg.findings || []).includes(canonical)) return 'ok';
  if ((reg.checks || []).includes(canonical)) return 'ok';
  if ((reg.external || []).includes(canonical)) return 'ok';
  if ((reg.edges || []).includes(canonical)) return 'ok';
  if ((reg.subcalls || []).includes(canonical)) return 'ok';
  if ((reg.visualElements || []).includes(canonical)) return 'ok';
  if ((reg.effectIds || []).includes(canonical)) return 'ok';
  if ((reg.explicitIntentIds || []).includes(canonical)) return 'ok';
  if ((reg.sections || []).includes(canonical)) return 'ok';
  if (canonical.startsWith('param:')) {
    const name = canonical.slice('param:'.length);
    if (name.length > 0 && (reg.params || []).includes(name)) return 'ok';
    return 'fabricated';
  }
  return 'fabricated';
}

function isStringArray(v) {
  return Array.isArray(v) && v.every((s) => typeof s === 'string');
}

function checkShape(inv) {
  const errors = [];
  if (!inv || typeof inv !== 'object' || Array.isArray(inv)) return ['investigation must be an object'];
  if (typeof inv.objective !== 'string') errors.push('investigation.objective must be a string');
  if (!Array.isArray(inv.evidenceInventory)) errors.push('investigation.evidenceInventory must be an array');
  if (!Array.isArray(inv.sourceAssessments)) errors.push('investigation.sourceAssessments must be an array');
  for (const k of ['intentInterpretation', 'executionAnalysis', 'parameterAnalysis']) {
    const s = inv[k];
    if (!s || typeof s !== 'object' || typeof s.statement !== 'string' || !isStringArray(s.basisRefs || [])) {
      errors.push(`investigation.${k} must be {statement, basisRefs[]}`);
    }
  }
  // Capability 5 B8: model intent is inference by construction. Any
  // other kind (or a missing one) means the model presented its
  // reading as something stronger — reject the shape.
  if (!inv.intentInterpretation || inv.intentInterpretation.kind !== 'inferred') {
    errors.push('investigation.intentInterpretation.kind must be "inferred"');
  }
  if (!Array.isArray(inv.discrepancies)) errors.push('investigation.discrepancies must be an array');
  if (!Array.isArray(inv.contradictions)) errors.push('investigation.contradictions must be an array');
  if (!Array.isArray(inv.competingExplanations)) errors.push('investigation.competingExplanations must be an array');
  if (!Array.isArray(inv.suspiciousBehaviours)) errors.push('investigation.suspiciousBehaviours must be an array');
  if (!isStringArray(inv.missingEvidence || [])) errors.push('investigation.missingEvidence must be string[]');
  if (!inv.uncertainty || typeof inv.uncertainty !== 'object' || typeof inv.uncertainty.explanation !== 'string') {
    errors.push('investigation.uncertainty must be {level, explanation}');
  }
  if (!Array.isArray(inv.conclusions)) errors.push('investigation.conclusions must be an array');
  if (!Array.isArray(inv.recommendations)) errors.push('investigation.recommendations must be an array');
  if (!isStringArray(inv.furtherInvestigation || [])) errors.push('investigation.furtherInvestigation must be string[]');
  if (inv.evidenceRelationships !== undefined) {
    if (!Array.isArray(inv.evidenceRelationships)) errors.push('investigation.evidenceRelationships must be an array');
    else {
      inv.evidenceRelationships.forEach((e, i) => {
        if (!e || typeof e !== 'object' || typeof e.type !== 'string' || typeof e.from !== 'string'
            || typeof e.to !== 'string' || typeof e.basis !== 'string') {
          errors.push(`investigation.evidenceRelationships[${i}] must be {type, from, to, basis}`);
        }
      });
    }
  }
  return errors;
}

// Walk every *Refs/basisRefs/sources array in the investigation and
// classify each entry. Sources in contradictions are free-form source
// names, not registry refs, so they are shape-checked only.
function collectRefIssues(inv, registry) {
  const fabricated = [];
  const synthetic = [];
  const malformed = [];
  const normalized = [];
  const visit = (refs, where) => {
    if (!Array.isArray(refs)) return;
    refs.forEach((r, i) => {
      const resolved = resolveRef(r);
      if (resolved.aliased) normalized.push({ where: `${where}[${i}]`, from: String(r).slice(0, 120), to: resolved.canonical });
      const c = classifyRef(r, registry);
      if (c === 'fabricated') fabricated.push({ where: `${where}[${i}]`, ref: String(r).slice(0, 120) });
      else if (c === 'synthetic') synthetic.push({ where: `${where}[${i}]`, ref: String(r).slice(0, 120) });
      else if (c === 'malformed') malformed.push({ where: `${where}[${i}]` });
    });
  };
  for (const k of ['intentInterpretation', 'executionAnalysis', 'parameterAnalysis']) {
    if (inv[k] && typeof inv[k] === 'object') visit(inv[k].basisRefs, k);
  }
  for (const d of inv.discrepancies || []) {
    if (!d || typeof d !== 'object') continue;
    visit(d.supportingRefs, 'discrepancy.supportingRefs');
    visit(d.contradictingRefs, 'discrepancy.contradictingRefs');
  }
  for (const c of inv.competingExplanations || []) {
    if (!c || typeof c !== 'object') continue;
    visit(c.supportingRefs, 'competingExplanations.supportingRefs');
    visit(c.contradictingRefs, 'competingExplanations.contradictingRefs');
  }
  for (const s of inv.suspiciousBehaviours || []) {
    if (s && typeof s === 'object') visit(s.basisRefs, 'suspiciousBehaviours');
  }
  inv.conclusions = Array.isArray(inv.conclusions) ? inv.conclusions : [];
  const unsupportedConclusions = [];
  inv.conclusions.forEach((c, i) => {
    if (!c || typeof c !== 'object') return;
    visit(c.supportingRefs, `conclusions[${i}].supportingRefs`);
    visit(c.contradictingRefs, `conclusions[${i}].contradictingRefs`);
    if (!Array.isArray(c.supportingRefs) || c.supportingRefs.length === 0) {
      unsupportedConclusions.push(i);
    }
  });
  for (const r of inv.recommendations || []) {
    if (r && typeof r === 'object') visit(r.basisRefs, 'recommendations');
  }
  return { fabricated, synthetic, malformed, normalized, unsupportedConclusions };
}

function validateInvestigation(inv, registry) {
  const shapeErrors = checkShape(inv);
  if (shapeErrors.length > 0) {
    return { ok: false, shapeErrors, fabricated: [], synthetic: [], malformed: [], normalized: [], unsupportedConclusions: [] };
  }
  const refs = collectRefIssues(inv, registry || {});
  return { ok: refs.fabricated.length === 0 && refs.malformed.length === 0, shapeErrors: [], ...refs };
}

module.exports = {
  SECTION_KEYS,
  ALIAS_MAP,
  buildEvidenceRegistry,
  classifyRef,
  resolveRef,
  validateInvestigation
};
