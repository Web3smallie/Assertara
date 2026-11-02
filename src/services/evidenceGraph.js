/**
 * Evidence relationship graph (Capability 3, B7). Explicit typed edges
 * between evidence items so corroboration and contradiction are data,
 * not prose. Built in two phases:
 * - deterministic edges pre-reasoning (associations, chain checks,
 *   simulation, summary derivation) — printed in the prompt with E-ids
 *   and citable by the model;
 * - model-derived edges post-reasoning (grounding support, comparison
 *   outcomes, support failures, reconciliation overrides, plus
 *   validated model-proposed edges) — review trail in the bundle.
 *
 * CORROBORATES requires independent roots: two citations sharing one
 * underlying source never corroborate (see reasoningRubric roots).
 */

const EDGE_TYPES = [
  'SUPPORTS', 'CONTRADICTS', 'CONTEXTUALIZES', 'DERIVED_FROM',
  'CORROBORATES', 'ASSOCIATED_WITH', 'SUPERSEDES', 'INVALIDATES'
];

function refRoot(ref) {
  try {
    return require('./reasoningRubric').refSourceRoot(ref);
  } catch {
    return 'unknown';
  }
}

function splitRefs(refs) {
  const ui = [];
  const tx = [];
  for (const r of refs || []) {
    const root = refRoot(r);
    if (root === 'visual' || root === 'page' || root === 'association' || root === 'agentEvidence') ui.push(r);
    else if (r !== undefined) tx.push(r);
  }
  return { ui, tx };
}

function buildDeterministicEdges({ associations, chainVerification, simReconciliation, summaryStatus, subcalls, actionElements } = {}) {
  const edges = [];
  const links = (associations && Array.isArray(associations.links)) ? associations.links : [];
  for (const link of links) {
    const members = Array.isArray(link.members) ? link.members : [];
    if (members.length < 2) continue;
    const a = members[0].regionId || members[0].id || '?';
    const b = members[1].regionId || members[1].id || '?';
    edges.push({
      type: link.kind === 'warning-context' ? 'CONTEXTUALIZES' : 'ASSOCIATED_WITH',
      from: a, to: b,
      basis: `${link.method || 'linked'}${link.rationale ? `: ${String(link.rationale).slice(0, 140)}` : ''}`,
      origin: 'deterministic', provenance: `association:${link.linkId || '?'}`
    });
  }
  const checks = (chainVerification && Array.isArray(chainVerification.checks)) ? chainVerification.checks : [];
  for (const c of checks) {
    if (!c || (c.status !== 'fail' && c.status !== 'pass')) continue;
    if (c.status === 'fail') {
      edges.push({
        type: 'CONTRADICTS', from: 'chain', to: 'tx',
        basis: `${c.checkId}: ${String(c.explanation || '').slice(0, 140)}`,
        origin: 'deterministic', provenance: `chainVerification:${c.checkId}`
      });
    } else if (c.checkId === 'BALANCE_SUFFICIENCY' || c.checkId === 'CHAIN_IDENTITY' || c.checkId === 'CODE_CALL_CONSISTENCY') {
      edges.push({
        type: 'CORROBORATES', from: 'chain', to: 'tx',
        basis: `${c.checkId}: ${String(c.explanation || '').slice(0, 140)}`,
        origin: 'deterministic', provenance: `chainVerification:${c.checkId}`
      });
    }
  }
  if (simReconciliation && simReconciliation.status === 'CONTRADICT') {
    edges.push({
      type: 'CONTRADICTS', from: 'simulation', to: 'tx',
      basis: String(simReconciliation.reason || 'measured execution contradicts decoded expectations').slice(0, 160),
      origin: 'deterministic', provenance: 'simReconciliation'
    });
  } else if (simReconciliation && simReconciliation.status === 'AGREE') {
    edges.push({
      type: 'CORROBORATES', from: 'simulation', to: 'tx',
      basis: 'measured execution consistent with decoded expectations',
      origin: 'deterministic', provenance: 'simReconciliation'
    });
  }
  const sumRegions = summaryStatus && Array.isArray(summaryStatus.regionIds) ? summaryStatus.regionIds : [];
  for (const id of sumRegions) {
    edges.push({
      type: 'DERIVED_FROM', from: 'intent', to: id,
      basis: 'investigation intent text derived from summary regions',
      origin: 'deterministic', provenance: 'summarySelection'
    });
  }
  // Capability 4 B4: nested-call structure. Each subcall derives from
  // its parent (the transaction for depth 1); unknown inners contradict
  // any assumption that the batch is fully understood.
  const subs = (subcalls && Array.isArray(subcalls.subcalls)) ? subcalls.subcalls : [];
  for (const s of subs) {
    if (!s || typeof s.subcallId !== 'string') continue;
    edges.push({
      type: 'DERIVED_FROM', from: s.parentId || 'tx', to: s.subcallId,
      basis: `nested call path ${s.path || '?'}: ${s.functionName || '?'} (${s.standard || '?'})`,
      origin: 'deterministic', provenance: `subcall:${s.subcallId}`
    });
    if (s.unknown === true || s.depthLimited === true) {
      edges.push({
        type: 'CONTRADICTS', from: s.subcallId, to: 'tx',
        basis: `uninterpretable nested call contradicts full understanding of the batch${s.selector ? ` (selector ${s.selector})` : ''}`,
        origin: 'deterministic', provenance: `subcall:${s.subcallId}`
      });
    }
  }
  // Capability 4 B10: action-element structure. Each element is
  // associated with its observed container; a display verb naming a
  // DIFFERENT operation family than the decoded function contradicts
  // the presentation. Display agreement never corroborates the tx.
  const aes = (actionElements && Array.isArray(actionElements.elements)) ? actionElements.elements : [];
  for (const e of aes) {
    if (!e || typeof e.elementId !== 'string') continue;
    if (e.container && typeof e.container.regionId === 'string') {
      edges.push({
        type: 'ASSOCIATED_WITH', from: e.elementId, to: e.container.regionId,
        basis: `action '${String(e.verb || e.actionText || '').slice(0, 60)}' observed inside container ${e.container.regionId} (display layout only)`,
        origin: 'deterministic', provenance: `actionElement:${e.elementId}`
      });
    }
    if (e.verbConsistent === false) {
      edges.push({
        type: 'CONTRADICTS', from: e.elementId, to: 'tx',
        basis: String(e.consistencyNote || 'display verb contradicts decoded function').slice(0, 160),
        origin: 'deterministic', provenance: `actionElement:${e.elementId}`
      });
    }
  }
  return edges;
}

function buildModelDerivedEdges({ grounding, intentComparison, supportValidation, reconciliation, modelEdges } = {}) {
  const edges = [];
  const claims = (grounding && Array.isArray(grounding.claims)) ? grounding.claims : [];
  claims.forEach((c, i) => {
    if (c && c.status === 'supported' && Array.isArray(c.regionIds)) {
      for (const id of c.regionIds) {
        edges.push({
          type: 'SUPPORTS', from: id, to: `claim#${i}`,
          basis: 'grounded citation with readable region OCR',
          origin: 'deterministic', provenance: 'grounding'
        });
      }
    }
  });
  const fields = (intentComparison && Array.isArray(intentComparison.fields)) ? intentComparison.fields : [];
  for (const f of fields) {
    if (!f || (f.status !== 'MATCH' && f.status !== 'MISMATCH')) continue;
    const { ui, tx } = splitRefs(f.evidenceRefs || []);
    if (ui.length === 0 || tx.length === 0) continue;
    if (f.status === 'MATCH') {
      const roots = [...new Set([...ui, ...tx].map(refRoot).filter((r) => r !== 'unknown'))];
      if (roots.length >= 2) {
        edges.push({
          type: 'CORROBORATES', from: ui[0], to: tx[0],
          basis: `field ${f.field}: independent roots agree (${roots.join('+')})`,
          origin: 'deterministic', provenance: 'intentComparison'
        });
      }
    } else {
      edges.push({
        type: 'CONTRADICTS', from: ui[0], to: tx[0],
        basis: `field ${f.field}: ${String(f.reason || 'conflict').slice(0, 140)}`,
        origin: 'deterministic', provenance: 'intentComparison'
      });
    }
  }
  const fails = (supportValidation && Array.isArray(supportValidation.failures)) ? supportValidation.failures : [];
  for (const fl of fails) {
    edges.push({
      type: 'INVALIDATES', from: fl.where || '?', to: String(fl.reason || '').slice(0, 120),
      basis: `citation support failure: ${fl.kind || 'unknown'}`,
      origin: 'deterministic', provenance: 'supportValidation'
    });
  }
  const overridden = (reconciliation && Array.isArray(reconciliation.overridden)) ? reconciliation.overridden : [];
  for (const o of overridden) {
    edges.push({
      type: 'SUPERSEDES', from: 'deterministic-comparison', to: String(o).slice(0, 120),
      basis: 'deterministic mismatch supersedes model resolution',
      origin: 'deterministic', provenance: 'reconciliation'
    });
  }
  for (const e of Array.isArray(modelEdges) ? modelEdges : []) {
    edges.push({ ...e, origin: 'model' });
  }
  return edges;
}

function assignEdgeIds(edges, startSeq = 1) {
  let seq = startSeq;
  return edges.map((e) => ({ edgeId: `E-${String(seq++).padStart(3, '0')}`, ...e }));
}

// Model-proposed edges: strict admission. Endpoints must be registry
// refs (validated by caller via classifyRef) or indexed investigation
// statements; types must be in-enum. Invalid edges are rejected with
// reasons, never merged.
const INDEXED_RE = /^(conclusions|discrepancies|contradictions|competingExplanations)\[\d+\]$/;

function validateModelEdges(edges, isKnownRef) {
  const merged = [];
  const rejected = [];
  if (!Array.isArray(edges)) return { merged, rejected: [{ index: -1, error: 'evidenceRelationships must be an array' }] };
  edges.slice(0, 40).forEach((e, i) => {
    const bad = (error) => rejected.push({ index: i, error });
    if (!e || typeof e !== 'object') return bad('edge must be an object');
    if (!EDGE_TYPES.includes(e.type)) return bad(`unknown edge type: ${String(e.type).slice(0, 40)}`);
    if (typeof e.from !== 'string' || typeof e.to !== 'string') return bad('from/to must be strings');
    const known = (id) => INDEXED_RE.test(id) || (typeof isKnownRef === 'function' && isKnownRef(id));
    if (!known(e.from)) return bad(`unknown endpoint: ${e.from.slice(0, 60)}`);
    if (!known(e.to)) return bad(`unknown endpoint: ${e.to.slice(0, 60)}`);
    if (typeof e.basis !== 'string' || e.basis.length === 0) return bad('basis required');
    merged.push({ type: e.type, from: e.from.slice(0, 160), to: e.to.slice(0, 160), basis: e.basis.slice(0, 300), provenance: 'model-proposed' });
  });
  if (edges.length > 40) rejected.push({ index: 40, error: 'edge cap of 40 exceeded' });
  return { merged, rejected };
}

module.exports = {
  EDGE_TYPES,
  buildDeterministicEdges,
  buildModelDerivedEdges,
  assignEdgeIds,
  validateModelEdges
};
