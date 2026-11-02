/**
 * Visual-claim grounding validation (visual roadmap Phase 2).
 *
 * Checks model-produced visual claims against the CURRENT evaluation's
 * genuine region evidence. Pure and deterministic: identical inputs always
 * yield identical output.
 *
 * Critical separations enforced here:
 * - A claim's `value` is the model's INTERPRETATION; the validator attaches
 *   the OBSERVED OCR text and geometry alongside it, never confusing them.
 * - A valid region reference does NOT mean the interpretation is correct;
 *   status 'supported' means "evidence exists and is readable", nothing more.
 * - Model-supplied geometry or OCR fields are rejected as fabrication
 *   attempts; observed evidence always comes from the evaluation, never
 *   from the claim object.
 *
 * Status precedence: invalid > unsupported > ambiguous > supported.
 */

const CLAIM_TYPES = ['amount', 'asset', 'recipient', 'action', 'warning', 'approval'];

// Claim keys that would manufacture evidence. Any presence taints the claim.
const FABRICATION_GEOMETRY_KEYS = ['boundingBox', 'bbox', 'box', 'coordinates', 'coords', 'mask', 'polygon', 'region'];
const FABRICATION_TEXT_KEYS = ['ocr', 'ocrText', 'observedText', 'observed', 'regionText', 'evidenceText'];

const INVALID_REASONS = new Set([
  'malformed-claim',
  'unknown-claim-type',
  'model-supplied-geometry-rejected',
  'model-supplied-ocr-rejected',
  'malformed-region-id',
  'unknown-region',
  'synthetic-region',
  'unknown-association',
  'association-member-missing'
]);
const UNSUPPORTED_REASONS = new Set([
  'no-region-reference',
  'region-ocr-failed',
  'region-ocr-empty'
]);
const AMBIGUOUS_REASONS = new Set(['association-unresolved']);

function stripOneBracketLayer(id) {
  if (typeof id !== 'string' || id.length < 3) return id;
  const first = id[0];
  const last = id[id.length - 1];
  if ((first === '[' && last === ']') || (first === '(' && last === ')')) {
    const inner = id.slice(1, -1);
    if (inner.length > 0 && !/[[()\]]/.test(inner)) return inner;
  }
  return id;
}

function addReason(reasons, code) {
  if (!reasons.includes(code)) reasons.push(code);
}

function validateClaim(raw, index, ctx) {
  const record = {
    index,
    type: null,
    value: null,
    regionIds: [],
    associationIds: [],
    observed: [],
    relatedLinks: [],
    status: null,
    reasons: []
  };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    record.status = 'invalid';
    record.reasons.push('malformed-claim');
    return record;
  }

  for (const k of FABRICATION_GEOMETRY_KEYS) {
    if (raw[k] !== undefined) addReason(record.reasons, 'model-supplied-geometry-rejected');
  }
  for (const k of FABRICATION_TEXT_KEYS) {
    if (raw[k] !== undefined) addReason(record.reasons, 'model-supplied-ocr-rejected');
  }

  if (typeof raw.type === 'string' && CLAIM_TYPES.includes(raw.type)) {
    record.type = raw.type;
  } else {
    record.type = typeof raw.type === 'string' ? raw.type : null;
    addReason(record.reasons, 'unknown-claim-type');
  }
  if (typeof raw.value === 'string' && raw.value.length > 0) {
    record.value = raw.value;
  } else {
    addReason(record.reasons, 'malformed-claim');
  }

  if (Array.isArray(raw.regionIds)) {
    // One-layer bracket strip mirrors reasoningValidation: the prompt
    // prints [R-001] and models copy the brackets. Canonical form flows
    // downstream; raw forms are preserved for audit.
    record.regionIds = raw.regionIds.map(stripOneBracketLayer);
    record.rawRegionIds = [...raw.regionIds];
    if (raw.regionIds.length === 0) addReason(record.reasons, 'no-region-reference');
  } else {
    addReason(record.reasons, 'malformed-claim');
  }
  if (raw.associationIds === undefined) {
    record.associationIds = [];
  } else if (Array.isArray(raw.associationIds)
    && raw.associationIds.every((id) => typeof id === 'string' && id.length > 0)) {
    record.associationIds = [...raw.associationIds];
  } else {
    addReason(record.reasons, 'malformed-claim');
  }

  for (let ri = 0; ri < record.regionIds.length; ri += 1) {
    const id = record.regionIds[ri];
    const rawId = (record.rawRegionIds && record.rawRegionIds[ri] !== undefined) ? record.rawRegionIds[ri] : id;
    const note = id !== rawId ? { normalizedFrom: rawId } : {};
    if (typeof id !== 'string' || id.length === 0) {
      addReason(record.reasons, 'malformed-region-id');
      record.observed.push({ regionId: typeof id === 'string' ? id : null, available: false, issue: 'malformed-region-id', ...note });
      continue;
    }
    if (ctx.syntheticIds.has(id)) {
      addReason(record.reasons, 'synthetic-region');
      record.observed.push({ regionId: id, available: false, genuine: false, issue: 'synthetic-region', ...note });
      continue;
    }
    const reg = ctx.regionMap.get(id);
    if (!reg) {
      addReason(record.reasons, 'unknown-region');
      record.observed.push({ regionId: id, available: false, issue: 'unknown-region', ...note });
      continue;
    }
    if (reg.genuine === false) {
      addReason(record.reasons, 'synthetic-region');
      record.observed.push({ regionId: id, available: false, genuine: false, issue: 'synthetic-region', ...note });
      continue;
    }
    const ocr = reg.ocr || {};
    if (ocr.error) {
      addReason(record.reasons, 'region-ocr-failed');
      record.observed.push({
        regionId: id, available: true, genuine: true, text: null,
        empty: false, ocrError: ocr.error, boundingBox: { ...reg.boundingBox },
        issue: 'region-ocr-failed', ...note
      });
      continue;
    }
    if (typeof ocr.text !== 'string' || ocr.text.length === 0) {
      addReason(record.reasons, 'region-ocr-empty');
      record.observed.push({
        regionId: id, available: true, genuine: true, text: typeof ocr.text === 'string' ? ocr.text : null,
        empty: true, ocrError: null, boundingBox: { ...reg.boundingBox },
        issue: 'region-ocr-empty', ...note
      });
      continue;
    }
    record.observed.push({
      regionId: id, available: true, genuine: true, text: ocr.text,
      empty: false, ocrError: null, boundingBox: { ...reg.boundingBox },
      issue: null, ...note
    });
  }

  for (const assocId of record.associationIds) {
    const link = ctx.links.find((l) => l && l.linkId === assocId);
    const amb = !link && ctx.ambiguities.find((a) => a && a.ambiguityId === assocId);
    const found = link || amb;
    if (!found) {
      addReason(record.reasons, 'unknown-association');
      continue;
    }
    const members = found.members || [];
    const missing = members.some((m) => !m || !ctx.regionMap.has(m.regionId));
    if (missing) addReason(record.reasons, 'association-member-missing');
    if (amb) addReason(record.reasons, 'association-unresolved');
  }

  // Validator-computed cross-reference (not model-claimed): Phase 1 links
  // whose members include a claimed region, for downstream review.
  const claimed = new Set(record.regionIds.filter((id) => typeof id === 'string'));
  record.relatedLinks = ctx.links
    .filter((l) => l && Array.isArray(l.members) && l.members.some((m) => m && claimed.has(m.regionId)))
    .map((l) => l.linkId);

  if (record.reasons.some((r) => INVALID_REASONS.has(r))) record.status = 'invalid';
  else if (record.reasons.some((r) => UNSUPPORTED_REASONS.has(r))) record.status = 'unsupported';
  else if (record.reasons.some((r) => AMBIGUOUS_REASONS.has(r))) record.status = 'ambiguous';
  else record.status = 'supported';
  return record;
}

/**
 * Validate a model's visual claims against one evaluation's evidence.
 * @param {*} claims reasoningResult.visualClaims (any shape; never trusted).
 * @param {{regions: Array, associations: {links: Array, ambiguities: Array},
 *   syntheticRegionIds: Array}} evidence Current evaluation's evidence only.
 */
function validateVisualClaims(claims, evidence) {
  const ev = evidence || {};
  if (claims === undefined || claims === null) {
    return { status: 'not-evaluated', reason: 'no-structured-claims', claims: [] };
  }
  if (!Array.isArray(claims)) {
    return { status: 'not-evaluated', reason: 'malformed-claims', claims: [] };
  }
  const regions = Array.isArray(ev.regions) ? ev.regions : [];
  const links = Array.isArray(ev.associations?.links) ? ev.associations.links : [];
  const ambiguities = Array.isArray(ev.associations?.ambiguities) ? ev.associations.ambiguities : [];
  const ctx = {
    regionMap: new Map(regions.filter((r) => r && typeof r.regionId === 'string').map((r) => [r.regionId, r])),
    links,
    ambiguities,
    syntheticIds: new Set(Array.isArray(ev.syntheticRegionIds) ? ev.syntheticRegionIds : [])
  };
  const validated = claims.map((raw, index) => validateClaim(raw, index, ctx));
  const summary = { supported: 0, invalid: 0, ambiguous: 0, unsupported: 0 };
  for (const c of validated) summary[c.status] += 1;
  return { status: 'evaluated', reason: null, claims: validated, summary };
}

module.exports = { validateVisualClaims, CLAIM_TYPES };
