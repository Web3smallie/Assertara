/**
 * Deterministic geometric element association (visual roadmap Phase 1).
 *
 * Links displayed amounts, recipients, actions, and warnings using genuine
 * SAM bounding boxes plus per-region OCR. Pure: identical inputs always
 * yield identical output, regardless of input order.
 *
 * Honesty rules enforced here, not by convention:
 * - No text means no roles: empty, missing, or failed OCR never produces
 *   transaction facts.
 * - Non-genuine (synthetic/mock) regions are rejected, never linked.
 * - Ambiguous geometry yields explicit ambiguity records, never a guess.
 *   The only exception is same-region co-occurrence: roles observed in a
 *   single OCR read are directly evidenced, not inferred across space.
 * - Proximity is recorded as adjacency (method + measured gap in px), never
 *   as proof of semantic association; every rationale says so.
 * - Associations describe the DISPLAY ONLY. They never override decoded
 *   transaction facts and never claim the display matches the wallet tx.
 */

const ROLE_AMOUNT = 'amount';
const ROLE_RECIPIENT = 'recipient';
const ROLE_ACTION = 'action';
const ROLE_WARNING = 'warning';
const ROLES = { AMOUNT: ROLE_AMOUNT, RECIPIENT: ROLE_RECIPIENT, ACTION: ROLE_ACTION, WARNING: ROLE_WARNING };

// Conservative token list: an amount requires a number PLUS a known symbol,
// so bare numbers (proposal ids, counts, versions) never become amounts.
const TOKEN_SYMBOLS = [
  'ETH', 'WETH', 'STETH', 'WSTETH', 'USDC', 'USDT', 'DAI', 'WBTC',
  'UNI', 'LINK', 'AAVE', 'MKR', 'COMP', 'SNX', 'CRV', 'BAL', 'YFI',
  'SUSHI', 'FRAX'
];
const AMOUNT_RES = [
  new RegExp(`\\b\\d[\\d,]*(\\.\\d+)?\\s*(${TOKEN_SYMBOLS.join('|')})\\b`, 'i'),
  /\$\s*\d[\d,]*(\.\d{1,2})?\b/
];
const ADDRESS_RE = /0x[0-9a-fA-F]{40}/;
const ENS_RE = /\b[a-z0-9][a-z0-9-]*\.eth\b/i;
const ACTION_RE = /\b(swap|swapping|send|sending|approve|approving|approval|transfer|transferring|claim|claiming|mint|minting|stake|staking|unstake|deposit|withdraw|bridge|bridging|pay|payment)\b/i;
const WARNING_RE = /\b(warning|warn|risk|risky|caution|careful|danger|dangerous|suspicious|unverified|alert|phishing|scam|malicious|honeypot|revoke)\b/i;

// Structural adjacency threshold: edge gap at most this multiple of the
// smaller box dimension. A layout heuristic for candidacy, NOT a calibrated
// probability — proximity links always say so in their rationale.
const PROXIMITY_FACTOR = 3;

function classifyTextRoles(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const roles = [];
  if (AMOUNT_RES.some((re) => re.test(text))) roles.push(ROLE_AMOUNT);
  if (ADDRESS_RE.test(text) || ENS_RE.test(text)) roles.push(ROLE_RECIPIENT);
  if (ACTION_RE.test(text)) roles.push(ROLE_ACTION);
  if (WARNING_RE.test(text)) roles.push(ROLE_WARNING);
  return roles;
}

function boxEdges(b) {
  return { x1: b.x, y1: b.y, x2: b.x + b.width, y2: b.y + b.height };
}

// Mirrors cropImageRegion's validity rules: finite numbers, positive size,
// non-negative origin, and (when dims are known) an origin inside the image.
function validateBox(box, dims) {
  if (!box || typeof box !== 'object') return 'not-an-object';
  for (const k of ['x', 'y', 'width', 'height']) {
    if (typeof box[k] !== 'number' || !Number.isFinite(box[k])) return 'non-finite-coords';
  }
  if (box.width <= 0 || box.height <= 0) return 'non-positive-size';
  if (box.x < 0 || box.y < 0) return 'negative-origin';
  if (dims && Number.isInteger(dims.width) && Number.isInteger(dims.height)) {
    if (box.x >= dims.width || box.y >= dims.height) return 'origin-outside-image';
  }
  return null;
}

function boxArea(b) {
  return b.width * b.height;
}

function containsBox(outer, inner) {
  const o = boxEdges(outer);
  const i = boxEdges(inner);
  return o.x1 <= i.x1 && o.y1 <= i.y1 && i.x2 <= o.x2 && i.y2 <= o.y2
    && boxArea(outer) > boxArea(inner);
}

function boxGap(a, b) {
  const A = boxEdges(a);
  const B = boxEdges(b);
  const gx = Math.max(0, Math.max(A.x1, B.x1) - Math.min(A.x2, B.x2));
  const gy = Math.max(0, Math.max(A.y1, B.y1) - Math.min(A.y2, B.y2));
  return Math.round(Math.hypot(gx, gy) * 100) / 100;
}

function minDim(b) {
  return Math.min(b.width, b.height);
}

function byRegionId(a, b) {
  return String(a.regionId ?? '').localeCompare(String(b.regionId ?? ''));
}

/**
 * Associate classified regions geometrically.
 * @param {Array} regions Entries {regionId, label?, boundingBox,
 *   genuine?, synthetic?, ocr?: {text?, empty?, error?}}.
 * @param {{dims?: {width: number, height: number}}} opts Optional image
 *   dimensions for bounds validation.
 * @returns {{links: Array, ambiguities: Array, unassociated: Array,
 *   rejected: Array}} Deterministic for identical inputs.
 */
function associateRegions(regions, opts = {}) {
  const dims = opts.dims || null;
  const links = [];
  const ambiguities = [];
  const unassociated = [];
  const rejected = [];
  let linkSeq = 0;
  let ambSeq = 0;

  const valid = [];
  for (const r of regions || []) {
    const id = (r && r.regionId) || null;
    if (!r || r.genuine === false || r.synthetic === true) {
      rejected.push({ regionId: id, reason: 'non-genuine-region' });
      continue;
    }
    const bad = validateBox(r.boundingBox, dims);
    if (bad) {
      rejected.push({ regionId: id, reason: `invalid-box:${bad}` });
      continue;
    }
    const ocr = r.ocr || {};
    const text = typeof ocr.text === 'string' ? ocr.text : null;
    // Geometry stands on SAM output alone; roles require successful OCR text.
    const roles = ocr.error ? [] : classifyTextRoles(text);
    valid.push({
      regionId: id,
      boundingBox: r.boundingBox,
      text,
      empty: ocr.empty === true,
      ocrError: ocr.error || null,
      roles
    });
  }
  valid.sort(byRegionId);

  const withRole = (role) => valid.filter((v) => v.roles.includes(role));
  const memberOf = (v, role) => ({
    regionId: v.regionId,
    role,
    text: v.text,
    boundingBox: { ...v.boundingBox }
  });

  // Geometric relation between two distinct regions, or null when the
  // candidate is out of scope. Containers may be any valid region: no
  // parent boundaries are invented, only observed boxes are used.
  function relate(anchor, cand) {
    if (containsBox(anchor.boundingBox, cand.boundingBox)
        || containsBox(cand.boundingBox, anchor.boundingBox)) {
      const container = containsBox(anchor.boundingBox, cand.boundingBox) ? anchor : cand;
      return {
        method: 'containment',
        containerRegionId: container.regionId,
        gapPx: boxGap(anchor.boundingBox, cand.boundingBox)
      };
    }
    const shared = valid
      .filter((c) => c !== anchor && c !== cand
        && containsBox(c.boundingBox, anchor.boundingBox)
        && containsBox(c.boundingBox, cand.boundingBox))
      .sort((a, b) => (boxArea(a.boundingBox) - boxArea(b.boundingBox)) || byRegionId(a, b))[0];
    if (shared) {
      return {
        method: 'shared-container',
        containerRegionId: shared.regionId,
        gapPx: boxGap(anchor.boundingBox, cand.boundingBox)
      };
    }
    const gap = boxGap(anchor.boundingBox, cand.boundingBox);
    const limit = PROXIMITY_FACTOR * Math.min(minDim(anchor.boundingBox), minDim(cand.boundingBox));
    if (gap <= limit) {
      return { method: 'proximity', containerRegionId: null, gapPx: gap };
    }
    return null;
  }

  function rationaleFor(rel) {
    if (rel.method === 'containment') {
      return `Boxes overlap by containment (${rel.containerRegionId} contains the other); spatial co-location, not proof of transaction semantics.`;
    }
    if (rel.method === 'shared-container') {
      return `Both regions lie inside observed box ${rel.containerRegionId}; shared-boundary association, not proof of transaction semantics.`;
    }
    return `Edge gap ${rel.gapPx}px within adjacency threshold; proximity alone is not proof of association.`;
  }

  // Unique in-scope candidate links; multiple candidates become an explicit
  // ambiguity; none leaves the anchor for the unassociated pass. Returns
  // 'linked' | 'ambiguous' | 'none'.
  function linkAnchor(kind, anchor, anchorRole, targetRole) {
    if (anchor.roles.includes(targetRole)) {
      links.push({
        linkId: `L-${String(++linkSeq).padStart(3, '0')}`,
        kind,
        method: 'same-region',
        members: [memberOf(anchor, anchorRole), memberOf(anchor, targetRole)],
        containerRegionId: null,
        gapPx: 0,
        rationale: `Both roles observed in the single OCR read of ${anchor.regionId}; textual co-occurrence, not proof of transaction semantics.`
      });
      return 'linked';
    }
    const cands = withRole(targetRole)
      .filter((c) => c !== anchor)
      .map((cand) => ({ cand, rel: relate(anchor, cand) }))
      .filter((e) => e.rel !== null)
      .sort((a, b) => (a.rel.gapPx - b.rel.gapPx) || byRegionId(a.cand, b.cand));
    if (cands.length === 1) {
      const { cand, rel } = cands[0];
      links.push({
        linkId: `L-${String(++linkSeq).padStart(3, '0')}`,
        kind,
        method: rel.method,
        members: [memberOf(anchor, anchorRole), memberOf(cand, targetRole)],
        containerRegionId: rel.containerRegionId,
        gapPx: rel.gapPx,
        rationale: rationaleFor(rel)
      });
      return 'linked';
    }
    if (cands.length > 1) {
      ambiguities.push({
        ambiguityId: `AMB-${String(++ambSeq).padStart(3, '0')}`,
        kind,
        anchor: memberOf(anchor, anchorRole),
        candidates: cands.map(({ cand, rel }) => ({
          ...memberOf(cand, targetRole),
          method: rel.method,
          gapPx: rel.gapPx,
          containerRegionId: rel.containerRegionId
        })),
        reason: `${cands.length} ${targetRole} candidates in scope for ${anchor.regionId ?? '(unidentified region)'}; no single link asserted.`
      });
      return 'ambiguous';
    }
    return 'none';
  }

  // Warning anchors relate to any classified transaction region; the first
  // matching role in fixed order keeps multi-role candidates deterministic.
  function linkWarning(anchor) {
    const order = [ROLE_AMOUNT, ROLE_RECIPIENT, ROLE_ACTION];
    const selfRole = order.find((role) => anchor.roles.includes(role));
    if (selfRole) {
      links.push({
        linkId: `L-${String(++linkSeq).padStart(3, '0')}`,
        kind: 'warning-context',
        method: 'same-region',
        members: [memberOf(anchor, ROLE_WARNING), memberOf(anchor, selfRole)],
        containerRegionId: null,
        gapPx: 0,
        rationale: `Both roles observed in the single OCR read of ${anchor.regionId}; textual co-occurrence, not proof of transaction semantics.`
      });
      return;
    }
    const cands = [];
    for (const v of valid) {
      if (v === anchor) continue;
      const role = order.find((r) => v.roles.includes(r));
      if (!role) continue;
      const rel = relate(anchor, v);
      if (rel) cands.push({ cand: v, role, rel });
    }
    cands.sort((a, b) => (a.rel.gapPx - b.rel.gapPx) || byRegionId(a.cand, b.cand));
    if (cands.length === 1) {
      const { cand, role, rel } = cands[0];
      links.push({
        linkId: `L-${String(++linkSeq).padStart(3, '0')}`,
        kind: 'warning-context',
        method: rel.method,
        members: [memberOf(anchor, ROLE_WARNING), memberOf(cand, role)],
        containerRegionId: rel.containerRegionId,
        gapPx: rel.gapPx,
        rationale: rationaleFor(rel)
      });
    } else if (cands.length > 1) {
      ambiguities.push({
        ambiguityId: `AMB-${String(++ambSeq).padStart(3, '0')}`,
        kind: 'warning-context',
        anchor: memberOf(anchor, ROLE_WARNING),
        candidates: cands.map(({ cand, role, rel }) => ({
          ...memberOf(cand, role),
          method: rel.method,
          gapPx: rel.gapPx,
          containerRegionId: rel.containerRegionId
        })),
        reason: `${cands.length} transaction regions in scope for ${anchor.regionId ?? '(unidentified region)'}; no single link asserted.`
      });
    }
  }

  // Fixed kind order keeps link/ambiguity IDs stable across runs.
  for (const anchor of withRole(ROLE_AMOUNT)) {
    linkAnchor('amount-recipient', anchor, ROLE_AMOUNT, ROLE_RECIPIENT);
  }
  for (const anchor of withRole(ROLE_ACTION)) {
    linkAnchor('action-amount', anchor, ROLE_ACTION, ROLE_AMOUNT);
    linkAnchor('action-recipient', anchor, ROLE_ACTION, ROLE_RECIPIENT);
  }
  for (const anchor of withRole(ROLE_WARNING)) {
    linkWarning(anchor);
  }

  const referenced = new Set();
  for (const l of links) for (const m of l.members) referenced.add(m.regionId);
  for (const a of ambiguities) {
    referenced.add(a.anchor.regionId);
    for (const c of a.candidates) referenced.add(c.regionId);
  }
  for (const v of valid) {
    if (referenced.has(v.regionId)) continue;
    let reason;
    if (v.ocrError) reason = `ocr-error:${v.ocrError.code || 'UNKNOWN'}`;
    else if (v.roles.length === 0) reason = (v.text === null || v.text === '' || v.empty) ? 'ocr-empty' : 'no-transaction-role';
    else reason = 'no-related-region';
    unassociated.push({ regionId: v.regionId, roles: [...v.roles], reason });
  }

  return { links, ambiguities, unassociated, rejected };
}

module.exports = {
  associateRegions,
  classifyTextRoles,
  PROXIMITY_FACTOR,
  ROLES
};
