/**
 * Visual role understanding (Capability 4, B10). Deterministic,
 * display-only interpretation of SAM regions + OCR that goes beyond
 * fixed keyword lists WITHOUT pretending geometry proves semantics.
 *
 * Three narrow jobs:
 * 1. buildActionElements: action-element triples — an action-text region,
 *    its smallest observed container box, and its linked amount/recipient
 *    members — plus an honest verb-vs-decoded-function consistency flag.
 * 2. findNamedElements: finding-specific element naming (addresses,
 *    address fragments, exact amount digits, limit words). Shared by the
 *    §9 warning comparison (specificity tier) and the role cross-check.
 *    Keyword-free in the sense that matters: it never consults the fixed
 *    WARNING_RE list — a paraphrased warning names a FINDING's elements.
 * 3. crossCheckVisualRoles: post-model verification of model-asserted
 *    visual roles against observed OCR. VERIFIED requires observed
 *    evidence; REFUTED requires strict contradiction; everything else is
 *    INCONCLUSIVE, never a guess.
 *
 * Associations describe the DISPLAY ONLY and never override decoded
 * transaction facts (see association.js honesty rules).
 */

const { classifyTextRoles } = require('./association');

const FULL_ADDRESS_RE = /0x[0-9a-fA-F]{40}/;
const ADDRESS_FRAGMENT_RE = /0x[0-9a-fA-F]{8,39}/g;
const DIGIT_RUN_RE = /(\d[\d,]*\.?\d*)/g;
const LIMIT_WORD_RE = /\b(unlimited|infinite|infinity|max|maximum)\b/i;

// Verb families for the verb-vs-function consistency flag. A verb names a
// DIFFERENT family than the decoded function (e.g. "Swap" over approve)
// is inconsistency worth flagging; batch/permit wrappers and unknown
// functions are unassessable, never forced into a verdict.
const VERB_FAMILY = new Map([
  ['swap', 'swap'], ['swapping', 'swap'],
  ['send', 'transfer'], ['sending', 'transfer'], ['transfer', 'transfer'],
  ['transferring', 'transfer'], ['pay', 'transfer'], ['payment', 'transfer'],
  ['approve', 'approval'], ['approving', 'approval'], ['approval', 'approval'],
  ['claim', 'claim'], ['claiming', 'claim'],
  ['mint', 'mint'], ['minting', 'mint'],
  ['stake', 'stake'], ['staking', 'stake'], ['unstake', 'stake'],
  ['deposit', 'deposit'], ['withdraw', 'withdraw'],
  ['bridge', 'bridge'], ['bridging', 'bridge']
]);
const FUNCTION_FAMILY = new Map([
  ['exactinputsingle', 'swap'], ['exactinput', 'swap'], ['exactoutputsingle', 'swap'],
  ['exactoutput', 'swap'], ['swap', 'swap'], ['swapexacttokensfortokens', 'swap'],
  ['swaptokensforexacttokens', 'swap'], ['swapexactethfortokens', 'swap'],
  ['swapethforexacttokens', 'swap'],
  ['transfer', 'transfer'], ['transferfrom', 'transfer'],
  ['safetransferfrom', 'transfer'], ['send', 'transfer'],
  ['approve', 'approval'], ['increaseallowance', 'approval'], ['decreaseallowance', 'approval'],
  ['setapprovalforall', 'approval'],
  ['claim', 'claim'], ['claimreward', 'claim'], ['claimrewards', 'claim'], ['getreward', 'claim'],
  ['mint', 'mint'], ['stake', 'stake'], ['deposit', 'deposit'], ['withdraw', 'withdraw'],
  ['bridge', 'bridge']
]);
const UNASSESSABLE_FUNCTIONS = new Set(['multicall', 'batch', 'execute', 'permit', 'selfpermit', 'unknown']);

function verbOf(text) {
  if (typeof text !== 'string') return null;
  const m = text.toLowerCase().match(/\b(swap|swapping|send|sending|approve|approving|approval|transfer|transferring|claim|claiming|mint|minting|stake|staking|unstake|deposit|withdraw|bridge|bridging|pay|payment)\b/);
  return m ? m[1] : null;
}

function areaOf(b) {
  return b && typeof b.width === 'number' && typeof b.height === 'number' ? b.width * b.height : 0;
}

function containsStrict(outer, inner) {
  if (!outer || !inner) return false;
  const ox2 = outer.x + outer.width;
  const oy2 = outer.y + outer.height;
  const ix2 = inner.x + inner.width;
  const iy2 = inner.y + inner.height;
  return outer.x <= inner.x && outer.y <= inner.y && ix2 <= ox2 && iy2 <= oy2
    && areaOf(outer) > areaOf(inner);
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

/**
 * Build action elements from observed regions + geometric links.
 * @param {{regions: Array, associations: {links: Array}, decodedTx: object}} evidence
 * @returns {{elements: Array, capped: boolean}} elements carry AE-xxx ids,
 *   deterministic by regionId order.
 */
function buildActionElements({ regions, associations, decodedTx } = {}) {
  const regs = Array.isArray(regions) ? regions.filter((r) => r && typeof r.regionId === 'string' && r.boundingBox) : [];
  const links = (associations && Array.isArray(associations.links)) ? associations.links : [];
  const fnRaw = decodedTx && typeof decodedTx.functionName === 'string' ? decodedTx.functionName : null;
  const fnLower = fnRaw ? fnRaw.toLowerCase() : null;
  const fnFamily = fnLower && !UNASSESSABLE_FUNCTIONS.has(fnLower) ? (FUNCTION_FAMILY.get(fnLower) || null) : null;

  const actions = regs
    .filter((r) => classifyTextRoles(r.ocr && typeof r.ocr.text === 'string' ? r.ocr.text : null).includes('action'))
    .sort((a, b) => String(a.regionId).localeCompare(String(b.regionId)));

  const elements = actions.slice(0, 10).map((a, i) => {
    const text = a.ocr && typeof a.ocr.text === 'string' ? a.ocr.text : '';
    const containers = regs
      .filter((r) => r !== a && containsStrict(r.boundingBox, a.boundingBox))
      .sort((x, y) => areaOf(x.boundingBox) - areaOf(y.boundingBox));
    const container = containers[0] || null;
    const memberRoles = new Set();
    const linkedAmounts = [];
    const linkedRecipients = [];
    for (const l of links) {
      if (!l || !Array.isArray(l.members) || !l.members.some((m) => m && m.regionId === a.regionId)) continue;
      for (const m of l.members) {
        if (!m || m.regionId === a.regionId) continue;
        if (m.role === 'amount') {
          memberRoles.add('amount');
          if (typeof m.text === 'string') linkedAmounts.push(m.text.slice(0, 80));
        } else if (m.role === 'recipient') {
          memberRoles.add('recipient');
          if (typeof m.text === 'string') linkedRecipients.push(m.text.slice(0, 80));
        } else if (typeof m.role === 'string') {
          memberRoles.add(m.role);
        }
      }
    }
    const verb = verbOf(text);
    const verbFamily = verb ? (VERB_FAMILY.get(verb) || null) : null;
    let verbConsistent = null;
    let consistencyNote = 'unassessed';
    if (verbFamily && fnFamily) {
      verbConsistent = verbFamily === fnFamily;
      consistencyNote = verbConsistent
        ? `display verb '${verb}' names the decoded ${fnRaw} family`
        : `display verb '${verb}' names ${verbFamily} but the transaction is ${fnRaw}`;
    } else if (!verbFamily && fnFamily) {
      consistencyNote = 'no action verb parsed from the display text';
    } else if (fnLower && UNASSESSABLE_FUNCTIONS.has(fnLower)) {
      consistencyNote = `decoded function ${fnRaw} is a batch/wrapper: a single display verb cannot describe it`;
    } else {
      consistencyNote = 'decoded function unknown or unmapped';
    }
    const el = {
      elementId: `AE-${String(i + 1).padStart(3, '0')}`,
      actionRegionId: a.regionId,
      actionText: text.slice(0, 160),
      verb,
      container: container ? {
        regionId: container.regionId,
        areaRatio: areaOf(a.boundingBox) > 0 ? round2(areaOf(container.boundingBox) / areaOf(a.boundingBox)) : null
      } : null,
      linkedRoles: [...memberRoles].sort(),
      linkedAmounts: [...new Set(linkedAmounts)].slice(0, 4),
      linkedRecipients: [...new Set(linkedRecipients)].slice(0, 4),
      decodedFunction: fnRaw,
      verbConsistent,
      consistencyNote
    };
    return el;
  });
  return { elements, capped: actions.length > elements.length };
}

function decodedAddresses(decodedTx) {
  const out = new Set();
  const push = (v) => {
    if (typeof v === 'string' && FULL_ADDRESS_RE.test(v)) out.add(v.toLowerCase());
  };
  const tx = decodedTx && typeof decodedTx === 'object' ? decodedTx : {};
  push(tx.contract);
  push(tx.sender);
  push(tx.recipient);
  const params = tx.parameters && typeof tx.parameters === 'object' ? tx.parameters : {};
  const scan = (v, depth) => {
    if (depth > 3) return;
    if (typeof v === 'string') push(v);
    else if (Array.isArray(v)) v.forEach((e) => scan(e, depth + 1));
    else if (v && typeof v === 'object') Object.values(v).forEach((e) => scan(e, depth + 1));
  };
  scan(params, 0);
  return [...out];
}

function decodedDigitRuns(decodedTx) {
  const out = new Set();
  const tx = decodedTx && typeof decodedTx === 'object' ? decodedTx : {};
  const params = tx.parameters && typeof tx.parameters === 'object' ? tx.parameters : {};
  const push = (v) => {
    if (typeof v === 'bigint') out.add(v.toString());
    else if (typeof v === 'number' && Number.isInteger(v)) out.add(String(v));
    else if (typeof v === 'string' && /^\d{4,}$/.test(v)) out.add(v.replace(/^0+(?=\d)/, '') || '0');
  };
  const scan = (v, depth) => {
    if (depth > 3) return;
    push(v);
    if (Array.isArray(v)) v.forEach((e) => scan(e, depth + 1));
    else if (v && typeof v === 'object') Object.values(v).forEach((e) => scan(e, depth + 1));
  };
  scan(params, 0);
  if (typeof tx.value === 'string' && /^\d{4,}$/.test(tx.value)) out.add(tx.value);
  return [...out];
}

/**
 * Find finding-specific elements named in observed text. Strict and
 * bounded: full addresses, 0x fragments of ≥8 hex chars matching a
 * decoded counterparty, exact digit runs (≥4 digits) matching a decoded
 * amount, and limit words when an approval-family finding stands.
 */
function findNamedElements(text, { decodedTx, findings } = {}) {
  const found = [];
  if (typeof text !== 'string' || text.length === 0) return found;
  const addrs = decodedAddresses(decodedTx);
  for (const m of text.match(/0x[0-9a-fA-F]{40}/g) || []) {
    if (addrs.includes(m.toLowerCase())) {
      found.push({ kind: 'address', value: m });
    }
  }
  ADDRESS_FRAGMENT_RE.lastIndex = 0;
  for (const m of text.match(ADDRESS_FRAGMENT_RE) || []) {
    if (/^0x[0-9a-fA-F]{40}$/.test(m)) continue;
    const low = m.toLowerCase();
    const hit = addrs.find((a) => a.startsWith(low));
    if (hit) found.push({ kind: 'address-fragment', value: m, resolvesTo: hit });
  }
  const digits = decodedDigitRuns(decodedTx);
  DIGIT_RUN_RE.lastIndex = 0;
  for (const m of text.match(DIGIT_RUN_RE) || []) {
    const compact = m.replace(/,/g, '');
    if (compact.replace('.', '').length < 4) continue;
    const intPart = compact.split('.')[0].replace(/^0+(?=\d)/, '') || '0';
    if (digits.includes(compact) || digits.includes(intPart)) {
      found.push({ kind: 'amount-digits', value: m });
    }
  }
  const approvalFinding = (Array.isArray(findings) ? findings : []).some((f) => f
    && /APPROVAL|ALLOWANCE|PERMIT|SPEND|OPERATOR/.test(String(f.ruleId || '')));
  if (approvalFinding) {
    const lm = text.match(LIMIT_WORD_RE);
    if (lm) found.push({ kind: 'limit-word', value: lm[1].toLowerCase() });
  }
  return found;
}

function notableFindings(ruleFindings) {
  return (Array.isArray(ruleFindings) ? ruleFindings : [])
    .filter((f) => f && (f.severity === 'HIGH' || f.severity === 'CRITICAL'));
}

/**
 * Post-model cross-check of model-asserted visual roles against observed
 * OCR. Only 'supported' grounding claims are checked; anything else is
 * reported INCONCLUSIVE with its grounding status as the reason.
 */
function crossCheckVisualRoles({ grounding, ruleFindings, decodedTx } = {}) {
  const claims = grounding && Array.isArray(grounding.claims) ? grounding.claims : [];
  const findings = notableFindings(ruleFindings);
  const checks = [];
  for (const c of claims.slice(0, 12)) {
    const observedText = (Array.isArray(c.observed) ? c.observed : [])
      .map((o) => (o && typeof o.text === 'string' ? o.text : ''))
      .filter((t) => t.length > 0)
      .join('\n');
    const base = {
      claimIndex: c.index,
      claimType: c.type,
      regionIds: Array.isArray(c.regionIds) ? c.regionIds : []
    };
    if (!c || c.status !== 'supported') {
      checks.push({ ...base, result: 'INCONCLUSIVE', reason: `grounding status is ${c ? c.status : 'missing'}; nothing observed to check against` });
      continue;
    }
    if (!['warning', 'action', 'amount', 'recipient', 'approval'].includes(c.type)) {
      checks.push({ ...base, result: 'INCONCLUSIVE', reason: `claim type '${c.type}' has no role cross-check` });
      continue;
    }
    const elements = findNamedElements(observedText, { decodedTx, findings });
    // REFUTED is strict: the model's value must assert a full address or
    // a long digit run that appears in NEITHER the cited region NOR the
    // decoded transaction. Interpretation stays the model's business;
    // only concrete contradictions refute.
    const value = typeof c.value === 'string' ? c.value : '';
    const valueAddrs = value.match(/0x[0-9a-fA-F]{40}/g) || [];
    const addrs = decodedAddresses(decodedTx);
    const phantomAddr = valueAddrs.find((a) => !observedText.toLowerCase().includes(a.toLowerCase())
      && !addrs.includes(a.toLowerCase()));
    if (phantomAddr) {
      checks.push({ ...base, result: 'REFUTED', reason: `asserted address ${phantomAddr} appears in neither the cited region nor the transaction` });
      continue;
    }
    const valueDigits = (value.match(/\d[\d,]{3,}/g) || []).map((d) => d.replace(/,/g, ''));
    const phantomDigits = valueDigits.find((d) => d.length >= 4 && !observedText.replace(/,/g, '').includes(d));
    if (phantomDigits && (c.type === 'amount' || c.type === 'recipient')) {
      checks.push({ ...base, result: 'REFUTED', reason: `asserted digits '${phantomDigits}' are absent from the cited region's observed text` });
      continue;
    }
    if (elements.length > 0) {
      checks.push({
        ...base,
        result: 'VERIFIED',
        reason: `observed text names ${elements.map((e) => `${e.kind}:${e.value}`).join(', ').slice(0, 160)}`,
        namedElements: elements.map((e) => e.kind)
      });
      continue;
    }
    checks.push({
      ...base,
      result: 'INCONCLUSIVE',
      reason: 'observed text names no finding element (address, amount, or limit); role assertion unverified but not contradicted'
    });
  }
  const summary = {
    checked: checks.length,
    VERIFIED: checks.filter((c) => c.result === 'VERIFIED').length,
    REFUTED: checks.filter((c) => c.result === 'REFUTED').length,
    INCONCLUSIVE: checks.filter((c) => c.result === 'INCONCLUSIVE').length,
    downgrade: checks.some((c) => c.result === 'REFUTED')
  };
  return { checks, summary };
}

module.exports = {
  buildActionElements,
  findNamedElements,
  crossCheckVisualRoles,
  notableFindings
};
