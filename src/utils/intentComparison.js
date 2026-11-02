/**
 * Deterministic UI-intent-to-transaction comparison (Phase A).
 *
 * Pure utility: compares what the UI can reliably establish against what the
 * decoded transaction reliably establishes. No services, no network, no env,
 * no mutable state. Monetary math uses BigInt and exact decimal strings only
 * — a JavaScript Number never touches a financial value on any path.
 *
 * Trust boundary (strict, structural):
 * - Only validated grounding records with status 'supported' are candidates,
 *   and even those are re-checked here: no fabrication keys, every cited
 *   region resolves to a genuine region with successful non-empty OCR, and
 *   the claim value must appear at TOKEN boundaries in the CITED regions'
 *   OCR text ("1 eth" is not corroborated by "21 eth"). Combined-scan text,
 *   DOM text, summary text, and model-supplied text or geometry can never
 *   corroborate a value.
 * - Corroborated values still need display-role attribution before any
 *   comparison: amounts via strong action-amount links, counterparties via
 *   destination labels or strong recipient links. Fees, balances, quotes,
 *   and sender/source displays are never transaction-amount or
 *   counterparty candidates. A lone number or address proves nothing alone.
 * - Amount regions labeled as fee, balance, quote, minimum, or allowance
 *   (in their own cited text) are excluded from fields those roles
 *   conflict with — even when linked. "Total" is not an excluded role.
 * - Approval-family verbs compare only with corroborated argument context
 *   (attributed spender/amount or approval-scope claim); a bare "Approve"
 *   button is generic confirmation language, not an operation.
 * - Native value compares only where msg.value is operative
 *   (nativeTransfer, deposit). Token amounts, swap legs, and withdrawals
 *   have their own fields or stay inconclusive; they never alias to native.
 * - Synthetic fallback regions, failed/empty OCR, unknown region ids, and
 *   ambiguity references can never yield MATCH.
 * - Missing, ambiguous, or semantically incomparable evidence yields
 *   INCONCLUSIVE — never MATCH. Overall MATCH is therefore unreachable in
 *   Phase A by design (target and warning coverage is explicitly incomplete).
 *
 * Statuses: MATCH (corroborated equivalence), MISMATCH (corroborated
 * conflict), INCONCLUSIVE (anything else).
 */

// Pure BigInt gap math (Capability 4 B3). utils-to-utils only: no
// services, network, or env, preserving this module's purity contract.
const { analyzeOutputGap } = require('./valueProtection');

const FULL_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const NATIVE_DECIMALS = 18;
const MAX_DECIMALS = 100;

// Displayed symbol aliases. ETH<->WETH is the only alias: dApps show native
// ETH where exactInputSingle encodes WETH. It affects symbol attribution
// only, never amounts or addresses.
const SYMBOL_ALIASES = { ETH: ['ETH', 'WETH'], WETH: ['WETH', 'ETH'] };

// Fabrication keys rejected by the grounding validator; re-checked here so a
// caller cannot launder model-supplied evidence through a forged 'supported'.
const FABRICATION_KEYS = [
  'boundingBox', 'bbox', 'box', 'coordinates', 'coords', 'mask', 'polygon',
  'region', 'ocr', 'ocrText', 'observedText', 'observed', 'regionText',
  'evidenceText'
];

// Conservative UI-verb to decoded-operation mapping. Only functions the
// decoder names are mapped; anything else (mint, claim, stake, bridge, …)
// is an unsupported operation, never a guessed one.
// Capability 4 B4: collect decoded inner function names from a multicall
// `calls` array, recursing into nested batches. Containers and unknown
// inners contribute nothing — only established operations match verbs.
function collectInnerFunctions(calls) {
  const found = [];
  const walk = (entries) => {
    if (!Array.isArray(entries)) return;
    for (const e of entries) {
      if (!e || typeof e !== 'object') continue;
      if (typeof e.functionName === 'string' && e.functionName !== 'unknownFunction' && e.functionName !== 'multicall') {
        if (!found.includes(e.functionName)) found.push(e.functionName);
      }
      walk(e.calls);
    }
  };
  walk(calls);
  return found;
}
const ACTION_MAP = [
  { pattern: /\bswap(?:ping)?\b/i, functions: ['exactInputSingle'] },
  { pattern: /\bapprov(?:e|ing|al)\b|\ballowance\b/i, functions: ['approve', 'increaseAllowance', 'setApprovalForAll'] },
  { pattern: /\btransfer(?:ring)?\b/i, functions: ['transfer', 'transferFrom'] },
  { pattern: /\bsend(?:ing)?\b/i, functions: ['transfer', 'transferFrom', 'nativeTransfer'] },
  { pattern: /\bdeposit\b/i, functions: ['deposit'] },
  { pattern: /\bwithdraw\b/i, functions: ['withdraw'] }
];

const UNLIMITED_WORDS = ['unlimited', 'infinite', 'infinity', 'max', 'maximum'];

// Capability 3 B5: finding-class vocabulary for warning disclosure.
// Stems (not whole words) so approve/approval/approving all match.
const FINDING_CLASS_WORDS = {
  INFINITE_APPROVAL: ['approv', 'allowance', 'unlimited', 'spend', 'access', 'permission'],
  AMBIGUOUS_APPROVAL_SCOPE: ['approv', 'allowance', 'scope', 'limit', 'permission'],
  NFT_SET_APPROVAL_FOR_ALL: ['approv', 'operator', 'collection', 'all'],
  UNVERIFIED_SPENDER: ['spend', 'verif', 'recipient', 'unknown', 'unverif', 'scam', 'phish', 'caution', 'careful'],
  PERMIT2_OFFCHAIN_APPROVAL: ['permit', 'sign', 'signature', 'offchain', 'off-chain'],
  SWAP_RECIPIENT_DIFFERS_FROM_SENDER: ['recipient', 'receiv', 'address', 'destination']
};
const GENERIC_RISK_WORDS = ['risk', 'warning', 'caution', 'careful', 'danger'];
const SAFETY_CLAIM_RE = /\b(safe|audited|secure|guaranteed|protected|trusted|verified|risk[\s-]?free|no\s+risk)\b/i;
const APPROVAL_DENIAL_RES = [/\bno\s+approv/i, /\bwithout\s+approv/i, /\bnever\s+asks\b/i, /\bdoes\s+not\s+require\b.{0,40}approv/i];

// The approve-family mapping entry. Approval verbs ("Approve", "Set
// approval", "Grant permission") double as generic confirmation language, so
// they compare only with corroborated argument context (below) — never alone.
const APPROVE_FUNCTIONS = ACTION_MAP[1].functions;

// Fiat-denoting symbols: never crypto-asset evidence, never a conflict.
const FIAT_WORDS = new Set(['USD', 'EUR', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD', 'CNY', 'DOLLAR', 'DOLLARS', 'EURO', 'EUROS']);

// Association link methods strong enough to attribute a display role.
// Proximity and shared-container are explicitly excluded: the association
// module records them as adjacency, not proof of a semantic relationship.
const STRONG_LINK_METHODS = new Set(['same-region', 'containment']);

// Observed direction labels, anchored at region-text start. A source label
// excludes an address from counterparty candidacy; a destination label (or a
// strong recipient link) positively attributes it. Labels come from observed
// OCR text, never from claim values.
const DEST_LABEL_RE = /^\s*(to|recipient|spender|operator|destination|pay to|send to)\b/i;
const SOURCE_LABEL_RE = /^\s*(from|sender|source|sent from|paying from)\b/i;

// Display-role vocabulary for amount regions. Applied ONLY to the candidate
// amount's own cited region text — never dialog-wide — so a fee row cannot
// taint a sibling payment amount and vice versa. "Total" is deliberately
// absent: "Total to pay" may describe the actual transaction amount. Bare
// "gas" counts only in label form ("Gas: ...") or fee compounds, so a
// GAS-token payment is never mistaken for a network fee.
const AMOUNT_ROLE_PATTERNS = [
  { role: 'fee', re: /\bfee(s)?\b|\bgas\s+(fee|price|limit|cost)\b|\b(network|transaction|tx)\s+(fee|fees|gas|cost)\b|\bmax\s+fee\b|^\s*gas\s*:/i },
  { role: 'balance', re: /\bbalance(s)?\b/i },
  { role: 'quote', re: /\bestimat(e|ed|es|ing|ion)?\b|\bquote[sd]?\b|\bquotation\b|\bexpected\b|\bprojection\b|\byou(['’]ll|\s+will)?\s+(get|receive)\b|\breceiv(e[sd]?|ing)\b/i },
  { role: 'minimum', re: /\bminimum\b|\bmin\b|\bat\s+least\b/i },
  { role: 'allowance', re: /\ballowance\b|\bspending\s+(limit|cap|allowance)\b|\bapprove[sd]?\s+(amount|limit|spending)\b|\blimit\b/i }
];
const AMOUNT_ROLES_ALL = new Set(['fee', 'balance', 'quote', 'minimum', 'allowance']);
const AMOUNT_ROLES_NON_ALLOWANCE = new Set(['fee', 'balance', 'quote', 'minimum']);

function rolesOfRegionText(text) {
  if (typeof text !== 'string') return [];
  return AMOUNT_ROLE_PATTERNS.filter((entry) => entry.re.test(text)).map((entry) => entry.role);
}

// Overlong values cannot be corroborated safely (and bound regex work).
const MAX_CORROBORATION_CHARS = 2000;

function normalizeText(value) {
  return String(value).toLowerCase().replace(/\s+/g, ' ').trim();
}

// Never-throwing formatter for untrusted values in reason strings. Template
// interpolation of a Symbol throws, so symbols and exotic types degrade to
// a type tag instead of escaping the utility as an exception.
function fmtReason(v) {
  if (typeof v === 'string') return v.length > 120 ? `${v.slice(0, 120)}…` : v;
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Token-boundary containment: the needle must appear as complete tokens,
// never as a substring of a longer word or number. "1 eth" is not found in
// "21 eth", "send" is not found in "sender", "eth" is not found in "tether".
function containsBounded(haystack, needle) {
  if (!needle || needle.length > MAX_CORROBORATION_CHARS) return false;
  const pattern = `(?<![\\p{L}\\p{N}])${escapeRegExp(needle)}(?![\\p{L}\\p{N}])`;
  try {
    return new RegExp(pattern, 'u').test(haystack);
  } catch {
    return new RegExp('(?<![A-Za-z0-9])' + escapeRegExp(needle) + '(?![A-Za-z0-9])').test(haystack);
  }
}

function sameAddress(a, b) {
  return typeof a === 'string' && typeof b === 'string'
    && FULL_ADDRESS_RE.test(a) && FULL_ADDRESS_RE.test(b)
    && a.toLowerCase() === b.toLowerCase();
}

// Strict thousands separators only: "1,000.5" ok; "1,00,0", misplaced
// commas, spaces, signs, and exponents are all rejected.
function splitDisplayNumber(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!/^(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?$/.test(s)) return null;
  const compact = s.replace(/,/g, '');
  const dot = compact.indexOf('.');
  return dot === -1
    ? { intPart: compact, fracPart: '' }
    : { intPart: compact.slice(0, dot), fracPart: compact.slice(dot + 1) };
}

// Exact display-decimal to base units. Returns a BigInt, or null when the
// input is malformed, decimals are untrusted, or displayed precision exceeds
// the token's decimals (a longer display may be truncated — incomparable).
function displayToBaseUnits(raw, decimals) {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > MAX_DECIMALS) return null;
  const parts = splitDisplayNumber(raw);
  if (!parts) return null;
  if (parts.fracPart.length > decimals) return null;
  try {
    return BigInt((parts.intPart + parts.fracPart.padEnd(decimals, '0')) || '0');
  } catch {
    return null;
  }
}

function parseBigIntStrict(raw) {
  if (typeof raw === 'bigint') return raw;
  if (typeof raw !== 'string' || !/^(?:0x[0-9a-fA-F]+|\d+)$/.test(raw.trim())) return null;
  try {
    return BigInt(raw.trim());
  } catch {
    return null;
  }
}

// A claim value must parse ENTIRELY as one amount: optional '$', a number,
// an optional trailing symbol. Sentences never parse; bare numbers carry no
// asset and are unattributable; '$'/fiat amounts never match crypto fields.
function parseClaimAmount(value) {
  if (typeof value !== 'string') return null;
  const m = value.trim().match(/^(\$)?\s*([0-9][0-9,]*(\.[0-9]+)?)\s*([A-Za-z]{1,12})?\s*$/);
  if (!m) return null;
  return { number: m[2], symbol: m[4] ? m[4].toUpperCase() : null, fiat: m[1] === '$' };
}

function symbolsEquivalent(a, b) {
  if (!a || !b) return false;
  const upA = String(a).toUpperCase();
  const upB = String(b).toUpperCase();
  if (upA === upB) return true;
  return (SYMBOL_ALIASES[upA] || []).includes(upB);
}

function validTokenMeta(meta) {
  return meta && typeof meta === 'object'
    && typeof meta.symbol === 'string' && meta.symbol.trim().length > 0
    && Number.isInteger(meta.decimals) && meta.decimals >= 0 && meta.decimals <= MAX_DECIMALS;
}

// Corroborate one validated claim against genuine observed OCR. Returns the
// usable record or null with a reason. Defense in depth: the caller's
// 'supported' status is necessary but never sufficient.
function corroborateClaim(claim, index, regionMap, ambiguityIds) {
  const ref = `claim#${index}`;
  if (!claim || typeof claim !== 'object' || Array.isArray(claim)) {
    return { usable: null, reason: `${ref} is malformed` };
  }
  if (claim.status !== 'supported') {
    return { usable: null, reason: `${ref} has grounding status '${fmtReason(claim.status)}', not 'supported'` };
  }
  const forged = FABRICATION_KEYS.find((k) => claim[k] !== undefined);
  if (forged) {
    return { usable: null, reason: `${ref} carries model-supplied '${forged}'` };
  }
  if (typeof claim.value !== 'string' || claim.value.length === 0) {
    return { usable: null, reason: `${ref} has no value` };
  }
  if (!Array.isArray(claim.regionIds) || claim.regionIds.length === 0) {
    return { usable: null, reason: `${ref} cites no regions` };
  }
  if (claim.associationIds !== undefined && !Array.isArray(claim.associationIds)) {
    return { usable: null, reason: `${ref} has malformed associationIds` };
  }
  if (Array.isArray(claim.associationIds)
    && claim.associationIds.some((id) => ambiguityIds.has(id))) {
    return { usable: null, reason: `${ref} rests on an unresolved ambiguity` };
  }
  const texts = [];
  for (const id of claim.regionIds) {
    const reg = typeof id === 'string' ? regionMap.get(id) : undefined;
    if (!reg) return { usable: null, reason: `${ref} cites unknown region '${fmtReason(id)}'` };
    if (reg.genuine === false || reg.synthetic === true) {
      return { usable: null, reason: `${ref} cites non-genuine region '${fmtReason(id)}'` };
    }
    const ocr = reg.ocr || {};
    if (ocr.error) return { usable: null, reason: `${ref} cites region '${fmtReason(id)}' with failed OCR` };
    if (typeof ocr.text !== 'string' || ocr.text.length === 0) {
      return { usable: null, reason: `${ref} cites region '${fmtReason(id)}' with empty OCR` };
    }
    texts.push(ocr.text);
  }
  const joined = normalizeText(texts.join('\n'));
  const needle = normalizeText(claim.value);
  if (!needle || !containsBounded(joined, needle)) {
    return { usable: null, reason: `${ref} value not found at token boundaries in cited region OCR` };
  }
  return {
    usable: {
      type: claim.type,
      value: claim.value,
      regionIds: [...claim.regionIds]
    },
    reason: null
  };
}

function fieldResult(field, status, uiValue, txValue, evidenceRefs, reason, extra) {
  return {
    field,
    status,
    uiValue: uiValue === undefined ? null : uiValue,
    txValue: txValue === undefined ? null : txValue,
    evidenceRefs: evidenceRefs || [],
    reason,
    ...(extra || {})
  };
}

function inconclusive(field, reason, extra) {
  return fieldResult(field, 'INCONCLUSIVE', null, null, [], reason, extra);
}

// Attribution over corroborated amount claims for one expected (symbol,
// decimals, raw tx value). Candidates whose own region text carries an
// excluded display role (fee, balance, quote, minimum — and allowance
// outside the allowance field) are set aside first, so a fee row can never
// be compared as the transaction amount even when linked. Zero eligible:
// missing (naming the excluded roles when that is why). One: the display
// role must still be attributable before any exact compare — a lone number
// is never assumed to be the transaction amount. Several: ambiguous, with
// every candidate's references preserved for audit.
function compareAttributedAmount(field, role, usableAmounts, expectedSymbol, decimals, txRaw, txRef, isAttributed, getRoles, excludedRoles) {
  const cands = usableAmounts.filter((c) => symbolsEquivalent(c.symbol, expectedSymbol));
  if (cands.length === 0) {
    return inconclusive(field, `no corroborated UI amount in ${expectedSymbol}`, { amountRole: role });
  }
  const eligible = [];
  const excluded = [];
  for (const cand of cands) {
    const roles = [...getRoles(cand)].filter((r) => excludedRoles.has(r));
    if (roles.length > 0) excluded.push({ cand, roles });
    else eligible.push(cand);
  }
  if (eligible.length === 0) {
    const roles = [...new Set(excluded.flatMap((e) => e.roles))].sort().join(', ');
    return fieldResult(field, 'INCONCLUSIVE', null, null,
      excluded.flatMap((e) => [`claim#${e.cand.claimRef}`, ...e.cand.regionIds.map((id) => `ocr:${id}`)]),
      `candidate amount(s) carry excluded display role(s) (${roles}); no attributable ${role} amount`,
      { amountRole: role });
  }
  const candsRef = (list) => list.flatMap((c) => [`claim#${c.claimRef}`, ...c.regionIds.map((id) => `ocr:${id}`)]);
  if (eligible.length > 1) {
    return fieldResult(field, 'INCONCLUSIVE', null, null, candsRef(eligible),
      `${eligible.length} corroborated ${expectedSymbol} amounts; attribution ambiguous`,
      { amountRole: role });
  }
  const cand = eligible[0];
  const candRefs = [`claim#${cand.claimRef}`, ...cand.regionIds.map((id) => `ocr:${id}`)];
  if (!isAttributed(cand)) {
    return fieldResult(field, 'INCONCLUSIVE', null, null, candRefs,
      `UI amount '${cand.raw}' has no attributable ${role} display role`, { amountRole: role });
  }
  const uiUnits = displayToBaseUnits(cand.number, decimals);
  if (uiUnits === null) {
    return fieldResult(field, 'INCONCLUSIVE', null, null, candRefs,
      `UI amount '${cand.raw}' is malformed or over-precise for ${decimals} decimals`, { amountRole: role });
  }
  const txUnits = parseBigIntStrict(txRaw);
  if (txUnits === null) {
    return fieldResult(field, 'INCONCLUSIVE', null, null, [...candRefs, `tx:${txRef}`],
      `decoded ${role} is missing or malformed`, { amountRole: role });
  }
  const refs = [...candRefs, `tx:${txRef}`];
  if (uiUnits === txUnits) {
    return fieldResult(field, 'MATCH', cand.raw, String(txUnits), refs, `exact equality at ${decimals} decimals`, { amountRole: role });
  }
  return fieldResult(field, 'MISMATCH', cand.raw, String(txUnits), refs, `UI ${cand.raw} != decoded ${String(txUnits)} base units`, { amountRole: role });
}

// Counterparty attribution: elimination first (known non-counterparty tx
// addresses, sender, source labels), then POSITIVE role attribution. The
// last remaining address is never assumed to be the counterparty: without a
// destination label or a strong recipient link it stays inconclusive, with
// its references preserved.
function compareCounterparty(role, usableAddresses, counterparty, counterpartyRef, otherTxAddresses, roleEvidence) {
  const known = new Set(
    (otherTxAddresses || [])
      .filter((a) => typeof a === 'string' && FULL_ADDRESS_RE.test(a))
      .map((a) => a.toLowerCase())
  );
  const fresh = usableAddresses
    .filter((c) => !known.has(c.value.toLowerCase()))
    .filter((c) => !roleEvidence.isSourceLabeled(c));
  if (fresh.length === 0) {
    return inconclusive('counterparty', `no corroborated UI address attributable to ${role}`, { role });
  }
  const candRefsFor = (list) => list.flatMap((c) => [`claim#${c.claimRef}`, ...c.regionIds.map((id) => `ocr:${id}`)]);
  if (fresh.length > 1) {
    return fieldResult('counterparty', 'INCONCLUSIVE', null, null, candRefsFor(fresh),
      `${fresh.length} candidate UI addresses for ${role}; attribution ambiguous`, { role });
  }
  const cand = fresh[0];
  const candRefs = candRefsFor([cand]);
  if (!roleEvidence.isAttributed(cand)) {
    return fieldResult('counterparty', 'INCONCLUSIVE', null, null, candRefs,
      `UI address has no attributable ${role} display role`, { role });
  }
  if (typeof counterparty !== 'string' || !FULL_ADDRESS_RE.test(counterparty)) {
    return fieldResult('counterparty', 'INCONCLUSIVE', null, null, [...candRefs, `tx:${counterpartyRef}`],
      `decoded ${role} is missing or invalid`, { role });
  }
  const refs = [...candRefs, `tx:${counterpartyRef}`];
  if (sameAddress(cand.value, counterparty)) {
    return fieldResult('counterparty', 'MATCH', cand.value, counterparty, refs, `exact address equality for ${role}`, { role });
  }
  return fieldResult('counterparty', 'MISMATCH', cand.value, counterparty, refs, `UI address differs from decoded ${role}`, { role });
}

// Region ids carrying a role in a strong-method link of one of the given
// kinds. Only observed link structures count; proximity adjacency never does.
function linkedRegionIds(links, kinds, role) {
  const ids = new Set();
  for (const link of links || []) {
    if (!link || typeof link !== 'object') continue;
    if (!STRONG_LINK_METHODS.has(link.method) || !kinds.includes(link.kind)) continue;
    const members = Array.isArray(link.members) ? link.members : [];
    for (const member of members) {
      if (member && typeof member.regionId === 'string' && member.role === role) ids.add(member.regionId);
    }
  }
  return ids;
}

/**
 * Compare corroborated UI facts against decoded transaction facts.
 * @param {object} uiFacts { regions, claims, associations?, domText? (never
 *   trusted), } Regions: [{regionId, genuine?, synthetic?, ocr?}]. Claims:
 *   validated grounding records [{type, value, regionIds, associationIds,
 *   status}].
 * @param {object} decodedFacts Decoder-shaped facts { contract, functionName,
 *   standard, parameters, isUnlimitedApproval, valueWei, valueEth, symbol?,
 *   decimals?, ruleFindings?, tokenMeta? }. tokenMeta maps lowercase address
 *   to trusted {symbol, decimals} for non-target tokens (e.g. swap legs).
 * @returns {{fields: Array, summary: {match, mismatch, inconclusive},
 *   overall: 'MATCH'|'MISMATCH'|'INCONCLUSIVE'}}
 */
function compareIntentToTx(uiFacts, decodedFacts) {
  if (!uiFacts || typeof uiFacts !== 'object' || Array.isArray(uiFacts)) {
    throw new TypeError('compareIntentToTx: uiFacts must be an object.');
  }
  if (!decodedFacts || typeof decodedFacts !== 'object' || Array.isArray(decodedFacts)) {
    throw new TypeError('compareIntentToTx: decodedFacts must be an object.');
  }

  const regions = Array.isArray(uiFacts.regions) ? uiFacts.regions : [];
  const regionMap = new Map(
    regions.filter((r) => r && typeof r.regionId === 'string').map((r) => [r.regionId, r])
  );
  const ambiguities = (uiFacts.associations && Array.isArray(uiFacts.associations.ambiguities))
    ? uiFacts.associations.ambiguities : [];
  const ambiguityIds = new Set(
    ambiguities.filter((a) => a && typeof a.ambiguityId === 'string').map((a) => a.ambiguityId)
  );
  const rawClaims = Array.isArray(uiFacts.claims) ? uiFacts.claims : [];
  const usable = [];
  rawClaims.forEach((claim, index) => {
    const { usable: ok } = corroborateClaim(claim, index, regionMap, ambiguityIds);
    if (ok) usable.push({ ...ok, index });
  });

  // Display-role attribution from observed association links. An amount is
  // attributable as a transaction amount only inside a strong action-amount
  // link; fees, balances, and quotes carry no such linkage.
  const links = (uiFacts.associations && Array.isArray(uiFacts.associations.links))
    ? uiFacts.associations.links : [];
  const amountLinked = linkedRegionIds(links, ['action-amount'], 'amount');
  const recipientLinked = linkedRegionIds(links, ['action-recipient', 'amount-recipient'], 'recipient');
  const regionTextMatches = (cand, re) => (cand.regionIds || []).some((id) => {
    const reg = regionMap.get(id);
    const text = reg && reg.ocr && typeof reg.ocr.text === 'string' ? reg.ocr.text : '';
    return re.test(text);
  });
  const isAmountAttributed = (cand) => (cand.regionIds || []).some((id) => amountLinked.has(id));
  // Excluded display roles across the candidate's own cited regions. Any
  // cited region carrying an excluded role disqualifies the candidate for
  // fields that exclude that role — erring toward INCONCLUSIVE on mixed
  // evidence rather than guessing which region describes the value.
  const amountRolesOf = (cand) => {
    const roles = new Set();
    for (const id of (cand.regionIds || [])) {
      const reg = regionMap.get(id);
      const text = reg && reg.ocr && typeof reg.ocr.text === 'string' ? reg.ocr.text : '';
      for (const role of rolesOfRegionText(text)) roles.add(role);
    }
    return roles;
  };
  const counterpartyEvidence = {
    isSourceLabeled: (cand) => regionTextMatches(cand, SOURCE_LABEL_RE),
    isAttributed: (cand) => regionTextMatches(cand, DEST_LABEL_RE)
      || (cand.regionIds || []).some((id) => recipientLinked.has(id))
  };

  const byType = (type) => usable.filter((c) => c.type === type);
  const usableAmounts = byType('amount')
    .map((c) => {
      const parsed = parseClaimAmount(c.value);
      if (!parsed || parsed.fiat || !parsed.symbol) return null;
      if (FIAT_WORDS.has(parsed.symbol)) return null;
      return { raw: c.value, number: parsed.number, symbol: parsed.symbol, claimRef: c.index, regionIds: c.regionIds };
    })
    .filter(Boolean);
  const usableAddresses = byType('recipient')
    .filter((c) => FULL_ADDRESS_RE.test(c.value))
    .map((c) => ({ value: c.value, claimRef: c.index, regionIds: c.regionIds }));

  // Operation context for approval verbs: an attributed counterparty
  // address, an attributed crypto amount that is not fee/balance/quote/
  // minimum-labeled, or a corroborated approval-scope claim anywhere in the
  // evaluation. A bare "Approve" button with none of these cannot establish
  // an approval operation.
  const hasApprovalContext =
    usableAddresses.some((c) => !counterpartyEvidence.isSourceLabeled(c) && counterpartyEvidence.isAttributed(c))
    || usableAmounts.some((c) => isAmountAttributed(c)
      && ![...amountRolesOf(c)].some((r) => AMOUNT_ROLES_NON_ALLOWANCE.has(r)))
    || byType('approval').length > 0;

  const params = (decodedFacts.parameters && typeof decodedFacts.parameters === 'object')
    ? decodedFacts.parameters : {};
  const fn = decodedFacts.functionName;
  const tokenMeta = (decodedFacts.tokenMeta && typeof decodedFacts.tokenMeta === 'object')
    ? decodedFacts.tokenMeta : {};
  const targetMeta = validTokenMeta({ symbol: decodedFacts.symbol, decimals: decodedFacts.decimals })
    ? { symbol: decodedFacts.symbol, decimals: decodedFacts.decimals }
    : null;

  const fields = [];

  // 1. Action. Mapped verbs only; unknown/unsupported/decoded-unknown always
  // inconclusive. Conflicting mapped claims are ambiguity, not a vote.
  {
    const actionClaims = byType('action');
    const mapped = actionClaims.map((c) => {
      const hit = ACTION_MAP.find((e) => e.pattern.test(c.value));
      return hit ? hit.functions : null;
    });
    const usable_mapped = mapped.filter(Boolean);
    if (actionClaims.length === 0) {
      fields.push(inconclusive('action', 'no corroborated UI action'));
    } else if (usable_mapped.length === 0) {
      fields.push(inconclusive('action', 'UI action uses an unsupported operation vocabulary'));
    } else if (usable_mapped.length !== actionClaims.length) {
      fields.push(inconclusive('action', 'UI actions mix supported and unsupported operations'));
    } else if (new Set(usable_mapped.map((fns) => fns.join('|'))).size > 1) {
      fields.push(inconclusive('action', 'UI actions map to conflicting operations'));
    } else if (fn === 'unknownFunction' || decodedFacts.standard === 'Unknown' || typeof fn !== 'string'
      || fn === 'permit' || fn === 'permitTransferFrom') {
      fields.push(inconclusive('action', 'decoded operation is unknown or its inner semantics are undecodable'));
    } else if (fn === 'multicall') {
      // Capability 4 B4: inners are decoded operations now. MATCH when
      // the UI verb maps to a decoded inner operation; never MISMATCH
      // (a batch may mix operations the UI describes partially).
      const inners = collectInnerFunctions(params.calls);
      const refs = [
        ...actionClaims.map((c) => `claim#${c.index}`),
        ...actionClaims.flatMap((c) => c.regionIds.map((id) => `ocr:${id}`)),
        'tx:parameters.calls'
      ];
      if (inners.length === 0) {
        fields.push(inconclusive('action', 'multicall carries no decoded inner operations'));
      } else if (usable_mapped[0] === APPROVE_FUNCTIONS && !hasApprovalContext) {
        fields.push(inconclusive('action', 'approval verb without corroborated operation context (spender, allowance, or approval scope)'));
      } else {
        const fns = usable_mapped[0];
        const hit = inners.filter((f) => fns.includes(f));
        fields.push(hit.length > 0
          ? fieldResult('action', 'MATCH', actionClaims.map((c) => c.value).join(' | '), hit.join(', '), refs, `UI verb matches decoded inner operation(s): ${hit.join(', ')}`)
          : inconclusive('action', `UI verb maps to ${fns.join('/')} but no decoded inner performs it (inners: ${inners.join(', ')})`));
      }
    } else if (usable_mapped[0] === APPROVE_FUNCTIONS && !hasApprovalContext) {
      fields.push(inconclusive('action', 'approval verb without corroborated operation context (spender, allowance, or approval scope)'));
    } else {
      const fns = usable_mapped[0];
      const refs = [
        ...actionClaims.map((c) => `claim#${c.index}`),
        ...actionClaims.flatMap((c) => c.regionIds.map((id) => `ocr:${id}`)),
        'tx:functionName'
      ];
      fields.push(fns.includes(fn)
        ? fieldResult('action', 'MATCH', actionClaims.map((c) => c.value).join(' | '), fn, refs, 'UI verb unambiguously matches decoded operation')
        : fieldResult('action', 'MISMATCH', actionClaims.map((c) => c.value).join(' | '), fn, refs, 'UI verb conflicts with decoded operation'));
    }
  }

  // 2. Target/router identity. Phase A has no deterministic UI-side
  // router-identity extractor; the field exists so the gap stays explicit.
  fields.push(inconclusive('target', 'no deterministic UI router-identity extractor in Phase A'));

  // 3. Native value. Compared only where msg.value IS the operative
  // amount (native transfers, deposits). Token-function amounts compare
  // under tokenAmount; swap value defers to the input leg; a withdrawal
  // display is never msg.value. A displayed ETH/WETH figure is otherwise
  // not a native-value candidate.
  if (fn === 'nativeTransfer' || fn === 'deposit') {
    fields.push(compareAttributedAmount(
      'nativeValue', 'native-value', usableAmounts, 'ETH', NATIVE_DECIMALS,
      decodedFacts.valueWei, 'valueWei', isAmountAttributed, amountRolesOf, AMOUNT_ROLES_ALL
    ));
  } else {
    const why = fn === 'exactInputSingle'
      ? 'swap value defers to input-leg comparison'
      : fn === 'withdraw'
        ? 'withdrawal amount is decoded from arguments, not msg.value'
        : ['approve', 'increaseAllowance', 'transfer', 'transferFrom', 'setApprovalForAll'].includes(fn)
          ? 'token-function amounts compare under tokenAmount'
          : 'operation semantics undecodable for native value';
    fields.push(inconclusive('nativeValue', why));
  }

  // 4. Asset symbol, single-token contexts only. Swaps carry two tokens, so
  // no UI asset mention can be attributed to either leg.
  {
    const singleTokenFn = ['approve', 'increaseAllowance', 'transfer', 'transferFrom'].includes(fn);
    const assetClaims = byType('asset')
      .filter((c) => /^[A-Za-z$]{1,12}$/.test(c.value.trim()))
      .filter((c) => !c.value.includes('$') && !FIAT_WORDS.has(c.value.trim().toUpperCase()));
    if (!singleTokenFn && fn !== 'nativeTransfer') {
      fields.push(inconclusive('asset', `asset attribution unsafe for '${fmtReason(fn)}'`));
    } else if (assetClaims.length === 0) {
      fields.push(inconclusive('asset', 'no corroborated UI asset symbol'));
    } else if (new Set(assetClaims.map((c) => c.value.trim().toUpperCase())).size > 1) {
      fields.push(inconclusive('asset', 'UI names conflicting assets'));
    } else {
      const expected = fn === 'nativeTransfer' ? 'ETH' : (targetMeta ? targetMeta.symbol : null);
      if (!expected) {
        fields.push(inconclusive('asset', 'decoded token identity unknown'));
      } else {
        const uiSymbol = assetClaims[0].value.trim().toUpperCase();
        const txRef = fn === 'nativeTransfer' ? 'tx:functionName(native-ETH)' : 'tx:symbol';
        const refs = [
          ...assetClaims.map((c) => `claim#${c.index}`),
          ...assetClaims.flatMap((c) => c.regionIds.map((id) => `ocr:${id}`)),
          txRef
        ];
        fields.push(symbolsEquivalent(uiSymbol, expected)
          ? fieldResult('asset', 'MATCH', uiSymbol, expected, refs, fn === 'nativeTransfer' ? 'native asset agrees' : 'single-token asset symbols agree')
          : fieldResult('asset', 'MISMATCH', uiSymbol, expected, refs, 'UI asset differs from decoded token'));
      }
    }
  }

  // 5. Counterparty, role-separated per function. The sender, the
  // transferFrom source, the target, and swap legs are elimination
  // candidates, never comparison targets; survivors still need positive
  // role attribution (destination label or strong recipient link).
  {
    const target = decodedFacts.contract;
    const sender = decodedFacts.sender;
    if (fn === 'approve' || fn === 'increaseAllowance') {
      fields.push(compareCounterparty('spender', usableAddresses, params.spender, 'parameters.spender', [target, sender], counterpartyEvidence));
    } else if (fn === 'transfer') {
      fields.push(compareCounterparty('transfer-recipient', usableAddresses, params.recipient, 'parameters.recipient', [target, sender], counterpartyEvidence));
    } else if (fn === 'transferFrom') {
      fields.push(compareCounterparty('transfer-recipient', usableAddresses, params.recipient, 'parameters.recipient', [target, sender, params.sender], counterpartyEvidence));
    } else if (fn === 'setApprovalForAll') {
      fields.push(compareCounterparty('operator', usableAddresses, params.operator, 'parameters.operator', [target, sender], counterpartyEvidence));
    } else if (fn === 'exactInputSingle') {
      fields.push(compareCounterparty(
        'swap-recipient', usableAddresses, params.recipient, 'parameters.recipient',
        [target, params.tokenIn, params.tokenOut, sender], counterpartyEvidence
      ));
    } else if (fn === 'nativeTransfer') {
      fields.push(compareCounterparty('native-recipient', usableAddresses, target, 'contract', [sender], counterpartyEvidence));
    } else {
      fields.push(inconclusive('counterparty', `no counterparty semantics for '${fmtReason(fn)}'`));
    }
  }

  // 6. Token amount, role-separated. The decoded token's own
  // symbol/decimals gate every comparison; defaults are never invented.
  {
    if (fn === 'approve' || fn === 'increaseAllowance') {
      if (!targetMeta) {
        fields.push(inconclusive('tokenAmount', 'decoded token identity/decimals unknown', { amountRole: 'allowance' }));
      } else {
        fields.push(compareAttributedAmount(
          'tokenAmount', 'allowance', usableAmounts, targetMeta.symbol, targetMeta.decimals,
          params.amount, 'parameters.amount', isAmountAttributed, amountRolesOf, AMOUNT_ROLES_NON_ALLOWANCE
        ));
      }
    } else if (fn === 'transfer' || fn === 'transferFrom') {
      if (!targetMeta) {
        fields.push(inconclusive('tokenAmount', 'decoded token identity/decimals unknown', { amountRole: 'transfer-amount' }));
      } else {
        fields.push(compareAttributedAmount(
          'tokenAmount', 'transfer-amount', usableAmounts, targetMeta.symbol, targetMeta.decimals,
          params.amount, 'parameters.amount', isAmountAttributed, amountRolesOf, AMOUNT_ROLES_ALL
        ));
      }
    } else if (fn === 'exactInputSingle') {
      const inAddr = String(params.tokenIn || '').toLowerCase();
      const inMeta = validTokenMeta(tokenMeta[inAddr]) ? tokenMeta[inAddr] : null;
      if (!inMeta) {
        fields.push(inconclusive('tokenAmount', 'swap input token identity/decimals not supplied', { amountRole: 'swap-input' }));
      } else {
        fields.push(compareAttributedAmount(
          'tokenAmount', 'swap-input', usableAmounts, inMeta.symbol, inMeta.decimals,
          params.amountIn, 'parameters.amountIn', isAmountAttributed, amountRolesOf, AMOUNT_ROLES_ALL
        ));
      }
    } else {
      fields.push(inconclusive('tokenAmount', `no token-amount semantics for '${fmtReason(fn)}'`, { amountRole: 'none' }));
    }
  }

  // 7. Swap output. A displayed quote and the calldata minimum are different
  // concepts; no equivalence comparison is attempted in Phase A.
  fields.push(fn === 'exactInputSingle'
    ? inconclusive('swapOutput', 'displayed output quotes are estimates, not comparable to amountOutMinimum')
    : inconclusive('swapOutput', 'not a swap transaction'));

  // 7b. Output protection (Capability 4 B3). swapOutput above stays
  // INCONCLUSIVE, but the JOINT fact — a corroborated displayed quote
  // beside an enforced floor — is interpretable: a zero floor means
  // none of the displayed expectation is enforced, and a floor above
  // the quote means the quoted outcome is unsatisfiable as stated.
  // Partial gaps are indicative only (the quote is an estimate) and
  // stay INCONCLUSIVE with the ratio recorded for the bundle.
  {
    if (fn !== 'exactInputSingle') {
      fields.push(inconclusive('outputProtection', 'not a swap transaction'));
    } else {
      const outAddr = String(params.tokenOut || '').toLowerCase();
      const outMeta = validTokenMeta(tokenMeta[outAddr]) ? tokenMeta[outAddr] : null;
      if (!outMeta) {
        fields.push(inconclusive('outputProtection', 'swap output token identity/decimals not supplied'));
      } else {
        const quotes = usableAmounts.filter((c) => symbolsEquivalent(c.symbol, outMeta.symbol)
          && [...amountRolesOf(c)].includes('quote'));
        if (quotes.length === 0) {
          fields.push(inconclusive('outputProtection', `no corroborated ${outMeta.symbol} output quote to relate to the enforced minimum`));
        } else if (quotes.length > 1 || !isAmountAttributed(quotes[0])) {
          fields.push(fieldResult('outputProtection', 'INCONCLUSIVE', null, null,
            quotes.flatMap((c) => [`claim#${c.claimRef}`, ...c.regionIds.map((id) => `ocr:${id}`)]),
            quotes.length > 1
              ? `${quotes.length} corroborated ${outMeta.symbol} output quotes; attribution ambiguous`
              : `UI output quote '${quotes[0].raw}' is not attributed to the swap output`));
        } else {
          const q = quotes[0];
          const quoteUnits = displayToBaseUnits(q.number, outMeta.decimals);
          const gap = analyzeOutputGap({ amountOutMinimum: params.amountOutMinimum, quotedOutputWei: quoteUnits });
          const refs = [`claim#${q.claimRef}`, ...q.regionIds.map((id) => `ocr:${id}`), 'tx:parameters.amountOutMinimum'];
          if (gap.status !== 'analyzed') {
            fields.push(fieldResult('outputProtection', 'INCONCLUSIVE', q.raw,
              params.amountOutMinimum === undefined ? null : String(params.amountOutMinimum), refs, gap.reason));
          } else if (gap.level === 'unprotected') {
            fields.push(fieldResult('outputProtection', 'MISMATCH', q.raw, '0', refs,
              `displayed ${outMeta.symbol} quote ${q.raw} is entirely unenforced (amountOutMinimum = 0)`,
              { gapBps: gap.gapBps, level: gap.level }));
          } else if (gap.level === 'minimum-exceeds-quote') {
            fields.push(fieldResult('outputProtection', 'MISMATCH', q.raw, gap.minOutWei, refs,
              `enforced minimum ${gap.minOutWei} base units exceeds displayed quote ${q.raw}: quoted outcome unsatisfiable as stated`,
              { gapBps: gap.gapBps, level: gap.level }));
          } else {
            fields.push(fieldResult('outputProtection', 'INCONCLUSIVE', q.raw, gap.minOutWei, refs,
              `indicative protection gap ${gap.gapBps} bps (quote is an estimate; minimum is enforced)`,
              { gapBps: gap.gapBps, level: gap.level }));
          }
        }
      }
    }
  }

  // 8. Approval scope. Displayed unlimited-vocabulary is never equated with
  // the 2^255 threshold without an explicit policy; NFT all-collection
  // approval has no deterministic UI boolean source.
  {
    const approvalClaims = byType('approval');
    const unlimitedShown = approvalClaims.some((c) =>
      UNLIMITED_WORDS.some((w) => normalizeText(c.value).includes(w)));
    if (fn === 'approve' || fn === 'increaseAllowance') {
      fields.push(unlimitedShown
        ? inconclusive('approvalScope', 'UI shows unlimited-vocabulary approval; no exact-equality policy for display wording vs 2^255 threshold')
        : inconclusive('approvalScope', 'no corroborated UI approval-scope statement'));
    } else if (fn === 'setApprovalForAll') {
      fields.push(inconclusive('approvalScope', 'all-collection approval scope has no deterministic UI boolean source'));
    } else {
      fields.push(inconclusive('approvalScope', 'not an approval transaction'));
    }
  }

  // 9. Warnings vs findings (Capability 3 B5). Strict promotion beyond
  // inconclusive-only: a warning MATCHES only when its text names the
  // finding's risk class; safety claims contradicting standing findings
  // MISMATCH; an agent purpose (fully observed stated intent) that
  // omits a material risk MISMATCHes. Browser absence stays
  // inconclusive — OCR gaps make visual absence unprovable.
  {
    const findings = Array.isArray(decodedFacts.ruleFindings) ? decodedFacts.ruleFindings : [];
    const notable = findings.filter((r) => r && (r.severity === 'HIGH' || r.severity === 'CRITICAL'));
    const warnClaims = byType('warning');
    const claimFullText = (c) => {
      const ocrBits = (c.regionIds || []).map((id) => {
        const reg = regionMap.get(id);
        return reg && reg.ocr && typeof reg.ocr.text === 'string' ? reg.ocr.text : '';
      });
      return `${c.value || ''}\n${ocrBits.join('\n')}`;
    };
    const classWords = (ruleId) => FINDING_CLASS_WORDS[ruleId] || GENERIC_RISK_WORDS;
    const claimRefs = (c) => [`claim#${c.index}`, ...(c.regionIds || []).map((id) => `ocr:${id}`)];
    if (notable.length === 0) {
      if (warnClaims.length > 0) {
        fields.push(inconclusive('warning', 'UI shows a warning with no decoded findings to relate it to'));
      } else {
        fields.push(inconclusive('warning', 'no warning observed and none required by decoded findings; absence unprovable'));
      }
    } else {
      const notableIds = notable.map((f) => f.ruleId);
      const safetyHit = [...warnClaims, ...byType('action')].find((c) => SAFETY_CLAIM_RE.test(claimFullText(c)));
      const approvalFn = fn === 'approve' || fn === 'increaseAllowance' || fn === 'setApprovalForAll';
      const denialHit = approvalFn && [...warnClaims, ...byType('action')]
        .find((c) => APPROVAL_DENIAL_RES.some((re) => re.test(claimFullText(c))));
      const accurateHit = warnClaims.find((c) => {
        const text = normalizeText(claimFullText(c));
        return notable.some((f) => classWords(f.ruleId).some((w) => text.includes(w)));
      });
      if (safetyHit) {
        fields.push(fieldResult('warning', 'MISMATCH', String(safetyHit.value).slice(0, 120), notableIds.join(','),
          [...claimRefs(safetyHit), ...notableIds.map((id) => `finding:${id}`)],
          'presentation safety claim contradicts standing security findings'));
      } else if (denialHit) {
        fields.push(fieldResult('warning', 'MISMATCH', String(denialHit.value).slice(0, 120), fn,
          [...claimRefs(denialHit), 'tx:functionName'],
          'presentation denies the approval the transaction requires'));
      } else if (accurateHit) {
        // Capability 4 B10: disclosure specificity. Naming the risk class
        // is a MATCH either way (pinned behavior), but a warning that
        // names a concrete finding element (address, amount, limit) is
        // specifically evidenced; class-words-only is generic. Verdict
        // unchanged; the tier informs review, not the outcome.
        let specificity = 'generic';
        let namedElements = [];
        try {
          // eslint-disable-next-line global-require
          const { findNamedElements } = require('./visualRoles');
          namedElements = findNamedElements(claimFullText(accurateHit), {
            decodedTx: decodedFacts,
            findings: notable
          }).map((e) => e.kind);
          if (namedElements.length > 0) specificity = 'specific';
        } catch {
          specificity = 'unassessed';
        }
        fields.push(fieldResult('warning', 'MATCH', String(accurateHit.value).slice(0, 120), notableIds.join(','),
          [...claimRefs(accurateHit), ...notableIds.map((id) => `finding:${id}`)],
          `warning accurately names the finding risk class (${specificity} disclosure)`,
          { specificity, namedElements }));
      } else if (typeof uiFacts.statedIntent === 'string' && uiFacts.statedIntent.length > 0) {
        const intentText = normalizeText(uiFacts.statedIntent);
        const disclosed = notable.some((f) => classWords(f.ruleId).some((w) => intentText.includes(w)));
        fields.push(disclosed
          ? fieldResult('warning', 'MATCH', uiFacts.statedIntent.slice(0, 120), notableIds.join(','),
            ['dom', ...notableIds.map((id) => `finding:${id}`)], 'stated intent discloses the finding risk class')
          : fieldResult('warning', 'MISMATCH', uiFacts.statedIntent.slice(0, 120), notableIds.join(','),
            ['dom', ...notableIds.map((id) => `finding:${id}`)], 'stated intent omits a material finding risk'));
      } else if (warnClaims.length > 0) {
        fields.push(inconclusive('warning', 'UI shows a warning but its relevance to the decoded findings is unverifiable'));
      } else {
        fields.push(inconclusive('warning', 'decoded findings exist but no warning observed; absence unprovable with incomplete visual coverage'));
      }
    }
  }

  const summary = { match: 0, mismatch: 0, inconclusive: 0 };
  // 10. Agent-evidence corroboration (Capability 3 B6). Region-less
  // path: 0x addresses named in admitted agent evidence are checked
  // against the decoded counterparties. Appended only when agent
  // evidence is present, so region-based investigations are untouched.
  {
    const items = Array.isArray(uiFacts.agentEvidence) ? uiFacts.agentEvidence : [];
    if (items.length > 0) {
      const parties = new Set();
      for (const p of [decodedFacts.contract, decodedFacts.sender, decodedFacts.parameters && decodedFacts.parameters.spender,
        decodedFacts.parameters && decodedFacts.parameters.recipient, decodedFacts.parameters && decodedFacts.parameters.operator,
        decodedFacts.parameters && decodedFacts.parameters.to]) {
        if (typeof p === 'string' && /^0x[0-9a-fA-F]{40}$/.test(p)) parties.add(p.toLowerCase());
      }
      const named = [];
      for (const it of items) {
        if (!it || typeof it.content !== 'string') continue;
        const addrs = it.content.match(/0x[0-9a-fA-F]{40}/g) || [];
        for (const a of addrs) named.push({ id: it.id, address: a.toLowerCase() });
      }
      if (named.length === 0) {
        fields.push(inconclusive('agentCorroboration', 'agent evidence names no testable addresses'));
      } else {
        const hit = named.find((n) => parties.has(n.address));
        const refs = [...new Set(named.map((n) => n.id))];
        fields.push(hit
          ? fieldResult('agentCorroboration', 'MATCH', hit.address, [...parties].join(','), [...refs, 'tx:target'],
            `agent evidence ${hit.id} names decoded counterparty ${hit.address}`)
          : fieldResult('agentCorroboration', 'MISMATCH', named.map((n) => n.address).join(','), [...parties].join(',') || '(none)', refs,
            'agent evidence names counterparties absent from the decoded transaction'));
      }
    }
  }

  for (const f of fields) {
    if (f.status === 'MATCH') summary.match += 1;
    else if (f.status === 'MISMATCH') summary.mismatch += 1;
    else summary.inconclusive += 1;
  }
  const overall = summary.mismatch > 0
    ? 'MISMATCH'
    : (summary.inconclusive > 0 ? 'INCONCLUSIVE' : 'MATCH');

  return { fields, summary, overall };
}

module.exports = { compareIntentToTx };