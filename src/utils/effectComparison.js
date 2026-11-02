/**
 * Requested-vs-actual effect comparison (Capability 5, B3).
 *
 * Answers, per reconstructed effect: was this requested? And per
 * corroborated request element: does any effect carry it out? Pure
 * deterministic comparison over grounded claims + the B2 effect list.
 *
 * Trust posture (mirrors intentComparison.js):
 * - Only 'supported' grounding claims participate. Unobserved,
 *   failed, or synthetic OCR never corroborates a request.
 * - With no relevant request evidence, every effect is INCONCLUSIVE
 *   — absence of a request record is not an unrequested effect.
 * - Opaque effects are excluded: their uncertainty is already owned
 *   by decode/unknown-function handling, not re-litigated here.
 * - Amount matching is decimal-aware only with verified decimals;
 *   otherwise exact raw-digit agreement is required.
 *
 * Output shape matches intentComparison fields so the adapter can
 * merge: [{ field, status, ui, tx, refs, reason, extra }].
 */

const ACTION_VERBS = [
  ['swap', /\bswap(ping|ped)?\b/i],
  ['transfer', /\b(transfer(ring|red)?|send(ing|s)?|pay(ment|ing)?)\b/i],
  ['approve', /\bapprov(e|al|ing)?\b/i],
  ['deposit', /\bdeposit(ing|ed|s)?\b/i],
  ['withdraw', /\bwithdraw(al|ing|ing)?\b/i],
  ['admin', /\b(owner(ship)?|admin|role|upgrade|pause|unpause|authority|governance)\b/i],
  ['bridge', /\bbridg(e|ing|ed)?\b/i]
];

const EFFECT_FAMILY = {
  'native-transfer': 'transfer', transfer: 'transfer', 'transfer-nft': 'transfer',
  swap: 'swap', approval: 'approve', 'approval-nft': 'approve',
  'permit-authorization': 'approve', wrap: 'deposit', unwrap: 'withdraw',
  'authority-change': 'admin', bridge: 'bridge', opaque: null
};

const FULL_ADDRESS_RE = /0x[0-9a-fA-F]{40}/g;

function regionTextById(regions) {
  const map = new Map();
  for (const r of (Array.isArray(regions) ? regions : [])) {
    if (!r || typeof r.regionId !== 'string') continue;
    const t = r.ocr && typeof r.ocr.text === 'string' ? r.ocr.text : '';
    map.set(r.regionId, t);
  }
  return map;
}

function claimFullText(claim, regionTexts) {
  const parts = [];
  if (claim && typeof claim.value === 'string') parts.push(claim.value);
  for (const id of (claim && Array.isArray(claim.regionIds) ? claim.regionIds : [])) {
    if (regionTexts.has(id)) parts.push(regionTexts.get(id));
  }
  return parts.join('\n');
}

function supportedClaims(claims) {
  return (Array.isArray(claims) ? claims : []).filter((c) => c && c.status === 'supported');
}

function digitsOf(s) {
  return String(s || '').replace(/[^0-9]/g, '');
}

function addressMentions(text) {
  FULL_ADDRESS_RE.lastIndex = 0;
  return (String(text || '').match(FULL_ADDRESS_RE) || []).map((a) => a.toLowerCase());
}

function addressFragmentHit(text, address) {
  if (typeof address !== 'string' || address.length !== 42) return false;
  const low = String(text || '').toLowerCase();
  if (low.includes(address.toLowerCase())) return true;
  for (const m of (low.match(/0x[0-9a-f]{8,40}/g) || [])) {
    if (address.toLowerCase().startsWith(m)) return true;
  }
  return false;
}

// Decimal-aware exact amount agreement. Claim texts carry display
// values ('1.0 ETH', '1,000 USDC'); effects carry base-unit integers.
// A claim requests an effect amount when, with exact BigInt math:
// raw equality, or scaled equality against verified decimals
// ('1.0' x 10^17 == 10^18 with 18 decimals), or truncated-display
// containment with >=4 digits on the shorter side. Addresses are
// stripped first so their hex digits never calibrate amounts.
function decimalNumbers(text) {
  const clean = String(text || '').replace(/0x[0-9a-fA-F]+/g, ' ');
  const out = [];
  const re = /(\d[\d,]*)(?:\.(\d+))?/g;
  let m;
  while ((m = re.exec(clean)) !== null) {
    const digits = ((m[1].replace(/,/g, '')) + (m[2] || '')).replace(/^0+(?=\d)/, '') || '0';
    out.push({ digits, scale: (m[2] || '').length });
  }
  return out;
}

function amountRequested(texts, effect) {
  if (!effect || typeof effect.amount !== 'string' || effect.amount.length === 0) return false;
  let amt;
  try { amt = BigInt(effect.amount); } catch { return false; }
  const dec = (effect.asset && Number.isSafeInteger(effect.asset.decimals) && effect.asset.decimals >= 0)
    ? effect.asset.decimals : null;
  for (const t of (Array.isArray(texts) ? texts : [])) {
    for (const n of decimalNumbers(t)) {
      let cn;
      try { cn = BigInt(n.digits); } catch { continue; }
      if (cn === amt) return true;
      if (dec !== null && n.scale <= dec && cn * (10n ** BigInt(dec - n.scale)) === amt) return true;
    }
    const raw = digitsOf(String(t || '').replace(/0x[0-9a-fA-F]+/g, ' '));
    if (raw.length > 0 && raw === effect.amount) return true;
    const short = Math.min(raw.length, effect.amount.length);
    if (short >= 4 && (raw.includes(effect.amount) || effect.amount.includes(raw))) return true;
  }
  return false;
}

function actionFamilyOf(text) {
  const fams = new Set();
  for (const [fam, re] of ACTION_VERBS) {
    if (re.test(String(text || ''))) fams.add(fam);
  }
  return fams;
}

function fieldResult(field, status, ui, tx, refs, reason, extra) {
  const f = { field, status, ui: String(ui).slice(0, 200), tx: String(tx).slice(0, 200), evidenceRefs: refs || [], reason };
  if (extra && typeof extra === 'object') Object.assign(f, extra);
  return f;
}

/**
 * Compare the reconstructed effect list against corroborated request
 * claims. Returns { fields, summary }.
 */
function compareEffectCoverage({ regions, claims, effects } = {}) {
  const regionTexts = regionTextById(regions);
  const supported = supportedClaims(claims);
  const list = effects && Array.isArray(effects.effects) ? effects.effects : [];
  const assessable = list.filter((e) => e && e.kind !== 'opaque');
  const fields = [];
  const summary = {
    effects: list.length, assessable: assessable.length,
    opaqueSkipped: list.length - assessable.length,
    requestedClaims: supported.length,
    unrequested: [], missing: [], inconclusive: []
  };

  if (assessable.length === 0) {
    return { fields, summary };
  }
  if (supported.length === 0) {
    for (const e of assessable) {
      summary.inconclusive.push(e.effectId);
      fields.push(fieldResult(`effect:${e.effectId}`, 'INCONCLUSIVE', '(no corroborated request)', `${e.kind} ${e.amount || ''}`.trim(),
        [e.effectId], 'no corroborated request evidence; effect cannot be judged requested or unrequested',
        { effectId: e.effectId, kind: e.kind }));
    }
    return { fields, summary };
  }

  const claimTexts = supported.map((c) => {
    const text = claimFullText(c, regionTexts);
    // Amount sources stay separate texts: the claim value ('1') and
    // its region text ('Send 1 USDC') must never concatenate into '11'.
    const texts = [...new Set([
      (c && typeof c.value === 'string' ? c.value : ''),
      ...((c && Array.isArray(c.regionIds) ? c.regionIds : [])
        .filter((id) => regionTexts.has(id))
        .map((id) => regionTexts.get(id)))
    ].filter((t) => t.length > 0))];
    return { claim: c, text, texts, families: actionFamilyOf(text) };
  });
  const byType = (t) => claimTexts.filter((c) => c.claim.type === t);

  // Funding-leg linkage: a tx-level native value leg (subcall null)
  // with the exact same base-unit amount as the tx-level operation
  // it funds (swap/wrap) is the SAME economic movement, not a second
  // payment. It inherits the sibling's coverage verdict instead of
  // demanding a separate request element. Inner value legs and
  // unequal amounts never link.
  const verdictById = new Map();
  const refsById = new Map();
  for (const e of assessable) {
    const fam = EFFECT_FAMILY[e.kind] || null;
    const refs = [e.effectId];
    let justified = null;
    // Approvals and authority changes need an explicit request of
    // their kind: an approval claim, or admin-family action wording.
    // Value effects accept amount, recipient, asset, or family proof.
    if (e.kind === 'approval' || e.kind === 'approval-nft' || e.kind === 'permit-authorization') {
      const hit = byType('approval')[0];
      if (hit) {
        justified = `approval requested (${String(hit.claim.value).slice(0, 80)})`;
        refs.push(...(hit.claim.regionIds || []));
      }
    } else if (e.kind === 'authority-change') {
      const hit = claimTexts.find((c) => c.claim.type === 'action' && c.families.has('admin'));
      if (hit) {
        justified = `administrative action requested (${String(hit.claim.value).slice(0, 80)})`;
        refs.push(...(hit.claim.regionIds || []));
      }
    } else {
      const addrHit = claimTexts.find((c) => (
        (c.claim.type === 'recipient' || c.claim.type === 'action' || c.claim.type === 'amount')
        && ((e.to && addressFragmentHit(c.text, e.to)) || (e.spender && addressFragmentHit(c.text, e.spender)))
      ));
      const amtHit = e.amount && claimTexts.find((c) => (c.claim.type === 'amount' || c.claim.type === 'action')
        && amountRequested(c.texts, e));
      const famHit = fam && claimTexts.find((c) => c.claim.type === 'action' && c.families.has(fam));
      const assetHit = e.asset && e.asset.symbol && claimTexts.find((c) => c.claim.type === 'asset'
        && String(c.text).toLowerCase().includes(String(e.asset.symbol).toLowerCase()));
      const hit = addrHit || amtHit || famHit || assetHit;
      if (hit) {
        justified = `requested (${hit.claim.type}: ${String(hit.claim.value).slice(0, 80)})`;
        refs.push(...(hit.claim.regionIds || []));
      }
    }
    if (justified) {
      verdictById.set(e.effectId, 'MATCH');
      refsById.set(e.effectId, [...new Set(refs)]);
      fields.push(fieldResult(`effect:${e.effectId}`, 'MATCH', justified, `${e.kind} ${e.amount || ''}`.trim(),
        [...new Set(refs)], 'effect traces to a corroborated request element',
        { effectId: e.effectId, kind: e.kind }));
    } else {
      verdictById.set(e.effectId, 'MISMATCH');
      summary.unrequested.push(e.effectId);
      fields.push(fieldResult(`effect:${e.effectId}`, 'MISMATCH', '(no matching request)', `${e.kind} ${e.amount || ''}`.trim(),
        [e.effectId], `no corroborated request element covers this ${e.kind} effect`,
        { effectId: e.effectId, kind: e.kind }));
    }
  }

  // Funding-leg inheritance pass (see rule above). Only upgrades a
  // MISMATCH native leg to MATCH when its funded sibling MATCHED.
  for (const e of assessable) {
    if (e.kind !== 'native-transfer') continue;
    if (e.subcall !== null && e.subcall !== undefined) continue;
    if (verdictById.get(e.effectId) !== 'MISMATCH') continue;
    if (typeof e.amount !== 'string' || e.amount.length === 0) continue;
    const sibling = assessable.find((s) => (s.kind === 'swap' || s.kind === 'wrap')
      && (s.subcall === null || s.subcall === undefined)
      && s.amount === e.amount
      && verdictById.get(s.effectId) === 'MATCH');
    if (!sibling) continue;
    verdictById.set(e.effectId, 'MATCH');
    summary.unrequested = summary.unrequested.filter((id) => id !== e.effectId);
    const f = fields.find((x) => x.field === `effect:${e.effectId}`);
    if (f) {
      f.status = 'MATCH';
      f.ui = `funding leg of ${sibling.effectId} (covered by same request)`.slice(0, 200);
      f.evidenceRefs = [...new Set([e.effectId, sibling.effectId, ...(refsById.get(sibling.effectId) || [])])];
      f.reason = `tx-value leg funds the matched ${sibling.kind}; same economic movement, not a second payment`;
      f.fundingFor = sibling.effectId;
    }
  }

  // Missing requested elements: corroborated amounts/recipients with
  // no effect carrying them. Action-family absence is owned by the
  // existing action field and not duplicated here.
  for (const c of byType('amount')) {
    const covered = assessable.some((e) => e.amount && amountRequested(c.texts, e));
    if (!covered) {
      summary.missing.push(`amount:${String(c.claim.value).slice(0, 60)}`);
      fields.push(fieldResult('effect:missing-amount', 'MISMATCH', String(c.claim.value).slice(0, 120), '(no effect carries this amount)',
        [...(c.claim.regionIds || [])], 'corroborated requested amount appears in no reconstructed effect',
        { claimType: 'amount' }));
    }
  }
  for (const c of byType('recipient')) {
    const addrs = addressMentions(c.text);
    const covered = addrs.length > 0 && assessable.some((e) => addrs.some((a) =>
      (e.to && e.to.toLowerCase() === a) || (e.spender && e.spender.toLowerCase() === a)
      || (e.to && addressFragmentHit(a, e.to)) || (e.spender && addressFragmentHit(a, e.spender))));
    if (!covered) {
      summary.missing.push(`recipient:${String(c.claim.value).slice(0, 60)}`);
      fields.push(fieldResult('effect:missing-recipient', 'MISMATCH', String(c.claim.value).slice(0, 120), '(no effect pays this party)',
        [...(c.claim.regionIds || [])], 'corroborated requested recipient appears in no reconstructed effect',
        { claimType: 'recipient' }));
    }
  }

  return { fields, summary };
}

module.exports = { compareEffectCoverage, ACTION_VERBS, EFFECT_FAMILY };
