/**
 * Intent-comparison adapter (Phase B).
 *
 * Prepares inputs for the pure `compareIntentToTx` utility from live
 * evaluation evidence and shapes its output for the evidence bundle.
 * Deterministic, narrowly scoped: no network, no model calls, no mutable
 * state. Never throws for malformed evidence — failures become an explicit
 * ERROR record so the evaluation always continues unchanged.
 *
 * Trust boundaries preserved (never weakened):
 * - Grounding records are PROJECTED to {type, value, regionIds,
 *   associationIds, status}. Validator-attached `observed` geometry/text and
 *   every other non-approved field is stripped, because the utility
 *   deliberately rejects model-adjacent evidence keys.
 * - Only genuine region entries are supplied; synthetic fallback OCR never
 *   enters as observed evidence.
 * - Token metadata comes exclusively from the static KNOWN_TOKENS list
 *   (directly for swap legs, via the decoder for the target token). Nothing
 *   from the request, DOM, screenshot, or model is trusted.
 * - The sender is accepted only when validated through the repository's
 *   viem `isAddress` convention; anything else is marked unavailable.
 */

const { isAddress } = require('viem');
const { KNOWN_TOKENS, matchKnownEntry } = require('../utils/abiSignatures');
const { compareIntentToTx } = require('../utils/intentComparison');

const APPROVED_CLAIM_FIELDS = ['type', 'value', 'regionIds', 'associationIds', 'status'];

const COVERAGE_NOTE = 'Per-field deterministic comparison of corroborated UI evidence against decoded '
  + 'transaction facts. MATCH means corroborated equivalence on that field only; MISMATCH means '
  + 'corroborated conflict; INCONCLUSIVE means missing, ambiguous, or undecodable evidence. '
  + 'The overall status is not a security certification and never verifies the entire transaction.';

function projectClaim(raw) {
  const out = {};
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    for (const key of APPROVED_CLAIM_FIELDS) {
      if (raw[key] !== undefined) out[key] = raw[key];
    }
  }
  return out;
}

function resolveStaticTokenMeta(address, chainId) {
  if (typeof address !== 'string') return null;
  // Capability 4 B5: swap-leg metadata is chain-scoped — mainnet
  // token decimals must never calibrate another chain's amounts.
  const entry = matchKnownEntry(KNOWN_TOKENS, address, chainId);
  if (!entry || typeof entry.symbol !== 'string' || !Number.isInteger(entry.decimals)) return null;
  return { symbol: entry.symbol, decimals: entry.decimals };
}

function buildUiFacts({ regionEntries, grounding, associations }) {
  const regions = Array.isArray(regionEntries)
    ? regionEntries.filter((r) => r && typeof r === 'object' && !Array.isArray(r))
    : [];
  const validated = grounding && typeof grounding === 'object' && Array.isArray(grounding.claims)
    ? grounding.claims
    : [];
  const links = associations && typeof associations === 'object' && Array.isArray(associations.links)
    ? associations.links
    : [];
  const ambiguities = associations && typeof associations === 'object' && Array.isArray(associations.ambiguities)
    ? associations.ambiguities
    : [];
  return {
    regions,
    claims: validated.map(projectClaim),
    associations: { links, ambiguities }
  };
}

function buildDecodedFacts({ decodedTx, sender }) {
  const tx = (decodedTx && typeof decodedTx === 'object' && !Array.isArray(decodedTx)) ? decodedTx : {};
  const params = (tx.parameters && typeof tx.parameters === 'object') ? tx.parameters : {};
  const senderValid = typeof sender === 'string' && isAddress(sender);
  const tokenMeta = {};
  if (tx.functionName === 'exactInputSingle') {
    for (const leg of [params.tokenIn, params.tokenOut]) {
      if (typeof leg !== 'string') continue;
      const meta = resolveStaticTokenMeta(leg, tx.chainId);
      if (meta) tokenMeta[leg.toLowerCase()] = meta;
    }
  }
  return {
    facts: {
      contract: tx.contract,
      functionName: tx.functionName,
      standard: tx.standard,
      parameters: params,
      valueWei: tx.valueWei,
      symbol: tx.symbol,
      decimals: tx.decimals,
      ruleFindings: Array.isArray(tx.ruleFindings) ? tx.ruleFindings : [],
      sender: senderValid ? sender : undefined,
      tokenMeta
    },
    senderSource: senderValid ? 'request.from-validated' : 'unavailable',
    targetMetaUsable: typeof tx.symbol === 'string' && tx.symbol.length > 0 && Number.isInteger(tx.decimals),
    swapLegsResolved: Object.keys(tokenMeta).length
  };
}

/**
 * Run the deterministic comparison over live evaluation evidence.
 * @param {{regionEntries: Array, grounding: object, associations: object,
 *   decodedTx: object, sender: string|null}} evidence
 * @returns {object} `visualEvidence.intentComparison` payload. Never throws.
 */
function buildIntentComparison(evidence) {
  const input = (evidence && typeof evidence === 'object') ? evidence : {};
  try {
    const uiFacts = buildUiFacts(input);
    // Capability 3 B5: fully-observed stated intent (agent purpose).
    // Assessed for disclosure, never trusted as fact.
    if (typeof input.statedIntent === 'string' && input.statedIntent.length > 0) {
      uiFacts.statedIntent = input.statedIntent.slice(0, 2000);
    }
    // Capability 3 B6: admitted agent evidence for region-less paths.
    if (Array.isArray(input.agentEvidence)) {
      uiFacts.agentEvidence = input.agentEvidence
        .filter((e) => e && typeof e.evidenceId === 'string' && typeof e.content === 'string')
        .map((e) => ({ id: e.evidenceId, content: e.content.slice(0, 4000) }));
    }
    const decoded = buildDecodedFacts(input);
    const result = compareIntentToTx(uiFacts, decoded.facts);
    // Capability 5 B3: effect-coverage comparison merges into the same
    // field list (effect:* fields). A comparison failure degrades to no
    // B3 fields -- never a partial coverage claim.
    let effectCoverage = { fields: [], summary: { effects: 0, assessable: 0, opaqueSkipped: 0, requestedClaims: 0, unrequested: [], missing: [], inconclusive: [] } };
    try {
      const { compareEffectCoverage } = require('../utils/effectComparison');
      const eff = input.effects && Array.isArray(input.effects.effects) ? input.effects : null;
      if (eff && eff.effects.length > 0) {
        effectCoverage = compareEffectCoverage({ regions: uiFacts.regions, claims: uiFacts.claims, effects: eff });
        result.fields.push(...effectCoverage.fields);
      }
    } catch {
      effectCoverage = { fields: [], summary: { effects: 0, assessable: 0, opaqueSkipped: 0, requestedClaims: 0, unrequested: [], missing: [], inconclusive: [], error: 'effect comparison failed; coverage unassessed' } };
    }
    result.effectCoverage = effectCoverage.summary;
    const comparedFields = result.fields.filter((f) => f.status !== 'INCONCLUSIVE').map((f) => f.field);
    const inconclusiveFields = result.fields.filter((f) => f.status === 'INCONCLUSIVE').map((f) => f.field);

    const limitations = [];
    if (decoded.senderSource === 'unavailable') {
      limitations.push('Transaction sender unavailable or invalid; sender-aware counterparty elimination disabled.');
    }
    if (!decoded.targetMetaUsable
      && ['approve', 'increaseAllowance', 'transfer', 'transferFrom'].includes(decoded.facts.functionName)) {
      limitations.push('Target token identity/decimals unknown; amount and asset comparisons are inconclusive.');
    }
    if (decoded.facts.functionName === 'exactInputSingle') {
      const tokenIn = decoded.facts.parameters && decoded.facts.parameters.tokenIn;
      const inResolved = typeof tokenIn === 'string' && Boolean(decoded.facts.tokenMeta[tokenIn.toLowerCase()]);
      if (!inResolved) {
        limitations.push('Swap input-leg token metadata unavailable from the static list; input comparison is inconclusive.');
      }
    }
    if (uiFacts.claims.length === 0) {
      limitations.push('No structured visual claims to corroborate; UI-side comparisons are inconclusive.');
    }
    return {
      status: result.overall,
      fields: result.fields,
      summary: result.summary,
      overall: result.overall,
      coverage: {
        comparedFields,
        inconclusiveFields,
        note: COVERAGE_NOTE
      },
      provenance: {
        tokenMetaSource: (decoded.targetMetaUsable || decoded.swapLegsResolved > 0)
          ? 'static-known-tokens'
          : 'unavailable',
        senderSource: decoded.senderSource
      },
      effectCoverage: result.effectCoverage || null,
      limitations
    };
  } catch (err) {
    return {
      status: 'ERROR',
      error: {
        code: 'COMPARISON_FAILED',
        message: String((err && err.message) || err).slice(0, 300)
      },
      fields: [],
      summary: { match: 0, mismatch: 0, inconclusive: 0 },
      overall: 'INCONCLUSIVE',
      coverage: {
        comparedFields: [],
        inconclusiveFields: [],
        note: COVERAGE_NOTE
      },
      provenance: { tokenMetaSource: 'unavailable', senderSource: 'unavailable' },
      limitations: ['Comparison could not run; no field was compared.']
    };
  }
}

module.exports = { buildIntentComparison, projectClaim, resolveStaticTokenMeta };
