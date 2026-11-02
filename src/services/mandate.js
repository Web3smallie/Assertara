/**
 * Mandate engine (agent execution system).
 *
 * Evaluates a proposed transaction against an independently authorised
 * mandate. The mandate is OPERATOR configuration (file path from
 * MANDATE_FILE), never agent input: anything the agent supplies about
 * its own authority is ignored. Missing mandate keys default to the
 * most restrictive setting; an absent or invalid mandate fails closed
 * (every proposal becomes UNCERTAIN, never ALLOW).
 *
 * All quantity comparisons use BigInt over decimal wei strings. No
 * price conversion exists anywhere in this module.
 */

const fs = require('fs');
const { buildSubcallTree } = require('./nestedCalls');
const { INFINITE_THRESHOLD } = require('../utils/abiSignatures');

const POLICY_ID = 'assertara-agent-mvp-1';

// Capability 5 B1: bound on nested operations evaluated per proposal.
// The decoder caps depth (5) but not breadth; beyond this count the
// mandate cannot verify every operation, so evaluation fails closed
// (UNCERTAIN) instead of sampling a subset.
const MAX_MANDATE_SUBCALLS = 500;

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const SELECTOR_RE = /^0x[0-9a-fA-F]{8}$/;
const WEI_RE = /^[0-9]+$/;

function isValidAddress(v) {
  return typeof v === 'string' && ADDRESS_RE.test(v);
}

function toWeiBigInt(v) {
  if (typeof v === 'bigint') return v >= 0n ? v : null;
  if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v === 'string') {
    const s = v.trim();
    if (WEI_RE.test(s)) return BigInt(s);
    if (/^0[xX][0-9a-fA-F]+$/.test(s)) return BigInt(s);
  }
  return null;
}

function lowerAddresses(list) {
  if (!Array.isArray(list)) return null;
  const out = [];
  for (const v of list) {
    if (!isValidAddress(v)) return null;
    out.push(v.toLowerCase());
  }
  return out;
}

/**
 * Load + validate + normalize a mandate file. Returns
 * { ok:true, mandate } or { ok:false, error }. Never throws.
 */
function loadMandate(filePath) {
  try {
    if (!filePath || typeof filePath !== 'string') return { ok: false, error: 'MANDATE_FILE is not configured' };
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, error: 'mandate file is not an object' };

    const errors = [];
    const need = (cond, msg) => { if (!cond) errors.push(msg); };

    need(typeof raw.id === 'string' && raw.id.length > 0 && raw.id.length <= 128, 'mandate.id must be a non-empty string');
    need(Number.isSafeInteger(raw.version) && raw.version > 0, 'mandate.version must be a positive integer');
    need(typeof raw.issuer === 'string' && raw.issuer.length > 0, 'mandate.issuer must be a non-empty string');

    const notBefore = Date.parse(raw.notBefore);
    const expiresAt = Date.parse(raw.expiresAt);
    need(Number.isFinite(notBefore), 'mandate.notBefore must be a valid timestamp');
    need(Number.isFinite(expiresAt), 'mandate.expiresAt must be a valid timestamp');
    if (Number.isFinite(notBefore) && Number.isFinite(expiresAt)) {
      need(expiresAt > notBefore, 'mandate.expiresAt must be after notBefore');
    }
    const revokedVersions = Array.isArray(raw.revokedVersions) ? raw.revokedVersions : null;
    need(revokedVersions !== null && revokedVersions.every((v) => Number.isSafeInteger(v) && v > 0), 'mandate.revokedVersions must be an integer array');

    need(isValidAddress(raw.signerAddress), 'mandate.signerAddress must be a valid address');
    const senders = lowerAddresses(raw.senders);
    need(senders !== null && senders.length > 0, 'mandate.senders must be a non-empty address array');

    const chains = Array.isArray(raw.chains) ? raw.chains : null;
    need(chains !== null, 'mandate.chains must be an array');
    const normChains = [];
    if (chains) {
      for (const c of chains) {
        const idOk = c && (typeof c.id === 'string' || typeof c.id === 'number') && toWeiBigInt(c.id) !== null;
        const rpcOk = c && typeof c.rpcUrl === 'string' && /^https?:\/\/.+/.test(c.rpcUrl);
        need(idOk && rpcOk, 'each mandate chain needs a numeric id and http(s) rpcUrl');
        if (idOk && rpcOk) normChains.push({ id: `0x${toWeiBigInt(c.id).toString(16)}`, rpcUrl: c.rpcUrl, name: typeof c.name === 'string' ? c.name : '' });
      }
    }

    const recipientsAllow = lowerAddresses(raw.recipients && raw.recipients.allow);
    const recipientsDeny = lowerAddresses(raw.recipients && raw.recipients.deny);
    need(recipientsAllow !== null, 'mandate.recipients.allow must be an address array (empty denies all)');
    need(recipientsDeny !== null, 'mandate.recipients.deny must be an address array');
    const contractsAllow = lowerAddresses(raw.contracts && raw.contracts.allow);
    need(contractsAllow !== null, 'mandate.contracts.allow must be an address array (empty denies all calls)');
    const selectorsAllow = Array.isArray(raw.selectors && raw.selectors.allow) ? raw.selectors.allow : null;
    need(selectorsAllow !== null && selectorsAllow.every((s) => typeof s === 'string' && SELECTOR_RE.test(s)),
      'mandate.selectors.allow must be a selector array (empty denies all calls)');
    need(typeof raw.allowNativeTransfer === 'boolean', 'mandate.allowNativeTransfer must be boolean');

    const maxNativePerTxWei = toWeiBigInt(raw.maxNativePerTxWei);
    need(maxNativePerTxWei !== null, 'mandate.maxNativePerTxWei must be a non-negative wei quantity');

    const approvals = raw.approvals && typeof raw.approvals === 'object' ? raw.approvals : null;
    need(approvals !== null, 'mandate.approvals must be an object');
    need(approvals && typeof approvals.allowUnlimited === 'boolean', 'mandate.approvals.allowUnlimited must be boolean');
    need(approvals && typeof approvals.allowOperatorAll === 'boolean', 'mandate.approvals.allowOperatorAll must be boolean');
    const spenderAllowlist = approvals ? lowerAddresses(approvals.spenderAllowlist) : null;
    need(spenderAllowlist !== null, 'mandate.approvals.spenderAllowlist must be an address array (empty denies all)');

    const spendingLimits = Array.isArray(raw.spendingLimits) ? raw.spendingLimits : null;
    need(spendingLimits !== null, 'mandate.spendingLimits must be an array');
    const normLimits = [];
    if (spendingLimits) {
      for (const l of spendingLimits) {
        const windowOk = l && Number.isSafeInteger(l.windowMs) && l.windowMs > 0;
        const maxOk = l && toWeiBigInt(l.maxNativeWei) !== null;
        need(windowOk && maxOk, 'each spending limit needs positive windowMs and maxNativeWei');
        if (windowOk && maxOk) normLimits.push({ windowMs: l.windowMs, maxNativeWei: toWeiBigInt(l.maxNativeWei).toString() });
      }
    }

    const reviewRules = Array.isArray(raw.reviewRules) ? raw.reviewRules : null;
    need(reviewRules !== null, 'mandate.reviewRules must be an array');
    const normReview = [];
    if (reviewRules) {
      for (const r of reviewRules) {
        if (!r || typeof r !== 'object') { need(false, 'review rule must be an object'); continue; }
        if (r.when === 'nativeValueAboveWei') {
          const v = toWeiBigInt(r.value);
          need(v !== null, 'nativeValueAboveWei rule needs a wei value');
          if (v !== null) normReview.push({ when: r.when, value: v.toString() });
        } else if (r.when === 'selector') {
          need(typeof r.selector === 'string' && SELECTOR_RE.test(r.selector), 'selector rule needs a selector');
          if (typeof r.selector === 'string' && SELECTOR_RE.test(r.selector)) normReview.push({ when: 'selector', selector: r.selector.toLowerCase() });
        } else {
          need(false, `unknown review rule: ${r.when}`);
        }
      }
    }

    if (errors.length > 0) return { ok: false, error: `invalid mandate: ${errors.join('; ')}` };
    const seal = raw.seal && typeof raw.seal === 'object' && !Array.isArray(raw.seal)
      ? {
        format: typeof raw.seal.format === 'string' ? raw.seal.format : null,
        authority: typeof raw.seal.authority === 'string' ? raw.seal.authority : null,
        algorithm: typeof raw.seal.algorithm === 'string' ? raw.seal.algorithm : null,
        signature: typeof raw.seal.signature === 'string' ? raw.seal.signature : null
      }
      : null;
    return {
      ok: true,
      mandate: {
        id: raw.id,
        version: raw.version,
        issuer: raw.issuer,
        notBefore: new Date(notBefore).toISOString(),
        expiresAt: new Date(expiresAt).toISOString(),
        notBeforeMs: notBefore,
        expiresAtMs: expiresAt,
        revokedVersions,
        signerAddress: raw.signerAddress.toLowerCase(),
        senders,
        chains: normChains,
        recipientsAllow,
        recipientsDeny,
        contractsAllow,
        selectorsAllow: selectorsAllow.map((s) => s.toLowerCase()),
        allowNativeTransfer: raw.allowNativeTransfer,
        maxNativePerTxWei: maxNativePerTxWei.toString(),
        approvals: { allowUnlimited: approvals.allowUnlimited, allowOperatorAll: approvals.allowOperatorAll, spenderAllowlist },
        spendingLimits: normLimits,
        reviewRules: normReview,
        policyId: POLICY_ID,
        seal
      }
    };
  } catch (err) {
    return { ok: false, error: `mandate load failed: ${err && err.message ? err.message : String(err)}` };
  }
}

function chainKey(chainId) {
  const v = toWeiBigInt(chainId);
  return v === null ? null : `0x${v.toString(16)}`;
}

/**
 * Evaluate a decoded transaction against the mandate. Pure except for
 * the injected spending ledger reads and clock.
 *
 * @param {object} args
 * @param {object|null} args.mandate Normalized mandate (or null).
 * @param {string|null} args.mandateError Why no mandate is active.
 * @param {object} args.tx Normalized proposal tx {from,to,data,value,chainId,...}.
 * @param {object} args.decodedTx Decoder output (may be unknownFunction).
 * @param {number} args.nowMs Clock.
 * @param {object|null} args.ledger Spending ledger {spentWithin} or null.
 * @returns {{decision, reasons, checks}} decision ∈ ALLOW|BLOCK|REVIEW|UNCERTAIN.
 */
function evaluateMandate({ mandate, mandateError, tx, decodedTx, nowMs, ledger }) {
  const reasons = [];
  const checks = [];
  const check = (id, pass, detail) => { checks.push({ id, pass: Boolean(pass), detail: detail || '' }); };

  if (!mandate) {
    check('mandate-active', false, mandateError || 'no active mandate');
    return { decision: 'UNCERTAIN', reasons: [`No active mandate: ${mandateError || 'none configured'}. Cannot authorize.`], checks };
  }

  // Liveness: expiry and revocation are mandatory prohibitions.
  if (!(nowMs >= mandate.notBeforeMs && nowMs < mandate.expiresAtMs)) {
    check('mandate-active', false, 'mandate outside validity window');
    return { decision: 'BLOCK', reasons: ['Mandate is expired or not yet effective.'], checks };
  }
  check('mandate-active', true, `mandate ${mandate.id} v${mandate.version}`);
  if (mandate.revokedVersions.indexOf(mandate.version) !== -1) {
    check('mandate-revoked', false, 'version revoked');
    return { decision: 'BLOCK', reasons: ['Mandate version is revoked.'], checks };
  }
  check('mandate-revoked', true, 'version not revoked');

  // Chain and sender.
  const chain = chainKey(tx.chainId);
  const chainEntry = chain === null ? null : mandate.chains.find((c) => c.id === chain);
  if (!chainEntry) {
    check('chain-allowed', false, `chain ${String(tx.chainId)} not permitted`);
    return { decision: 'BLOCK', reasons: [`Chain ${String(tx.chainId)} is not permitted by the mandate.`], checks };
  }
  check('chain-allowed', true, chainEntry.name || chain);
  const sender = typeof tx.from === 'string' ? tx.from.toLowerCase() : '';
  if (mandate.senders.indexOf(sender) === -1 || sender !== mandate.signerAddress) {
    check('sender-authorized', false, `sender ${sender || '(missing)'} not authorized`);
    return { decision: 'BLOCK', reasons: ['Sender is not the mandate-authorized signer address.'], checks };
  }
  check('sender-authorized', true, sender);

  // Recipient.
  const to = typeof tx.to === 'string' ? tx.to.toLowerCase() : '';
  if (mandate.recipientsDeny.indexOf(to) !== -1) {
    check('recipient-allowed', false, 'recipient explicitly denied');
    return { decision: 'BLOCK', reasons: ['Recipient is explicitly denied by the mandate.'], checks };
  }
  if (mandate.recipientsAllow.indexOf(to) === -1) {
    check('recipient-allowed', false, 'recipient not allowlisted');
    return { decision: 'BLOCK', reasons: ['Recipient is not on the mandate allowlist.'], checks };
  }
  check('recipient-allowed', true, to);

  const data = typeof tx.data === 'string' ? tx.data : '0x';
  const isNative = data === '0x' || data === '';
  const valueWei = toWeiBigInt(tx.value === undefined || tx.value === null || tx.value === '' ? '0x0' : tx.value);
  if (valueWei === null) {
    check('value-parseable', false, 'value not a valid quantity');
    return { decision: 'BLOCK', reasons: ['Transaction value is not a valid quantity.'], checks };
  }
  check('value-parseable', true, `${valueWei.toString()} wei`);

  const reviewHits = [];

  if (isNative) {
    if (!mandate.allowNativeTransfer) {
      check('native-transfer-allowed', false, 'native transfers disabled');
      return { decision: 'BLOCK', reasons: ['Native transfers are disabled by the mandate.'], checks };
    }
    check('native-transfer-allowed', true, 'native transfers permitted');
    if (valueWei > BigInt(mandate.maxNativePerTxWei)) {
      check('native-per-tx-limit', false, 'value exceeds per-transaction maximum');
      return { decision: 'BLOCK', reasons: ['Value exceeds the mandate per-transaction maximum.'], checks };
    }
    check('native-per-tx-limit', true, 'within per-transaction maximum');
    // Spending windows (native only; ERC-20 amounts need token metadata
    // we do not have, so they are structurally restricted instead).
    if (mandate.spendingLimits.length > 0) {
      if (!ledger || typeof ledger.spentWithin !== 'function') {
        check('spending-window', false, 'ledger unavailable');
        return { decision: 'UNCERTAIN', reasons: ['Spending ledger unavailable; cannot verify limits.'], checks };
      }
      for (const lim of mandate.spendingLimits) {
        let spent;
        try {
          spent = BigInt(ledger.spentWithin({ chainId: chain, windowMs: lim.windowMs, nowMs }));
        } catch {
          check('spending-window', false, 'ledger read failed');
          return { decision: 'UNCERTAIN', reasons: ['Spending ledger read failed; cannot verify limits.'], checks };
        }
        if (spent + valueWei > BigInt(lim.maxNativeWei)) {
          check('spending-window', false, `window ${lim.windowMs}ms would exceed maximum`);
          return { decision: 'BLOCK', reasons: ['Spending window limit would be exceeded.'], checks };
        }
      }
      check('spending-window', true, 'within all spending windows');
    } else {
      check('spending-window', true, 'no spending windows configured');
    }
    for (const rule of mandate.reviewRules) {
      if (rule.when === 'nativeValueAboveWei' && valueWei > BigInt(rule.value)) {
        reviewHits.push(`Value above operator-review threshold (${rule.value} wei).`);
      }
      if (rule.when === 'selector' && rule.selector === '0x00000000') {
        reviewHits.push('Native transfer matches a review selector rule.');
      }
    }
  } else {
    // Contract call branch.
    if (mandate.contractsAllow.indexOf(to) === -1) {
      check('contract-allowed', false, 'contract not allowlisted');
      return { decision: 'BLOCK', reasons: ['Target contract is not on the mandate allowlist.'], checks };
    }
    check('contract-allowed', true, to);
    const selector = data.slice(0, 10).toLowerCase();
    if (mandate.selectorsAllow.indexOf(selector) === -1) {
      check('selector-allowed', false, `selector ${selector} not allowlisted`);
      return { decision: 'BLOCK', reasons: ['Function selector is not permitted by the mandate.'], checks };
    }
    check('selector-allowed', true, selector);
    const fn = decodedTx && typeof decodedTx.functionName === 'string' ? decodedTx.functionName : 'unknownFunction';
    if (fn === 'unknownFunction') {
      check('calldata-decodable', false, 'calldata not decodable');
      return { decision: 'UNCERTAIN', reasons: ['Calldata allows the selector but does not decode; cannot verify arguments.'], checks };
    }
    check('calldata-decodable', true, fn);
    // Approval structure rules (no value accounting without token metadata).
    const params = (decodedTx && decodedTx.parameters) || {};
    const spender = typeof params.spender === 'string' ? params.spender.toLowerCase()
      : typeof params.operator === 'string' ? params.operator.toLowerCase() : null;
    const isApprovalLike = fn === 'approve' || fn === 'setApprovalForAll' || fn === 'permit' || fn === 'permitTransferFrom';
    if (isApprovalLike) {
      if (decodedTx.isUnlimitedApproval && !mandate.approvals.allowUnlimited) {
        check('approval-unlimited', false, 'unlimited allowance prohibited');
        return { decision: 'BLOCK', reasons: ['Unlimited approvals are prohibited by the mandate.'], checks };
      }
      check('approval-unlimited', true, 'no prohibited unlimited allowance');
      const operatorAll = fn === 'setApprovalForAll' && params.approved === true;
      if (operatorAll && !mandate.approvals.allowOperatorAll) {
        check('approval-operator', false, 'operator-wide approval prohibited');
        return { decision: 'BLOCK', reasons: ['Broad operator approvals are prohibited by the mandate.'], checks };
      }
      check('approval-operator', true, 'no prohibited operator approval');
      if (!spender || mandate.approvals.spenderAllowlist.indexOf(spender) === -1) {
        check('approval-spender', false, 'spender not allowlisted');
        return { decision: 'BLOCK', reasons: ['Approval spender is not allowlisted.'], checks };
      }
      check('approval-spender', true, spender);
    } else {
      check('approval-unlimited', true, 'not an approval call');
      check('approval-operator', true, 'not an approval call');
      check('approval-spender', true, 'not an approval call');
    }
    for (const rule of mandate.reviewRules) {
      if (rule.when === 'selector' && rule.selector === selector) {
        reviewHits.push(`Selector ${selector} requires operator review.`);
      }
      if (rule.when === 'nativeValueAboveWei' && valueWei > BigInt(rule.value)) {
        reviewHits.push(`Value above operator-review threshold (${rule.value} wei).`);
      }
    }
  }

  // Capability 5 B1: recursive inner-operation authorization. The
  // top-level checks above see only the batch envelope; every decoded
  // subcall must independently satisfy the mandate's recipient,
  // selector, and approval constraints. Unknown or uninterpretable
  // inners BLOCK agent execution (browser investigations hold REVIEW
  // via the UNKNOWN_INNER_CALL policy rule instead).
  const inner = evaluateInnerOperations({ mandate, to, decodedTx, check });
  if (inner.decision !== 'ALLOW') {
    return { decision: inner.decision, reasons: inner.reasons, checks };
  }

  if (reviewHits.length > 0) {
    check('operator-review', false, reviewHits.join(' '));
    return { decision: 'REVIEW', reasons: reviewHits, checks };
  }
  check('operator-review', true, 'no review rule triggered');
  return { decision: 'ALLOW', reasons: ['Transaction satisfies all mandate constraints.'], checks };
}

/**
 * Authorize every nested operation in the decoded batch. Pure over
 * (mandate, to, decodedTx); appends per-subcall check records.
 * Returns { decision: ALLOW|BLOCK|UNCERTAIN, reasons }.
 */
function evaluateInnerOperations({ mandate, to, decodedTx, check }) {
  const pass = (id, detail) => check(id, true, detail);
  const fail = (id, detail) => check(id, false, detail);
  let tree;
  try {
    tree = buildSubcallTree(decodedTx);
  } catch (err) {
    fail('inner-tree', `subcall tree build failed: ${String((err && err.message) || err).slice(0, 120)}`);
    return { decision: 'UNCERTAIN', reasons: ['Nested structure cannot be rebuilt; mandate cannot verify inner operations.'] };
  }
  const subs = (tree && Array.isArray(tree.subcalls)) ? tree.subcalls : [];
  if (subs.length === 0) {
    pass('inner-operations', 'no nested operations');
    return { decision: 'ALLOW', reasons: [] };
  }
  if (subs.length > MAX_MANDATE_SUBCALLS) {
    fail('inner-operations', `subcall count ${subs.length} exceeds evaluation bound ${MAX_MANDATE_SUBCALLS}`);
    return { decision: 'UNCERTAIN', reasons: [`Batch contains ${subs.length} nested operations, exceeding the mandate evaluation bound (${MAX_MANDATE_SUBCALLS}); cannot verify all operations.`] };
  }
  const allow = new Set(mandate.selectorsAllow || []);
  for (const s of subs) {
    const tag = `inner-${s.subcallId || 'unknown'}`;
    const label = `${s.subcallId || '?'} (${s.functionName || 'unknownFunction'})`;
    if (s.unknown === true || s.depthLimited === true) {
      fail(`${tag}-interpretable`, `nested operation ${label} is uninterpretable`);
      return { decision: 'BLOCK', reasons: [`Nested operation ${label} cannot be interpreted; agent execution refused.`] };
    }
    pass(`${tag}-interpretable`, `${s.functionName} (${s.standard})`);
    // Inners execute in the batch target's context; a node naming any
    // other target escapes the authorized call frame.
    if (typeof s.target === 'string' && s.target.toLowerCase() !== to) {
      fail(`${tag}-target`, `nested target ${s.target} escapes batch context ${to}`);
      return { decision: 'BLOCK', reasons: [`Nested operation ${label} targets ${s.target}, outside the authorized batch target.`] };
    }
    pass(`${tag}-target`, 'executes in batch-target context');
    const sel = typeof s.selector === 'string' ? s.selector.toLowerCase() : '';
    if (!SELECTOR_RE.test(sel) || !allow.has(sel)) {
      fail(`${tag}-selector`, `selector ${sel || '(missing)'} not allowlisted`);
      return { decision: 'BLOCK', reasons: [`Nested operation ${label} uses selector ${sel || '(missing)'}, which is not permitted by the mandate.`] };
    }
    pass(`${tag}-selector`, sel);
    const params = (s.parameters && typeof s.parameters === 'object') ? s.parameters : {};
    // Fund recipients of inner operations obey the same allow/deny
    // lists as top-level recipients.
    for (const key of ['recipient', 'to']) {
      const r = params[key];
      if (r === undefined || r === null) continue;
      const rl = typeof r === 'string' ? r.toLowerCase() : '';
      if (!isValidAddress(rl)) {
        fail(`${tag}-recipient`, `nested ${key} is not a verifiable address`);
        return { decision: 'BLOCK', reasons: [`Nested operation ${label} names an unverifiable ${key}; agent execution refused.`] };
      }
      if (mandate.recipientsDeny.indexOf(rl) !== -1) {
        fail(`${tag}-recipient`, 'nested recipient explicitly denied');
        return { decision: 'BLOCK', reasons: [`Nested operation ${label} pays denied recipient ${rl}.`] };
      }
      if (mandate.recipientsAllow.indexOf(rl) === -1) {
        fail(`${tag}-recipient`, 'nested recipient not allowlisted');
        return { decision: 'BLOCK', reasons: [`Nested operation ${label} pays recipient ${rl}, which is not allowlisted.`] };
      }
      pass(`${tag}-recipient`, `${key} ${rl}`);
    }
    // Inner approval-likes obey the same structural rules as
    // top-level approvals. increaseAllowance is included here even
    // though the legacy top-level list omits it: an inner allowance
    // grant to a non-allowlisted spender must never pass silently.
    const fn = s.functionName;
    const innerApprovalLike = fn === 'approve' || fn === 'setApprovalForAll' || fn === 'permit'
      || fn === 'permitTransferFrom' || fn === 'increaseAllowance';
    if (!innerApprovalLike) continue;
    // Permit2 approve decodes positionally ([token, spender, amount,
    // expiration]); read the ABI-fixed positions as fallback.
    const iargs = Array.isArray(params.args) ? params.args : [];
    const spenderRaw = typeof params.spender === 'string' ? params.spender
      : typeof params.operator === 'string' ? params.operator
      : (fn === 'approve' && s.standard === 'Permit2' && typeof iargs[1] === 'string' ? iargs[1] : null);
    const spender = typeof spenderRaw === 'string' ? spenderRaw.toLowerCase() : null;
    const amtRaw = params.amount !== undefined ? params.amount : params.value !== undefined ? params.value
      : (fn === 'approve' && s.standard === 'Permit2' ? iargs[2] : undefined);
    const amt = (typeof amtRaw === 'bigint' || typeof amtRaw === 'number' || typeof amtRaw === 'string')
      ? toWeiBigInt(amtRaw) : null;
    if (amt !== null && amt >= INFINITE_THRESHOLD && !mandate.approvals.allowUnlimited) {
      fail(`${tag}-approval-unlimited`, 'nested unlimited allowance prohibited');
      return { decision: 'BLOCK', reasons: [`Nested operation ${label} grants an unlimited allowance, prohibited by the mandate.`] };
    }
    pass(`${tag}-approval-unlimited`, 'no prohibited nested unlimited allowance');
    if (fn === 'setApprovalForAll' && params.approved === true && !mandate.approvals.allowOperatorAll) {
      fail(`${tag}-approval-operator`, 'nested operator-wide approval prohibited');
      return { decision: 'BLOCK', reasons: [`Nested operation ${label} grants a broad operator approval, prohibited by the mandate.`] };
    }
    pass(`${tag}-approval-operator`, 'no prohibited nested operator approval');
    if (!spender || !isValidAddress(spender) || mandate.approvals.spenderAllowlist.indexOf(spender) === -1) {
      fail(`${tag}-approval-spender`, 'nested spender not allowlisted');
      return { decision: 'BLOCK', reasons: [`Nested operation ${label} grants authority to non-allowlisted spender ${spender || '(missing)'}.`] };
    }
    pass(`${tag}-approval-spender`, spender);
  }
  pass('inner-operations', `${subs.length} nested operation(s) authorized`);
  return { decision: 'ALLOW', reasons: [] };
}

/**
 * Mandate continuity across restarts. The last-seen {id, version} is
 * recorded in durable store state; a restart that loads the SAME mandate
 * id at a LOWER version is a rollback (operator error or tamper) and must
 * fail closed rather than silently re-arm older, possibly looser rules.
 * A new mandate id is an explicit rotation and is allowed.
 *
 * @param {{id:string,version:number}|null} last Last-seen mandate (or null on first boot).
 * @param {object} current Freshly loaded mandate.
 * @returns {{ok:true}|{ok:false,error:string}}
 */
function checkMandateContinuity({ last, current }) {
  if (!last) return { ok: true };
  if (!current || typeof current.id !== 'string') return { ok: false, error: 'no active mandate to compare' };
  if (last.id !== current.id) return { ok: true };
  if (!Number.isSafeInteger(last.version)) return { ok: false, error: 'stored mandate version is unreadable' };
  if (current.version < last.version) {
    return { ok: false, error: `mandate ${current.id} v${current.version} is older than last-seen v${last.version}; refusing rollback` };
  }
  return { ok: true };
}

const SEAL_FORMAT = 'assertara-mandate-seal-1';
const SEAL_BODY_FORMAT = 'assertara-mandate-body-1';
const SEAL_ALGORITHM = 'eip191-secp256k1';

/**
 * Deterministic signing representation of a NORMALIZED mandate: explicit
 * field order, normalized values (lowercased addresses, hex chain ids,
 * decimal wei strings) — exactly what enforcement consumes, so the seal
 * cannot be interpreted differently by different components. Array order
 * is significant: reordering requires a re-seal.
 */
function canonicalMandateBody(m) {
  return JSON.stringify({
    format: SEAL_BODY_FORMAT,
    id: m.id,
    version: m.version,
    issuer: m.issuer,
    notBefore: m.notBefore,
    expiresAt: m.expiresAt,
    revokedVersions: [...(m.revokedVersions || [])],
    signerAddress: m.signerAddress,
    senders: [...(m.senders || [])],
    chains: (m.chains || []).map((c) => ({ id: c.id, rpcUrl: c.rpcUrl, name: c.name || '' })),
    recipientsAllow: [...(m.recipientsAllow || [])],
    recipientsDeny: [...(m.recipientsDeny || [])],
    contractsAllow: [...(m.contractsAllow || [])],
    selectorsAllow: [...(m.selectorsAllow || [])],
    allowNativeTransfer: m.allowNativeTransfer,
    maxNativePerTxWei: m.maxNativePerTxWei,
    approvals: {
      allowUnlimited: Boolean(m.approvals && m.approvals.allowUnlimited),
      allowOperatorAll: Boolean(m.approvals && m.approvals.allowOperatorAll),
      spenderAllowlist: [...((m.approvals && m.approvals.spenderAllowlist) || [])]
    },
    spendingLimits: (m.spendingLimits || []).map((l) => ({ windowMs: l.windowMs, maxNativeWei: l.maxNativeWei })),
    reviewRules: (m.reviewRules || []).map((r) => (
      r.when === 'selector' ? { when: 'selector', selector: r.selector } : { when: r.when, value: r.value }
    )),
    policyId: m.policyId || POLICY_ID
  });
}

/**
 * Seal a normalized mandate with the operator signing key (EIP-191
 * personal-sign over the canonical body via viem). Returns the seal
 * block to embed as top-level `seal` in the mandate file. Operator
 * ceremony only — never called by the agent path or the signer.
 */
async function sealMandateObject(mandate, operatorPrivateKey) {
  if (!mandate || typeof mandate !== 'object') throw new Error('seal requires a normalized mandate');
  if (!operatorPrivateKey || typeof operatorPrivateKey !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(operatorPrivateKey)) {
    throw new Error('seal requires OPERATOR_SIGNING_KEY as a 0x 32-byte hex key');
  }
  const { privateKeyToAccount } = require('viem/accounts');
  const account = privateKeyToAccount(operatorPrivateKey);
  const signature = await account.signMessage({ message: canonicalMandateBody(mandate) });
  return { format: SEAL_FORMAT, authority: account.address.toLowerCase(), algorithm: SEAL_ALGORITHM, signature };
}

/**
 * Verify a mandate seal against trusted authorities. Checks format,
 * algorithm, authority membership, and the cryptographic signature over
 * the canonical body. Expiry/revocation stay enforced by the existing
 * liveness checks over the same sealed bytes. Never throws on hostile
 * input — returns {ok:false, error}.
 */
async function verifyMandateSeal({ mandate, authorities }) {
  try {
    const list = Array.isArray(authorities) ? authorities.filter((a) => typeof a === 'string' && isValidAddress(a)).map((a) => a.toLowerCase()) : [];
    if (list.length === 0) return { ok: false, error: 'mandate signing authority is not configured' };
    if (!mandate || typeof mandate !== 'object') return { ok: false, error: 'no mandate to verify' };
    const seal = mandate.seal;
    if (!seal || typeof seal !== 'object') return { ok: false, error: 'mandate is not sealed; refusing unverified mandate' };
    if (seal.format !== SEAL_FORMAT) return { ok: false, error: `unsupported mandate seal format: ${String(seal.format)}` };
    if (seal.algorithm !== SEAL_ALGORITHM) return { ok: false, error: `unsupported mandate seal algorithm: ${String(seal.algorithm)}` };
    if (typeof seal.authority !== 'string' || !isValidAddress(seal.authority)) {
      return { ok: false, error: 'mandate seal authority is malformed' };
    }
    if (typeof seal.signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(seal.signature)) {
      return { ok: false, error: 'mandate seal signature is malformed' };
    }
    if (list.indexOf(seal.authority.toLowerCase()) === -1) {
      return { ok: false, error: `mandate seal authority ${seal.authority} is not trusted` };
    }
    const { recoverMessageAddress } = require('viem');
    const recovered = await recoverMessageAddress({ message: canonicalMandateBody(mandate), signature: seal.signature });
    if (String(recovered).toLowerCase() !== seal.authority.toLowerCase()) {
      return { ok: false, error: 'mandate signature invalid: mandate bytes do not match the seal' };
    }
    return { ok: true, authority: seal.authority.toLowerCase() };
  } catch (err) {
    return { ok: false, error: `mandate seal verification failed: ${err && err.message ? err.message : String(err)}` };
  }
}

module.exports = {
  POLICY_ID, SEAL_FORMAT, SEAL_ALGORITHM,
  loadMandate, evaluateMandate, checkMandateContinuity,
  canonicalMandateBody, sealMandateObject, verifyMandateSeal,
  toWeiBigInt, isValidAddress
};
