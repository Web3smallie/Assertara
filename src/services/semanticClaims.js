/**
 * Deterministic semantic-claim verification (Capability 4, B7).
 *
 * Reference validation proves a citation EXISTS; this module checks
 * whether checkable semantic claims are TRUE. It extracts narrow,
 * falsifiable claims from the model's conclusions and discrepancies —
 * named recipients, amounts, unlimited assertions, minimums, function
 * names, identity assertions, deadlines, implementation addresses —
 * and compares each against the verified structured record (decoded
 * transaction, identity ladder, proxy resolution, deadline analysis).
 *
 * Outcomes per claim: VERIFIED / CONTRADICTED / INCONCLUSIVE /
 * NOT_APPLICABLE. Parsing is deliberately strict: a claim that cannot
 * be framed unambiguously is INCONCLUSIVE, never guessed at, and a
 * claim about a concept the transaction lacks is NOT_APPLICABLE,
 * never punished. CONTRADICTED claims downgrade MATCH verdicts and
 * hold review — a verdict resting on falsehoods is unreliable.
 *
 * This is not natural-language understanding: eight fixed claim
 * shapes with anchored patterns and exact comparisons. Anything
 * outside those shapes stays unverified and is reported as such.
 */

const { KNOWN_TOKENS, matchKnownEntry } = require('../utils/abiSignatures');
const { classifyApprovalAmount } = require('../utils/valueProtection');
const { DEADLINE_FIELDS } = require('./deadlineAnalysis');

const MAX_CLAIMS = 24;
const FULL_ADDRESS_RE = /0x[0-9a-fA-F]{40}/;
const SELECTOR_RE = /0x[0-9a-fA-F]{8}\b/;

// Role word → decoded parameter keys holding that party.
const ROLE_PARAMS = {
  recipient: ['recipient', 'to'],
  receiver: ['recipient', 'to'],
  beneficiary: ['recipient', 'to'],
  to: ['recipient', 'to'],
  spender: ['spender'],
  operator: ['operator'],
  owner: ['newOwner'],
  sender: ['sender'],
  from: ['sender'],
  implementation: ['newImplementation']
};

function parseUint(v) {
  try {
    if (typeof v === 'bigint') return v < 0n ? null : v;
    if (typeof v === 'string' && /^\d+$/.test(v.trim())) return BigInt(v.trim());
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
    return null;
  } catch {
    return null;
  }
}

function parseDisplayAmount(numStr) {
  const clean = String(numStr).replace(/,/g, '');
  if (!/^\d+(\.\d+)?$/.test(clean)) return null;
  const [whole, frac = ''] = clean.split('.');
  return { whole, frac };
}

function displayToBase(numStr, decimals) {
  const parsed = parseDisplayAmount(numStr);
  if (!parsed || !Number.isInteger(decimals) || decimals < 0 || decimals > 77) return null;
  const fracPadded = (parsed.frac + '0'.repeat(decimals)).slice(0, decimals);
  try {
    return BigInt(parsed.whole + fracPadded);
  } catch {
    return null;
  }
}

function tokenDecimals(symbol, decodedTx, chainId) {
  const sym = String(symbol).toUpperCase();
  if (sym === 'ETH' || sym === 'WETH') {
    if (decodedTx && Number.isInteger(decodedTx.decimals)) return decodedTx.decimals;
    return 18;
  }
  // Scoped static metadata for known symbols only; anything else is
  // honestly unknown (no invented decimals).
  for (const addr of Object.keys(KNOWN_TOKENS)) {
    const entry = matchKnownEntry(KNOWN_TOKENS, addr, chainId);
    if (entry && entry.symbol.toUpperCase() === sym && Number.isInteger(entry.decimals)) return entry.decimals;
  }
  return null;
}

function decodedParties(decodedTx) {
  const p = (decodedTx && decodedTx.parameters) || {};
  const out = {};
  for (const k of ['recipient', 'to', 'spender', 'operator', 'sender', 'newOwner', 'newImplementation', 'account', 'owner']) {
    if (typeof p[k] === 'string') out[k] = p[k].toLowerCase();
  }
  if (decodedTx && typeof decodedTx.contract === 'string') out.contract = decodedTx.contract.toLowerCase();
  return out;
}

function decodedAmounts(decodedTx) {
  const p = (decodedTx && decodedTx.parameters) || {};
  const out = [];
  for (const k of ['amount', 'amountIn', 'value']) {
    const v = parseUint(p[k]);
    if (v !== null) out.push({ key: k, value: v });
  }
  const wei = decodedTx ? parseUint(decodedTx.valueWei) : null;
  if (wei !== null) out.push({ key: 'valueWei', value: wei });
  return out;
}

// Token-window negation scope (live fix, record inv_mvv6yj0w): the old
// 24-char window caught "not" from an earlier clause ("does not match
// ... purpose: unlimited") and flipped polarity wrongly. Only the three
// tokens immediately before the word can negate it — "not unlimited"
// still negates, "does not match ... unlimited" no longer does.
function negatedBefore(text, index, tokens = 3) {
  const before = text.slice(0, index).toLowerCase().split(/\s+/).filter(Boolean);
  const slice = before.slice(-tokens).join(' ');
  return /\b(not|n't|never|no)\b/.test(slice);
}

function negatedAfter(text, index, window = 12) {
  const slice = text.slice(index, index + window).toLowerCase();
  return /^\s*(is\s+)?not\b/.test(slice);
}

let claimSeq = 0;
function mkClaim(target, where, excerpt, parsed, result, explanation, evidenceRefs) {
  claimSeq += 1;
  return {
    claimId: `CLM-${String(claimSeq).padStart(3, '0')}`,
    target, where: where.slice(0, 60), excerpt: String(excerpt).slice(0, 280),
    parsed, result, explanation, evidenceRefs: Array.isArray(evidenceRefs) ? evidenceRefs : []
  };
}

// --- Target 1: named recipient/counterparty vs decoded parties ---
function checkCounterparty(statement, where, ctx) {
  const out = [];
  const parties = decodedParties(ctx.decodedTx);
  // Framed: role word … address, or address … role word.
  const roleWords = Object.keys(ROLE_PARAMS).join('|');
  const fwd = new RegExp(`\\b(${roleWords})\\b[^.\\n]{0,40}(0x[0-9a-fA-F]{40})`, 'gi');
  const bwd = new RegExp(`(0x[0-9a-fA-F]{40})[^.\\n]{0,40}\\b(${roleWords}|receives|is the (?:new )?owner)\\b`, 'gi');
  const seen = new Set();
  let m;
  const consider = (roleRaw, addrRaw, index, windowText) => {
    const addr = addrRaw.toLowerCase();
    let role = roleRaw.toLowerCase();
    // Live fix (record inv_mvv5gka0): "to unverified impl 0x1111" is an
    // implementation mention wearing a 'to' frame — reframe before
    // comparing, else the proxy address is wrongly checked as recipient.
    if (role !== 'implementation' && /\bimpl(ementation)?\b/i.test(windowText || '')) role = 'implementation';
    const key = `${role}:${addr}`;
    if (seen.has(key)) return;
    seen.add(key);
    if (negatedBefore(statement, index) || negatedAfter(statement, index + addrRaw.length + roleRaw.length)) {
      out.push(mkClaim('counterparty', where, statement, { role, address: addr },
        'INCONCLUSIVE', 'negated counterparty mention; polarity unsafe to evaluate', []));
      return;
    }
    // A framed address that IS the transaction target is a target
    // mention, not a recipient claim — abstain rather than contradict.
    if (parties.contract && addr === parties.contract) {
      out.push(mkClaim('counterparty', where, statement, { role, address: addr },
        'INCONCLUSIVE', 'names the transaction target; no recipient-role claim to check', []));
      return;
    }
    let keys = ROLE_PARAMS[role];
    if (!keys) {
      // Backwards phrasing ("0x… receives", "0x… is the owner").
      keys = /owner/.test(role) ? ['newOwner'] : ['recipient', 'to'];
    }
    const candidates = keys.map((k) => parties[k]).filter(Boolean);
    // Implementation role also consults resolved proxy evidence.
    if (role === 'implementation' && ctx.proxyResolution && typeof ctx.proxyResolution.implementation === 'string') {
      candidates.push(ctx.proxyResolution.implementation.toLowerCase());
    }
    if (candidates.length === 0) {
      out.push(mkClaim('counterparty', where, statement, { role, address: addr },
        'NOT_APPLICABLE', `statement names a ${role} but the transaction decodes no such party`, []));
      return;
    }
    if (candidates.includes(addr)) {
      out.push(mkClaim('counterparty', where, statement, { role, address: addr },
        'VERIFIED', `named ${role} ${addr} equals the decoded value`, ['tx']));
    } else {
      out.push(mkClaim('counterparty', where, statement, { role, address: addr },
        'CONTRADICTED', `named ${role} ${addr} matches no decoded ${keys.join('/')} (${candidates.join(', ') || 'none'})`, ['tx']));
    }
  };
  while ((m = fwd.exec(statement)) !== null) consider(m[1], m[2], m.index + m[0].lastIndexOf(m[2]), m[0]);
  while ((m = bwd.exec(statement)) !== null) consider(m[2], m[1], m.index, m[0]);
  return out;
}

// --- Target 2: claimed amount vs decoded amounts ---
// Number pattern consumes the FULL digit run: the old alternation
// (\d{1,3} first) matched only the "100" prefix of "1000000" (live
// record inv_mvv63yc4), fabricating a contradiction. Greedy run plus
// a no-digit-or-comma-ahead guard instead.
const NUM_RUN = String.raw`(\d+(?:,\d{3})*(?:\.\d+)?)(?![\d,])`;
const AMOUNT_FRAME_RE = new RegExp(`\\b(amountIn|amount\\s*:|approves?|transfer(?:s|red|ring)?|value\\s*:)\\s*${NUM_RUN}\\s*(ETH|WETH|USDC|USDT|DAI|UNI)\\b`, 'gi');

function checkAmount(statement, where, ctx) {
  const out = [];
  const amounts = decodedAmounts(ctx.decodedTx);
  AMOUNT_FRAME_RE.lastIndex = 0;
  let m;
  while ((m = AMOUNT_FRAME_RE.exec(statement)) !== null) {
    const frame = m[1].toLowerCase();
    const num = m[2];
    const sym = m[3].toUpperCase();
    if (negatedBefore(statement, m.index)) {
      out.push(mkClaim('amount', where, statement, { frame, num, sym },
        'INCONCLUSIVE', 'negated amount mention; polarity unsafe to evaluate', []));
      continue;
    }
    if (amounts.length === 0) {
      out.push(mkClaim('amount', where, statement, { frame, num, sym },
        'NOT_APPLICABLE', 'statement claims an amount but the transaction decodes no comparable amount', []));
      continue;
    }
    const decimals = tokenDecimals(sym, ctx.decodedTx, ctx.chainId);
    if (decimals === null) {
      out.push(mkClaim('amount', where, statement, { frame, num, sym },
        'INCONCLUSIVE', `no verified decimals for ${sym}; display value cannot be converted`, []));
      continue;
    }
    const claimed = displayToBase(num, decimals);
    if (claimed === null) {
      out.push(mkClaim('amount', where, statement, { frame, num, sym },
        'INCONCLUSIVE', 'claimed number unparseable', []));
      continue;
    }
    const hit = amounts.find((a) => a.value === claimed);
    out.push(mkClaim('amount', where, statement, { frame, num, sym, baseUnits: claimed.toString() },
      hit ? 'VERIFIED' : 'CONTRADICTED',
      hit
        ? `claimed ${num} ${sym} equals decoded ${hit.key} (${hit.value})`
        : `claimed ${num} ${sym} (${claimed} base units) equals no decoded amount (${amounts.map((a) => `${a.key}=${a.value}`).join(', ')})`,
      ['tx']));
  }
  return out;
}

// --- Target 3: unlimited assertions vs decoded allowance ---
function checkUnlimited(statement, where, ctx) {
  const out = [];
  const re = /\b(unlimited|infinite)\b/gi;
  let m;
  const fn = ctx.decodedTx && ctx.decodedTx.functionName;
  const isApproval = fn === 'approve' || fn === 'increaseAllowance' || fn === 'permit';
  while ((m = re.exec(statement)) !== null) {
    const negated = negatedBefore(statement, m.index) || negatedAfter(statement, m.index + m[0].length);
    if (!isApproval) {
      out.push(mkClaim('unlimited', where, statement, { word: m[0].toLowerCase(), negated },
        'NOT_APPLICABLE', `unlimited language on a non-approval operation (${fn || 'unknown'})`, []));
      continue;
    }
    const raw = ctx.decodedTx.parameters ? (ctx.decodedTx.parameters.amount !== undefined ? ctx.decodedTx.parameters.amount : ctx.decodedTx.parameters.value) : undefined;
    const cls = classifyApprovalAmount(raw === undefined ? NaN : raw);
    if (cls.kind === 'unparseable') {
      out.push(mkClaim('unlimited', where, statement, { word: m[0].toLowerCase(), negated },
        'INCONCLUSIVE', 'decoded allowance unavailable; assertion cannot be checked', []));
      continue;
    }
    const actualUnlimited = cls.kind === 'unlimited';
    const claimedUnlimited = !negated;
    out.push(mkClaim('unlimited', where, statement, { word: m[0].toLowerCase(), negated, decoded: cls.value },
      actualUnlimited === claimedUnlimited ? 'VERIFIED' : 'CONTRADICTED',
      actualUnlimited === claimedUnlimited
        ? `unlimited assertion agrees with decoded allowance (${cls.value})`
        : `statement claims ${claimedUnlimited ? 'unlimited' : 'limited'} but decoded allowance is ${cls.value} (${cls.kind})`,
      ['tx']));
  }
  return out;
}

// --- Target 4: claimed minimum output vs decoded minimum ---
function checkMinOutput(statement, where, ctx) {
  const out = [];
  const fn = ctx.decodedTx && ctx.decodedTx.functionName;
  const field = fn === 'exactInputSingle' ? 'amountOutMinimum'
    : (fn === 'swapExactTokensForTokens' || fn === 'swapExactETHForTokens' ? 'amountOutMin' : null);
  const re = new RegExp(`(?:amountOutMinimum|minimum[^.\\n]{0,30}?)\\s*${NUM_RUN}\\s*(USDC|USDT|DAI|WETH|ETH|UNI)?`, 'gi');
  let m;
  while ((m = re.exec(statement)) !== null) {
    const num = m[1];
    const sym = (m[2] || '').toUpperCase() || null;
    if (!field) {
      out.push(mkClaim('min-output', where, statement, { num, sym },
        'NOT_APPLICABLE', `minimum-output language on ${fn || 'unknown'} (no minimum concept)`, []));
      continue;
    }
    if (negatedBefore(statement, m.index)) {
      out.push(mkClaim('min-output', where, statement, { num, sym },
        'INCONCLUSIVE', 'negated minimum mention; polarity unsafe to evaluate', []));
      continue;
    }
    const decoded = parseUint(ctx.decodedTx.parameters ? ctx.decodedTx.parameters[field] : undefined);
    if (decoded === null) {
      out.push(mkClaim('min-output', where, statement, { num, sym },
        'INCONCLUSIVE', 'decoded minimum unavailable', []));
      continue;
    }
    // Raw equality first (live fix, record inv_mvv63yc4): a model that
    // names the decoded integer verbatim ("minimum 1000000") agrees
    // with the evidence however units are interpreted. Only otherwise
    // attempt display conversion.
    const raw = parseUint(num.replace(/,/g, ''));
    if (raw !== null && raw === decoded) {
      out.push(mkClaim('min-output', where, statement, { num, sym, baseUnits: raw.toString() },
        'VERIFIED', `claimed minimum ${num} names the decoded ${field} exactly (${decoded})`, ['tx']));
      continue;
    }
    // Numbers with decimals/symbol are display values; huge plain
    // integers are plausibly base units. Convert display only with
    // verified output-token decimals, else compare raw when plausible.
    let claimed = null;
    if (sym) {
      const dec = tokenDecimals(sym, ctx.decodedTx, ctx.chainId);
      if (dec === null) {
        out.push(mkClaim('min-output', where, statement, { num, sym },
          'INCONCLUSIVE', `no verified decimals for ${sym}`, []));
        continue;
      }
      claimed = displayToBase(num, dec);
    } else if (num.includes('.') || num.replace(/,/g, '').length < 10) {
      // Display-shaped without a symbol: try output-token decimals.
      const dec = outputTokenDecimals(ctx);
      if (dec === null) {
        out.push(mkClaim('min-output', where, statement, { num, sym },
          'INCONCLUSIVE', 'display-shaped minimum without a verifiable token/symbol', []));
        continue;
      }
      claimed = displayToBase(num, dec);
    } else {
      claimed = parseUint(num.replace(/,/g, ''));
    }
    if (claimed === null) {
      out.push(mkClaim('min-output', where, statement, { num, sym },
        'INCONCLUSIVE', 'claimed minimum unparseable', []));
      continue;
    }
    out.push(mkClaim('min-output', where, statement, { num, sym, baseUnits: claimed.toString() },
      claimed === decoded ? 'VERIFIED' : 'CONTRADICTED',
      claimed === decoded
        ? `claimed minimum ${num}${sym ? ` ${sym}` : ''} equals decoded ${field} (${decoded})`
        : `claimed minimum ${num}${sym ? ` ${sym}` : ''} (${claimed}) differs from decoded ${field} (${decoded})`,
      ['tx']));
  }
  return out;
}

function outputTokenDecimals(ctx) {
  const p = (ctx.decodedTx && ctx.decodedTx.parameters) || {};
  const out = p.tokenOut || (Array.isArray(p.path) && p.path.length > 0 ? p.path[p.path.length - 1] : null);
  if (typeof out !== 'string') return null;
  const entry = matchKnownEntry(KNOWN_TOKENS, out, ctx.chainId);
  return entry && Number.isInteger(entry.decimals) ? entry.decimals : null;
}

// --- Target 5: claimed function/selector vs decode ---
function checkFunction(statement, where, ctx) {
  const out = [];
  const decodedFn = ctx.decodedTx && ctx.decodedTx.functionName;
  const re = /the\s+(?:transaction|call|function)\s+(?:calls?|executes?|invokes?|is)\s+`?([A-Za-z0-9_]+)`?/gi;
  let m;
  while ((m = re.exec(statement)) !== null) {
    const named = m[1];
    if (typeof decodedFn !== 'string') {
      out.push(mkClaim('function', where, statement, { named }, 'INCONCLUSIVE', 'no decoded function to compare', []));
      continue;
    }
    // Skip generic verbs captured as names ("is a", "calls the").
    if (/^(a|the|this|that|an)$/i.test(named)) continue;
    out.push(mkClaim('function', where, statement, { named },
      named === decodedFn ? 'VERIFIED' : 'CONTRADICTED',
      named === decodedFn
        ? `named function ${named} equals the decoded function`
        : `named function ${named} differs from decoded ${decodedFn}`,
      ['tx']));
  }
  const sre = /selector\s+(0x[0-9a-fA-F]{8})\b/gi;
  while ((m = sre.exec(statement)) !== null) {
    const claimed = m[1].toLowerCase();
    const p = (ctx.decodedTx && ctx.decodedTx.parameters) || {};
    const truthful = (typeof p.selector === 'string' && p.selector.toLowerCase() === claimed)
      || (typeof ctx.decodedTx.rawCalldata === 'string' && ctx.decodedTx.rawCalldata.slice(0, 10).toLowerCase() === claimed);
    const known = typeof p.selector === 'string' || typeof ctx.decodedTx.rawCalldata === 'string';
    out.push(mkClaim('function', where, statement, { selector: claimed },
      !known ? 'INCONCLUSIVE' : (truthful ? 'VERIFIED' : 'CONTRADICTED'),
      !known ? 'no decoded selector carried to compare' : (truthful ? `selector ${claimed} matches the calldata` : `selector ${claimed} is not the calldata selector`),
      ['tx']));
  }
  return out;
}

// --- Target 6: contract-identity assertions vs the ladder ---
function checkIdentity(statement, where, ctx) {
  const out = [];
  const status = ctx.contractIdentity && ctx.contractIdentity.status;
  const verifiedSet = ['source-verified', 'bytecode-matched', 'proxy-implementation-resolved'];
  const unverifiedSet = ['static-label', 'code-present-unverified', 'unknown', 'verification-unavailable'];
  const re = /\b(verif[a-z]*|unverif[a-z]*|unknown|known|audited)\s+(contract|implementation|token|router)\b|\b(contract|implementation|token|router)\s+is\s+(verif[a-z]*|unverif[a-z]*|unknown|known)\b/gi;
  let m;
  while ((m = re.exec(statement)) !== null) {
    const word = (m[1] || m[4] || '').toLowerCase();
    const positive = /^(verif[a-z]*|known|audited)$/.test(word) && !word.startsWith('unverif');
    if (!status) {
      out.push(mkClaim('identity', where, statement, { word }, 'INCONCLUSIVE', 'no identity record to compare', []));
      continue;
    }
    const actualVerified = verifiedSet.includes(status);
    const actualKnown = actualVerified || status === 'static-label';
    const expected = positive ? (word === 'known' ? actualKnown : actualVerified) : unverifiedSet.includes(status);
    out.push(mkClaim('identity', where, statement, { word },
      expected ? 'VERIFIED' : 'CONTRADICTED',
      expected
        ? `identity assertion ("${word}") agrees with status ${status}`
        : `identity assertion ("${word}") disagrees with status ${status}`,
      ['identity']));
  }
  const pre = /\bis\s+(not\s+)?a\s+proxy\b/gi;
  while ((m = pre.exec(statement)) !== null) {
    const claimsProxy = !m[1];
    const isProxy = ctx.proxyResolution ? ctx.proxyResolution.isProxy : null;
    if (isProxy !== true && isProxy !== false) {
      out.push(mkClaim('proxy', where, statement, { claimsProxy }, 'INCONCLUSIVE', 'proxy status unknown', []));
      continue;
    }
    out.push(mkClaim('proxy', where, statement, { claimsProxy },
      claimsProxy === isProxy ? 'VERIFIED' : 'CONTRADICTED',
      claimsProxy === isProxy
        ? `proxy assertion agrees (isProxy=${isProxy})`
        : `statement claims ${claimsProxy ? 'a proxy' : 'not a proxy'} but isProxy=${isProxy}`,
      ['proxy']));
  }
  return out;
}

// --- Target 7: deadline claims vs decoded deadline + analysis ---
function checkDeadline(statement, where, ctx) {
  const out = [];
  const std = ctx.decodedTx && ctx.decodedTx.standard;
  const fn = ctx.decodedTx && ctx.decodedTx.functionName;
  const field = (DEADLINE_FIELDS[std] || {})[fn] || null;
  const re = /(?:deadline|expir(?:ation|es|ed|y))[^.\n]{0,40}?(\d{9,12})/gi;
  let m;
  while ((m = re.exec(statement)) !== null) {
    const num = m[1];
    if (!field) {
      out.push(mkClaim('deadline', where, statement, { num },
        'NOT_APPLICABLE', `deadline value claimed on ${fn || 'unknown'} (no deadline concept)`, []));
      continue;
    }
    const decoded = parseUint(ctx.decodedTx.parameters ? ctx.decodedTx.parameters[field] : undefined);
    if (decoded === null) {
      out.push(mkClaim('deadline', where, statement, { num },
        'INCONCLUSIVE', 'decoded deadline unavailable', []));
      continue;
    }
    const claimed = BigInt(num);
    out.push(mkClaim('deadline', where, statement, { num },
      claimed === decoded ? 'VERIFIED' : 'CONTRADICTED',
      claimed === decoded
        ? `claimed deadline ${num} equals decoded ${field}`
        : `claimed deadline ${num} differs from decoded ${field} (${decoded})`,
      ['tx', 'deadlines']));
  }
  const ere = /\b(already expired|has expired|is expired|not expired|still valid|unexpired)\b/gi;
  while ((m = ere.exec(statement)) !== null) {
    const phrase = m[1].toLowerCase();
    const claimsExpired = phrase === 'already expired' || phrase === 'has expired' || phrase === 'is expired';
    const states = (ctx.deadlineAnalysis && Array.isArray(ctx.deadlineAnalysis.states)) ? ctx.deadlineAnalysis.states : [];
    const top = states.find((s) => s && s.label === 'top-level call');
    if (!top || (top.outcome !== 'expired' && top.outcome !== 'valid' && top.outcome !== 'near-expiry')) {
      out.push(mkClaim('deadline', where, statement, { phrase },
        'INCONCLUSIVE', 'no assessed expiry state to compare', []));
      continue;
    }
    const actualExpired = top.outcome === 'expired';
    out.push(mkClaim('deadline', where, statement, { phrase },
      claimsExpired === actualExpired ? 'VERIFIED' : 'CONTRADICTED',
      claimsExpired === actualExpired
        ? `expiry assertion agrees (outcome=${top.outcome})`
        : `statement claims ${claimsExpired ? 'expired' : 'live'} but outcome=${top.outcome}`,
      ['deadlines']));
  }
  return out;
}

// --- Target 8: claimed implementation vs resolved implementation ---
function checkImplementation(statement, where, ctx) {
  const out = [];
  const re = /implementation[^.\n]{0,40}(0x[0-9a-fA-F]{40})/gi;
  let m;
  while ((m = re.exec(statement)) !== null) {
    const addr = m[1].toLowerCase();
    const resolved = ctx.proxyResolution && typeof ctx.proxyResolution.implementation === 'string'
      ? ctx.proxyResolution.implementation.toLowerCase() : null;
    if (!resolved) {
      out.push(mkClaim('implementation', where, statement, { address: addr },
        'INCONCLUSIVE', 'no resolved implementation to compare', []));
      continue;
    }
    out.push(mkClaim('implementation', where, statement, { address: addr },
      addr === resolved ? 'VERIFIED' : 'CONTRADICTED',
      addr === resolved
        ? `claimed implementation ${addr} equals the resolved implementation`
        : `claimed implementation ${addr} differs from resolved ${resolved}`,
      ['proxy']));
  }
  return out;
}

function collectStatements(reasoningResult) {
  const inv = (reasoningResult && reasoningResult.investigation) || reasoningResult || {};
  const out = [];
  const push = (where, s) => {
    if (typeof s === 'string' && s.trim().length > 0) out.push({ where, statement: s.slice(0, 2000) });
  };
  (Array.isArray(inv.conclusions) ? inv.conclusions.slice(0, 12) : []).forEach((c, i) => {
    if (c && typeof c === 'object') push(`conclusions[${i}]`, c.statement);
    else if (typeof c === 'string') push(`conclusions[${i}]`, c);
  });
  (Array.isArray(inv.discrepancies) ? inv.discrepancies.slice(0, 12) : []).forEach((d, i) => {
    if (d && typeof d === 'object') push(`discrepancies[${i}]`, d.statement || d.description);
    else if (typeof d === 'string') push(`discrepancies[${i}]`, d);
  });
  return out;
}

/**
 * Verify checkable semantic claims in a reasoning result against the
 * verified record. Returns { claims, summary } where summary counts
 * outcomes and flags safe-direction handling.
 */
function verifySemanticClaims({ reasoningResult, decodedTx, chainId, contractIdentity, proxyResolution, deadlineAnalysis } = {}) {
  claimSeq = 0;
  const ctx = { decodedTx: decodedTx || {}, chainId: chainId === undefined || chainId === null ? null : String(chainId), contractIdentity, proxyResolution, deadlineAnalysis };
  const statements = collectStatements(reasoningResult);
  let claims = [];
  let truncated = false;
  for (const [si, { where, statement }] of statements.entries()) {
    claims.push(
      ...checkCounterparty(statement, where, ctx),
      ...checkAmount(statement, where, ctx),
      ...checkUnlimited(statement, where, ctx),
      ...checkMinOutput(statement, where, ctx),
      ...checkFunction(statement, where, ctx),
      ...checkIdentity(statement, where, ctx),
      ...checkDeadline(statement, where, ctx),
      ...checkImplementation(statement, where, ctx)
    );
    if (claims.length >= MAX_CLAIMS) {
      truncated = si < statements.length - 1 || claims.length > MAX_CLAIMS;
      break;
    }
  }
  claims = claims.slice(0, MAX_CLAIMS);
  const counts = { VERIFIED: 0, CONTRADICTED: 0, INCONCLUSIVE: 0, NOT_APPLICABLE: 0 };
  for (const c of claims) counts[c.result] = (counts[c.result] || 0) + 1;
  const contradicted = claims.filter((c) => c.result === 'CONTRADICTED');
  return {
    claims,
    summary: {
      statements: statements.length,
      evaluated: claims.length,
      truncated,
      ...counts,
      downgrade: contradicted.length > 0,
      hold: contradicted.length > 0 ? {
        source: 'semantic-claims',
        reason: `Model reasoning contradicts verified evidence: ${contradicted.slice(0, 3).map((c) => `${c.claimId} ${c.target}`).join(', ')}${contradicted.length > 3 ? '…' : ''}.`
      } : null
    }
  };
}

module.exports = { MAX_CLAIMS, verifySemanticClaims };
