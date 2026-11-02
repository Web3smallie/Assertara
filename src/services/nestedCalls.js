/**
 * Nested transaction interpretation (Capability 4, B4).
 *
 * The decoder recursively decodes multicall inners (to depth 5), but
 * until now nothing consumed them: a harmless top-level `multicall`
 * could conceal approvals, transfers, or drains. This module turns the
 * raw inner-call arrays into a stable, citable subcall tree and runs
 * the EXISTING rule evaluators over each inner operation, so nested
 * behavior fires the same findings, policy, and safeguards as
 * top-level behavior — with subcall provenance attached.
 *
 * Semantics notes (honest boundaries):
 * - Inner calls in a multicall execute against the batch target's
 *   context; the token contract an inner approve/transfer refers to is
 *   NOT established from calldata, so inner approve/transferFrom are
 *   always standard-ambiguous (allowance-vs-token-id unresolved).
 * - Unknown inner selectors and depth-limited branches are
 *   uninterpretable: each yields an UNKNOWN_INNER_CALL finding rather
 *   than a silent pass.
 * - Inner findings reuse top-level ruleIds (policy already maps them);
 *   each carries metadata.subcall { subcallId, path } plus a
 *   description prefix naming the nested call.
 */

const { INFINITE_THRESHOLD } = require('../utils/abiSignatures');
const { evaluateInfiniteApproval } = require('../rules/infiniteApproval');
const { evaluateUnverifiedSpender } = require('../rules/unverifiedSpender');
const { evaluatePermit2Drain } = require('../rules/permit2Drain');
const { evaluateSwapRecipient } = require('../rules/swapRecipient');
const { evaluatePrivilegedOperation } = require('../rules/privilegedOperation');
const { evaluateValueProtection } = require('../rules/valueProtection');

// Inner-derived findings cap per investigation. Any single finding
// already holds the transaction for review, so the cap only bounds
// bundle verbosity — never the hold decision. The subcall tree itself
// is always complete.
const MAX_INNER_FINDINGS = 50;

function padId(n) {
  return `SC-${String(n).padStart(3, '0')}`;
}

// Name inner args for effect-relevant functions, mirroring the
// decoder's top-level extraction (same slot layouts, same standards).
function nameInnerArgs(entry) {
  const args = Array.isArray(entry.args) ? entry.args : [];
  const params = {};
  const { functionName, standard } = entry;
  if ((functionName === 'approve' || functionName === 'increaseAllowance') && standard === 'ERC20') {
    params.spender = args[0];
    params.amount = args[1];
  } else if (functionName === 'transfer' && standard === 'ERC20') {
    params.recipient = args[0];
    params.amount = args[1];
  } else if (functionName === 'transferFrom' && standard === 'ERC20') {
    params.sender = args[0];
    params.recipient = args[1];
    params.amount = args[2];
  } else if (functionName === 'setApprovalForAll' && standard === 'ERC721') {
    params.operator = args[0];
    params.approved = args[1];
  } else if (functionName === 'exactInputSingle' && standard === 'UniswapV3Router') {
    const p = args[0] || {};
    const pick = (name, i) => (p[name] !== undefined ? p[name] : p[i]);
    params.tokenIn = pick('tokenIn', 0);
    params.tokenOut = pick('tokenOut', 1);
    params.fee = pick('fee', 2);
    params.recipient = pick('recipient', 3);
    params.amountIn = pick('amountIn', 4);
    params.amountOutMinimum = pick('amountOutMinimum', 5);
    params.sqrtPriceLimitX96 = pick('sqrtPriceLimitX96', 6);
  } else if (functionName === 'transferOwnership' && standard === 'Ownable') {
    params.newOwner = args[0];
  } else if (functionName === 'renounceOwnership' && standard === 'Ownable') {
    params.renounced = true;
  } else if ((functionName === 'grantRole' || functionName === 'revokeRole' || functionName === 'renounceRole') && standard === 'AccessControl') {
    params.role = args[0];
    params.account = args[1];
  } else if ((functionName === 'pause' || functionName === 'unpause') && standard === 'Pausable') {
    params.paused = functionName === 'pause';
  } else if (functionName === 'upgradeTo' && standard === 'ProxyAdmin') {
    params.newImplementation = args[0];
  } else if (functionName === 'upgradeToAndCall' && standard === 'ProxyAdmin') {
    params.newImplementation = args[0];
    params.data = args[1];
  } else if (functionName === 'changeAdmin' && standard === 'ProxyAdmin') {
    params.newAdmin = args[0];
  } else if (functionName === 'approve' && standard === 'Permit2') {
    params.token = args[0];
    params.spender = args[1];
    params.amount = args[2];
    params.expiration = args[3];
  } else if (functionName === 'permit' && standard === 'Permit2') {
    params.owner = args[0];
    const single = args[1];
    params.expiration = single && typeof single === 'object'
      ? (single.expiration !== undefined ? single.expiration : single[2])
      : undefined;
  } else if (functionName === 'permit' && standard === 'ERC20') {
    params.owner = args[0];
    params.spender = args[1];
    params.value = args[2];
    params.deadline = args[3];
  } else if (functionName === 'swapExactTokensForTokens' && standard === 'UniswapV2Router') {
    params.amountIn = args[0];
    params.amountOutMin = args[1];
    params.path = args[2];
    params.to = args[3];
    params.deadline = args[4];
  } else if (functionName === 'swapTokensForExactTokens' && standard === 'UniswapV2Router') {
    params.amountOut = args[0];
    params.amountInMax = args[1];
    params.path = args[2];
    params.to = args[3];
    params.deadline = args[4];
  } else if (functionName === 'swapExactETHForTokens' && standard === 'UniswapV2Router') {
    params.amountOutMin = args[0];
    params.path = args[1];
    params.to = args[2];
    params.deadline = args[3];
  } else if (args.length > 0) {
    params.args = args;
  }
  return params;
}

function fmtAmount(v) {
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'string') return v.slice(0, 80);
  return null;
}

function fmtAddr(v) {
  return typeof v === 'string' ? v.toLowerCase() : null;
}

// One-line human summary of an inner operation's effect, plus machine
// flags. Summaries describe shape only ("approve X amount Y"), never
// intent.
function describeEffect(functionName, standard, params) {
  const effect = { summary: `${functionName} (${standard})`, movesAssets: false, grantsApproval: false, unknown: false };
  if (functionName === 'approve' && standard === 'ERC20') {
    const unlimited = typeof params.amount === 'bigint' && params.amount >= INFINITE_THRESHOLD;
    effect.grantsApproval = true;
    effect.summary = `approve spender ${fmtAddr(params.spender) || '?'} amount ${fmtAmount(params.amount) || '?'}${unlimited ? ' (UNLIMITED)' : ''}`;
  } else if (functionName === 'increaseAllowance' && standard === 'ERC20') {
    effect.grantsApproval = true;
    effect.summary = `increaseAllowance spender ${fmtAddr(params.spender) || '?'} added ${fmtAmount(params.amount) || '?'}`;
  } else if (functionName === 'transfer' && standard === 'ERC20') {
    effect.movesAssets = true;
    effect.summary = `transfer ${fmtAmount(params.amount) || '?'} to ${fmtAddr(params.recipient) || '?'}`;
  } else if (functionName === 'transferFrom' && standard === 'ERC20') {
    effect.movesAssets = true;
    effect.summary = `transferFrom ${fmtAddr(params.sender) || '?'} -> ${fmtAddr(params.recipient) || '?'} amount ${fmtAmount(params.amount) || '?'}`;
  } else if (functionName === 'setApprovalForAll' && standard === 'ERC721') {
    effect.grantsApproval = params.approved === true;
    effect.summary = `setApprovalForAll operator ${fmtAddr(params.operator) || '?'} approved=${params.approved === true}`;
  } else if (functionName === 'exactInputSingle' && standard === 'UniswapV3Router') {
    effect.movesAssets = true;
    effect.summary = `swap ${fmtAmount(params.amountIn) || '?'} in (min out ${fmtAmount(params.amountOutMinimum) || '?'}) to ${fmtAddr(params.recipient) || '?'}`;
  } else if (standard === 'UniswapV2Router' && typeof functionName === 'string' && functionName.startsWith('swap')) {
    effect.movesAssets = true;
    effect.summary = `${functionName} to ${fmtAddr(params.to) || '?'} deadline ${fmtAmount(params.deadline) || '?'}`;
  } else if (functionName === 'permit') {
    effect.grantsApproval = true;
    effect.summary = `permit spender ${fmtAddr(params.spender) || '?'} deadline/expiry ${fmtAmount(params.deadline !== undefined ? params.deadline : params.expiration) || '?'}`;
  } else if (functionName === 'multicall') {
    effect.summary = 'nested batch (see children)';
  } else if (functionName === 'depositV3' && standard === 'AcrossV3') {
    effect.movesAssets = true;
    effect.summary = `bridge depositV3 ${fmtAmount(params.inputAmount) || '?'} -> chain ${fmtAmount(params.destinationChainId) || '?'} recipient ${fmtAddr(params.recipient) || '?'}`;
  } else if (functionName === 'depositForBurn' && standard === 'CCTPV1') {
    effect.movesAssets = true;
    effect.summary = `bridge depositForBurn ${fmtAmount(params.amount) || '?'} -> domain ${fmtAmount(params.destinationDomain) || '?'}`;
  } else if (functionName === 'unknownFunction') {
    effect.unknown = true;
    effect.summary = `uninterpretable call (selector ${params.selector || 'unknown'})`;
  } else {
    effect.summary = `${functionName} (${standard})`;
  }
  return effect;
}

/**
 * Build the stable subcall tree from decoded parameters. Pure and
 * deterministic: IDs (SC-001…) assign in pre-order traversal, so every
 * caller deriving from the same decodedTx gets identical IDs.
 */
function buildSubcallTree(decodedTx) {
  const empty = { hasNested: false, subcalls: [], maxDepth: 0, unknownCount: 0, depthLimitedCount: 0 };
  const target = decodedTx && typeof decodedTx.contract === 'string' ? decodedTx.contract : null;
  const roots = decodedTx && decodedTx.parameters && Array.isArray(decodedTx.parameters.calls)
    ? decodedTx.parameters.calls : null;
  if (!roots || roots.length === 0) return empty;
  const subcalls = [];
  let seq = 0;
  let unknownCount = 0;
  let depthLimitedCount = 0;
  let maxDepth = 0;
  const walk = (entries, pathPrefix, depth, parentId) => {
    if (!Array.isArray(entries)) return;
    entries.forEach((entry, i) => {
      if (!entry || typeof entry !== 'object') return;
      seq += 1;
      maxDepth = Math.max(maxDepth, depth);
      const id = padId(seq);
      const path = pathPrefix === '' ? String(i) : `${pathPrefix}/${i}`;
      const unknown = entry.functionName === 'unknownFunction' || entry.standard === 'Unknown';
      const depthLimited = entry.depthLimited === true;
      if (unknown) unknownCount += 1;
      if (depthLimited) depthLimitedCount += 1;
      const children = Array.isArray(entry.calls) ? entry.calls : [];
      const container = entry.functionName === 'multicall' && children.length > 0;
      const parameters = unknown ? { selector: entry.selector || null } : nameInnerArgs(entry);
      const effect = depthLimited
        ? { summary: `decode depth limit reached at ${entry.functionName}; ${children.length} child(ren) undecoded`, movesAssets: false, grantsApproval: false, unknown: true }
        : describeEffect(entry.functionName, entry.standard, parameters);
      if (unknown) effect.unknown = true;
      subcalls.push({
        subcallId: id,
        path,
        depth,
        parentId,
        index: typeof entry.index === 'number' ? entry.index : i,
        target,
        selector: typeof entry.selector === 'string' ? entry.selector : null,
        functionName: entry.functionName || 'unknownFunction',
        standard: entry.standard || 'Unknown',
        unknown,
        depthLimited,
        container,
        parameters,
        effect,
        raw: typeof entry.raw === 'string' ? entry.raw.slice(0, 1024) : null
      });
      walk(children, path, depth + 1, id);
    });
  };
  walk(roots, '', 1, null);
  return { hasNested: subcalls.length > 0, subcalls, maxDepth, unknownCount, depthLimitedCount };
}

/**
 * Run the existing rule evaluators over each interpretable inner call.
 * Each inner is shaped exactly like a top-level decode (same fields the
 * rules read), with standard-ambiguity set for approve/transferFrom
 * (inner token context is unknown). Unknown and depth-limited inners
 * yield UNKNOWN_INNER_CALL findings. Findings cap at MAX_INNER_FINDINGS.
 */
function evaluateSubcallFindings(tree, { contract, sender, chainId } = {}) {
  const out = [];
  if (!tree || !Array.isArray(tree.subcalls)) return out;
  for (const sc of tree.subcalls) {
    if (out.length >= MAX_INNER_FINDINGS) break;
    if (sc.container) continue;
    if (sc.unknown || sc.depthLimited) {
      out.push({
        ruleId: 'UNKNOWN_INNER_CALL',
        severity: 'MEDIUM',
        description: `[nested ${sc.subcallId} ${sc.functionName}] Batch contains an uninterpretable inner call${sc.selector ? ` (selector ${sc.selector})` : ''}${sc.depthLimited ? ' (decode depth limit reached)' : ''} at path ${sc.path}: its behavior cannot be established and may conceal asset movement or approvals.`,
        triggered: true,
        metadata: { subcall: { subcallId: sc.subcallId, path: sc.path }, selector: sc.selector, depthLimited: sc.depthLimited === true }
      });
      continue;
    }
    const shaped = {
      contract: contract || sc.target,
      chainId: chainId === undefined ? null : chainId,
      functionName: sc.functionName,
      standard: sc.standard,
      parameters: sc.parameters || {},
      sender: typeof sender === 'string' ? sender : undefined
    };
    if ((sc.functionName === 'approve' || sc.functionName === 'transferFrom') && sc.standard === 'ERC20') {
      shaped.standardAmbiguous = true;
      shaped.standardCandidates = ['ERC20', 'ERC721'];
    }
    if (sc.functionName === 'approve' && sc.standard === 'ERC20'
        && typeof shaped.parameters.amount === 'bigint' && shaped.parameters.amount >= INFINITE_THRESHOLD) {
      shaped.isUnlimitedApproval = false; // ambiguous standard: never a confirmed unlimited allowance
    }
    const hits = [
      evaluateInfiniteApproval(shaped),
      evaluateUnverifiedSpender(shaped),
      evaluatePermit2Drain(shaped),
      evaluateSwapRecipient(shaped),
      evaluatePrivilegedOperation(shaped),
      evaluateValueProtection(shaped)
    ].filter(Boolean);
    for (const h of hits) {
      if (out.length >= MAX_INNER_FINDINGS) break;
      out.push({
        ...h,
        description: `[nested ${sc.subcallId} ${sc.functionName}] ${h.description || ''}`,
        metadata: { ...(h.metadata || {}), subcall: { subcallId: sc.subcallId, path: sc.path } }
      });
    }
  }
  return out;
}

/**
 * Canonical subcall-tree hash (Capability 5, B1). Binds mandate
 * authorization to the exact nested structure that was evaluated:
 * the approval token carries this hash and the signer recomputes it
 * from the presented transaction, so any mutation between evaluation
 * and signing — including inner-call changes the top-level digest
 * already covers — is detected at inner granularity.
 *
 * Canonicalization is type-insensitive across the app/signer
 * boundary (the app hashes the bundle's serialized decodedTx, the
 * signer hashes a fresh decode of the approved bytes): BigInt and
 * decimal strings collapse to 'bigint:<digits>', addresses
 * lowercase, object keys sorted, undefined becomes null. Display
 * fields (summaries, raw excerpts) are excluded: the hash covers
 * authorized structure, not presentation.
 */
function canonicalizeTreeValue(v, depth) {
  if (depth > 8) return null;
  if (v === null || v === undefined) return null;
  if (typeof v === 'bigint') return `bigint:${v.toString()}`;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return Number.isSafeInteger(v) ? `int:${v}` : null;
  if (typeof v === 'string') {
    if (/^0x[0-9a-fA-F]+$/.test(v)) return v.toLowerCase();
    if (/^[0-9]+$/.test(v)) return `bigint:${v.replace(/^0+(?=\d)/, '') || '0'}`;
    return v.slice(0, 256);
  }
  if (Array.isArray(v)) return v.slice(0, 200).map((e) => canonicalizeTreeValue(e, depth + 1));
  if (typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (typeof k !== 'string' || k.length === 0 || k.length > 128) continue;
      out[k] = canonicalizeTreeValue(v[k], depth + 1);
    }
    return out;
  }
  return null;
}

function hashSubcallTree(decodedTx) {
  const crypto = require('crypto');
  let tree;
  try {
    tree = buildSubcallTree(decodedTx);
  } catch {
    return null;
  }
  const projection = (tree.subcalls || []).map((s) => ({
    id: s.subcallId,
    path: s.path,
    depth: s.depth,
    parent: s.parentId,
    target: typeof s.target === 'string' ? s.target.toLowerCase() : null,
    selector: typeof s.selector === 'string' ? s.selector.toLowerCase() : null,
    fn: s.functionName,
    std: s.standard,
    unknown: s.unknown === true,
    depthLimited: s.depthLimited === true,
    container: s.container === true,
    params: canonicalizeTreeValue(s.parameters, 0)
  }));
  return crypto.createHash('sha256').update(JSON.stringify(projection), 'utf8').digest('hex');
}

module.exports = { MAX_INNER_FINDINGS, buildSubcallTree, evaluateSubcallFindings, nameInnerArgs, hashSubcallTree, canonicalizeTreeValue };
