/**
 * Deterministic economic-effect reconstruction (Capability 5, B2).
 *
 * Turns decoded calls — top-level plus every nested subcall — into a
 * machine-readable effect list: what value or authority each operation
 * moves, between which parties, in exact integer units. This is the
 * deterministic substrate B3 (requested-vs-actual) and B4
 * (composition) reason over, and the only effect vocabulary the model
 * may cite (EF-xxx); anything it asserts beyond this list is
 * unsupported by construction.
 *
 * Honesty rules (no invented economics):
 * - Every node carries verification:'decoded' unless a later stage
 *   (simulation receipt in B7) upgrades it. Decoded effects are what
 *   the transaction ASKS to do — never what executed.
 * - Inner-call token contracts are NOT established from batch
 *   context (see nestedCalls.js): inner transfer/approve nodes name
 *   parties and amounts exactly but leave asset.contract null with an
 *   explicit note. The exceptions are calls that name their own
 *   tokens (Permit2 approve, swaps with token legs/paths).
 * - Inner transfer senders are likewise unestablished (msg.sender in
 *   batch context is not decoded): from is null with a note, except
 *   transferFrom-style calls whose sender is an explicit parameter.
 * - Unknown, depth-limited, or unmapped calls produce opaque nodes
 *   and force downstream uncertainty — never silent omission.
 * - Amounts are exact integer decimal strings (BigInt); display
 *   conversion happens only with verified decimals and is labeled.
 */

const { KNOWN_TOKENS, INFINITE_THRESHOLD } = require('../utils/abiSignatures');
const { buildSubcallTree } = require('./nestedCalls');

const MAX_EFFECTS = 200;

const EFFECT_KINDS = [
  'native-transfer', 'transfer', 'transfer-nft', 'approval', 'approval-nft',
  'permit-authorization', 'swap', 'wrap', 'unwrap', 'authority-change', 'bridge', 'opaque'
];

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

function lowerAddr(v) {
  return typeof v === 'string' && ADDRESS_RE.test(v) ? v.toLowerCase() : null;
}

function exactInt(v) {
  try {
    if (typeof v === 'bigint') return v >= 0n ? v.toString() : null;
    if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? String(v) : null;
    if (typeof v === 'string') {
      const s = v.trim();
      if (/^[0-9]+$/.test(s)) return BigInt(s).toString();
      if (/^0[xX][0-9a-fA-F]+$/.test(s)) return BigInt(s).toString();
    }
  } catch { /* fall through */ }
  return null;
}

function tokenMeta(contract, chainId) {
  const meta = { symbol: null, decimals: null };
  if (!contract) return meta;
  const entry = KNOWN_TOKENS[contract.toLowerCase()];
  if (!entry) return meta;
  try {
    const want = BigInt(chainId).toString();
    const chains = Array.isArray(entry.chains) ? entry.chains.map((c) => BigInt(c).toString()) : [];
    if (!chains.includes(want)) return meta;
  } catch {
    return meta;
  }
  return { symbol: entry.symbol || null, decimals: Number.isSafeInteger(entry.decimals) ? entry.decimals : null };
}

function padId(n) {
  return `EF-${String(n).padStart(3, '0')}`;
}

function baseNode(seq, kind, operation, subcall) {
  return {
    effectId: padId(seq),
    kind,
    operation,
    subcall,
    asset: { standard: 'unknown', contract: null, symbol: null, decimals: null, tokenId: null },
    amount: null,
    from: null,
    to: null,
    spender: null,
    operator: null,
    unlimited: null,
    verification: 'decoded',
    confidence: 'exact',
    provenance: [subcall ? `decode:${subcall.subcallId}` : 'decode:tx'],
    notes: []
  };
}

/**
 * Map one decoded operation (top-level call or subcall) to effect
 * nodes. `isTop` gates what the batch context establishes: top-level
 * calls execute against tx.to with tx.from as caller; inners name
 * only what their parameters state.
 */
function mapOperation({ functionName, standard, parameters, selector, unknown, depthLimited, subcall, tx, topContract, chainId }) {
  const fn = typeof functionName === 'string' ? functionName : 'unknownFunction';
  const std = typeof standard === 'string' ? standard : 'Unknown';
  const params = (parameters && typeof parameters === 'object') ? parameters : {};
  const op = { functionName: fn, standard: std };
  const isTop = !subcall;
  const out = [];

  if (unknown === true || depthLimited === true || fn === 'unknownFunction') {
    const n = baseNode(0, 'opaque', op, subcall);
    n.confidence = 'unknown';
    n.notes.push(depthLimited === true
      ? 'decode depth limit reached: children undecoded; economic consequences unknown'
      : `uninterpretable call (selector ${typeof selector === 'string' ? selector : 'unknown'}); economic consequences unknown`);
    out.push(n);
    return out;
  }

  const tokenContract = (explicit) => {
    const c = lowerAddr(explicit);
    if (c) return { contract: c, note: null };
    if (isTop && topContract) return { contract: topContract, note: null };
    return { contract: null, note: 'token contract unestablished from batch context' };
  };
  const withAsset = (n, assetStd, contractInfo) => {
    n.asset.standard = assetStd;
    n.asset.contract = contractInfo.contract;
    const meta = tokenMeta(contractInfo.contract, chainId);
    n.asset.symbol = meta.symbol;
    n.asset.decimals = meta.decimals;
    if (contractInfo.note) {
      n.notes.push(contractInfo.note);
      if (n.confidence === 'exact') n.confidence = 'partial';
    }
    return n;
  };

  const approvalLike = (fn === 'approve' || fn === 'increaseAllowance') && std === 'ERC20';
  const transferLike = fn === 'transfer' && std === 'ERC20';
  const transferFromLike = fn === 'transferFrom' && (std === 'ERC20' || std === 'ERC721');

  if (transferLike) {
    const n = baseNode(0, 'transfer', op, subcall);
    withAsset(n, 'ERC20', tokenContract(null));
    n.amount = exactInt(params.amount);
    if (n.amount === null) { n.notes.push('amount undecodable'); n.confidence = 'partial'; }
    n.from = isTop ? lowerAddr(tx.from) : null;
    if (!isTop) n.notes.push('sender unestablished in batch context');
    n.to = lowerAddr(params.recipient);
    if (!n.to) { n.notes.push('recipient unverifiable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (transferFromLike && std === 'ERC20') {
    const n = baseNode(0, 'transfer', op, subcall);
    withAsset(n, 'ERC20', tokenContract(null));
    n.amount = exactInt(params.amount);
    if (n.amount === null) { n.notes.push('amount undecodable'); n.confidence = 'partial'; }
    n.from = lowerAddr(params.sender);
    n.to = lowerAddr(params.recipient);
    if (!n.from || !n.to) { n.notes.push('counterparty unverifiable'); n.confidence = 'partial'; }
    out.push(n);
  } else if ((fn === 'transferFrom' || fn === 'safeTransferFrom') && std === 'ERC721') {
    const n = baseNode(0, 'transfer-nft', op, subcall);
    withAsset(n, 'ERC721', tokenContract(null));
    const args = Array.isArray(params.args) ? params.args : [];
    n.from = lowerAddr(params.sender !== undefined ? params.sender : args[0]);
    n.to = lowerAddr(params.recipient !== undefined ? params.recipient : args[1]);
    n.asset.tokenId = exactInt(params.tokenId !== undefined ? params.tokenId : args[2]);
    if (!n.from || !n.to || n.asset.tokenId === null) { n.notes.push('nft parties/token undecodable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (approvalLike) {
    const n = baseNode(0, 'approval', op, subcall);
    withAsset(n, 'ERC20', tokenContract(null));
    n.amount = exactInt(params.amount);
    if (n.amount === null) { n.notes.push('amount undecodable'); n.confidence = 'partial'; }
    n.spender = lowerAddr(params.spender);
    if (!n.spender) { n.notes.push('spender unverifiable'); n.confidence = 'partial'; }
    try {
      n.unlimited = n.amount !== null && BigInt(n.amount) >= INFINITE_THRESHOLD;
    } catch { n.unlimited = null; }
    if (fn === 'increaseAllowance') n.notes.push('delta semantics: adds to the current allowance; the resulting total needs chain state');
    out.push(n);
  } else if (fn === 'setApprovalForAll' && std === 'ERC721') {
    const n = baseNode(0, 'approval-nft', op, subcall);
    withAsset(n, 'ERC721', tokenContract(null));
    n.operator = lowerAddr(params.operator);
    n.unlimited = params.approved === true ? true : params.approved === false ? false : null;
    if (!n.operator) { n.notes.push('operator unverifiable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (fn === 'approve' && std === 'Permit2') {
    const n = baseNode(0, 'approval', op, subcall);
    // Decoder yields positional args for Permit2 approve:
    // [token, spender, amount, expiration].
    const pargs = Array.isArray(params.args) ? params.args : [];
    const pToken = params.token !== undefined ? params.token : pargs[0];
    const pSpender = params.spender !== undefined ? params.spender : pargs[1];
    const pAmount = params.amount !== undefined ? params.amount : pargs[2];
    const pExp = params.expiration !== undefined ? params.expiration : pargs[3];
    withAsset(n, 'ERC20', tokenContract(pToken));
    n.amount = exactInt(pAmount);
    n.spender = lowerAddr(pSpender);
    const exp = exactInt(pExp);
    n.expiration = exp;
    if (exp !== null) n.notes.push(`permit2 expiration ${exp}`);
    if (n.amount === null || !n.spender) { n.notes.push('permit2 terms undecodable'); n.confidence = 'partial'; }
    try {
      n.unlimited = n.amount !== null && BigInt(n.amount) >= INFINITE_THRESHOLD;
    } catch { n.unlimited = null; }
    out.push(n);
  } else if (fn === 'permit') {
    const n = baseNode(0, 'permit-authorization', op, subcall);
    withAsset(n, std === 'ERC721' ? 'ERC721' : 'ERC20', tokenContract(params.token));
    n.amount = exactInt(params.value !== undefined ? params.value : params.amount);
    n.owner = lowerAddr(params.owner);
    n.spender = lowerAddr(params.spender);
    const dl = exactInt(params.deadline !== undefined ? params.deadline : params.expiration);
    // Capability 5 B6: submission deadline, NOT allowance duration.
    // (EIP-2612 allowances persist; only Permit2 expirations bound them.)
    n.signedExpiry = dl;
    if (dl !== null) n.notes.push(`signed expiry ${dl}`);
    n.notes.push('off-chain signature authorizes future on-chain spending; no value moves in this call');
    if (!n.spender) { n.notes.push('spender unverifiable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (fn === 'exactInputSingle' && std === 'UniswapV3Router') {
    const n = baseNode(0, 'swap', op, subcall);
    n.asset.standard = 'ERC20';
    const legs = { in: lowerAddr(params.tokenIn), out: lowerAddr(params.tokenOut) };
    n.asset.contract = legs.in;
    const meta = tokenMeta(legs.in, chainId);
    n.asset.symbol = meta.symbol;
    n.asset.decimals = meta.decimals;
    n.amount = exactInt(params.amountIn);
    n.from = isTop ? lowerAddr(tx.from) : null;
    if (!isTop) n.notes.push('swapper unestablished in batch context');
    n.to = lowerAddr(params.recipient);
    const minOut = exactInt(params.amountOutMinimum);
    n.notes.push(`legs ${legs.in || '?'} -> ${legs.out || '?'}; minimum out ${minOut === null ? 'undecodable' : minOut}`);
    if (n.amount === null || !legs.in || !legs.out) { n.notes.push('swap terms undecodable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (std === 'UniswapV2Router' && typeof fn === 'string' && fn.startsWith('swap')) {
    const n = baseNode(0, 'swap', op, subcall);
    n.asset.standard = 'ERC20';
    const path = Array.isArray(params.path) ? params.path : [];
    const legs = { in: lowerAddr(path[0]), out: lowerAddr(path[path.length - 1]) };
    n.asset.contract = legs.in;
    const meta = tokenMeta(legs.in, chainId);
    n.asset.symbol = meta.symbol;
    n.asset.decimals = meta.decimals;
    n.amount = exactInt(params.amountIn !== undefined ? params.amountIn : params.amountInMax);
    n.from = isTop ? lowerAddr(tx.from) : null;
    if (!isTop) n.notes.push('swapper unestablished in batch context');
    n.to = lowerAddr(params.to);
    n.notes.push(`path ${legs.in || '?'} -> ${legs.out || '?'} (${path.length} hop(s))`);
    if (n.amount === null || !legs.in || !legs.out) { n.notes.push('swap terms undecodable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (fn === 'depositV3' && std === 'AcrossV3') {
    const n = baseNode(0, 'bridge', op, subcall);
    withAsset(n, 'ERC20', tokenContract(params.inputToken));
    n.amount = exactInt(params.inputAmount);
    if (n.amount === null) { n.notes.push('input amount undecodable'); n.confidence = 'partial'; }
    n.from = lowerAddr(params.depositor);
    if (!n.from) { n.notes.push('depositor unverifiable'); n.confidence = 'partial'; }
    n.to = lowerAddr(params.recipient);
    if (!n.to) { n.notes.push('destination recipient unverifiable'); n.confidence = 'partial'; }
    else n.notes.push('recipient lives on the destination chain, not the source chain');
    n.bridge = {
      protocol: 'across-v3',
      destinationChain: exactInt(params.destinationChainId),
      destinationAsset: lowerAddr(params.outputToken),
      expectedOutput: exactInt(params.outputAmount),
      hasMessage: typeof params.message === 'string' && params.message.startsWith('0x') && params.message.length > 2
    };
    if (n.bridge.destinationChain === null) { n.notes.push('destination chain undecodable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (fn === 'depositForBurn' && std === 'CCTPV1') {
    const n = baseNode(0, 'bridge', op, subcall);
    withAsset(n, 'ERC20', tokenContract(params.burnToken));
    n.amount = exactInt(params.amount);
    if (n.amount === null) { n.notes.push('burn amount undecodable'); n.confidence = 'partial'; }
    n.from = isTop ? lowerAddr(tx.from) : null;
    if (!isTop) n.notes.push('burner unestablished in batch context');
    const { bytes32ToAddress } = require('../utils/bridgeAnalysis');
    n.to = bytes32ToAddress(params.mintRecipient);
    if (!n.to) { n.notes.push('mint recipient is not a left-padded EVM address'); n.confidence = 'partial'; }
    else n.notes.push('recipient lives on the destination chain, not the source chain');
    n.bridge = {
      protocol: 'cctp-v1',
      destinationDomain: exactInt(params.destinationDomain),
      destinationAsset: null,
      expectedOutput: n.amount
    };
    n.notes.push('destination mints native USDC after attestation; domain-to-chain resolution lives in bridge analysis');
    out.push(n);
  } else if (fn === 'deposit' && std === 'WETH') {
    const n = baseNode(0, 'wrap', op, subcall);
    n.asset.standard = 'ERC20';
    n.asset.contract = isTop ? topContract : null;
    if (!isTop) n.notes.push('weth contract unestablished in batch context');
    n.amount = isTop ? exactInt(tx.value) : null;
    if (isTop) n.from = lowerAddr(tx.from);
    if (isTop) n.to = topContract;
    else n.notes.push('wrap amount unestablished for nested deposit (no per-call value)');
    if (n.amount === null && isTop) { n.notes.push('deposit value undecodable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (fn === 'withdraw' && std === 'WETH') {
    const n = baseNode(0, 'unwrap', op, subcall);
    n.asset.standard = 'ERC20';
    n.asset.contract = isTop ? topContract : null;
    if (!isTop) n.notes.push('weth contract unestablished in batch context');
    const args = Array.isArray(params.args) ? params.args : [];
    n.amount = exactInt(params.wad !== undefined ? params.wad : params.amount !== undefined ? params.amount : args[0]);
    n.from = isTop ? topContract : null;
    n.to = isTop ? lowerAddr(tx.from) : null;
    if (!isTop) n.notes.push('unwrap parties unestablished in batch context');
    if (n.amount === null) { n.notes.push('withdraw amount undecodable'); n.confidence = 'partial'; }
    out.push(n);
  } else if (fn === 'multicall') {
    // Container: children carry the effects; the frame itself moves
    // nothing. Skipped so the effect list stays an effect list.
  } else if ((fn === 'transferOwnership' || fn === 'renounceOwnership') && std === 'Ownable') {
    const n = baseNode(0, 'authority-change', op, subcall);
    n.to = lowerAddr(params.newOwner);
    n.notes.push(fn === 'renounceOwnership' ? 'ownership renounced (zero-address authority)' : `ownership to ${n.to || 'unverifiable'}`);
    if (fn === 'transferOwnership' && !n.to) n.confidence = 'partial';
    out.push(n);
  } else if ((fn === 'grantRole' || fn === 'revokeRole' || fn === 'renounceRole') && std === 'AccessControl') {
    const n = baseNode(0, 'authority-change', op, subcall);
    n.to = lowerAddr(params.account);
    n.notes.push(`${fn} role ${typeof params.role === 'string' ? params.role.slice(0, 66) : 'undecodable'} account ${n.to || 'unverifiable'}`);
    if (!n.to) n.confidence = 'partial';
    out.push(n);
  } else if ((fn === 'pause' || fn === 'unpause') && std === 'Pausable') {
    const n = baseNode(0, 'authority-change', op, subcall);
    n.notes.push(fn === 'pause' ? 'protocol paused' : 'protocol unpaused');
    out.push(n);
  } else if ((fn === 'upgradeTo' || fn === 'upgradeToAndCall' || fn === 'changeAdmin') && std === 'ProxyAdmin') {
    const n = baseNode(0, 'authority-change', op, subcall);
    n.to = lowerAddr(params.newImplementation !== undefined ? params.newImplementation : params.newAdmin);
    n.notes.push(`${fn}: implementation authority changes`);
    if (!n.to) n.confidence = 'partial';
    out.push(n);
  } else {
    const n = baseNode(0, 'opaque', op, subcall);
    n.confidence = 'unknown';
    n.notes.push(`decoded ${fn} (${std}) has no effect mapping; economic consequences unmodeled`);
    out.push(n);
  }
  return out;
}

/**
 * Reconstruct the deterministic effect list for a transaction.
 * @param {{tx:{from,to,value},decodedTx:object,chainId}} args
 * @returns {{effects:Array,truncated:boolean,opaqueCount:number,summary:object}}
 * Never throws for malformed input: unmapped structure becomes opaque.
 */
function reconstructEffects(args) {
  const { tx, decodedTx, chainId } = (args && typeof args === 'object') ? args : {};
  const effects = [];
  const t = (tx && typeof tx === 'object') ? tx : {};
  const topContract = lowerAddr(t.to);
  let overflowed = false;
  const push = (nodes) => {
    for (const n of nodes) {
      if (effects.length >= MAX_EFFECTS) return false;
      n.effectId = padId(effects.length + 1);
      effects.push(n);
    }
    return true;
  };
  try {
    const d = (decodedTx && typeof decodedTx === 'object') ? decodedTx : {};
    // Native leg: attached value authorizes movement regardless of
    // calldata (payable or not — execution validity is separate).
    const wei = exactInt(t.value === undefined || t.value === null || t.value === '' ? '0x0' : t.value);
    if (wei !== null && BigInt(wei) > 0n) {
      const n = baseNode(0, 'native-transfer', { functionName: '(value)', standard: 'Native' }, null);
      n.asset.standard = 'native';
      n.asset.decimals = 18; // EVM protocol constant: 1 native unit = 10^18 wei.
      n.amount = wei;
      n.from = lowerAddr(t.from);
      n.to = topContract;
      if (!n.from || !n.to) { n.notes.push('native parties unverifiable'); n.confidence = 'partial'; }
      push([n]);
    }
    const fn = typeof d.functionName === 'string' ? d.functionName : 'unknownFunction';
    const isNativeOnly = fn === 'nativeTransfer';
    if (!isNativeOnly) {
      push(mapOperation({
        functionName: d.functionName, standard: d.standard, parameters: d.parameters,
        selector: d.selector, unknown: fn === 'unknownFunction', depthLimited: false,
        subcall: null, tx: t, topContract, chainId
      }));
    }
    let tree = null;
    try {
      tree = buildSubcallTree(d);
    } catch {
      tree = null;
    }
    if (tree && Array.isArray(tree.subcalls)) {
      for (const s of tree.subcalls) {
        if (effects.length >= MAX_EFFECTS) {
          overflowed = true;
          break;
        }
        push(mapOperation({
          functionName: s.functionName, standard: s.standard, parameters: s.parameters,
          selector: s.selector, unknown: s.unknown === true, depthLimited: s.depthLimited === true,
          subcall: { subcallId: s.subcallId, path: s.path }, tx: t, topContract, chainId
        }));
      }
      if (overflowed) {
        // One node past the cap so the overflow itself is listed,
        // never implied by a flag alone.
        const n = baseNode(0, 'opaque', { functionName: '(overflow)', standard: 'Unknown' }, null);
        n.confidence = 'unknown';
        n.notes.push(`effect list capped at ${MAX_EFFECTS}; further nested operations unlisted and unverified`);
        n.effectId = padId(effects.length + 1);
        effects.push(n);
      }
    }
  } catch (err) {
    const n = baseNode(0, 'opaque', { functionName: '(reconstruction)', standard: 'Unknown' }, null);
    n.confidence = 'unknown';
    n.notes.push(`reconstruction failed: ${String((err && err.message) || err).slice(0, 160)}`);
    if (effects.length < MAX_EFFECTS) {
      n.effectId = padId(effects.length + 1);
      effects.push(n);
    }
  }
  const listed = effects.length;
  const opaqueCount = effects.filter((e) => e.kind === 'opaque').length;
  const byKind = {};
  for (const e of effects) byKind[e.kind] = (byKind[e.kind] || 0) + 1;
  return {
    effects,
    truncated: overflowed,
    opaqueCount,
    summary: { total: listed, byKind, opaqueCount, verification: 'decoded', note: 'decoded effects: what the transaction asks to do, not what executed' }
  };
}

module.exports = { MAX_EFFECTS, EFFECT_KINDS, reconstructEffects, mapOperation, exactInt, tokenMeta };
