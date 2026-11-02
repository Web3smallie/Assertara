/**
 * Deterministic EVM Calldata Decoder & Security Rule Engine
 */

const { decodeFunctionData, toFunctionSelector, getAddress, formatEther } = require('viem');
const {
  ERC20_ABI,
  ERC721_ABI,
  WETH_ABI,
  PERMIT2_ABI,
  UNISWAP_V3_ROUTER_ABI,
  UNISWAP_V2_ROUTER_ABI,
  ACROSS_V3_ABI,
  CCTP_V1_ABI,
  OWNABLE_ABI,
  ACCESS_CONTROL_ABI,
  PAUSABLE_ABI,
  PROXY_ADMIN_ABI,
  KNOWN_TOKENS,
  KNOWN_ROUTERS,
  MAX_UINT256,
  INFINITE_THRESHOLD,
  normalizeMapChainId,
  matchKnownEntry
} = require('../utils/abiSignatures');

const { evaluateInfiniteApproval } = require('../rules/infiniteApproval');
const { evaluateUnverifiedSpender } = require('../rules/unverifiedSpender');
const { evaluatePermit2Drain } = require('../rules/permit2Drain');
const { evaluateSwapRecipient } = require('../rules/swapRecipient');
const { evaluatePrivilegedOperation } = require('../rules/privilegedOperation');
const { evaluateValueProtection } = require('../rules/valueProtection');
const { buildSubcallTree, evaluateSubcallFindings } = require('./nestedCalls');

const ALL_ABIS = [
  { name: 'ERC20', abi: ERC20_ABI },
  { name: 'ERC721', abi: ERC721_ABI },
  { name: 'WETH', abi: WETH_ABI },
  { name: 'Permit2', abi: PERMIT2_ABI },
  { name: 'UniswapV3Router', abi: UNISWAP_V3_ROUTER_ABI },
  { name: 'UniswapV2Router', abi: UNISWAP_V2_ROUTER_ABI },
  { name: 'AcrossV3', abi: ACROSS_V3_ABI },
  { name: 'CCTPV1', abi: CCTP_V1_ABI },
  { name: 'Ownable', abi: OWNABLE_ABI },
  { name: 'AccessControl', abi: ACCESS_CONTROL_ABI },
  { name: 'Pausable', abi: PAUSABLE_ABI },
  { name: 'ProxyAdmin', abi: PROXY_ADMIN_ABI }
];

// Canonical ExactInputSingleParams layout for SwapRouter02 (IV3SwapRouter):
// (address tokenIn, address tokenOut, uint24 fee, address recipient,
//  uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)
const EXACT_INPUT_SINGLE_FIELDS = [
  { name: 'tokenIn', type: 'address' },
  { name: 'tokenOut', type: 'address' },
  { name: 'fee', type: 'number' },
  { name: 'recipient', type: 'address' },
  { name: 'amountIn', type: 'bigint' },
  { name: 'amountOutMinimum', type: 'bigint' },
  { name: 'sqrtPriceLimitX96', type: 'bigint' }
];

// Maximum levels of nested `calls` arrays below the outer multicall. A
// multicall found at the boundary is still identified (selector, raw,
// functionName) but marked depthLimited with calls: [] instead of recursing,
// so adversarially nested calldata cannot exhaust the stack.
const MAX_MULTICALL_DEPTH = 5;

// Decode each inner call of a multicall(bytes[]) against the known ABIs,
// recursing into nested multicalls up to MAX_MULTICALL_DEPTH. Every inner
// call keeps its raw calldata; undecodable inners are explicit
// unknownFunction records, never invented facts. Never throws: malformed
// entries yield an unknownFunction record with the raw input preserved.
function decodeMulticallInnerCalls(innerArray, depth = 0) {
  if (!Array.isArray(innerArray)) return [];
  return innerArray.map((raw, index) => {
    const entry = {
      index,
      raw: typeof raw === 'string' ? raw : null,
      selector: null,
      functionName: 'unknownFunction',
      standard: 'Unknown'
    };
    if (typeof raw !== 'string' || raw.length < 10) return entry;
    entry.selector = raw.slice(0, 10);
    for (const { name, abi } of ALL_ABIS) {
      try {
        const decoded = decodeFunctionData({ abi, data: raw });
        if (decoded && decoded.functionName) {
          entry.functionName = decoded.functionName;
          entry.standard = name;
          entry.args = decoded.args;
          if (decoded.functionName === 'multicall' && name === 'UniswapV3Router') {
            if (depth + 1 >= MAX_MULTICALL_DEPTH) {
              entry.depthLimited = true;
              entry.calls = [];
            } else {
              entry.calls = decodeMulticallInnerCalls(decoded.args && decoded.args[0], depth + 1);
            }
          }
          break;
        }
      } catch {
        // Try the next ABI; persistent failure stays unknownFunction.
      }
    }
    return entry;
  });
}

// Identify a known function by selector alone, without decoding parameters.
function matchKnownSelector(data) {
  const selector = data.slice(0, 10).toLowerCase();
  for (const { name, abi } of ALL_ABIS) {
    for (const item of abi) {
      if (item.type !== 'function') continue;
      let itemSelector;
      try {
        itemSelector = toFunctionSelector(item);
      } catch {
        continue;
      }
      if (itemSelector.toLowerCase() === selector) {
        return { standard: name, item };
      }
    }
  }
  return null;
}

// Decode an exactInputSingle call whose trailing calldata words are missing
// (e.g. fixtures carrying only the leading tuple fields). Extracts whichever
// complete 32-byte words are present, in canonical field order; never invents
// fields beyond the actual calldata length.
function decodeTruncatedExactInputSingle(data) {
  const hex = data.startsWith('0x') ? data.slice(2) : data;
  const words = hex.slice(8).match(/.{1,64}/g) || [];
  const complete = words.filter((w) => w.length === 64);
  // Skip the tuple offset word when present (full-style encoding truncated mid-tuple).
  let start = 0;
  if (complete.length > 1 && BigInt('0x' + complete[0]) === 32n) start = 1;
  const parameters = {};
  for (let i = start; i < complete.length && i - start < EXACT_INPUT_SINGLE_FIELDS.length; i++) {
    const field = EXACT_INPUT_SINGLE_FIELDS[i - start];
    const word = complete[i];
    parameters[field.name] = field.type === 'address'
      ? getAddress('0x' + word.slice(24))
      : field.type === 'number'
        ? Number(BigInt('0x' + word))
        : BigInt('0x' + word);
  }
  return parameters;
}

// Coded error for malformed transaction values. Callers translate this into
// a structured client error (HTTP 400) instead of an uncontrolled throw.
const DECODE_INVALID_VALUE = 'DECODE_INVALID_VALUE';

// Coded error for non-string transaction addresses/calldata. Previously a
// numeric `to`/`data` threw a raw TypeError (500); malformed input is a
// client error (400), matching the value convention above.
const DECODE_INVALID_DATA = 'DECODE_INVALID_DATA';

function invalidValueError(value) {
  const shown = typeof value === 'string' ? JSON.stringify(value.slice(0, 60)) : typeof value;
  const err = new Error(`"value" must be a 0x hex or decimal wei integer; got ${shown}`);
  err.code = DECODE_INVALID_VALUE;
  return err;
}

function invalidDataError(field, value) {
  const shown = typeof value === 'string' ? JSON.stringify(value.slice(0, 60)) : (value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value);
  const err = new Error(`"${field}" must be a 0x hex string; got ${shown}`);
  err.code = DECODE_INVALID_DATA;
  return err;
}

// Parse msg.value into exact representations. Missing/empty values follow
// the existing input contract (default '0x0' → zero). ETH rendering uses
// viem's formatEther: exact decimal strings with no floating-point
// arithmetic; whole-ETH output is unchanged ('1', '0'). Nothing is rounded
// or truncated: the raw wei string is always preserved in valueWei.
function parseTransactionValue(value) {
  if (value === undefined || value === null || value === '') {
    return { valueWei: '0', valueEth: '0' };
  }
  // Only safe integers are accepted as numbers: larger integer-valued
  // doubles already lost wei precision before reaching us.
  if (typeof value === 'boolean' || (typeof value === 'number' && !Number.isSafeInteger(value))) {
    throw invalidValueError(value);
  }
  let wei;
  try {
    wei = typeof value === 'bigint' ? value : BigInt(value);
  } catch {
    throw invalidValueError(value);
  }
  if (wei < 0n) throw invalidValueError(value);
  return { valueWei: wei.toString(), valueEth: formatEther(wei) };
}

function serializeBigInt(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'bigint') return obj.toString();
  if (Array.isArray(obj)) return obj.map(serializeBigInt);
  if (typeof obj === 'object') {
    const res = {};
    for (const [key, val] of Object.entries(obj)) {
      res[key] = serializeBigInt(val);
    }
    return res;
  }
  return obj;
}

function decodeTransactionCalldata({ to, data, value = '0x0', from, chainId }) {
  if (typeof to !== 'string' || to.length === 0) throw invalidDataError('to', to);
  if (data !== undefined && data !== null && typeof data !== 'string') throw invalidDataError('data', data);
  const targetAddress = (to || '').toLowerCase();
  // Capability 4 B5: static labels apply only on their own chains. A
  // mainnet token/router address on another chain is an unrelated
  // contract and must decode as unknown — never with borrowed metadata.
  const normalizedChainId = normalizeMapChainId(chainId);
  const knownToken = matchKnownEntry(KNOWN_TOKENS, targetAddress, normalizedChainId);
  const knownRouter = matchKnownEntry(KNOWN_ROUTERS, targetAddress, normalizedChainId);
  const { valueWei, valueEth } = parseTransactionValue(value);

  const result = {
    contract: targetAddress,
    chainId: normalizedChainId,
    contractName: knownToken ? knownToken.name : (knownRouter ? knownRouter.name : 'Unknown Contract'),
    symbol: knownToken ? knownToken.symbol : null,
    decimals: knownToken ? knownToken.decimals : null,
    valueWei,
    valueEth,
    functionName: null,
    standard: null,
    standardAmbiguous: false,
    standardCandidates: [],
    parameters: {},
    isUnlimitedApproval: false,
    rawCalldata: data,
    ruleFindings: []
  };

  // If simple ETH transfer with no calldata
  if (!data || data === '0x' || data === '0x0') {
    result.functionName = 'nativeTransfer';
    result.standard = 'Native';
    result.parameters = { recipient: targetAddress, value: result.valueEth };
    return result;
  }

  // Attempt decoding against known canonical ABIs
  let fullDecodeMatched = false;
  for (const { name, abi } of ALL_ABIS) {
    try {
      const decoded = decodeFunctionData({ abi, data });
      if (decoded && decoded.functionName) {
        result.functionName = decoded.functionName;
        result.standard = name;

        // Extract parameters by name. Branches are scoped by standard, not
        // bare function name: Permit2 approve(token, spender, amount,
        // expiration) shares its name with ERC-20 approve(spender, amount),
        // and the ERC-20 slot layout would mislabel its arguments (the token
        // would pose as the spender). Unscoped functions keep generic args.
        if (decoded.args) {
          if ((decoded.functionName === 'approve' || decoded.functionName === 'increaseAllowance') && name === 'ERC20') {
            result.parameters.spender = decoded.args[0];
            result.parameters.amount = decoded.args[1];
            if (typeof decoded.args[1] === 'bigint' && decoded.args[1] >= INFINITE_THRESHOLD) {
              result.isUnlimitedApproval = true;
            }
          } else if (decoded.functionName === 'transfer' && name === 'ERC20') {
            result.parameters.recipient = decoded.args[0];
            result.parameters.amount = decoded.args[1];
          } else if (decoded.functionName === 'transferFrom' && name === 'ERC20') {
            result.parameters.sender = decoded.args[0];
            result.parameters.recipient = decoded.args[1];
            result.parameters.amount = decoded.args[2];
          } else if (decoded.functionName === 'setApprovalForAll' && name === 'ERC721') {
            result.parameters.operator = decoded.args[0];
            result.parameters.approved = decoded.args[1];
            result.isUnlimitedApproval = Boolean(decoded.args[1]);
          } else if (decoded.functionName === 'exactInputSingle' && name === 'UniswapV3Router') {
            const params = decoded.args[0] || {};
            const pick = (fieldName, index) =>
              params[fieldName] !== undefined ? params[fieldName] : params[index];
            result.parameters.tokenIn = pick('tokenIn', 0);
            result.parameters.tokenOut = pick('tokenOut', 1);
            result.parameters.fee = pick('fee', 2);
            result.parameters.recipient = pick('recipient', 3);
            result.parameters.amountIn = pick('amountIn', 4);
            result.parameters.amountOutMinimum = pick('amountOutMinimum', 5);
            result.parameters.sqrtPriceLimitX96 = pick('sqrtPriceLimitX96', 6);
          } else if (decoded.functionName === 'multicall' && name === 'UniswapV3Router') {
            result.parameters.args = decoded.args;
            result.parameters.calls = decodeMulticallInnerCalls(decoded.args && decoded.args[0]);
          } else if (decoded.functionName === 'depositV3' && name === 'AcrossV3') {
            result.parameters.depositor = decoded.args[0];
            result.parameters.recipient = decoded.args[1];
            result.parameters.inputToken = decoded.args[2];
            result.parameters.outputToken = decoded.args[3];
            result.parameters.inputAmount = decoded.args[4];
            result.parameters.outputAmount = decoded.args[5];
            result.parameters.destinationChainId = decoded.args[6];
            result.parameters.exclusiveRelayer = decoded.args[7];
            result.parameters.quoteTimestamp = decoded.args[8];
            result.parameters.fillDeadline = decoded.args[9];
            result.parameters.exclusivityDeadline = decoded.args[10];
            result.parameters.message = decoded.args[11];
          } else if (decoded.functionName === 'depositForBurn' && name === 'CCTPV1') {
            result.parameters.amount = decoded.args[0];
            result.parameters.destinationDomain = decoded.args[1];
            result.parameters.mintRecipient = decoded.args[2];
            result.parameters.burnToken = decoded.args[3];
          } else if (decoded.functionName === 'transferOwnership' && name === 'Ownable') {
            result.parameters.newOwner = decoded.args[0];
          } else if (decoded.functionName === 'renounceOwnership' && name === 'Ownable') {
            result.parameters.renounced = true;
          } else if ((decoded.functionName === 'grantRole' || decoded.functionName === 'revokeRole' || decoded.functionName === 'renounceRole') && name === 'AccessControl') {
            result.parameters.role = decoded.args[0];
            result.parameters.account = decoded.args[1];
          } else if ((decoded.functionName === 'pause' || decoded.functionName === 'unpause') && name === 'Pausable') {
            result.parameters.paused = decoded.functionName === 'pause';
          } else if (decoded.functionName === 'upgradeTo' && name === 'ProxyAdmin') {
            result.parameters.newImplementation = decoded.args[0];
          } else if (decoded.functionName === 'upgradeToAndCall' && name === 'ProxyAdmin') {
            result.parameters.newImplementation = decoded.args[0];
            result.parameters.data = decoded.args[1];
          } else if (decoded.functionName === 'changeAdmin' && name === 'ProxyAdmin') {
            result.parameters.newAdmin = decoded.args[0];
          } else if (decoded.functionName === 'permit' && name === 'ERC20') {
            // EIP-2612 gasless approval: owner/spender/value/deadline/v/r/s.
            // spender/value reuse the approval keys deliberately, so the
            // unverified-spender rule treats a gasless authorization to an
            // unknown party exactly like an on-chain one.
            result.parameters.owner = decoded.args[0];
            result.parameters.spender = decoded.args[1];
            result.parameters.value = decoded.args[2];
            result.parameters.deadline = decoded.args[3];
          } else if (decoded.functionName === 'approve' && name === 'Permit2') {
            // Capability 4 B6: expiration only. Named spender/amount
            // extraction stays suppressed (anti-mislabeling pin).
            result.parameters.args = decoded.args;
            result.parameters.expiration = decoded.args[3];
          } else if (decoded.functionName === 'permit' && name === 'Permit2') {
            result.parameters.args = decoded.args;
            const single = decoded.args[1];
            result.parameters.expiration = single && typeof single === 'object'
              ? (single.expiration !== undefined ? single.expiration : single[2])
              : undefined;
          } else if (decoded.functionName === 'swapExactTokensForTokens' && name === 'UniswapV2Router') {
            result.parameters.amountIn = decoded.args[0];
            result.parameters.amountOutMin = decoded.args[1];
            result.parameters.path = decoded.args[2];
            result.parameters.to = decoded.args[3];
            result.parameters.deadline = decoded.args[4];
          } else if (decoded.functionName === 'swapTokensForExactTokens' && name === 'UniswapV2Router') {
            result.parameters.amountOut = decoded.args[0];
            result.parameters.amountInMax = decoded.args[1];
            result.parameters.path = decoded.args[2];
            result.parameters.to = decoded.args[3];
            result.parameters.deadline = decoded.args[4];
          } else if (decoded.functionName === 'swapExactETHForTokens' && name === 'UniswapV2Router') {
            result.parameters.amountOutMin = decoded.args[0];
            result.parameters.path = decoded.args[1];
            result.parameters.to = decoded.args[2];
            result.parameters.deadline = decoded.args[3];
          } else {
            result.parameters.args = decoded.args;
          }
        }
        // Zero-argument privileged functions: viem omits `args` entirely
        // for them, so they never enter the extraction chain above. Their
        // parameters are fixed flags, not decoded values.
        if (!decoded.args) {
          if (decoded.functionName === 'renounceOwnership' && name === 'Ownable') {
            result.parameters.renounced = true;
          } else if ((decoded.functionName === 'pause' || decoded.functionName === 'unpause') && name === 'Pausable') {
            result.parameters.paused = decoded.functionName === 'pause';
          }
        }
        fullDecodeMatched = true;
        break;
      }
    } catch {
      // Continue searching next ABI
    }
  }

  // The selector identifies a known function even when trailing calldata words
  // are missing. Decode whichever complete fields are present for
  // exactInputSingle; anything else stays unknownFunction below.
  if (!fullDecodeMatched) {
    const matched = matchKnownSelector(data);
    if (matched && matched.item.name === 'exactInputSingle') {
      result.functionName = 'exactInputSingle';
      result.standard = matched.standard;
      result.parameters = decodeTruncatedExactInputSingle(data);
    }
  }

  // If function remains unparsed
  if (!result.functionName) {
    result.functionName = 'unknownFunction';
    result.standard = 'Unknown';
    result.parameters = { selector: data.slice(0, 10), dataLength: data.length };
  }

  // Selector ambiguity (ERC-20/ERC-721): approve and transferFrom share
  // selectors across standards (0x095ea7b3, 0x23b872dd), so first-match ABI
  // order attributes ERC20. That attribution is certain only when the
  // target is a known ERC-20 token; otherwise the standard is explicitly
  // ambiguous. Positional parameter values stay exact, but semantic labels
  // (amount vs token id) and threshold rules must not treat ERC20 as
  // confirmed. A threshold crossed on an unidentified standard is therefore
  // not a confirmed unlimited allowance (the ambiguous-scope rule below
  // preserves the alert honestly instead).
  if ((result.functionName === 'approve' || result.functionName === 'transferFrom')
      && result.standard === 'ERC20' && !knownToken) {
    result.standardAmbiguous = true;
    result.standardCandidates = ['ERC20', 'ERC721'];
    result.isUnlimitedApproval = false;
  }

  // Evaluate deterministic security rules. The sender is threaded through
  // (when the caller supplies it) so recipient-relative rules can compare.
  const rules = [
    evaluateInfiniteApproval(result),
    evaluateUnverifiedSpender(result),
    evaluatePermit2Drain(result),
    evaluateSwapRecipient({ ...result, sender: from }),
    evaluatePrivilegedOperation({ ...result, sender: from }),
    evaluateValueProtection(result)
  ].filter(Boolean);

  // Capability 4 B4: nested calls face the same rules as top-level
  // calls. Runs pre-serialization (inner amounts are still BigInt);
  // every inner finding carries subcall provenance. A harmless
  // top-level batch must not conceal a dangerous inner operation.
  if (result.parameters && Array.isArray(result.parameters.calls) && result.parameters.calls.length > 0) {
    try {
      const tree = buildSubcallTree(result);
      const inner = evaluateSubcallFindings(tree, { contract: result.contract, sender: from, chainId: normalizedChainId });
      for (const f of inner) rules.push(f);
    } catch {
      rules.push({
        ruleId: 'UNKNOWN_INNER_CALL',
        severity: 'MEDIUM',
        description: 'Nested-call analysis failed unexpectedly; inner behavior is uninterpretable.',
        triggered: true,
        metadata: { subcall: null, analysisError: true }
      });
    }
  }

  result.ruleFindings = rules;

  // Serialize BigInts before returning
  return serializeBigInt(result);
}

module.exports = { decodeTransactionCalldata, parseTransactionValue, DECODE_INVALID_VALUE, DECODE_INVALID_DATA };
