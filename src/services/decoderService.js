/**
 * Deterministic EVM Calldata Decoder & Security Rule Engine
 */

const { decodeFunctionData, toFunctionSelector, getAddress } = require('viem');
const {
  ERC20_ABI,
  ERC721_ABI,
  WETH_ABI,
  PERMIT2_ABI,
  UNISWAP_V3_ROUTER_ABI,
  KNOWN_TOKENS,
  KNOWN_ROUTERS,
  MAX_UINT256,
  INFINITE_THRESHOLD
} = require('../utils/abiSignatures');

const { evaluateInfiniteApproval } = require('../rules/infiniteApproval');
const { evaluateUnverifiedSpender } = require('../rules/unverifiedSpender');
const { evaluatePermit2Drain } = require('../rules/permit2Drain');

const ALL_ABIS = [
  { name: 'ERC20', abi: ERC20_ABI },
  { name: 'ERC721', abi: ERC721_ABI },
  { name: 'WETH', abi: WETH_ABI },
  { name: 'Permit2', abi: PERMIT2_ABI },
  { name: 'UniswapV3Router', abi: UNISWAP_V3_ROUTER_ABI }
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

function decodeTransactionCalldata({ to, data, value = '0x0' }) {
  const targetAddress = (to || '').toLowerCase();
  const knownToken = KNOWN_TOKENS[targetAddress];
  const knownRouter = KNOWN_ROUTERS[targetAddress];

  const result = {
    contract: targetAddress,
    contractName: knownToken ? knownToken.name : (knownRouter || 'Unknown Contract'),
    symbol: knownToken ? knownToken.symbol : null,
    decimals: knownToken ? knownToken.decimals : null,
    valueEth: value === '0x0' || !value ? '0' : (BigInt(value) / 10n ** 18n).toString(),
    functionName: null,
    standard: null,
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

        // Extract parameters by name
        if (decoded.args) {
          if (decoded.functionName === 'approve' || decoded.functionName === 'increaseAllowance') {
            result.parameters.spender = decoded.args[0];
            result.parameters.amount = decoded.args[1];
            if (typeof decoded.args[1] === 'bigint' && decoded.args[1] >= INFINITE_THRESHOLD) {
              result.isUnlimitedApproval = true;
            }
          } else if (decoded.functionName === 'transfer') {
            result.parameters.recipient = decoded.args[0];
            result.parameters.amount = decoded.args[1];
          } else if (decoded.functionName === 'transferFrom') {
            result.parameters.sender = decoded.args[0];
            result.parameters.recipient = decoded.args[1];
            result.parameters.amount = decoded.args[2];
          } else if (decoded.functionName === 'setApprovalForAll') {
            result.parameters.operator = decoded.args[0];
            result.parameters.approved = decoded.args[1];
            result.isUnlimitedApproval = Boolean(decoded.args[1]);
          } else if (decoded.functionName === 'exactInputSingle') {
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
          } else {
            result.parameters.args = decoded.args;
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

  // Evaluate deterministic security rules
  const rules = [
    evaluateInfiniteApproval(result),
    evaluateUnverifiedSpender(result),
    evaluatePermit2Drain(result)
  ].filter(Boolean);

  result.ruleFindings = rules;

  // Serialize BigInts before returning
  return serializeBigInt(result);
}

module.exports = { decodeTransactionCalldata };
