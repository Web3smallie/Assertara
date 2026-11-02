/**
 * Canonical ABI definitions for deterministic EVM transaction decoding
 */

const { parseAbi } = require('viem');

const ERC20_ABI = parseAbi([
  'function approve(address spender, uint256 amount) external returns (bool)',
  'function transfer(address recipient, uint256 amount) external returns (bool)',
  'function transferFrom(address sender, address recipient, uint256 amount) external returns (bool)',
  'function increaseAllowance(address spender, uint256 addedValue) external returns (bool)',
  'function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external'
]);

const ERC721_ABI = parseAbi([
  'function setApprovalForAll(address operator, bool approved) external',
  'function approve(address to, uint256 tokenId) external',
  'function safeTransferFrom(address from, address to, uint256 tokenId) external',
  'function transferFrom(address from, address to, uint256 tokenId) external'
]);

const WETH_ABI = parseAbi([
  'function deposit() external payable',
  'function withdraw(uint256 wad) external'
]);

const PERMIT2_ABI = parseAbi([
  'function approve(address token, address spender, uint160 amount, uint48 expiration) external',
  'function permit(address owner, (address token, uint160 amount, uint48 expiration, uint48 nonce) permitSingle, bytes signature) external'
]);

const UNISWAP_V3_ROUTER_ABI = parseAbi([
  'function exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96) params) external payable returns (uint256 amountOut)',
  'function multicall(bytes[] data) external payable returns (bytes[] results)'
]);

// Capability 5 B5: narrow bridge interfaces (single entrypoint each).
// Across V3 depositV3 signature corroborated against Across docs and the
// RPC-verified dedaub protocol reference (selector 0x7b939232).
// CCTP V1 depositForBurn corroborated against the same reference
// (selector 0x6fd3504e). Decoding is signature-exact.
const ACROSS_V3_ABI = parseAbi([
  'function depositV3(address depositor, address recipient, address inputToken, address outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, address exclusiveRelayer, uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityDeadline, bytes message) external payable'
]);

const CCTP_V1_ABI = parseAbi([
  'function depositForBurn(uint256 amount, uint32 destinationDomain, bytes32 mintRecipient, address burnToken) external returns (uint64 nonce)'
]);

// Capability 4 B2: privileged-operation interfaces (OpenZeppelin-shaped).
// Decoding is signature-exact: a same-named function with different
// parameter types has a different selector and never matches these.
const OWNABLE_ABI = parseAbi([
  'function transferOwnership(address newOwner) external',
  'function renounceOwnership() external'
]);

const ACCESS_CONTROL_ABI = parseAbi([
  'function grantRole(bytes32 role, address account) external',
  'function revokeRole(bytes32 role, address account) external',
  'function renounceRole(bytes32 role, address account) external'
]);

const PAUSABLE_ABI = parseAbi([
  'function pause() external',
  'function unpause() external'
]);

const PROXY_ADMIN_ABI = parseAbi([
  'function upgradeTo(address newImplementation) external',
  'function upgradeToAndCall(address newImplementation, bytes data) external payable',
  'function changeAdmin(address newAdmin) external'
]);

// Capability 4 B6: Uniswap V2-style swaps carry explicit deadlines
// (V3 exactInputSingle deliberately does not — absence there is by
// design, never "missing"). Path arrays decode as address lists.
const UNISWAP_V2_ROUTER_ABI = parseAbi([
  'function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline) external returns (uint256[] amounts)',
  'function swapTokensForExactTokens(uint256 amountOut, uint256 amountInMax, address[] path, address to, uint256 deadline) external returns (uint256[] amounts)',
  'function swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline) external payable returns (uint256[] amounts)'
]);

// Standard known token metadata. Capability 4 B5: every entry carries
// the chain IDs it is verified on (decimal strings). These five are
// Ethereum-mainnet deployments; entries for other chains must be added
// from verified sources — never by reusing these addresses elsewhere.
const KNOWN_TOKENS = {
  '0xdac17f958d2ee523a2206206994597c13d831ec7': { symbol: 'USDT', decimals: 6, name: 'Tether USD', chains: ['1'] },
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { symbol: 'USDC', decimals: 6, name: 'USD Coin', chains: ['1'] },
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': { symbol: 'WETH', decimals: 18, name: 'Wrapped Ether', chains: ['1'] },
  '0x6b175474e89094c44da98b954eedeac495271d0f': { symbol: 'DAI', decimals: 18, name: 'Dai Stablecoin', chains: ['1'] },
  '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984': { symbol: 'UNI', decimals: 18, name: 'Uniswap', chains: ['1'] }
};

// Known canonical routers (mainnet deployments; same chain rule as above).
const KNOWN_ROUTERS = {
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': { name: 'Uniswap V3 SwapRouter02', chains: ['1'] },
  '0xe592427a0aece92de3edee1f18e0157c05861564': { name: 'Uniswap V3 SwapRouter', chains: ['1'] },
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': { name: 'Uniswap V2 Router02', chains: ['1'] },
  '0x000000000022d473030f116ddee9f6b43ac78ba3': { name: 'Uniswap Permit2', chains: ['1'] },
  '0x1111111254fb6c44bac0bed2854e76f90643097d': { name: '1inch Aggregation Router V5', chains: ['1'] }
};

// Normalize a chain id to a decimal string (accepts 1, '1', '0x1').
// Returns null when unparseable.
function normalizeMapChainId(chainId) {
  try {
    if (chainId === undefined || chainId === null || chainId === '') return null;
    return BigInt(chainId).toString(10);
  } catch {
    return null;
  }
}

// Chain-scoped static-map lookup. The entry applies when the caller's
// chain is unknown (legacy unscoped callers keep working) or when it
// matches one of the entry's chains. A mainnet label never applies to
// another chain's address.
function matchKnownEntry(map, address, chainId) {
  if (!map || typeof address !== 'string') return null;
  const entry = map[address.toLowerCase()];
  if (!entry) return null;
  const want = normalizeMapChainId(chainId);
  if (want === null) return entry;
  const chains = Array.isArray(entry.chains) ? entry.chains : null;
  if (!chains) return entry;
  return chains.includes(want) ? entry : null;
}

// Chains an address is statically known on (for cross-chain notes).
function knownEntryChains(map, address) {
  if (!map || typeof address !== 'string') return [];
  const entry = map[address.toLowerCase()];
  return entry && Array.isArray(entry.chains) ? [...entry.chains] : [];
}

const MAX_UINT256 = (1n << 256n) - 1n;
const INFINITE_THRESHOLD = (1n << 255n);

module.exports = {
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
  matchKnownEntry,
  knownEntryChains
};
