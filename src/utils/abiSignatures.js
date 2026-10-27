/**
 * Canonical ABI definitions for deterministic EVM transaction decoding
 */

const { parseAbi } = require('viem');

const ERC20_ABI = parseAbi([
  'function approve(address spender, uint256 amount) external returns (bool)',
  'function transfer(address recipient, uint256 amount) external returns (bool)',
  'function transferFrom(address sender, address recipient, uint256 amount) external returns (bool)',
  'function increaseAllowance(address spender, uint256 addedValue) external returns (bool)'
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

// Standard known token metadata
const KNOWN_TOKENS = {
  '0xdac17f958d2ee523a2206206994597c13d831ec7': { symbol: 'USDT', decimals: 6, name: 'Tether USD' },
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { symbol: 'USDC', decimals: 6, name: 'USD Coin' },
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': { symbol: 'WETH', decimals: 18, name: 'Wrapped Ether' },
  '0x6b175474e89094c44da98b954eedeac495271d0f': { symbol: 'DAI', decimals: 18, name: 'Dai Stablecoin' },
  '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984': { symbol: 'UNI', decimals: 18, name: 'Uniswap' }
};

// Known canonical routers
const KNOWN_ROUTERS = {
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': 'Uniswap V3 SwapRouter02',
  '0xe592427a0aece92de3edee1f18e0157c05861564': 'Uniswap V3 SwapRouter',
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2 Router02',
  '0x000000000022d473030f116ddee9f6b43ac78ba3': 'Uniswap Permit2',
  '0x1111111254fb6c44bac0bed2854e76f90643097d': '1inch Aggregation Router V5'
};

const MAX_UINT256 = (1n << 256n) - 1n;
const INFINITE_THRESHOLD = (1n << 255n);

module.exports = {
  ERC20_ABI,
  ERC721_ABI,
  WETH_ABI,
  PERMIT2_ABI,
  UNISWAP_V3_ROUTER_ABI,
  KNOWN_TOKENS,
  KNOWN_ROUTERS,
  MAX_UINT256,
  INFINITE_THRESHOLD
};
