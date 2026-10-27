const assert = require('assert');
const { encodeFunctionData, toFunctionSelector } = require('viem');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');
const { UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');

function runDecoderTests() {
  console.log('Testing EVM Calldata Decoder & Rules...\n');

  // Test 1: Infinite USDT Approval to Unverified Spender
  const usdtApprovalData = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  const decoded1 = decodeTransactionCalldata({
    to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    data: usdtApprovalData,
    value: '0x0'
  });

  assert.strictEqual(decoded1.functionName, 'approve', 'Should decode approve function');
  assert.strictEqual(decoded1.symbol, 'USDT', 'Should identify USDT');
  assert.strictEqual(decoded1.isUnlimitedApproval, true, 'Should flag unlimited approval');
  assert.ok(decoded1.ruleFindings.some(r => r.ruleId === 'INFINITE_APPROVAL'), 'Should trigger INFINITE_APPROVAL rule');
  assert.ok(decoded1.ruleFindings.some(r => r.ruleId === 'UNVERIFIED_SPENDER'), 'Should trigger UNVERIFIED_SPENDER rule');
  console.log('✔ Test 1 Passed: Infinite approval correctly decoded and flagged.');

  // Test 2: Standard ERC20 Transfer
  const transferData = '0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000000000005f5e100'; // 100 USDT (100 * 10^6)
  const decoded2 = decodeTransactionCalldata({
    to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    data: transferData,
    value: '0x0'
  });

  assert.strictEqual(decoded2.functionName, 'transfer', 'Should decode transfer function');
  assert.strictEqual(decoded2.parameters.amount, '100000000', 'Should extract exact amount');
  assert.strictEqual(decoded2.isUnlimitedApproval, false, 'Should not be unlimited');
  console.log('✔ Test 2 Passed: Standard transfer correctly decoded without false alarms.');

  // Test 3: NFT setApprovalForAll
  const nftApprovalData = '0xa22cb465000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b230000000000000000000000000000000000000000000000000000000000000001';
  const decoded3 = decodeTransactionCalldata({
    to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', // BAYC
    data: nftApprovalData
  });

  assert.strictEqual(decoded3.functionName, 'setApprovalForAll', 'Should decode setApprovalForAll');
  assert.ok(decoded3.ruleFindings.some(r => r.ruleId === 'NFT_SET_APPROVAL_FOR_ALL'), 'Should flag NFT_SET_APPROVAL_FOR_ALL');
  console.log('✔ Test 3 Passed: NFT setApprovalForAll correctly flagged.');

  // Test 4: SwapRouter02 exactInputSingle fixture (exact calldata from integration.test.js Scenario 2)
  const swapData = '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4';
  const decoded4 = decodeTransactionCalldata({
    to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Uniswap V3 SwapRouter02
    data: swapData,
    value: '0xde0b6b3a7640000' // 1 ETH
  });

  assert.strictEqual(decoded4.functionName, 'exactInputSingle', 'Should decode exactInputSingle, not unknownFunction');
  assert.strictEqual(decoded4.standard, 'UniswapV3Router', 'Should identify the Uniswap V3 router standard');
  assert.strictEqual(decoded4.contractName, 'Uniswap V3 SwapRouter02', 'Should identify SwapRouter02');
  assert.strictEqual(decoded4.parameters.tokenIn.toLowerCase(), '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', 'Should extract WETH tokenIn');
  assert.strictEqual(decoded4.parameters.tokenOut.toLowerCase(), '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', 'Should extract USDC tokenOut');
  assert.strictEqual(decoded4.parameters.fee, 500, 'Should extract the 500 (0.05%) fee tier');
  assert.ok(!('recipient' in decoded4.parameters), 'Must not invent fields beyond the calldata length');
  assert.ok(!('amountIn' in decoded4.parameters), 'Must not invent fields beyond the calldata length');
  assert.strictEqual(decoded4.isUnlimitedApproval, false, 'Swap must not flag unlimited approval');
  assert.deepStrictEqual(decoded4.ruleFindings, [], 'Legitimate swap must trigger no security rules');
  console.log('✔ Test 4 Passed: SwapRouter02 exactInputSingle fixture correctly decoded.');

  // Test 5: Corrected ABI yields the canonical selector and full calldata round-trips
  const exactInputSingleItem = UNISWAP_V3_ROUTER_ABI.find((i) => i.type === 'function' && i.name === 'exactInputSingle');
  assert.strictEqual(toFunctionSelector(exactInputSingleItem), '0x04e45aaf', 'ABI must yield the canonical SwapRouter02 selector');
  const fullSwapData = encodeFunctionData({
    abi: UNISWAP_V3_ROUTER_ABI,
    functionName: 'exactInputSingle',
    args: [{
      tokenIn: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
      tokenOut: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      fee: 500,
      recipient: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      amountIn: 1000000000000000000n,
      amountOutMinimum: 3400000000n,
      sqrtPriceLimitX96: 0n
    }]
  });
  const decoded5 = decodeTransactionCalldata({
    to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
    data: fullSwapData,
    value: '0xde0b6b3a7640000'
  });

  assert.strictEqual(decoded5.functionName, 'exactInputSingle', 'Should decode full exactInputSingle calldata');
  assert.strictEqual(decoded5.standard, 'UniswapV3Router', 'Should identify the Uniswap V3 router standard');
  assert.strictEqual(decoded5.parameters.tokenIn.toLowerCase(), '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', 'Should extract tokenIn by name');
  assert.strictEqual(decoded5.parameters.tokenOut.toLowerCase(), '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', 'Should extract tokenOut by name');
  assert.strictEqual(decoded5.parameters.fee, 500, 'Should extract fee by name');
  assert.strictEqual(decoded5.parameters.recipient.toLowerCase(), '0xd8da6bf26964af9d7eed9e03e53415d37aa96045', 'Should extract recipient by name');
  assert.strictEqual(decoded5.parameters.amountIn, '1000000000000000000', 'Should extract amountIn by name');
  assert.strictEqual(decoded5.parameters.amountOutMinimum, '3400000000', 'Should extract amountOutMinimum by name');
  assert.strictEqual(decoded5.parameters.sqrtPriceLimitX96, '0', 'Should extract sqrtPriceLimitX96 by name');
  assert.ok(!('deadline' in decoded5.parameters), 'SwapRouter02 params must not contain deadline');
  console.log('✔ Test 5 Passed: Full exactInputSingle calldata decodes to all seven named fields.');

  console.log('\nAll Decoder Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runDecoderTests();
}

module.exports = { runDecoderTests };
