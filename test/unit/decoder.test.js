const assert = require('assert');
const { encodeFunctionData, toFunctionSelector } = require('viem');
const { decodeTransactionCalldata, DECODE_INVALID_VALUE, DECODE_INVALID_DATA } = require('../../src/services/decoderService');
const { ERC20_ABI, ERC721_ABI, WETH_ABI, PERMIT2_ABI, UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');

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
  // Capability 4 B3 contract change (spec-mandated): this fixture is a
  // TRUNCATED exactInputSingle — amountOutMinimum is absent from the
  // calldata, so no enforceable output floor can be established. That
  // must surface as MISSING_OUTPUT_PROTECTION, not a silent pass. The
  // "legitimate complete swap stays clean" case moved to Test 5 below.
  assert.ok(decoded4.ruleFindings.some(r => r.ruleId === 'MISSING_OUTPUT_PROTECTION'), 'Truncated swap with no minimum must flag MISSING_OUTPUT_PROTECTION');
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
  assert.ok(!decoded5.ruleFindings.some(r => r.ruleId === 'ZERO_MINIMUM_OUTPUT' || r.ruleId === 'MISSING_OUTPUT_PROTECTION'), 'Complete swap with a nonzero minimum triggers no value-protection rules');
  console.log('✔ Test 5 Passed: Full exactInputSingle calldata decodes to all seven named fields.');

  // Test 6: Transaction value precision — exact ETH decimals, raw wei kept.
  // Regression: integer wei/1e18 division silently floored 0.5 ETH to '0'.
  const valueOf = (value) => decodeTransactionCalldata({
    to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    data: transferData,
    ...(value === undefined ? {} : { value })
  });
  const precisionCases = [
    ['1 ETH keeps its representation', '0xde0b6b3a7640000', '1', '1000000000000000000'],
    ['0.5 ETH is exact', '0x6f05b59d3b20000', '0.5', '500000000000000000'],
    ['1 wei is exact', '0x1', '0.000000000000000001', '1'],
    ['1.5 ETH decimal input is exact', '1500000000000000000', '1.5', '1500000000000000000'],
    ['zero stays zero', '0x0', '0', '0'],
    ['empty value follows the zero contract', '', '0', '0'],
    ['large wei beyond 2^64 stays exact', '123456789012345678901234567890', '123456789012.34567890123456789', '123456789012345678901234567890']
  ];
  for (const [name, input, eth, wei] of precisionCases) {
    const decoded = valueOf(input);
    assert.strictEqual(decoded.valueEth, eth, `${name}: valueEth`);
    assert.strictEqual(decoded.valueWei, wei, `${name}: valueWei`);
  }
  const missing = valueOf(undefined);
  assert.strictEqual(missing.valueEth, '0', 'Missing value defaults to zero ETH');
  assert.strictEqual(missing.valueWei, '0', 'Missing value defaults to zero wei');
  const nativeHalf = decodeTransactionCalldata({
    to: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    data: '0x',
    value: '0x6f05b59d3b20000'
  });
  assert.strictEqual(nativeHalf.functionName, 'nativeTransfer');
  assert.strictEqual(nativeHalf.parameters.value, '0.5', 'Native transfer keeps the exact fractional value');
  console.log('✔ Test 6 Passed: Fractional ETH values decode exactly; whole ETH unchanged.');

  // Test 7: Malformed values throw a coded error, never an uncontrolled BigInt throw.
  for (const [name, bad] of [
    ['non-hex', '0xZZ'],
    ['fractional decimal', '1.5'],
    ['negative decimal', '-1'],
    ['negative hex', '-0x1'],
    ['plain text', 'abc'],
    ['boolean', true],
    ['fractional number', 1.5],
    ['unsafe integer number', 10 ** 18]
  ]) {
    assert.throws(
      () => valueOf(bad),
      (e) => e && e.code === DECODE_INVALID_VALUE,
      `${name} must throw ${DECODE_INVALID_VALUE}`
    );
  }
  console.log('✔ Test 7 Passed: Malformed values rejected with a structured code.');

  // Test 8 (Component 4): transferFrom named extraction, including an
  // amount beyond 2^64 that only exact BigInt handling preserves.
  const USER = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
  const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
  const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
  const tfData = encodeFunctionData({
    abi: ERC20_ABI, functionName: 'transferFrom',
    args: [USER, SPENDER, 123456789012345678901234567890n]
  });
  const decoded8 = decodeTransactionCalldata({ to: USDT, data: tfData, value: '0x0' });
  assert.strictEqual(decoded8.functionName, 'transferFrom');
  assert.strictEqual(decoded8.standard, 'ERC20');
  assert.strictEqual(decoded8.parameters.sender.toLowerCase(), USER.toLowerCase());
  assert.strictEqual(decoded8.parameters.recipient.toLowerCase(), SPENDER.toLowerCase());
  assert.strictEqual(decoded8.parameters.amount, '123456789012345678901234567890', 'Huge amounts stay exact');
  assert.strictEqual(decoded8.isUnlimitedApproval, false);
  console.log('✔ Test 8 Passed: transferFrom decodes with exact sender/recipient/amount.');

  // Test 9 (Component 4): increaseAllowance extraction + unlimited threshold.
  const smallAllow = encodeFunctionData({
    abi: ERC20_ABI, functionName: 'increaseAllowance', args: [SPENDER, 1000n]
  });
  const decoded9a = decodeTransactionCalldata({ to: USDT, data: smallAllow, value: '0x0' });
  assert.strictEqual(decoded9a.functionName, 'increaseAllowance');
  assert.strictEqual(decoded9a.parameters.spender.toLowerCase(), SPENDER.toLowerCase());
  assert.strictEqual(decoded9a.parameters.amount, '1000');
  assert.strictEqual(decoded9a.isUnlimitedApproval, false);
  assert.ok(!decoded9a.ruleFindings.some((r) => r.ruleId === 'INFINITE_APPROVAL'));
  const maxAllow = encodeFunctionData({
    abi: ERC20_ABI, functionName: 'increaseAllowance', args: [SPENDER, (1n << 256n) - 1n]
  });
  const decoded9b = decodeTransactionCalldata({ to: USDT, data: maxAllow, value: '0x0' });
  assert.strictEqual(decoded9b.isUnlimitedApproval, true);
  assert.ok(decoded9b.ruleFindings.some((r) => r.ruleId === 'INFINITE_APPROVAL'), 'Max allowance fires the rule');
  console.log('✔ Test 9 Passed: increaseAllowance decodes; max fires INFINITE_APPROVAL.');

  // Test 10 (Component 4): ERC-721 approve calldata. Its canonical signature
  // is identical to ERC-20 approve (selector 0x095ea7b3), so first-match ABI
  // order deterministically attributes it to ERC20. Pinned, not guessed:
  // selector alone cannot distinguish the two standards.
  const nftApproveData = encodeFunctionData({
    abi: ERC721_ABI, functionName: 'approve', args: [SPENDER, 1234n]
  });
  assert.strictEqual(nftApproveData.slice(0, 10), '0x095ea7b3', 'Collision precondition');
  const decoded10 = decodeTransactionCalldata({
    to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', data: nftApproveData
  });
  assert.strictEqual(decoded10.functionName, 'approve');
  assert.strictEqual(decoded10.standard, 'ERC20', 'First-match order wins the collision');
  assert.strictEqual(decoded10.parameters.spender.toLowerCase(), SPENDER.toLowerCase());
  assert.strictEqual(decoded10.parameters.amount, '1234', 'Token id rides the shared uint256 slot');
  console.log('✔ Test 10 Passed: ERC-721 approve collision resolves to ERC20 by order.');

  // Test 11 (Component 4): safeTransferFrom has a distinct selector and
  // decodes under the ERC721 standard with args preserved.
  const safeData = encodeFunctionData({
    abi: ERC721_ABI, functionName: 'safeTransferFrom', args: [USER, SPENDER, 1234n]
  });
  const decoded11 = decodeTransactionCalldata({
    to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', data: safeData
  });
  assert.strictEqual(decoded11.functionName, 'safeTransferFrom');
  assert.strictEqual(decoded11.standard, 'ERC721');
  assert.strictEqual(decoded11.parameters.args[0].toLowerCase(), USER.toLowerCase());
  assert.strictEqual(decoded11.parameters.args[1].toLowerCase(), SPENDER.toLowerCase());
  assert.strictEqual(decoded11.parameters.args[2], '1234');
  console.log('✔ Test 11 Passed: safeTransferFrom decodes with args preserved.');

  // Test 12 (Component 4): ERC-721 transferFrom collides with ERC-20
  // transferFrom (selector 0x23b872dd); first-match order attributes ERC20.
  const nftTfData = encodeFunctionData({
    abi: ERC721_ABI, functionName: 'transferFrom', args: [USER, SPENDER, 1234n]
  });
  assert.strictEqual(nftTfData.slice(0, 10), '0x23b872dd', 'Collision precondition');
  const decoded12 = decodeTransactionCalldata({
    to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', data: nftTfData
  });
  assert.strictEqual(decoded12.functionName, 'transferFrom');
  assert.strictEqual(decoded12.standard, 'ERC20', 'First-match order wins the collision');
  assert.strictEqual(decoded12.parameters.sender.toLowerCase(), USER.toLowerCase());
  console.log('✔ Test 12 Passed: ERC-721 transferFrom collision resolves to ERC20 by order.');

  // Test 13 (Component 4): WETH deposit (no args, payable value kept) and
  // withdraw (wad preserved in args).
  const depositData = encodeFunctionData({ abi: WETH_ABI, functionName: 'deposit' });
  const decoded13a = decodeTransactionCalldata({
    to: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', data: depositData, value: '0xde0b6b3a7640000'
  });
  assert.strictEqual(decoded13a.functionName, 'deposit');
  assert.strictEqual(decoded13a.standard, 'WETH');
  assert.strictEqual(decoded13a.symbol, 'WETH');
  assert.strictEqual(decoded13a.valueEth, '1', 'Payable value preserved');
  const withdrawData = encodeFunctionData({ abi: WETH_ABI, functionName: 'withdraw', args: [500000000000000000n] });
  const decoded13b = decodeTransactionCalldata({
    to: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', data: withdrawData, value: '0x0'
  });
  assert.strictEqual(decoded13b.functionName, 'withdraw');
  assert.strictEqual(decoded13b.parameters.args[0], '500000000000000000');
  console.log('✔ Test 13 Passed: WETH deposit/withdraw decode correctly.');

  // Test 14 (Component 4): Permit2 approve + permit. The permit rule fires
  // on the decoded function name — no decoder integration defect, the gap
  // was test coverage only.
  const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
  const p2ApproveData = encodeFunctionData({
    abi: PERMIT2_ABI, functionName: 'approve',
    args: [USDT, SPENDER, (1n << 160n) - 1n, 1893456000]
  });
  const decoded14a = decodeTransactionCalldata({ to: PERMIT2, data: p2ApproveData, value: '0x0' });
  assert.strictEqual(decoded14a.functionName, 'approve');
  assert.strictEqual(decoded14a.standard, 'Permit2', 'Distinct selector decodes under Permit2');
  assert.strictEqual(decoded14a.contractName, 'Uniswap Permit2');
  assert.strictEqual(decoded14a.parameters.args[0].toLowerCase(), USDT.toLowerCase());
  assert.strictEqual(decoded14a.parameters.args[1].toLowerCase(), SPENDER.toLowerCase());
  assert.strictEqual(decoded14a.parameters.args[2], '1461501637330902918203684832716283019655932542975', 'uint160 max exact');
  assert.ok(!('spender' in decoded14a.parameters), 'No ERC-20 slot mislabeling on Permit2 approve');
  assert.ok(!decoded14a.ruleFindings.some((r) => r.ruleId === 'UNVERIFIED_SPENDER'), 'Token must not pose as spender');
  const OWNER = '0x1111111254fb6c44bac0bed2854e76f90643097d';
  const permitData = encodeFunctionData({
    abi: PERMIT2_ABI, functionName: 'permit',
    args: [OWNER, { token: USDT, amount: 1000000n, expiration: 1893456000, nonce: 7 }, '0x1234']
  });
  const decoded14b = decodeTransactionCalldata({ to: PERMIT2, data: permitData, value: '0x0' });
  assert.strictEqual(decoded14b.functionName, 'permit');
  assert.strictEqual(decoded14b.standard, 'Permit2');
  assert.strictEqual(decoded14b.parameters.args[0].toLowerCase(), OWNER.toLowerCase());
  const permitRule = decoded14b.ruleFindings.find((r) => r.ruleId === 'PERMIT2_OFFCHAIN_APPROVAL');
  assert.ok(permitRule, 'Permit fires the Permit2 rule');
  assert.strictEqual(permitRule.severity, 'HIGH');
  console.log('✔ Test 14 Passed: Permit2 approve/permit decode; permit rule fires.');

  // Test 15 (Component 4): multicall inner calls decode one level. Known
  // inners resolve; unknown and truncated inners stay explicit
  // unknownFunction records with raw calldata preserved. Outer args kept.
  const innerApprove = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [SPENDER, 500n] });
  const innerTransfer = encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [USER, 42n] });
  const multiData = encodeFunctionData({
    abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
    args: [[innerApprove, innerTransfer, '0xdeadbeef', '0x1234']]
  });
  const decoded15 = decodeTransactionCalldata({
    to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data: multiData, value: '0x0'
  });
  assert.strictEqual(decoded15.functionName, 'multicall');
  assert.strictEqual(decoded15.standard, 'UniswapV3Router');
  assert.ok(Array.isArray(decoded15.parameters.args), 'Outer args preserved');
  const calls = decoded15.parameters.calls;
  assert.strictEqual(calls.length, 4);
  assert.strictEqual(calls[0].functionName, 'approve');
  assert.strictEqual(calls[0].standard, 'ERC20');
  assert.strictEqual(calls[0].selector, '0x095ea7b3');
  assert.strictEqual(calls[0].raw, innerApprove);
  assert.strictEqual(calls[1].functionName, 'transfer');
  assert.strictEqual(calls[1].args[1], '42');
  assert.strictEqual(calls[2].functionName, 'unknownFunction', 'Unknown inner stays unknown');
  assert.strictEqual(calls[2].selector, '0xdeadbeef');
  assert.strictEqual(calls[2].raw, '0xdeadbeef');
  assert.ok(!('args' in calls[2]), 'Unknown inner carries no invented args');
  assert.strictEqual(calls[3].functionName, 'unknownFunction', 'Truncated inner stays unknown');
  assert.strictEqual(calls[3].selector, null);
  assert.strictEqual(calls[3].raw, '0x1234');
  console.log('✔ Test 15 Passed: Multicall inners decode; unknown inners explicit.');

  // Test 16 (Component 4): malformed calldata stays safe. Truncated and
  // junk calldata decode unknown (never throw); non-string inputs throw the
  // coded DECODE_INVALID_DATA error; absent data keeps the native contract.
  const truncatedApprove = '0x095ea7b3' + '00'.repeat(20);
  const decoded16a = decodeTransactionCalldata({ to: USDT, data: truncatedApprove, value: '0x0' });
  assert.strictEqual(decoded16a.functionName, 'unknownFunction', 'Truncated non-swap stays unknown');
  assert.strictEqual(decoded16a.parameters.selector, '0x095ea7b3');
  assert.strictEqual(decoded16a.parameters.dataLength, truncatedApprove.length);
  const decoded16b = decodeTransactionCalldata({ to: USDT, data: '0xZZZZ', value: '0x0' });
  assert.strictEqual(decoded16b.functionName, 'unknownFunction', 'Junk hex stays unknown');
  for (const [name, bad] of [['numeric to', { to: 12345, data: '0x' }], ['null to', { to: null, data: '0x' }],
      ['numeric data', { to: USDT, data: 12345 }], ['object data', { to: USDT, data: {} }], ['boolean data', { to: USDT, data: true }]]) {
    assert.throws(() => decodeTransactionCalldata(bad),
      (e) => e && e.code === DECODE_INVALID_DATA, `${name} must throw ${DECODE_INVALID_DATA}`);
  }
  for (const [name, tx] of [['undefined data', { to: USER }], ['null data', { to: USER, data: null }], ['empty data', { to: USER, data: '0x' }]]) {
    assert.strictEqual(decodeTransactionCalldata(tx).functionName, 'nativeTransfer', `${name} keeps the native contract`);
  }
  console.log('✔ Test 16 Passed: Malformed calldata safe; bad types coded.');

  // Test 17 (Component 4): unknown selector decodes directly with its
  // selector, length, and raw calldata preserved for disclosure.
  const decoded17 = decodeTransactionCalldata({
    to: '0x1234567890123456789012345678901234567890', data: '0xdeadbeef', value: '0x0'
  });
  assert.strictEqual(decoded17.functionName, 'unknownFunction');
  assert.strictEqual(decoded17.standard, 'Unknown');
  assert.strictEqual(decoded17.contractName, 'Unknown Contract');
  assert.strictEqual(decoded17.parameters.selector, '0xdeadbeef');
  assert.strictEqual(decoded17.parameters.dataLength, 10);
  assert.strictEqual(decoded17.rawCalldata, '0xdeadbeef');
  assert.deepStrictEqual(decoded17.ruleFindings, []);
  console.log('✔ Test 17 Passed: Unknown selector recorded with evidence.');

  // Test 18 (Component 4): extreme parameter amounts stay exact strings;
  // max-uint approve metadata distinguishes 2^256-1 from merely large.
  const maxData = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [SPENDER, (1n << 256n) - 1n] });
  const decoded18 = decodeTransactionCalldata({ to: USDT, data: maxData, value: '0x0' });
  assert.strictEqual(decoded18.parameters.amount, '115792089237316195423570985008687907853269984665640564039457584007913129639935');
  const infRule = decoded18.ruleFindings.find((r) => r.ruleId === 'INFINITE_APPROVAL');
  assert.ok(infRule && infRule.metadata.isMaxUint === true, 'Max-uint metadata exact');
  console.log('✔ Test 18 Passed: Extreme amounts exact; max-uint flagged.');

  // Test 19 (Targeted): approve(max) on an unidentified contract is
  // explicitly ambiguous — never a confirmed unlimited allowance. The
  // alert survives as an honestly-worded ambiguous-scope finding.
  const UNKNOWN_TARGET = '0x1234567890123456789012345678901234567890';
  const ambMaxData = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [SPENDER, (1n << 256n) - 1n] });
  const decoded19 = decodeTransactionCalldata({ to: UNKNOWN_TARGET, data: ambMaxData, value: '0x0' });
  assert.strictEqual(decoded19.functionName, 'approve');
  assert.strictEqual(decoded19.standard, 'ERC20', 'First-match order kept as positional best effort');
  assert.strictEqual(decoded19.standardAmbiguous, true);
  assert.deepStrictEqual(decoded19.standardCandidates, ['ERC20', 'ERC721']);
  assert.strictEqual(decoded19.parameters.spender.toLowerCase(), SPENDER.toLowerCase(), 'Positional values stay exact');
  assert.strictEqual(decoded19.isUnlimitedApproval, false, 'Unconfirmed unlimited stays false');
  assert.ok(!decoded19.ruleFindings.some((r) => r.ruleId === 'INFINITE_APPROVAL'), 'No confirmed-unlimited claim');
  const ambRule = decoded19.ruleFindings.find((r) => r.ruleId === 'AMBIGUOUS_APPROVAL_SCOPE');
  assert.ok(ambRule, 'Ambiguous alert preserved');
  assert.strictEqual(ambRule.severity, 'MEDIUM');
  assert.deepStrictEqual(ambRule.metadata.standardCandidates, ['ERC20', 'ERC721']);
  console.log('✔ Test 19 Passed: Ambiguous approve(max) flagged honestly, never confirmed.');

  // Test 20 (Targeted): approve(max) on a known ERC-20 target is
  // unambiguous — existing INFINITE_APPROVAL behavior intact.
  const decoded20 = decodeTransactionCalldata({ to: USDT, data: ambMaxData, value: '0x0' });
  assert.strictEqual(decoded20.standardAmbiguous, false);
  assert.deepStrictEqual(decoded20.standardCandidates, []);
  assert.strictEqual(decoded20.isUnlimitedApproval, true);
  assert.ok(decoded20.ruleFindings.some((r) => r.ruleId === 'INFINITE_APPROVAL'));
  assert.ok(!decoded20.ruleFindings.some((r) => r.ruleId === 'AMBIGUOUS_APPROVAL_SCOPE'));
  console.log('✔ Test 20 Passed: Known-target approve(max) still confirms unlimited.');

  // Test 21 (Targeted): transferFrom on an unidentified contract is
  // ambiguous with positional values intact; on a known token it is not.
  const decoded21a = decodeTransactionCalldata({ to: UNKNOWN_TARGET, data: tfData, value: '0x0' });
  assert.strictEqual(decoded21a.standardAmbiguous, true);
  assert.deepStrictEqual(decoded21a.standardCandidates, ['ERC20', 'ERC721']);
  assert.strictEqual(decoded21a.parameters.amount, '123456789012345678901234567890');
  assert.strictEqual(decoded8.standardAmbiguous, false, 'Known-target transferFrom unambiguous');
  console.log('✔ Test 21 Passed: transferFrom ambiguity follows target knowledge.');

  // Test 22 (Targeted): functions with distinct selectors are never
  // flagged ambiguous, even on unidentified contracts.
  const p2Amb = decodeTransactionCalldata({ to: UNKNOWN_TARGET, data: p2ApproveData, value: '0x0' });
  assert.strictEqual(p2Amb.functionName, 'approve');
  assert.strictEqual(p2Amb.standard, 'Permit2');
  assert.strictEqual(p2Amb.standardAmbiguous, false, 'Distinct selector is unambiguous');
  const swapAmb = decodeTransactionCalldata({ to: UNKNOWN_TARGET, data: swapData, value: '0xde0b6b3a7640000' });
  assert.strictEqual(swapAmb.functionName, 'exactInputSingle');
  assert.strictEqual(swapAmb.standardAmbiguous, false);
  const nftAmb = decodeTransactionCalldata({ to: UNKNOWN_TARGET, data: nftApprovalData, value: '0x0' });
  assert.strictEqual(nftAmb.standardAmbiguous, false, 'setApprovalForAll is unambiguous');
  console.log('✔ Test 22 Passed: Distinct selectors never ambiguous.');

  // Test 23 (Targeted): nested multicall decodes recursively. Known inners
  // resolve at depth; unknown nested inners stay explicit with raw kept.
  const nestedInner = encodeFunctionData({
    abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [[innerTransfer, '0xdeadbeef']]
  });
  const nestedOuter = encodeFunctionData({
    abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [[innerApprove, nestedInner]]
  });
  const decoded23 = decodeTransactionCalldata({
    to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data: nestedOuter, value: '0x0'
  });
  assert.strictEqual(decoded23.functionName, 'multicall');
  const outer23 = decoded23.parameters.calls;
  assert.strictEqual(outer23.length, 2);
  assert.strictEqual(outer23[0].functionName, 'approve');
  assert.ok(!('calls' in outer23[0]), 'Non-multicall inners carry no calls array');
  assert.strictEqual(outer23[1].functionName, 'multicall');
  assert.strictEqual(outer23[1].standard, 'UniswapV3Router');
  assert.strictEqual(outer23[1].raw, nestedInner);
  assert.strictEqual(outer23[1].calls.length, 2);
  assert.strictEqual(outer23[1].calls[0].functionName, 'transfer');
  assert.strictEqual(outer23[1].calls[0].args[1], '42');
  assert.strictEqual(outer23[1].calls[1].functionName, 'unknownFunction');
  assert.strictEqual(outer23[1].calls[1].selector, '0xdeadbeef');
  assert.strictEqual(outer23[1].calls[1].raw, '0xdeadbeef');
  console.log('✔ Test 23 Passed: Nested multicall decodes; nested unknown explicit.');

  // Test 24 (Targeted): recursion-depth boundary + malformed nested
  // calldata. Seven wrappers identify five levels (four expanded, the fifth
  // cut off honestly with depthLimited); garbage nested entries never crash
  // the decode.
  const MULTI_SELECTOR = toFunctionSelector(UNISWAP_V3_ROUTER_ABI.find((i) => i.type === 'function' && i.name === 'multicall'));
  let layer = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [SPENDER, 1n] });
  const layers = [layer];
  for (let i = 0; i < 7; i++) {
    layer = encodeFunctionData({ abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [[layer]] });
    layers.push(layer);
  }
  const decoded24 = decodeTransactionCalldata({
    to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data: layers[7], value: '0x0'
  });
  let cursor = decoded24.parameters.calls;
  let depth = 0;
  while (cursor.length === 1 && cursor[0].functionName === 'multicall' && !cursor[0].depthLimited) {
    assert.strictEqual(cursor[0].selector, MULTI_SELECTOR);
    cursor = cursor[0].calls;
    depth += 1;
  }
  assert.strictEqual(depth, 4, 'Four expanded levels precede the boundary entry');
  assert.strictEqual(cursor.length, 1);
  assert.strictEqual(cursor[0].functionName, 'multicall', 'Boundary entry still identified');
  assert.strictEqual(cursor[0].depthLimited, true);
  assert.deepStrictEqual(cursor[0].calls, []);
  assert.strictEqual(cursor[0].raw, layers[2], 'Boundary raw preserved for inspection');
  const badNested = encodeFunctionData({
    abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
    args: [[encodeFunctionData({ abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [['0xdeadbeef', '0x12']] })]]
  });
  const decoded24b = decodeTransactionCalldata({
    to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', data: badNested, value: '0x0'
  });
  const nestedBad = decoded24b.parameters.calls[0].calls;
  assert.strictEqual(nestedBad[0].functionName, 'unknownFunction');
  assert.strictEqual(nestedBad[0].selector, '0xdeadbeef');
  assert.strictEqual(nestedBad[1].functionName, 'unknownFunction');
  assert.strictEqual(nestedBad[1].selector, null);
  assert.strictEqual(nestedBad[1].raw, '0x12');
  console.log('✔ Test 24 Passed: Depth boundary honest; malformed nested safe.');

  console.log('\nAll Decoder Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runDecoderTests();
}

module.exports = { runDecoderTests };
