// Phase A: deterministic UI-intent-to-transaction comparison utility.
// Pure unit tests: hand-built UI facts and decoder-shaped facts only.
const assert = require('assert');
const { compareIntentToTx } = require('../../src/utils/intentComparison');

const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const OTHER = '0x1111111254fb6c44bac0bed2854e76f90643097d';
const ALICE = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const MAX_UINT = '115792089237316195423570985008687907853269984665640564039457584007913129639935';

function region(regionId, text, opts = {}) {
  return {
    regionId,
    genuine: opts.genuine !== false,
    synthetic: opts.synthetic === true,
    ocr: opts.error
      ? { text: null, empty: false, error: opts.error }
      : { text, empty: text.length === 0, error: null }
  };
}

function claim(type, value, regionIds, opts = {}) {
  return {
    type,
    value,
    regionIds,
    associationIds: opts.associationIds || [],
    status: opts.status || 'supported',
    ...(opts.extra || {})
  };
}

function fieldOf(result, field) {
  return result.fields.find((f) => f.field === field);
}

// Observed association link in the Phase 1 shape: {linkId, kind, method,
// members:[{regionId, role}]}. Only same-region/containment action-amount
// and action-/amount-recipient links attribute display roles.
function link(linkId, kind, method, members) {
  return { linkId, kind, method, members: members.map(([regionId, role]) => ({ regionId, role })) };
}

function assoc(links, ambiguities = []) {
  return { links, ambiguities };
}

async function runIntentComparisonTests() {
  console.log('\n=== Running Intent Comparison Tests ===');

  // Test 1: exact wei-to-ETH equality on a native transfer with an
  // attributed transaction amount.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH now')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    const f = fieldOf(res, 'nativeValue');
    assert.strictEqual(f.status, 'MATCH');
    assert.strictEqual(f.uiValue, '1.0 ETH');
    assert.strictEqual(f.txValue, '1000000000000000000');
    assert.ok(f.evidenceRefs.includes('ocr:R-001') && f.evidenceRefs.includes('tx:valueWei'));
  }
  console.log('✔ Test 1 Passed: Exact wei-to-ETH equality.');

  // Test 2: native amount mismatch on a native transfer.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 2 ETH now')],
        claims: [claim('amount', '2 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'MISMATCH');
    assert.strictEqual(res.overall, 'MISMATCH');
    assert.strictEqual(res.summary.mismatch, 1);
  }
  console.log('✔ Test 2 Passed: Native amount mismatch.');

  // Test 3: decimal precision and very large amounts (no floats anywhere).
  {
    const payLink = assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])]);
    const million = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay total 1,000,000 ETH')],
        claims: [claim('amount', '1,000,000 ETH', ['R-001'])],
        associations: payLink
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000000000' }
    );
    assert.strictEqual(fieldOf(million, 'nativeValue').status, 'MATCH', 'million ETH with separators');
    const dust = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 0.000000000000000001 ETH')],
        claims: [claim('amount', '0.000000000000000001 ETH', ['R-001'])],
        associations: payLink
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1' }
    );
    assert.strictEqual(fieldOf(dust, 'nativeValue').status, 'MATCH', 'single-wei precision');
    const huge = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay amount 123456789012345678.0 ETH')],
        claims: [claim('amount', '123456789012345678.0 ETH', ['R-001'])],
        associations: payLink
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '123456789012345678000000000000000000' }
    );
    assert.strictEqual(fieldOf(huge, 'nativeValue').status, 'MATCH', 'beyond float precision');
  }
  console.log('✔ Test 3 Passed: Precision and huge amounts exact.');

  // Test 4: malformed numerics and over-precision stay inconclusive.
  {
    const payLink = assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])]);
    for (const bad of ['1.0.0 ETH', '1,00,0 ETH', '1e18 ETH', '-5 ETH', 'ETH']) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', `Pay ${bad} now`)],
          claims: [claim('amount', bad, ['R-001'])],
          associations: payLink
        },
        { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
      );
      assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE', bad);
    }
    const overPrecise = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0000001 USDC')],
        claims: [claim('amount', '1.0000001 USDC', ['R-001'])],
        associations: payLink
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: OTHER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(overPrecise, 'tokenAmount').status, 'INCONCLUSIVE', '7dp exceeds 6dp');
  }
  console.log('✔ Test 4 Passed: Malformed numerics rejected.');

  // Test 5: ERC-20 raw conversion with trusted decimals.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Send 3,450 USDC')],
        claims: [claim('amount', '3,450 USDC', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: OTHER, amount: '3450000000' }, valueWei: '0'
      }
    );
    const f = fieldOf(res, 'tokenAmount');
    assert.strictEqual(f.status, 'MATCH');
    assert.strictEqual(f.amountRole, 'transfer-amount');
    assert.ok(f.evidenceRefs.includes('tx:parameters.amount'));
  }
  console.log('✔ Test 5 Passed: ERC-20 conversion exact.');

  // Test 6: unknown decimals block comparison (never default 18).
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Send 3,450 USDC')],
        claims: [claim('amount', '3,450 USDC', ['R-001'])]
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: null,
        parameters: { recipient: OTHER, amount: '3450000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(res, 'tokenAmount').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 6 Passed: Unknown decimals inconclusive.');

  // Test 7: unknown token identity blocks comparison.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Send 100 TOKEN')],
        claims: [claim('amount', '100 TOKEN', ['R-001'])]
      },
      {
        contract: OTHER, functionName: 'transfer', standard: 'ERC20', symbol: null, decimals: null,
        parameters: { recipient: OTHER, amount: '100' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(res, 'tokenAmount').status, 'INCONCLUSIVE');
    assert.strictEqual(fieldOf(res, 'asset').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 7 Passed: Unknown token identity inconclusive.');

  // Test 8: full address equality despite casing.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', `Approve spender ${SPENDER}`)],
        claims: [claim('recipient', SPENDER.toUpperCase().replace('0X', '0x'), ['R-001'])],
        associations: assoc([link('L-001', 'action-recipient', 'same-region', [['R-001', 'action'], ['R-001', 'recipient']])])
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    const f = fieldOf(res, 'counterparty');
    assert.strictEqual(f.status, 'MATCH');
    assert.strictEqual(f.role, 'spender');
  }
  console.log('✔ Test 8 Passed: Address equality is case-insensitive.');

  // Test 9: different full addresses mismatch.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', `To ${OTHER}`)],
        claims: [claim('recipient', OTHER, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    const f = fieldOf(res, 'counterparty');
    assert.strictEqual(f.status, 'MISMATCH');
    assert.strictEqual(f.role, 'transfer-recipient');
    assert.strictEqual(res.overall, 'MISMATCH');
  }
  console.log('✔ Test 9 Passed: Different addresses mismatch.');

  // Test 10: truncated addresses never compare.
  {
    for (const short of ['0x942c…B31b23', '0x942c...B31b23', '0x942c733f', '942c733fa43900388424a1bf7f94d934b3531b23']) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', `To ${short}`)],
          claims: [claim('recipient', short, ['R-001'])]
        },
        {
          contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
          parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0'
        }
      );
      assert.strictEqual(fieldOf(res, 'counterparty').status, 'INCONCLUSIVE', short);
    }
  }
  console.log('✔ Test 10 Passed: Truncated addresses inconclusive.');

  // Test 11: spender versus transaction target stay separate.
  {
    const targetOnly = compareIntentToTx(
      {
        regions: [region('R-001', `Token ${USDC}`)],
        claims: [claim('recipient', USDC, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(targetOnly, 'counterparty').status, 'INCONCLUSIVE', 'target is not the spender');
    const both = compareIntentToTx(
      {
        regions: [region('R-001', `Token ${USDC}`), region('R-002', `Spender ${SPENDER}`)],
        claims: [claim('recipient', USDC, ['R-001']), claim('recipient', SPENDER, ['R-002'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(both, 'counterparty').status, 'MATCH', 'elimination attributes the spender');
  }
  console.log('✔ Test 11 Passed: Spender/target elimination sound.');

  // Test 12: exact allowance versus unlimited semantics.
  {
    const exact = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve 1.0 USDC')],
        claims: [claim('amount', '1.0 USDC', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, isUnlimitedApproval: false, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(exact, 'tokenAmount').status, 'MATCH');
    const unlimited = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve Unlimited spending')],
        claims: [claim('approval', 'Unlimited spending', ['R-001'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: MAX_UINT }, isUnlimitedApproval: true, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(unlimited, 'approvalScope').status, 'INCONCLUSIVE', 'wording != threshold');
    assert.strictEqual(fieldOf(unlimited, 'tokenAmount').status, 'INCONCLUSIVE', 'no numeric UI amount');
  }
  console.log('✔ Test 12 Passed: Allowance semantics preserved.');

  // Test 13: swap input and output stay separate.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'You pay 1.0 ETH'), region('R-002', 'You receive 3,450 USDC')],
        claims: [claim('amount', '1.0 ETH', ['R-001']), claim('amount', '3,450 USDC', ['R-002'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        symbol: null, decimals: null, valueWei: '1000000000000000000',
        parameters: { tokenIn: WETH, tokenOut: USDC, fee: 3000, recipient: OTHER, amountIn: '1000000000000000000', amountOutMinimum: '3400000000' },
        tokenMeta: { [WETH]: { symbol: 'WETH', decimals: 18 }, [USDC]: { symbol: 'USDC', decimals: 6 } }
      }
    );
    assert.strictEqual(fieldOf(res, 'tokenAmount').status, 'MATCH', 'ETH input attributed by symbol');
    assert.strictEqual(fieldOf(res, 'swapOutput').status, 'INCONCLUSIVE', 'output never directly compared');
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE', 'swap value defers to the input leg');
  }
  console.log('✔ Test 13 Passed: Swap legs separated.');

  // Test 14: output estimate is never equated with the minimum, even when
  // the numbers coincide.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'You receive 3,400 USDC')],
        claims: [claim('amount', '3,400 USDC', ['R-001'])]
      },
      {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        symbol: null, decimals: null, valueWei: '0',
        parameters: { tokenIn: WETH, tokenOut: USDC, fee: 3000, recipient: OTHER, amountIn: '1000000000000000000', amountOutMinimum: '3400000000' },
        tokenMeta: { [WETH]: { symbol: 'WETH', decimals: 18 }, [USDC]: { symbol: 'USDC', decimals: 6 } }
      }
    );
    assert.strictEqual(fieldOf(res, 'swapOutput').status, 'INCONCLUSIVE');
    assert.ok(fieldOf(res, 'swapOutput').reason.includes('estimates'));
  }
  console.log('✔ Test 14 Passed: Output estimate incomparable.');

  // Test 15: unknown selectors poison every operation comparison.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Swap 1.0 ETH'), region('R-002', `To ${OTHER}`)],
        claims: [claim('action', 'Swap', ['R-001']), claim('recipient', OTHER, ['R-002'])]
      },
      { contract: OTHER, functionName: 'unknownFunction', standard: 'Unknown', parameters: { selector: '0xdeadbeef' }, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(res, 'action').status, 'INCONCLUSIVE');
    assert.strictEqual(fieldOf(res, 'counterparty').status, 'INCONCLUSIVE');
    assert.strictEqual(res.overall, 'INCONCLUSIVE');
  }
  console.log('✔ Test 15 Passed: Unknown selectors inconclusive.');

  // Test 16: partial swap parameters cannot compare on missing legs.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'You pay 1.0 ETH'), region('R-002', `To ${OTHER}`)],
        claims: [claim('amount', '1.0 ETH', ['R-001']), claim('recipient', OTHER, ['R-002'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        symbol: null, decimals: null, valueWei: '0',
        parameters: { tokenIn: WETH, tokenOut: USDC },
        tokenMeta: { [WETH]: { symbol: 'WETH', decimals: 18 } }
      }
    );
    assert.strictEqual(fieldOf(res, 'tokenAmount').status, 'INCONCLUSIVE', 'amountIn absent');
    assert.ok(fieldOf(res, 'tokenAmount').reason.includes('missing or malformed'), 'fails on the tx side, not attribution');
    assert.strictEqual(fieldOf(res, 'counterparty').status, 'INCONCLUSIVE', 'recipient absent');
    assert.ok(fieldOf(res, 'counterparty').reason.includes('missing or invalid'), 'fails on the tx side, not attribution');
  }
  console.log('✔ Test 16 Passed: Partial params inconclusive.');

  // Test 17: multicall and Permit2 semantics stay inconclusive.
  {
    const multi = compareIntentToTx(
      {
        regions: [region('R-001', 'Swap tokens')],
        claims: [claim('action', 'Swap', ['R-001'])]
      },
      { contract: ROUTER, functionName: 'multicall', standard: 'UniswapV3Router', parameters: { args: [] }, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(multi, 'action').status, 'INCONCLUSIVE', 'inner calls undecodable');
    assert.strictEqual(fieldOf(multi, 'counterparty').status, 'INCONCLUSIVE');
    const permit = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve spending')],
        claims: [claim('action', 'Approve', ['R-001'])]
      },
      { contract: OTHER, functionName: 'permit', standard: 'Permit2', parameters: { args: [] }, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(permit, 'action').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 17 Passed: Multicall/Permit2 inconclusive.');

  // Test 18: missing visual evidence yields no match anywhere.
  {
    const res = compareIntentToTx(
      { regions: [], claims: [] },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.ok(res.fields.every((f) => f.status === 'INCONCLUSIVE'));
    assert.strictEqual(res.overall, 'INCONCLUSIVE');
    assert.strictEqual(res.summary.match, 0);
    assert.strictEqual(res.summary.mismatch, 0);
  }
  console.log('✔ Test 18 Passed: Missing evidence never matches.');

  // Test 19: failed and empty OCR cannot corroborate.
  {
    const failed = compareIntentToTx(
      {
        regions: [region('R-001', '', { error: { code: 'OCR_FAILED', message: 'boom' } })],
        claims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [], status: 'supported' }]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(failed, 'nativeValue').status, 'INCONCLUSIVE', 'failed OCR');
    const empty = compareIntentToTx(
      {
        regions: [region('R-001', '')],
        claims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [], status: 'supported' }]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(empty, 'nativeValue').status, 'INCONCLUSIVE', 'empty OCR');
  }
  console.log('✔ Test 19 Passed: Failed/empty OCR unusable.');

  // Test 20: synthetic fallback text can never corroborate.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-FALLBACK', 'Pay 1.0 ETH', { genuine: false, synthetic: true })],
        claims: [claim('amount', '1.0 ETH', ['R-FALLBACK'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 20 Passed: Synthetic evidence unusable.');

  // Test 21: invalid region references cannot corroborate.
  {
    for (const ids of [['R-999'], [null], ['R-001', 'R-999']]) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', 'Pay 1.0 ETH')],
          claims: [{ type: 'amount', value: '1.0 ETH', regionIds: ids, associationIds: [], status: 'supported' }]
        },
        { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '1000000000000000000' }
      );
      assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE', JSON.stringify(ids));
    }
  }
  console.log('✔ Test 21 Passed: Bad region refs unusable.');

  // Test 22: a 'supported' claim whose value conflicts with its OCR is dead.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [claim('amount', '5.0 ETH', ['R-001'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '5000000000000000000' }
    );
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE', 'value contradicts cited OCR');
  }
  console.log('✔ Test 22 Passed: Conflicting claim value rejected.');

  // Test 23: claims resting on unresolved ambiguities are unusable.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'], { associationIds: ['AMB-001'] })],
        associations: { links: [], ambiguities: [{ ambiguityId: 'AMB-001' }] }
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 23 Passed: Ambiguity-backed claims unusable.');

  // Test 24: model prose absent from cited OCR corroborates nothing.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Confirm swap')],
        claims: [claim('action', 'Send all funds to attacker', ['R-001'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(res, 'action').status, 'INCONCLUSIVE');
    assert.ok(fieldOf(res, 'action').reason.includes('no corroborated UI action'));
  }
  console.log('✔ Test 24 Passed: Uncorroborated prose rejected.');

  // Test 25: missing refs and forged evidence fields are rejected.
  {
    const noRefs = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', [])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(noRefs, 'nativeValue').status, 'INCONCLUSIVE', 'empty regionIds');
    const forged = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'], { extra: { observedText: 'Pay 1.0 ETH' } })]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(forged, 'nativeValue').status, 'INCONCLUSIVE', 'model-supplied text key');
    const forgedGeom = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'], { extra: { boundingBox: { x: 0, y: 0, width: 1, height: 1 } } })]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(forgedGeom, 'nativeValue').status, 'INCONCLUSIVE', 'model-supplied geometry key');
  }
  console.log('✔ Test 25 Passed: Missing/forged refs rejected.');

  // Test 26: safe action mappings only.
  {
    const cases = [
      ['Swap tokens', 'exactInputSingle', 'MATCH'],
      ['Send funds', 'transfer', 'MATCH'],
      ['Mint an NFT', 'mint', 'INCONCLUSIVE'],
      ['Claim reward', 'claim', 'INCONCLUSIVE']
    ];
    for (const [verb, fn, expected] of cases) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', verb)],
          claims: [claim('action', verb.split(' ')[0], ['R-001'])]
        },
        { contract: OTHER, functionName: fn, standard: 'ERC20', parameters: {}, valueWei: '0' }
      );
      assert.strictEqual(fieldOf(res, 'action').status, expected, verb);
    }
    // Approval verbs compare only with argument context (spender here).
    {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', 'Approve spending'), region('R-002', `Spender ${SPENDER}`)],
          claims: [claim('action', 'Approve', ['R-001']), claim('recipient', SPENDER, ['R-002'])]
        },
        { contract: USDC, functionName: 'approve', standard: 'ERC20', parameters: {}, valueWei: '0' }
      );
      assert.strictEqual(fieldOf(res, 'action').status, 'MATCH', 'Approve spending with spender');
    }
    const conflict = compareIntentToTx(
      {
        regions: [region('R-001', 'Swap'), region('R-002', 'Approve')],
        claims: [claim('action', 'Swap', ['R-001']), claim('action', 'Approve', ['R-002'])]
      },
      { contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router', parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(conflict, 'action').status, 'INCONCLUSIVE', 'conflicting verbs');
  }
  console.log('✔ Test 26 Passed: Action mapping conservative.');

  // Test 27: warning absence with incomplete evidence proves nothing.
  {
    const silent = compareIntentToTx(
      { regions: [], claims: [] },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', parameters: {}, valueWei: '0',
        ruleFindings: [{ ruleId: 'INFINITE_APPROVAL', severity: 'HIGH' }]
      }
    );
    assert.strictEqual(fieldOf(silent, 'warning').status, 'INCONCLUSIVE');
    const shown = compareIntentToTx(
      {
        regions: [region('R-001', 'Warning: risky')],
        claims: [claim('warning', 'Warning: risky', ['R-001'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', parameters: {}, valueWei: '0',
        ruleFindings: [{ ruleId: 'INFINITE_APPROVAL', severity: 'HIGH' }]
      }
    );
    assert.strictEqual(fieldOf(shown, 'warning').status, 'INCONCLUSIVE', 'relevance unverifiable');
    const quiet = compareIntentToTx(
      { regions: [], claims: [] },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '0', ruleFindings: [] }
    );
    assert.strictEqual(fieldOf(quiet, 'warning').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 27 Passed: Warnings stay inconclusive.');

  // Test 28: identical inputs yield identical outputs.
  {
    const ui = {
      regions: [region('R-001', 'Pay 1.0 ETH now'), region('R-002', `To ${OTHER}`)],
      claims: [claim('amount', '1.0 ETH', ['R-001']), claim('recipient', OTHER, ['R-002'])],
      associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
    };
    const tx = {
      contract: OTHER, functionName: 'nativeTransfer', standard: 'Native',
      parameters: {}, valueWei: '1000000000000000000'
    };
    const a = compareIntentToTx(JSON.parse(JSON.stringify(ui)), JSON.parse(JSON.stringify(tx)));
    const b = compareIntentToTx(JSON.parse(JSON.stringify(ui)), JSON.parse(JSON.stringify(tx)));
    assert.deepStrictEqual(a, b);
    assert.strictEqual(fieldOf(a, 'nativeValue').status, 'MATCH');
    assert.strictEqual(fieldOf(a, 'counterparty').status, 'MATCH');
  }
  console.log('✔ Test 28 Passed: Output deterministic.');

  // Test 29: fiat and bare numbers are never attributed to crypto fields.
  {
    const fiat = compareIntentToTx(
      {
        regions: [region('R-001', 'Total $100')],
        claims: [claim('amount', '$100', ['R-001'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '100' }
    );
    assert.strictEqual(fieldOf(fiat, 'nativeValue').status, 'INCONCLUSIVE', 'fiat ignored');
    const bare = compareIntentToTx(
      {
        regions: [region('R-001', 'Count 100')],
        claims: [claim('amount', '100', ['R-001'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '100' }
    );
    assert.strictEqual(fieldOf(bare, 'nativeValue').status, 'INCONCLUSIVE', 'asset never inferred');
  }
  console.log('✔ Test 29 Passed: Fiat/bare numbers unattributed.');

  // Test 30: ETH/WETH display aliasing is explicit and bounded.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 WETH')],
        claims: [claim('amount', '1.0 WETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'MATCH', 'documented alias only');
  }
  console.log('✔ Test 30 Passed: ETH/WETH alias bounded.');

  // Test 31: target identity and ENS names stay inconclusive.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Send to vitalik.eth')],
        claims: [claim('recipient', 'vitalik.eth', ['R-001'])]
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(res, 'target').status, 'INCONCLUSIVE');
    assert.strictEqual(fieldOf(res, 'counterparty').status, 'INCONCLUSIVE', 'no ENS resolver');
  }
  console.log('✔ Test 31 Passed: Target/ENS inconclusive.');

  // Test 32: malformed top-level inputs throw; malformed internals degrade.
  {
    assert.throws(() => compareIntentToTx(null, {}), TypeError);
    assert.throws(() => compareIntentToTx({}, null), TypeError);
    assert.throws(() => compareIntentToTx([], {}), TypeError);
    const degraded = compareIntentToTx(
      { regions: null, claims: 'nope' },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: 'nope', valueWei: '0' }
    );
    assert.ok(degraded.fields.every((f) => f.status === 'INCONCLUSIVE'));
  }
  console.log('✔ Test 32 Passed: Input validation sound.');

  // Test 33 (Fix 1): boundary-aware corroboration rejects substring
  // impostors but keeps genuine matches.
  {
    const tx = { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' };
    const payLink = assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])]);
    const sub = compareIntentToTx(
      {
        regions: [region('R-001', 'Balance: 21 ETH')],
        claims: [claim('amount', '1 ETH', ['R-001'])],
        associations: payLink
      },
      tx
    );
    assert.strictEqual(fieldOf(sub, 'nativeValue').status, 'INCONCLUSIVE', '1 ETH is not 21 ETH');
    const senderLabel = compareIntentToTx(
      {
        regions: [region('R-001', 'Sender: Alice')],
        claims: [claim('action', 'Send', ['R-001'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(senderLabel, 'action').status, 'INCONCLUSIVE', 'Send is not Sender');
    const tether = compareIntentToTx(
      {
        regions: [region('R-001', 'Tether USD balance')],
        claims: [claim('asset', 'ETH', ['R-001'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6, parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(tether, 'asset').status, 'INCONCLUSIVE', 'ETH is not Tether');
    // Positive controls: exact bounded values still corroborate.
    const exact = compareIntentToTx(
      {
        regions: [region('R-001', 'Confirmed: pay 1.0 ETH.')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: payLink
      },
      tx
    );
    assert.strictEqual(fieldOf(exact, 'nativeValue').status, 'MATCH', 'punctuation-tolerant exact match');
    const verb = compareIntentToTx(
      {
        regions: [region('R-001', 'Send 1.0 ETH')],
        claims: [claim('action', 'Send', ['R-001'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(verb, 'action').status, 'MATCH', 'standalone verb matches');
  }
  console.log('✔ Test 33 Passed: Boundary corroboration sound.');

  // Test 34 (Fix 2): a WETH transfer amount never becomes a native value.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Send 1.0 WETH')],
        claims: [claim('amount', '1.0 WETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      {
        contract: WETH, functionName: 'transfer', standard: 'ERC20', symbol: 'WETH', decimals: 18,
        parameters: { recipient: SPENDER, amount: '1000000000000000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(res, 'tokenAmount').status, 'MATCH');
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE');
    assert.ok(fieldOf(res, 'nativeValue').reason.includes('tokenAmount'));
  }
  console.log('✔ Test 34 Passed: WETH transfer not native value.');

  // Test 35 (Fix 2): a withdrawal display is never msg.value.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Withdraw 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: WETH, functionName: 'withdraw', standard: 'WETH', parameters: { args: [] }, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE');
    assert.ok(fieldOf(res, 'nativeValue').reason.includes('not msg.value'));
  }
  console.log('✔ Test 35 Passed: Withdrawal not native value.');

  // Test 36 (Fix 5): a fee-only display never becomes the transaction amount.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Network fee 0.001 ETH')],
        claims: [claim('amount', '0.001 ETH', ['R-001'])]
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE');
    assert.ok(fieldOf(res, 'nativeValue').reason.includes('excluded display role'));
  }
  console.log('✔ Test 36 Passed: Fee-only display unattributed.');

  // Test 37 (Fix 5): balance-only and quote-only amounts stay unattributed,
  // and weak proximity links do not attribute.
  {
    const balance = compareIntentToTx(
      {
        regions: [region('R-001', 'Balance: 21 ETH')],
        claims: [claim('amount', '21 ETH', ['R-001'])]
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '21000000000000000000' }
    );
    assert.strictEqual(fieldOf(balance, 'nativeValue').status, 'INCONCLUSIVE', 'balance is not the tx amount');
    const quote = compareIntentToTx(
      {
        regions: [region('R-001', 'Estimated output 3,450 USDC'), region('R-002', 'Pay 1.0 ETH')],
        claims: [claim('amount', '3,450 USDC', ['R-001']), claim('amount', '1.0 ETH', ['R-002'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-002', 'action'], ['R-002', 'amount']])])
      },
      {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        symbol: null, decimals: null, valueWei: '1000000000000000000',
        parameters: { tokenIn: WETH, tokenOut: USDC, recipient: SPENDER, amountIn: '1000000000000000000', amountOutMinimum: '3400000000' },
        tokenMeta: { [WETH]: { symbol: 'WETH', decimals: 18 }, [USDC]: { symbol: 'USDC', decimals: 6 } }
      }
    );
    assert.strictEqual(fieldOf(quote, 'tokenAmount').status, 'MATCH', 'pay leg attributed');
    const weak = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay now'), region('R-002', '1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-002'])],
        associations: assoc([link('L-001', 'action-amount', 'proximity', [['R-001', 'action'], ['R-002', 'amount']])])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(weak, 'nativeValue').status, 'INCONCLUSIVE', 'proximity is adjacency, not attribution');
  }
  console.log('✔ Test 37 Passed: Balance/quote/proximity unattributed.');

  // Test 38 (Fixes 2+5): native and deposit amounts with genuine
  // attribution compare; unattributed ones do not.
  {
    const attributed = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'containment', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(attributed, 'nativeValue').status, 'MATCH', 'containment attributes');
    const bare = compareIntentToTx(
      {
        regions: [region('R-001', '1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])]
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(bare, 'nativeValue').status, 'INCONCLUSIVE', 'lone number proves nothing');
    const deposit = compareIntentToTx(
      {
        regions: [region('R-001', 'Deposit 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: WETH, functionName: 'deposit', standard: 'WETH', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(deposit, 'nativeValue').status, 'MATCH', 'deposit value is operative');
    const depositBare = compareIntentToTx(
      {
        regions: [region('R-001', '1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])]
      },
      { contract: WETH, functionName: 'deposit', standard: 'WETH', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(depositBare, 'nativeValue').status, 'INCONCLUSIVE', 'unattributed deposit amount');
  }
  console.log('✔ Test 38 Passed: Attributed native/deposit amounts compare.');

  // Test 39 (Fix 3): sender-only displays are never counterparties.
  {
    const senderOnly = compareIntentToTx(
      {
        regions: [region('R-001', `From ${ALICE}`)],
        claims: [claim('recipient', ALICE, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0', sender: ALICE
      }
    );
    assert.strictEqual(fieldOf(senderOnly, 'counterparty').status, 'INCONCLUSIVE', 'sender eliminated');
    // Same display without a known sender: the source label still excludes it.
    const unlabeled = compareIntentToTx(
      {
        regions: [region('R-001', `From ${ALICE}`)],
        claims: [claim('recipient', ALICE, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(unlabeled, 'counterparty').status, 'INCONCLUSIVE', 'source label excludes');
    // Positive control: a destination-labeled spender still compares.
    const destLabeled = compareIntentToTx(
      {
        regions: [region('R-001', `Spender ${SPENDER}`)],
        claims: [claim('recipient', SPENDER, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0', sender: ALICE
      }
    );
    assert.strictEqual(fieldOf(destLabeled, 'counterparty').status, 'MATCH');
  }
  console.log('✔ Test 39 Passed: Sender displays excluded.');

  // Test 40 (Fix 3): transferFrom source and destination stay separate.
  {
    const sourceOnly = compareIntentToTx(
      {
        regions: [region('R-001', `From ${ALICE}`)],
        claims: [claim('recipient', ALICE, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'transferFrom', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { sender: ALICE, recipient: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(sourceOnly, 'counterparty').status, 'INCONCLUSIVE', 'source is not the destination');
    const destShown = compareIntentToTx(
      {
        regions: [region('R-001', `To ${SPENDER}`)],
        claims: [claim('recipient', SPENDER, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'transferFrom', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { sender: ALICE, recipient: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(destShown, 'counterparty').status, 'MATCH');
    assert.strictEqual(fieldOf(destShown, 'counterparty').role, 'transfer-recipient');
  }
  console.log('✔ Test 40 Passed: Source/destination separated.');

  // Test 41 (Fix 3): self-directed flows, multiple addresses, and role
  // collisions never produce a counterparty match.
  {
    const selfApprove = compareIntentToTx(
      {
        regions: [region('R-001', `Spender ${ALICE}`)],
        claims: [claim('recipient', ALICE, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: ALICE, amount: '1000000' }, valueWei: '0', sender: ALICE
      }
    );
    assert.strictEqual(fieldOf(selfApprove, 'counterparty').status, 'INCONCLUSIVE', 'sender==spender collision');
    const multi = compareIntentToTx(
      {
        regions: [region('R-001', `To ${SPENDER}`), region('R-002', `To ${OTHER}`)],
        claims: [claim('recipient', SPENDER, ['R-001']), claim('recipient', OTHER, ['R-002'])]
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(multi, 'counterparty').status, 'INCONCLUSIVE', 'two destinations ambiguous');
    assert.ok(fieldOf(multi, 'counterparty').evidenceRefs.includes('ocr:R-001'));
    assert.ok(fieldOf(multi, 'counterparty').evidenceRefs.includes('ocr:R-002'));
    const unattributed = compareIntentToTx(
      {
        regions: [region('R-001', `Contact ${SPENDER} for support`)],
        claims: [claim('recipient', SPENDER, ['R-001'])]
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(unattributed, 'counterparty').status, 'INCONCLUSIVE', 'support address unattributed');
    assert.ok(fieldOf(unattributed, 'counterparty').reason.includes('no attributable'));
  }
  console.log('✔ Test 41 Passed: Collisions stay inconclusive.');

  // Test 42 (Fix 4): fiat labels are never crypto-asset conflicts.
  {
    for (const fiat of ['$', 'USD', 'EUR']) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', `Total ${fiat} 100`)],
          claims: [claim('asset', fiat, ['R-001'])]
        },
        {
          contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
          parameters: { recipient: SPENDER, amount: '100000000' }, valueWei: '0'
        }
      );
      assert.strictEqual(fieldOf(res, 'asset').status, 'INCONCLUSIVE', fiat);
    }
    // Positive controls: genuine crypto symbols still compare.
    const match = compareIntentToTx(
      {
        regions: [region('R-001', 'Send USDC')],
        claims: [claim('asset', 'USDC', ['R-001'])]
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '100000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(match, 'asset').status, 'MATCH');
    const conflict = compareIntentToTx(
      {
        regions: [region('R-001', 'Send DAI')],
        claims: [claim('asset', 'DAI', ['R-001'])]
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '100000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(conflict, 'asset').status, 'MISMATCH', 'genuine token conflict still detected');
  }
  console.log('✔ Test 42 Passed: Fiat never conflicts.');

  // Test 43 (Fix 6): ambiguous INCONCLUSIVE results preserve every
  // candidate's evidence references.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH'), region('R-002', 'Pay 2.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001']), claim('amount', '2.0 ETH', ['R-002'])],
        associations: assoc([
          link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']]),
          link('L-002', 'action-amount', 'same-region', [['R-002', 'action'], ['R-002', 'amount']])
        ])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    const f = fieldOf(res, 'nativeValue');
    assert.strictEqual(f.status, 'INCONCLUSIVE');
    assert.ok(f.evidenceRefs.includes('claim#0') && f.evidenceRefs.includes('claim#1'));
    assert.ok(f.evidenceRefs.includes('ocr:R-001') && f.evidenceRefs.includes('ocr:R-002'));
  }
  console.log('✔ Test 43 Passed: Ambiguity preserves refs.');

  // Test 44 (Fix 6): malformed associationIds and non-supported statuses
  // cannot corroborate.
  {
    for (const badIds of ['AMB-001', 42, { id: 'AMB-001' }]) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', 'Pay 1.0 ETH')],
          claims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: badIds, status: 'supported' }],
          associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
        },
        { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
      );
      assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE', JSON.stringify(badIds));
    }
    for (const status of ['invalid', 'unsupported', 'ambiguous', 'not-evaluated', null]) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', 'Pay 1.0 ETH')],
          claims: [{ type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [], status }]
        },
        { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
      );
      assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE', String(status));
    }
  }
  console.log('✔ Test 44 Passed: Malformed claims rejected.');

  // Test 45 (Fix 6): missing decoder fields, absurd metadata, and exotic
  // values degrade safely without throwing.
  {
    const missing = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native' }
    );
    assert.strictEqual(fieldOf(missing, 'nativeValue').status, 'INCONCLUSIVE', 'valueWei absent');
    assert.ok(fieldOf(missing, 'nativeValue').reason.includes('missing or malformed'));
    const absurdMeta = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        parameters: { tokenIn: WETH, amountIn: '1000000000000000000' }, valueWei: '0',
        tokenMeta: { [WETH]: { symbol: 'WETH', decimals: 101 } }
      }
    );
    assert.strictEqual(fieldOf(absurdMeta, 'tokenAmount').status, 'INCONCLUSIVE', 'decimals over cap');
    const exotic = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 1.0 ETH')],
        claims: [
          { type: 'amount', value: '1.0 ETH', regionIds: [Symbol('x')], associationIds: [], status: 'supported' },
          { type: 'amount', value: '1.0 ETH', regionIds: ['R-001'], associationIds: [], status: Symbol('y') }
        ]
      },
      { contract: OTHER, functionName: Symbol('z'), standard: 'Native', parameters: {}, valueWei: '0' }
    );
    assert.ok(exotic.fields.every((f) => f.status === 'INCONCLUSIVE'), 'symbols never throw, never match');
    const giant = compareIntentToTx(
      {
        regions: [region('R-001', `Pay ${'1'.repeat(3000)} ETH`)],
        claims: [claim('amount', `${'1'.repeat(3000)} ETH`, ['R-001'])]
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(giant, 'nativeValue').status, 'INCONCLUSIVE', 'overlong values unusable');
  }
  console.log('✔ Test 45 Passed: Malformed input degrades safely.');

  // Test 46: identical logical inputs in different property orders agree.
  {
    const uiA = {
      regions: [region('R-001', 'Pay 1.0 ETH now')],
      claims: [claim('amount', '1.0 ETH', ['R-001'])],
      associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
    };
    const uiB = {
      associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])]),
      claims: [claim('amount', '1.0 ETH', ['R-001'])],
      regions: [region('R-001', 'Pay 1.0 ETH now')]
    };
    const txA = { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' };
    const txB = { valueWei: '1000000000000000000', parameters: {}, standard: 'Native', functionName: 'nativeTransfer', contract: OTHER };
    assert.deepStrictEqual(compareIntentToTx(uiA, txA), compareIntentToTx(uiB, txB));
  }
  console.log('✔ Test 46 Passed: Property order irrelevant.');

  // Test 47 (Fix 1): payment and fee in the same dialog, same symbol. The
  // fee is excluded even with a containment link; only the payment compares.
  {
    const ui = {
      regions: [
        region('R-000', 'Confirm swap details'),
        region('R-001', 'Pay 1.0 ETH'),
        region('R-002', 'Network fee 0.01 ETH')
      ],
      claims: [claim('amount', '1.0 ETH', ['R-001']), claim('amount', '0.01 ETH', ['R-002'])],
      associations: assoc([
        link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']]),
        link('L-002', 'action-amount', 'containment', [['R-000', 'action'], ['R-002', 'amount']])
      ])
    };
    const tx = { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' };
    const res = compareIntentToTx(JSON.parse(JSON.stringify(ui)), tx);
    const f = fieldOf(res, 'nativeValue');
    assert.strictEqual(f.status, 'MATCH');
    assert.strictEqual(f.uiValue, '1.0 ETH', 'fee cannot supply the matched value');
    assert.deepStrictEqual(f.evidenceRefs, ['claim#0', 'ocr:R-001', 'tx:valueWei'], 'fee refs excluded');
    const wrong = compareIntentToTx(JSON.parse(JSON.stringify(ui)),
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '2000000000000000000' });
    const g = fieldOf(wrong, 'nativeValue');
    assert.strictEqual(g.status, 'MISMATCH');
    assert.strictEqual(g.uiValue, '1.0 ETH', 'mismatch driven by the payment, not the fee');
  }
  console.log('✔ Test 47 Passed: Fee excluded beside payment.');

  // Test 48 (Fix 1): a fee region contained in a summary, claimed alone,
  // cannot compare — linkage does not override the fee role.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-000', 'Transaction summary'), region('R-002', 'Max fee 0.01 ETH')],
        claims: [claim('amount', '0.01 ETH', ['R-002'])],
        associations: assoc([
          link('L-001', 'action-amount', 'containment', [['R-000', 'action'], ['R-002', 'amount']])
        ])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE');
    assert.ok(fieldOf(res, 'nativeValue').reason.includes('fee'));
  }
  console.log('✔ Test 48 Passed: Linked fee still excluded.');

  // Test 49 (Fix 1): same symbol, different roles — an allowance display is
  // not a transfer amount, but is valid allowance evidence.
  {
    const tx = {
      contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
      parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0'
    };
    const ui = {
      regions: [region('R-001', 'Allowance 5.0 USDC'), region('R-002', 'Send 1.0 USDC')],
      claims: [claim('amount', '5.0 USDC', ['R-001']), claim('amount', '1.0 USDC', ['R-002'])],
      associations: assoc([
        link('L-001', 'action-amount', 'same-region', [['R-002', 'action'], ['R-002', 'amount']])
      ])
    };
    const res = compareIntentToTx(JSON.parse(JSON.stringify(ui)), tx);
    assert.strictEqual(fieldOf(res, 'tokenAmount').status, 'MATCH');
    assert.strictEqual(fieldOf(res, 'tokenAmount').uiValue, '1.0 USDC');
    const allowanceOnly = compareIntentToTx(
      {
        regions: [region('R-001', 'Spending limit 5.0 USDC')],
        claims: [claim('amount', '5.0 USDC', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      tx
    );
    assert.strictEqual(fieldOf(allowanceOnly, 'tokenAmount').status, 'INCONCLUSIVE', 'allowance is not a transfer');
  }
  console.log('✔ Test 49 Passed: Role separation within a symbol.');

  // Test 50 (Fix 1): balance-only, quote-only, minimum-only, and
  // allowance-only displays stay inconclusive for main-amount fields.
  {
    const tx = { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' };
    for (const [text, value] of [
      ['Balance: 1.0 ETH', '1.0 ETH'],
      ['Estimated output 1.0 ETH', '1.0 ETH'],
      ['Minimum received 1.0 ETH', '1.0 ETH'],
      ['You receive 1.0 ETH', '1.0 ETH'],
      ['Gas: 1.0 ETH', '1.0 ETH']
    ]) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', text)],
          claims: [claim('amount', value, ['R-001'])],
          associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
        },
        tx
      );
      assert.strictEqual(fieldOf(res, 'nativeValue').status, 'INCONCLUSIVE', text);
    }
  }
  console.log('✔ Test 50 Passed: Non-payment roles excluded.');

  // Test 51 (Fix 1): "Total to pay" is a legitimate transaction amount;
  // "total" is not an excluded role. A GAS-token payment is not a gas fee.
  {
    const total = compareIntentToTx(
      {
        regions: [region('R-001', 'Total to pay 1.0 ETH')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(total, 'nativeValue').status, 'MATCH');
    const gasToken = compareIntentToTx(
      {
        regions: [region('R-001', 'Pay 100 GAS')],
        claims: [claim('amount', '100 GAS', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      {
        contract: OTHER, functionName: 'transfer', standard: 'ERC20', symbol: 'GAS', decimals: 8,
        parameters: { recipient: SPENDER, amount: '10000000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(gasToken, 'tokenAmount').status, 'MATCH', 'GAS token is not a gas fee');
  }
  console.log('✔ Test 51 Passed: Total and GAS token preserved.');

  // Test 52 (Fix 1): mixed-role single regions and swap input/quote pairs.
  {
    const mixed = compareIntentToTx(
      {
        regions: [region('R-001', 'Balance: 21 ETH, pay 1.0 ETH.')],
        claims: [claim('amount', '1.0 ETH', ['R-001'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])])
      },
      { contract: OTHER, functionName: 'nativeTransfer', standard: 'Native', parameters: {}, valueWei: '1000000000000000000' }
    );
    assert.strictEqual(fieldOf(mixed, 'nativeValue').status, 'INCONCLUSIVE', 'mixed roles resolve to no role');
    const swap = compareIntentToTx(
      {
        regions: [region('R-001', 'You pay 1.0 ETH'), region('R-002', 'Estimated output 3,450 USDC')],
        claims: [claim('amount', '1.0 ETH', ['R-001']), claim('amount', '3,450 USDC', ['R-002'])],
        associations: assoc([
          link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']]),
          link('L-002', 'action-amount', 'containment', [['R-001', 'action'], ['R-002', 'amount']])
        ])
      },
      {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        symbol: null, decimals: null, valueWei: '1000000000000000000',
        parameters: { tokenIn: WETH, tokenOut: USDC, recipient: SPENDER, amountIn: '1000000000000000000', amountOutMinimum: '3400000000' },
        tokenMeta: { [WETH]: { symbol: 'WETH', decimals: 18 }, [USDC]: { symbol: 'USDC', decimals: 6 } }
      }
    );
    assert.strictEqual(fieldOf(swap, 'tokenAmount').status, 'MATCH');
    assert.strictEqual(fieldOf(swap, 'tokenAmount').uiValue, '1.0 ETH');
    assert.strictEqual(fieldOf(swap, 'swapOutput').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 52 Passed: Mixed roles and swap quotes safe.');

  // Test 53 (Fix 2): a bare "Approve" button establishes no operation.
  {
    const vsTransfer = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve')],
        claims: [claim('action', 'Approve', ['R-001'])]
      },
      { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(vsTransfer, 'action').status, 'INCONCLUSIVE', 'no false MISMATCH');
    assert.ok(fieldOf(vsTransfer, 'action').reason.includes('without corroborated operation context'));
    const vsApprove = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve')],
        claims: [claim('action', 'Approve', ['R-001'])]
      },
      { contract: USDC, functionName: 'approve', standard: 'ERC20', parameters: {}, valueWei: '0' }
    );
    assert.strictEqual(fieldOf(vsApprove, 'action').status, 'INCONCLUSIVE', 'no cheap MATCH either');
  }
  console.log('✔ Test 53 Passed: Bare Approve inconclusive.');

  // Test 54 (Fix 2): approval with corroborated spender or allowance
  // context compares genuinely.
  {
    const withSpender = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve'), region('R-002', `Spender ${SPENDER}`)],
        claims: [claim('action', 'Approve', ['R-001']), claim('recipient', SPENDER, ['R-002'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(withSpender, 'action').status, 'MATCH', 'spender context establishes the operation');
    const conflict = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve'), region('R-002', `Spender ${SPENDER}`)],
        claims: [claim('action', 'Approve', ['R-001']), claim('recipient', SPENDER, ['R-002'])]
      },
      {
        contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { recipient: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(conflict, 'action').status, 'MISMATCH', 'contextualized approval genuinely conflicts');
    const withAllowance = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve'), region('R-002', 'Approve 1.0 USDC')],
        claims: [claim('action', 'Approve', ['R-001']), claim('amount', '1.0 USDC', ['R-002'])],
        associations: assoc([link('L-001', 'action-amount', 'same-region', [['R-002', 'action'], ['R-002', 'amount']])])
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: '1000000' }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(withAllowance, 'action').status, 'MATCH', 'allowance context establishes the operation');
    const withScope = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve'), region('R-002', 'Unlimited spending')],
        claims: [claim('action', 'Approve', ['R-001']), claim('approval', 'Unlimited spending', ['R-002'])]
      },
      {
        contract: USDC, functionName: 'approve', standard: 'ERC20', symbol: 'USDC', decimals: 6,
        parameters: { spender: SPENDER, amount: MAX_UINT }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(withScope, 'action').status, 'MATCH', 'scope claim establishes the operation');
  }
  console.log('✔ Test 54 Passed: Contextualized approval compares.');

  // Test 55 (Fix 2): NFT operator approval with context; generic labels
  // without operation vocabulary stay inconclusive.
  {
    const nft = compareIntentToTx(
      {
        regions: [region('R-001', 'Set approval'), region('R-002', `Operator ${SPENDER}`)],
        claims: [claim('action', 'Set approval', ['R-001']), claim('recipient', SPENDER, ['R-002'])]
      },
      {
        contract: OTHER, functionName: 'setApprovalForAll', standard: 'ERC721',
        parameters: { operator: SPENDER, approved: true }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(nft, 'action').status, 'MATCH');
    assert.strictEqual(fieldOf(nft, 'counterparty').status, 'MATCH');
    assert.strictEqual(fieldOf(nft, 'counterparty').role, 'operator');
    for (const label of ['Confirm', 'Submit transaction', 'Review details']) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', label)],
          claims: [claim('action', label.split(' ')[0], ['R-001'])]
        },
        { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: {}, valueWei: '0' }
      );
      assert.strictEqual(fieldOf(res, 'action').status, 'INCONCLUSIVE', label);
    }
  }
  console.log('✔ Test 55 Passed: NFT approval and generic labels.');

  // Test 56 (Fix 2): an approval label against a non-approval operation
  // stays inconclusive without context — even for swaps.
  {
    const res = compareIntentToTx(
      {
        regions: [region('R-001', 'Approve')],
        claims: [claim('action', 'Approve', ['R-001'])]
      },
      {
        contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
        parameters: { tokenIn: WETH, tokenOut: USDC }, valueWei: '0'
      }
    );
    assert.strictEqual(fieldOf(res, 'action').status, 'INCONCLUSIVE');
  }
  console.log('✔ Test 56 Passed: Context-free approval conflict inconclusive.');

  // Test 57 (Fix 2 regression): unambiguous non-approval verbs still
  // compare exactly as before.
  {
    const cases = [
      ['Swap now', 'Swap', 'exactInputSingle', 'MATCH'],
      ['Send funds', 'Send', 'transfer', 'MATCH'],
      ['Send funds', 'Send', 'approve', 'MISMATCH'],
      ['Deposit funds', 'Deposit', 'deposit', 'MATCH'],
      ['Withdraw funds', 'Withdraw', 'deposit', 'MISMATCH'],
      ['Transfer assets', 'Transfer', 'transferFrom', 'MATCH']
    ];
    for (const [text, verb, fn, expected] of cases) {
      const res = compareIntentToTx(
        {
          regions: [region('R-001', text)],
          claims: [claim('action', verb, ['R-001'])]
        },
        { contract: OTHER, functionName: fn, standard: 'ERC20', parameters: {}, valueWei: '0' }
      );
      assert.strictEqual(fieldOf(res, 'action').status, expected, `${verb} vs ${fn}`);
    }
  }
  console.log('✔ Test 57 Passed: Verb matrix unchanged.');

  console.log('\nAll Intent Comparison Tests Passed Successfully!\n');
}

module.exports = { runIntentComparisonTests };

if (require.main === module) {
  runIntentComparisonTests().catch((err) => {
    console.error(`\nIntent Comparison Tests Failed: ${err.message}\n`);
    process.exit(1);
  });
}
