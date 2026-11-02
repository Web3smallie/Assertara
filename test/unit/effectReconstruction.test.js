/**
 * Capability 5 B2: deterministic economic-effect reconstruction.
 * Unit + mocked-integration tests. Live-model citation behavior is
 * covered by the gated live batteries.
 */
const assert = require('assert');
const { encodeFunctionData } = require('viem');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');
const {
  MAX_EFFECTS, EFFECT_KINDS, reconstructEffects, exactInt, tokenMeta
} = require('../../src/services/effectReconstruction');
const {
  ERC20_ABI, ERC721_ABI, WETH_ABI, PERMIT2_ABI,
  UNISWAP_V3_ROUTER_ABI, UNISWAP_V2_ROUTER_ABI, OWNABLE_ABI
} = require('../../src/utils/abiSignatures');

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
const V2 = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
const V3 = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const MAX = (1n << 256n) - 1n;

function recon(to, data, value, chainId = '0x1') {
  const decodedTx = decodeTransactionCalldata({ to, data, value });
  return reconstructEffects({ tx: { from: A0, to, value }, decodedTx, chainId });
}

async function run() {
  console.log('Testing Cap5 B2 effect reconstruction...\n');

  // B2.1: native transfer exact.
  {
    const r = recon(A1, '0x', '0xde0b6b3a7640000');
    assert.strictEqual(r.effects.length, 1);
    const e = r.effects[0];
    assert.strictEqual(e.effectId, 'EF-001');
    assert.strictEqual(e.kind, 'native-transfer');
    assert.strictEqual(e.amount, '1000000000000000000');
    assert.strictEqual(e.from, A0.toLowerCase());
    assert.strictEqual(e.to, A1.toLowerCase());
    assert.strictEqual(e.asset.standard, 'native');
    assert.strictEqual(e.verification, 'decoded');
    assert.strictEqual(e.confidence, 'exact');
    console.log('✔ B2.1 Passed: Native transfer exact (parties, 1 ETH).');
  }

  // B2.2: ERC20 transfer/approve top-level + token metadata scoping.
  {
    const t = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] }), '0x0');
    const e = t.effects[0];
    assert.strictEqual(e.kind, 'transfer');
    assert.strictEqual(e.amount, '1000');
    assert.strictEqual(e.from, A0.toLowerCase());
    assert.strictEqual(e.to, A1.toLowerCase());
    assert.strictEqual(e.asset.contract, USDC.toLowerCase());
    assert.strictEqual(e.asset.symbol, 'USDC');
    assert.strictEqual(e.asset.decimals, 6);
    const wrongChain = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] }), '0x0', '0x89');
    assert.strictEqual(wrongChain.effects[0].asset.symbol, null, 'chain-1 metadata never applied off-chain');
    const a = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, MAX] }), '0x0');
    assert.strictEqual(a.effects[0].kind, 'approval');
    assert.strictEqual(a.effects[0].spender, A1.toLowerCase());
    assert.strictEqual(a.effects[0].unlimited, true);
    const unk = recon(`0x${'5'.repeat(40)}`, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1n] }), '0x0');
    assert.strictEqual(unk.effects[0].asset.symbol, null, 'unknown token has no symbol');
    assert.strictEqual(unk.effects[0].asset.contract, `0x${'5'.repeat(40)}`, 'but contract recorded');
    console.log('✔ B2.2 Passed: ERC20 effects + chain-scoped metadata honesty.');
  }

  // B2.3: transferFrom explicit parties; NFT transfer + collection approval.
  {
    const t = recon(USDC, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transferFrom', args: [A0, A1, 50n] }), '0x0');
    assert.strictEqual(t.effects[0].from, A0.toLowerCase());
    assert.strictEqual(t.effects[0].to, A1.toLowerCase());
    const BAYC = `0x${'b'.repeat(40)}`;
    const n = recon(BAYC, encodeFunctionData({ abi: ERC721_ABI, functionName: 'safeTransferFrom', args: [A0, A1, 1234n] }), '0x0');
    assert.strictEqual(n.effects[0].kind, 'transfer-nft');
    assert.strictEqual(n.effects[0].asset.tokenId, '1234');
    assert.strictEqual(n.effects[0].from, A0.toLowerCase());
    const op = recon(BAYC, encodeFunctionData({ abi: ERC721_ABI, functionName: 'setApprovalForAll', args: [A1, true] }), '0x0');
    assert.strictEqual(op.effects[0].kind, 'approval-nft');
    assert.strictEqual(op.effects[0].operator, A1.toLowerCase());
    assert.strictEqual(op.effects[0].unlimited, true, 'collection-wide approval flagged');
    console.log('✔ B2.3 Passed: Explicit parties, NFT legs, operator scope.');
  }

  // B2.4: swaps carry legs, amounts, minimums.
  {
    const v3 = recon(V3, encodeFunctionData({
      abi: UNISWAP_V3_ROUTER_ABI, functionName: 'exactInputSingle',
      args: [{ tokenIn: WETH, tokenOut: USDC, fee: 500, recipient: A0, amountIn: 1000000000000000000n, amountOutMinimum: 3400000000n, sqrtPriceLimitX96: 0n }]
    }), '0x0');
    const e = v3.effects[0];
    assert.strictEqual(e.kind, 'swap');
    assert.strictEqual(e.amount, '1000000000000000000');
    assert.ok(e.notes.join(' ').includes('3400000000'), 'minimum preserved');
    assert.ok(e.notes.join(' ').includes(WETH.toLowerCase()), 'input leg recorded');
    assert.ok(e.notes.join(' ').includes(USDC.toLowerCase()), 'output leg recorded');
    const v2 = recon(V2, encodeFunctionData({
      abi: UNISWAP_V2_ROUTER_ABI, functionName: 'swapExactTokensForTokens',
      args: [1000n, 900n, [WETH, USDC], A0, 1893456000n]
    }), '0x0');
    assert.strictEqual(v2.effects[0].kind, 'swap');
    assert.ok(v2.effects[0].notes.join(' ').includes('2 hop(s)'));
    assert.strictEqual(v2.effects[0].to, A0.toLowerCase());
    console.log('✔ B2.4 Passed: V2/V3 swap legs and minimums.');
  }

  // B2.5: wrap/unwrap + payable native leg alongside call effects.
  {
    const d = recon(WETH, encodeFunctionData({ abi: WETH_ABI, functionName: 'deposit', args: [] }), '0xde0b6b3a7640000');
    const kinds = d.effects.map((e) => e.kind).sort();
    assert.deepStrictEqual(kinds, ['native-transfer', 'wrap'], 'value leg + wrap leg');
    assert.strictEqual(d.effects.find((e) => e.kind === 'wrap').amount, '1000000000000000000');
    const w = recon(WETH, encodeFunctionData({ abi: WETH_ABI, functionName: 'withdraw', args: [500n] }), '0x0');
    assert.strictEqual(w.effects[0].kind, 'unwrap');
    assert.strictEqual(w.effects[0].amount, '500');
    assert.strictEqual(w.effects[0].to, A0.toLowerCase());
    console.log('✔ B2.5 Passed: Wrap/unwrap + native leg separation.');
  }

  // B2.6: permits authorize future spending; nothing moves now.
  {
    const p = recon(USDC, encodeFunctionData({
      abi: ERC20_ABI, functionName: 'permit',
      args: [A0, V2, 500000000n, 1893456000n, 27, `0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`]
    }), '0x0');
    const e = p.effects[0];
    assert.strictEqual(e.kind, 'permit-authorization');
    assert.strictEqual(e.spender, V2.toLowerCase());
    assert.ok(e.notes.join(' ').includes('no value moves'), 'no-movement stated');
    const p2 = recon('0x000000000022D473030F116dDEE9F6B43aC78BA3', encodeFunctionData({
      abi: PERMIT2_ABI, functionName: 'approve', args: [USDC, A1, 100n, 1893456000]
    }), '0x0');
    assert.strictEqual(p2.effects[0].kind, 'approval');
    assert.strictEqual(p2.effects[0].asset.contract, USDC.toLowerCase(), 'permit2 names its own token');
    console.log('✔ B2.6 Passed: Permit authorization without movement claims.');
  }

  // B2.7: privileged operations become authority-change nodes.
  {
    const r = recon(`0x${'9'.repeat(40)}`, encodeFunctionData({ abi: OWNABLE_ABI, functionName: 'transferOwnership', args: [A1] }), '0x0');
    const e = r.effects[0];
    assert.strictEqual(e.kind, 'authority-change');
    assert.strictEqual(e.to, A1.toLowerCase());
    assert.strictEqual(e.amount, null, 'authority changes move no value');
    console.log('✔ B2.7 Passed: Authority-change nodes carry parties, not value.');
  }

  // B2.8: nested honesty — inner parties exact, inner token/send context unestablished.
  {
    const data = encodeFunctionData({
      abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
      args: [[
        encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 100n] }),
        encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, MAX] })
      ]]
    });
    const r = recon(V3, data, '0x0');
    assert.strictEqual(r.effects.length, 2, 'multicall frame emits no effect of its own');
    const [t, a] = r.effects;
    assert.strictEqual(t.subcall.subcallId, 'SC-001');
    assert.strictEqual(t.to, A1.toLowerCase(), 'inner recipient exact');
    assert.strictEqual(t.asset.contract, null, 'inner token unestablished');
    assert.strictEqual(t.from, null, 'inner sender unestablished');
    assert.strictEqual(t.confidence, 'partial');
    assert.strictEqual(a.kind, 'approval');
    assert.strictEqual(a.unlimited, true);
    assert.ok(a.notes.join(' ').includes('batch context'));
    assert.ok(r.effects.every((e) => e.verification === 'decoded'));
    console.log('✔ B2.8 Passed: Inner effects exact where known, explicit where not.');
  }

  // B2.9: unknown/unmapped/depth-limited become opaque; garbage never throws.
  {
    const u = recon(`0x${'7'.repeat(40)}`, '0xdeadbeef', '0x0');
    assert.strictEqual(u.effects[0].kind, 'opaque');
    assert.strictEqual(u.opaqueCount, 1);
    const batchUnknown = encodeFunctionData({
      abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [[`0xdeadbeef${'00'.repeat(32)}`]]
    });
    const b = recon(V3, batchUnknown, '0x0');
    assert.strictEqual(b.effects[0].kind, 'opaque');
    assert.ok(b.effects[0].subcall && b.effects[0].subcall.subcallId === 'SC-001');
    for (const bad of [null, undefined, {}, { tx: null }, { tx: {}, decodedTx: { parameters: 42 } }, { tx: { value: 'nonsense' }, decodedTx: {} }]) {
      const r = reconstructEffects(bad);
      assert.ok(Array.isArray(r.effects), 'never throws');
    }
    assert.strictEqual(exactInt('abc'), null);
    assert.strictEqual(exactInt(-5), null);
    assert.strictEqual(exactInt('0x10'), '16');
    assert.ok(EFFECT_KINDS.includes('opaque') && MAX_EFFECTS === 200);
    assert.deepStrictEqual(tokenMeta(null, '1'), { symbol: null, decimals: null });
    console.log('✔ B2.9 Passed: Opaque boundaries + total input tolerance.');
  }

  // B2.10: overflow cap is explicit, not silent.
  {
    const decodedTx = { contract: V3, parameters: { calls: [] } };
    for (let i = 0; i < 250; i += 1) {
      decodedTx.parameters.calls.push({ functionName: 'transfer', standard: 'ERC20', selector: '0xa9059cbb', args: [A1, 1n] });
    }
    const r = reconstructEffects({ tx: { from: A0, to: V3, value: '0x0' }, decodedTx, chainId: '1' });
    assert.strictEqual(r.truncated, true);
    assert.strictEqual(r.effects.length, MAX_EFFECTS + 1, '200 listed + 1 overflow node');
    assert.strictEqual(r.effects[r.effects.length - 1].kind, 'opaque');
    assert.ok(r.effects[r.effects.length - 1].notes.join(' ').includes('capped'));
    console.log('✔ B2.10 Passed: Overflow is a listed opaque node.');
  }

  // B2.11: production path — pack block, registry, bundle, prompt.
  {
    const { packEvidence } = require('../../src/services/evidencePacker');
    const { buildEvidenceRegistry, classifyRef } = require('../../src/services/reasoningValidation');
    const { selectSystemPrompt, PROMPT_VERSION } = require('../../src/services/reasoningPrompts');
    const decodedTx = decodeTransactionCalldata({
      to: USDC, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, MAX] }), value: '0x0'
    });
    const effects = reconstructEffects({ tx: { from: A0, to: USDC, value: '0x0' }, decodedTx, chainId: '1' });
    const page = packEvidence({
      visualText: '', pageContext: { title: 't', url: 'https://w.example' },
      decodedTx, visualMeta: {}, extra: { effects }
    }).sectionTexts.find((s) => s.name === 'tx').text;
    assert.ok(page.includes('[EF-001]') && page.includes('DECODED ONLY'), 'effect block reaches the prompt');
    const reg = buildEvidenceRegistry({ pageContext: {}, decodedTx, visualMeta: {}, extra: { effects } });
    assert.strictEqual(classifyRef('EF-001', reg), 'ok', 'printed effect resolves');
    assert.strictEqual(classifyRef('effects', reg), 'ok', 'effects section resolves');
    const bare = buildEvidenceRegistry({ pageContext: {}, decodedTx, visualMeta: {}, extra: {} });
    assert.strictEqual(classifyRef('EF-001', bare), 'fabricated', 'unprinted effect stays fabricated');
    assert.ok(selectSystemPrompt('browser').text.includes('S10.'), 'S10 rule present');
    assert.strictEqual(PROMPT_VERSION, 'investigate-2.7');
    // Bundle exposure through the live controller path (mocked model).
    const appConfig = require('../../src/config/env');
    const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    global.fetch = async () => ({
      ok: true,
      json: async () => ({
        model: 'mock-m',
        choices: [{ message: { content: JSON.stringify({ verdict: 'MATCH', confidence: 0.9, summary: 'canned', discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION' }) } }]
      })
    });
    try {
      let body = null;
      await handleEvaluateTransaction({ body: {
        pageContext: { title: 't', url: 'https://w.example' },
        transaction: { from: A0, to: USDC, data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, 100n] }), value: '0x0', chainId: '0x1' }
      } }, { status: () => ({ json: (b) => { body = b; } }) });
      assert.ok(body && Array.isArray(body.effects.effects) && body.effects.effects.length >= 1, 'bundle carries effects');
      assert.strictEqual(body.effects.effects[0].kind, 'approval');
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B2.11 Passed: Pack + registry + bundle + S10 end to end.');
  }

  console.log('\nAll Cap5 B2 Tests Passed Successfully!\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
