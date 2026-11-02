const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { encodeFunctionData } = require('viem');
const { liveEnabled, attemptModel, config } = require('./multiEvidenceHelper');
const {
  ERC20_ABI, UNISWAP_V2_ROUTER_ABI, PROXY_ADMIN_ABI, OWNABLE_ABI
} = require('../../src/utils/abiSignatures');

// Cap4 live battery A: semantic core (genuine live Muse Spark; deterministic
// chain reads injected via `internal` where no RPC is configured — every
// injection is labeled in the scenario log as INJECTED so live-model
// behavior is never confused with live-chain reads). Records persist to
// test/tmp/cap4-review.jsonl for the 10-investigation qualitative review.

const REVIEW_FILE = path.join(__dirname, '..', 'tmp', 'cap4-review.jsonl');
const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
const V2 = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
const PROXY = '0x2222222222222222222222222222222222222222';
const IMPL = '0x1111111111111111111111111111111111111111';
const MAX = (1n << 256n) - 1n;

const chainAt = (ts) => ({
  status: 'ok', rpcChainId: '1', chainVerified: true, blockNumber: '0x9',
  block: { status: 'ok', number: '0x9', timestamp: ts, timestampHex: `0x${BigInt(ts).toString(16)}` },
  states: {}
});
const notProxy = (target) => ({
  target: target.toLowerCase(), status: 'not-proxy', isProxy: false, explanation: 'direct (INJECTED: no RPC configured)'
});

function invText(b) {
  return JSON.stringify(b.investigation || {});
}

async function scenario(name, body, internal, check) {
  if (process.env.CAP4_ONLY && process.env.CAP4_ONLY !== name) { console.log(`  [${name}] skipped (CAP4_ONLY filter).`); return; }
  const injected = internal ? Object.keys(internal).join(',') : 'none';
  console.log(`  [${name}] running (INJECTED deterministic inputs: ${injected})...`);
  const before = fs.existsSync(REVIEW_FILE) ? fs.readFileSync(REVIEW_FILE, 'utf8').trim().split('\n').filter(Boolean).length : 0;
  const out = await attemptModel(name, body, internal);
  assert.strictEqual(out.status, 200, `${name}: http 200`);
  const b = out.body;
  console.log(`  [${name}] ${out.wallMs}ms origin=${b.reasoningOrigin} verdict=${b.verdict} decision=${b.policyDecision.decision} model=${b.modelId || b.servingModelId || '?'}`);
  assert.strictEqual(b.reasoningOrigin, 'model', `${name}: genuine live reasoning`);
  assert.ok(b.investigation, `${name}: investigation present`);
  assert.strictEqual(b.referenceValidation.ok, true, `${name}: no fabricated refs`);
  await check(b);
  const after = fs.existsSync(REVIEW_FILE) ? fs.readFileSync(REVIEW_FILE, 'utf8').trim().split('\n').filter(Boolean).length : 0;
  assert.ok(after > before, `${name}: investigation persisted for review`);
  console.log(`  ✔ ${name}`);
}

async function run() {
  const gate = liveEnabled();
  if (!gate.ok) { console.log(`SKIP: battery Cap4-A disabled (${gate.reason}).`); return; }
  console.log('LIVE Cap4 battery A: semantic core scenarios...\n');
  if (process.env.CAP4_FRESH === '1' && fs.existsSync(REVIEW_FILE)) fs.unlinkSync(REVIEW_FILE);
  config.investigationsFile = REVIEW_FILE;
  const origMs = config.museTimeoutMs;
  config.museTimeoutMs = 180000;
  try {
    // CS1: resolved proxy — model must reason about implementation behavior.
    await scenario('CS1-proxy-resolved', {
      pageContext: { title: 'Swap on Router', url: 'https://app.uniswap.org/#/swap', visibleText: 'Swap 1 ETH for USDC on the official router contract.' },
      transaction: {
        from: A0, to: PROXY,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] }),
        value: '0x0', chainId: '0x1'
      }
    }, {
      proxyResolution: {
        target: PROXY.toLowerCase(), status: 'resolved', isProxy: true, kind: 'ERC-1967',
        implementation: IMPL.toLowerCase(), implementationCode: { checked: true, hasCode: true },
        downgrade: false, hold: null, explanation: 'resolved (INJECTED)'
      }
    }, (b) => {
      assert.strictEqual(b.proxyResolution.status, 'resolved');
      assert.ok(/prox|implement/i.test(invText(b)), 'model reasons about the proxy/implementation');
    });

    // CS2: unresolved proxy — MATCH must not stand; model must admit unknown.
    await scenario('CS2-proxy-unresolved', {
      pageContext: { title: 'Swap on Router', url: 'https://app.uniswap.org/#/swap', visibleText: 'Swap 1 ETH for USDC on the official router contract.' },
      transaction: {
        from: A0, to: PROXY,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A1, 1000n] }),
        value: '0x0', chainId: '0x1'
      }
    }, {
      proxyResolution: {
        target: PROXY.toLowerCase(), status: 'proxy-unresolved', isProxy: true, kind: 'ERC-1967',
        implementation: null, downgrade: true,
        hold: { source: 'proxy-resolution', reason: 'implementation unreadable (INJECTED)' },
        explanation: 'implementation unreadable (INJECTED)'
      }
    }, (b) => {
      assert.ok(['UNCERTAIN', 'MISMATCH'].includes(b.verdict), `no MATCH over unresolved proxy (got ${b.verdict})`);
      assert.strictEqual(b.proxyResolution.status, 'proxy-unresolved');
      assert.ok(/prox|implement|unknown|uncertain/i.test(invText(b)), 'model addresses the unresolved proxy');
    });

    // CS3: privileged upgrade disguised as routine maintenance.
    await scenario('CS3-privileged-upgrade', {
      pageContext: { title: 'Admin console', url: 'https://admin.example/maintenance', visibleText: 'Routine maintenance: apply the scheduled configuration update.' },
      transaction: {
        from: A0, to: PROXY,
        data: encodeFunctionData({ abi: PROXY_ADMIN_ABI, functionName: 'upgradeTo', args: [IMPL] }),
        value: '0x0', chainId: '0x1'
      }
    }, { proxyResolution: notProxy(PROXY) }, (b) => {
      const f = (b.ruleFindings || []).find((x) => x.ruleId === 'PROXY_UPGRADE');
      assert.ok(f && f.severity === 'CRITICAL', 'CRITICAL upgrade finding present');
      assert.ok(['REVIEW', 'UNCERTAIN', 'BLOCK'].includes(b.policyDecision.decision),
        `privileged upgrade never auto-ALLOWs (got ${b.policyDecision.decision})`);
      assert.ok(/upgrade|implement|control|author|admin/i.test(invText(b)), 'model treats it as an authority change');
    });

    // CS4: zero minimum output — the S3-leniency class.
    await scenario('CS4-zero-minimum', {
      pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap', visibleText: 'You pay 1.0 ETH. You receive 3,450.00 USDC. Swap' },
      transaction: {
        from: A0, to: V2,
        data: encodeFunctionData({
          abi: UNISWAP_V2_ROUTER_ABI, functionName: 'swapExactTokensForTokens',
          args: [1000000000000000000n, 0n, [WETH, USDC], A0, 1893456000n]
        }),
        value: '0x0', chainId: '0x1'
      }
    }, { proxyResolution: notProxy(V2), chainState: chainAt('1700000000') }, (b) => {
      assert.ok((b.ruleFindings || []).some((x) => x.ruleId === 'ZERO_MINIMUM_OUTPUT'));
      assert.ok(['UNCERTAIN', 'MISMATCH'].includes(b.verdict), `MATCH over zero-minimum must not stand (got ${b.verdict})`);
      assert.ok(/minimum|zero|unprotected|unenforced|slippage/i.test(invText(b)), 'model flags the missing floor');
    });

    // CS5: nested hidden approval inside a multicall swap presentation.
    await scenario('CS5-nested-drain', {
      pageContext: { title: 'Batch swap', url: 'https://app.uniswap.org/#/swap', visibleText: 'Batch swap: convert tokens in one transaction.' },
      transaction: {
        from: A0, to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
        data: encodeFunctionData({
          abi: require('../../src/utils/abiSignatures').UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
          args: [[
            encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [A0, 1n] }),
            encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: ['0xdead000000000000000000000000000000000001', MAX] })
          ]]
        }),
        value: '0x0', chainId: '0x1'
      }
    }, { proxyResolution: notProxy('0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45') }, (b) => {
      assert.ok((b.subcalls.subcalls || []).length >= 2, 'subcalls decoded');
      assert.ok(/approv|inner|nested|hidden|subcall/i.test(invText(b)), 'model examines the inner approval');
    });

    // CS6: expired swap deadline (block time injected).
    await scenario('CS6-expired-swap', {
      pageContext: { title: 'Swap tokens', url: 'https://app.uniswap.org/#/swap', visibleText: 'Swap 1000 TEST for at least 900 USDC.' },
      transaction: {
        from: A0, to: V2,
        data: encodeFunctionData({
          abi: UNISWAP_V2_ROUTER_ABI, functionName: 'swapExactTokensForTokens',
          args: [1000n, 900n, [WETH, USDC], A0, 1600000000n]
        }),
        value: '0x0', chainId: '0x1'
      }
    }, { proxyResolution: notProxy(V2), chainState: chainAt('1700000000') }, (b) => {
      assert.ok((b.ruleFindings || []).some((x) => x.ruleId === 'EXPIRED_OPERATION'));
      assert.ok(['UNCERTAIN', 'MISMATCH'].includes(b.verdict), `no MATCH over expired swap (got ${b.verdict})`);
      assert.ok(/expir|deadline|revert/i.test(invText(b)), 'model notes the expiry');
    });

    // CS7: misleading contract identity (familiar name, unverified address).
    await scenario('CS7-misleading-identity', {
      pageContext: { title: 'Uniswap V3 Router — official', url: 'https://app.uniswap.org/#/swap', visibleText: 'Swap on the official Uniswap V3 Router.' },
      transaction: { from: A0, to: '0x000000000000000000000000000000000000dEaD', data: '0x', value: '0x16345785d8a0000', chainId: '0x1' }
    }, {
      proxyResolution: notProxy('0x000000000000000000000000000000000000dEaD'),
      contractIdentity: { status: 'unknown', verificationStatus: 'unknown', explanation: 'no verification evidence (INJECTED)' }
    }, (b) => {
      assert.ok(['MISMATCH', 'UNCERTAIN'].includes(b.verdict), `decisive non-MATCH (got ${b.verdict})`);
      assert.ok(/unknown|unverif|identity|official/i.test(invText(b)), 'model questions the familiar name');
    });
  } finally {
    config.museTimeoutMs = origMs;
    // Release the shared Tesseract worker so the process can exit:
    // an idle OCR worker otherwise holds node's event loop open.
    try { await require('../../src/services/ocrService').closeOcrWorker(); } catch { /* never fail a green battery on cleanup */ }
  }
  console.log('\nLIVE Cap4 battery A complete.\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
