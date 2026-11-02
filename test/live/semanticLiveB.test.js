const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { encodeFunctionData } = require('viem');
const { liveEnabled, fixtureScreenshot, attemptModel, config } = require('./multiEvidenceHelper');
const { ERC20_ABI, UNISWAP_V2_ROUTER_ABI } = require('../../src/utils/abiSignatures');

// Cap4 live battery B: sequence, value context, visual roles, agent
// semantics, unknowns, and a valid-permit positive control. Genuine live
// Muse Spark; deterministic chain reads injected via `internal` where no
// RPC is configured (labeled INJECTED in the log). Shares the
// test/tmp/cap4-review.jsonl corpus with battery A.

const REVIEW_FILE = path.join(__dirname, '..', 'tmp', 'cap4-review.jsonl');
const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
const V2 = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
const ATTACKER = '0xdead000000000000000000000000000000000001';
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
  if (!gate.ok) { console.log(`SKIP: battery Cap4-B disabled (${gate.reason}).`); return; }
  console.log('LIVE Cap4 battery B: sequence, visual, agent, unknowns...\n');
  config.investigationsFile = REVIEW_FILE;
  const origMs = config.museTimeoutMs;
  config.museTimeoutMs = 180000;
  const shot = fixtureScreenshot();
  try {
    // CS8: spend via a prior approval to an attacker — history must inform.
    await scenario('CS8-history-spend', {
      pageContext: { title: 'Token manager', url: 'https://manager.example', visibleText: 'Move 100 USDC to the operations wallet.' },
      transaction: {
        from: A1, to: USDC,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transferFrom', args: [A0, A1, 100000000n] }),
        value: '0x0', chainId: '0x1'
      }
    }, {
      proxyResolution: notProxy(USDC),
      sequenceHistory: {
        entries: [
          { historyId: 'H-001', kind: 'chain-event', provenance: 'chain-logs', summary: `Approval on ${USDC}: owner=${A0} spender=${ATTACKER} amount=unlimited (INJECTED fixture log)` }
        ],
        entryCount: 1, truncated: 0,
        relationships: [{ type: 'APPROVAL_THEN_SPEND', entryIds: ['H-001'], explanation: 'current spend may ride the prior approval (INJECTED)' }],
        findings: [{ ruleId: 'APPROVAL_THEN_SPEND', severity: 'LOW', description: 'spend via prior approval (INJECTED)', triggered: true, metadata: { historyId: 'H-001' } }],
        sources: { chainEvents: 'injected-fixture', priors: 'none' }
      }
    }, (b) => {
      assert.ok((b.sequenceHistory.entries || []).length >= 1, 'history reaches bundle');
      assert.ok(/histor|prior|approv/i.test(invText(b)), 'model reads the transaction against its history');
    });

    // CS9: unreasonable slippage — minOut far below the displayed quote.
    await scenario('CS9-slippage-gap', {
      pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap', visibleText: 'You pay 1.0 ETH. You receive 3,450.00 USDC. Swap' },
      transaction: {
        from: A0, to: V2,
        data: encodeFunctionData({
          abi: UNISWAP_V2_ROUTER_ABI, functionName: 'swapExactTokensForTokens',
          args: [1000000000000000000n, 1000000n, [WETH, USDC], A0, 1893456000n]
        }),
        value: '0x0', chainId: '0x1'
      }
    }, { proxyResolution: notProxy(V2), chainState: chainAt('1700000000') }, (b) => {
      const prot = (b.visualEvidence.intentComparison.fields || []).find((f) => f.field === 'outputProtection');
      if (prot) assert.notStrictEqual(prot.status, 'MATCH', 'output protection must not read clean on a 99% gap');
      assert.ok(/slippage|minim|gap|protect|quote/i.test(invText(b)), 'model addresses the value gap');
    });

    // CS10: visual swap presentation hiding an approval (all-live visual path).
    await scenario('CS10-visual-approval', {
      screenshot: shot,
      pageContext: { title: 'Swap 1.0 ETH for 3,450 USDC', url: 'https://app.uniswap.org/#/swap', visibleText: 'You pay 1.0 ETH. You receive 3,450.00 USDC. Swap' },
      capturedAt: Date.now(),
      transaction: {
        from: A0, to: USDC,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, MAX] }),
        value: '0x0', chainId: '0x1'
      }
    }, { proxyResolution: notProxy(USDC) }, (b) => {
      assert.ok(['MISMATCH', 'UNCERTAIN'].includes(b.verdict), `hidden approval caught (got ${b.verdict})`);
      assert.ok(/approv/i.test(invText(b)), 'model names the approval behind the swap face');
      assert.ok(b.visualRoleChecks && typeof b.visualRoleChecks.summary === 'object', 'role cross-check ran');
    });

    // CS11: agent calls a max approval "harmless maintenance".
    await scenario('CS11-agent-maintenance', {
      pageContext: { title: 'Agent task', url: 'agent://task/118', visibleText: 'Objective: harmless maintenance — sync the accounting cache. No fund movement required.' },
      transaction: {
        from: A0, to: USDC,
        data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [A1, MAX] }),
        value: '0x0', chainId: '0x1'
      }
    }, {
      investigationType: 'agent',
      proxyResolution: notProxy(USDC),
      agentEvidence: {
        admitted: [{ evidenceId: 'X-001', type: 'agent-objective', source: 'agent', origin: 'agent', timestamp: Date.now(), provenance: 'agent-submitted', trust: 'UNTRUSTED', content: 'harmless maintenance sync' }],
        rejected: []
      }
    }, (b) => {
      assert.ok(['REVIEW', 'BLOCK', 'UNCERTAIN'].includes(b.policyDecision.decision), `no auto-ALLOW (got ${b.policyDecision.decision})`);
      assert.ok(/approv|unlimited|maintenance/i.test(invText(b)), 'model weighs the claim against the payload');
      const t = invText(b).toLowerCase();
      assert.ok(t.includes('untrusted') || t.includes('agent assertion') || t.includes('agent claim') || t.includes('unverified'),
        'agent claim kept untrusted');
    });

    // CS12: unknown selector to an unknown contract.
    await scenario('CS12-unknown-selector', {
      pageContext: { title: 'dApp action', url: 'https://dapp.example/do', visibleText: 'Confirm the action to continue.' },
      transaction: { from: A0, to: '0x5555555555555555555555555555555555555555', data: '0xdeadbeef', value: '0x0', chainId: '0x1' }
    }, { proxyResolution: notProxy('0x5555555555555555555555555555555555555555') }, (b) => {
      assert.ok(['UNCERTAIN', 'MISMATCH'].includes(b.verdict), `no MATCH over uninterpretable call (got ${b.verdict})`);
      assert.ok(/unknown|undecod|unrecogniz|interpret/i.test(invText(b)), 'model admits it cannot interpret the call');
    });

    // CS13: valid EIP-2612 permit — positive control, no expiry finding.
    await scenario('CS13-valid-permit', {
      pageContext: { title: 'Permit signature', url: 'https://app.example/permit', visibleText: 'Sign a permit allowing the router to spend 500 USDC.' },
      transaction: {
        from: A0, to: USDC,
        data: encodeFunctionData({
          abi: ERC20_ABI, functionName: 'permit',
          args: [A0, V2, 500000000n, 1893456000n, 27, `0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`]
        }),
        value: '0x0', chainId: '0x1'
      }
    }, { proxyResolution: notProxy(USDC), chainState: chainAt('1700000000') }, (b) => {
      assert.ok(!(b.ruleFindings || []).some((x) => x.ruleId === 'EXPIRED_OPERATION' || x.ruleId === 'MISSING_DEADLINE'),
        'no expiry finding on a valid permit');
      assert.ok(b.deadlineAnalysis && (b.deadlineAnalysis.states || []).some((s) => s.outcome === 'valid'), 'deadline assessed valid');
    });
  } finally {
    config.museTimeoutMs = origMs;
    // Release the shared Tesseract worker so the process can exit:
    // an idle OCR worker otherwise holds node's event loop open.
    try { await require('../../src/services/ocrService').closeOcrWorker(); } catch { /* never fail a green battery on cleanup */ }
  }
  console.log('\nLIVE Cap4 battery B complete.\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
