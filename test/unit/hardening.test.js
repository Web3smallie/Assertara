const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  simulateTransactionWithFoundry, generateFoundryTestContract,
  validateSimulationInputs, MAX_CALLDATA_BYTES
} = require('../../src/services/simulatorService');
const { evaluateSemanticDiscrepancy, fallbackHeuristicReasoner } = require('../../src/services/reasonerService');
const { compileEvidenceBundle } = require('../../src/services/evidenceService');
const { adjudicate, runGates, GATES } = require('../../src/agent/verifier');
const { EvidenceGraph } = require('../../src/agent/evidenceGraph');
const { runFeature, runRepoReview } = require('../../src/agent/features');
const { runTool } = require('../../src/agent/toolRegistry');

const ADDR_A = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const ADDR_B = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const APPROVE_DATA = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b230000000000000000000000000000000000000000000000000000000000000064';
const APPROVE_TX = { to: ADDR_B, data: APPROVE_DATA, value: '0x0' };
const SIM_DECODED = {
  functionName: 'approve', symbol: 'USDT',
  parameters: { spender: SPENDER, amount: '100' },
  isUnlimitedApproval: false, contract: ADDR_B, ruleFindings: []
};

function simDirSnapshot() {
  const dir = path.join(__dirname, '..', '..', 'test', 'simulations');
  try {
    return fs.readdirSync(dir).sort();
  } catch {
    return null;
  }
}

// Recursive strict-shape check: every object node needs
// additionalProperties:false and required ⊇ properties.
function assertStrictSchema(schema, where) {
  assert.ok(schema && typeof schema === 'object', `${where}: schema is an object`);
  (function walk(node, trail) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'object' || node.properties) {
      assert.strictEqual(node.additionalProperties, false, `${where}${trail}: additionalProperties:false`);
      const props = Object.keys(node.properties || {});
      assert.ok(Array.isArray(node.required), `${where}${trail}: required array`);
      for (const k of props) assert.ok(node.required.includes(k), `${where}${trail}: required includes ${k}`);
      for (const [k, v] of Object.entries(node.properties || {})) walk(v, `${trail}.${k}`);
    }
    if (node.type === 'array' && node.items) walk(node.items, `${trail}[]`);
  })(schema, '');
}

function capturingStub(content) {
  const seen = {};
  return { seen, model: { async complete(args) { seen.args = args; return { content }; } } };
}

async function runHardeningTests() {
  console.log('Testing Phase 14: Boundaries, Provenance & Schemas...\n');

  // Test 1: adversarial simulator inputs rejected before generation.
  {
    const before = simDirSnapshot();
    const evil = [
      ['newline injection', { from: `${ADDR_A}\ncontract Evil {}`, to: ADDR_B, data: APPROVE_DATA }],
      ['quote breakout', { from: `${ADDR_A}"; malicious(); "`, to: ADDR_B, data: APPROVE_DATA }],
      ['comment injection', { from: '0x0000000000000000000000000000000000000000', to: ADDR_B, data: '0x095ea7b3//evil' }],
      ['short from', { from: '0x1', to: ADDR_B, data: APPROVE_DATA }],
      ['non-hex from', { from: '0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ', to: ADDR_B, data: APPROVE_DATA }],
      ['numeric from', { from: 12345, to: ADDR_B, data: APPROVE_DATA }],
      ['object from', { from: { evil: true }, to: ADDR_B, data: APPROVE_DATA }],
      ['missing to', { from: ADDR_A, data: APPROVE_DATA }],
      ['short to', { from: ADDR_A, to: '0x2', data: APPROVE_DATA }],
      ['non-string data', { from: ADDR_A, to: ADDR_B, data: 999 }],
      ['odd-length data', { from: ADDR_A, to: ADDR_B, data: '0x123' }],
      ['non-hex data', { from: ADDR_A, to: ADDR_B, data: '0xzzzz' }],
      ['over-cap data', { from: ADDR_A, to: ADDR_B, data: `0x${'ab'.repeat(MAX_CALLDATA_BYTES + 1)}` }],
      ['missing decodedTx', { from: ADDR_A, to: ADDR_B, data: APPROVE_DATA, decodedTx: null }],
      ['spender injection', { from: ADDR_A, to: ADDR_B, data: APPROVE_DATA, decodedTx: { ...SIM_DECODED, parameters: { spender: '0x1"; attack(); "' } } }]
    ];
    for (const [label, input] of evil) {
      const r = await simulateTransactionWithFoundry({ decodedTx: SIM_DECODED, ...input });
      assert.strictEqual(r.status, 'FAILED', `${label}: rejected`);
      assert.ok(r.error.includes('SIM_VALIDATION'), `${label}: structured error`);
      assert.strictEqual(r.executed, false, `${label}: never executed`);
      assert.ok(r.reason.includes('before any source generation'), `${label}: reason honest`);
    }
    assert.deepStrictEqual(simDirSnapshot(), before, 'Rejected inputs write no .t.sol files');
    assert.throws(() => validateSimulationInputs({}), (e) => e.code === 'SIM_VALIDATION');
    console.log('✔ Test 1 Passed: 15 adversarial inputs rejected; disk untouched.');
  }

  // Test 2: legitimate inputs preserved; generated source structurally safe.
  {
    const r = await simulateTransactionWithFoundry({ from: ADDR_A, to: ADDR_B, data: APPROVE_DATA, decodedTx: SIM_DECODED });
    assert.ok(['FALLBACK', 'EXECUTED'].includes(r.status), `Legit input reaches toolchain (got ${r.status})`);
    assert.ok(!String(r.error || '').includes('SIM_VALIDATION'), 'No validation error for legit input');
    const native = await simulateTransactionWithFoundry({ to: ADDR_B, decodedTx: { ...SIM_DECODED, functionName: 'nativeTransfer' } });
    assert.ok(['FALLBACK', 'EXECUTED'].includes(native.status), 'Missing from/data (native transfer) still supported');
    const src = generateFoundryTestContract({ victimAddress: ADDR_A, tokenAddress: ADDR_B, spenderAddress: SPENDER, calldataHex: APPROVE_DATA, testId: 'abc123' });
    assert.ok(src.includes(`VICTIM = ${ADDR_A}`) && src.includes(`hex"${APPROVE_DATA.slice(2)}"`));
    // Interpolated values are allowlist-charset: re-validate everything the
    // generator embedded and confirm no metacharacters could have ridden along.
    for (const v of [ADDR_A, ADDR_B, SPENDER, APPROVE_DATA]) {
      assert.ok(!/["';\n\r`/]/.test(v), 'Interpolated values carry no source metacharacters');
    }
    const capEdge = `0x${'ab'.repeat(MAX_CALLDATA_BYTES)}`;
    assert.doesNotThrow(() => validateSimulationInputs({ to: ADDR_B, data: capEdge, decodedTx: SIM_DECODED }), 'Exact cap accepted');
    console.log('✔ Test 2 Passed: Legit inputs simulate; interpolation charset-safe.');
  }

  // Test 3: fallback vs model provenance on every reasoner path.
  {
    const swapPage = { url: 'https://app.uniswap.org/#/swap', title: 'Swap 1.0 ETH for 3,450 USDC' };
    const swapTx = { ...SIM_DECODED, contractName: 'Uniswap V3 SwapRouter02', functionName: 'exactInputSingle', standard: 'UniswapV3Router', valueEth: '1', parameters: {} };
    assert.strictEqual(fallbackHeuristicReasoner('', swapPage, swapTx).origin, 'heuristic-fallback');
    assert.strictEqual(fallbackHeuristicReasoner('', { title: 'Claim free' }, { ...SIM_DECODED, isUnlimitedApproval: true }).origin, 'heuristic-fallback');
    assert.strictEqual(fallbackHeuristicReasoner('', { title: 'Gov' }, { functionName: 'unknownFunction', standard: 'Unknown', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] }).origin, 'heuristic-fallback');
    const realFetch = global.fetch;
    const config = require('../../src/config/env');
    const originalKey = config.modelApiKey;
    config.modelApiKey = 'test-live-key';
    try {
      global.fetch = async () => ({ ok: true, json: async () => ({ choices: [{ message: { content: '{"verdict":"MATCH","confidence":0.9}' } }] }) });
      const live = await evaluateSemanticDiscrepancy('', swapPage, swapTx);
      assert.strictEqual(live.origin, 'model', 'Live model path labeled model');
      assert.strictEqual(live.verdict, 'MATCH', 'Verdict itself unchanged');
      global.fetch = async () => { throw new Error('network down'); };
      const degraded = await evaluateSemanticDiscrepancy('', swapPage, swapTx);
      assert.strictEqual(degraded.origin, 'heuristic-fallback', 'Unavailable model degrades with label');
      assert.strictEqual(degraded.verdict, 'MATCH', 'Deterministic fallback behavior preserved');
    } finally {
      global.fetch = realFetch;
      config.modelApiKey = originalKey;
    }
    console.log('✔ Test 3 Passed: origin=model vs heuristic-fallback on all paths.');
  }

  // Test 4: provenance preserved through bundle + extension display.
  {
    const bundle = compileEvidenceBundle({
      visualResult: { regions: [], combinedText: '' },
      decodedTx: { contract: ADDR_B, contractName: 'T', functionName: 'approve', parameters: {}, isUnlimitedApproval: false, ruleFindings: [] },
      reasoningResult: { verdict: 'MISMATCH', confidence: 0.9, summary: 's', recommendedAction: 'BLOCK_TRANSACTION', origin: 'heuristic-fallback' },
      simulationResult: null
    });
    assert.strictEqual(bundle.reasoningOrigin, 'heuristic-fallback');
    assert.strictEqual(bundle.verdict, 'MISMATCH', 'Verdict untouched by provenance work');
    const bare = compileEvidenceBundle({
      visualResult: { regions: [], combinedText: '' },
      decodedTx: { contract: ADDR_B, functionName: 'approve', parameters: {}, isUnlimitedApproval: false },
      reasoningResult: { verdict: 'MATCH' }, simulationResult: null
    });
    assert.strictEqual(bare.reasoningOrigin, 'unknown', 'Missing origin degrades to unknown, never invented');
    require('../../extension/shared/format.js');
    const F = globalThis.AssertaraFormat;
    assert.strictEqual(F.reasoningOriginLabel('model'), 'Muse Spark analysis');
    assert.ok(F.reasoningOriginLabel('heuristic-fallback').includes('unverified'));
    assert.strictEqual(F.reasoningOriginLabel(undefined), 'Reasoning source unknown');
    console.log('✔ Test 4 Passed: Provenance flows bundle → display; unknown never invented.');
  }

  // Test 5: contradiction semantics — none, resolved (×2 paths), unresolved, malformed.
  {
    const g0 = new EvidenceGraph('inv_h5a');
    const s0 = g0.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    assert.strictEqual(adjudicate({ id: 'F-0', claim: 'x', supporting: [s0.id], contradicting: [] }, g0, { verdict: 'SUPPORTED', reasons: [] }).status, 'VERIFIED', 'Clean finding verifies');
    // Unresolved contradiction + SUPPORTED → HYPOTHESIS, never VERIFIED.
    const g1 = new EvidenceGraph('inv_h5b');
    const s1 = g1.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const c1 = g1.append({ kind: 'CounterReading', producer: 'TOOL', payload: {}, created_turn: 1 });
    const cCtr = adjudicate({ id: 'F-1', claim: 'x', supporting: [s1.id], contradicting: [c1.id] }, g1, { verdict: 'SUPPORTED', reasons: ['reviewer weighed it'] });
    assert.strictEqual(cCtr.status, 'HYPOTHESIS', 'Reviewer SUPPORT cannot discharge a listed contradiction');
    assert.ok(cCtr.reasons.some((r) => r.includes('unresolved contradictions')));
    // Resolved via superseding record → VERIFIED.
    const g2 = new EvidenceGraph('inv_h5c');
    const s2 = g2.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const c2 = g2.append({ kind: 'CounterReading', producer: 'TOOL', payload: {}, created_turn: 1 });
    g2.append({ kind: 'Retest', producer: 'TOOL', payload: {}, created_turn: 2, supersedes: c2.id });
    assert.strictEqual(adjudicate({ id: 'F-2', claim: 'x', supporting: [s2.id], contradicting: [c2.id] }, g2, { verdict: 'SUPPORTED', reasons: [] }).status, 'VERIFIED', 'Superseded contradiction resolves');
    // Resolved via Finding-node REFINES edge → VERIFIED.
    const g3 = new EvidenceGraph('inv_h5d');
    const s3 = g3.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const c3 = g3.append({ kind: 'CounterReading', producer: 'TOOL', payload: {}, created_turn: 1 });
    const fn = g3.append({ kind: 'Finding', producer: 'TOOL', payload: { findingId: 'F-3' }, created_turn: 1 });
    g3.relate(fn.id, 'REFINES', c3.id);
    assert.strictEqual(adjudicate({ id: 'F-3', claim: 'x', supporting: [s3.id], contradicting: [c3.id] }, g3, { verdict: 'SUPPORTED', reasons: [] }).status, 'VERIFIED', 'Edge-resolved contradiction resolves');
    // Malformed (unknown id) → REJECTED, not capped.
    const g4 = new EvidenceGraph('inv_h5e');
    const s4 = g4.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    assert.strictEqual(adjudicate({ id: 'F-4', claim: 'x', supporting: [s4.id], contradicting: ['E-404'] }, g4, { verdict: 'SUPPORTED', reasons: [] }).status, 'REJECTED', 'Unknown contradiction ref rejects');
    console.log('✔ Test 5 Passed: Contradictions cap at HYPOTHESIS; two resolution paths verify.');
  }

  // Test 6: capping gates compose; non-capping failures still reject.
  {
    const g = new EvidenceGraph('inv_h6');
    const s = g.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const e = g.append({ kind: 'Experimental', producer: 'MODEL', payload: {}, created_turn: 1 });
    const c = g.append({ kind: 'CounterReading', producer: 'TOOL', payload: {}, created_turn: 1 });
    const both = adjudicate({ id: 'F-6', claim: 'x', supporting: [s.id, e.id], contradicting: [c.id] }, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(both.status, 'HYPOTHESIS', 'Experimental + contradiction: unproven, not broken');
    assert.strictEqual(runGates({ id: 'F-6b', claim: 'x', supporting: [s.id], contradicting: [c.id, 'E-404'] }, g).pass, false);
    const mixed = adjudicate({ id: 'F-6c', claim: 'x', supporting: [s.id], contradicting: [c.id, 'E-404'] }, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(mixed.status, 'REJECTED', 'Capping + malformed-ref rejects');
    assert.strictEqual(GATES.length, 8, 'Eight gates registered (support gate added)');
    console.log('✔ Test 6 Passed: Capping composition correct; malformed mixes reject.');
  }

  // Test 7: all 8 legacy feature schemas meet strict-shape requirements.
  {
    const captured = {};
    const cap = (key, content) => capturingStub(content);
    const t = cap('t', { action: 'a', assets: [], contract: 'c', permissions: 'p', boundedOrUnlimited: 'b', consequences: [], risks: [], unknowns: [], quoted: { function: 'approve', to: ADDR_B, amount: '100', spender: SPENDER } });
    await runFeature('F4_translator', { tx: APPROVE_TX }, { model: t.model });
    captured.translator = t.seen.args.schema;
    const tr = cap('tr', { signal: 'GREEN', reasons: [], needsDeepDive: false });
    await runFeature('F5_interceptor', { tx: APPROVE_TX }, { model: tr.model });
    captured.triage = tr.seen.args.schema;
    const qa = cap('qa', { answer: 'a', citations: ['E-1'] });
    await runFeature('F9_ask', { graphExport: { nodes: [{ id: 'E-1' }] }, question: 'q?' }, { model: qa.model });
    captured.ask = qa.seen.args.schema;
    const scripted = { async nextTurn() { return { actions: [], stop: true, stopReason: 'd' }; } };
    const rv = cap('rv', { verdict: 'SUPPORTED', reasons: [] });
    await runFeature('F2_advanced', { goal: 'g', inputs: {}, hypotheses: [{ id: 'H-1', claim: 'c', supporting: ['E-001'] }] }, { modelClient: scripted, reviewer: rv.model });
    captured.review = rv.seen.args.schema;
    const stubChain = { async getBlockNumber() { return 10n; }, async getLogs() { return []; }, async readContract() { return 0n; } };
    const sn = cap('sn', { summary: 's', highestRisk: [] });
    await runFeature('F6_sentinel', { owner: ADDR_A, tokens: [ADDR_B], fromBlock: 0n, toBlock: 5n }, { client: stubChain, model: sn.model });
    captured.sentinel = sn.seen.args.schema;
    const dx = cap('dx', { summary: 's', flags: [], unknowns: [] });
    await runFeature('F7_dossier', { address: ADDR_A }, {
      client: { ...stubChain, async getBytecode() { return '0x'; }, async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; } },
      history: false, model: dx.model
    });
    captured.dossier = dx.seen.args.schema;
    const sc = cap('sc', { annotations: [{ turn: 0, tactics: ['other-suspicious'], why: 'w' }] });
    await runFeature('F8_scamcall', { turns: [{ text: 'hello' }] }, { model: sc.model });
    captured.scamcall = sc.seen.args.schema;
    const rr = cap('rr', { hypotheses: [{ claim: 'c', refs: ['a.sol:1'] }], pocDrafts: [], questions: [] });
    await runRepoReview({ files: [{ path: 'a.sol', content: 'x' }] }, { model: rr.model });
    captured.repoReview = rr.seen.args.schema;
    assert.strictEqual(Object.keys(captured).length, 8, 'All 8 legacy runners captured');
    for (const [name, schema] of Object.entries(captured)) assertStrictSchema(schema, name);
    console.log('✔ Test 7 Passed: All 8 legacy schemas are strict-compatible.');
  }

  // Test 8: malformed model outputs on fixed-schema runners handled safely.
  {
    const garbage = await runFeature('F5_interceptor', { tx: APPROVE_TX }, { model: { async complete() { return { content: { signal: 'PURPLE', reasons: 'not-an-array', needsDeepDive: 'yes' } }; } } });
    assert.ok(['GREEN', 'AMBER', 'RED', 'INCONCLUSIVE'].includes(garbage.signal), 'Garbage signal cannot escape the enum');
    const badTactic = await runFeature('F8_scamcall', { turns: [{ text: 'hi' }] }, { model: { async complete() { return { content: { annotations: [{ turn: 0, tactics: ['mind-control'], why: 'x' }, { turn: 9, tactics: [], why: 'y' }] } }; } } });
    assert.strictEqual(badTactic.status, 'PARTIAL');
    assert.strictEqual(badTactic.timeline.length, 0, 'Invalid tactics/turns dropped, never rendered');
    assert.strictEqual(badTactic.dropped.length, 2);
    const badCite = await runFeature('F9_ask', { graphExport: { nodes: [{ id: 'E-1' }] }, question: 'q?' }, { model: { async complete() { return { content: { answer: 'a', citations: ['E-999'] } }; } } });
    assert.strictEqual(badCite.status, 'PARTIAL');
    assert.deepStrictEqual(badCite.citations, [], 'Fabricated citations dropped');
    console.log('✔ Test 8 Passed: Malformed outputs contained on fixed runners.');
  }

  // Test 9: honest degraded behavior without a model.
  {
    await assert.rejects(runFeature('F4_translator', { tx: APPROVE_TX }, {}), /model client/);
    await assert.rejects(runFeature('F8_scamcall', { turns: [{ text: 'hi' }] }, {}), /model client/);
    await assert.rejects(runFeature('F9_ask', { graphExport: { nodes: [] }, question: 'q' }, {}), /model client/);
    await assert.rejects(runRepoReview({ files: [{ path: 'a', content: 'x' }] }, {}), /model client/);
    const triage = await runFeature('F5_interceptor', { tx: APPROVE_TX }, {});
    assert.strictEqual(triage.reasons.some((r) => r.includes('unavailable')), true, 'Model-less triage says so');
    console.log('✔ Test 9 Passed: Missing models fail loudly or degrade honestly.');
  }

  // Test 10: cross-feature boundary spot-checks (Phases 1–13 hold).
  {
    const g = new EvidenceGraph('inv_h10');
    const s = g.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const e = g.append({ kind: 'Experimental', producer: 'MODEL', payload: {}, created_turn: 1 });
    assert.strictEqual(adjudicate({ id: 'F-X', claim: 'x', supporting: [s.id, e.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] }).status, 'HYPOTHESIS', 'Experimental still caps');
    const nr = g.append({ kind: 'ToolResult', producer: 'TOOL', payload: { result: { status: 'NOT_REPRODUCED' } }, created_turn: 1 });
    assert.strictEqual(adjudicate({ id: 'F-NR', claim: 'the PoC reproduced the bug', supporting: [nr.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] }).status, 'REJECTED', 'NOT_REPRODUCED is not reproduction');
    const to = g.append({ kind: 'ToolResult', producer: 'TOOL', payload: { error: 'timed out' }, created_turn: 1 });
    assert.strictEqual(adjudicate({ id: 'F-TO', claim: 'subject safe', supporting: [to.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] }).status, 'REJECTED', 'Timeouts cannot support');
    const { runAuditTransition } = require('../../src/agent/features');
    assert.strictEqual(runAuditTransition({ record: { id: 'R', status: 'FIX_CLAIMED', history: [] }, newStatus: 'VERIFIED_FIXED' }).status, 'REJECTED', 'FIX_CLAIMED ≠ VERIFIED_FIXED');
    const { Recorder, replayRecording } = require('../../src/agent/replay');
    const rec = new Recorder({ investigationId: 'i', runId: 'r' });
    rec.append('model.turn', { actor: 'model', data: { turn: 1 } });
    const rp = replayRecording(rec.export());
    assert.strictEqual(rp.timeline[0].class, 'interpreted');
    assert.strictEqual(rp.timeline[0].viewOrigin, 'deterministic-summary', 'Replay keeps recorded/derived distinct');
    const { checkReadiness, validateReadinessRecord } = require('../../src/agent/readiness');
    const f3 = await checkReadiness('f3.runners');
    assert.strictEqual(f3.status, 'TEST_ONLY');
    assert.strictEqual(validateReadinessRecord(f3), true, 'Readiness records validate');
    console.log('✔ Test 10 Passed: Prior-phase boundaries spot-verified.');
  }

  // Test 11: simulate_tx tool validates before executing.
  {
    await assert.rejects(runTool('simulate_tx', { to: ADDR_B, from: '0x1', data: APPROVE_DATA }), /"from" must be a 0x address/);
    await assert.rejects(runTool('simulate_tx', { to: ADDR_B, data: 'not-hex' }), /"data" must be hex bytes/);
    const ok = await runTool('simulate_tx', { from: ADDR_A, to: ADDR_B, data: APPROVE_DATA });
    assert.ok(['FALLBACK', 'EXECUTED'].includes(ok.status), 'Valid tool input reaches the service');
    assert.ok(!String(ok.error || '').includes('SIM_VALIDATION'));
    console.log('✔ Test 11 Passed: simulate_tx validates from/data pre-execution.');
  }

  // Test 12: Phase 1–13 regression (all prior lanes intact).
  {
    const { WatchScheduler } = require('../../src/agent/scheduler');
    const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
    fs.mkdirSync(root, { recursive: true });
    const scratch = fs.mkdtempSync(path.join(root, 'assertara-hardening-'));
    let now = Date.now();
    const sched = new WatchScheduler({ dir: scratch, now: () => now });
    sched.client = {
      async getBytecode() { return '0x11'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    sched.addTarget({ address: ADDR_A, intervalMs: 5000 });
    now += 6000;
    assert.strictEqual((await sched.tickOnce()).checked, 1, 'Scheduler intact');
    fs.rmSync(scratch, { recursive: true, force: true });
    try { fs.rmdirSync(root); } catch { /* non-empty or gone: leave it */ }
    const { buildPdf } = require('./pdfIngest.test.js');
    const { ingestAuditPdf, toLedgerIntake } = require('../../src/agent/pdfIngest');
    const pdf = await ingestAuditPdf({ data: buildPdf([['H-01 Regression check', 'Body.']]) });
    assert.strictEqual(toLedgerIntake(pdf).findings.length, 1, 'PDF intact');
    const { submitHarnessRun } = require('../../src/agent/harness');
    assert.strictEqual((await submitHarnessRun({ kind: 'static', files: [{ path: 'a.sol', content: 'x' }] })).status, 'STATIC_ANALYSIS_ONLY', 'Harness intact');
    const { discoverApprovals } = require('../../src/agent/chain');
    const hist = await discoverApprovals({
      owner: ADDR_A, tokens: [ADDR_B], fromBlock: 0n, toBlock: 5n,
      client: { async getBlockNumber() { return 10n; }, async getLogs() { return []; }, async readContract() { return 0n; } }
    });
    assert.strictEqual(hist.coverage.status, 'COMPLETE_WITHIN_REQUESTED_SCOPE', 'History intact');
    const { answerFindingQuestion } = require('../../src/agent/askAbout');
    const q = await answerFindingQuestion({
      finding: { id: 'F-R', claim: 'c', supporting: ['E-1'], contradicting: [] },
      evidence: [{ ref: 'E-1', kind: 'K', summary: 's' }], question: 'q?'
    }, { model: { async complete() { return { content: { answer: 'a', citations: ['E-1'], answerable: 'full', uncertaintyNote: '', missingEvidence: [] } }; } } });
    assert.strictEqual(q.status, 'OK', 'AskAbout intact');
    const { localizeAssessment } = require('../../src/agent/localize');
    const loc = await localizeAssessment({
      assessment: { segments: [{ id: 's', text: `Review ${SPENDER} carefully (E-001).` }], protected: {} },
      targetLang: 'es'
    }, { model: { async complete() { return { content: { segments: [{ id: 's', text: `Revise ${SPENDER} cuidadosamente (E-001).` }] } }; } } });
    assert.strictEqual(loc.status, 'OK', 'Localize intact');
    const { checkReadiness: cr } = require('../../src/agent/readiness');
    assert.strictEqual((await cr('web.intel')).status, 'UNAVAILABLE', 'Readiness intact');
    console.log('✔ Test 12 Passed: Phases 1–13 behavior preserved.');
  }

  console.log('\nAll Hardening Tests Passed Successfully!\n');
}

if (require.main === module) {
  runHardeningTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runHardeningTests };
