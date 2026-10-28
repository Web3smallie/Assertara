const assert = require('assert');
const {
  READINESS_STATUSES, EXECUTION_EVIDENCE, EXECUTION_KINDS,
  CAPABILITIES, listCapabilities,
  validateReadinessRecord, checkReadiness, checkAllReadiness
} = require('../../src/agent/readiness');
const { EvidenceGraph } = require('../../src/agent/evidenceGraph');
const { adjudicate, runGates, GATES, FAILED_TOOL_STATUSES } = require('../../src/agent/verifier');
const { TOOLS, runTool, describeTools } = require('../../src/agent/toolRegistry');

const EXPECTED_IDS = [
  'f3.runners', 'core.local', 'exec.harness', 'media.stt', 'media.frames',
  'media.ocr', 'sim.forge', 'chain.history', 'chain.source',
  'model.spark', 'model.sam', 'monitor.push', 'web.intel'
];

function toolNode(g, result, turn = 1) {
  return g.append({ kind: 'ToolResult', producer: 'TOOL', tool_ref: 'probe-tool', payload: { result }, created_turn: turn });
}

function okRecord(over = {}) {
  return {
    capability: 'test.cap', name: 'Test', status: 'READY',
    checked: ['x'], succeeded: ['x'], failed: [], unknown: [],
    dependencies: [], executedWith: 'live', evidence: {},
    checkedAt: new Date().toISOString(), ...over
  };
}

async function runReadinessTests() {
  console.log('Testing Experimental Audit: Inventory, Readiness & Boundaries...\n');

  // Test 1: inventory is complete, shaped, and drops nothing silently.
  {
    assert.deepStrictEqual(listCapabilities().sort(), [...EXPECTED_IDS].sort(), '13 capabilities, no silent removals');
    for (const id of EXPECTED_IDS) {
      const c = CAPABILITIES[id];
      assert.strictEqual(c.id, id);
      for (const k of ['name', 'purpose', 'classification', 'classificationEvidence']) {
        assert.ok(typeof c[k] === 'string' && c[k].length > 0, `${id}.${k} non-empty`);
      }
      assert.ok(READINESS_STATUSES.includes(c.classification), `${id} classification valid`);
      assert.ok(EXECUTION_KINDS.includes(c.executionKind), `${id} executionKind valid`);
      assert.ok(Array.isArray(c.limitations) && c.limitations.length > 0, `${id} documents limitations`);
      assert.ok(Array.isArray(c.tests) && c.tests.length > 0, `${id} names proving tests`);
      assert.strictEqual(typeof c.check, 'function', `${id} has an automated check`);
      if (c.entryPoint === null) {
        assert.strictEqual(c.classification, 'UNAVAILABLE', `${id}: null entryPoint only for documented gaps`);
      }
    }
    console.log('✔ Test 1 Passed: 13-capability inventory complete and shaped.');
  }

  // Test 2: all five readiness statuses, honestly produced.
  {
    const ready = await checkReadiness('core.local');
    assert.strictEqual(ready.status, 'READY');
    assert.strictEqual(ready.executedWith, 'live');
    const partial = await checkReadiness('sim.forge', {
      probe: async () => ({ ok: true, version: '1.7.1' }),
      existsSync: () => false
    });
    assert.strictEqual(partial.status, 'PARTIAL');
    assert.strictEqual(partial.executedWith, 'mock');
    assert.ok(partial.failed.some((f) => f.includes('forge-std')));
    const unavail = await checkReadiness('exec.harness', {
      probe: async () => ({ ok: false, error: 'not-installed' })
    });
    assert.strictEqual(unavail.status, 'UNAVAILABLE');
    // Phase 18: the adapter ships; runtime + verified image are the blockers.
    assert.ok(unavail.failed.some((f) => f.includes('verified sandbox image')));
    assert.strictEqual(unavail.evidence.adapter, 'shipped');
    assert.ok(unavail.evidence.adapterNote.includes('live execution unverified here'));
    const testOnly = await checkReadiness('f3.runners');
    assert.strictEqual(testOnly.status, 'TEST_ONLY');
    assert.ok(testOnly.evidence.testOnlyReason.length > 0);
    const failed = await checkReadiness('exec.harness', {
      probe: async () => { throw new Error('probe exploded'); }
    });
    assert.strictEqual(failed.status, 'FAILED_CHECK');
    assert.ok(failed.failed.some((f) => f.includes('probe exploded')));
    // Full sweep stays offline-safe and self-consistent.
    const all = await checkAllReadiness();
    assert.strictEqual(Object.keys(all.results).length, EXPECTED_IDS.length);
    assert.ok(Object.values(all.results).every((r) => validateReadinessRecord(r) === true));
    assert.strictEqual(Object.values(all.summary).reduce((a, b) => a + b, 0), EXPECTED_IDS.length);
    console.log('✔ Test 2 Passed: READY/PARTIAL/UNAVAILABLE/TEST_ONLY/FAILED_CHECK all produced.');
  }

  // Test 3: missing deps and failed probes never upgrade to success.
  {
    // Daemon present but no verified image: still UNAVAILABLE, never READY/PARTIAL.
    const daemonUp = await checkReadiness('exec.harness', {
      probe: async (bin) => (bin === 'docker'
        ? { ok: true, version: '99.0.0' }
        : { ok: false, error: 'not-installed' })
    });
    assert.strictEqual(daemonUp.status, 'UNAVAILABLE', 'Daemon without verified image is not readiness');
    assert.ok(daemonUp.failed.some((f) => f.includes('verified sandbox image')));
    // Unknown capability id throws loudly instead of inventing a record.
    await assert.rejects(checkReadiness('nope.missing'), (e) => e.code === 'UNKNOWN_CAPABILITY');
    // Live chain probe without a target throws instead of hitting a default.
    await assert.rejects(checkReadiness('chain.history', { live: true }), (e) => e.code === 'LIVE_NEEDS_TARGET');
    console.log('✔ Test 3 Passed: Absent deps stay failed; no silent upgrades.');
  }

  // Test 4: live execution and test doubles are inseparably labeled.
  {
    const mocked = await checkReadiness('media.stt', { probe: async () => ({ ok: false, error: 'x' }) });
    assert.strictEqual(mocked.executedWith, 'mock', 'Injected probe is labeled mock');
    const probed = await checkReadiness('media.stt');
    assert.strictEqual(probed.executedWith, 'probe', 'Real local probe is labeled probe');
    const fixture = await checkReadiness('chain.history');
    assert.strictEqual(fixture.executedWith, 'fixture');
    assert.ok(fixture.unknown.some((u) => u.includes('reachability')));
    const live = await checkReadiness('core.local');
    assert.strictEqual(live.executedWith, 'live');
    for (const r of [mocked, probed, fixture, live]) {
      assert.ok(!Number.isNaN(Date.parse(r.checkedAt)), 'Every record carries a timestamp');
    }
    // Config-key checks record presence booleans, never key material.
    const spark = await checkReadiness('model.spark', { apiKey: 'sk-should-never-appear-abcdef123456' });
    assert.strictEqual(spark.evidence.configured, true);
    assert.ok(!JSON.stringify(spark).includes('sk-should-never-appear'));
    console.log('✔ Test 4 Passed: live/fixture/mock/probe labels + timestamps; no key material.');
  }

  // Test 5: experimental evidence still cannot verify (gate regression).
  {
    const g = new EvidenceGraph('inv_r13e');
    const stable = g.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const exp = g.append({ kind: 'Experimental', producer: 'MODEL', payload: {}, created_turn: 1 });
    const tainted = { id: 'F-E', claim: 'x', supporting: [stable.id, exp.id], contradicting: [] };
    const capped = adjudicate(tainted, g, { verdict: 'SUPPORTED', reasons: ['ok'] });
    assert.strictEqual(capped.status, 'HYPOTHESIS');
    assert.ok(capped.reasons.some((r) => r.includes('experimental')));
    const { runExperimental } = require('../../src/agent/features');
    assert.strictEqual(runExperimental({}).status, 'GATED');
    assert.strictEqual(runExperimental({ allowExperimental: true }).status, 'EXPERIMENTAL');
    console.log('✔ Test 5 Passed: Experimental gate holds at HYPOTHESIS.');
  }

  // Test 6: failed/unavailable/mock tool evidence cannot support a finding.
  {
    const cases = [
      ['EXECUTION_UNAVAILABLE', { status: 'EXECUTION_UNAVAILABLE' }],
      ['EXECUTION_FAILED', { status: 'EXECUTION_FAILED' }],
      ['EXECUTION_TIMED_OUT', { status: 'EXECUTION_TIMED_OUT' }],
      ['TRANSCRIPTION_UNAVAILABLE', { status: 'TRANSCRIPTION_UNAVAILABLE' }],
      ['BACKEND_ERROR', { status: 'BACKEND_ERROR' }],
      ['VIDEO_PROCESSING_UNAVAILABLE', { status: 'VIDEO_PROCESSING_UNAVAILABLE' }],
      ['simulator FAILED', { status: 'FAILED', executed: false }],
      ['generic UNAVAILABLE', { status: 'UNAVAILABLE' }]
    ];
    for (const [label, result] of cases) {
      const g = new EvidenceGraph('inv_r13f');
      const n = toolNode(g, result);
      const r = adjudicate({ id: 'F-F', claim: 'the subject is safe', supporting: [n.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: ['ok'] });
      assert.strictEqual(r.status, 'REJECTED', `${label} must reject, not verify`);
      assert.ok(r.reasons.some((x) => x.includes('failed/unavailable/mock')), `${label} reason names the boundary`);
    }
    // Error-only payloads (orchestrator tool failures/timeouts) also reject.
    {
      const g = new EvidenceGraph('inv_r13t');
      const n = g.append({ kind: 'ToolResult', producer: 'TOOL', tool_ref: 'decode_tx', payload: { error: 'decode_tx timed out after 30ms' }, created_turn: 1 });
      const r = adjudicate({ id: 'F-T', claim: 'the subject is safe', supporting: [n.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] });
      assert.strictEqual(r.status, 'REJECTED', 'Timeout/error payloads cannot support findings');
    }
    // Mock-mode results (labeled but fabricated) also reject.
    {
      const g = new EvidenceGraph('inv_r13m');
      const n = toolNode(g, { success: true, mode: 'mock', regions: [{ label: 'x' }] });
      const r = adjudicate({ id: 'F-M', claim: 'the button is at (120,380)', supporting: [n.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] });
      assert.strictEqual(r.status, 'REJECTED', 'Mock results cannot support findings');
    }
    // Control: genuine EXECUTED + non-trigger claim still verifies.
    {
      const g = new EvidenceGraph('inv_r13c');
      const n = toolNode(g, { status: 'EXECUTED', executed: true, success: true });
      const r = adjudicate({ id: 'F-C', claim: 'the approval is unlimited', supporting: [n.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: ['ok'] });
      assert.strictEqual(r.status, 'VERIFIED', 'Genuine artifacts keep working');
    }
    // FALLBACK and TRANSCRIPTION_PARTIAL stay citable (real, partial evidence).
    {
      const g = new EvidenceGraph('inv_r13p');
      const n = toolNode(g, { status: 'FALLBACK', executed: false });
      const r = adjudicate({ id: 'F-P', claim: 'the approval is unlimited', supporting: [n.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: ['ok'] });
      assert.strictEqual(r.status, 'VERIFIED', 'FALLBACK is honest evidence, not failure');
    }
    assert.ok(FAILED_TOOL_STATUSES.has('EXECUTION_UNAVAILABLE') && GATES.length === 8, 'Eight gates after the support gate (driver phase)');
    console.log('✔ Test 6 Passed: Failures/timeouts/mocks reject; genuine + fallback cite cleanly.');
  }

  // Test 7: harness reproduction vocabulary recognized; near-misses rejected.
  {
    const claim = 'the PoC reproduced the reentrancy on the test contract';
    for (const genuine of ['VULNERABILITY_REPRODUCED', 'PATCH_VERIFIED']) {
      const g = new EvidenceGraph('inv_r13g');
      const n = toolNode(g, { status: genuine, criterionMet: true });
      const gates = runGates({ id: 'F-G', claim, supporting: [n.id], contradicting: [] }, g);
      assert.strictEqual(gates.pass, true, `${genuine} is a genuine artifact`);
    }
    for (const [label, result] of [
      ['NOT_REPRODUCED', { status: 'NOT_REPRODUCED', criterionMet: false }],
      ['EXECUTION_COMPLETED', { status: 'EXECUTION_COMPLETED' }],
      ['STATIC_ANALYSIS_ONLY', { status: 'STATIC_ANALYSIS_ONLY' }]
    ]) {
      const g = new EvidenceGraph('inv_r13n');
      const n = toolNode(g, result);
      const r = adjudicate({ id: 'F-N', claim, supporting: [n.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] });
      assert.strictEqual(r.status, 'REJECTED', `${label} must not satisfy an execution claim`);
    }
    // Pre-existing behavior preserved: EXECUTED + passed:true still genuine.
    const g = new EvidenceGraph('inv_r13e2');
    const n = toolNode(g, { status: 'EXECUTED', executed: true });
    assert.strictEqual(runGates({ id: 'F-E2', claim, supporting: [n.id], contradicting: [] }, g).pass, true);
    console.log('✔ Test 7 Passed: Reproduced/patch-verified genuine; completion/static/absence rejected.');
  }

  // Test 8: timeouts and unavailable lanes never return success shapes.
  {
    const { submitHarnessRun } = require('../../src/agent/harness');
    const unavail = await submitHarnessRun({ kind: 'execute', files: [{ path: 't.js', content: 'x' }], entry: { tool: 'node', args: ['t.js'] } });
    assert.strictEqual(unavail.status, 'EXECUTION_UNAVAILABLE');
    assert.ok(unavail.executed !== true && unavail.status !== 'EXECUTED');
    assert.ok(Array.isArray(unavail.requirements) && unavail.requirements.length > 0);
    const hangRoot = require('path').join(__dirname, '..', '..', 'data', '.test-tmp', 'r13-hang');
    let hanging;
    try {
      hanging = await submitHarnessRun(
        { kind: 'execute', files: [{ path: 't.js', content: 'x' }], entry: { tool: 'node', args: ['t.js'] }, timeoutMs: 1000 },
        { executor: { name: 'never-resolves', run: () => new Promise(() => {}) }, workspaceRoot: hangRoot }
      );
    } finally {
      require('fs').rmSync(hangRoot, { recursive: true, force: true });
    }
    assert.strictEqual(hanging.status, 'EXECUTION_TIMED_OUT');
    assert.ok(!JSON.stringify(hanging).includes('VULNERABILITY_REPRODUCED'));
    const { ingestAudio } = require('../../src/agent/audioIngest');
    const wav = Buffer.alloc(44);
    wav.write('RIFF', 0); wav.writeUInt32LE(36, 4); wav.write('WAVEfmt ', 8); wav.writeUInt32LE(16, 16);
    wav.writeUInt16LE(1, 20); wav.writeUInt16LE(1, 22); wav.writeUInt32LE(8000, 24);
    wav.writeUInt32LE(8000, 28); wav.writeUInt16LE(1, 32); wav.writeUInt16LE(8, 34); wav.write('data', 36);
    const noStt = await ingestAudio({ data: wav });
    assert.strictEqual(noStt.status, 'TRANSCRIPTION_UNAVAILABLE');
    const { ingestVideo } = require('../../src/agent/videoIngest');
    const mp4 = Buffer.concat([Buffer.from([0, 0, 0, 24, 102, 116, 121, 112, 105, 115, 111, 109]), Buffer.alloc(64)]);
    const noExt = await ingestVideo({ data: mp4 });
    assert.strictEqual(noExt.status, 'VIDEO_PROCESSING_UNAVAILABLE');
    console.log('✔ Test 8 Passed: Unavailable/timeout lanes carry requirements, never results.');
  }

  // Test 9: malformed and self-contradictory readiness records rejected.
  {
    assert.strictEqual(validateReadinessRecord(okRecord()), true);
    assert.throws(() => validateReadinessRecord(okRecord({ status: 'READY', failed: ['x'] })), (e) => e.code === 'READY_WITH_GAPS');
    assert.throws(() => validateReadinessRecord(okRecord({ status: 'READY', unknown: ['x'] })), (e) => e.code === 'READY_WITH_GAPS');
    assert.throws(() => validateReadinessRecord(okRecord({ status: 'UNAVAILABLE', succeeded: ['x'] })), (e) => e.code === 'UNAVAILABLE_WITH_SUCCESS');
    assert.throws(() => validateReadinessRecord(okRecord({ status: 'PARTIAL', failed: [], unknown: [] })), (e) => e.code === 'BAD_PARTIAL');
    assert.throws(() => validateReadinessRecord(okRecord({ status: 'PARTIAL', succeeded: [] })), (e) => e.code === 'BAD_PARTIAL');
    assert.throws(() => validateReadinessRecord(okRecord({ status: 'FAILED_CHECK' })), (e) => e.code === 'BAD_FAILED_CHECK');
    assert.throws(() => validateReadinessRecord(okRecord({ status: 'TEST_ONLY' })), (e) => e.code === 'BAD_TEST_ONLY');
    assert.throws(() => validateReadinessRecord(okRecord({ status: 'MAYBE' })), (e) => e.code === 'BAD_STATUS');
    assert.throws(() => validateReadinessRecord(okRecord({ executedWith: 'vibes' })), (e) => e.code === 'BAD_EVIDENCE_KIND');
    assert.throws(() => validateReadinessRecord(okRecord({ checked: [] })), (e) => e.code === 'BAD_RECORD');
    assert.throws(() => validateReadinessRecord(okRecord({ checkedAt: 'not-a-date' })), (e) => e.code === 'BAD_RECORD');
    assert.throws(() => validateReadinessRecord(okRecord({ evidence: { k: 'sk-abcdefghijklmnopqrst' } })), (e) => e.code === 'SECRET_LEAK');
    assert.throws(() => validateReadinessRecord(null), (e) => e.code === 'BAD_RECORD');
    console.log('✔ Test 9 Passed: Record validator enforces shape + invariants + secrecy.');
  }

  // Test 10: registries, maps, and boundaries agree.
  {
    const sm = await runTool('schedule_monitor', {});
    assert.strictEqual(sm.status, 'UNAVAILABLE');
    assert.ok(sm.requirements.some((r) => r.includes('scheduler.js')), 'Boundary names the real scheduler');
    assert.ok(sm.requirements.some((r) => r.includes('authorization')), 'Boundary states the authorization rule');
    for (const t of Object.values(TOOLS)) {
      assert.strictEqual(typeof t.run, 'function', `${t.name} has a run function`);
      assert.ok(/transition|ledger|adjudicat|setstatus|verifyfinding/i.test(t.name) === false, `${t.name} cannot reach verification state`);
      if (t.status === 'UNAVAILABLE') assert.ok(t.requirements.length > 0, `${t.name} lists requirements`);
    }
    const described = describeTools();
    assert.strictEqual(described.length, Object.keys(TOOLS).length);
    assert.ok(described.every((t) => ['AVAILABLE', 'UNAVAILABLE'].includes(t.status)));
    const { FEATURES } = require('../../src/agent/features');
    assert.strictEqual(Object.keys(FEATURES).length, 15, 'All 15 areas remain mapped');
    assert.strictEqual(FEATURES.F3_experimental.status, 'EXPERIMENTAL');
    console.log('✔ Test 10 Passed: Tool/feature registries consistent; verification unreachable by tools.');
  }

  // Test 11: static review ≠ reproduction; generated patch ≠ verified fix.
  {
    const { submitHarnessRun } = require('../../src/agent/harness');
    const statik = await submitHarnessRun({ kind: 'static', files: [{ path: 'V.sol', content: 'x' }] });
    assert.strictEqual(statik.status, 'STATIC_ANALYSIS_ONLY');
    const g = new EvidenceGraph('inv_r13s');
    const n = toolNode(g, { status: 'STATIC_ANALYSIS_ONLY' });
    const r = adjudicate({ id: 'F-S', claim: 'review reproduced the bug dynamically', supporting: [n.id], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(r.status, 'REJECTED', 'Static review cannot satisfy a reproduction claim');
    const { runRepoReview, runAuditTransition } = require('../../src/agent/features');
    const review = await runRepoReview({ files: [{ path: 'V.sol', content: 'line1\nline2' }], concern: 'reentrancy' }, {
      model: { async complete() { return { content: { hypotheses: [{ claim: 'c', refs: ['V.sol:1'] }], pocDrafts: ['draft'], questions: [] } }; } }
    });
    assert.ok(review.pocDrafts.every((p) => p.status === 'UNEXECUTED'), 'PoC drafts stay unexecuted text');
    const noProof = runAuditTransition({ record: { id: 'R-1', status: 'FIX_CLAIMED', history: [] }, newStatus: 'VERIFIED_FIXED' });
    assert.strictEqual(noProof.status, 'REJECTED', 'VERIFIED_FIXED needs passing-test evidence');
    const proven = runAuditTransition({ record: { id: 'R-1', status: 'FIX_CLAIMED', history: [] }, newStatus: 'VERIFIED_FIXED', testEvidence: { passed: true, logs: 'suite green' } });
    assert.strictEqual(proven.status, 'OK', 'Real proof still transitions');
    const { evaluateCriterion } = require('../../src/agent/harness');
    assert.strictEqual(evaluateCriterion({ type: 'exit-code', code: 0 }, { exitCode: 1, stdout: '', stderr: '' }), false);
    console.log('✔ Test 11 Passed: Static ≠ reproduced; VERIFIED_FIXED keeps its proof bar.');
  }

  // Test 12: Phase 1–12 regression (all prior lanes intact).
  {
    const { adjudicate: adj } = require('../../src/agent/verifier');
    const g = new EvidenceGraph('inv_phase13reg');
    const exp = g.append({ kind: 'ModelReading', producer: 'MODEL', payload: { experimental: true }, created_turn: 1 });
    assert.strictEqual(adj({ supporting: [exp.id], conflicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] }).status, 'HYPOTHESIS', 'Phase 1 intact');
    const { WatchScheduler } = require('../../src/agent/scheduler');
    const fs = require('fs');
    const path = require('path');
    const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
    fs.mkdirSync(root, { recursive: true });
    const scratch = fs.mkdtempSync(path.join(root, 'assertara-readiness-'));
    let now = Date.now();
    const sched = new WatchScheduler({ dir: scratch, now: () => now });
    sched.client = {
      async getBytecode() { return '0x11'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    sched.addTarget({ address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', intervalMs: 5000 });
    now += 6000;
    assert.strictEqual((await sched.tickOnce()).checked, 1, 'Phase 2 intact');
    fs.rmSync(scratch, { recursive: true, force: true });
    try { fs.rmdirSync(root); } catch { /* non-empty or gone: leave it */ }
    const { buildPdf } = require('./pdfIngest.test.js');
    const { ingestAuditPdf, toLedgerIntake } = require('../../src/agent/pdfIngest');
    const pdf = await ingestAuditPdf({ data: buildPdf([['H-01 Regression check', 'Body.']]) });
    assert.strictEqual(toLedgerIntake(pdf).findings.length, 1, 'Phase 3 intact');
    const { submitHarnessRun: shr } = require('../../src/agent/harness');
    assert.strictEqual((await shr({ kind: 'static', files: [{ path: 'a.sol', content: 'x' }] })).status, 'STATIC_ANALYSIS_ONLY', 'Phase 4 intact');
    const { ingestTranscript } = require('../../src/agent/audioIngest');
    assert.ok(ingestTranscript({ text: 'hi' }).turns.every((x) => x.provenance === 'TRANSCRIPT_PROVIDED'), 'Phase 5 intact');
    const { discoverApprovals } = require('../../src/agent/chain');
    const stubChain = {
      async getBlockNumber() { return 10n; },
      async getLogs() { return []; },
      async readContract() { return 0n; }
    };
    const hist = await discoverApprovals({
      owner: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      tokens: ['0xdAC17F958D2ee523a2206206994597C13D831ec7'],
      fromBlock: 0n, toBlock: 5n, client: stubChain
    });
    assert.strictEqual(hist.coverage.status, 'COMPLETE_WITHIN_REQUESTED_SCOPE', 'Phase 6 intact');
    const { buildDossier } = require('../../src/agent/dossier');
    const d = await buildDossier({
      address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      client: { ...stubChain, async getBytecode() { return '0x'; }, async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; } },
      history: false
    });
    assert.strictEqual(d.bytecode.hasCode, false, 'Phase 7 intact');
    const { answerFindingQuestion } = require('../../src/agent/askAbout');
    const q = await answerFindingQuestion({
      finding: { id: 'F-R', claim: 'c', supporting: ['E-1'], contradicting: [] },
      evidence: [{ ref: 'E-1', kind: 'K', summary: 's' }], question: 'q?'
    }, { model: { async complete() { return { content: { answer: 'a', citations: ['E-1'], answerable: 'full', uncertaintyNote: '', missingEvidence: [] } }; } } });
    assert.strictEqual(q.status, 'OK', 'Phase 8 intact');
    const { assessAuditFindings } = require('../../src/agent/auditAssess');
    const a = await assessAuditFindings({
      records: [{ id: 'R-1', description: 'd', location: 'p.1', status: 'UNRESOLVED', history: [] }],
      report: { status: 'OK', findings: [{ index: 0, sourceId: null, severity: null, title: 't', startPage: 1, endPage: 1, quote: 'q', codeRefs: [] }] }
    });
    assert.strictEqual(a.assessments[0].verdict, 'UNRESOLVED', 'Phase 9 intact');
    const { detectVideoCapabilities } = require('../../src/agent/videoIngest');
    assert.strictEqual((await detectVideoCapabilities()).canProcessVideo, false, 'Phase 10 intact');
    const { localizeAssessment } = require('../../src/agent/localize');
    const loc = await localizeAssessment({
      assessment: { segments: [{ id: 's', text: 'Review 0x942c733fa43900388424a1bf7f94d934b3531b23 carefully (E-001).' }], protected: {} },
      targetLang: 'es'
    }, { model: { async complete() { return { content: { segments: [{ id: 's', text: 'Revise 0x942c733fa43900388424a1bf7f94d934b3531b23 cuidadosamente (E-001).' }] } }; } } });
    assert.strictEqual(loc.status, 'OK', 'Phase 11 intact');
    const { Recorder, replayRecording, validRecording } = require('../../src/agent/replay');
    const rec = new Recorder({ investigationId: 'inv_reg13', runId: 'run_reg13' });
    rec.append('investigation.started', { data: { featureId: 'F1_core' } });
    rec.append('investigation.stopped', { data: { status: 'COMPLETE' } });
    const exported = rec.export();
    assert.strictEqual(validRecording(exported).ok, true, 'Phase 12 record intact');
    assert.strictEqual(replayRecording(exported).status, 'OK', 'Phase 12 replay intact');
    console.log('✔ Test 12 Passed: Phases 1–12 behavior preserved.');
  }

  console.log('\nAll Experimental Audit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runReadinessTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runReadinessTests };
