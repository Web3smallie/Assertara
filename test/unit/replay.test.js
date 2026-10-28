const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  RECORDING_VERSION, MAX_EVENTS, MAX_EVENT_BYTES, MAX_RECORDING_BYTES,
  EVENT_TYPES, EVENT_CLASS, REPLAY_NOTE,
  Recorder, redactSensitive, stableStringify, validRecording,
  saveRecording, loadRecording, recordFromRun, replayRecording
} = require('../../src/agent/replay');
const { Orchestrator } = require('../../src/agent/orchestrator');
const { runFeature } = require('../../src/agent/features');

function testRecorder(opts = {}) {
  let t = 1_700_000_000_000;
  return new Recorder({
    investigationId: 'inv_test1',
    runId: 'run_test1',
    featureId: 'F1_core',
    model: 'muse-spark-1.3',
    now: () => (t += 1000),
    ...opts
  });
}

function sampleRecording() {
  const r = testRecorder();
  r.append('investigation.started', { data: { featureId: 'F1_core', inputsHash: 'a'.repeat(64), inputs: { goal: 't' }, inputRedactions: [] } });
  r.append('model.turn', { actor: 'model', data: { turn: 1, effort: 'low', notes: 'n', stop: true, actionCount: 1 } });
  r.append('tool.called', { data: { turn: 1, tool: 'decode_tx', argsHash: 'b'.repeat(64) } });
  r.append('tool.result', { actor: 'tool', data: { turn: 1, tool: 'decode_tx', ok: true, evidenceId: 'E-002', outputHash: 'c'.repeat(64) }, evidenceRefs: ['E-002'] });
  r.append('evidence.appended', { data: { evidenceId: 'E-001', kind: 'InvestigationInputs', producer: 'USER' }, evidenceRefs: ['E-001'] });
  r.append('investigation.stopped', { data: { status: 'COMPLETE', stopReason: 'done', ledger: { toolCalls: 1 } } });
  return r.export();
}

async function scriptedRun() {
  const stub = {
    nextTurn: async ({ graph }) => (graph.nodes.length > 1
      ? { actions: [], stop: true, stopReason: 'reviewed', notes: 'looks decoded' }
      : { actions: [{ tool: 'decode_tx', args: { to: '0xdAC17F958D2ee523a2206206994597C13D831ec7', data: '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' } }], notes: 'decode it' })
  };
  const orch = new Orchestrator({ modelClient: stub });
  return orch.run('F1_core', { goal: 'scripted' });
}

async function runReplayTests() {
  console.log('Testing Investigation Replay: Events, Chain & Theater...\n');

  // Test 1: ordered event recording with linkage, classes, versions.
  {
    const r = testRecorder();
    const e1 = r.append('investigation.started', { data: { featureId: 'F1_core' } });
    const e2 = r.append('model.turn', { actor: 'model', data: { turn: 1 } });
    const e3 = r.append('investigation.stopped', { data: { status: 'COMPLETE' } });
    assert.deepStrictEqual([e1.seq, e2.seq, e3.seq], [1, 2, 3]);
    assert.strictEqual(e1.prevHash, 'GENESIS');
    assert.strictEqual(e2.prevHash, e1.hash);
    assert.strictEqual(e3.prevHash, e2.hash);
    assert.ok(Date.parse(e1.ts) < Date.parse(e2.ts), 'Injected clock orders timestamps');
    assert.deepStrictEqual([e1.class, e2.class, e3.class], ['observed', 'interpreted', 'observed']);
    assert.ok(e1.versions.orchestrator && e1.versions.model === 'muse-spark-1.3');
    const rec = r.export();
    assert.strictEqual(rec.type, 'ReplayRecording');
    assert.strictEqual(rec.version, RECORDING_VERSION);
    assert.strictEqual(rec.head, e3.hash);
    assert.strictEqual(rec.eventCount, 3);
    assert.strictEqual(rec.mode, 'live');
    console.log('✔ Test 1 Passed: Ordered, linked, classified events.');
  }

  // Test 2: event schema validation rejects bad shapes with codes.
  {
    const r = testRecorder();
    assert.throws(() => r.append('nope.unknown', { data: {} }), (e) => e.code === 'UNKNOWN_EVENT_TYPE');
    assert.throws(() => r.append('model.turn', { actor: 'ghost', data: {} }), (e) => e.code === 'BAD_ACTOR');
    assert.throws(() => r.append('model.turn', { data: 'string' }), (e) => e.code === 'BAD_EVENT_DATA');
    assert.throws(() => r.append('model.turn', { data: [1] }), (e) => e.code === 'BAD_EVENT_DATA');
    assert.throws(() => r.append('tool.result', { data: {}, evidenceRefs: [42] }), (e) => e.code === 'BAD_EVIDENCE_REFS');
    assert.throws(() => new Recorder({ investigationId: '', runId: 'x' }), (e) => e.code === 'BAD_ID');
    const circular = {}; circular.self = circular;
    assert.throws(() => r.append('model.turn', { data: { c: circular } }), (e) => e.code === 'VALUE_CIRCULAR');
    // Loader-level schema failures return codes, never throw.
    assert.strictEqual(validRecording(null).code, 'MALFORMED_RECORDING');
    assert.strictEqual(validRecording({ type: 'ReplayRecording', version: 999, events: [] }).code, 'UNSUPPORTED_VERSION');
    const badSeq = sampleRecording();
    badSeq.events[2].seq = 99;
    assert.strictEqual(validRecording(badSeq).code, 'MALFORMED_RECORDING');
    const badClass = sampleRecording();
    badClass.events[1].class = 'observed';
    assert.strictEqual(validRecording(badClass).code, 'MALFORMED_RECORDING');
    console.log('✔ Test 2 Passed: Schemas enforced with explicit codes.');
  }

  // Test 3: secrets redacted, legitimate evidence preserved.
  {
    const input = {
      apiKey: 'sk-live-should-vanish',
      nested: { password: 'hunter2', count: 3 },
      headers: { Authorization: 'Bearer abc.def.ghi' },
      bearerToken: 'ghp_faketoken123456',
      pem: '-----BEGIN EC PRIVATE KEY-----\nabc',
      to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      amount: '3450',
      token: 'USDC',
      tokenAddress: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      authorizationList: [{ chainId: '1', address: '0x942c733fa43900388424a1bf7f94d934b3531b23', nonce: '7' }],
      txHash: `0x${'ab'.repeat(32)}`
    };
    const { value, redacted } = redactSensitive(input);
    assert.strictEqual(value.apiKey, '[REDACTED]');
    assert.strictEqual(value.nested.password, '[REDACTED]');
    assert.strictEqual(value.nested.count, 3);
    assert.strictEqual(value.headers.Authorization, '[REDACTED]');
    assert.strictEqual(value.bearerToken, '[REDACTED]');
    assert.strictEqual(value.pem, '[REDACTED]');
    assert.ok(redacted.length >= 5 && redacted.includes('$.apiKey'));
    assert.strictEqual(value.to, input.to, 'Addresses survive');
    assert.strictEqual(value.token, 'USDC', '`token` key is evidence, not a secret');
    assert.deepStrictEqual(value.authorizationList, input.authorizationList, 'On-chain auth tuples survive');
    // Recorder applies redaction automatically and reports paths.
    const r = testRecorder();
    const e = r.append('investigation.started', { data: { featureId: 'F1', apiKey: 'sk-x', to: input.to } });
    assert.strictEqual(e.data.apiKey, '[REDACTED]');
    assert.strictEqual(e.data.to, input.to);
    assert.deepStrictEqual(e.redacted, ['$.apiKey']);
    assert.strictEqual(e.redactedCount, 1);
    console.log('✔ Test 3 Passed: Redaction surgical; evidence intact.');
  }

  // Test 4: a well-formed chain verifies; head pins the history.
  {
    const rec = sampleRecording();
    const v = validRecording(rec);
    assert.strictEqual(v.ok, true);
    assert.ok(v.bytes > 0);
    // Determinism: identical logical content rehashes identically.
    assert.strictEqual(stableStringify({ b: 1, a: [3, 2] }), stableStringify({ a: [3, 2], b: 1 }));
    // JSON round-trip (what persistence does) preserves the chain.
    assert.strictEqual(validRecording(JSON.parse(JSON.stringify(rec))).ok, true);
    // BigInt payloads (decoded tx params) survive canonicalization.
    const r = testRecorder();
    r.append('tool.result', { actor: 'tool', data: { amount: 2n ** 256n - 1n } });
    const exp = r.export();
    assert.strictEqual(validRecording(exp).ok, true);
    assert.deepStrictEqual(exp.events[0].data.amount, { __bigint: (2n ** 256n - 1n).toString() });
    console.log('✔ Test 4 Passed: Chain verifies; canonical form stable.');
  }

  // Test 5: modification, deletion, reorder, truncation all detected with seq.
  {
    const edited = sampleRecording();
    edited.events[3].data.outputHash = 'd'.repeat(64);
    const m = validRecording(edited);
    assert.strictEqual(m.code, 'EVENT_MODIFIED');
    assert.strictEqual(m.seq, 4);
    const deleted = sampleRecording();
    deleted.events.splice(2, 1);
    deleted.eventCount = deleted.events.length;
    deleted.events.forEach((e, i) => { e.seq = i + 1; }); // attacker renumbers
    assert.strictEqual(validRecording(deleted).code, 'CHAIN_LINK_BROKEN');
    const reordered = sampleRecording();
    const [a, b] = [reordered.events[1], reordered.events[2]];
    reordered.events[1] = b; reordered.events[2] = a;
    reordered.events[1].seq = 2; reordered.events[2].seq = 3; // renumbered swap
    const ro = validRecording(reordered);
    assert.ok(['CHAIN_LINK_BROKEN', 'EVENT_MODIFIED'].includes(ro.code), `reorder caught as ${ro.code}`);
    const truncated = sampleRecording();
    truncated.events.pop();
    truncated.eventCount = truncated.events.length;
    const tr = validRecording(truncated);
    assert.ok(['CHAIN_LINK_BROKEN', 'HEAD_MISMATCH'].includes(tr.code), `truncate caught as ${tr.code}`);
    const badHead = sampleRecording();
    badHead.head = 'f'.repeat(64);
    assert.strictEqual(validRecording(badHead).code, 'HEAD_MISMATCH');
    // Class flip without rehash trips schema before hashing.
    const flipped = sampleRecording();
    flipped.events[1].class = 'observed';
    assert.strictEqual(validRecording(flipped).code, 'MALFORMED_RECORDING');
    console.log('✔ Test 5 Passed: Tamper detected; offending seq named.');
  }

  // Test 6: atomic persistence, traversal defense, corrupt recovery.
  {
    const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
    fs.mkdirSync(root, { recursive: true });
    const scratch = fs.mkdtempSync(path.join(root, 'assertara-replay-'));
    try {
      const rec = sampleRecording();
      const { path: saved } = saveRecording(scratch, rec);
      assert.ok(saved.startsWith(path.resolve(scratch)));
      assert.ok(!fs.readdirSync(scratch).some((f) => f.includes('.tmp-')), 'No tmp debris left behind');
      const loaded = loadRecording(saved);
      assert.strictEqual(loaded.ok, true);
      assert.deepStrictEqual(loaded.recording, rec, 'Round-trip byte-identical');
      // Corrupt file (truncated JSON) → code, not throw.
      const corrupt = path.join(scratch, 'replay-corrupt.json');
      fs.writeFileSync(corrupt, '{"type":"ReplayRecording","events":[', 'utf8');
      assert.strictEqual(loadRecording(corrupt).code, 'MALFORMED_RECORDING');
      // Tampered file on disk fails the chain on load.
      const evil = JSON.parse(JSON.stringify(rec));
      evil.events[0].data.inputs.goal = 'rewritten-history';
      const evilPath = path.join(scratch, 'replay-evil.json');
      fs.writeFileSync(evilPath, JSON.stringify(evil), 'utf8');
      const evilLoad = loadRecording(evilPath);
      assert.strictEqual(evilLoad.ok, false);
      assert.strictEqual(evilLoad.code, 'EVENT_MODIFIED');
      // Missing file, hostile runIds, invalid envelopes.
      assert.strictEqual(loadRecording(path.join(scratch, 'replay-nope.json')).code, 'NOT_FOUND');
      for (const bad of ['../escape', 'a/b', '', 'x'.repeat(200)]) {
        assert.throws(() => saveRecording(scratch, { ...rec, runId: bad }), (e) => ['BAD_RUN_ID', 'MALFORMED_RECORDING'].includes(e.code), `runId rejected: ${bad}`);
      }
      assert.throws(() => saveRecording(scratch, { type: 'nope' }), (e) => e.code === 'MALFORMED_RECORDING');
      console.log('✔ Test 6 Passed: Atomic saves; corrupt/traversal inputs safe.');
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
      try { fs.rmdirSync(root); } catch { /* non-empty or gone: leave it */ }
    }
  }

  // Test 7: full run → recording → replay round-trip through the F13 runner.
  {
    const record = await scriptedRun();
    const built = await runFeature('F13_replay', { build: true, record, graph: record.graph }, {});
    assert.strictEqual(built.status, 'OK');
    assert.strictEqual(built.mode, 'build');
    assert.strictEqual(built.recording.mode, 'derived');
    assert.strictEqual(built.recording.events[0].type, 'investigation.started');
    assert.strictEqual(built.recording.events.at(-1).type, 'investigation.stopped');
    const replayed = await runFeature('F13_replay', { recording: built.recording, evidence: record.graph.export() }, {});
    assert.strictEqual(replayed.status, 'OK');
    assert.strictEqual(replayed.mode, 'historical');
    const rp = replayed.replay;
    assert.strictEqual(rp.integrity.verified, true);
    assert.strictEqual(rp.integrity.checkedEvents, rp.timeline.length);
    assert.deepStrictEqual(rp.timeline.map((t) => t.seq), rp.timeline.map((_, i) => i + 1), 'Timeline order = seq order');
    assert.ok(rp.timeline.some((t) => t.type === 'model.turn' && t.class === 'interpreted'));
    assert.ok(rp.timeline.some((t) => t.type === 'tool.result' && t.class === 'observed'));
    assert.deepStrictEqual(rp.evidence.missing, []);
    assert.ok(rp.limits.some((l) => l.includes('derived recording')));
    // Legacy bundle path untouched.
    const legacy = await runFeature('F13_replay', { record, graph: record.graph }, {});
    assert.strictEqual(legacy.bundle.type, 'ReplayBundle');
    console.log('✔ Test 7 Passed: Build → replay round-trip; legacy intact.');
  }

  // Test 8: missing/unavailable evidence reported as gaps, never invented.
  {
    const record = await scriptedRun();
    const rec = recordFromRun({ record, graph: record.graph });
    const noGraph = replayRecording(rec);
    assert.strictEqual(noGraph.status, 'OK');
    assert.strictEqual(noGraph.evidence.checked, false);
    assert.ok(noGraph.timeline.find((t) => t.evidence.length > 0).evidence.every((e) => e.status === 'unchecked'));
    assert.ok(noGraph.limits.some((l) => l.includes('no evidence graph')));
    const partial = replayRecording(rec, { evidence: { nodes: [{ id: 'E-999' }] } });
    assert.strictEqual(partial.status, 'PARTIAL');
    assert.ok(partial.evidence.missing.includes('E-002'));
    assert.ok(partial.gaps.every((g) => g.kind === 'missing-evidence' && Number.isInteger(g.seq)));
    const broken = replayRecording({ ...rec, head: '0'.repeat(64) });
    assert.strictEqual(broken.status, 'FAILED');
    assert.strictEqual(broken.integrity.verified, false);
    assert.deepStrictEqual(broken.timeline, []);
    console.log('✔ Test 8 Passed: Evidence gaps explicit; corruption fails.');
  }

  // Test 9: recorded outputs vs deterministic summaries stay distinct.
  {
    const rec = sampleRecording();
    const rp = replayRecording(rec, { evidence: { nodes: [{ id: 'E-001' }, { id: 'E-002' }] } });
    assert.strictEqual(rp.status, 'OK');
    for (const item of rp.timeline) {
      const source = rec.events[item.seq - 1];
      assert.deepStrictEqual(item.recorded, source.data, `seq ${item.seq}: recorded is verbatim`);
      assert.strictEqual(typeof item.view, 'string');
      assert.strictEqual(item.viewOrigin, 'deterministic-summary');
      assert.ok(!('interpretation' in item) && !('assessment' in item), 'No new-interpretation fields smuggled in');
    }
    assert.strictEqual(rp.note, REPLAY_NOTE);
    assert.ok(rp.note.includes('Nothing was re-executed'));
    // Same input replays byte-identically: replay adds nothing of its own.
    assert.deepStrictEqual(replayRecording(rec, { evidence: { nodes: [{ id: 'E-001' }, { id: 'E-002' }] } }), rp);
    console.log('✔ Test 9 Passed: Verbatim history; labeled summaries.');
  }

  // Test 10: ordinary replay cannot reach external services or sign anything.
  {
    const rec = sampleRecording();
    const realFetch = globalThis.fetch;
    globalThis.fetch = () => { throw new Error('NETWORK_MUST_NOT_HAPPEN'); };
    try {
      const rp = replayRecording(rec);
      assert.strictEqual(typeof rp.then, 'undefined', 'Replay is synchronous — no async I/O hiding inside');
      assert.strictEqual(rp.status, 'OK');
      assert.strictEqual(rp.mode, 'historical');
      const blob = JSON.stringify(rp);
      assert.ok(!/sign|submit|broadcast|private[_-]?key/i.test(blob), 'No signing/submission vocabulary in replay output');
    } finally {
      globalThis.fetch = realFetch;
    }
    // Conversion is local too: no model key, no RPC, no executor involved.
    const record = await scriptedRun();
    const derived = recordFromRun({ record, graph: record.graph });
    assert.strictEqual(validRecording(derived).ok, true);
    console.log('✔ Test 10 Passed: Replay pure; poisoned network untouched.');
  }

  // Test 11: resource limits reject oversized events and recordings.
  {
    const r = testRecorder();
    const big = 'x'.repeat(MAX_EVENT_BYTES);
    assert.throws(() => r.append('model.turn', { data: { blob: big } }), (e) => e.code === 'EVENT_TOO_LARGE');
    const r2 = testRecorder({ runId: 'run_many' });
    for (let i = 0; i < MAX_EVENTS; i += 1) {
      r2.append(i === 0 ? 'investigation.started' : 'model.turn', { data: { n: i } });
    }
    assert.throws(() => r2.append('model.turn', { data: {} }), (e) => e.code === 'TOO_MANY_EVENTS');
    // Recording-level cap trips before chain work on forged envelopes.
    const forged = { type: 'ReplayRecording', version: 1, investigationId: 'i', runId: 'r', events: [{ pad: 'y'.repeat(MAX_RECORDING_BYTES) }], eventCount: 1, head: 'z' };
    assert.strictEqual(validRecording(forged).code, 'RECORDING_TOO_LARGE');
    assert.ok(MAX_EVENTS === 1000 && MAX_EVENT_BYTES === 65536 && MAX_RECORDING_BYTES === 4194304, 'Limits pinned, not drifted');
    console.log('✔ Test 11 Passed: Caps enforced at every layer.');
  }

  // Test 12: Phase 1–11 regression (all prior lanes intact).
  {
    const { adjudicate } = require('../../src/agent/verifier');
    const { EvidenceGraph } = require('../../src/agent/evidenceGraph');
    const g = new EvidenceGraph('inv_phase12reg');
    const exp = g.append({ kind: 'ModelReading', producer: 'MODEL', payload: { experimental: true }, created_turn: 1 });
    const capped = adjudicate({ supporting: [exp.id], conflicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(capped.status, 'HYPOTHESIS', 'Phase 1 intact');
    const { WatchScheduler } = require('../../src/agent/scheduler');
    const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
    fs.mkdirSync(root, { recursive: true });
    const scratch = fs.mkdtempSync(path.join(root, 'assertara-replay-reg-'));
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
    const { submitHarnessRun } = require('../../src/agent/harness');
    const statik = await submitHarnessRun({ kind: 'static', files: [{ path: 'a.sol', content: 'x' }] });
    assert.strictEqual(statik.status, 'STATIC_ANALYSIS_ONLY', 'Phase 4 intact');
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
    const caps = await detectVideoCapabilities();
    assert.strictEqual(caps.canProcessVideo, false, 'Phase 10 intact');
    const { localizeAssessment } = require('../../src/agent/localize');
    const loc = await localizeAssessment({
      assessment: { segments: [{ id: 's', text: `Review 0x942c733fa43900388424a1bf7f94d934b3531b23 carefully (E-001).` }], protected: {} },
      targetLang: 'es'
    }, { model: { async complete() { return { content: { segments: [{ id: 's', text: 'Revise 0x942c733fa43900388424a1bf7f94d934b3531b23 cuidadosamente (E-001).' }] } }; } } });
    assert.strictEqual(loc.status, 'OK', 'Phase 11 intact');
    console.log('✔ Test 12 Passed: Phases 1–11 behavior preserved.');
  }

  // Test 13 (Phase 15): execution failures pair with their own error nodes —
  // a later success in the same turn must not inherit a failure's evidence.
  {
    const stub = {
      nextTurn: async ({ graph }) => (graph.nodes.length > 1
        ? { actions: [], stop: true, stopReason: 'done' }
        : { actions: [
          { tool: 'compare_fields', args: { displayed: 'not-an-object', decoded: 'also-not' } },
          { tool: 'decode_tx', args: { to: '0xdAC17F958D2ee523a2206206994597C13D831ec7', data: '0x095ea7b3' } }
        ] })
    };
    const orch = new Orchestrator({ modelClient: stub });
    const record = await orch.run('F1_core', { goal: 'mixed-outcome turn' });
    const results = record.graph.byKind('ToolResult');
    assert.strictEqual(results.length, 2, 'Both executions recorded ToolResults');
    const failed = results.find((n) => n.payload && n.payload.error !== undefined);
    const succeeded = results.find((n) => n.payload && n.payload.result !== undefined);
    assert.ok(failed && succeeded, 'One error node and one success node exist');
    const rec = recordFromRun({ record, graph: record.graph });
    assert.strictEqual(validRecording(rec).ok, true);
    const byType = (t) => rec.events.filter((e) => e.type === t);
    assert.strictEqual(byType('tool.rejected').length, 0, 'Executed failures are results, not rejections');
    const failResult = byType('tool.result').find((e) => e.data.ok === false);
    assert.ok(failResult, 'Failure recorded as tool.result ok:false');
    assert.strictEqual(failResult.data.evidenceId, failed.id, 'Failure pairs with its own error node');
    assert.deepStrictEqual(failResult.evidenceRefs, [failed.id]);
    const okResult = byType('tool.result').find((e) => e.data.ok === true);
    assert.ok(okResult, 'Success recorded as tool.result ok:true');
    assert.strictEqual(okResult.data.evidenceId, succeeded.id, 'Success pairs with the success node, not the failure');
    const rp = replayRecording(rec, { evidence: record.graph.export() });
    assert.strictEqual(rp.status, 'OK');
    assert.ok(rp.timeline.some((t) => t.type === 'tool.result' && t.view.includes('FAILED')), 'Failed result views as FAILED');
    console.log('✔ Test 13 Passed: Mixed-outcome turns pair without cross-contamination.');
  }

  console.log('\nAll Investigation Replay Tests Passed Successfully!\n');
}

if (require.main === module) {
  runReplayTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runReplayTests };
