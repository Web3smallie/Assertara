const assert = require('assert');
const { EvidenceGraph } = require('../../src/agent/evidenceGraph');
const { TOOLS, runTool, describeTools } = require('../../src/agent/toolRegistry');
const { SparkAdapter, SparkApiError } = require('../../src/agent/sparkAdapter');
const { Orchestrator } = require('../../src/agent/orchestrator');
const { adjudicate, runGates } = require('../../src/agent/verifier');
const { buildReplayBundle, buildTranslatorOutput } = require('../../src/agent/reports');
const { FEATURES, runFeature } = require('../../src/agent/features');

const APPROVE_TX = {
  to: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
  data: '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  value: '0x0'
};

function scriptedModel(turns) {
  let i = 0;
  return {
    async nextTurn() {
      const turn = turns[Math.min(i, turns.length - 1)];
      i += 1;
      return { actions: [], usage: { input_tokens: 100, output_tokens: 10 }, estimatedCostUsd: 0.001, ...turn };
    }
  };
}

async function runAgentTests() {
  console.log('Testing Agentic Foundation: Graph, Tools, Adapter, Loop, Verifier...\n');

  // Test 1: evidence graph append/relate/validate/export.
  {
    const g = new EvidenceGraph('inv_test');
    const a = g.append({ kind: 'Screenshot', producer: 'USER', payload: { hash: 'abc' }, created_turn: 0 });
    const b = g.append({ kind: 'DecodedTx', producer: 'TOOL', tool_ref: 'decode_tx', payload: {}, created_turn: 1 });
    assert.strictEqual(a.id, 'E-001');
    assert.strictEqual(b.id, 'E-002');
    g.relate(a.id, 'DERIVED_FROM', b.id);
    assert.deepStrictEqual(g.validateRefs(['E-001', 'E-999']), { ok: false, unknown: ['E-999'] });
    assert.throws(() => g.append({ kind: 'X', producer: 'MODEL2' }), /producer/);
    assert.throws(() => g.relate('E-001', 'SUPPORTS', 'E-404'), /unknown evidence/);
    const exported = g.export();
    assert.strictEqual(exported.nodes.length, 2);
    assert.strictEqual(exported.edges.length, 1);
    console.log('✔ Test 1 Passed: Evidence graph stores, links, and validates.');
  }

  // Test 2: tool registry executes real tools, validates args, marks boundaries.
  {
    const decoded = await runTool('decode_tx', APPROVE_TX);
    assert.strictEqual(decoded.functionName, 'approve');
    assert.strictEqual(decoded.isUnlimitedApproval, true);
    const cmp = await runTool('compare_fields', {
      displayed: { recipient: decoded.parameters.spender, amount: '1' },
      decoded
    });
    assert.strictEqual(cmp.fields.recipient.verdict, 'MATCH');
    assert.strictEqual(cmp.fields.amount.verdict, 'DIFFER');
    assert.strictEqual(cmp.overall, 'DIFFER');
    const allowance = await runTool('allowance_analysis', { decoded });
    assert.strictEqual(allowance.isUnlimited, true);
    assert.ok(allowance.flags.includes('UNLIMITED_APPROVAL'));
    await assert.rejects(runTool('nope', {}), /unknown tool/);
    await assert.rejects(runTool('decode_tx', { to: '0x123' }), /0x address/);
    const t = await runTool('schedule_monitor', {});
    assert.strictEqual(t.status, 'UNAVAILABLE');
    assert.ok(t.requirements.length > 0, 'Boundary must list integration requirements');
    assert.strictEqual(describeTools().length, Object.keys(TOOLS).length);
    console.log('✔ Test 2 Passed: Tools execute honestly with validation and boundaries.');
  }

  // Test 3: Spark adapter builds correct requests and maps errors (stubbed fetch).
  {
    let seen;
    const okFetch = async (url, opts) => {
      seen = { url, body: JSON.parse(opts.body), auth: opts.headers.Authorization };
      return {
        ok: true,
        text: async () => JSON.stringify({
          id: 'resp_1', status: 'completed',
          output: [
            { type: 'message', content: [{ type: 'output_text', text: '{"a":1}' }] },
            { type: 'function_call', call_id: 'c1', name: 'decode_tx', arguments: '{"to":"0x1"}' }
          ],
          usage: { input_tokens: 100, output_tokens: 10, input_tokens_details: { cached_tokens: 20 } }
        }),
        headers: { get: () => null }
      };
    };
    const adapter = new SparkAdapter({ apiKey: 'LIVE_KEY_FOR_TEST', fetchImpl: okFetch });
    const res = await adapter.request({
      input: 'hi', schema: { type: 'object' }, schemaName: 't', effort: 'high',
      previousResponseId: 'resp_0', tools: [{ type: 'function', name: 'f' }]
    });
    assert.strictEqual(seen.url, 'https://api.meta.ai/v1/responses');
    assert.strictEqual(seen.body.model, 'muse-spark-1.3');
    assert.deepStrictEqual(seen.body.reasoning, { effort: 'high' });
    assert.strictEqual(seen.body.text.format.type, 'json_schema');
    assert.strictEqual(seen.body.previous_response_id, 'resp_0');
    assert.strictEqual(seen.body.prompt_cache_key, 'assertara-investigate');
    assert.ok(!JSON.stringify(seen.body).includes('LIVE_KEY_FOR_TEST'), 'Key must never be in the body');
    assert.strictEqual(seen.auth, 'Bearer LIVE_KEY_FOR_TEST');
    assert.strictEqual(res.text, '{"a":1}');
    assert.strictEqual(res.toolCalls[0].name, 'decode_tx');
    assert.strictEqual(res.cachedTokens, 20);
    assert.ok(res.estimatedCostUsd > 0 && res.estimatedCostUsd < 1, 'Cost estimated from usage');

    const errFetch = (status, body) => async () => ({
      ok: false, status, text: async () => JSON.stringify(body), headers: { get: () => null }
    });
    const a429 = new SparkAdapter({ apiKey: 'k', fetchImpl: errFetch(429, { error: { message: 'slow', type: 'rate_limit_error' } }) });
    const e429 = await a429.request({ input: 'x' }).catch((e) => e);
    assert.ok(e429 instanceof SparkApiError && e429.retryable === true, '429 must be retryable');
    const a401 = new SparkAdapter({ apiKey: 'k', fetchImpl: errFetch(401, { error: { message: 'bad', type: 'authentication_error', code: 'invalid_api_key' } }) });
    const e401 = await a401.request({ input: 'x' }).catch((e) => e);
    assert.strictEqual(e401.retryable, false, '401 must not be retried');
    const hanging = new SparkAdapter({
      apiKey: 'k',
      // Faithful stub: like real fetch, rejects with AbortError on abort.
      fetchImpl: (url, opts) => new Promise((_, reject) => {
        opts.signal.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      })
    });
    const eTimeout = await hanging.request({ input: 'x', timeoutMs: 30 }).catch((e) => e);
    assert.strictEqual(eTimeout.type, 'timeout', 'Hanging calls must time out');
    const unconfigured = new SparkAdapter({
      apiKey: 'mock_x', fetchImpl: async () => { throw new Error('must not call fetch'); }
    });
    await assert.rejects(unconfigured.request({ input: 'x' }), /placeholder/, 'Placeholder keys must never reach the network');
    console.log('✔ Test 3 Passed: Adapter requests, usage, errors, and timeouts behave.');
  }

  // Test 4: adapter preflight + structured complete().
  {
    let seen;
    const fetchImpl = async (url, opts) => {
      seen = { url, body: JSON.parse(opts.body) };
      if (url.endsWith('/input_tokens')) {
        const payload = JSON.stringify({ object: 'response.input_tokens', input_tokens: 42 });
        // Faithful stub: real fetch Responses expose both text() and json().
        return { ok: true, text: async () => payload, json: async () => JSON.parse(payload) };
      }
      return { ok: true, text: async () => JSON.stringify({ id: 'r', output: [{ type: 'message', content: [{ type: 'output_text', text: '{"ok":true}' }] }], usage: null }), headers: { get: () => null } };
    };
    const adapter = new SparkAdapter({ apiKey: 'k', fetchImpl });
    assert.strictEqual(await adapter.preflightCount({ input: 'hello' }), 42);
    assert.ok(seen.url.endsWith('/input_tokens'), 'Preflight must hit the count endpoint');
    const done = await adapter.complete({ system: 's', input: 'q', schema: { type: 'object' }, effort: 'low' });
    assert.deepStrictEqual(done.content, { ok: true });
    const bad = new SparkAdapter({
      apiKey: 'k',
      fetchImpl: async () => ({ ok: true, text: async () => JSON.stringify({ output: [{ type: 'message', content: [{ type: 'output_text', text: 'not json' }] }] }), headers: { get: () => null } })
    });
    await assert.rejects(bad.complete({ input: 'q', schema: { type: 'object' } }), /malformed JSON/);
    console.log('✔ Test 4 Passed: Preflight counts and complete() validates JSON.');
  }

  // Test 5: orchestrator loop executes, dedups, budgets, and terminates.
  {
    const model = scriptedModel([
      { actions: [{ tool: 'decode_tx', args: APPROVE_TX }, { tool: 'nope', args: {} }, { tool: 'decode_tx', args: {} }] },
      { actions: [{ tool: 'decode_tx', args: APPROVE_TX }] },
      { stop: true, stopReason: 'done' }
    ]);
    const orch = new Orchestrator({ modelClient: model, budget: { maxTurns: 8, maxToolCalls: 24, toolTimeoutMs: 5000, maxUsd: 10, maxIdleTurns: 2 } });
    const record = await orch.run('F1_core', { tx: APPROVE_TX });
    assert.strictEqual(record.status, 'COMPLETE');
    assert.strictEqual(record.turns.length, 3);
    assert.strictEqual(record.turns[0].actions.filter((a) => a.ok).length, 1, 'Only the valid call runs');
    assert.strictEqual(record.ledger.deduped, 1, 'Repeat call is deduped');
    assert.ok(record.graph.byKind('ToolResult').length >= 1, 'Results land in the graph');
    assert.strictEqual(record.ledger.modelCalls, 3);
    console.log('✔ Test 5 Passed: Loop validates, dedups, parallel-runs, and stops.');
  }

  // Test 6: budgets and model failures end honestly as INCOMPLETE.
  {
    const looping = scriptedModel([{ actions: [{ tool: 'decode_tx', args: { ...APPROVE_TX, value: '0x1' } }] }]);
    const orch = new Orchestrator({ modelClient: looping, budget: { maxTurns: 2, maxToolCalls: 24, toolTimeoutMs: 5000, maxUsd: 10, maxIdleTurns: 5 } });
    const capped = await orch.run('F1_core', {});
    assert.strictEqual(capped.status, 'INCOMPLETE');
    assert.ok(capped.stopReason.includes('Budget exhausted'));
    const failing = { async nextTurn() { throw new Error('boom'); } };
    const orch2 = new Orchestrator({ modelClient: failing });
    const failed = await orch2.run('F1_core', {});
    assert.strictEqual(failed.status, 'INCOMPLETE');
    assert.ok(failed.stopReason.includes('boom'));
    console.log('✔ Test 6 Passed: Budget exhaustion and model failure stay honest.');
  }

  // Test 7: verifier gates + adjudication.
  {
    const g = new EvidenceGraph('inv_v');
    const n1 = g.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const good = { id: 'F-1', claim: 'x', supporting: [n1.id], contradicting: [] };
    assert.deepStrictEqual(adjudicate(good, g, { verdict: 'SUPPORTED', reasons: ['ok'] }).status, 'VERIFIED');
    assert.deepStrictEqual(adjudicate(good, g, { verdict: 'PARTIAL', reasons: [] }).status, 'LIKELY');
    assert.deepStrictEqual(adjudicate(good, g, { verdict: 'REJECTED', reasons: ['no'] }).status, 'REJECTED');
    assert.deepStrictEqual(adjudicate(good, g, null).status, 'HYPOTHESIS');
    const badRefs = { id: 'F-2', claim: 'x', supporting: ['E-404'], contradicting: [] };
    const r1 = adjudicate(badRefs, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(r1.status, 'REJECTED', 'Unknown evidence IDs must reject');
    const selfVerified = { id: 'F-3', claim: 'x', supporting: [n1.id], contradicting: [], proposedStatus: 'VERIFIED', proposedBy: 'MODEL' };
    assert.strictEqual(runGates(selfVerified, g).pass, false, 'Model-proposed VERIFIED is inadmissible');
    const fakeExec = { id: 'F-4', claim: 'simulation executed and passed', supporting: [n1.id], contradicting: [] };
    const r2 = adjudicate(fakeExec, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(r2.status, 'REJECTED', 'Execution claims need genuine artifacts');
    console.log('✔ Test 7 Passed: Verification gates and adjudication hold.');
  }

  // Test 8: reports build typed bundles.
  {
    const g = new EvidenceGraph('inv_r');
    g.append({ kind: 'Screenshot', producer: 'USER', payload: {}, created_turn: 0 });
    const record = { id: 'inv_r', feature: 'F1_core', status: 'COMPLETE', stopReason: 'done', inputs: { a: 1 }, turns: [], ledger: { toolCalls: 1 } };
    const bundle = buildReplayBundle({ record, graph: g });
    assert.strictEqual(bundle.type, 'ReplayBundle');
    assert.deepStrictEqual(bundle.inputs, { a: 1 });
    assert.ok(bundle.note.includes('recorded history'));
    const t = buildTranslatorOutput({ decoded: { functionName: 'approve', contract: '0x1', parameters: {} }, explanation: { action: 'a' }, risks: [], unknowns: [] });
    assert.strictEqual(t.type, 'TranslatorOutput');
    console.log('✔ Test 8 Passed: Report builders emit typed bundles.');
  }

  // Test 9: all 15 features resolve; unavailable ones carry requirements.
  {
    assert.strictEqual(Object.keys(FEATURES).length, 15, 'All 15 areas must be mapped');
    for (const [id, f] of Object.entries(FEATURES)) {
      assert.ok(['IMPLEMENTED', 'PARTIAL', 'EXPERIMENTAL', 'UNAVAILABLE'].includes(f.status), `${id} needs a status`);
      if (f.status === 'UNAVAILABLE') assert.ok(f.requirements && f.requirements.length > 0, `${id} must list requirements`);
    }
    await assert.rejects(
      runFeature('F8_scamcall', { turns: [{ text: 'hi' }] }, {}),
      /model client/,
      'Model-required runners must fail loudly without a model, not fake analysis'
    );
    const b = await runFeature('F11_video', {}, {});
    assert.strictEqual(b.status, 'PARTIAL');
    assert.ok(b.limitations.length > 0, 'Partial boundary must list limitations');
    console.log('✔ Test 9 Passed: Feature map complete with honest boundaries.');
  }

  // Test 10: F4 translator grounds quotes; mismatches flagged, never rendered as fact.
  {
    const honestModel = { async complete() {
      return { content: {
        action: 'approve', assets: ['USDT'], contract: 'USDT token', permissions: 'spender allowance',
        boundedOrUnlimited: 'unlimited', consequences: [], risks: ['drain'], unknowns: [],
        quoted: { function: 'approve', to: APPROVE_TX.to, amount: String(2n ** 256n - 1n), spender: '0x942c733fa43900388424a1bf7f94d934b3531b23' }
      } };
    } };
    const ok = await runFeature('F4_translator', { tx: APPROVE_TX }, { model: honestModel });
    assert.strictEqual(ok.status, 'OK');
    assert.strictEqual(ok.output.verifiedAgainst.function, 'approve');
    const lyingModel = { async complete() {
      const c = (await honestModel.complete()).content;
      c.quoted.amount = '100';
      return { content: c };
    } };
    const bad = await runFeature('F4_translator', { tx: APPROVE_TX }, { model: lyingModel });
    assert.strictEqual(bad.status, 'UNVERIFIED_QUOTES');
    assert.ok(bad.issues.some((i) => i.includes('amount mismatch')));
    console.log('✔ Test 10 Passed: Translator verifies quotes against decode.');
  }

  // Test 11: F5 triage signals honestly with and without a model.
  {
    const red = await runFeature('F5_interceptor', { tx: APPROVE_TX }, {});
    assert.strictEqual(red.signal, 'RED', 'Unlimited approve must be RED deterministically');
    assert.strictEqual(red.escalate, true);
    const calmModel = { async complete() { return { content: { signal: 'GREEN', reasons: [], needsDeepDive: false } }; } };
    const still = await runFeature('F5_interceptor', { tx: APPROVE_TX }, { model: calmModel });
    assert.strictEqual(still.signal, 'RED', 'A calm model must not downgrade deterministic RED');
    console.log('✔ Test 11 Passed: Triage never downgrades deterministic findings.');
  }

  // Test 12: F9 answers cite only real ids; F12 fails closed on altered fields.
  {
    const g = new EvidenceGraph('inv_q');
    const n = g.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const model = { async complete() { return { content: { answer: 'because', citations: [n.id, 'E-404'] } }; } };
    const qa = await runFeature('F9_ask', { graphExport: g.export(), question: 'why?' }, { model });
    assert.strictEqual(qa.status, 'PARTIAL');
    assert.deepStrictEqual(qa.citations, [n.id]);
    assert.deepStrictEqual(qa.dropped, ['E-404']);
    const finding = { claim: 'Risky approval on 0xabc, see E-001', severity: 'HIGH', contract: '0xabc', functionName: 'approve', parameters: { a: 1 }, supporting: ['E-001'], contradicting: [], recommendedAction: 'Review before signing' };
    const goodT = { async complete() { return { content: { segments: [{ id: 'claim', text: 'Aprobación riesgosa en 0xabc, ver E-001' }, { id: 'recommendedAction', text: 'Revisar antes de firmar' }] } }; } };
    const lok = await runFeature('F12_localize', { finding, targetLang: 'es' }, { model: goodT });
    assert.strictEqual(lok.status, 'OK');
    assert.strictEqual(lok.finding.severity, 'HIGH', 'Protected fields reattached canonically');
    assert.strictEqual(lok.finding.claim, 'Aprobación riesgosa en 0xabc, ver E-001');
    const badT = { async complete() { return { content: { segments: [{ id: 'claim', text: 'Todo verificado y garantizado' }, { id: 'recommendedAction', text: 'y' }] } }; } };
    const lfail = await runFeature('F12_localize', { finding, targetLang: 'es' }, { model: badT });
    assert.strictEqual(lfail.status, 'FAILED', 'Strengthened claims and dropped values must fail closed');
    console.log('✔ Test 12 Passed: Q&A citations validated; localization fails closed.');
  }

  // Test 13: F1 core run + F13 replay round-trip.
  {
    const model = scriptedModel([
      { actions: [{ tool: 'decode_tx', args: APPROVE_TX }] },
      { stop: true, stopReason: 'enough' }
    ]);
    const core = await runFeature('F1_core', { tx: APPROVE_TX }, { modelClient: model });
    assert.strictEqual(core.status, 'OK');
    assert.strictEqual(core.record.status, 'COMPLETE');
    const replay = await runFeature('F13_replay', { record: core.record, graph: core.record.graph }, {});
    assert.strictEqual(replay.status, 'OK');
    assert.strictEqual(replay.bundle.graph.nodes.length, core.record.graph.export().nodes.length);
    console.log('✔ Test 13 Passed: Core loop runs and replays from history.');
  }

  // Test 14: read-only chain readers (stub client) + pure exposure/diff logic.
  {
    const { fetchApprovals, computeExposure, readContractMeta, diffWatch } = require('../../src/agent/chain');
    const OWNER = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
    const TOKEN = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
    const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
    const pad = (a) => `0x000000000000000000000000${a.slice(2).toLowerCase()}`;
    const stub = {
      async getBlockNumber() { return 23000000n; },
      async getLogs() {
        return [{
          address: TOKEN, topics: ['0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925', pad(OWNER), pad(SPENDER)],
          transactionHash: '0xabc', blockNumber: 22999999n
        }];
      },
      async readContract() { return 2n ** 256n - 1n; },
      async getBytecode() { return '0x6080604055'; },
      async getStorageAt({ slot }) {
        return slot.endsWith('bbc') ? `0x000000000000000000000000${SPENDER.slice(2).toLowerCase()}` : '0x0000000000000000000000000000000000000000000000000000000000000000';
      }
    };
    const fetched = await fetchApprovals({ owner: OWNER, client: stub });
    assert.strictEqual(fetched.approvals.length, 1);
    assert.strictEqual(fetched.approvals[0].spender.toLowerCase(), SPENDER.toLowerCase());
    assert.strictEqual(fetched.truncated, false);
    const exposure = computeExposure([...fetched.approvals, { token: TOKEN, spender: SPENDER, allowance: null }]);
    assert.strictEqual(exposure.unlimitedCount, 1);
    assert.strictEqual(exposure.unreadableCount, 1);
    const meta = await readContractMeta({ address: TOKEN, client: stub });
    assert.strictEqual(meta.hasCode, true);
    assert.strictEqual(meta.eip1967Implementation.toLowerCase(), SPENDER.toLowerCase());
    assert.strictEqual(meta.eip1967Admin, null);
    const diff = diffWatch({ ...meta, eip1967Implementation: null }, meta);
    assert.strictEqual(diff.changed, true);
    assert.strictEqual(diff.changes[0].field, 'eip1967Implementation');
    await assert.rejects(fetchApprovals({ owner: '0x123', client: stub }), /0x address/);
    console.log('✔ Test 14 Passed: Chain readers fetch, compute, and diff honestly.');
  }

  // Test 15: F6 sentinel + F7 dossier run on deterministic chain data.
  {
    const { runSentinel, runDossier } = require('../../src/agent/features');
    const OWNER = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
    const stub = {
      async getBlockNumber() { return 100n; },
      async getLogs() { return []; },
      async readContract() { throw new Error('unused'); },
      async getBytecode() { return '0x'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    const s = await runSentinel({ owner: OWNER }, { client: stub });
    assert.strictEqual(s.status, 'OK');
    assert.strictEqual(s.exposure.approvalCount, 0, 'Empty history must report zero, not invent');
    assert.strictEqual(s.narrative, null, 'No model means no narration, not a fake one');
    const model = { async complete() { return { content: { summary: 'clean', highestRisk: [] } }; } };
    const s2 = await runSentinel({ owner: OWNER }, { client: stub, model });
    assert.strictEqual(s2.narrative.summary, 'clean');
    const d = await runDossier({ address: OWNER }, { client: stub });
    assert.strictEqual(d.meta.hasCode, false, 'EOA must report no code');
    console.log('✔ Test 15 Passed: Sentinel and dossier run deterministically.');
  }

  // Test 16: F8 transcript lane validates turn indexes and tactic names.
  {
    const { runScamCallTranscript } = require('../../src/agent/features');
    const turns = [{ speaker: 'A', text: 'Hello' }, { speaker: 'B', text: 'Read me your seed phrase now' }];
    const good = { async complete() { return { content: { annotations: [{ turn: 1, tactics: ['seed-phrase-request', 'urgency-pressure'], why: 'explicit request' }] } }; } };
    const ok = await runScamCallTranscript({ turns }, { model: good });
    assert.strictEqual(ok.status, 'OK');
    assert.strictEqual(ok.timeline.length, 1);
    const bad = { async complete() { return { content: { annotations: [{ turn: 7, tactics: ['seed-phrase-request'], why: 'x' }, { turn: 0, tactics: ['mind-reading'], why: 'y' }] } }; } };
    const partial = await runScamCallTranscript({ turns }, { model: bad });
    assert.strictEqual(partial.status, 'PARTIAL');
    assert.strictEqual(partial.dropped.length, 2, 'Bad indexes and tactics must be dropped');
    console.log('✔ Test 16 Passed: Scam-call timeline validates references.');
  }

  // Test 17: F10 ledger enforces the status machine; VERIFIED_FIXED needs proof.
  {
    const { runAuditIntake, runAuditTransition } = require('../../src/agent/features');
    const intake = runAuditIntake({ findings: [{ id: 'A-1', description: 'reentrancy?' }] });
    assert.strictEqual(intake.records[0].status, 'UNRESOLVED');
    const opened = runAuditTransition({ record: intake.records[0], newStatus: 'OPEN' });
    assert.strictEqual(opened.status, 'OK');
    const illegal = runAuditTransition({ record: intake.records[0], newStatus: 'VERIFIED_FIXED' });
    assert.strictEqual(illegal.status, 'REJECTED', 'Skipping states must be rejected');
    const claimed = runAuditTransition({ record: opened.record, newStatus: 'FIX_CLAIMED' });
    const noProof = runAuditTransition({ record: claimed.record, newStatus: 'VERIFIED_FIXED' });
    assert.strictEqual(noProof.status, 'REJECTED', 'Fix claims need passing-test evidence');
    const proven = runAuditTransition({ record: claimed.record, newStatus: 'VERIFIED_FIXED', testEvidence: { passed: true, logs: 'ok' } });
    assert.strictEqual(proven.status, 'OK');
    console.log('✔ Test 17 Passed: Audit ledger enforces verified-fix proof.');
  }

  // Test 18: F14 watch checks diff honestly; F15 reviews statically with valid refs.
  {
    const { runWatchCheck, runRepoReview } = require('../../src/agent/features');
    const ADDR = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
    const stubV1 = {
      async getBytecode() { return '0x11'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    const first = await runWatchCheck({ watch: { address: ADDR } }, { client: stubV1 });
    assert.strictEqual(first.baselineEstablished.bytecodeLength, 1);
    assert.strictEqual(first.changed, false);
    const stubV2 = {
      async getBytecode() { return '0x1122'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    const second = await runWatchCheck({ watch: { address: ADDR }, baseline: first.baselineEstablished }, { client: stubV2 });
    assert.strictEqual(second.changed, true);
    assert.strictEqual(second.changes[0].field, 'bytecodeLength');
    const files = [{ path: 'Vault.sol', content: 'line1\nline2\nline3' }];
    const model = { async complete() { return { content: { hypotheses: [{ claim: 'x', refs: ['Vault.sol:2', 'Nope.sol:9'] }], pocDrafts: ['test draft'], questions: [] } }; } };
    const review = await runRepoReview({ files, concern: 'reentrancy' }, { model });
    assert.strictEqual(review.status, 'PARTIAL');
    assert.deepStrictEqual(review.hypotheses[0].refs, ['Vault.sol:2']);
    assert.deepStrictEqual(review.droppedRefs, ['Nope.sol:9']);
    assert.strictEqual(review.pocDrafts[0].status, 'UNEXECUTED', 'Drafts must never imply execution');
    console.log('✔ Test 18 Passed: Watch diffs and static reviews stay honest.');
  }

  // Test 19: F2 advanced loop with fresh review; F3 stays gated.
  {
    const { runAdvanced, runExperimental } = require('../../src/agent/features');
    const modelClient = scriptedModel([{ stop: true, stopReason: 'triage done' }]);
    const reviewer = { async complete() { return { content: { verdict: 'SUPPORTED', reasons: ['graph backs it'] } }; } };
    const adv = await runAdvanced({ goal: 'g', inputs: {}, hypotheses: [{ id: 'H-1', claim: 'c', supporting: ['E-001'], contradicting: [] }] }, { modelClient, reviewer });
    assert.strictEqual(adv.status, 'OK');
    assert.strictEqual(adv.reviewed[0].adjudication.status, 'VERIFIED', 'E-001 (seeded inputs) resolves, review supports');
    const gated = runExperimental({});
    assert.strictEqual(gated.status, 'GATED');
    const opted = runExperimental({ allowExperimental: true });
    assert.strictEqual(opted.status, 'EXPERIMENTAL');
    console.log('✔ Test 19 Passed: Advanced review adjudicates; experimental stays gated.');
  }

  // Test 20: partial boundaries resolve honestly with limitations.
  {
    const f11 = await runFeature('F11_video', {}, {});
    assert.strictEqual(f11.status, 'PARTIAL');
    assert.ok(f11.limitations.length > 0);
    await assert.rejects(runTool('chain_history', { owner: '0x123' }), /0x address/, 'Chain tool validates without network');
    console.log('✔ Test 20 Passed: Video partial-boundary honest; chain tool validates args.');
  }

  // Test 21: RPC failures surface as errors, never fabricated chain data.
  {
    const { fetchApprovals } = require('../../src/agent/chain');
    const failing = {
      async getBlockNumber() { throw new Error('RPC Request failed: 403'); },
      async getLogs() { throw new Error('unreachable'); }
    };
    await assert.rejects(
      fetchApprovals({ owner: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', client: failing }),
      /403/,
      'RPC errors must propagate, not become fake approvals'
    );
    console.log('✔ Test 21 Passed: Chain failures surface honestly.');
  }

  // Test 22: retry-once for 429 / 5xx / timeout — then stop.
  {
    const okBody = { id: 'r', status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: '{"ok":true}' }] }], usage: null };
    let calls = 0;
    const flaky429 = new SparkAdapter({
      apiKey: 'k',
      fetchImpl: async () => {
        calls += 1;
        if (calls === 1) {
          return { ok: false, status: 429, text: async () => JSON.stringify({ error: { message: 'slow', type: 'rate_limit_error' } }), headers: { get: (h) => (h === 'retry-after' ? '0' : null) } };
        }
        return { ok: true, text: async () => JSON.stringify(okBody), headers: { get: () => null } };
      }
    });
    const recovered = await flaky429.request({ input: 'x', timeoutMs: 5000 });
    assert.strictEqual(recovered.text, '{"ok":true}', 'One transient 429 must be retried');
    assert.strictEqual(calls, 2, 'Exactly one retry, not a loop');

    let calls500 = 0;
    const always500 = new SparkAdapter({
      apiKey: 'k',
      fetchImpl: async () => {
        calls500 += 1;
        return { ok: false, status: 500, text: async () => JSON.stringify({ error: { message: 'bad', type: 'server_error' } }), headers: { get: () => null } };
      }
    });
    await assert.rejects(always500.request({ input: 'x', timeoutMs: 5000 }), /bad/);
    assert.strictEqual(calls500, 2, 'Persistent 5xx must stop after one retry');
    console.log('✔ Test 22 Passed: Transient failures retry exactly once.');
  }

  // Test 23: validation errors and 4xx are never retried.
  {
    let calls = 0;
    const badRequest = new SparkAdapter({
      apiKey: 'k',
      fetchImpl: async () => {
        calls += 1;
        return { ok: false, status: 400, text: async () => JSON.stringify({ error: { message: 'bad schema', type: 'invalid_request_error' } }), headers: { get: () => null } };
      }
    });
    await assert.rejects(badRequest.request({ input: 'x', timeoutMs: 5000 }), /bad schema/);
    assert.strictEqual(calls, 1, 'HTTP 400 must never be retried');

    // Orchestrator validation failures are recorded once, never executed or retried.
    const invalidTwice = scriptedModel([
      { actions: [{ tool: 'decode_tx', args: { to: '0x123' } }] },
      { actions: [{ tool: 'decode_tx', args: { to: '0x123' } }], stop: true }
    ]);
    const orch = new Orchestrator({ modelClient: invalidTwice });
    const record = await orch.run('F1_core', {});
    assert.strictEqual(record.ledger.toolCalls, 0, 'Invalid actions must never execute');
    assert.strictEqual(record.ledger.failures, 0, 'Validation rejections are not execution failures');
    console.log('✔ Test 23 Passed: 4xx and validation failures never retry.');
  }

  // Test 24: experimental-sourced evidence cannot establish VERIFIED.
  {
    const g = new EvidenceGraph('inv_x');
    const stable = g.append({ kind: 'DecodedTx', producer: 'TOOL', payload: {}, created_turn: 1 });
    const exp = g.append({ kind: 'ModelReading', producer: 'MODEL', payload: { experimental: true }, created_turn: 2 });
    const tainted = { id: 'F-X', claim: 'x', supporting: [stable.id, exp.id], contradicting: [] };
    const capped = adjudicate(tainted, g, { verdict: 'SUPPORTED', reasons: ['looks good'] });
    assert.strictEqual(capped.status, 'HYPOTHESIS', 'Experimental support caps at HYPOTHESIS even when reviewed');
    assert.ok(capped.reasons.some((r) => r.includes('experimental')), 'Reason must name the experimental evidence');
    const clean = { id: 'F-Y', claim: 'x', supporting: [stable.id], contradicting: [] };
    assert.strictEqual(adjudicate(clean, g, { verdict: 'SUPPORTED', reasons: [] }).status, 'VERIFIED');
    console.log('✔ Test 24 Passed: Experimental evidence cannot verify findings.');
  }

  console.log('\nAll Agent Foundation Tests Passed Successfully!\n');
}

if (require.main === module) {
  runAgentTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentTests };
