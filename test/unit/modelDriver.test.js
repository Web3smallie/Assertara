const assert = require('assert');
const { createModelDriver, TURN_SCHEMA, MAX_ACTIONS_PER_TURN } = require('../../src/agent/modelDriver');
const { SparkApiError } = require('../../src/agent/sparkAdapter');
const { Orchestrator } = require('../../src/agent/orchestrator');
const { runCoreInvestigation, runAdvanced } = require('../../src/agent/features');
const { adjudicate } = require('../../src/agent/verifier');
const { EvidenceGraph } = require('../../src/agent/evidenceGraph');

const ADDR_B = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const APPROVE_DATA = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

// Scripted stand-in for SparkAdapter.complete(). Labeled doubles: these prove
// OUR driver logic (validation, bounds, honesty), never model behavior.
function stubAdapter(turns, { configured = true, capture = null, failWith = null } = {}) {
  let i = 0;
  return {
    isConfigured: () => configured,
    async complete(args) {
      if (capture) capture.push(args);
      if (failWith) throw failWith;
      const content = turns[Math.min(i, turns.length - 1)];
      i += 1;
      return { content, usage: { input_tokens: 10, output_tokens: 5 }, responseId: `resp_turn${i}` };
    }
  };
}

function stopTurn(over = {}) {
  return { actions: [], stop: true, stopReason: 'done', notes: 'n', ...over };
}

// Scripted adapter with a per-call plan: each entry is { content } or
// { throw: err }. Counts calls so tests prove exactly-one-correction.
function plannedAdapter(plan, { capture = null } = {}) {
  let i = 0;
  const adapter = {
    calls: 0,
    isConfigured: () => true,
    async complete(args) {
      adapter.calls += 1;
      if (capture) capture.push(args);
      const step = plan[Math.min(i, plan.length - 1)];
      i += 1;
      if (step && step.throw) throw step.throw;
      return {
        content: step.content,
        usage: step.usage || { input_tokens: 10, output_tokens: 5 },
        estimatedCostUsd: step.estimatedCostUsd !== undefined ? step.estimatedCostUsd : 0.001,
        responseId: step.responseId || `resp_p${i}`
      };
    }
  };
  return adapter;
}

function typedThrow(type, attempt = null) {
  const err = new SparkApiError({ status: 200, type, message: `${type} (fixture)` });
  if (attempt) err.attempt = attempt;
  return err;
}

async function runDriverTests() {
  console.log('Testing Live Model Driver: Turns, Bounds & Honesty...\n');

  // Test 1: successful model-driven F1 investigation (stubbed adapter).
  {
    const decode = {
      actions: [{ tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: APPROVE_DATA }) }],
      stop: false, stopReason: '', notes: 'decode first'
    };
    const driver = createModelDriver({ adapter: stubAdapter([decode, stopTurn({ stopReason: 'decoded; enough to conclude' })]) });
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'decode the approval' });
    assert.strictEqual(record.status, 'COMPLETE');
    assert.strictEqual(record.turns.length, 2);
    const results = record.graph.byKind('ToolResult');
    assert.strictEqual(results.length, 1);
    assert.strictEqual(results[0].payload.result.functionName, 'approve');
    assert.strictEqual(record.ledger.modelCalls, 2, 'Usage forwarded to the ledger');
    assert.strictEqual(record.ledger.inputTokens, 20);
    console.log('✔ Test 1 Passed: Model-driven loop decodes and completes.');
  }

  // Test 2: malformed model output halts honestly; nothing executes.
  {
    for (const [label, content] of [
      ['non-object', 'just a string'],
      ['missing actions', { stop: false, stopReason: '', notes: '' }],
      ['non-boolean stop', { actions: [], stop: 'yes', stopReason: '', notes: '' }]
    ]) {
      const driver = createModelDriver({ adapter: stubAdapter([content]) });
      const orch = new Orchestrator({ modelClient: driver });
      const record = await orch.run('F1_core', { goal: 'g' });
      assert.strictEqual(record.status, 'COMPLETE', `${label}: concludes, not spins`);
      assert.ok(record.stopReason.includes('model-error'), `${label}: reason names the defect`);
      assert.strictEqual(record.graph.byKind('ToolResult').length, 0, `${label}: no tool invoked`);
    }
    // Bad argsJson drops the action and stops instead of spinning.
    const driver = createModelDriver({
      adapter: stubAdapter([{ actions: [{ tool: 'decode_tx', argsJson: '{oops' }], stop: false, stopReason: '', notes: '' }])
    });
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.ok(record.stopReason.includes('model-error'));
    assert.ok(record.turns[0].notes.includes('not valid JSON'));
    assert.strictEqual(record.graph.byKind('ToolResult').length, 0);
    console.log('✔ Test 2 Passed: Malformed turns halt with model-error, zero execution.');
  }

  // Test 3: unavailable model throws before any network; run goes INCOMPLETE.
  {
    let calls = 0;
    const driver = createModelDriver({
      adapter: { isConfigured: () => false, async complete() { calls += 1; throw new Error('must not be called'); } }
    });
    await assert.rejects(driver.nextTurn({ graph: { nodes: [] }, ledger: {} }), (e) => e.code === 'MODEL_UNAVAILABLE');
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(record.status, 'INCOMPLETE');
    assert.ok(record.stopReason.includes('model-unavailable'));
    assert.strictEqual(calls, 0, 'No model call attempted without a key');
    console.log('✔ Test 3 Passed: Missing key → INCOMPLETE, zero network attempts.');
  }

  // Test 4: transport failure (429-after-retry) → INCOMPLETE, failure counted.
  {
    const err = new SparkApiError({ status: 429, type: 'rate_limited', message: 'Rate limited after retry.' });
    const driver = createModelDriver({ adapter: stubAdapter([stopTurn()], { failWith: err }) });
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(record.status, 'INCOMPLETE');
    assert.ok(record.stopReason.includes('Rate limited'));
    assert.strictEqual(record.ledger.failures, 1);
    assert.strictEqual(record.graph.byKind('ToolResult').length, 0, 'No fabricated evidence on failure');
    console.log('✔ Test 4 Passed: Transport failure → INCOMPLETE with ledger count.');
  }

  // Test 5: tool failure mid-run is recorded; error evidence cannot verify.
  {
    const bad = {
      actions: [{ tool: 'compare_fields', argsJson: JSON.stringify({ displayed: 'x', decoded: 'y' }) }],
      stop: false, stopReason: '', notes: 'bad-shape call'
    };
    const driver = createModelDriver({ adapter: stubAdapter([bad, stopTurn({ stopReason: 'tool failed; stopping' })]) });
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(record.status, 'COMPLETE');
    assert.strictEqual(record.graph.byKind('ToolFailure').length, 1);
    const errNode = record.graph.byKind('ToolResult')[0];
    assert.ok(errNode.payload.error, 'Error payload recorded');
    const adj = adjudicate({ id: 'F-5', claim: 'subject safe', supporting: [errNode.id], contradicting: [] }, record.graph, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(adj.status, 'REJECTED', 'Failure evidence cannot support a finding');
    console.log('✔ Test 5 Passed: Tool failures recorded; failed support rejects.');
  }

  // Test 6: iteration limit terminates a never-stopping model.
  {
    const forever = {
      actions: [{ tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: '0x095ea7b3' }) }],
      stop: false, stopReason: '', notes: 'again'
    };
    const driver = createModelDriver({ adapter: stubAdapter([forever]) });
    const orch = new Orchestrator({ modelClient: driver, budget: { maxTurns: 2 } });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(record.status, 'INCOMPLETE');
    assert.ok(record.stopReason.includes('max turns reached'));
    assert.strictEqual(record.turns.length, 2, 'Bounded exactly at maxTurns');
    console.log('✔ Test 6 Passed: maxTurns terminates runaway models.');
  }

  // Test 7: unknown tools dropped, per-turn cap enforced, valid work proceeds.
  {
    const mixed = {
      actions: [
        { tool: 'nope_unknown', argsJson: '{}' },
        { tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: '0x095ea7b3' }) },
        { tool: 'decode_tx', argsJson: '{}' },
        { tool: 'decode_tx', argsJson: '{}' },
        { tool: 'decode_tx', argsJson: '{}' }
      ],
      stop: false, stopReason: '', notes: ''
    };
    const driver = createModelDriver({ adapter: stubAdapter([mixed, stopTurn()]) });
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'g' });
    const notes = record.turns[0].notes;
    assert.ok(notes.includes('nope_unknown'), 'Dropped tool named in notes');
    assert.ok(notes.includes('over the per-turn cap'), 'Cap truncation disclosed');
    assert.ok(record.turns[0].actions.some((a) => a.tool === 'decode_tx' && a.ok === true), 'Valid action still ran');
    assert.ok(!record.turns[0].actions.some((a) => a.tool === 'nope_unknown'), 'Unknown tool never reached the orchestrator');
    assert.strictEqual(MAX_ACTIONS_PER_TURN, 4);
    console.log('✔ Test 7 Passed: Bad actions dropped+disclosed; good actions run.');
  }

  // Test 8: secrets in inputs/evidence never reach the model prompt.
  {
    const capture = [];
    const driver = createModelDriver({ adapter: stubAdapter([stopTurn()], { capture }) });
    const orch = new Orchestrator({ modelClient: driver });
    await orch.run('F1_core', { goal: 'g', apiKey: 'sk-live-secret-abcdef123456', nested: { password: 'hunter2' }, note: 'pasted key sk-inline-secret-xyz987654 inside prose' });
    assert.strictEqual(capture.length, 1);
    const blob = JSON.stringify(capture[0]);
    assert.ok(!blob.includes('sk-live-secret'), 'API key scrubbed from prompt');
    assert.ok(!blob.includes('hunter2'), 'Nested secret scrubbed from prompt');
    assert.ok(!blob.includes('sk-inline-secret'), 'Prose-embedded key scrubbed from prompt');
    assert.ok(blob.includes('[REDACTED]'), 'Scrubbing visible, not silent');
    assert.ok(blob.includes('scrubbed'), 'Scrub counts reported in the prompt');
    console.log('✔ Test 8 Passed: Prompts redacted with visible counts.');
  }

  // Test 9: response continuity + strict turn schema shape.
  {
    const capture = [];
    const t1 = {
      actions: [{ tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: '0x095ea7b3' }) }],
      stop: false, stopReason: '', notes: 't1'
    };
    const driver = createModelDriver({ adapter: stubAdapter([t1, stopTurn()], { capture }) });
    const orch = new Orchestrator({ modelClient: driver });
    await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(capture.length, 2);
    assert.strictEqual(capture[1].previousResponseId, 'resp_turn1', 'Turn 2 continues turn 1 server-side');
    assert.strictEqual(capture[0].schemaName, 'investigation_turn');
    assert.strictEqual(capture[0].schema.additionalProperties, false);
    assert.deepStrictEqual(capture[0].schema.required, ['actions', 'stop', 'stopReason', 'notes']);
    assert.strictEqual(capture[0].schema.properties.actions.items.additionalProperties, false);
    assert.deepStrictEqual(capture[0].schema, TURN_SCHEMA);
    assert.ok(capture[0].system.includes('decode_tx') && capture[0].system.includes('Never invent'), 'System carries tool catalog + rules');
    console.log('✔ Test 9 Passed: previous_response_id threads; turn schema strict.');
  }

  // Test 10: F2 live path — core loop + fresh review; failures never verify.
  {
    const decode = {
      actions: [{ tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: APPROVE_DATA }) }],
      stop: false, stopReason: '', notes: 'decode'
    };
    const adapter = stubAdapter([decode, stopTurn({ stopReason: 'have decode' })]);
    const reviewer = { async complete() { return { content: { verdict: 'SUPPORTED', reasons: ['decode matches'] } }; } };
    const adv = await runAdvanced(
      { goal: 'g', inputs: {}, hypotheses: [{ id: 'H-1', claim: 'approval decoded', supporting: ['E-002'] }] },
      { live: true, adapter, reviewer }
    );
    assert.strictEqual(adv.status, 'OK');
    assert.strictEqual(adv.reviewed[0].adjudication.status, 'VERIFIED', 'Clean supported hypothesis verifies');
    // Failing core (unavailable adapter) → runAdvanced throws before review:
    // no record, no adjudication, nothing to misread as verified.
    const dead = { isConfigured: () => false, async complete() { throw new Error('must not run'); } };
    const failed = await runAdvanced({ goal: 'g', inputs: {}, hypotheses: [] }, { live: true, adapter: dead }).catch((e) => ({ thrown: e }));
    assert.ok(!failed.thrown, 'Empty-hypothesis run with dead adapter resolves (INCOMPLETE core, nothing to review)');
    assert.strictEqual(failed.record.status, 'INCOMPLETE');
    assert.deepStrictEqual(failed.reviewed, []);
    console.log('✔ Test 10 Passed: F2 live path verifies cleanly; dead core reviews nothing.');
  }

  // Test 11: live:true with an unconfigured default adapter stays offline.
  {
    const config = require('../../src/config/env');
    const originalKey = config.modelApiKey;
    config.modelApiKey = 'mock_test-key';
    try {
      const r = await runCoreInvestigation({ goal: 'g', inputs: {} }, { live: true });
      assert.strictEqual(r.record.status, 'INCOMPLETE');
      assert.ok(r.record.stopReason.includes('model-unavailable'));
    } finally {
      config.modelApiKey = originalKey;
    }
    await assert.rejects(runCoreInvestigation({ goal: 'g', inputs: {} }, {}), /requires a modelClient/);
    console.log('✔ Test 11 Passed: live:true without a key is INCOMPLETE, offline.');
  }

  // Test 12: cross-phase regression (gates, lanes, replay, readiness).
  {
    const g = new EvidenceGraph('inv_driverreg');
    const exp = g.append({ kind: 'ModelReading', producer: 'MODEL', payload: { experimental: true }, created_turn: 1 });
    assert.strictEqual(adjudicate({ supporting: [exp.id], conflicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] }).status, 'HYPOTHESIS');
    const { runGates, GATES } = require('../../src/agent/verifier');
    assert.strictEqual(GATES.length, 8);
    assert.strictEqual(adjudicate({ id: 'F-0', claim: 'x', supporting: [], contradicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] }).status, 'REJECTED', 'Empty support cannot verify');
    assert.strictEqual(runGates({ id: 'F', claim: 'x', supporting: [], contradicting: ['E-404'] }, g).pass, false);
    const { answerFindingQuestion } = require('../../src/agent/askAbout');
    const q = await answerFindingQuestion({
      finding: { id: 'F-R', claim: 'c', supporting: ['E-1'], contradicting: [] },
      evidence: [{ ref: 'E-1', kind: 'K', summary: 's' }], question: 'q?'
    }, { model: { async complete() { return { content: { answer: 'a', citations: ['E-1'], answerable: 'full', uncertaintyNote: '', missingEvidence: [] } }; } } });
    assert.strictEqual(q.status, 'OK');
    const { Recorder, replayRecording } = require('../../src/agent/replay');
    const rec = new Recorder({ investigationId: 'i', runId: 'r' });
    rec.append('investigation.started', { data: { featureId: 'F1_core' } });
    rec.append('investigation.stopped', { data: { status: 'COMPLETE' } });
    assert.strictEqual(replayRecording(rec.export()).status, 'OK');
    const { checkReadiness } = require('../../src/agent/readiness');
    assert.strictEqual((await checkReadiness('f3.runners')).status, 'TEST_ONLY');
    const { validateSimulationInputs } = require('../../src/services/simulatorService');
    assert.throws(() => validateSimulationInputs({ to: '0x1', data: '0x', decodedTx: {} }), /SIM_VALIDATION/);
    console.log('✔ Test 12 Passed: Gates, lanes, replay, readiness, simulator intact.');
  }

  // Test 13: prose-prefixed model output is repaired; refusals still fail.
  {
    const { SparkAdapter } = require('../../src/agent/sparkAdapter');
    const textAdapter = (text) => new SparkAdapter({
      apiKey: 'test-key',
      fetchImpl: async () => ({
        ok: true,
        text: async () => JSON.stringify({ id: 'r', output: [{ type: 'message', content: [{ type: 'output_text', text }] }], usage: null }),
        headers: { get: () => null }
      })
    });
    const prefixed = await textAdapter('Working on it.\n{"a":1}').complete({ input: 'x' });
    assert.deepStrictEqual(prefixed.content, { a: 1 });
    assert.strictEqual(prefixed.repaired, true);
    const clean = await textAdapter('{"a":2}').complete({ input: 'x' });
    assert.deepStrictEqual(clean.content, { a: 2 });
    assert.strictEqual(clean.repaired, false);
    const bracesInStrings = await textAdapter('Note: use {"x"} syntax.\n{"a":{"b":"}oops{"}}').complete({ input: 'x' });
    assert.deepStrictEqual(bracesInStrings.content, { a: { b: '}oops{' } });
    await assert.rejects(textAdapter("I can't help with that.").complete({ input: 'x' }), (e) => e.type === 'invalid_response');
    await assert.rejects(textAdapter('{"a":').complete({ input: 'x' }), (e) => e.type === 'invalid_response');
    console.log('✔ Test 13 Passed: Prose prefix repaired; refusals/truncation rejected.');
  }

  // Test 14: valid output never triggers a correction request.
  {
    const adapter = plannedAdapter([{ content: stopTurn({ stopReason: 'clean' }) }]);
    const driver = createModelDriver({ adapter });
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(adapter.calls, 1, 'Exactly one model call for valid output');
    assert.strictEqual(record.status, 'COMPLETE');
    assert.ok(!record.turns[0].notes.includes('[corrected'), 'No correction marking on clean turns');
    console.log('✔ Test 14 Passed: Valid turns cost exactly one call.');
  }

  // Test 15: shape-invalid output triggers exactly one correction; the fix is
  // validated from scratch and executed only if fully valid.
  {
    const validDecode = {
      actions: [{ tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: APPROVE_DATA }) }],
      stop: false, stopReason: '', notes: 'fixed turn'
    };
    const capture = [];
    const adapter = plannedAdapter([{ content: 'garbage-string' }, { content: validDecode }, { content: stopTurn() }], { capture });
    const driver = createModelDriver({ adapter });
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(adapter.calls, 3, 'Turn 1 (initial + correction) + turn 2 stop');
    assert.ok(capture[1].input.includes('CORRECTION REQUIRED'), 'Second call is the correction prompt');
    assert.ok(capture[1].input.includes('bad-turn-shape'), 'Correction names the failure category');
    assert.ok(capture[1].input.includes('"stop":<boolean>'), 'Correction restates schema constraints');
    assert.ok(!capture[1].input.includes('garbage-string'), 'Raw bad output is never echoed back');
    assert.strictEqual(record.graph.byKind('ToolResult').length, 1, 'Corrected action executed after full validation');
    assert.ok(record.turns[0].notes.includes('[corrected after 1 malformed attempt'), 'Acceptance marked as corrected');
    // From-scratch proof: a corrected action that fails orchestrator-level
    // validation (malformed address) is rejected, never executed.
    const badInner = {
      actions: [{ tool: 'decode_tx', argsJson: JSON.stringify({ to: '0x123', data: '0x' }) }],
      stop: false, stopReason: '', notes: 'bad address'
    };
    const adapter2 = plannedAdapter([{ content: { actions: 'nope', stop: false, stopReason: '', notes: '' } }, { content: badInner }]);
    const orch2 = new Orchestrator({ modelClient: createModelDriver({ adapter: adapter2 }) });
    const record2 = await orch2.run('F1_core', { goal: 'g' });
    assert.strictEqual(record2.graph.byKind('ToolResult').length, 0, 'Orchestrator-invalid args never execute');
    console.log('✔ Test 15 Passed: One correction; fixed output fully revalidated.');
  }

  // Test 16: a still-malformed correction fails safely with zero execution.
  {
    const adapter = plannedAdapter([{ content: 'bad-1' }, { content: 'bad-2' }, { content: stopTurn() }]);
    const driver = createModelDriver({ adapter });
    const orch = new Orchestrator({ modelClient: driver });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(adapter.calls, 2, 'Initial + exactly one correction, then stop');
    assert.strictEqual(record.status, 'COMPLETE');
    assert.ok(record.stopReason.includes('correction still malformed'));
    assert.ok(record.stopReason.includes('bad-1') === false, 'Raw output not leaked into the reason');
    assert.strictEqual(record.graph.byKind('ToolResult').length, 0);
    console.log('✔ Test 16 Passed: Failed correction stops safely; never a third call.');
  }

  // Test 17: corrected output with invalid actions is filtered, never trusted.
  {
    const mixed = {
      actions: [
        { tool: 'nope_evil', argsJson: '{}' },
        { tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: '0x095ea7b3' }) }
      ],
      stop: false, stopReason: '', notes: 'mixed'
    };
    const adapter = plannedAdapter([{ content: { stop: 'not-a-boolean' } }, { content: mixed }, { content: stopTurn() }]);
    const orch = new Orchestrator({ modelClient: createModelDriver({ adapter }) });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.ok(record.turns[0].actions.some((a) => a.tool === 'decode_tx' && a.ok === true), 'Valid corrected action runs');
    assert.ok(!record.turns[0].actions.some((a) => a.tool === 'nope_evil'), 'Unknown corrected tool never reaches execution');
    const allBad = {
      actions: [{ tool: 'nope_evil', argsJson: '{}' }],
      stop: false, stopReason: '', notes: 'all bad'
    };
    const adapter2 = plannedAdapter([{ content: 42 }, { content: allBad }]);
    const orch2 = new Orchestrator({ modelClient: createModelDriver({ adapter: adapter2 }) });
    const record2 = await orch2.run('F1_core', { goal: 'g' });
    assert.ok(record2.stopReason.includes('no valid actions'));
    assert.strictEqual(record2.graph.byKind('ToolResult').length, 0);
    console.log('✔ Test 17 Passed: Corrected actions filtered by the same pipeline.');
  }

  // Tests 18–22: refusal, transport, auth, provider, and truncation failures
  // never trigger correction — one call, then INCOMPLETE.
  {
    const cases = [
      ['refusal', typedThrow('refusal')],
      ['timeout', new SparkApiError({ status: 0, type: 'timeout', message: 'timed out', retryable: true })],
      ['transport_error', typedThrow('transport_error')],
      ['configuration_error', typedThrow('configuration_error')],
      ['rate_limit_error', new SparkApiError({ status: 429, type: 'rate_limit_error', message: 'slow', retryable: true })],
      ['server_error', new SparkApiError({ status: 500, type: 'server_error', message: 'boom', retryable: true })],
      ['truncated_response', typedThrow('truncated_response')]
    ];
    for (const [label, err] of cases) {
      const adapter = plannedAdapter([{ throw: err }]);
      const orch = new Orchestrator({ modelClient: createModelDriver({ adapter }) });
      const record = await orch.run('F1_core', { goal: 'g' });
      assert.strictEqual(adapter.calls, 1, `${label}: no correction call`);
      assert.strictEqual(record.status, 'INCOMPLETE', `${label}: honest incomplete`);
      assert.strictEqual(record.graph.byKind('ToolResult').length, 0, `${label}: nothing fabricated`);
    }
    console.log('✔ Tests 18–22 Passed: Non-format failures rethrow; zero corrections.');
  }

  // Test 23: usage, cost, response IDs, and provenance across both attempts.
  {
    const firstAttempt = { responseId: 'resp_first', usage: { input_tokens: 10, output_tokens: 5 }, estimatedCostUsd: 1 };
    const capture = [];
    const adapter = plannedAdapter([
      { throw: typedThrow('invalid_response', firstAttempt) },
      { content: stopTurn({ stopReason: 'fixed' }), usage: { input_tokens: 20, output_tokens: 7 }, estimatedCostUsd: 2, responseId: 'resp_second' }
    ], { capture });
    const driver = createModelDriver({ adapter });
    const turn = await driver.nextTurn({ graph: { nodes: [] }, ledger: {} });
    assert.strictEqual(turn.corrected, true);
    assert.deepStrictEqual(turn.usage, { input_tokens: 30, output_tokens: 12 }, 'Token usage summed across attempts');
    assert.strictEqual(turn.estimatedCostUsd, 3, 'Cost summed across attempts');
    assert.deepStrictEqual(turn.correction, { attempts: 2, firstErrorCategory: 'no-parseable-json', firstResponseId: 'resp_first', responseId: 'resp_second' });
    assert.strictEqual(capture[1].previousResponseId, 'resp_first', 'Correction chains off the failed attempt');
    assert.ok(turn.notes.includes('usage combined across both attempts'));
    // Unknown stays unknown: first attempt unreported → nulls, never zeros.
    const adapter2 = plannedAdapter([
      { throw: typedThrow('invalid_response') },
      { content: stopTurn(), usage: { input_tokens: 20, output_tokens: 7 }, estimatedCostUsd: 0.002, responseId: 'resp_b' }
    ]);
    const turn2 = await createModelDriver({ adapter: adapter2 }).nextTurn({ graph: { nodes: [] }, ledger: {} });
    assert.strictEqual(turn2.usage, null, 'Partial usage reported as unknown');
    assert.strictEqual(turn2.estimatedCostUsd, null, 'Partial cost reported as unknown');
    assert.ok(turn2.notes.includes('usage unknown'));
    console.log('✔ Test 23 Passed: Provenance chained; usage merged or honestly unknown.');
  }

  // Test 24: correction cannot exceed turn/action limits.
  {
    const six = {
      actions: [0, 1, 2, 3, 4, 5].map((i) => ({ tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: `0x095ea7b${i}` }) })),
      stop: false, stopReason: '', notes: 'six pack'
    };
    const adapter = plannedAdapter([{ content: 'bad' }, { content: six }]);
    const orch = new Orchestrator({ modelClient: createModelDriver({ adapter }), budget: { maxTurns: 1 } });
    const record = await orch.run('F1_core', { goal: 'g' });
    assert.strictEqual(record.turns.length, 1, 'Correction stays inside the same turn');
    assert.ok(record.turns[0].actions.length <= 4, 'Per-turn cap applies to corrected actions');
    assert.ok(record.turns[0].notes.includes('over the per-turn cap'), 'Truncation disclosed');
    console.log('✔ Test 24 Passed: Correction respects turn and action caps.');
  }

  // Test 25: failed correction cannot verify anything or fabricate evidence.
  {
    const adapter = plannedAdapter([{ content: 'bad-1' }, { content: 'bad-2' }]);
    const adv = await runAdvanced(
      { goal: 'g', inputs: {}, hypotheses: [{ id: 'H-1', claim: 'c', supporting: [], contradicting: [] }] },
      { modelClient: createModelDriver({ adapter }), reviewer: { async complete() { return { content: { verdict: 'SUPPORTED', reasons: ['trust me'] } }; } } }
    );
    assert.ok(adv.record.stopReason.includes('correction still malformed'));
    assert.strictEqual(adv.record.graph.byKind('ToolResult').length, 0);
    assert.ok(adv.reviewed.every((r) => r.adjudication.status !== 'VERIFIED'), 'Failed correction never verifies');
    console.log('✔ Test 25 Passed: Failed correction yields no findings, no VERIFIED.');
  }

  // Test 26: F1/F2 behavior unchanged when correction never triggers.
  {
    const decode = {
      actions: [{ tool: 'decode_tx', argsJson: JSON.stringify({ to: ADDR_B, data: APPROVE_DATA }) }],
      stop: false, stopReason: '', notes: 'decode'
    };
    const adapter = plannedAdapter([decode, stopTurn({ stopReason: 'have decode' })]);
    const f1 = await runCoreInvestigation({ goal: 'g', inputs: {} }, { modelClient: createModelDriver({ adapter }) });
    assert.strictEqual(adapter.calls, 2, 'One call per turn, no extras');
    assert.ok(f1.record.turns.every((t) => !(t.notes || '').includes('[corrected')));
    const adapter2 = plannedAdapter([decode, stopTurn({ stopReason: 'have decode' })]);
    const f2 = await runAdvanced(
      { goal: 'g', inputs: {}, hypotheses: [{ id: 'H-1', claim: 'approval decoded', supporting: ['E-002'] }] },
      { modelClient: createModelDriver({ adapter: adapter2 }), reviewer: { async complete() { return { content: { verdict: 'SUPPORTED', reasons: ['ok'] } }; } } }
    );
    assert.strictEqual(f2.reviewed[0].adjudication.status, 'VERIFIED');
    console.log('✔ Test 26 Passed: Clean runs behave exactly as before.');
  }

  // Test 27: adapter error taxonomy — refusal, truncation, transport typed.
  {
    const { SparkAdapter } = require('../../src/agent/sparkAdapter');
    const bodyAdapter = (body) => new SparkAdapter({
      apiKey: 'test-key',
      fetchImpl: async () => ({ ok: true, text: async () => JSON.stringify(body), headers: { get: () => null } })
    });
    const refused = await bodyAdapter({ id: 'r1', status: 'completed', output: [{ type: 'refusal', refusal: 'nope' }], usage: { input_tokens: 3, output_tokens: 1 } })
      .complete({ input: 'x' }).then(() => null, (e) => e);
    assert.strictEqual(refused.type, 'refusal');
    assert.ok(!refused.message.includes('nope'), 'Refusal text never echoed');
    assert.strictEqual(refused.attempt.responseId, 'r1', 'Attempt provenance attached');
    const blockRefused = await bodyAdapter({ id: 'r1b', output: [{ type: 'message', content: [{ type: 'refusal', refusal: 'no' }] }] })
      .complete({ input: 'x' }).then(() => null, (e) => e);
    assert.strictEqual(blockRefused.type, 'refusal');
    const truncated = await bodyAdapter({ id: 'r2', status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' }, output: [] })
      .complete({ input: 'x' }).then(() => null, (e) => e);
    assert.strictEqual(truncated.type, 'truncated_response');
    assert.ok(truncated.message.includes('max_output_tokens'));
    const connFail = new SparkAdapter({ apiKey: 'k', fetchImpl: async () => { throw new TypeError('fetch failed'); } });
    const transport = await connFail.request({ input: 'x' }).then(() => null, (e) => e);
    assert.strictEqual(transport.type, 'transport_error');
    assert.strictEqual(transport.retryable, false, 'Retry policy unchanged: no new retries');
    const garbageBody = new SparkAdapter({ apiKey: 'k', fetchImpl: async () => ({ ok: true, status: 200, text: async () => '<html>proxy', headers: { get: () => null } }) });
    const garbage = await garbageBody.request({ input: 'x' }).then(() => null, (e) => e);
    assert.strictEqual(garbage.type, 'transport_error');
    const malformed = await bodyAdapter({ id: 'r3', output: [{ type: 'message', content: [{ type: 'output_text', text: 'plain prose, no json' }] }] })
      .complete({ input: 'x' }).then(() => null, (e) => e);
    assert.strictEqual(malformed.type, 'invalid_response');
    assert.strictEqual(malformed.attempt.responseId, 'r3');
    console.log('✔ Test 27 Passed: refusal/truncated/transport/invalid distinctly typed.');
  }

  console.log('\nAll Model Driver Tests Passed Successfully!\n');
}

if (require.main === module) {
  runDriverTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runDriverTests };
