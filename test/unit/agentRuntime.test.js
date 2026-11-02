const assert = require('assert');
const { createAutonomousAgent } = require('../../agent/index');
const { ZERO_ADDRESS } = require('../../agent/planner/planner');

// Agent runtime lifecycle: planning, conservative execution, refusal
// handling, and reporting. Planner and Assertara integration are both
// faked here (no network, no model); genuine behavior is covered by
// the demo e2e suite and the gated live test.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

function stubPlanner(plan, model) {
  const calls = [];
  const fn = async ({ task }) => { calls.push(task); return { plan, model: model || 'stub-planner-1' }; };
  fn.calls = calls;
  return fn;
}

function fakeIntegration(script) {
  // script: array of per-submit outcomes or Errors to throw.
  const calls = [];
  let i = 0;
  return {
    calls,
    isCleanExecution: (ex) => Boolean(ex && ex.outcome === 'EXECUTED'),
    async executeAction(tx, opts) {
      calls.push({ tx, opts });
      const next = script[Math.min(i, script.length - 1)];
      i += 1;
      if (next instanceof Error) throw next;
      return next;
    }
  };
}

function allowOutcome(overrides) {
  return {
    requestId: 'agent_a1', traceId: 'tr_a1', txDigest: 'd', decision: 'ALLOW',
    reasons: ['ok'], released: false, txHash: '0xexec', receipt: { status: '0x1' },
    execution: { outcome: 'EXECUTED', txHash: '0xexec' }, findings: { v: 1 },
    ...(overrides || {})
  };
}

function singleActionPlan() {
  return { reasoning: 'pay the contributor', actions: [{ note: 'pay', to: A1, value: '0x1000', data: '0x' }] };
}

function makeAgent({ plan, model, script, plannerFn } = {}) {
  const planner = plannerFn || stubPlanner(plan || singleActionPlan(), model);
  const integration = fakeIntegration(script || [allowOutcome()]);
  const events = [];
  const agent = createAutonomousAgent({
    agentId: 'test-agent', address: A0, chainId: 31337,
    planner, integration, onEvent: (e) => events.push(e)
  });
  return { agent, planner, integration, events };
}

async function runAgentRuntimeTests() {
  console.log('Testing agent runtime (lifecycle, refusals, reporting)...\n');

  // Test 1: ALLOW completes with shared ids and an ordered stage log.
  {
    const { agent, integration, events } = makeAgent({});
    const out = await agent.runTask('Pay the contributor');
    assert.strictEqual(out.status, 'COMPLETED');
    assert.strictEqual(out.actions.length, 1);
    assert.strictEqual(out.actions[0].requestId, 'agent_a1');
    assert.strictEqual(out.actions[0].traceId, 'tr_a1');
    assert.strictEqual(out.actions[0].txHash, '0xexec');
    assert.strictEqual(out.decision, 'ALLOW');
    assert.deepStrictEqual(out.actions[0].transaction, { from: A0, to: A1, value: '0x1000', data: '0x', chainId: 31337 });
    const stages = out.steps.map((s) => s.event);
    assert.deepStrictEqual(stages.slice(0, 4), ['TASK_RECEIVED', 'PLANNING', 'PLANNED', 'ACTION_CONSTRUCTED']);
    assert.strictEqual(stages[stages.length - 1], 'TASK_COMPLETED');
    assert.strictEqual(integration.calls.length, 1, 'submitted exactly once');
    assert.ok(events.length > 0, 'observer received events');
    assert.ok(events.every((e) => e.taskId === out.taskId), 'events carry the task id');
    console.log('✔ Test 1 Passed: ALLOW completes with shared ids and ordered stages.');
  }

  // Test 2: BLOCK stops the task with no resubmission.
  {
    const blocked = { ...allowOutcome(), decision: 'BLOCK', reasons: ['mandate: denied'], released: false, txHash: null, receipt: null, execution: null, stopped: true };
    const { agent, integration } = makeAgent({ script: [blocked] });
    const out = await agent.runTask('Pay the stranger');
    assert.strictEqual(out.status, 'STOPPED');
    assert.ok(out.stoppedReason.startsWith('BLOCKED'), out.stoppedReason);
    assert.strictEqual(out.decision, 'BLOCK');
    assert.strictEqual(out.txHash, null, 'nothing signed');
    assert.strictEqual(integration.calls.length, 1, 'submitted once, never resubmitted');
    assert.strictEqual(out.actions[0].requestId, 'agent_a1', 'denial still traceable by id');
    console.log('✔ Test 2 Passed: BLOCK stops without resubmission, denial traceable.');
  }

  // Test 3: UNCERTAIN stops the task and is never treated as approval.
  {
    const uncertain = { ...allowOutcome(), decision: 'UNCERTAIN', reasons: ['mandate: inconclusive'], txHash: null, receipt: null, execution: null, stopped: true };
    const { agent, integration } = makeAgent({ script: [uncertain] });
    const out = await agent.runTask('Do the unclear thing');
    assert.strictEqual(out.status, 'STOPPED');
    assert.ok(/HELD: decision UNCERTAIN/.test(out.stoppedReason));
    assert.strictEqual(integration.calls.length, 1);
    console.log('✔ Test 3 Passed: UNCERTAIN stops, never approved.');
  }

  // Test 4: released REVIEW executes; operator timeout keeps HELD semantics.
  {
    const released = allowOutcome({ decision: 'REVIEW', released: true });
    const { agent } = makeAgent({ script: [released] });
    const out = await agent.runTask('Big payment');
    assert.strictEqual(out.status, 'COMPLETED');
    assert.strictEqual(out.decision, 'REVIEW');
    assert.strictEqual(out.actions[0].released, true);
    const timeoutErr = new Error('Timed out waiting for operator release.');
    timeoutErr.code = 'TIMEOUT';
    const held = makeAgent({ script: [timeoutErr] });
    const out2 = await held.agent.runTask('Big payment');
    assert.strictEqual(out2.status, 'STOPPED');
    assert.strictEqual(out2.stoppedReason, 'HELD: operator release not observed before timeout');
    console.log('✔ Test 4 Passed: Released REVIEW executes; timeout stays HELD.');
  }

  // Test 5: planner gaps (zero-address) stop before any submission.
  {
    const gap = { reasoning: 'no recipient named', actions: [{ note: 'gap', to: ZERO_ADDRESS, value: '0x0', data: '0x' }] };
    const { agent, integration } = makeAgent({ plan: gap });
    const out = await agent.runTask('Pay someone');
    assert.strictEqual(out.status, 'STOPPED');
    assert.ok(out.stoppedReason.startsWith('PLAN_INCOMPLETE'), out.stoppedReason);
    assert.strictEqual(integration.calls.length, 0, 'placeholder never submitted');
    console.log('✔ Test 5 Passed: Planner gaps stop with zero submissions.');
  }

  // Test 6: planner failure and transport errors stop loudly.
  {
    const bad = makeAgent({ plannerFn: async () => ({ plan: { nope: true }, model: 'stub' }) });
    const out = await bad.agent.runTask('Pay');
    assert.strictEqual(out.status, 'STOPPED');
    assert.ok(out.stoppedReason.startsWith('PLAN_FAILED'), out.stoppedReason);
    const boom = makeAgent({ script: [new Error('connection reset')] });
    const out2 = await boom.agent.runTask('Pay');
    assert.strictEqual(out2.status, 'STOPPED');
    assert.ok(out2.stoppedReason.startsWith('EXECUTION_ERROR'), out2.stoppedReason);
    console.log('✔ Test 6 Passed: Plan and transport failures stop loudly.');
  }

  // Test 7: multi-action — first executes, BLOCK on second ends the task.
  {
    const plan = {
      reasoning: 'two pays',
      actions: [
        { note: 'one', to: A1, value: '0x1000', data: '0x' },
        { note: 'two', to: A1, value: '0x1000', data: '0x' }
      ]
    };
    const blocked = { ...allowOutcome({ requestId: 'agent_b2' }), decision: 'BLOCK', reasons: ['mandate: denied'], txHash: null, receipt: null, execution: null, stopped: true };
    const { agent, integration } = makeAgent({ plan, script: [allowOutcome({ requestId: 'agent_b1' }), blocked] });
    const out = await agent.runTask('Pay twice');
    assert.strictEqual(out.status, 'STOPPED');
    assert.ok(out.stoppedReason.startsWith('BLOCKED'));
    assert.strictEqual(out.actions.length, 2, 'first action intact, denial recorded');
    assert.strictEqual(out.actions[0].txHash, '0xexec');
    assert.strictEqual(out.actions[1].txHash, null);
    assert.strictEqual(integration.calls.length, 2, 'no third submit, no reroute');
    console.log('✔ Test 7 Passed: Multi-action stops at first refusal, history intact.');
  }

  // Test 8: unclean execution (diverged) stops further actions.
  {
    const dirty = allowOutcome({ execution: { outcome: 'EFFECTS_DIVERGED', txHash: '0xexec' } });
    const plan = {
      reasoning: 'two pays',
      actions: [
        { note: 'one', to: A1, value: '0x1000', data: '0x' },
        { note: 'two', to: A1, value: '0x1000', data: '0x' }
      ]
    };
    const { agent, integration } = makeAgent({ plan, script: [dirty, allowOutcome()] });
    const out = await agent.runTask('Pay twice');
    assert.strictEqual(out.status, 'STOPPED');
    assert.ok(out.stoppedReason.startsWith('EXECUTION_NOT_CLEAN'), out.stoppedReason);
    assert.strictEqual(integration.calls.length, 1, 'second action never submitted');
    console.log('✔ Test 8 Passed: Diverged execution halts the task.');
  }

  // Test 9: registry + constructor validation.
  {
    const { agent } = makeAgent({});
    const out = await agent.runTask('Pay');
    assert.strictEqual(agent.getTask(out.taskId).taskId, out.taskId);
    assert.strictEqual(agent.getTask('task_missing'), null);
    assert.ok(agent.listTasks().length >= 1);
    assert.throws(() => createAutonomousAgent({ chainId: 1, planner: async () => ({}), integration: {} }), /sending address/);
    assert.throws(() => createAutonomousAgent({ address: A0, planner: async () => ({}), integration: {} }), /chain id/);
    assert.throws(() => createAutonomousAgent({ address: A0, chainId: 1, integration: { executeAction: async () => ({}) } }), /planner/);
    assert.throws(() => createAutonomousAgent({ address: A0, chainId: 1, planner: async () => ({}) }), /integration/);
    await assert.rejects(() => agent.runTask('  '), /non-empty task/);
    console.log('✔ Test 9 Passed: Registry works; constructor and intake validate.');
  }

  console.log('\nAll agent runtime tests passed.');
}

if (require.main === module) {
  runAgentRuntimeTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentRuntimeTests };
