const assert = require('assert');
const { createAutonomousAgent } = require('../../agent/index');
const { projectTask } = require('../../src/agentTasks');

// Task timing instrumentation: planning, per-action submit/wait/
// execute phases, and total wall time are genuinely measured and
// persisted on the task record, then projected to the task surface.
// Planner and integration are faked (no network, no model).

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const PLAN = { reasoning: 'pay the contributor', actions: [{ note: 'pay', to: A1, value: '0x1000', data: '0x' }] };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function memoryStore() {
  const tasks = new Map();
  return {
    tasks,
    createTask(rec) { tasks.set(rec.taskId, { ...rec }); },
    updateTask(id, patch) { tasks.set(id, { ...(tasks.get(id) || {}), ...(patch || {}), taskId: id }); },
    getTask(id) { return tasks.get(id) || null; }
  };
}

async function runAgentTimingsTests() {
  console.log('Testing agent timing instrumentation...\n');

  // Test 1: COMPLETED task carries measured plan/total timings and
  // per-action phase timings; the store persists them.
  {
    const store = memoryStore();
    const planner = async () => { await sleep(40); return { plan: PLAN, model: 'stub' }; };
    const integration = {
      isCleanExecution: (ex) => ex && ex.outcome === 'EXECUTED',
      async executeAction() {
        await sleep(10);
        return {
          requestId: 'r', traceId: 'tr', txDigest: 'd', decision: 'ALLOW', reasons: ['ok'],
          released: false, txHash: '0x1', receipt: {}, execution: { outcome: 'EXECUTED' },
          findings: {}, timings: { submitMs: 11, waitMs: 22, executeMs: 33 }
        };
      }
    };
    const agent = createAutonomousAgent({ agentId: 't', address: A0, chainId: 31337, planner, integration, taskStore: store });
    const out = await agent.runTask('Pay the contributor');
    assert.strictEqual(out.status, 'COMPLETED');
    assert.ok(out.timings.planMs >= 35, `planMs measured, got ${out.timings.planMs}`);
    assert.ok(out.timings.totalMs >= out.timings.planMs, 'total covers planning');
    assert.deepStrictEqual(out.actions[0].timings, { submitMs: 11, waitMs: 22, executeMs: 33 });
    const stored = store.getTask(out.taskId);
    assert.deepStrictEqual(stored.timings, out.timings, 'store persists task timings');
    assert.deepStrictEqual(stored.actions[0].timings, { submitMs: 11, waitMs: 22, executeMs: 33 });
    const projected = projectTask(stored);
    assert.deepStrictEqual(projected.timings, out.timings, 'task surface exposes timings');
    assert.deepStrictEqual(projected.actions[0].timings, { submitMs: 11, waitMs: 22, executeMs: 33 });
  }

  // Test 2: BLOCKED task still records timings (executeMs null).
  {
    const planner = async () => ({ plan: PLAN, model: 'stub' });
    const integration = {
      isCleanExecution: () => false,
      async executeAction() {
        return {
          requestId: 'r', traceId: 'tr', txDigest: 'd', decision: 'BLOCK', reasons: ['denied'],
          released: false, txHash: null, receipt: null, execution: null,
          findings: {}, stopped: true, timings: { submitMs: 5, waitMs: 50, executeMs: null }
        };
      }
    };
    const agent = createAutonomousAgent({ agentId: 't', address: A0, chainId: 31337, planner, integration });
    const out = await agent.runTask('Pay the stranger');
    assert.strictEqual(out.status, 'STOPPED');
    assert.deepStrictEqual(out.actions[0].timings, { submitMs: 5, waitMs: 50, executeMs: null });
    assert.ok(Number.isFinite(out.timings.totalMs));
  }

  // Test 3: PLAN_FAILED records a total but no plan duration.
  {
    const planner = async () => { throw new Error('no key'); };
    const agent = createAutonomousAgent({
      agentId: 't', address: A0, chainId: 31337, planner,
      integration: { executeAction: async () => { throw new Error('must not submit'); } }
    });
    const out = await agent.runTask('Pay anyone');
    assert.strictEqual(out.status, 'STOPPED');
    assert.match(out.stoppedReason, /PLAN_FAILED/);
    assert.strictEqual(out.timings.planMs, null);
    assert.ok(Number.isFinite(out.timings.totalMs));
  }

  // Test 4: projection sanitizes non-numeric timings and tolerates absence.
  {
    const junk = projectTask({ taskId: 'x', timings: { planMs: 'soon', totalMs: -5 }, actions: [{ timings: { submitMs: NaN } }] });
    assert.deepStrictEqual(junk.timings, { planMs: null, totalMs: null });
    assert.deepStrictEqual(junk.actions[0].timings, { submitMs: null, waitMs: null, executeMs: null });
    const bare = projectTask({ taskId: 'x' });
    assert.strictEqual(bare.timings, null);
    assert.deepStrictEqual(bare.actions, []);
  }

  console.log('\nAll Agent Timing Tests Passed Successfully!');
}

runAgentTimingsTests().catch((err) => { console.error(err); process.exit(1); });
