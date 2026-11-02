const assert = require('assert');
const T = require('../../src/agentTasks');

function res() {
  return {
    statusCode: 200, body: null,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; }
  };
}

function run() {
  console.log('Testing agent task surface...\n');
  T.setAgentTaskRunner(null);

  // 1. Unattached runner answers 503 (honest, never invents a task).
  {
    const r1 = res();
    T.handleCreateTask({ body: { task: 'hello' } }, r1);
    assert.strictEqual(r1.statusCode, 503);
    const r2 = res();
    T.handleGetTask({ params: { id: 'task_x' } }, r2);
    assert.strictEqual(r2.statusCode, 503);
    console.log('  ✔ unattached runner answers 503');
  }

  // 2. Validation: empty, missing, and oversized tasks rejected.
  {
    T.setAgentTaskRunner({ submit: () => ({ taskId: 't1' }), get: () => null });
    try {
      for (const body of [{}, { task: '' }, { task: '   ' }, { task: 'x'.repeat(2001) }, {}]) {
        const r = res();
        T.handleCreateTask({ body }, r);
        assert.strictEqual(r.statusCode, 400, JSON.stringify(body).slice(0, 40));
      }
      console.log('  ✔ task validation rejects bad input');
    } finally {
      T.setAgentTaskRunner(null);
    }
  }

  // 3. Submit returns 202 with the runner-issued id; busy runner maps to 409.
  {
    let calls = 0;
    T.setAgentTaskRunner({
      submit: () => { calls += 1; return { taskId: 'task_abc' }; },
      get: () => null
    });
    try {
      const r = res();
      T.handleCreateTask({ body: { task: 'Pay X' } }, r);
      assert.strictEqual(r.statusCode, 202);
      assert.deepStrictEqual(r.body, { taskId: 'task_abc', status: 'RUNNING' });
      assert.strictEqual(calls, 1);
    } finally {
      T.setAgentTaskRunner(null);
    }
    T.setAgentTaskRunner({
      submit: () => { throw Object.assign(new Error('busy'), { code: 'TASK_RUNNING' }); },
      get: () => null
    });
    try {
      const r = res();
      T.handleCreateTask({ body: { task: 'Pay X' } }, r);
      assert.strictEqual(r.statusCode, 409);
      console.log('  ✔ submit 202 + busy 409');
    } finally {
      T.setAgentTaskRunner(null);
    }
  }

  // 4. Get returns the projected outcome; unknown ids 404.
  {
    const outcome = {
      taskId: 'task_abc', agent: 'demo-agent', task: 'Pay X', status: 'COMPLETED',
      reasoning: 'r', plannerModel: 'm', planAttempts: 1, decision: 'ALLOW',
      txHash: '0x1', execution: { outcome: 'EXECUTED' }, stoppedReason: null,
      actions: [{
        index: 0, transaction: { to: '0x2', value: '5', chainId: 31337 }, digestPreview: 'd',
        requestId: 'req', traceId: 'tr', txDigest: 'dg', decision: 'ALLOW', reasons: ['ok'],
        released: false, txHash: '0x1', receipt: { status: '0x1' }, execution: { outcome: 'EXECUTED' },
        findings: { v: 1 }, secretField: 'must-not-pass'
      }],
      steps: [{ at: 1, event: 'TASK_RECEIVED', detail: 'Pay X', actionIndex: null }, 'junk', null],
      privateKey: 'must-not-pass'
    };
    T.setAgentTaskRunner({ submit: () => ({ taskId: 'x' }), get: (id) => (id === 'task_abc' ? outcome : null) });
    try {
      const r = res();
      T.handleGetTask({ params: { id: 'task_abc' } }, r);
      assert.strictEqual(r.statusCode, 200);
      assert.strictEqual(r.body.taskId, 'task_abc');
      assert.strictEqual(r.body.privateKey, undefined, 'projection drops unknown fields');
      assert.strictEqual(r.body.actions[0].secretField, undefined);
      assert.strictEqual(r.body.steps.length, 1, 'malformed steps dropped');
      assert.strictEqual(r.body.steps[0].event, 'TASK_RECEIVED');
      const r404 = res();
      T.handleGetTask({ params: { id: 'nope' } }, r404);
      assert.strictEqual(r404.statusCode, 404);
      const rBad = res();
      T.handleGetTask({ params: {} }, rBad);
      assert.strictEqual(rBad.statusCode, 404);
      console.log('  ✔ get projects outcome; unknown ids 404');
    } finally {
      T.setAgentTaskRunner(null);
    }
  }

  // 5. src/ never imports the agent subsystem (boundary preserved).
  {
    const fs = require('fs');
    const src = fs.readFileSync(require.resolve('../../src/agentTasks'), 'utf8');
    assert.ok(!src.includes('agent/') && !src.includes('agent\\'), 'agentTasks must not import agent/');
    assert.ok(!src.includes('sdk/') && !src.includes('sdk\\'), 'agentTasks must not import sdk/');
    console.log('  ✔ import boundary preserved (no agent/ or sdk/ imports)');
  }

  console.log('\nAll Agent Task Tests Passed Successfully!');
}

if (require.main === module) run();
module.exports = { run };
