const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createAgent, validatePlan } = require('../../demo/agent');

// Agent-runner boundaries + decision control flow. ALL model/policy/signer
// interactions here are injected fakes (MOCKED) — these tests prove the
// agent obeys decisions and holds no authority, never that it can reason.
// Genuine reasoning is evidenced only by the live demo (demo/runDemo.js).

const PLAN = { reasoning: 'stub plan', to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', value: '0x11c37937e0800', data: '0x' };

function fakePolicy({ decision, token, statuses }) {
  const calls = { propose: 0, status: 0 };
  let n = 0;
  return {
    calls,
    api: {
      propose: async () => {
        calls.propose += 1;
        return { requestId: 'agent_test-1', decision, approval: token || null, reasons: [], investigation: { verdict: 'MATCH', reasoningOrigin: 'model' } };
      },
      status: async () => {
        calls.status += 1;
        if (statuses && statuses[Math.min(n, statuses.length - 1)]) return statuses[Math.min(n++, statuses.length - 1)];
        return { decision, approvalToken: token || null, execution: token ? { outcome: 'EXECUTED', receiptStatus: '0x1' } : null };
      }
    }
  };
}

async function runAgentRunnerTests() {
  console.log('Testing agent-runner boundaries + control flow (MOCKED transports)...\n');

  // Test 1: source hygiene — the agent holds no authority material.
  {
    const src = fs.readFileSync(path.join(__dirname, '..', '..', 'demo', 'agent.js'), 'utf8');
    for (const forbidden of ['SIGNER_PRIVATE_KEY', 'APPROVAL_SECRET', 'OPERATOR_SECRET', 'privateKeyToAccount', 'sendTransaction', 'eth_sendTransaction', 'mnemonic', '.authorize', 'authorize:', 'authorize(']) {
      assert.ok(!src.includes(forbidden), `agent source must not contain code pattern ${forbidden}`);
    }
    assert.ok(!/require\(['"]\.\.\/src\/signer\//.test(src), 'agent must not import the signer');
    assert.ok(!/require\(['"]\.\.\/src\/services\/approvals['"]\)/.test(src), 'agent must not import approvals');
    console.log('✔ Test 1 Passed: Agent source holds no authority.');
  }

  // Test 2: ALLOW executes exactly once through the controlled path.
  {
    const policy = fakePolicy({ decision: 'ALLOW', token: 'apv1.stub.token' });
    const signs = [];
    const agent = createAgent({
      agentId: 't', address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', chainId: '0x7a69',
      planner: async () => ({ plan: PLAN, model: 'stub' }),
      policyApi: policy.api,
      signerApi: { sign: async (p) => { signs.push(p); return { ok: true, txHash: `0x${'aa'.repeat(32)}` }; } }
    });
    const o = await agent.runTask('stub task');
    assert.strictEqual(o.decision, 'ALLOW');
    assert.strictEqual(signs.length, 1, 'exactly one signer call');
    assert.deepStrictEqual(signs[0].transaction.to, PLAN.to);
    assert.strictEqual(signs[0].approval, 'apv1.stub.token', 'signs with the issued token only');
    assert.strictEqual(o.execution.outcome, 'EXECUTED');
    assert.strictEqual(o.stoppedReason, null);
    console.log('✔ Test 2 Passed: ALLOW executes once.');
  }

  // Test 3: BLOCK stops the task with no signer contact and no retry.
  {
    const policy = fakePolicy({ decision: 'BLOCK' });
    let signs = 0;
    const agent = createAgent({
      agentId: 't', address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', chainId: '0x7a69',
      planner: async () => ({ plan: PLAN, model: 'stub' }),
      policyApi: policy.api,
      signerApi: { sign: async () => { signs += 1; return { ok: true, txHash: '0x00' }; } }
    });
    const o = await agent.runTask('stub task');
    assert.strictEqual(o.decision, 'BLOCK');
    assert.strictEqual(signs, 0, 'blocked agent never calls the signer');
    assert.strictEqual(policy.calls.propose, 1, 'no modify-and-resubmit after BLOCK');
    assert.ok(/^BLOCKED/.test(o.stoppedReason));
    assert.strictEqual(o.txHash, null);
    console.log('✔ Test 3 Passed: BLOCK stops without retry.');
  }

  // Test 4: REVIEW polls without signing until an operator release appears.
  {
    const policy = fakePolicy({
      decision: 'REVIEW',
      statuses: [
        { decision: 'REVIEW', approvalToken: null, execution: null },
        { decision: 'REVIEW', approvalToken: 'apv1.released.token', execution: null },
        { decision: 'REVIEW', approvalToken: 'apv1.released.token', execution: { outcome: 'EXECUTED', receiptStatus: '0x1' } }
      ]
    });
    const signs = [];
    const agent = createAgent({
      agentId: 't', address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', chainId: '0x7a69',
      planner: async () => ({ plan: PLAN, model: 'stub' }),
      policyApi: policy.api,
      signerApi: { sign: async (p) => { signs.push(p); return { ok: true, txHash: `0x${'bb'.repeat(32)}` }; } },
      pollIntervalMs: 5, reviewTimeoutMs: 5000
    });
    assert.ok(!('authorize' in policy.api), 'agent policy surface exposes no authorize');
    const o = await agent.runTask('stub task');
    assert.strictEqual(o.decision, 'REVIEW');
    assert.strictEqual(signs.length, 1, 'signs once, only after the token appears');
    assert.strictEqual(signs[0].approval, 'apv1.released.token');
    assert.strictEqual(o.execution.outcome, 'EXECUTED');
    console.log('✔ Test 4 Passed: REVIEW waits, then proceeds on release.');
  }

  // Test 5: UNCERTAIN (and anything unexpected) authorizes nothing.
  {
    for (const decision of ['UNCERTAIN', 'WEIRD']) {
      const policy = fakePolicy({ decision });
      let signs = 0;
      const agent = createAgent({
        agentId: 't', address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', chainId: '0x7a69',
        planner: async () => ({ plan: PLAN, model: 'stub' }),
        policyApi: policy.api,
        signerApi: { sign: async () => { signs += 1; return { ok: true, txHash: '0x00' }; } }
      });
      const o = await agent.runTask('stub task');
      assert.strictEqual(signs, 0, `${decision} never signs`);
      assert.strictEqual(policy.calls.propose, 1, `${decision} never resubmits`);
      assert.ok(o.stoppedReason, `${decision} records a stop`);
    }
    console.log('✔ Test 5 Passed: UNCERTAIN/unknown held.');
  }

  // Test 6: invalid planner output never reaches Assertara.
  {
    let proposes = 0;
    const agent = createAgent({
      agentId: 't', address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', chainId: '0x7a69',
      planner: async () => ({ plan: { reasoning: '', to: 'nope', value: 'lots', data: '0x' }, model: 'stub' }),
      policyApi: { propose: async () => { proposes += 1; return {}; }, status: async () => ({}) },
      signerApi: { sign: async () => ({ ok: true, txHash: '0x00' }) }
    });
    const o = await agent.runTask('stub task');
    assert.strictEqual(proposes, 0, 'malformed plans are never proposed');
    assert.ok(/^PLAN_FAILED/.test(o.stoppedReason));
    assert.strictEqual(validatePlan(PLAN), null, 'validator accepts a good plan');
    assert.ok(validatePlan({ ...PLAN, to: '0x123' }), 'validator rejects bad address');
    console.log('✔ Test 6 Passed: Malformed plans contained.');
  }

  console.log('\nAll Agent-Runner Boundary Tests Passed Successfully!\n');
}

if (require.main === module) {
  runAgentRunnerTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentRunnerTests };
