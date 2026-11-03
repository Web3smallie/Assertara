const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Agent Demo A/B end-to-end: REAL agent runtime + REAL SDK + REAL
// policy app, signer, and Anvil. Planners are deterministic stubs and
// the investigation model is canned MATCH (labeled MOCK) so verdicts
// are deterministic; genuine autonomy (live planner + live model) is
// covered by the gated test/live/agentLive.test.js.

const { bootStack } = require('../../demo/command-stack');
const { LOCAL_ADDRS } = require('../../demo/scenarios');
const { createAutonomousAgent } = require('../../agent/index');
const { createTaskStore } = require('../../agent/runtime/taskStore');
const { createAssertaraIntegration, createClient } = require('../../agent/integrations/assertara');

const VALUE_0005 = '0x11c37937e08000'; // 0.005 ETH

async function rpc(rpcUrl, method, params) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params || [] })
  });
  if (!res.ok) throw new Error(`rpc http ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(body.error.message || 'rpc error');
  return body.result;
}

function stubPlanner(plan) {
  return async () => ({ plan, model: 'stub-planner-e2e' });
}

async function runAgentDemoTests() {
  console.log('Testing agent demos A/B (runtime + SDK + stack; MOCK model)...\n');
  const stack = await bootStack({});
  console.log(`  stack: policy=${stack.policyBase} signer=${stack.signerBase}`);
  const realFetch = global.fetch;
  try {
    const appConfig = require('../../src/config/env');
    global.fetch = async (url, opts) => {
      if (typeof url === 'string' && url.startsWith(appConfig.metaApiBaseUrl)) {
        return {
          ok: true,
          json: async () => ({ choices: [{ message: { content: JSON.stringify({
            verdict: 'MATCH', confidence: 0.95, summary: 'agent-demos MOCK MATCH',
            discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
          }) } }] })
        };
      }
      return realFetch(url, opts);
    };

    const store = createTaskStore({
      snapshotFile: path.join(stack.tmp, 'agent-tasks.json'),
      ledgerFile: path.join(stack.tmp, 'agent-tasks.jsonl')
    });
    store.load();
    const client = createClient({ policyBase: stack.policyBase, signerBase: stack.signerBase, fetchImpl: realFetch });

    // Demo A: legitimate contributor payment executes end to end.
    {
      const before = await rpc(stack.anvilRpc, 'eth_blockNumber', []);
      const agent = createAutonomousAgent({
        agentId: 'demo-a-agent', address: LOCAL_ADDRS.a0, chainId: 31337,
        planner: stubPlanner({
          reasoning: 'Pay the October contributor milestone to the named address.',
          actions: [{ note: 'contributor payment', to: LOCAL_ADDRS.a1, value: VALUE_0005, data: '0x' }]
        }),
        integration: createAssertaraIntegration({ client, agentId: 'demo-a-agent' }),
        taskStore: store
      });
      const out = await agent.runTask(`Pay our contributor 0.005 ETH at ${LOCAL_ADDRS.a1} for the October milestone.`);
      assert.strictEqual(out.status, 'COMPLETED', JSON.stringify(out.stoppedReason));
      assert.strictEqual(out.decision, 'ALLOW');
      assert.ok(/^0x[0-9a-fA-F]{64}$/.test(out.txHash), 'real tx hash');
      assert.strictEqual(out.execution.outcome, 'EXECUTED');
      assert.strictEqual(out.reasoning, 'Pay the October contributor milestone to the named address.', 'planner reasoning verbatim');
      const a = out.actions[0];
      assert.ok(/^agent_/.test(a.requestId) && typeof a.traceId === 'string', 'shared ids on the action');
      assert.ok(Array.isArray(a.reasons) && a.reasons.length > 0, 'Assertara reasons recorded');
      assert.ok(!a.reasons.includes(out.reasoning), 'investigation findings distinct from planner reasoning');
      assert.ok(a.findings && a.findings.v === 1, 'evidence envelope attached');
      const receipt = await rpc(stack.anvilRpc, 'eth_getTransactionReceipt', [out.txHash]);
      assert.strictEqual(receipt.status, '0x1', 'independent receipt verification');
      assert.strictEqual(receipt.to.toLowerCase(), LOCAL_ADDRS.a1.toLowerCase());
      const after = await rpc(stack.anvilRpc, 'eth_blockNumber', []);
      assert.strictEqual(BigInt(after) - BigInt(before), 1n, 'chain advanced exactly one block');
      // Cross-check through a second path: raw status read shows the same decision.
      const st = await (await realFetch(`${stack.policyBase}/api/v1/agent/requests/${a.requestId}`)).json();
      assert.strictEqual(st.decision, 'ALLOW');
      assert.strictEqual(st.execution.outcome, 'EXECUTED');
      // Durability: the task journal survives a reload.
      const store2 = createTaskStore({ snapshotFile: path.join(stack.tmp, 'agent-tasks.json') });
      store2.load();
      const reloaded = store2.getTask(out.taskId);
      assert.ok(reloaded && reloaded.status === 'COMPLETED' && reloaded.actions.length === 1, 'task journal durable');
      assert.strictEqual(reloaded.actions[0].requestId, a.requestId, 'ids durable');
      console.log('✔ Demo A Passed: agent pays, ALLOW executes, receipt independently verified.');
    }

    // Demo B: intent mismatch is detected and the divergent payment is
    // BLOCKED; chain untouched. The task/purpose names the contributor
    // while the built transaction targets the denied address.
    {
      const before = await rpc(stack.anvilRpc, 'eth_blockNumber', []);
      const agent = createAutonomousAgent({
        agentId: 'demo-b-agent', address: LOCAL_ADDRS.a0, chainId: 31337,
        planner: stubPlanner({
          reasoning: 'Scripted Demo B output: faulty agent build targeting the denied address.',
          actions: [{ note: 'contributor payment (divergent build)', to: LOCAL_ADDRS.stranger, value: VALUE_0005, data: '0x' }]
        }),
        integration: createAssertaraIntegration({ client, agentId: 'demo-b-agent' }),
        taskStore: store
      });
      const out = await agent.runTask(
        `Pay our contributor 0.005 ETH at ${LOCAL_ADDRS.a1} for the November milestone.`,
        { evidence: [{ evidenceId: 'demo-b-intent', type: 'intent', content: `User intent: pay contributor ${LOCAL_ADDRS.a1} 0.005 ETH for the November milestone.` }] }
      );
      assert.strictEqual(out.status, 'STOPPED');
      assert.ok(out.stoppedReason.startsWith('BLOCKED'), out.stoppedReason);
      assert.strictEqual(out.decision, 'BLOCK');
      assert.strictEqual(out.txHash, null, 'nothing signed');
      assert.strictEqual(out.execution, null, 'nothing executed');
      assert.ok(/^agent_/.test(out.actions[0].requestId), 'denial traceable by request id');
      assert.ok(out.actions[0].reasons.some((r) => r.startsWith('mandate:')), 'denial cites mandate reasons');
      assert.strictEqual(await rpc(stack.anvilRpc, 'eth_blockNumber', []), before, 'chain untouched');
      // Mismatch detection is deterministic: the evidence names the
      // contributor while the decoded transaction targets the stranger,
      // so the persisted comparison carries an agentCorroboration
      // MISMATCH field even though the mock model reports MATCH.
      const evalId = out.actions[0].findings.investigation.evalId;
      const invLine = fs.readFileSync(path.join(stack.tmp, 'investigations.jsonl'), 'utf8')
        .split('\n').find((l) => l.includes(evalId));
      assert.ok(invLine && invLine.includes('agentCorroboration') && invLine.includes('MISMATCH'), 'deterministic mismatch field persisted');
      const stored = store.getTask(out.taskId);
      assert.ok(stored && stored.status === 'STOPPED' && stored.decision === 'BLOCK', 'denial journaled');
      console.log('✔ Demo B Passed: intent mismatch detected, BLOCKED, nothing signed, chain untouched.');
    }
  } finally {
    global.fetch = realFetch;
    stack.kill();
  }
  console.log('\nAll agent demo tests passed.');
}

if (require.main === module) {
  runAgentDemoTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentDemoTests };
