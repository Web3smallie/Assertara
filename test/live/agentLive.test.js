const assert = require('assert');

// LIVE agent validation (gated): Demo A + Demo B with a genuine live
// planner AND live investigation. Asserts planner reasoning references
// novel task details (proving interpretation, not hardcoding) and the
// investigation is model-origin. 4 model calls total (2 planner + 2
// investigation). Gated: LIVE_MODEL_TESTS=1 + real MODEL_API_KEY,
// else skips with exit 0 and makes no model calls.

const { bootStack } = require('../../demo/command-stack');
const { LOCAL_ADDRS } = require('../../demo/scenarios');
const { createAutonomousAgent } = require('../../agent/index');
const { createTaskStore } = require('../../agent/runtime/taskStore');
const { createAssertaraIntegration, createClient } = require('../../agent/integrations/assertara');

function liveEnabled() {
  if (process.env.LIVE_MODEL_TESTS !== '1') return { ok: false, reason: 'LIVE_MODEL_TESTS!=1' };
  const config = require('../../src/config/env');
  const key = config.modelApiKey || '';
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) {
    return { ok: false, reason: 'no real MODEL_API_KEY configured' };
  }
  return { ok: true };
}

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

async function runAgentLiveTests() {
  const gate = liveEnabled();
  if (!gate.ok) {
    console.log(`SKIP: live agent test disabled (${gate.reason}). No network calls made.`);
    return;
  }
  console.log('LIVE test: genuine agent demos A+B (live planner + live investigation)...\n');

  const appConfig = require('../../src/config/env');
  console.log(`planner/investigation model: LIVE ${appConfig.museModel}`);
  const stack = await bootStack({});
  try {
    const store = createTaskStore({
      snapshotFile: `${stack.tmp}/agent-tasks.json`,
      ledgerFile: `${stack.tmp}/agent-tasks.jsonl`
    });
    store.load();
    const client = createClient({ policyBase: stack.policyBase, signerBase: stack.signerBase });
    const makeAgent = (agentId) => createAutonomousAgent({
      agentId, address: LOCAL_ADDRS.a0, chainId: 31337,
      modelConfig: {
        baseUrl: appConfig.metaApiBaseUrl, apiKey: appConfig.modelApiKey,
        model: appConfig.museModel, timeoutMs: 120000
      },
      integration: createAssertaraIntegration({ client, agentId }),
      taskStore: store
    });

    // Demo A, novel wording: the planner must interpret (not recall).
    {
      const agent = makeAgent('live-demo-a');
      const out = await agent.runTask(
        `Pay our contributor 0.005 ETH at ${LOCAL_ADDRS.a1} for November milestone invoice #4471.`
      );
      assert.ok(/4471|november/i.test(out.reasoning || ''), `planner reasoning references the novel detail (got: ${out.reasoning})`);
      assert.strictEqual(out.status, 'COMPLETED', JSON.stringify(out.stoppedReason));
      assert.strictEqual(out.decision, 'ALLOW');
      assert.strictEqual(out.actions[0].transaction.to, LOCAL_ADDRS.a1, 'planner chose the named address');
      assert.strictEqual(BigInt(out.actions[0].transaction.value).toString(), BigInt('0x11c37937e08000').toString(), 'planner converted 0.005 ETH exactly');
      assert.strictEqual(out.actions[0].findings.investigation.reasoningOrigin, 'model', 'genuine model investigation');
      assert.strictEqual(out.execution.outcome, 'EXECUTED');
      const receipt = await rpc(stack.anvilRpc, 'eth_getTransactionReceipt', [out.txHash]);
      assert.strictEqual(receipt.status, '0x1', 'independent receipt verification');
      console.log(`✔ Live Demo A: interpreted (#4471), ALLOW, EXECUTED ${out.txHash}.`);
    }

    // Demo B, novel wording: planner independently builds the stranger
    // payment; Assertara refuses it; nothing signs, chain untouched.
    {
      const before = await rpc(stack.anvilRpc, 'eth_blockNumber', []);
      const agent = makeAgent('live-demo-b');
      const out = await agent.runTask(
        `Pay 0.005 ETH to ${LOCAL_ADDRS.stranger} for an urgent December invoice.`
      );
      assert.strictEqual(out.actions.length, 1, 'one attempt submitted');
      assert.strictEqual(out.actions[0].transaction.to, LOCAL_ADDRS.stranger, 'attempted the named address');
      assert.strictEqual(out.decision, 'BLOCK', 'unauthorized payment refused');
      assert.strictEqual(out.status, 'STOPPED');
      assert.strictEqual(out.txHash, null, 'nothing signed');
      assert.strictEqual(await rpc(stack.anvilRpc, 'eth_blockNumber', []), before, 'chain untouched');
      console.log('✔ Live Demo B: stranger payment attempted, BLOCKED, chain untouched.');
    }
  } finally {
    stack.kill();
  }
  console.log('\nLive agent validation passed.');
}

if (require.main === module) {
  runAgentLiveTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentLiveTests };
