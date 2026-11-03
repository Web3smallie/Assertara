/**
 * Agent-driven demos: the autonomous agent performs Demo A (legitimate
 * payment, live planner) and Demo B (intent mismatch via scripted
 * divergent output) with a LIVE investigation in both.
 *
 * Standalone (default): boots a fresh isolated stack on ephemeral
 * ports, runs the demos, then tears the stack down.
 *
 * Reuse mode: connects the agent to an already-running stack so
 * terminal-launched investigations appear in that stack's frontend.
 * Nothing is booted in reuse mode; all endpoints must already be up.
 *
 * The harness reports outcomes; it asserts nothing about verdicts.
 * Expected decisions live ONLY in the test suites, never here.
 *
 * Usage: node demo/agentDriven.js [a|b|both]
 *        [--policy-base URL --signer-base URL --anvil-rpc URL]
 *        [--api-key KEY]
 *
 * Reuse endpoints may also come from the environment
 * (ASSERTARA_POLICY_BASE / ASSERTARA_SIGNER_BASE / ASSERTARA_ANVIL_RPC /
 * ASSERTARA_API_KEY); explicit flags win. Supplying --policy-base (or
 * the env equivalent) selects reuse mode; otherwise standalone mode
 * boots an isolated stack. Reuse mode never falls back to booting.
 */

const fs = require('fs');
const path = require('path');
const { bootStack } = require('./command-stack');
const { LOCAL_ADDRS } = require('./scenarios');
const { createAutonomousAgent } = require('../agent/index');
const { createTaskStore } = require('../agent/runtime/taskStore');
const { AssertaraClient } = require('assertara');

const EXPECTED_CHAIN_ID_HEX = '0x7a69'; // 31337 (local Anvil)

const USAGE = 'usage: node demo/agentDriven.js [a|b|both] [--policy-base URL --signer-base URL --anvil-rpc URL] [--api-key KEY]';

function flagValue(args, i) {
  const v = args[i + 1];
  if (!v || v.startsWith('--')) throw new Error(`${USAGE} (${args[i]} requires a value)`);
  return v;
}

function parseAgentDrivenArgs(argv) {
  let which = 'both';
  let whichSet = false;
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--policy-base' || a === '--signer-base' || a === '--anvil-rpc' || a === '--api-key') {
      flags[a] = flagValue(argv, i);
      i++;
    } else if (a.startsWith('--')) {
      throw new Error(`${USAGE} (unknown option ${a})`);
    } else if (!whichSet) {
      which = a.toLowerCase();
      whichSet = true;
    } else {
      throw new Error(USAGE);
    }
  }
  const runA = which === 'a' || which === 'both';
  const runB = which === 'b' || which === 'both';
  if (!runA && !runB) throw new Error(USAGE);
  const trim = (v) => (typeof v === 'string' ? v.trim().replace(/\/$/, '') : v);
  const policyBase = trim(flags['--policy-base'] || process.env.ASSERTARA_POLICY_BASE || null);
  let reuse = null;
  if (policyBase) {
    reuse = {
      policyBase,
      signerBase: trim(flags['--signer-base'] || process.env.ASSERTARA_SIGNER_BASE || null),
      anvilRpc: trim(flags['--anvil-rpc'] || process.env.ASSERTARA_ANVIL_RPC || null),
      apiKey: (flags['--api-key'] || process.env.ASSERTARA_API_KEY || null)
    };
    const missing = ['signerBase', 'anvilRpc'].filter((k) => !reuse[k]);
    if (missing.length > 0) {
      throw new Error(
        `reuse mode (--policy-base) also requires ${missing.map((k) => (k === 'signerBase' ? '--signer-base' : '--anvil-rpc')).join(' and ')}; ` +
        'refusing to start (no silent fallback to an isolated stack).'
      );
    }
  }
  return { which, runA, runB, reuse };
}

async function validateReuseTargets({ policyBase, signerBase, anvilRpc, apiKey }, { fetchImpl } = {}) {
  const client = new AssertaraClient({ policyBase, signerBase, apiKey, fetchImpl });
  let connected;
  try {
    connected = await client.connect();
  } catch (err) {
    throw new Error(`reuse target unreachable or unusable at ${policyBase}: ${err.message} (refusing to boot a fallback stack)`);
  }
  const doFetch = fetchImpl || fetch;
  let signerHealth;
  try {
    const res = await doFetch(`${signerBase}/health`);
    if (!res.ok) throw new Error(`http ${res.status}`);
    signerHealth = await res.json();
  } catch (err) {
    throw new Error(`reuse signer unhealthy at ${signerBase}: ${err.message} (refusing to boot a fallback stack)`);
  }
  if (!signerHealth || signerHealth.ok !== true) {
    throw new Error(`reuse signer unhealthy at ${signerBase}: ${JSON.stringify(signerHealth)} (refusing to boot a fallback stack)`);
  }
  if (String(signerHealth.address || '').toLowerCase() !== LOCAL_ADDRS.a0.toLowerCase()) {
    throw new Error(
      `reuse signer identity mismatch: ${signerHealth.address} is not the demo agent address ${LOCAL_ADDRS.a0} ` +
      '(refusing to run against an incompatible stack)'
    );
  }
  let chainId;
  try {
    const res = await doFetch(anvilRpc, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] })
    });
    if (!res.ok) throw new Error(`http ${res.status}`);
    const body = await res.json();
    if (body.error) throw new Error(body.error.message || 'rpc error');
    chainId = body.result;
  } catch (err) {
    throw new Error(`reuse chain unreachable at ${anvilRpc}: ${err.message} (refusing to boot a fallback stack)`);
  }
  if (String(chainId).toLowerCase() !== EXPECTED_CHAIN_ID_HEX) {
    throw new Error(
      `reuse chain mismatch at ${anvilRpc}: chainId ${chainId}, expected ${EXPECTED_CHAIN_ID_HEX} (refusing to run against an incompatible stack)`
    );
  }
  return {
    mandate: connected.mandate,
    signer: { address: signerHealth.address, mandateId: signerHealth.mandateId, mandateVersion: signerHealth.mandateVersion },
    chainId
  };
}

const DEMO_A_TASK = `Pay our contributor 0.005 ETH at ${LOCAL_ADDRS.a1} for the October milestone.`;
// Demo B: intent mismatch. The user intent (task text, also submitted
// as the investigation purpose) names the contributor, while the
// scripted agent output builds a transaction to the denied address.
// The evidence envelope restates the contributor intent so the
// deterministic corroboration check has a testable address.
const DEMO_B_TASK = `Pay our contributor 0.005 ETH at ${LOCAL_ADDRS.a1} for the November milestone.`;
const DEMO_B_VALUE = '0x11c37937e08000'; // 0.005 ETH
const DEMO_B_DIVERGENT_PLAN = {
  reasoning: 'Scripted Demo B output: faulty agent build targeting the denied address while the stated intent names the contributor.',
  actions: [{ note: 'contributor payment (divergent build)', to: LOCAL_ADDRS.stranger, value: DEMO_B_VALUE, data: '0x' }]
};
const DEMO_B_EVIDENCE = [{
  evidenceId: 'demo-b-intent',
  type: 'intent',
  content: `User intent: pay contributor ${LOCAL_ADDRS.a1} 0.005 ETH for the November milestone.`
}];

async function anvilBlockNumber(anvilRpc) {
  const res = await fetch(anvilRpc, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] })
  });
  if (!res.ok) throw new Error(`anvil http ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(body.error.message || 'anvil rpc error');
  return body.result;
}

function printOutcome(label, out) {
  console.log(`\n===== ${label} =====`);
  console.log(`taskId:   ${out.taskId}`);
  console.log(`status:   ${out.status}`);
  console.log(`reasoning (agent planner): ${out.reasoning || '(none)'}`);
  for (const a of out.actions) {
    console.log(`-- action ${a.index}: decision=${a.decision} requestId=${a.requestId} traceId=${a.traceId}`);
    for (const r of (a.reasons || []).slice(0, 4)) console.log(`   reason: ${r}`);
    if (a.txHash) console.log(`   txHash=${a.txHash} outcome=${a.execution ? a.execution.outcome : 'pending'}`);
    if (a.provenance && a.provenance.manifestDigest) console.log(`   manifest=${a.provenance.manifestDigest}`);
  }
  if (out.stoppedReason) console.log(`stopped:  ${out.stoppedReason}`);
}

async function main() {
  const { runA, runB, reuse } = parseAgentDrivenArgs(process.argv.slice(2));

  const appConfig = require('../src/config/env');
  const key = appConfig.modelApiKey || '';
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) {
    throw new Error('agentDriven demos need a real MODEL_API_KEY (live planner + live investigation).');
  }
  // Reuse mode: attach to the running stack after validating every
  // endpoint. Standalone mode: unchanged isolated-stack behavior.
  let stack;
  if (reuse) {
    const preflight = await validateReuseTargets(reuse);
    const dir = fs.mkdtempSync(path.join(__dirname, 'tmp', 'reuse-'));
    console.log(`reuse: policy=${reuse.policyBase} signer=${reuse.signerBase} anvil=${reuse.anvilRpc} (no services started)`);
    console.log(`reuse: mandate=${preflight.mandate.id || preflight.mandate.mandateId || 'configured'} signer=${preflight.signer.address} chain=${preflight.chainId}`);
    stack = {
      tmp: dir, policyBase: reuse.policyBase, signerBase: reuse.signerBase,
      anvilRpc: reuse.anvilRpc, reuse: true, kill: () => {}
    };
  } else {
    stack = await bootStack({});
    console.log(`stack: policy=${stack.policyBase} signer=${stack.signerBase}`);
  }
  try {
    if (runA) {
      console.log('\n--- Demo A: legitimate contributor payment ---');
      printOutcome('DEMO A', await runDemoATask({
        policyBase: stack.policyBase, signerBase: stack.signerBase,
        tmpDir: stack.tmp, apiKey: reuse ? reuse.apiKey : null,
        onEvent: (e) => console.log(`  [${e.event}] ${e.detail || ''}`)
      }));
    }
    if (runB) {
      console.log('\n--- Demo B: intent mismatch (divergent agent output) ---');
      const store = createTaskStore({
        snapshotFile: `${stack.tmp}/agent-tasks.json`,
        ledgerFile: `${stack.tmp}/agent-tasks.jsonl`
      });
      store.load();
      // Scripted divergent output: the live planner is bypassed for Demo B
      // so the mismatch inputs are deterministic, while the investigation
      // stays fully live. The task text (user intent, also submitted as
      // the purpose) names the contributor; the built transaction targets
      // the denied address. Nothing here asserts a verdict — the test
      // suites own all expectations.
      const agent = createAutonomousAgent({
        agentId: 'demo-agent',
        address: LOCAL_ADDRS.a0,
        chainId: 31337,
        planner: async () => ({ plan: DEMO_B_DIVERGENT_PLAN, model: 'scripted-divergent-demo-b' }),
        clientOpts: { policyBase: stack.policyBase, signerBase: stack.signerBase, apiKey: reuse ? reuse.apiKey : null },
        taskStore: store,
        onEvent: (e) => console.log(`  [${e.event}] ${e.detail || ''}`)
      });
      const blockBefore = await anvilBlockNumber(stack.anvilRpc);
      const outcome = await agent.runTask(DEMO_B_TASK, { evidence: DEMO_B_EVIDENCE });
      const blockAfter = await anvilBlockNumber(stack.anvilRpc);
      printOutcome('DEMO B', outcome);
      const first = (outcome.actions && outcome.actions[0]) || {};
      const inv = (first.findings && first.findings.investigation) || {};
      const bundle = {
        demo: 'B', task: DEMO_B_TASK,
        status: outcome.status, stoppedReason: outcome.stoppedReason,
        decision: outcome.decision, txHash: outcome.txHash, execution: outcome.execution,
        blockBefore, blockAfter, chainUntouched: blockBefore === blockAfter,
        requestId: first.requestId || null, traceId: first.traceId || null,
        evalId: inv.evalId || null, verdict: inv.verdict || null,
        reasoningOrigin: inv.reasoningOrigin || null,
        reasons: first.reasons || [],
        mandateChecks: (first.findings && first.findings.mandateChecks) || null
      };
      fs.writeFileSync(`${stack.tmp}/demoB-outcome.json`, JSON.stringify(bundle, null, 2), 'utf8');
      console.log(`demoB: outcome bundle -> ${stack.tmp}/demoB-outcome.json`);
    }
  } finally {
    stack.kill();
  }
}

// Demo A as a callable stage (used by the CLI above and by
// demo/demoA.js). Same agent, task, and flow — returns the outcome
// instead of printing it.
async function runDemoATask({ policyBase, signerBase, tmpDir, apiKey, agentId, onEvent } = {}) {
  const appConfig = require('../src/config/env');
  const key = appConfig.modelApiKey || '';
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) {
    throw new Error('agentDriven demos need a real MODEL_API_KEY (live planner + live investigation).');
  }
  const dir = tmpDir || fs.mkdtempSync(path.join(__dirname, 'tmp', 'demoA-'));
  const store = createTaskStore({
    snapshotFile: `${dir}/agent-tasks.json`,
    ledgerFile: `${dir}/agent-tasks.jsonl`
  });
  store.load();
  const agent = createAutonomousAgent({
    agentId: agentId || 'demo-agent',
    address: LOCAL_ADDRS.a0,
    chainId: 31337,
    modelConfig: {
      baseUrl: appConfig.metaApiBaseUrl, apiKey: appConfig.modelApiKey,
      model: appConfig.museModel, timeoutMs: 120000
    },
    clientOpts: { policyBase, signerBase, apiKey: apiKey || null },
    taskStore: store,
    onEvent: onEvent || (() => {})
  });
  return agent.runTask(DEMO_A_TASK);
}

if (require.main === module) {
  main().catch((err) => { console.error(`agentDriven FAILED: ${err.stack || err.message}`); process.exit(1); });
}

module.exports = { DEMO_A_TASK, DEMO_B_TASK, DEMO_B_DIVERGENT_PLAN, DEMO_B_EVIDENCE, parseAgentDrivenArgs, validateReuseTargets, runDemoATask, printOutcome };
