/**
 * Agent task runner for the demo command stack (browser demo support).
 *
 * Creates the genuine autonomous agent runtime (same configuration as
 * demo/agentDriven.js) and injects it into the policy server's task
 * surface. One task runs at a time. Task state is in-memory only.
 * Nothing here changes agent, investigation, policy, or signer logic.
 */

const crypto = require('crypto');
const { createAutonomousAgent } = require('../agent/index');
const { LOCAL_ADDRS } = require('./scenarios');
const { setAgentTaskRunner } = require('../src/agentTasks');

function attachAgentTaskRunner({ policyBase, signerBase } = {}) {
  const appConfig = require('../src/config/env');
  const key = appConfig.modelApiKey || '';
  // Live planning needs a real key (mock stacks cannot plan). Leave the
  // task surface unattached so it answers an honest 503.
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) return false;

  const agent = createAutonomousAgent({
    agentId: 'demo-agent',
    address: LOCAL_ADDRS.a0,
    chainId: 31337,
    modelConfig: {
      baseUrl: appConfig.metaApiBaseUrl, apiKey: appConfig.modelApiKey,
      model: appConfig.museModel, timeoutMs: 120000
    },
    clientOpts: { policyBase, signerBase }
  });

  let activeTaskId = null;
  const failures = new Map();

  setAgentTaskRunner({
    submit(taskText) {
      if (activeTaskId) {
        const cur = agent.getTask(activeTaskId);
        if (cur && cur.status === 'RUNNING') {
          throw Object.assign(new Error('Another agent task is already running.'), { code: 'TASK_RUNNING' });
        }
      }
      const taskId = `task_${crypto.randomUUID()}`;
      activeTaskId = taskId;
      agent.runTask(taskText, { taskId }).then(
        () => { if (activeTaskId === taskId) activeTaskId = null; },
        (err) => {
          failures.set(taskId, String((err && err.message) || err).slice(0, 500));
          if (activeTaskId === taskId) activeTaskId = null;
        }
      );
      return { taskId };
    },
    get(taskId) {
      const t = agent.getTask(taskId);
      if (t) return t;
      if (failures.has(taskId)) {
        return {
          taskId, agent: 'demo-agent', task: null, status: 'FAILED',
          reasoning: null, plannerModel: null, planAttempts: null,
          actions: [], decision: null, txHash: null, execution: null,
          stoppedReason: failures.get(taskId), steps: []
        };
      }
      return null;
    }
  });
  return true;
}

module.exports = { attachAgentTaskRunner };
