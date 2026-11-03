/**
 * Autonomous agent runtime: task lifecycle and execution orchestration.
 *
 * Receives tasks, plans with a (live or injected) planner, builds the
 * actual transactions, and runs each through the Assertara integration
 * (SDK). The runtime makes task decisions; it never authorizes: every
 * submission can be refused, and refusals end the task without retry,
 * reroute, or resubmission.
 */

const crypto = require('crypto');
const { planWithRetry, livePlanner } = require('../planner/planner');
const { nextAction } = require('../reasoning/actionSelector');
const { buildTransaction } = require('../transaction-builder/builder');
const { createReporter } = require('../reporting/reporter');
const { createAssertaraIntegration, createClient } = require('../integrations/assertara');

function createAutonomousAgent(opts = {}) {
  const agent = (opts.agentId || 'autonomous-agent').slice(0, 128);
  const address = opts.address;
  const chainId = opts.chainId;
  if (!address) throw new Error('createAutonomousAgent requires the agent sending address.');
  if (chainId === undefined || chainId === null) throw new Error('createAutonomousAgent requires a chain id.');
  const registry = new Map();
  const store = opts.taskStore || null;
  const operatorTimeoutMs = opts.operatorTimeoutMs;

  let plannerFn = opts.planner || null;
  if (!plannerFn && opts.modelConfig) {
    const mc = opts.modelConfig;
    plannerFn = ({ task }) => livePlanner({
      fetchImpl: mc.fetchImpl, baseUrl: mc.baseUrl, apiKey: mc.apiKey, model: mc.model,
      task, agentAddress: address, chainId: String(chainId), timeoutMs: mc.timeoutMs
    });
  }
  if (typeof plannerFn !== 'function') {
    throw new Error('createAutonomousAgent requires a planner function or modelConfig.');
  }

  let integration = opts.integration || null;
  if (!integration && opts.clientOpts) {
    integration = createAssertaraIntegration({ client: createClient(opts.clientOpts), agentId: agent });
  }
  if (!integration || typeof integration.executeAction !== 'function') {
    throw new Error('createAutonomousAgent requires an Assertara integration or clientOpts.');
  }

  function persist(taskId, patch) {
    registry.set(taskId, { ...(registry.get(taskId) || {}), ...patch });
    if (store && typeof store.updateTask === 'function') store.updateTask(taskId, patch);
  }

  async function runTask(taskText, runOpts = {}) {
    if (typeof taskText !== 'string' || taskText.trim().length === 0) {
      throw new Error('runTask requires a non-empty task description.');
    }
    const taskId = runOpts.taskId || `task_${crypto.randomUUID()}`;
    const reporter = createReporter({ taskId, onEvent: opts.onEvent });
    const taskStartedAt = Date.now();
    const outcome = {
      taskId, agent, task: taskText, status: 'RUNNING',
      reasoning: null, plannerModel: null, planAttempts: null,
      actions: [], decision: null, txHash: null, execution: null,
      stoppedReason: null, steps: reporter.steps,
      timings: { planMs: null, totalMs: null }
    };
    const stampTotal = () => {
      outcome.timings.totalMs = Date.now() - taskStartedAt;
      return outcome.timings;
    };
    registry.set(taskId, outcome);
    if (store && typeof store.createTask === 'function') {
      store.createTask({ taskId, agent, task: taskText, createdAt: Date.now(), status: 'RUNNING' });
    }
    reporter.log('TASK_RECEIVED', taskText.slice(0, 200));

    let plan;
    try {
      reporter.log('PLANNING', 'interpreting task with planner model');
      const planStartedAt = Date.now();
      const planned = await planWithRetry(taskText, plannerFn);
      plan = planned.plan;
      outcome.reasoning = plan.reasoning;
      outcome.plannerModel = planned.model;
      outcome.planAttempts = planned.attempts;
      outcome.timings.planMs = Date.now() - planStartedAt;
      persist(taskId, { reasoning: plan.reasoning, plannerModel: planned.model, status: 'PLANNED', timings: { ...outcome.timings } });
      reporter.log('PLANNED', `model=${planned.model} attempts=${planned.attempts} actions=${plan.actions.length}`);
    } catch (err) {
      outcome.status = 'STOPPED';
      outcome.stoppedReason = `PLAN_FAILED: ${err.message}`;
      persist(taskId, { status: outcome.status, stoppedReason: outcome.stoppedReason, timings: stampTotal() });
      reporter.log('STOPPED', outcome.stoppedReason);
      return outcome;
    }

    const state = { executed: 0, lastDecision: null };
    for (;;) {
      const next = nextAction(plan, state);
      if (next.kind === 'done') {
        outcome.status = 'COMPLETED';
        persist(taskId, { status: outcome.status, timings: stampTotal() });
        reporter.log('TASK_COMPLETED', `all ${outcome.actions.length} action(s) executed and verified`);
        return outcome;
      }
      if (next.kind === 'stop') {
        outcome.status = 'STOPPED';
        outcome.stoppedReason = next.stoppedReason;
        persist(taskId, { status: outcome.status, stoppedReason: outcome.stoppedReason, timings: stampTotal() });
        reporter.log('STOPPED', outcome.stoppedReason);
        return outcome;
      }
      let built;
      try {
        built = buildTransaction(next.action, { from: address, chainId });
      } catch (err) {
        outcome.status = 'STOPPED';
        outcome.stoppedReason = `BUILD_FAILED: ${err.message}`;
        persist(taskId, { status: outcome.status, stoppedReason: outcome.stoppedReason, timings: stampTotal() });
        reporter.log('STOPPED', outcome.stoppedReason);
        return outcome;
      }
      reporter.log('ACTION_CONSTRUCTED', `action ${next.index + 1}/${plan.actions.length} to=${built.transaction.to} value=${built.transaction.value} digest=${built.digestPreview || 'n/a'}`,
        { actionIndex: next.index });
      let result;
      try {
        result = await integration.executeAction(built.transaction, {
          purpose: taskText,
          idempotencyKey: runOpts.idempotencyKey,
          evidence: runOpts.evidence,
          operatorTimeoutMs,
          // No onProgress logging here: the integration already emits
          // each progress event through onEvent below (with requestId,
          // traceId, and actionIndex); logging again would duplicate it.
          onEvent: (event, detail, extra) => reporter.log(event, detail, { ...(extra || {}), actionIndex: next.index })
        });
      } catch (err) {
        outcome.status = 'STOPPED';
        // Operator-release timeouts keep HELD semantics (the decision was
        // REVIEW, not a failure); everything else is a loud error stop.
        // Matched on the stable error code string so this module never
        // imports the SDK (boundary: integrations/ only).
        outcome.stoppedReason = err && err.code === 'TIMEOUT' && /operator release/i.test(err.message || '')
          ? 'HELD: operator release not observed before timeout'
          : `EXECUTION_ERROR: ${err.message}`;
        persist(taskId, { status: outcome.status, stoppedReason: outcome.stoppedReason, timings: stampTotal() });
        reporter.log('STOPPED', outcome.stoppedReason);
        return outcome;
      }
      const actionOutcome = {
        index: next.index, note: next.action.note || '',
        transaction: built.transaction, digestPreview: built.digestPreview,
        requestId: result.requestId, traceId: result.traceId, txDigest: result.txDigest || null,
        decision: result.decision, reasons: result.reasons || [],
        released: Boolean(result.released), txHash: result.txHash || null,
        receipt: result.receipt || null, execution: result.execution || null,
        findings: result.findings || null, timings: result.timings || null,
        provenance: result.provenance || null
      };
      outcome.actions.push(actionOutcome);
      outcome.decision = result.decision;
      outcome.txHash = result.txHash || outcome.txHash;
      outcome.execution = result.execution || outcome.execution;
      persist(taskId, { actions: outcome.actions, decision: outcome.decision });
      state.lastDecision = result.decision;
      if (result.decision === 'ALLOW' || (result.decision === 'REVIEW' && result.released)) {
        if (!result.execution) {
          outcome.status = 'STOPPED';
          outcome.stoppedReason = 'EXECUTION_UNVERIFIED: no execution record returned; task ends';
          persist(taskId, { status: outcome.status, stoppedReason: outcome.stoppedReason, timings: stampTotal() });
          reporter.log('STOPPED', outcome.stoppedReason);
          return outcome;
        }
        if (typeof integration.isCleanExecution === 'function' && !integration.isCleanExecution(result.execution)) {
          outcome.status = 'STOPPED';
          outcome.stoppedReason = `EXECUTION_NOT_CLEAN: outcome=${result.execution.outcome}; task ends without further actions`;
          persist(taskId, { status: outcome.status, stoppedReason: outcome.stoppedReason, timings: stampTotal() });
          reporter.log('STOPPED', outcome.stoppedReason);
          return outcome;
        }
        state.executed += 1;
      }
      // BLOCK/UNCERTAIN (and anything else): loop back; the selector stops the task.
    }
  }

  function getTask(taskId) {
    if (store && typeof store.getTask === 'function') {
      const stored = store.getTask(taskId);
      if (stored) return stored;
    }
    return registry.get(taskId) || null;
  }

  function listTasks() {
    if (store && typeof store.listTasks === 'function') return store.listTasks();
    return [...registry.values()];
  }

  return { runTask, getTask, listTasks };
}

module.exports = { createAutonomousAgent };
