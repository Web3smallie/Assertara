/**
 * Assertara Agent Orchestrator — bounded investigation loop.
 * The model proposes actions; the application validates, executes, budgets,
 * deduplicates, and terminates. Model client is injected (real SparkAdapter
 * in production, scripted stubs in tests). No network here.
 */

const { EvidenceGraph, sha256Hex } = require('./evidenceGraph');
const { TOOLS, runTool } = require('./toolRegistry');

const TERMINAL = ['COMPLETE', 'INCOMPLETE'];
const DEFAULT_BUDGET = {
  maxTurns: 8,
  maxToolCalls: 24,
  toolTimeoutMs: 30000,
  maxUsd: 2.0,
  maxIdleTurns: 2
};

function stableArgsKey(name, args) {
  return `${name}:${sha256Hex(JSON.stringify(args || {}))}`;
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  // Race (not allSettled): settle on first outcome, then release the timer.
  // The timer must stay referenced so the event loop survives until settle.
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

class Orchestrator {
  constructor({ modelClient, budget } = {}) {
    if (!modelClient || typeof modelClient.nextTurn !== 'function') {
      throw new Error('orchestrator requires a modelClient with nextTurn()');
    }
    this.modelClient = modelClient;
    this.budget = { ...DEFAULT_BUDGET, ...(budget || {}) };
  }

  createInvestigation(featureId, inputs) {
    return {
      id: `inv_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`,
      featureId,
      inputs: inputs || {},
      status: 'RUNNING',
      turns: [],
      ledger: { modelCalls: 0, toolCalls: 0, failures: 0, retries: 0, inputTokens: 0, outputTokens: 0, cachedTokens: 0, estimatedCostUsd: 0, deduped: 0 },
      stopReason: null,
      graph: new EvidenceGraph('pending')
    };
  }

  validateAction(action, executedKeys) {
    if (!action || typeof action !== 'object') return { ok: false, error: 'action must be an object' };
    const spec = TOOLS[action.tool];
    if (!spec) return { ok: false, error: `unknown tool: ${action.tool}` };
    if (spec.status === 'UNAVAILABLE') {
      return { ok: false, error: `tool ${action.tool} is UNAVAILABLE: ${(spec.requirements || []).join(' ')}`, unavailable: true };
    }
    if (!action.args || typeof action.args !== 'object' || Array.isArray(action.args)) {
      return { ok: false, error: `tool ${action.tool}: args must be an object` };
    }
    for (const field of spec.required || []) {
      if (action.args[field] === undefined || action.args[field] === null || action.args[field] === '') {
        return { ok: false, error: `tool ${action.tool}: missing required argument "${field}"` };
      }
    }
    // Run the tool's own format validation pre-execution so malformed args
    // are rejected as invalid (never executed, never counted as failures).
    // runTool re-validates defensively at execution time.
    if (typeof spec.validate === 'function') {
      try {
        spec.validate(action.args);
      } catch (err) {
        return { ok: false, error: err.message || `tool ${action.tool}: invalid arguments` };
      }
    }
    const key = stableArgsKey(action.tool, action.args);
    if (executedKeys.has(key)) return { ok: false, error: `duplicate tool call suppressed: ${action.tool}`, duplicate: true, key };
    return { ok: true, key };
  }

  async executeAction(record, action, key) {
    const started = Date.now();
    try {
      const result = await withTimeout(runTool(action.tool, action.args), this.budget.toolTimeoutMs, action.tool);
      record.ledger.toolCalls += 1;
      return { ok: true, result, latencyMs: Date.now() - started };
    } catch (err) {
      record.ledger.toolCalls += 1;
      record.ledger.failures += 1;
      return { ok: false, error: err.message || String(err), latencyMs: Date.now() - started };
    }
  }

  ledgerAddUsage(record, usage, estimatedCostUsd) {
    if (!usage) return;
    record.ledger.modelCalls += 1;
    if (Number.isFinite(usage.input_tokens)) record.ledger.inputTokens += usage.input_tokens;
    if (Number.isFinite(usage.output_tokens)) record.ledger.outputTokens += usage.output_tokens;
    const cached = usage.input_tokens_details && usage.input_tokens_details.cached_tokens;
    if (Number.isFinite(cached)) record.ledger.cachedTokens += cached;
    if (Number.isFinite(estimatedCostUsd)) {
      record.ledger.estimatedCostUsd += estimatedCostUsd;
    }
  }

  budgetExceeded(record) {
    if (record.turns.length >= this.budget.maxTurns) return 'max turns reached';
    if (record.ledger.toolCalls >= this.budget.maxToolCalls) return 'max tool calls reached';
    if (this.budget.maxUsd !== null && record.ledger.estimatedCostUsd > this.budget.maxUsd) {
      return 'spending cap reached';
    }
    return null;
  }

  async run(featureId, inputs, { system, effortFor } = {}) {
    const record = this.createInvestigation(featureId, inputs);
    record.graph.investigationId = record.id;
    // Seed the graph with the raw inputs so replay never depends on memory.
    record.graph.append({ kind: 'InvestigationInputs', producer: 'USER', payload: inputs || {}, created_turn: 0 });
    const executedKeys = new Set();
    let idleTurns = 0;
    let responseId = null;

    while (!TERMINAL.includes(record.status)) {
      const overrun = this.budgetExceeded(record);
      if (overrun) {
        record.status = 'INCOMPLETE';
        record.stopReason = `Budget exhausted: ${overrun}. Partial results preserved; unknowns remain.`;
        break;
      }
      const turnIndex = record.turns.length + 1;
      const effort = typeof effortFor === 'function' ? effortFor(turnIndex, record) : 'low';
      let turn;
      try {
        turn = await this.modelClient.nextTurn({
          system: system || `Assertara investigator for ${featureId}. Propose validated tool actions or stop. Never invent evidence IDs.`,
          effort,
          responseId,
          graph: record.graph.export(),
          ledger: { ...record.ledger }
        });
      } catch (err) {
        record.ledger.failures += 1;
        record.status = 'INCOMPLETE';
        record.stopReason = `Model call failed: ${err.message}. Partial results preserved.`;
        break;
      }
      this.ledgerAddUsage(record, turn.usage, turn.estimatedCostUsd);
      if (turn.responseId) responseId = turn.responseId;

      const turnRecord = { index: turnIndex, effort, actions: [], notes: turn.notes || null, stop: Boolean(turn.stop) };
      const validActions = [];
      for (const action of turn.actions || []) {
        const check = this.validateAction(action, executedKeys);
        if (!check.ok) {
          if (check.duplicate) record.ledger.deduped += 1;
          turnRecord.actions.push({ tool: action && action.tool, ok: false, error: check.error });
          continue;
        }
        executedKeys.add(check.key);
        validActions.push({ action, key: check.key });
      }
      // Independent tool calls run in parallel; each is already validated.
      const results = await Promise.all(validActions.map(({ action }) => this.executeAction(record, action)));
      validActions.forEach(({ action }, i) => {
        const outcome = results[i];
        turnRecord.actions.push({ tool: action.tool, ok: outcome.ok, ...(outcome.ok ? {} : { error: outcome.error }) });
        const node = record.graph.append({
          kind: 'ToolResult',
          producer: 'TOOL',
          tool_ref: action.tool,
          input_hashes: [sha256Hex(JSON.stringify(action.args || {}))],
          payload: outcome.ok ? { result: outcome.result } : { error: outcome.error },
          created_turn: turnIndex
        });
        if (!outcome.ok) {
          record.graph.append({
            kind: 'ToolFailure', producer: 'TOOL', tool_ref: action.tool,
            payload: { error: outcome.error }, created_turn: turnIndex
          });
        }
        void node;
      });
      record.turns.push(turnRecord);

      if (turn.stop) {
        record.status = 'COMPLETE';
        record.stopReason = turn.stopReason || 'Model requested stop.';
        break;
      }
      if (validActions.length === 0) {
        idleTurns += 1;
        if (idleTurns >= this.budget.maxIdleTurns) {
          record.status = 'INCOMPLETE';
          record.stopReason = 'No new validated actions for consecutive turns; stopping without forcing a verdict.';
          break;
        }
      } else {
        idleTurns = 0;
      }
    }
    return record;
  }
}

module.exports = { Orchestrator, DEFAULT_BUDGET, TERMINAL };
