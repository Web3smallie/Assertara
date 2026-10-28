/**
 * Assertara Live Model Driver — SparkAdapter-backed `nextTurn()` for the
 * F1/F2 investigation loops (no parallel orchestration: the orchestrator
 * still validates, executes, budgets, and terminates).
 *
 * Turn contract (strict-schema): the model returns
 *   { actions: [{ tool, argsJson }], stop, stopReason, notes }
 * `argsJson` is a JSON-encoded args object, not an inline object, because
 * strict json_schema forbids additionalProperties:true — per-tool args
 * shapes cannot be expressed inline. The driver JSON-parses argsJson and the
 * orchestrator re-validates everything (allowlists, required fields, tool
 * validators, dedup) before any execution or evidence mutation.
 *
 * Error semantics (both honest, both recorded on the investigation record):
 * - Transport/unavailable (no key, 429/5xx-after-retry, timeout): THROW a
 *   coded ModelDriverError → the orchestrator marks the run INCOMPLETE with
 *   the message. The investigation could not proceed.
 * - Unusable model output (malformed turn, no valid actions): return a STOP
 *   turn with a `model-error:` stopReason → the run COMPLETES with the
 *   reason. The model participated but produced nothing actionable.
 * Neither path fabricates tool results, and neither assigns verdicts —
 * adjudication stays application-owned downstream.
 *
 * Bounded correction: exactly ONE follow-up request is allowed per turn, and
 * only for correctable formatting failures (unparseable model JSON, wrong
 * turn shape, format-class args defects). Refusals, truncation, transport,
 * auth, and provider errors never trigger it. The correction carries only
 * the failure category + schema constraints (never raw output), is validated
 * from scratch by the same pipeline, and is marked corrected on acceptance.
 * Usage/cost merge across both attempts when both report; otherwise unknown.
 */

const { SparkAdapter, SparkApiError } = require('./sparkAdapter');
const { TOOLS } = require('./toolRegistry');
const { redactSensitive } = require('./replay');

const TURN_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['actions', 'stop', 'stopReason', 'notes'],
  properties: {
    actions: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['tool', 'argsJson'],
        properties: { tool: { type: 'string' }, argsJson: { type: 'string' } }
      }
    },
    stop: { type: 'boolean' },
    stopReason: { type: 'string' },
    notes: { type: 'string' }
  }
};

const MAX_ACTIONS_PER_TURN = 4;
const MAX_SUMMARY_CHARS = 6000;
const MAX_ARG_BYTES = 16 * 1024;

function driverError(code, message) {
  const err = new Error(message);
  err.code = code;
  err.name = 'ModelDriverError';
  return err;
}

function truncate(s, n) {
  const str = String(s === null || s === undefined ? '' : s);
  return str.length > n ? `${str.slice(0, n)}…` : str;
}

function availableTools() {
  return Object.values(TOOLS)
    .filter((t) => t.status !== 'UNAVAILABLE')
    .map((t) => ({ name: t.name, description: t.description, required: t.required || [] }));
}

// Bounded, redacted evidence summary. The graph export may embed raw caller
// inputs (InvestigationInputs node) — secrets are scrubbed before the model
// ever sees them, and the scrub count is reported, not hidden. Scrubbing is
// two-layer: structured redaction on each payload BEFORE stringifying (so
// key-named secrets never reach text), plus an inline sweep for credential
// shapes embedded in free text (transcripts, pasted keys).
function scrubInline(text) {
  let count = 0;
  const scrubbed = String(text).replace(/sk-[A-Za-z0-9\-]{8,}|Bearer\s+[A-Za-z0-9\-._~+/=]{8,}/g, () => {
    count += 1;
    return '[REDACTED]';
  });
  return { text: scrubbed, count };
}

function summarizeGraph(graphExport, { maxChars = MAX_SUMMARY_CHARS } = {}) {
  const nodes = (graphExport && Array.isArray(graphExport.nodes) ? graphExport.nodes : []).slice(0, 100);
  let redactedCount = 0;
  const lines = nodes.map((n) => {
    let preview = '';
    try {
      const { value: safe, redacted } = redactSensitive(n.payload === undefined ? null : n.payload);
      redactedCount += redacted.length;
      preview = truncate(JSON.stringify(safe), 300);
    } catch {
      preview = '(unserializable payload)';
    }
    return `- ${n.id} [${n.kind}/${n.producer}${n.tool_ref ? `:${n.tool_ref}` : ''} turn:${n.created_turn}]: ${preview}`;
  });
  const inline = scrubInline(lines.join('\n').slice(0, maxChars));
  return { text: inline.text, redactedCount: redactedCount + inline.count };
}

function goalFromGraph(graphExport) {
  const nodes = (graphExport && Array.isArray(graphExport.nodes) ? graphExport.nodes : []);
  const seed = nodes.find((n) => n.kind === 'InvestigationInputs');
  const payload = (seed && seed.payload && typeof seed.payload === 'object') ? seed.payload : {};
  return { goal: typeof payload.goal === 'string' ? payload.goal : '(no stated goal)', inputs: payload };
}

function buildSystemPrompt(baseSystem, tools, extra = '') {
  const catalog = tools.map((t) => `- ${t.name}${t.required.length > 0 ? ` (required args: ${t.required.join(', ')})` : ''}: ${truncate(t.description, 160)}`).join('\n');
  return [
    baseSystem || 'Assertara investigator. Propose validated tool actions or stop. Never invent evidence IDs.',
    '',
    'RULES:',
    '1. Investigate ONLY through the tools below. Every claim you will make must trace to tool-returned evidence IDs (E-001, ...).',
    '2. argsJson must be a JSON object string with exactly the arguments the tool needs. Never invent tool results, IDs, or addresses.',
    '3. Keep each turn focused: at most 4 independent actions. Prefer decoding and reading chain state before interpreting.',
    '4. Set stop=true with a stopReason when the goal is answered, when no tool can supply the missing evidence, or when further calls would repeat work.',
    '5. notes is a short private memo (what you learned this turn / what remains). stopReason explains why a stop is final.',
    extra,
    '',
    'AVAILABLE TOOLS:',
    catalog
  ].filter((l) => l !== '').join('\n');
}

function parseTurnContent(content) {
  if (!content || typeof content !== 'object' || Array.isArray(content)) {
    return { ok: false, error: 'turn content must be an object' };
  }
  if (!Array.isArray(content.actions)) return { ok: false, error: 'turn.actions must be an array' };
  if (typeof content.stop !== 'boolean') return { ok: false, error: 'turn.stop must be a boolean' };
  if (typeof content.stopReason !== 'string' || typeof content.notes !== 'string') {
    return { ok: false, error: 'turn.stopReason and turn.notes must be strings' };
  }
  return { ok: true, value: content };
}

// Merge two attempts' usage honestly: a field is reported only when BOTH
// attempts reported it; otherwise it is omitted (unknown), never zero-filled.
// Cost sums only when both attempts priced; otherwise null (unknown).
function mergeAttemptUsage(first, second) {
  const u1 = (first && first.usage) || {};
  const u2 = (second && second.usage) || {};
  const usage = {};
  for (const k of ['input_tokens', 'output_tokens']) {
    if (Number.isFinite(u1[k]) && Number.isFinite(u2[k])) usage[k] = u1[k] + u2[k];
  }
  const c1 = (u1.input_tokens_details && u1.input_tokens_details.cached_tokens);
  const c2 = (u2.input_tokens_details && u2.input_tokens_details.cached_tokens);
  if (Number.isFinite(c1) && Number.isFinite(c2)) {
    usage.input_tokens_details = { cached_tokens: c1 + c2 };
  }
  const cost1 = first ? first.estimatedCostUsd : null;
  const cost2 = second ? second.estimatedCostUsd : null;
  return {
    usage: Object.keys(usage).length > 0 ? usage : null,
    estimatedCostUsd: (Number.isFinite(cost1) && Number.isFinite(cost2)) ? cost1 + cost2 : null,
    unknown: !(Number.isFinite(cost1) && Number.isFinite(cost2))
  };
}

// Correction prompt: fixed template + failure category + schema constraints.
// Never echoes raw model output (it may quote prompt content) and carries no
// caller data, so there is nothing secret to leak.
function correctionInput(category) {
  return [
    'CORRECTION REQUIRED — your previous turn output failed validation and was discarded. No action was executed and no evidence changed.',
    `Failure category: ${truncate(category, 300)}`,
    'Return ONLY a single JSON object for the investigation turn, exactly matching this schema (no prose before or after it):',
    '{"actions":[{"tool":"<one of the available tools>","argsJson":"<a JSON object string with that tool\'s arguments>"}],"stop":<boolean>,"stopReason":"<string>","notes":"<string>"}',
    'Rules: every key above is required; actions may be [] only with "stop":true; argsJson must parse as a JSON object (never a string or array) and stay under 16KB; use only tools from the available list.'
  ].join('\n');
}

function isCorrectableThrow(err) {
  return err instanceof SparkApiError && err.type === 'invalid_response';
}

function adapterConfigured(a) {
  if (!a || typeof a.complete !== 'function') return false;
  if (typeof a.isConfigured === 'function') return a.isConfigured() === true;
  if (typeof a.configured === 'boolean') return a.configured;
  return true; // complete()-only doubles carry no signal; explicit injection is explicit trust
}

function defaultAdapter() {
  const { modelApiKey } = require('../config/env');
  return new SparkAdapter({ apiKey: modelApiKey || '' });
}

function createModelDriver({
  adapter = null,
  allowTools = null,
  maxActionsPerTurn = MAX_ACTIONS_PER_TURN,
  maxSummaryChars = MAX_SUMMARY_CHARS,
  systemExtra = ''
} = {}) {
  const live = adapter || defaultAdapter();
  const catalog = availableTools();
  const allowed = new Set(
    Array.isArray(allowTools) && allowTools.length > 0 ? allowTools : catalog.map((t) => t.name)
  );
  const tools = catalog.filter((t) => allowed.has(t.name));

  async function nextTurn({ system, effort, responseId, graph, ledger } = {}) {
    if (!adapterConfigured(live)) {
      throw driverError('MODEL_UNAVAILABLE', 'model-unavailable: no API key configured; no model call attempted');
    }
    const { goal, inputs } = goalFromGraph(graph);
    const evidence = summarizeGraph(graph, { maxChars: maxSummaryChars });
    const { value: safeInputs, redacted: inputRedactions } = redactSensitive(
      (() => { try { return JSON.parse(JSON.stringify(inputs || {})); } catch { return {}; } })()
    );
    const inlineInputs = scrubInline(truncate(JSON.stringify(safeInputs), 1500));
    const input = [
      `GOAL: ${truncate(scrubInline(goal).text, 500)}`,
      `EFFORT: ${effort || 'low'}`,
      `LEDGER: toolCalls=${(ledger && ledger.toolCalls) || 0} failures=${(ledger && ledger.failures) || 0}`,
      `CALLER INPUTS (redacted, ${inputRedactions.length + inlineInputs.count} fields scrubbed): ${inlineInputs.text}`,
      `EVIDENCE SO FAR (${evidence.redactedCount} fields scrubbed):`,
      evidence.text || '(no evidence yet — start by gathering it with tools)'
    ].join('\n');
    const fullSystem = buildSystemPrompt(system, tools, systemExtra);
    const callArgs = {
      system: fullSystem,
      schema: TURN_SCHEMA,
      schemaName: 'investigation_turn',
      effort: effort === 'high' ? 'high' : 'low'
    };
    // Shared action validation (initial + corrected responses alike): every
    // drop is labeled format-class or not. Only format-class drops
    // (malformed entries, unparseable/non-object/oversized argsJson) may
    // trigger a correction; unknown-tool drops never do.
    function validateActions(list) {
      const actions = [];
      const dropped = [];
      for (const a of (list || []).slice(0, maxActionsPerTurn)) {
        if (!a || typeof a.tool !== 'string' || typeof a.argsJson !== 'string') {
          dropped.push({ reason: 'malformed action entry (needs tool + argsJson strings)', format: true });
          continue;
        }
        if (!allowed.has(a.tool)) {
          dropped.push({ reason: `unknown or disallowed tool: ${truncate(a.tool, 60)}`, format: false });
          continue;
        }
        if (Buffer.byteLength(a.argsJson, 'utf8') > MAX_ARG_BYTES) {
          dropped.push({ reason: `tool ${a.tool}: args exceed ${MAX_ARG_BYTES} bytes`, format: true });
          continue;
        }
        let args;
        try {
          args = JSON.parse(a.argsJson);
        } catch {
          dropped.push({ reason: `tool ${a.tool}: argsJson is not valid JSON`, format: true });
          continue;
        }
        if (!args || typeof args !== 'object' || Array.isArray(args)) {
          dropped.push({ reason: `tool ${a.tool}: args must decode to an object`, format: true });
          continue;
        }
        actions.push({ tool: a.tool, args });
      }
      if ((list || []).length > maxActionsPerTurn) {
        dropped.push({ reason: `${list.length - maxActionsPerTurn} excess action(s) over the per-turn cap of ${maxActionsPerTurn}`, format: false });
      }
      return { actions, dropped };
    }
    function dropNotes(contentNotes, dropped) {
      return [contentNotes, ...dropped.map((d) => `[driver dropped] ${d.reason}`)]
        .filter((s) => s && s.length > 0).join('\n').slice(0, 2000);
    }
    // ONE correction attempt, linear (never recursive, never looped). Runs at
    // most once per nextTurn call: the corrected response is validated from
    // scratch by the same pipeline, and any failure after it stops safely.
    async function runCorrection(category, firstAttempt, chainId) {
      let fixed;
      try {
        fixed = await live.complete({
          ...callArgs,
          input: correctionInput(category),
          ...(chainId ? { previousResponseId: chainId } : {})
        });
      } catch (err) {
        return {
          actions: [], stop: true,
          stopReason: `model-error: correction attempt failed (${truncate((err && err.message) || String(err), 200)}); original failure: ${category}`,
          notes: `Correction attempt failed; original failure (${category}) stands. No action was executed.`,
          usage: null, estimatedCostUsd: null, responseId: (firstAttempt && firstAttempt.responseId) || null,
          corrected: false
        };
      }
      const merged = mergeAttemptUsage(firstAttempt, fixed);
      const usageNote = merged.unknown ? 'usage unknown (an attempt went unreported)' : 'usage combined across both attempts';
      const reParsed = parseTurnContent(fixed && fixed.content);
      if (!reParsed.ok) {
        return {
          actions: [], stop: true,
          stopReason: `model-error: correction still malformed (${reParsed.error}); original failure: ${category}`,
          notes: `Correction rejected (${reParsed.error}); ${usageNote}. No action was executed.`,
          usage: merged.usage, estimatedCostUsd: merged.estimatedCostUsd, responseId: fixed.responseId || null,
          corrected: false
        };
      }
      const reChecked = validateActions(reParsed.value.actions);
      const reNotes = dropNotes(reParsed.value.notes, reChecked.dropped);
      if (reChecked.actions.length === 0 && reParsed.value.stop !== true) {
        return {
          actions: [], stop: true,
          stopReason: `model-error: correction yielded no valid actions; original failure: ${category}`,
          notes: `[correction rejected] ${reNotes}\n${usageNote}. No action was executed.`.slice(0, 2000),
          usage: merged.usage, estimatedCostUsd: merged.estimatedCostUsd, responseId: fixed.responseId || null,
          corrected: false
        };
      }
      return {
        actions: reChecked.actions, stop: reParsed.value.stop === true,
        stopReason: truncate(reParsed.value.stopReason, 500),
        notes: `[corrected after 1 malformed attempt (${category})] ${reNotes}\n${usageNote}.`.slice(0, 2000),
        usage: merged.usage, estimatedCostUsd: merged.estimatedCostUsd, responseId: fixed.responseId || null,
        corrected: true,
        correction: {
          attempts: 2, firstErrorCategory: category,
          firstResponseId: (firstAttempt && firstAttempt.responseId) || null,
          responseId: fixed.responseId || null
        }
      };
    }

    let raw;
    try {
      raw = await live.complete({
        ...callArgs, input,
        ...(responseId ? { previousResponseId: responseId } : {})
      });
    } catch (err) {
      // Only unparseable-but-present model content is correctable. Refusals,
      // truncation, transport, auth, and provider errors rethrow unchanged —
      // the run goes INCOMPLETE via the existing path, never corrected.
      if (isCorrectableThrow(err)) {
        return runCorrection('no-parseable-json', (err && err.attempt) || null, (err && err.attempt && err.attempt.responseId) || responseId || null);
      }
      if (err instanceof SparkApiError || (err && err.code)) throw err;
      throw driverError('MODEL_CALL_FAILED', `model call failed: ${truncate((err && err.message) || String(err), 250)}`);
    }
    const parsed = parseTurnContent(raw && raw.content);
    if (!parsed.ok) {
      return runCorrection(`bad-turn-shape: ${parsed.error}`, raw, raw.responseId || responseId || null);
    }
    const content = parsed.value;
    const checked = validateActions(content.actions);
    const notes = dropNotes(content.notes, checked.dropped);
    if (checked.actions.length === 0 && content.stop !== true) {
      if (checked.dropped.length > 0 && checked.dropped.every((d) => d.format)) {
        const kinds = [...new Set(checked.dropped.map((d) => d.reason.split(':')[0]))].slice(0, 3).join('; ');
        return runCorrection(`bad-args-format: ${kinds}`, raw, raw.responseId || responseId || null);
      }
      return {
        actions: [], stop: true,
        stopReason: `model-error: no valid actions (${checked.dropped.map((d) => d.reason).join('; ') || 'empty actions'}); stopping instead of spinning`,
        notes,
        usage: raw.usage, estimatedCostUsd: raw.estimatedCostUsd, responseId: raw.responseId || null
      };
    }
    return {
      actions: checked.actions, stop: content.stop === true,
      stopReason: truncate(content.stopReason, 500),
      notes,
      usage: raw.usage, estimatedCostUsd: raw.estimatedCostUsd, responseId: raw.responseId || null
    };
  }

  return { nextTurn, TURN_SCHEMA, allowedTools: [...allowed] };
}

module.exports = { createModelDriver, defaultAdapter, TURN_SCHEMA, MAX_ACTIONS_PER_TURN, MAX_SUMMARY_CHARS, MAX_ARG_BYTES };
