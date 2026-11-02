/**
 * Agent planner: genuine model reasoning over novel task text.
 *
 * Migrated from demo/agent.js with identical transport semantics and
 * an extended plan shape (v2 multi-action, v1 single-tx accepted).
 * Greedy decoding (temperature 0) makes identical tasks reproduce
 * identical plans; it does not make the reasoning scripted.
 */

const { PLANNER_SYSTEM_V2 } = require('./prompts');

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;
const DEC_RE = /^[0-9]+$/;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const MAX_ACTIONS = 8;

function validateAction(action, idx) {
  const where = idx === undefined ? 'action' : `actions[${idx}]`;
  if (!action || typeof action !== 'object' || Array.isArray(action)) return `${where} is not an object`;
  if (typeof action.to !== 'string' || !ADDRESS_RE.test(action.to)) return `${where}.to must be a valid address`;
  if (typeof action.value !== 'string') return `${where}.value must be a string quantity`;
  const v = action.value.trim();
  if (!((HEX_RE.test(v) && v.length > 2) || DEC_RE.test(v))) return `${where}.value must be a hex or decimal quantity`;
  if (typeof action.data !== 'string' || !HEX_RE.test(action.data)) return `${where}.data must be 0x hex`;
  if (action.note !== undefined && typeof action.note !== 'string') return `${where}.note must be a string when present`;
  return null;
}

// Returns null when valid, else a human-readable error. Accepts v2
// ({reasoning, actions[]}) and legacy v1 ({reasoning, to, value, data}).
function validatePlan(plan) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) return 'plan is not an object';
  if (typeof plan.reasoning !== 'string' || plan.reasoning.length === 0) return 'reasoning is required';
  if (Array.isArray(plan.actions)) {
    if (plan.actions.length === 0) return 'actions must not be empty';
    if (plan.actions.length > MAX_ACTIONS) return `actions must hold at most ${MAX_ACTIONS} entries`;
    for (let i = 0; i < plan.actions.length; i += 1) {
      const invalid = validateAction(plan.actions[i], i);
      if (invalid) return invalid;
    }
    return null;
  }
  return validateAction(plan);
}

// Normalize either accepted shape to { reasoning, actions[] }.
function normalizePlan(plan) {
  if (Array.isArray(plan.actions)) {
    return {
      reasoning: plan.reasoning,
      actions: plan.actions.map((a) => ({ note: a.note || '', to: a.to, value: a.value, data: a.data }))
    };
  }
  return {
    reasoning: plan.reasoning,
    actions: [{ note: '', to: plan.to, value: plan.value, data: plan.data }]
  };
}

// True when the planner honestly reported a gap (zero-address
// placeholder per the prompt rules). The runtime must stop with
// PLAN_INCOMPLETE and never submit such an action.
function isPlaceholderAction(action) {
  return action && typeof action.to === 'string' && action.to.toLowerCase() === ZERO_ADDRESS;
}

// Planner output cap. Worst valid visible output is ~1.1k tokens
// (reasoning plus at most 8 actions); the same reasoning model has
// been observed spending ~4k hidden reasoning tokens before emitting
// content on simple tasks. 8000 covers both with margin (observed
// demo outputs are ~100-150 tokens), bounding cost and tail latency
// without truncating any valid plan.
const PLANNER_MAX_TOKENS = 8000;

// Live planner: throws on transport failure (callers fail loudly;
// planner output is never mocked here).
async function livePlanner({ fetchImpl, baseUrl, apiKey, model, task, agentAddress, chainId, timeoutMs, system }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs || 120000);
  try {
    const res = await (fetchImpl || fetch)(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: system || PLANNER_SYSTEM_V2 },
          { role: 'user', content: `Task: ${task}\nYour sending address: ${agentAddress}\nChain id: ${chainId}` }
        ],
        response_format: { type: 'json_object' },
        temperature: 0,
        max_tokens: PLANNER_MAX_TOKENS
      }),
      signal: ctrl.signal
    });
    if (!res.ok) throw new Error(`planner API status ${res.status}`);
    const data = await res.json();
    const choice = data.choices && data.choices[0];
    if (choice && choice.finish_reason === 'length') {
      const err = new Error(`planner output truncated at the ${PLANNER_MAX_TOKENS}-token cap; refusing to guess the missing actions`);
      err.code = 'PLANNER_TRUNCATED';
      throw err;
    }
    const content = choice && choice.message && choice.message.content;
    return { plan: JSON.parse(content), model: data.model || model };
  } finally {
    clearTimeout(timer);
  }
}

// Plan with one validation-driven reprompt (same discipline as the
// migrated runner): at most 2 attempts, then PLAN_FAILED. Cap
// truncations are never retried: the reprompt input is strictly
// longer, so a second attempt cannot fit either.
async function planWithRetry(task, plannerFn, { maxAttempts } = {}) {
  const max = maxAttempts || 2;
  let lastError = null;
  for (let attempt = 1; attempt <= max; attempt += 1) {
    const input = lastError ? `${task}\n(Previous plan rejected: ${lastError}. Fix it.)` : task;
    // A planner throw (transport failure, output truncation) never
    // retries: only a returned-but-invalid plan earns a reprompt, and
    // a cap-truncated reprompt input is strictly longer, so a second
    // attempt cannot fit either.
    const { plan: candidate, model } = await plannerFn({ task: input });
    const invalid = validatePlan(candidate);
    if (!invalid) return { plan: normalizePlan(candidate), model, attempts: attempt };
    lastError = invalid;
  }
  throw new Error(`planner produced no valid transaction: ${lastError}`);
}

module.exports = {
  ZERO_ADDRESS, MAX_ACTIONS, PLANNER_MAX_TOKENS,
  validatePlan, validateAction, normalizePlan, isPlaceholderAction,
  livePlanner, planWithRetry
};
