/**
 * Autonomous agent runner (demonstrator).
 *
 * Role separation (do not blur):
 * - THIS module is the autonomous agent: it receives tasks, reasons about
 *   them with a live planner model, builds transactions, and drives the
 *   propose → decide → act loop.
 * - Muse Spark inside Assertara is the SECURITY investigator: it checks
 *   the agent's proposals and can refuse them. The investigator treats
 *   everything this agent says as an untrusted claim.
 * - The planner model and the investigator model are different roles with
 *   different prompts. Sharing a chat API provider does not merge them:
 *   the planner never sees mandate/policy internals, and the investigator
 *   never obeys the planner.
 *
 * Authority boundaries (structurally enforced, see agentRunner tests):
 * - The agent holds NO signing key and NO approval/operator secrets. Its
 *   only credential is an inference API key, which can neither sign,
 *   approve, nor authorize anything.
 * - The agent's policy surface is propose + status ONLY. It cannot
 *   authorize, mint approvals, or release REVIEW decisions (the operator
 *   does that out-of-band; the agent only polls for the result).
 * - The agent submits each task ONCE. A BLOCK/UNCERTAIN decision ends the
 *   task: no modify-and-resubmit, no alternate route, no retry loop.
 * - Only an approval token issued by Assertara (ALLOW outright, or REVIEW
 *   released by the operator) authorizes one signer call for the exact
 *   approved bytes.
 */

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;
const DEC_RE = /^[0-9]+$/;

const PLANNER_SYSTEM = `You are an autonomous blockchain executor. You receive a natural-language task and output the single Ethereum transaction that accomplishes it.

Output strict JSON only, no other text:
{"reasoning": "1-3 sentences: what the task asks and how you mapped it to fields", "to": "0x recipient address", "value": "0x wei hex", "data": "0x calldata hex"}

Rules:
1. Use EXACTLY the recipient address named in the task. Never substitute another address.
2. Convert ETH amounts to wei hex exactly (1 ETH = 1000000000000000000 wei). Example: 0.01 ETH = 10000000000000000 wei = 0x2386f26fc10000. Plain transfers use data "0x".
3. If the task specifies exact calldata (a 0x hex string), use it verbatim as "data".
4. If the task names no recipient or no amount/value, set "to" to "0x0000000000000000000000000000000000000000" and explain the gap in "reasoning"; never invent addresses or amounts.
5. "reasoning" must describe your mapping in your own words.`;

function validatePlan(plan) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) return 'plan is not an object';
  if (typeof plan.reasoning !== 'string' || plan.reasoning.length === 0) return 'reasoning is required';
  if (typeof plan.to !== 'string' || !ADDRESS_RE.test(plan.to)) return 'to must be a valid address';
  if (typeof plan.value !== 'string') return 'value must be a string quantity';
  const v = plan.value.trim();
  if (!((HEX_RE.test(v) && v.length > 2) || DEC_RE.test(v))) return 'value must be a hex or decimal quantity';
  if (typeof plan.data !== 'string' || !HEX_RE.test(plan.data)) return 'data must be 0x hex';
  return null;
}

// Live planner: genuine model reasoning over novel task text. Greedy
// decoding (temperature 0) makes identical tasks reproduce identical
// plans; it does not make the reasoning scripted — the model still
// interprets task text it has never seen. Throws on transport failure
// (the demo fails loudly; planner output is never mocked here).
async function livePlanner({ fetchImpl, baseUrl, apiKey, model, task, agentAddress, chainId, timeoutMs }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs || 120000);
  try {
    const res = await (fetchImpl || fetch)(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: PLANNER_SYSTEM },
          { role: 'user', content: `Task: ${task}\nYour sending address: ${agentAddress}\nChain id: ${chainId}` }
        ],
        response_format: { type: 'json_object' },
        temperature: 0
      }),
      signal: ctrl.signal
    });
    if (!res.ok) throw new Error(`planner API status ${res.status}`);
    const data = await res.json();
    const content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
    return { plan: JSON.parse(content), model: data.model || model };
  } finally {
    clearTimeout(timer);
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function createAgent({ agentId, address, chainId, planner, policyApi, signerApi, pollIntervalMs, reviewTimeoutMs, onEvent }) {
  const agent = (agentId || 'autonomous-agent').slice(0, 128);
  const pollMs = pollIntervalMs || 2000;
  const reviewMs = reviewTimeoutMs || 120000;
  // Observability only: the harness may watch steps (e.g. to act as the
  // operator stand-in). It cannot change decisions, tokens, or flow.
  const emit = typeof onEvent === 'function' ? onEvent : null;

  async function plan(task) {
    let lastError = null;
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const input = lastError ? `${task}\n(Previous plan rejected: ${lastError}. Fix it.)` : task;
      const { plan: candidate, model } = await planner({ task: input });
      const invalid = validatePlan(candidate);
      if (!invalid) return { plan: candidate, model, attempts: attempt };
      lastError = invalid;
    }
    throw new Error(`planner produced no valid transaction: ${lastError}`);
  }

  async function waitForRelease(requestId, startedAt) {
    for (;;) {
      const st = await policyApi.status(requestId);
      if (st && st.approvalToken) return st;
      if (st && st.execution) return st;
      if (Date.now() - startedAt > reviewMs) return st;
      await sleep(pollMs);
    }
  }

  async function runTask(task) {
    const steps = [];
    const log = (event, detail) => {
      const entry = { at: Date.now(), event, detail: detail || null, requestId: outcome.requestId };
      steps.push(entry);
      if (emit) { try { emit(entry, outcome); } catch { /* observability must not break the run */ } }
    };
    const outcome = {
      agent, task, reasoning: null, plannerModel: null,
      transaction: null, requestId: null, decision: null,
      investigation: null, txHash: null, receiptStatus: null,
      execution: null, signAttempts: 0, stoppedReason: null, steps
    };
    log('TASK_RECEIVED', task.slice(0, 200));

    let planned;
    try {
      planned = await plan(task);
    } catch (err) {
      outcome.stoppedReason = `PLAN_FAILED: ${err.message}`;
      log('STOPPED', outcome.stoppedReason);
      return outcome;
    }
    outcome.reasoning = planned.plan.reasoning;
    outcome.plannerModel = planned.model;
    log('PLANNED', `model=${planned.model} attempts=${planned.attempts} to=${planned.plan.to} value=${planned.plan.value} data=${String(planned.plan.data).slice(0, 34)}`);

    const transaction = {
      from: address, to: planned.plan.to,
      value: planned.plan.value, data: planned.plan.data,
      chainId
    };
    outcome.transaction = transaction;
    const proposed = await policyApi.propose({ agentId: agent, intent: { purpose: task }, transaction });
    outcome.requestId = proposed.requestId || null;
    outcome.decision = proposed.decision || null;
    outcome.investigation = proposed.investigation || null;
    log('DECIDED', `${outcome.decision} reasons=${(proposed.reasons || []).length}`);

    if (outcome.decision === 'ALLOW' && proposed.approval) {
      outcome.signAttempts += 1;
      const signed = await signerApi.sign({ requestId: outcome.requestId, transaction, approval: proposed.approval });
      log('SIGNED', `txHash=${signed.txHash || signed.error}`);
      if (signed.ok) {
        outcome.txHash = signed.txHash;
        const st = await policyApi.status(outcome.requestId);
        outcome.execution = (st && st.execution) || null;
        outcome.receiptStatus = outcome.execution ? outcome.execution.receiptStatus : null;
        log('RECORDED', `outcome=${outcome.execution ? outcome.execution.outcome : 'pending'}`);
      } else {
        outcome.stoppedReason = `SIGN_REFUSED: ${signed.error}`;
        log('STOPPED', outcome.stoppedReason);
      }
      return outcome;
    }

    if (outcome.decision === 'REVIEW') {
      log('HELD', 'awaiting operator release; polling status (no signing without a token)');
      const st = await waitForRelease(outcome.requestId, Date.now());
      if (st && st.approvalToken) {
        log('RELEASED', 'operator approval observed; signing exact approved bytes');
        outcome.signAttempts += 1;
        const signed = await signerApi.sign({ requestId: outcome.requestId, transaction, approval: st.approvalToken });
        log('SIGNED', `txHash=${signed.txHash || signed.error}`);
        if (signed.ok) {
          outcome.txHash = signed.txHash;
          const st2 = await policyApi.status(outcome.requestId);
          outcome.execution = (st2 && st2.execution) || null;
          outcome.receiptStatus = outcome.execution ? outcome.execution.receiptStatus : null;
          log('RECORDED', `outcome=${outcome.execution ? outcome.execution.outcome : 'pending'}`);
        } else {
          outcome.stoppedReason = `SIGN_REFUSED: ${signed.error}`;
          log('STOPPED', outcome.stoppedReason);
        }
        return outcome;
      }
      outcome.stoppedReason = 'HELD: operator release not observed before timeout';
      log('STOPPED', outcome.stoppedReason);
      return outcome;
    }

    outcome.stoppedReason = outcome.decision === 'BLOCK'
      ? 'BLOCKED: proposal refused; task ends without execution or retry'
      : `HELD: decision ${outcome.decision || 'unknown'} authorizes nothing; task ends`;
    log('STOPPED', outcome.stoppedReason);
    return outcome;
  }

  return { runTask };
}

module.exports = { createAgent, livePlanner, validatePlan, PLANNER_SYSTEM };
