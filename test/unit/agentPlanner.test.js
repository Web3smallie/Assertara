const assert = require('assert');
const {
  ZERO_ADDRESS, MAX_ACTIONS,
  validatePlan, normalizePlan, isPlaceholderAction,
  planWithRetry
} = require('../../agent/planner/planner');
const { PLANNER_SYSTEM_V2, PLANNER_SYSTEM_V1 } = require('../../agent/planner/prompts');

// Agent planner validation: v2 multi-action and legacy v1 shapes,
// normalization, placeholder detection, and retry discipline.
// The planner function is stubbed here; genuine model output is
// covered by the gated live demo.

const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

function goodAction(overrides) {
  return { note: 'pay', to: A1, value: '0x1000', data: '0x', ...(overrides || {}) };
}

async function runAgentPlannerTests() {
  console.log('Testing agent planner (validation, shapes, retry)...\n');

  // Test 1: v2 and v1 valid shapes pass; normalization unifies them.
  {
    assert.strictEqual(validatePlan({ reasoning: 'r', actions: [goodAction()] }), null);
    assert.strictEqual(validatePlan({ reasoning: 'r', actions: [goodAction(), goodAction({ note: 'two' })] }), null);
    assert.strictEqual(validatePlan({ reasoning: 'r', to: A1, value: '42', data: '0x' }), null, 'legacy v1 accepted');
    const n = normalizePlan({ reasoning: 'r', to: A1, value: '42', data: '0x' });
    assert.deepStrictEqual(n, { reasoning: 'r', actions: [{ note: '', to: A1, value: '42', data: '0x' }] });
    assert.strictEqual(MAX_ACTIONS, 8);
    console.log('✔ Test 1 Passed: v1/v2 shapes validate and normalize identically.');
  }

  // Test 2: malformed plans rejected with precise errors.
  {
    const cases = [
      [null, 'not an object'],
      [{}, 'reasoning is required'],
      [{ reasoning: 'r', actions: [] }, 'must not be empty'],
      [{ reasoning: 'r', actions: new Array(9).fill(goodAction()) }, 'at most 8'],
      [{ reasoning: 'r', actions: [{ ...goodAction(), to: '0x123' }] }, 'actions[0].to'],
      [{ reasoning: 'r', actions: [{ ...goodAction(), value: '-1' }] }, 'actions[0].value'],
      [{ reasoning: 'r', actions: [{ ...goodAction(), data: 'zz' }] }, 'actions[0].data'],
      [{ reasoning: 'r', actions: [{ ...goodAction(), note: 7 }] }, 'actions[0].note'],
      [{ reasoning: 'r', actions: ['nope'] }, 'actions[0] is not an object'],
      [{ reasoning: 'r', to: A1, value: '0x', data: '0x' }, 'hex or decimal quantity']
    ];
    for (const [plan, fragment] of cases) {
      const err = validatePlan(plan);
      assert.ok(err && err.includes(fragment), `${JSON.stringify(plan)} rejected (${err})`);
    }
    console.log('✔ Test 2 Passed: Malformed plans rejected with precise errors.');
  }

  // Test 3: zero-address placeholder is valid shape but flagged for the runtime.
  {
    const plan = { reasoning: 'no recipient named', actions: [goodAction({ to: ZERO_ADDRESS })] };
    assert.strictEqual(validatePlan(plan), null, 'honest gap signal is well-formed');
    assert.strictEqual(isPlaceholderAction(plan.actions[0]), true, 'flagged as placeholder');
    assert.strictEqual(isPlaceholderAction(goodAction()), false);
    console.log('✔ Test 3 Passed: Honest gaps validate but are flagged never-to-submit.');
  }

  // Test 4: retry discipline — reprompt once with the error, then fail loud.
  {
    const seen = [];
    const flaky = async ({ task }) => {
      seen.push(task);
      if (seen.length === 1) return { plan: { reasoning: 'r' }, model: 'stub-1' };
      return { plan: { reasoning: 'r', to: A1, value: '0x1', data: '0x' }, model: 'stub-1' };
    };
    const out = await planWithRetry('pay', flaky);
    assert.strictEqual(out.attempts, 2);
    assert.strictEqual(out.plan.actions.length, 1);
    assert.ok(seen[1].includes('Previous plan rejected'), 'reprompt carries the validation error');
    const hopeless = async () => ({ plan: { nope: true }, model: 'stub-1' });
    await assert.rejects(() => planWithRetry('pay', hopeless), /planner produced no valid transaction/);
    console.log('✔ Test 4 Passed: One validation reprompt, then loud failure.');
  }

  // Test 5: prompts pin the safety rules (exact address, no invention, JSON only).
  {
    for (const [label, prompt] of [['v2', PLANNER_SYSTEM_V2], ['v1', PLANNER_SYSTEM_V1]]) {
      assert.ok(prompt.includes('EXACTLY the recipient address'), `${label} pins exact address`);
      assert.ok(prompt.includes('never invent addresses or amounts'), `${label} forbids invention`);
      assert.ok(prompt.includes('strict JSON only'), `${label} pins JSON output`);
    }
    assert.ok(PLANNER_SYSTEM_V2.includes('"actions"'), 'v2 requests the actions array');
    console.log('✔ Test 5 Passed: Planner prompts pin exactness and no-invention rules.');
  }

  console.log('\nAll agent planner tests passed.');
}

if (require.main === module) {
  runAgentPlannerTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentPlannerTests };
