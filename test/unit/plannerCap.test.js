const assert = require('assert');
const { livePlanner, planWithRetry, PLANNER_MAX_TOKENS } = require('../../agent/planner/planner');

// Planner output cap: the request carries a bounded max_tokens, and a
// cap truncation fails loudly (never silently, never retried). No
// network, no model: fetch is fully stubbed.

const PLAN = { reasoning: 'pay the contributor', actions: [{ note: 'pay', to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', value: '0x1000', data: '0x' }] };

function stubFetch(handler) {
  const calls = [];
  const fn = async (url, init) => { calls.push({ url, init }); return handler(url, init); };
  fn.calls = calls;
  return fn;
}
const jsonRes = (body) => ({ ok: true, status: 200, json: async () => body });

async function runPlannerCapTests() {
  console.log('Testing planner output cap...\n');

  // Test 1: the planner request carries the documented cap.
  {
    assert.strictEqual(PLANNER_MAX_TOKENS, 8000);
    const fetch = stubFetch(() => jsonRes({ choices: [{ message: { content: JSON.stringify(PLAN) }, finish_reason: 'stop' }], model: 'stub' }));
    const out = await livePlanner({ fetchImpl: fetch, baseUrl: 'http://x', apiKey: 'k', model: 'm', task: 't', agentAddress: '0xa', chainId: '1' });
    assert.deepStrictEqual(out.plan, PLAN);
    const body = JSON.parse(fetch.calls[0].init.body);
    assert.strictEqual(body.max_tokens, 8000);
    assert.strictEqual(body.temperature, 0);
  }

  // Test 2: finish_reason=length throws a distinctive truncation error.
  {
    const fetch = stubFetch(() => jsonRes({ choices: [{ message: { content: '{"partial":' }, finish_reason: 'length' }] }));
    await assert.rejects(
      livePlanner({ fetchImpl: fetch, baseUrl: 'http://x', apiKey: 'k', model: 'm', task: 't', agentAddress: 'a', chainId: '1' }),
      (err) => err.code === 'PLANNER_TRUNCATED' && /truncated/.test(err.message)
    );
  }

  // Test 3: truncations never retry (the reprompt input is longer, so a
  // second attempt cannot fit either); other throws still propagate.
  {
    let calls = 0;
    const trunc = async () => { calls += 1; const e = new Error('x'); e.code = 'PLANNER_TRUNCATED'; throw e; };
    await assert.rejects(planWithRetry('task', trunc), /x/);
    assert.strictEqual(calls, 1, 'truncation attempted exactly once');
    let tCalls = 0;
    const transport = async () => { tCalls += 1; throw new Error('socket hangup'); };
    await assert.rejects(planWithRetry('task', transport), /socket hangup/);
    assert.strictEqual(tCalls, 1, 'transport errors still propagate without retry');
  }

  // Test 4: validation reprompt behavior is unchanged (one reprompt).
  {
    let calls = 0;
    const flaky = async () => { calls += 1; return calls === 1 ? { plan: { bogus: true }, model: 's' } : { plan: PLAN, model: 's' }; };
    const out = await planWithRetry('task', flaky);
    assert.strictEqual(out.attempts, 2);
    assert.deepStrictEqual(out.plan.actions.length, 1);
  }

  console.log('\nAll Planner Cap Tests Passed Successfully!');
}

runPlannerCapTests().catch((err) => { console.error(err); process.exit(1); });
