const assert = require('assert');
const { AssertaraClient } = require('../../sdk/index');
const { Investigation } = require('../../sdk/investigation');
const { digestTx } = require('../../sdk/digest');

// SSE decision wait: the live stream resolves on the agent-response
// marker with a single status read; every stream failure falls back
// to bounded polling; execute() accepts a just-observed record. No
// network, no model: fetch is fully stubbed.

const TX = { from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', value: '0x1000', data: '0x', chainId: 31337 };
const DECIDED = { decision: 'ALLOW', status: 'DECIDED', reasons: ['ok'], txDigest: digestTx(TX), approvalToken: 'tok', approvalExpiresAt: Date.now() + 60000 };
const UNDECIDED = { decision: null, status: 'RUNNING', stage: 'investigate', reasons: [] };

function sseBody(frames, { hang } = {}) {
  const bytes = Buffer.from(frames.map((f) => `data: ${JSON.stringify(f)}\n\n`).join(''));
  let reads = 0;
  return {
    getReader() {
      return {
        read(signal) {
          reads += 1;
          if (hang) {
            return new Promise((_, reject) => {
              if (signal) {
                if (signal.aborted) reject(new Error('aborted'));
                else signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
              }
              // No signal: fail loudly rather than hang the suite forever.
              else reject(new Error('hanging stub requires an abort signal'));
            });
          }
          if (reads === 1) return Promise.resolve({ done: false, value: bytes });
          return Promise.resolve({ done: true, value: undefined });
        },
        cancel() { return Promise.resolve(); },
        releaseLock() {}
      };
    }
  };
}

function stubFetch({ streamFrames, streamBehavior, statuses }) {
  const calls = [];
  const statusQueue = (statuses || []).slice();
  const fn = async (url, init) => {
    const u = String(url);
    calls.push({ url: u, method: (init && init.method) || 'GET' });
    if (u.includes('/stream')) {
      if (streamBehavior === 'http-error') return { ok: false, status: 500, json: async () => ({}) };
      if (streamBehavior === 'throw') throw new Error('socket hangup');
      const hanging = streamBehavior === 'hang';
      const body = sseBody(streamFrames || [], { hang: hanging });
      const inner = body.getReader();
      const signal = init && init.signal;
      return {
        ok: true,
        body: {
          getReader: () => ({
            read: () => inner.read(signal),
            cancel: () => inner.cancel(),
            releaseLock: () => inner.releaseLock()
          })
        }
      };
    }
    if (u.includes('/api/v1/agent/requests/') && (!init || !init.method || init.method === 'GET')) {
      const next = statusQueue.length > 0 ? statusQueue.shift() : UNDECIDED;
      return { ok: true, status: 200, json: async () => next };
    }
    if (u.endsWith('/sign')) return { ok: true, status: 200, json: async () => ({ txHash: '0x1', receipt: { status: '0x1' } }) };
    throw new Error(`unstubbed url ${u}`);
  };
  fn.calls = calls;
  return fn;
}

function makeClient(fetchImpl) {
  return new AssertaraClient({ policyBase: 'http://policy', signerBase: 'http://signer', fetchImpl });
}
const gets = (calls, part) => calls.filter((c) => c.method === 'GET' && c.url.includes(part));

async function runSseWaitTests() {
  console.log('Testing SSE decision wait + execute dedupe...\n');

  // Test 1: live path resolves on the agent-response marker with one
  // stream + one status read; progress keeps the {stage,progress} shape.
  {
    const progress = [];
    const fetch = stubFetch({
      streamFrames: [
        { type: 'trace-start' },
        { type: 'span-start', component: 'muse-spark' },
        { type: 'span-finish', component: 'muse-spark', status: 'COMPLETED' },
        { type: 'span-finish', component: 'decoder', status: 'COMPLETED' },
        { type: 'span-finish', component: 'agent-response', status: 'COMPLETED' }
      ],
      statuses: [DECIDED]
    });
    const out = await makeClient(fetch).waitForDecisionLive('r1', {
      traceId: 'tr1', timeoutMs: 5000, onProgress: (p) => progress.push(p)
    });
    assert.strictEqual(out.decision, 'ALLOW');
    assert.strictEqual(gets(fetch.calls, '/stream').length, 1, 'exactly one stream request');
    assert.strictEqual(gets(fetch.calls, '/api/v1/agent/requests/').length, 1, 'exactly one status read');
    assert.ok(fetch.calls.every((c) => c.method === 'GET'), 'waiter only reads');
    assert.deepStrictEqual(progress[0], { stage: 'muse-spark', progress: { museSpark: { state: 'running' } } });
    assert.deepStrictEqual(progress[1], { stage: 'muse-spark', progress: { museSpark: { state: 'completed' } } });
    assert.deepStrictEqual(progress[2], { stage: 'decoder', progress: null });
    assert.strictEqual(progress[3].stage, 'agent-response');
  }

  // Test 2: trace-finish without a marker (e.g. malformed REJECTED)
  // still resolves through one status read.
  {
    const fetch = stubFetch({
      streamFrames: [{ type: 'trace-start' }, { type: 'trace-finish', durationMs: 5 }],
      statuses: [{ decision: null, status: 'REJECTED', reasons: ['malformed'] }]
    });
    const out = await makeClient(fetch).waitForDecisionLive('r1', { traceId: 'tr1', timeoutMs: 5000 });
    assert.strictEqual(out.status, 'REJECTED');
    assert.strictEqual(gets(fetch.calls, '/api/v1/agent/requests/').length, 1);
  }

  // Test 3: stream HTTP failure falls back to polling; no POSTs ever.
  {
    const fetch = stubFetch({ streamBehavior: 'http-error', statuses: [UNDECIDED, UNDECIDED, DECIDED] });
    const out = await makeClient(fetch).waitForDecisionLive('r1', { traceId: 'tr1', timeoutMs: 5000, pollIntervalMs: 5 });
    assert.strictEqual(out.decision, 'ALLOW');
    assert.ok(gets(fetch.calls, '/api/v1/agent/requests/').length >= 3, 'polling fallback engaged');
    assert.ok(fetch.calls.every((c) => c.method === 'GET'), 'fallback only reads: no duplicate submit/execute possible');
  }

  // Test 4: stream disconnect (throw) falls back to polling.
  {
    const fetch = stubFetch({ streamBehavior: 'throw', statuses: [UNDECIDED, DECIDED] });
    const out = await makeClient(fetch).waitForDecisionLive('r1', { traceId: 'tr1', timeoutMs: 5000, pollIntervalMs: 5 });
    assert.strictEqual(out.decision, 'ALLOW');
    assert.ok(gets(fetch.calls, '/api/v1/agent/requests/').length >= 2);
  }

  // Test 5: no traceId polls directly without touching the stream.
  {
    const fetch = stubFetch({ statuses: [DECIDED] });
    const out = await makeClient(fetch).waitForDecisionLive('r1', { timeoutMs: 5000, pollIntervalMs: 5 });
    assert.strictEqual(out.decision, 'ALLOW');
    assert.strictEqual(gets(fetch.calls, '/stream').length, 0, 'no stream without a traceId');
  }

  // Test 6: marker seen but record not yet decided -> brief poll, then resolve.
  {
    const fetch = stubFetch({
      streamFrames: [{ type: 'span-finish', component: 'agent-response', status: 'COMPLETED' }],
      statuses: [UNDECIDED, DECIDED]
    });
    const out = await makeClient(fetch).waitForDecisionLive('r1', { traceId: 'tr1', timeoutMs: 5000, pollIntervalMs: 5 });
    assert.strictEqual(out.decision, 'ALLOW');
    assert.strictEqual(gets(fetch.calls, '/api/v1/agent/requests/').length, 2);
  }

  // Test 7: hanging stream + undecided record -> loud timeout (bounded total).
  {
    const fetch = stubFetch({ streamBehavior: 'hang', statuses: [] });
    await assert.rejects(
      makeClient(fetch).waitForDecisionLive('r1', { traceId: 'tr1', timeoutMs: 120, pollIntervalMs: 10 }),
      /timed out/i
    );
  }

  // Test 8: a throwing onProgress never breaks the wait.
  {
    const fetch = stubFetch({
      streamFrames: [
        { type: 'span-start', component: 'muse-spark' },
        { type: 'span-finish', component: 'agent-response', status: 'COMPLETED' }
      ],
      statuses: [DECIDED]
    });
    const out = await makeClient(fetch).waitForDecisionLive('r1', {
      traceId: 'tr1', timeoutMs: 5000, onProgress: () => { throw new Error('observer boom'); }
    });
    assert.strictEqual(out.decision, 'ALLOW');
  }

  // Test 9: execute() with a just-observed record skips the status
  // re-read but still signs through every guard.
  {
    const fetch = stubFetch({ statuses: [] });
    const out = await makeClient(fetch).execute({ requestId: 'r1', transaction: TX, status: { ...DECIDED } });
    assert.strictEqual(out.txHash, '0x1');
    assert.strictEqual(gets(fetch.calls, '/api/v1/agent/requests/').length, 0, 'no redundant status fetch');
    assert.strictEqual(fetch.calls.filter((c) => c.url.endsWith('/sign')).length, 1);
  }

  // Test 10: a stale handed-over record fails loudly before any signer contact.
  {
    const fetch = stubFetch({ statuses: [] });
    await assert.rejects(
      makeClient(fetch).execute({ requestId: 'r1', transaction: TX, status: { ...DECIDED, approvalExpiresAt: Date.now() - 1000 } }),
      /expired/i
    );
    assert.strictEqual(fetch.calls.filter((c) => c.url.endsWith('/sign')).length, 0, 'no signer contact on stale approval');
    await assert.rejects(
      makeClient(fetch).execute({ requestId: 'r1', transaction: TX, status: { ...DECIDED, decision: 'BLOCK' } }),
      /BLOCK/
    );
  }

  // Test 11: execute() without a handover re-reads (unchanged default).
  {
    const fetch = stubFetch({ statuses: [DECIDED] });
    const out = await makeClient(fetch).execute({ requestId: 'r1', transaction: TX });
    assert.strictEqual(out.txHash, '0x1');
    assert.strictEqual(gets(fetch.calls, '/api/v1/agent/requests/').length, 1);
  }

  // Test 12: the handle prefers live with a traceId, polls without.
  {
    const calls = [];
    const fake = {
      waitForDecisionLive: async (id, o) => { calls.push(['live', id, o.traceId]); return DECIDED; },
      waitForDecision: async (id) => { calls.push(['poll', id]); return DECIDED; }
    };
    const withTrace = new Investigation(fake, { requestId: 'r', traceId: 'tr' });
    assert.strictEqual((await withTrace.wait()).decision, 'ALLOW');
    const withoutTrace = new Investigation(fake, { requestId: 'r' });
    assert.strictEqual((await withoutTrace.wait()).decision, 'ALLOW');
    assert.deepStrictEqual(calls.map((c) => c[0]), ['live', 'poll']);
    assert.strictEqual(calls[0][2], 'tr');
    const replay = new Investigation(fake, { requestId: 'r', traceId: 'tr', snapshot: DECIDED });
    assert.strictEqual((await replay.wait()).decision, 'ALLOW');
    assert.strictEqual(calls.length, 2, 'replay snapshot still short-circuits');
  }

  console.log('\nAll SSE Wait Tests Passed Successfully!');
}

runSseWaitTests().catch((err) => { console.error(err); process.exit(1); });
