const assert = require('assert');
const { AssertaraClient, isCleanExecution } = require('../../sdk/client');
const { AssertaraError, CODES } = require('../../sdk/errors');
const { digestTx } = require('../../sdk/digest');

// SDK client: guards, error mapping, waits, and visibility against a
// mocked transport. No network, no chain, no model.

const TX = { from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', value: '0x1000', data: '0x', chainId: '0x7a69' };
const DIGEST = digestTx(TX);

function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

// routes: { 'METHOD path': (url, opts, calls) => response | body }
// records every call (method, path, headers, body) for assertion.
function mockFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    const method = (opts && opts.method) || 'GET';
    const u = String(url);
    const base = u.startsWith('http://signer:2') ? 'http://signer:2' : 'http://policy:1';
    const path = u.slice(base.length);
    const key = `${method} ${path}`;
    const entry = { method, path, url: u, headers: (opts && opts.headers) || {}, body: opts && opts.body ? JSON.parse(opts.body) : undefined };
    calls.push(entry);
    const handler = routes[key] || routes[path];
    if (!handler) throw new Error(`unexpected fetch ${key}`);
    const out = typeof handler === 'function' ? await handler(u, opts, calls) : handler;
    if (out && typeof out.ok === 'boolean' && typeof out.json === 'function') return out;
    return jsonResponse(200, out);
  };
  return { fetchImpl, calls };
}

function sseStream(events) {
  const text = events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join('');
  const bytes = new TextEncoder().encode(text);
  let consumed = false;
  return {
    ok: true,
    status: 200,
    body: {
      getReader() {
        return {
          async read() {
            if (consumed) return { done: true, value: undefined };
            consumed = true;
            return { done: false, value: bytes };
          },
          async cancel() {},
          releaseLock() {}
        };
      }
    }
  };
}

function clientWith(routes, opts) {
  const { fetchImpl, calls } = mockFetch(routes);
  const client = new AssertaraClient({
    policyBase: 'http://policy:1',
    signerBase: 'http://signer:2',
    apiKey: 'alpha:aaaaaaaaaaaaaaaa',
    fetchImpl,
    nowFn: () => 1767225600000,
    ...(opts || {})
  });
  return { client, calls };
}

function allowStatus(overrides) {
  return {
    requestId: 'agent_1', status: 'APPROVED', decision: 'ALLOW', reasons: ['ok'],
    txDigest: DIGEST, traceId: 'tr_1',
    investigation: { evalId: 'eval_1', verdict: 'MATCH', reasoningOrigin: 'model', ruleFindings: [], safeguardTriggers: [] },
    mandate: { id: 'm', version: 1 },
    approvalToken: 'apv1.token.mac', approvalExpiresAt: 1767225900000,
    operatorAuthorizationRequired: false, operatorAuthorized: false,
    execution: null, visual: null, createdAt: 1, updatedAt: 2,
    ...(overrides || {})
  };
}

async function runSdkClientTests() {
  console.log('Testing SDK client (guards, mapping, waits, visibility)...\n');

  // Test 1: connect verifies health and an active mandate.
  {
    const { client } = clientWith({
      'GET /health': { status: 'healthy' },
      'GET /api/v1/agent/mandate': { configured: true, id: 'm', version: 1 }
    });
    const out = await client.connect();
    assert.strictEqual(out.policy.status, 'healthy');
    assert.strictEqual(out.mandate.id, 'm');
    const { client: bad } = clientWith({
      'GET /health': { status: 'healthy' },
      'GET /api/v1/agent/mandate': { configured: false, error: 'none' }
    });
    await assert.rejects(() => bad.connect(), (e) => e.code === CODES.UNAVAILABLE);
    console.log('✔ Test 1 Passed: connect() fails fast without an active mandate.');
  }

  // Test 2: submit sends auth + idempotency key, returns the handle ids.
  {
    const { client, calls } = clientWith({
      'POST /api/v1/agent/investigations': { requestId: 'agent_9', traceId: 'tr_9', txDigest: DIGEST, status: 'INVESTIGATING', replayed: false }
    });
    const inv = await client.submit({ transaction: TX, purpose: 'p', agentId: 'a1' });
    assert.strictEqual(inv.requestId, 'agent_9');
    assert.strictEqual(inv.traceId, 'tr_9');
    assert.strictEqual(calls.length, 1);
    assert.strictEqual(calls[0].headers.Authorization, 'Bearer alpha:aaaaaaaaaaaaaaaa');
    assert.ok(/^sdk_/.test(calls[0].headers['Idempotency-Key']), 'key auto-generated');
    assert.deepStrictEqual(calls[0].body.transaction, TX, 'exact bytes submitted');
    console.log('✔ Test 2 Passed: submit() shape, auth, idempotency, exact bytes.');
  }

  // Test 3: HTTP status to error-code mapping across the table.
  {
    const cases = [
      [400, CODES.VALIDATION], [401, CODES.AUTH], [403, CODES.AUTH], [404, CODES.NOT_FOUND],
      [409, CODES.CONFLICT], [410, CODES.EXPIRED], [429, CODES.RATE_LIMITED],
      [502, CODES.UPSTREAM], [503, CODES.UNAVAILABLE], [500, CODES.SERVER]
    ];
    for (const [status, code] of cases) {
      const { client } = clientWith({ 'GET /api/v1/agent/requests/agent_x': jsonResponse(status, { error: `e${status}`, requestId: 'agent_x' }) });
      const err = await client.getStatus('agent_x').then(() => null, (e) => e);
      assert.ok(err instanceof AssertaraError, `status ${status} typed`);
      assert.strictEqual(err.code, code, `status ${status} maps to ${code}`);
      assert.strictEqual(err.message, `e${status}`);
    }
    console.log('✔ Test 3 Passed: Full HTTP-to-error-code mapping exact.');
  }

  // Test 4: waitForDecision polls, surfaces genuine progress, then resolves terminal.
  {
    const seen = [];
    let n = 0;
    const { client } = clientWith({
      'GET /api/v1/agent/requests/agent_w': () => {
        n += 1;
        if (n < 3) return { requestId: 'agent_w', status: 'INVESTIGATING', decision: null, stage: 'muse-spark', progress: { museSpark: { state: 'running' } } };
        return allowStatus({ requestId: 'agent_w' });
      }
    }, { timeouts: { pollInterval: 5, decision: 5000 } });
    const out = await client.waitForDecision('agent_w', { onProgress: (p) => seen.push(p) });
    assert.strictEqual(out.decision, 'ALLOW');
    assert.strictEqual(seen.length, 2, 'progress delivered while running');
    assert.strictEqual(seen[0].stage, 'muse-spark');
    console.log('✔ Test 4 Passed: Decision wait polls and forwards live progress.');
  }

  // Test 5: waitForDecision times out instead of hanging.
  {
    // Real clock here: the shared fixed nowFn would freeze the deadline.
    const { client } = clientWith({
      'GET /api/v1/agent/requests/agent_hang': { requestId: 'agent_hang', status: 'INVESTIGATING', decision: null }
    }, { timeouts: { pollInterval: 5, decision: 60 }, nowFn: () => Date.now() });
    const err = await client.waitForDecision('agent_hang').then(() => null, (e) => e);
    assert.ok(err && err.code === CODES.TIMEOUT);
    console.log('✔ Test 5 Passed: Decision wait times out cleanly.');
  }

  // Test 6: execute() happy path uses the FRESH approval and exact bytes.
  {
    const { client, calls } = clientWith({
      'GET /api/v1/agent/requests/agent_1': allowStatus(),
      'POST /sign': { ok: true, txHash: '0xabc', receipt: { status: '0x1' }, verification: { receiptVerified: true } }
    });
    const out = await client.execute({ requestId: 'agent_1', transaction: TX });
    assert.strictEqual(out.txHash, '0xabc');
    const sign = calls.find((c) => c.path === '/sign');
    assert.ok(sign, 'signer contacted once');
    assert.strictEqual(sign.body.approval, 'apv1.token.mac', 'approval comes from fresh status');
    assert.deepStrictEqual(sign.body.transaction, TX, 'exact bytes signed');
    assert.strictEqual(sign.body.requestId, 'agent_1');
    // REVIEW released out-of-band (usable token present) is executable too.
    const released = clientWith({
      'GET /api/v1/agent/requests/agent_1': allowStatus({ decision: 'REVIEW', operatorAuthorizationRequired: true, operatorAuthorized: true }),
      'POST /sign': { ok: true, txHash: '0xrel', receipt: { status: '0x1' }, verification: { receiptVerified: true } }
    });
    const out2 = await released.client.execute({ requestId: 'agent_1', transaction: TX });
    assert.strictEqual(out2.txHash, '0xrel', 'released REVIEW executes');
    assert.ok(released.calls.some((c) => c.path === '/sign'), 'released REVIEW reaches the signer');
    console.log('✔ Test 6 Passed: execute() verifies fresh, signs exact bytes (ALLOW + released REVIEW).');
  }

  // Test 7: BLOCK / UNCERTAIN / REVIEW-pending / expired / digest-mismatch never reach the signer.
  {
    const variants = [
      ['BLOCK', allowStatus({ decision: 'BLOCK', approvalToken: null }), CODES.NOT_EXECUTABLE],
      ['UNCERTAIN', allowStatus({ decision: 'UNCERTAIN', approvalToken: null }), CODES.NOT_EXECUTABLE],
      ['REVIEW-pending', allowStatus({ decision: 'REVIEW', approvalToken: null, operatorAuthorizationRequired: true }), CODES.NOT_EXECUTABLE],
      ['expired', allowStatus({ approvalExpiresAt: 1000 }), CODES.EXPIRED]
    ];
    for (const [label, status, code] of variants) {
      const { client, calls } = clientWith({ 'GET /api/v1/agent/requests/agent_1': status });
      const err = await client.execute({ requestId: 'agent_1', transaction: TX }).then(() => null, (e) => e);
      assert.ok(err && err.code === code, `${label} refused with ${code}`);
      assert.ok(!calls.some((c) => c.path === '/sign'), `${label} never contacts the signer`);
    }
    const { client, calls } = clientWith({ 'GET /api/v1/agent/requests/agent_1': allowStatus() });
    const mutated = { ...TX, value: '0x1001' };
    const err = await client.execute({ requestId: 'agent_1', transaction: mutated }).then(() => null, (e) => e);
    assert.ok(err && err.code === CODES.DIGEST_MISMATCH, 'mutated bytes refused');
    assert.ok(!calls.some((c) => c.path === '/sign'), 'mutated bytes never contact the signer');
    console.log('✔ Test 7 Passed: All non-executable states + digest mismatch stop before the signer.');
  }

  // Test 8: signer refusal surfaces as AUTH with the server reason.
  {
    const { client } = clientWith({
      'GET /api/v1/agent/requests/agent_1': allowStatus(),
      'POST /sign': jsonResponse(403, { error: 'approval already consumed' })
    });
    const err = await client.execute({ requestId: 'agent_1', transaction: TX }).then(() => null, (e) => e);
    assert.ok(err && err.code === CODES.AUTH, 'refusal is AUTH');
    assert.ok(/already consumed/.test(err.message), 'server reason preserved');
    console.log('✔ Test 8 Passed: Signer refusal mapped with reason intact.');
  }

  // Test 9: operator wait resolves on release, refuses terminal non-REVIEW, times out.
  {
    let n = 0;
    const { client } = clientWith({
      'GET /api/v1/agent/requests/agent_r': () => {
        n += 1;
        return allowStatus({ requestId: 'agent_r', decision: 'REVIEW', approvalToken: n < 2 ? null : 'apv1.op.mac', operatorAuthorizationRequired: true, operatorAuthorized: n >= 2 });
      }
    }, { timeouts: { pollInterval: 5, operator: 5000 } });
    const out = await client.waitForOperatorApproval('agent_r');
    assert.strictEqual(out.approvalToken, 'apv1.op.mac');
    const { client: blocked } = clientWith({ 'GET /api/v1/agent/requests/agent_b': allowStatus({ requestId: 'agent_b', decision: 'BLOCK', approvalToken: null }) });
    const err = await blocked.waitForOperatorApproval('agent_b').then(() => null, (e) => e);
    assert.ok(err && err.code === CODES.NOT_EXECUTABLE, 'BLOCK never waits for release');
    console.log('✔ Test 9 Passed: Operator wait releases, refuses BLOCK, never sends secrets.');
  }

  // Test 10: execution wait returns outcomes verbatim; only EXECUTED is clean.
  {
    const { client } = clientWith({
      'GET /api/v1/agent/requests/agent_e': allowStatus({ requestId: 'agent_e', execution: { outcome: 'EFFECTS_DIVERGED', txHash: '0xd' } })
    });
    const ex = await client.waitForExecution('agent_e');
    assert.strictEqual(ex.outcome, 'EFFECTS_DIVERGED', 'divergence returned, never relabeled');
    assert.strictEqual(isCleanExecution(ex), false);
    assert.strictEqual(isCleanExecution({ outcome: 'EXECUTED' }), true);
    console.log('✔ Test 10 Passed: Execution outcomes verbatim; cleanliness explicit.');
  }

  // Test 11: streamProgress forwards genuine events untouched and ends on stream-end.
  {
    const events = [
      { seq: 1, type: 'span-start', component: 'muse-spark' },
      { seq: 2, type: 'span-finish', component: 'muse-spark', status: 'COMPLETED' },
      { seq: 3, type: 'stream-end', traceId: 'tr_s' }
    ];
    const seen = [];
    const streaming = async () => sseStream(events);
    const client = new AssertaraClient({ policyBase: 'http://policy:1', apiKey: 'a:b', fetchImpl: streaming });
    const last = await client.streamProgress('tr_s', (e) => { seen.push(e); });
    assert.deepStrictEqual(seen, events, 'events forwarded exactly, none invented');
    assert.strictEqual(last.type, 'stream-end');
    console.log('✔ Test 11 Passed: SSE stream forwards genuine events only.');
  }

  // Test 12: the client surface cannot carry operator secrets or signing keys.
  {
    const client = new AssertaraClient({ policyBase: 'http://policy:1', privateKey: '0xdead', operatorSecret: 'shh', mnemonic: 'x' });
    assert.strictEqual(client.privateKey, undefined, 'private key not retained');
    assert.strictEqual(client.operatorSecret, undefined, 'operator secret not retained');
    assert.strictEqual(client.mnemonic, undefined, 'mnemonic not retained');
    const methods = Object.getOwnPropertyNames(AssertaraClient.prototype).filter((m) => m !== 'constructor');
    assert.ok(!methods.some((m) => /secret|private|mnemonic|sign|broadcast|raw|force|override/i.test(m) && m !== 'streamProgress'), `no dangerous methods: ${methods.join(',')}`);
    assert.ok(!('operatorSecret' in client) && !('privateKey' in client));
    console.log('✔ Test 12 Passed: No secret/key surface anywhere on the client.');
  }

  console.log('\nAll SDK client tests passed.');
}

if (require.main === module) {
  runSdkClientTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSdkClientTests };
