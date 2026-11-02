const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

// SDK end-to-end: REAL policy app (HTTP), REAL signer process, REAL
// Anvil chain, REAL SDK client + guarded wallet. The ONLY mock is the
// model transport (canned MATCH verdicts, labeled MOCK): every security
// property — auth, isolation, async progress, guards, digest binding,
// single-use, operator gating, broadcast, receipt verification — runs
// against genuine components and a live chain.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const STRANGER = '0x000000000000000000000000000000000000dEaD';
const UNKNOWN = '0x1234567890123456789012345678901234567890';
const ANVIL_MNEMONIC = 'test test test test test test test test test test test junk';

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

async function rpc(rpcUrl, method, params) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params || [] })
  });
  if (!res.ok) throw new Error(`rpc http ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(body.error.message || 'rpc error');
  return body.result;
}

async function waitFor(fn, timeoutMs, label) {
  const start = Date.now();
  for (;;) {
    try {
      const out = await fn();
      if (out) return out;
    } catch { /* keep waiting */ }
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

function sdkMandate(anvilRpc) {
  return {
    id: 'sdk-e2e-mandate', version: 1, issuer: 'sdk-e2e-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: A0, senders: [A0],
    chains: [{ id: 31337, rpcUrl: anvilRpc, name: 'anvil-sdk-e2e' }],
    // UNKNOWN is an allowlisted recipient AND contract so the unknown-
    // selector probe reaches calldata decoding (UNCERTAIN) instead of
    // stopping at the recipient gate (BLOCK).
    recipients: { allow: [A1, UNKNOWN], deny: [STRANGER] },
    contracts: { allow: [UNKNOWN] }, selectors: { allow: ['0xdeadbeef'] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [{ windowMs: 86400000, maxNativeWei: '1000000000000000000' }],
    reviewRules: [{ when: 'nativeValueAboveWei', value: '10000000000000000' }]
  };
}

async function runSdkFlowTests() {
  console.log('Testing SDK end-to-end (app + signer + Anvil; MOCK model)...\n');

  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'sdk-e2e-'));

  const APPROVAL_SECRET = crypto.randomBytes(32).toString('hex');
  const OPERATOR_SECRET = crypto.randomBytes(32).toString('hex');
  const ALPHA_SECRET = crypto.randomBytes(32).toString('hex');
  const BETA_SECRET = crypto.randomBytes(32).toString('hex');

  const { mnemonicToAccount, generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
  const anvilAccount = mnemonicToAccount(ANVIL_MNEMONIC);
  assert.strictEqual(anvilAccount.address.toLowerCase(), A0.toLowerCase(), 'derived key must be Anvil account[0]');
  const SIGNER_KEY = `0x${Buffer.from(anvilAccount.getHdKey().privateKey).toString('hex')}`;
  const OPERATOR_KEY = generatePrivateKey();
  const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address;

  const anvilPort = await freePort();
  const signerPort = await freePort();
  const anvilRpc = `http://127.0.0.1:${anvilPort}`;
  const mandateFile = path.join(tmp, 'mandate.json');
  fs.writeFileSync(mandateFile, JSON.stringify(sdkMandate(anvilRpc)), 'utf8');
  const { sealMandateFile } = require('../../src/signer/signMandate');
  await sealMandateFile(mandateFile, OPERATOR_KEY);

  const anvilCandidates = [
    process.env.ANVIL_BIN,
    path.join(os.homedir(), '.foundry', 'bin', process.platform === 'win32' ? 'anvil.exe' : 'anvil'),
    'anvil'
  ].filter(Boolean);
  const anvilBin = anvilCandidates.find((c) => { try { return fs.existsSync(c); } catch { return false; } }) || 'anvil';
  const anvil = spawn(anvilBin, ['--port', String(anvilPort)], { stdio: ['ignore', 'ignore', 'pipe'] });
  anvil.on('error', () => {});
  let policyServer = null;
  let signerProc = null;
  const killAll = () => {
    try { anvil.kill('SIGKILL'); } catch {}
    try { if (signerProc) signerProc.kill('SIGKILL'); } catch {}
    try { if (policyServer) policyServer.close(); } catch {}
  };

  const realFetch = global.fetch;
  try {
    await waitFor(async () => (await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69', 30000, 'anvil boot');

    process.env.MANDATE_FILE = mandateFile;
    process.env.APPROVAL_SECRET = APPROVAL_SECRET;
    process.env.OPERATOR_SECRET = OPERATOR_SECRET;
    process.env.TRUSTED_MANDATE_AUTHORITIES = OPERATOR_ADDR;
    process.env.AGENT_API_KEYS = `alpha:${ALPHA_SECRET},beta:${BETA_SECRET}`;
    delete process.env.AGENT_AUTH_MODE;
    process.env.AGENT_LEDGER_FILE = path.join(tmp, 'agent-ledger.jsonl');
    process.env.SPENDING_LEDGER_FILE = path.join(tmp, 'agent-spending.jsonl');
    process.env.AGENT_SNAPSHOT_FILE = path.join(tmp, 'agent-requests.json');
    process.env.INVESTIGATIONS_FILE = path.join(tmp, 'investigations.jsonl');
    process.env.MODEL_API_KEY = 'sdk-e2e-key';
    const appConfig = require('../../src/config/env');

    // Model transport stub (MOCK) with an optional gate for the progress test.
    let gateModel = null;
    global.fetch = async (url, opts) => {
      if (typeof url === 'string' && url.startsWith(appConfig.metaApiBaseUrl)) {
        if (gateModel) await gateModel();
        return {
          ok: true,
          json: async () => ({ choices: [{ message: { content: JSON.stringify({
            verdict: 'MATCH', confidence: 0.95, summary: 'sdk-e2e MOCK MATCH',
            discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
          }) } }] })
        };
      }
      return realFetch(url, opts);
    };

    const app = require('../../src/server.js');
    const policyPort = await new Promise((resolve, reject) => {
      policyServer = app.listen(0, '127.0.0.1', () => resolve(policyServer.address().port));
      policyServer.on('error', reject);
    });
    const policyBase = `http://127.0.0.1:${policyPort}`;

    signerProc = spawn('node', [path.join(__dirname, '..', '..', 'src', 'signer', 'server.js')], {
      env: {
        ...process.env,
        APPROVAL_SECRET, OPERATOR_SECRET, MANDATE_FILE: mandateFile,
        SIGNER_TRUSTED_MANDATE_AUTHORITIES: OPERATOR_ADDR,
        SIGNER_PRIVATE_KEY: SIGNER_KEY, SIGNER_PORT: String(signerPort),
        SIGNER_CONSUMED_FILE: path.join(tmp, 'signer-consumed.jsonl'),
        POLICY_CALLBACK_URL: `${policyBase}/api/v1/internal/signer-callback`
      },
      stdio: ['ignore', 'ignore', 'pipe']
    });
    signerProc.on('error', () => {});
    const signerBase = `http://127.0.0.1:${signerPort}`;
    await waitFor(async () => {
      const h = await (await realFetch(`${signerBase}/health`)).json();
      return h && h.ok === true ? h : null;
    }, 30000, 'signer boot');

    const { AssertaraClient, createGuardedWallet, isCleanExecution, CODES } = require('../../sdk/index');
    const alpha = new AssertaraClient({ policyBase, signerBase, apiKey: `alpha:${ALPHA_SECRET}`, fetchImpl: realFetch });
    const beta = new AssertaraClient({ policyBase, signerBase, apiKey: `beta:${BETA_SECRET}`, fetchImpl: realFetch });
    const raw = async (method, p, { key, body } = {}) => {
      const res = await realFetch(`${policyBase}${p}`, {
        method,
        headers: {
          ...(key ? { Authorization: `Bearer ${key}` } : {}),
          ...(body !== undefined ? { 'content-type': 'application/json' } : {})
        },
        body: body !== undefined ? JSON.stringify(body) : undefined
      });
      return { status: res.status, body: await res.json().catch(() => ({})) };
    };
    const alphaKey = `alpha:${ALPHA_SECRET}`;

    // Test 1: connect + auth enforcement over real HTTP.
    {
      const conn = await alpha.connect();
      assert.strictEqual(conn.mandate.id, 'sdk-e2e-mandate');
      assert.strictEqual((await raw('GET', '/api/v1/agent/mandate')).status, 401, 'no key rejected');
      assert.strictEqual((await raw('GET', '/api/v1/agent/mandate', { key: `alpha:WRONG${ALPHA_SECRET.slice(5)}` })).status, 401, 'wrong secret rejected');
      assert.strictEqual((await raw('GET', '/api/v1/agent/mandate', { key: alphaKey })).status, 200, 'valid key admitted');
      console.log('✔ Test 1 Passed: connect() works; HTTP auth enforced (401 without a valid key).');
    }

    // Test 2: guarded ALLOW flow — submit, decide, sign, execute, verify receipt.
    let alphaRequestId = null;
    {
      const wallet = createGuardedWallet({ client: alpha, account: A0, chainId: 31337 });
      const out = await wallet.sendTransaction(
        { to: A1, value: '0x11c37937e08000' }, // 0.005 ETH
        { purpose: 'sdk e2e legitimate transfer', onProgress: () => {} }
      );
      alphaRequestId = out.requestId;
      assert.strictEqual(out.decision, 'ALLOW');
      assert.ok(/^0x[0-9a-fA-F]{64}$/.test(out.txHash), 'real tx hash');
      assert.strictEqual(isCleanExecution(out.execution), true, 'clean EXECUTED outcome');
      const receipt = await rpc(anvilRpc, 'eth_getTransactionReceipt', [out.txHash]);
      assert.strictEqual(receipt.status, '0x1', 'independent receipt check');
      assert.strictEqual(receipt.to.toLowerCase(), A1.toLowerCase());
      const onchain = await rpc(anvilRpc, 'eth_getTransactionByHash', [out.txHash]);
      assert.strictEqual(BigInt(onchain.value).toString(), BigInt('0x11c37937e08000').toString(), 'exact value landed');
      console.log('✔ Test 2 Passed: Guarded ALLOW executes with an independently verified receipt.');
    }

    // Test 3: genuine progress visibility — 202, INVESTIGATING stage, live SSE, then decision.
    {
      let release = null;
      gateModel = () => new Promise((r) => { release = r; });
      try {
        const inv = await alpha.submit({
          transaction: { from: A0, to: A1, value: '0x1000', data: '0x', chainId: '0x7a69' },
          purpose: 'sdk e2e progress probe'
        });
        assert.ok(/^agent_/.test(inv.requestId) && typeof inv.traceId === 'string', 'ids returned immediately');
        await waitFor(async () => {
          const st = await alpha.getStatus(inv.requestId);
          return st.progress && st.progress.museSpark && st.progress.museSpark.state === 'running' ? st : null;
        }, 15000, 'mid-run progress');
        const mid = await alpha.getStatus(inv.requestId);
        assert.strictEqual(mid.decision, null, 'no decision published mid-run');
        assert.ok(typeof mid.stage === 'string' && mid.stage.length > 0, 'real stage reported');
        const events = [];
        // ALLOW traces stay RUNNING (open for execution recording), so
        // the stream has no terminal event here: abort it once the live
        // progress assertions below have passed.
        const streamCtl = new AbortController();
        const streamDone = inv.stream((e) => { events.push(e); }, { signal: streamCtl.signal })
          .then(() => null, (e) => e);
        await waitFor(() => events.some((e) => e.type === 'span-start' && e.component === 'muse-spark'), 15000, 'live muse-spark span-start');
        release();
        gateModel = null;
        const decided = await inv.wait();
        assert.strictEqual(decided.decision, 'ALLOW', 'gated run still decides normally');
        await waitFor(() => events.some((e) => e.type === 'span-finish' && e.component === 'muse-spark'), 15000, 'live muse-spark span-finish');
        streamCtl.abort();
        await streamDone;
      } finally {
        if (release) release();
        gateModel = null;
      }
      console.log('✔ Test 3 Passed: 202 → live stage/SSE progress → published decision.');
    }

    // Test 4: BLOCK leaves the chain untouched and never signs.
    {
      const before = await rpc(anvilRpc, 'eth_blockNumber', []);
      const wallet = createGuardedWallet({ client: alpha, account: A0, chainId: 31337 });
      const err = await wallet.sendTransaction({ to: STRANGER, value: '0x1000' }, { purpose: 'denied recipient' })
        .then(() => null, (e) => e);
      assert.ok(err && err.code === CODES.NOT_EXECUTABLE, 'BLOCK refused as NOT_EXECUTABLE');
      assert.strictEqual(err.detail.decision, 'BLOCK');
      assert.strictEqual(await rpc(anvilRpc, 'eth_blockNumber', []), before, 'chain untouched');
      console.log('✔ Test 4 Passed: BLOCK throws before signing; chain untouched.');
    }

    // Test 5: UNCERTAIN never executes.
    {
      const wallet = createGuardedWallet({ client: alpha, account: A0, chainId: 31337 });
      const err = await wallet.sendTransaction(
        { to: UNKNOWN, value: '0x0', data: `0xdeadbeef${'11'.repeat(32)}` },
        { purpose: 'unknown contract probe' }
      ).then(() => null, (e) => e);
      assert.ok(err && err.code === CODES.NOT_EXECUTABLE, 'UNCERTAIN refused');
      assert.strictEqual(err.detail.decision, 'UNCERTAIN');
      console.log('✔ Test 5 Passed: UNCERTAIN never executes.');
    }

    // Test 6: REVIEW holds, releases once via operator, executes once (no double-spend).
    {
      const wallet = createGuardedWallet({ client: alpha, account: A0, chainId: 31337 });
      const tx = { to: A1, value: '0x470de4df820000' }; // 0.02 ETH > 0.01 review line
      const inv = await alpha.submit({ transaction: { from: A0, ...tx, data: '0x', chainId: '0x7a69' }, purpose: 'review then release' });
      const decided = await inv.wait();
      assert.strictEqual(decided.decision, 'REVIEW');
      const early = await alpha.execute({ requestId: inv.requestId, transaction: { from: A0, ...tx, data: '0x', chainId: '0x7a69' } })
        .then(() => null, (e) => e);
      assert.ok(early && early.code === CODES.NOT_EXECUTABLE, 'pre-release execute refused');
      // Operator stand-in (test-only): the SDK never sees this secret.
      const auth = await raw('POST', `/api/v1/agent/requests/${inv.requestId}/authorize`, {
        key: alphaKey, body: { operatorSecret: OPERATOR_SECRET }
      });
      assert.strictEqual(auth.status, 200, JSON.stringify(auth.body));
      assert.strictEqual(auth.body.authorized, true);
      const released = await alpha.waitForOperatorApproval(inv.requestId, { timeoutMs: 15000 });
      assert.ok(released.approvalToken, 'token appears after release');
      const signed = await inv.execute({ from: A0, ...tx, data: '0x', chainId: '0x7a69' });
      assert.ok(/^0x[0-9a-fA-F]{64}$/.test(signed.txHash));
      const execution = await inv.waitForExecution({ timeoutMs: 30000 });
      assert.strictEqual(isCleanExecution(execution), true);
      const again = await inv.execute({ from: A0, ...tx, data: '0x', chainId: '0x7a69' }).then(() => null, (e) => e);
      assert.ok(again && again.code === CODES.AUTH, 'second execute refused by single-use');
      assert.ok(/consumed/.test(again.message), 'refusal names consumption');
      void wallet;
      console.log('✔ Test 6 Passed: REVIEW holds → releases once → executes once (replay refused).');
    }

    // Test 7: sync propose stays backward compatible over HTTP.
    {
      const res = await raw('POST', '/api/v1/agent/propose', {
        key: alphaKey,
        body: { agentId: 'sdk-e2e', intent: { purpose: 'compat probe' }, transaction: { from: A0, to: A1, value: '0x1000', data: '0x', chainId: '0x7a69' } }
      });
      assert.strictEqual(res.status, 200, JSON.stringify(res.body));
      for (const k of ['requestId', 'traceId', 'decision', 'reasons', 'txDigest', 'mandate', 'policyId', 'approval',
        'operatorAuthorizationRequired', 'operatorAvailable', 'investigation', 'mandateChecks', 'visual', 'createdAt']) {
        assert.ok(k in res.body, `propose keeps field ${k}`);
      }
      assert.deepStrictEqual(Object.keys(res.body.investigation).sort(),
        ['evalId', 'verdict', 'reasoningOrigin', 'ruleFindings', 'safeguardTriggers'].sort());
      console.log('✔ Test 7 Passed: Sync propose response contract unchanged.');
    }

    // Test 8: idempotent replay + evidence envelope over HTTP.
    {
      const post = async (headers) => {
        const res = await realFetch(`${policyBase}/api/v1/agent/investigations`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${alphaKey}`, 'content-type': 'application/json', ...headers },
          body: JSON.stringify({ transaction: { from: A0, to: A1, value: '0x1000', data: '0x', chainId: '0x7a69' }, intent: { purpose: 'idem http' } })
        });
        return { status: res.status, replayed: res.headers.get('idempotent-replayed'), body: await res.json() };
      };
      const first = await post({ 'Idempotency-Key': 'sdk-e2e-idem-8' });
      assert.strictEqual(first.status, 202);
      const fin = await alpha.waitForDecision(first.body.requestId, { timeoutMs: 60000 });
      assert.strictEqual(fin.decision, 'ALLOW');
      const second = await post({ 'Idempotency-Key': 'sdk-e2e-idem-8' });
      assert.strictEqual(second.status, 200, JSON.stringify(second.body));
      assert.strictEqual(second.replayed, 'true');
      assert.strictEqual(second.body.requestId, first.body.requestId);
      assert.strictEqual(second.body.decision, 'ALLOW');
      const ev = await alpha.getEvidence(first.body.requestId);
      assert.strictEqual(ev.v, 1);
      assert.strictEqual(ev.decision, 'ALLOW');
      assert.ok(ev.mandateChecks.length > 0 && ev.reasons.length > 0);
      console.log('✔ Test 8 Passed: HTTP idempotency replay + evidence envelope exact.');
    }

    // Test 9: ownership isolation across integrations (keys + traces).
    {
      const other = await beta.submit({
        transaction: { from: A0, to: A1, value: '0x1000', data: '0x', chainId: '0x7a69' },
        purpose: 'beta request'
      });
      await beta.waitForDecision(other.requestId, { timeoutMs: 60000 });
      assert.strictEqual((await raw('GET', `/api/v1/agent/requests/${other.requestId}`, { key: alphaKey })).status, 404, 'alpha cannot read beta request');
      assert.strictEqual((await raw('GET', `/api/v1/agent/requests/${alphaRequestId}`, { key: `beta:${BETA_SECRET}` })).status, 404, 'beta cannot read alpha request');
      const traces = await raw('GET', '/api/v1/observations/traces', { key: alphaKey });
      assert.strictEqual(traces.status, 200);
      const ids = traces.body.traces.map((t) => t.requestId);
      assert.ok(ids.includes(alphaRequestId), 'own trace listed');
      assert.ok(!ids.includes(other.requestId), 'foreign trace excluded');
      assert.strictEqual((await raw('GET', `/api/v1/observations/traces/${other.traceId}`, { key: alphaKey })).status, 404, 'foreign trace snapshot denied');
      console.log('✔ Test 9 Passed: Per-integration isolation on requests and traces.');
    }

    // Test 10: concurrent async runs complete independently.
    {
      const [a, b] = await Promise.all([
        alpha.submit({ transaction: { from: A0, to: A1, value: '0x1000', data: '0x', chainId: '0x7a69' }, purpose: 'race a' }),
        alpha.submit({ transaction: { from: A0, to: A1, value: '0x1001', data: '0x', chainId: '0x7a69' }, purpose: 'race b' })
      ]);
      assert.notStrictEqual(a.requestId, b.requestId);
      const [ra, rb] = await Promise.all([a.wait({ timeoutMs: 60000 }), b.wait({ timeoutMs: 60000 })]);
      assert.strictEqual(ra.decision, 'ALLOW');
      assert.strictEqual(rb.decision, 'ALLOW');
      console.log('✔ Test 10 Passed: Concurrent investigations complete independently.');
    }
  } finally {
    global.fetch = realFetch;
    killAll();
    await new Promise((r) => setTimeout(r, 500));
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
  console.log('\nAll SDK flow tests passed.');
}

if (require.main === module) {
  runSdkFlowTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSdkFlowTests };
