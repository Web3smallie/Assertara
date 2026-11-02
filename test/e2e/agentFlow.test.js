const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

// End-to-end agent execution: REAL policy app (HTTP), REAL signer
// process, REAL Anvil chain. The ONLY mock is the model transport
// (canned MATCH/UNCERTAIN verdicts, labeled MOCK below): every
// security property under test — mandate enforcement, digest
// binding, approval single-use, operator gating, broadcast, receipt
// verification — runs against genuine components and a live chain.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
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
    } catch {
      /* keep waiting */
    }
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function runAgentFlowTests() {
  console.log('Testing agent execution end-to-end (app + signer + Anvil; MOCK model)...\n');

  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'e2e-'));
  let failed = false;

  const APPROVAL_SECRET = crypto.randomBytes(32).toString('hex');
  const OPERATOR_SECRET = crypto.randomBytes(32).toString('hex');

  // Signer key: derived from Anvil's documented default mnemonic (never
  // hardcoded); the address assertion below fails loudly on drift.
  const { mnemonicToAccount } = require('viem/accounts');
  const anvilAccount = mnemonicToAccount(ANVIL_MNEMONIC);
  assert.strictEqual(anvilAccount.address.toLowerCase(), A0.toLowerCase(), 'derived key must be Anvil account[0]');
  const SIGNER_KEY = `0x${Buffer.from(anvilAccount.getHdKey().privateKey).toString('hex')}`;
  assert.ok(/^0x[0-9a-fA-F]{64}$/.test(SIGNER_KEY), 'derived key well-formed');

  const anvilPort = await freePort();
  const signerPort = await freePort();
  const anvilRpc = `http://127.0.0.1:${anvilPort}`;

  const mandateSrc = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'agent-mandate.json'), 'utf8'));
  mandateSrc.chains[0].rpcUrl = anvilRpc;
  const mandateFile = path.join(tmp, 'mandate.json');
  fs.writeFileSync(mandateFile, JSON.stringify(mandateSrc), 'utf8');
  // Operator sealing ceremony (test-only key): both services boot from
  // this sealed file and trust only its authority.
  const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
  const { sealMandateFile } = require('../../src/signer/signMandate');
  const OPERATOR_KEY = generatePrivateKey();
  const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address;
  await sealMandateFile(mandateFile, OPERATOR_KEY);

  // Boot Anvil (explicit Foundry path first: CI shells may not inherit it).
  const anvilCandidates = [
    process.env.ANVIL_BIN,
    path.join(os.homedir(), '.foundry', 'bin', process.platform === 'win32' ? 'anvil.exe' : 'anvil'),
    'anvil'
  ].filter(Boolean);
  const anvilBin = anvilCandidates.find((c) => { try { return fs.existsSync(c); } catch { return false; } }) || 'anvil';
  let anvil;
  try {
    anvil = spawn(anvilBin, ['--port', String(anvilPort)], { stdio: ['ignore', 'ignore', 'pipe'] });
  } catch (err) {
    throw new Error(`cannot spawn anvil (required for e2e): ${err.message}`);
  }
  let anvilStderr = '';
  if (anvil.stderr) anvil.stderr.on('data', (d) => { anvilStderr += String(d).slice(-2000); });
  anvil.on('error', () => {});
  const killAll = [];
  killAll.push(() => { try { anvil.kill('SIGKILL'); } catch {} });

  // Model transport stub (MOCK): canned verdicts, real-fetch passthrough.
  const realFetch = global.fetch;
  let cannedVerdict = 'MATCH';
  const canned = (verdict) => ({
    ok: true,
    json: async () => ({ choices: [{ message: { content: JSON.stringify({
      verdict, confidence: 0.95, summary: `e2e MOCK ${verdict}`,
      discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
    }) } }] })
  });

  let policyServer = null;
  let signerProc = null;
  killAll.push(() => { try { if (signerProc) signerProc.kill('SIGKILL'); } catch {} });
  killAll.push(() => { try { if (policyServer) policyServer.close(); } catch {} });

  try {
    await waitFor(async () => (await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69', 30000, 'anvil boot');
    console.log(`  anvil up on ${anvilPort} (chain 31337)`);

    // Policy app in-process (env set BEFORE require: config reads at load).
    process.env.MANDATE_FILE = mandateFile;
    process.env.APPROVAL_SECRET = APPROVAL_SECRET;
    process.env.OPERATOR_SECRET = OPERATOR_SECRET;
    process.env.TRUSTED_MANDATE_AUTHORITIES = OPERATOR_ADDR;
    process.env.AGENT_LEDGER_FILE = path.join(tmp, 'agent-ledger.jsonl');
    process.env.SPENDING_LEDGER_FILE = path.join(tmp, 'agent-spending.jsonl');
    process.env.AGENT_SNAPSHOT_FILE = path.join(tmp, 'agent-requests.json');
    process.env.AGENT_AUTH_MODE = 'development';
    process.env.MODEL_API_KEY = 'e2e-test-key';
    const appConfig = require('../../src/config/env');
    global.fetch = async (url, opts) => {
      if (typeof url === 'string' && url.startsWith(appConfig.metaApiBaseUrl)) return canned(cannedVerdict);
      return realFetch(url, opts);
    };
    const app = require('../../src/server.js');
    const policyPort = await new Promise((resolve, reject) => {
      policyServer = app.listen(0, '127.0.0.1', () => resolve(policyServer.address().port));
      policyServer.on('error', reject);
    });
    const policyBase = `http://127.0.0.1:${policyPort}`;
    console.log(`  policy app up on ${policyPort}`);

    // Signer as a SEPARATE OS process with its own secrets.
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
    let signerStderr = '';
    if (signerProc.stderr) signerProc.stderr.on('data', (d) => { signerStderr += String(d).slice(-2000); });
    signerProc.on('error', () => {});
    const signerBase = `http://127.0.0.1:${signerPort}`;
    await waitFor(async () => {
      const h = await (await fetch(`${signerBase}/health`)).json();
      return h && h.ok === true && h.address.toLowerCase() === A0.toLowerCase() && h.mandateVersion === 1 ? h : null;
    }, 30000, 'signer boot').catch((err) => { throw new Error(`${err.message}. signer stderr: ${signerStderr}`); });
    console.log(`  signer up on ${signerPort} (separate process)`);

    const post = async (url, body, status) => {
      const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
      const json = await res.json().catch(() => ({}));
      assert.strictEqual(res.status, status === undefined ? 200 : status, `POST ${url} -> ${res.status}: ${JSON.stringify(json).slice(0, 300)}`);
      return json;
    };
    const get = async (url, status) => {
      const res = await fetch(url);
      const json = await res.json().catch(() => ({}));
      assert.strictEqual(res.status, status === undefined ? 200 : status, `GET ${url} -> ${res.status}`);
      return json;
    };
    const propose = (transaction, intent) => post(`${policyBase}/api/v1/agent/propose`,
      { agentId: 'e2e-agent', intent: { purpose: intent || 'e2e test transfer' }, transaction });
    const tx = (overrides) => ({ from: A0, to: A1, data: '0x', value: '0x11c37937e0800', chainId: '0x7a69', ...(overrides || {}) }); // 0.005 ETH = 5e15 wei
    const signerHealth = () => get(`${signerBase}/health`);

    // Sanity: mandate metadata visible, no secrets.
    const meta = await get(`${policyBase}/api/v1/agent/mandate`);
    assert.strictEqual(meta.configured, true);
    assert.strictEqual(meta.version, 1);
    assert.ok(!JSON.stringify(meta).includes(APPROVAL_SECRET.slice(0, 8)), 'no secrets in metadata');

    // Scenario B — prohibited action (model says MATCH; mandate blocks).
    {
      const blockBefore = await rpc(anvilRpc, 'eth_blockNumber', []);
      const out = await propose(tx({ to: A0 }), 'pay self (not allowlisted)');
      assert.strictEqual(out.decision, 'BLOCK', 'non-allowlisted recipient blocks despite model MATCH');
      assert.strictEqual(out.approval, null, 'BLOCK issues no token');
      const r1 = await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: tx({ to: A0 }), approval: 'forged.token.here' }, 403);
      assert.ok(/invalid|forged|approval/i.test(r1.error), 'forged approval refused');
      await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: tx({ to: A0 }) }, 403);
      assert.strictEqual(await rpc(anvilRpc, 'eth_blockNumber', []), blockBefore, 'no broadcast for blocked action');
      assert.strictEqual((await signerHealth()).consumedApprovals, 0, 'zero approvals consumed');
      console.log('✔ Scenario B Passed: Prohibited action blocked, signer refused, chain untouched.');
    }

    // Scenario D — investigation inconclusive (MOCK UNCERTAIN): no execution.
    {
      cannedVerdict = 'UNCERTAIN';
      try {
        const out = await propose(tx(), 'inconclusive investigation');
        assert.strictEqual(out.decision, 'UNCERTAIN');
        assert.strictEqual(out.approval, null, 'UNCERTAIN issues no token');
        await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: tx(), approval: 'apv1.e30.evil' }, 403);
      } finally {
        cannedVerdict = 'MATCH';
      }
      console.log('✔ Scenario D Passed: Uncertain action held, no execution.');
    }

    // Scenario A — permitted action executes on Anvil with a real receipt.
    let hashA;
    {
      const out = await propose(tx(), 'pay contributor 0.005 ETH');
      assert.strictEqual(out.decision, 'ALLOW');
      assert.ok(out.approval, 'ALLOW issues a token');
      const signed = await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: tx(), approval: out.approval });
      assert.strictEqual(signed.ok, true, JSON.stringify(signed.error || 'signed'));
      hashA = signed.txHash;
      assert.ok(/^0x[0-9a-fA-F]{64}$/.test(hashA), 'real tx hash returned');
      assert.strictEqual(signed.verification.balanceDeltaOk, true, 'recipient balance delta verified on-chain');
      const st = await waitFor(async () => {
        const s = await get(`${policyBase}/api/v1/agent/requests/${out.requestId}`);
        return s.execution && s.execution.outcome ? s : null;
      }, 15000, 'execution record (signer callback)');
      assert.strictEqual(st.execution.outcome, 'EXECUTED');
      assert.strictEqual(st.execution.receiptStatus, '0x1');
      assert.strictEqual(st.execution.txHash, hashA);
      const receipt = await rpc(anvilRpc, 'eth_getTransactionReceipt', [hashA]);
      assert.strictEqual(receipt.status, '0x1', 'independent receipt check');
      assert.strictEqual(receipt.to.toLowerCase(), A1.toLowerCase());
      console.log(`✔ Scenario A Passed: EXECUTED on Anvil. REAL_TX_A=${hashA} status=0x1 block=${receipt.blockNumber}`);
    }

    // Scenario C — approved action mutated before signing: refused, then original executes.
    let hashC;
    {
      const out = await propose(tx(), 'mutation target 0.005 ETH');
      assert.strictEqual(out.decision, 'ALLOW');
      const consumedBefore = (await signerHealth()).consumedApprovals;
      const mutated = tx({ value: '0x11c37937e0801' }); // +1 wei
      const refused = await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: mutated, approval: out.approval }, 403);
      assert.ok(/digest/.test(refused.error), 'digest mismatch named');
      assert.strictEqual((await signerHealth()).consumedApprovals, consumedBefore, 'refused attempt consumes nothing');
      const signed = await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: tx(), approval: out.approval });
      assert.strictEqual(signed.ok, true, 'original payload still executes after refused mutation');
      hashC = signed.txHash;
      const replay = await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: tx(), approval: out.approval }, 403);
      assert.ok(/already consumed/.test(replay.error), 'approval single-use enforced');
      console.log(`✔ Scenario C Passed: Mutation refused, original executed. REAL_TX_C=${hashC}`);
    }

    // Scenario E — operator authorization gates above-threshold value.
    let hashE;
    {
      const big = tx({ value: '0x470de4df820000' }); // 0.02 ETH > 0.01 review threshold
      const out = await propose(big, 'above-threshold payout');
      assert.strictEqual(out.decision, 'REVIEW');
      assert.strictEqual(out.approval, null);
      assert.strictEqual(out.operatorAuthorizationRequired, true);
      await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: big }, 403);
      const wrong = await post(`${policyBase}/api/v1/agent/requests/${out.requestId}/authorize`, { operatorSecret: 'wrong' }, 403);
      assert.ok(/authentication failed/.test(wrong.error));
      const auth = await post(`${policyBase}/api/v1/agent/requests/${out.requestId}/authorize`, { operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(auth.authorized, true);
      assert.ok(auth.approval, 'operator mints the token');
      const signed = await post(`${signerBase}/sign`, { requestId: out.requestId, transaction: big, approval: auth.approval });
      assert.strictEqual(signed.ok, true);
      hashE = signed.txHash;
      // Backup path: agent reports the same receipt directly (idempotent).
      await waitFor(async () => {
        const s = await get(`${policyBase}/api/v1/agent/requests/${out.requestId}`);
        return s.execution && s.execution.outcome ? s : null;
      }, 15000, 'execution record');
      const dup = await post(`${policyBase}/api/v1/agent/requests/${out.requestId}/receipts`, { txHash: hashE });
      assert.strictEqual(dup.duplicate, true, 'receipt reporting idempotent');
      assert.strictEqual(dup.execution.outcome, 'EXECUTED');
      console.log(`✔ Scenario E Passed: REVIEW held, operator released, executed. REAL_TX_E=${hashE}`);
    }

    console.log('\nAll Agent E2E Scenarios Passed Successfully!\n');
  } catch (err) {
    failed = true;
    throw err;
  } finally {
    global.fetch = realFetch;
    for (const kill of killAll) kill();
    await new Promise((r) => setTimeout(r, 500));
    if (!failed) {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    } else {
      console.log(`e2e artifacts preserved at: ${tmp}`);
    }
  }
}

if (require.main === module) {
  runAgentFlowTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentFlowTests };
