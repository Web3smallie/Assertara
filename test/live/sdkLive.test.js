const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

// LIVE SDK validation (gated): one legitimate scenario through the real
// SDK against a real stack with a genuine Muse Spark investigation —
// async submit, live SSE progress observed BEFORE the decision,
// guarded execution, independently verified receipt.
// Gated: runs only with LIVE_MODEL_TESTS=1 and a real MODEL_API_KEY.
// Otherwise skips with exit 0 and makes no model calls.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const ANVIL_MNEMONIC = 'test test test test test test test test test test test junk';

function liveEnabled() {
  if (process.env.LIVE_MODEL_TESTS !== '1') return { ok: false, reason: 'LIVE_MODEL_TESTS!=1' };
  const config = require('../../src/config/env');
  const key = config.modelApiKey || '';
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) {
    return { ok: false, reason: 'no real MODEL_API_KEY configured' };
  }
  return { ok: true };
}

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
    await new Promise((r) => setTimeout(r, 500));
  }
}

async function runSdkLiveTests() {
  const gate = liveEnabled();
  if (!gate.ok) {
    console.log(`SKIP: live SDK test disabled (${gate.reason}). No network calls made.`);
    return;
  }
  console.log('LIVE test: genuine SDK flow with a real Muse Spark investigation...\n');

  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'sdk-live-'));

  const APPROVAL_SECRET = crypto.randomBytes(32).toString('hex');
  const OPERATOR_SECRET = crypto.randomBytes(32).toString('hex');
  const ALPHA_SECRET = crypto.randomBytes(32).toString('hex');

  const { mnemonicToAccount, generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
  const anvilAccount = mnemonicToAccount(ANVIL_MNEMONIC);
  assert.strictEqual(anvilAccount.address.toLowerCase(), A0.toLowerCase());
  const SIGNER_KEY = `0x${Buffer.from(anvilAccount.getHdKey().privateKey).toString('hex')}`;
  const OPERATOR_KEY = generatePrivateKey();
  const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address;

  const anvilPort = await freePort();
  const signerPort = await freePort();
  const anvilRpc = `http://127.0.0.1:${anvilPort}`;
  const mandateFile = path.join(tmp, 'mandate.json');
  fs.writeFileSync(mandateFile, JSON.stringify({
    id: 'sdk-live-mandate', version: 1, issuer: 'sdk-live-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: A0, senders: [A0],
    chains: [{ id: 31337, rpcUrl: anvilRpc, name: 'anvil-sdk-live' }],
    recipients: { allow: [A1], deny: [] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true, maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [], reviewRules: []
  }), 'utf8');
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

  try {
    await waitFor(async () => (await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69', 30000, 'anvil boot');
    process.env.MANDATE_FILE = mandateFile;
    process.env.APPROVAL_SECRET = APPROVAL_SECRET;
    process.env.OPERATOR_SECRET = OPERATOR_SECRET;
    process.env.TRUSTED_MANDATE_AUTHORITIES = OPERATOR_ADDR;
    process.env.AGENT_API_KEYS = `alpha:${ALPHA_SECRET}`;
    delete process.env.AGENT_AUTH_MODE;
    process.env.AGENT_LEDGER_FILE = path.join(tmp, 'agent-ledger.jsonl');
    process.env.SPENDING_LEDGER_FILE = path.join(tmp, 'agent-spending.jsonl');
    process.env.AGENT_SNAPSHOT_FILE = path.join(tmp, 'agent-requests.json');
    process.env.INVESTIGATIONS_FILE = path.join(tmp, 'investigations.jsonl');
    const appConfig = require('../../src/config/env');
    console.log(`model: LIVE ${appConfig.museModel} (no fetch stubs anywhere in this run)`);
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
      const h = await (await fetch(`${signerBase}/health`)).json();
      return h && h.ok === true ? h : null;
    }, 30000, 'signer boot');

    const { AssertaraClient, isCleanExecution } = require('../../sdk/index');
    const client = new AssertaraClient({ policyBase, signerBase, apiKey: `alpha:${ALPHA_SECRET}` });
    await client.connect();

    // Submit first so the trace exists, then stream live events while
    // the genuine model works; the span-start MUST arrive before wait().
    const tx = { from: A0, to: A1, value: '0x11c37937e08000', data: '0x', chainId: '0x7a69' };
    const inv = await client.submit({ transaction: tx, purpose: 'sdk live legitimate transfer' });
    console.log(`submitted: requestId=${inv.requestId} traceId=${inv.traceId}`);
    const events = [];
    let sawModelStart = false;
    // ALLOW traces stay RUNNING (open for execution recording), so the
    // stream has no terminal event: abort it once the live progress
    // assertions below have passed.
    const streamCtl = new AbortController();
    const streaming = inv.stream((e) => {
      events.push(e);
      if (e.type === 'span-start' && e.component === 'muse-spark') sawModelStart = true;
    }, { signal: streamCtl.signal }).then(() => null, (e) => e);
    const decided = await inv.wait({ timeoutMs: 240000 });
    assert.strictEqual(sawModelStart, true, 'genuine muse-spark span-start observed BEFORE the decision');
    assert.strictEqual(decided.decision, 'ALLOW', `live legitimate transfer allows (got ${decided.decision})`);
    assert.strictEqual(decided.investigation.reasoningOrigin, 'model', 'genuine model origin, not fallback');
    await waitFor(() => events.find((e) => e.type === 'span-finish' && e.component === 'muse-spark'), 60000, 'live muse-spark span-finish');
    streamCtl.abort();
    await streaming;
    const finish = events.find((e) => e.type === 'span-finish' && e.component === 'muse-spark');
    assert.ok(finish && finish.status === 'COMPLETED', 'live span-finish COMPLETED observed');
    console.log(`investigation: verdict=${decided.investigation.verdict} origin=model modelMs=${finish.durationMs}`);

    const signed = await inv.execute(tx);
    assert.ok(/^0x[0-9a-fA-F]{64}$/.test(signed.txHash), 'real tx hash from controlled signer');
    const execution = await inv.waitForExecution({ timeoutMs: 60000 });
    assert.strictEqual(isCleanExecution(execution), true, 'clean EXECUTED outcome');
    const receipt = await rpc(anvilRpc, 'eth_getTransactionReceipt', [signed.txHash]);
    assert.strictEqual(receipt.status, '0x1', 'independent receipt check');
    console.log(`executed: txHash=${signed.txHash} block=${receipt.blockNumber} outcome=${execution.outcome}`);
  } finally {
    killAll();
    await new Promise((r) => setTimeout(r, 500));
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
  console.log('\nLive SDK validation passed.');
}

if (require.main === module) {
  runSdkLiveTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSdkLiveTests };
