const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

// B7 post-execution verification e2e: REAL policy app (HTTP), REAL
// signer process, REAL Anvil chain, REAL compiled ERC-20 contracts
// (forge-built from test/e2e/contracts/Token.sol). The ONLY mock is
// the model transport (canned MATCH, labeled MOCK): receipt logs,
// effect reconciliation, and execution outcomes are all genuine.

const A0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const A1 = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const A2 = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
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

function foundryBin(name) {
  const exe = process.platform === 'win32' ? `${name}.exe` : name;
  const candidates = [
    process.env[name.toUpperCase() + '_BIN'],
    path.join(os.homedir(), '.foundry', 'bin', exe),
    name
  ].filter(Boolean);
  return candidates.find((c) => { try { return fs.existsSync(c); } catch { return false; } }) || name;
}

async function runEffectVerificationTests() {
  console.log('Testing B7 post-execution verification e2e (real Anvil + real ERC-20; MOCK model)...\n');

  const tmpBase = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(tmpBase, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(tmpBase, 'e2e-b7-'));
  let failed = false;

  const APPROVAL_SECRET = crypto.randomBytes(32).toString('hex');
  const OPERATOR_SECRET = crypto.randomBytes(32).toString('hex');

  const { mnemonicToAccount } = require('viem/accounts');
  const anvilAccount = mnemonicToAccount(ANVIL_MNEMONIC);
  assert.strictEqual(anvilAccount.address.toLowerCase(), A0.toLowerCase(), 'derived key must be Anvil account[0]');
  const SIGNER_KEY = `0x${Buffer.from(anvilAccount.getHdKey().privateKey).toString('hex')}`;

  const anvilPort = await freePort();
  const signerPort = await freePort();
  const anvilRpc = `http://127.0.0.1:${anvilPort}`;
  const killAll = [];

  const anvil = spawn(foundryBin('anvil'), ['--port', String(anvilPort)], { stdio: ['ignore', 'ignore', 'pipe'] });
  let anvilStderr = '';
  if (anvil.stderr) anvil.stderr.on('data', (d) => { anvilStderr += String(d).slice(-2000); });
  anvil.on('error', () => {});
  killAll.push(() => { try { anvil.kill('SIGKILL'); } catch {} });

  const realFetch = global.fetch;
  let policyServer = null;
  let signerProc = null;
  killAll.push(() => { try { if (signerProc) signerProc.kill('SIGKILL'); } catch {} });
  killAll.push(() => { try { if (policyServer) policyServer.close(); } catch {} });

  try {
    await waitFor(async () => (await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69', 30000, 'anvil boot')
      .catch((err) => { throw new Error(`${err.message}. anvil stderr: ${anvilStderr}`); });
    console.log(`  anvil up on ${anvilPort} (chain 31337)`);

    // Compile the real ERC-20 fixtures with forge (fails loudly when
    // the toolchain is unavailable: no bytecode is ever hand-made).
    const forgeDir = path.join(tmp, 'forge');
    fs.mkdirSync(path.join(forgeDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(forgeDir, 'foundry.toml'), "[profile.default]\nsrc = 'src'\nout = 'out'\n", 'utf8');
    fs.copyFileSync(path.join(__dirname, 'contracts', 'Token.sol'), path.join(forgeDir, 'src', 'Token.sol'));
    try {
      execFileSync(foundryBin('forge'), ['build', '--root', forgeDir], { stdio: 'pipe', timeout: 180000 });
    } catch (err) {
      throw new Error(`forge build failed (required for B7 e2e): ${(err.stderr || err.message || '').toString().slice(0, 500)}`);
    }
    const readArtifact = (name) => {
      const art = JSON.parse(fs.readFileSync(path.join(forgeDir, 'out', 'Token.sol', `${name}.json`), 'utf8'));
      assert.ok(art.bytecode && art.bytecode.object && art.bytecode.object.length > 100, `${name} bytecode present`);
      return art;
    };
    const testTokenArt = readArtifact('TestToken');
    const feeTokenArt = readArtifact('FeeToken');
    console.log('  forge compiled TestToken + FeeToken');

    // Deploy both tokens from Anvil account[0] (unlocked).
    const { encodeDeployData, encodeFunctionData, parseAbi } = require('viem');
    const deploy = async (artifact, args) => {
      const data = encodeDeployData({ abi: artifact.abi, bytecode: artifact.bytecode.object, args: args || [] });
      const hash = await rpc(anvilRpc, 'eth_sendTransaction', [{ from: A0, data }]);
      const receipt = await waitFor(async () => rpc(anvilRpc, 'eth_getTransactionReceipt', [hash]), 15000, 'deploy receipt');
      assert.strictEqual(receipt.status, '0x1', 'deploy succeeds');
      assert.ok(/^0x[0-9a-fA-F]{40}$/.test(receipt.contractAddress), 'contract address returned');
      return receipt.contractAddress;
    };
    const TOKEN = await deploy(testTokenArt);
    const FEE = await deploy(feeTokenArt, [A2]);
    console.log(`  deployed TestToken=${TOKEN} FeeToken=${FEE}`);

    // Mandate allowlists both token contracts + transfer/approve selectors.
    const mandateSrc = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'agent-mandate.json'), 'utf8'));
    mandateSrc.chains[0].rpcUrl = anvilRpc;
    mandateSrc.recipients.allow.push(TOKEN, FEE);
    mandateSrc.contracts.allow.push(TOKEN, FEE);
    mandateSrc.selectors.allow.push('0xa9059cbb', '0x095ea7b3');
    mandateSrc.approvals.spenderAllowlist.push(A1);
    const mandateFile = path.join(tmp, 'mandate.json');
    fs.writeFileSync(mandateFile, JSON.stringify(mandateSrc), 'utf8');
    const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
    const { sealMandateFile } = require('../../src/signer/signMandate');
    const OPERATOR_KEY = generatePrivateKey();
    const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address;
    await sealMandateFile(mandateFile, OPERATOR_KEY);

    // Policy app in-process.
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
    const canned = {
      ok: true,
      json: async () => ({ choices: [{ message: { content: JSON.stringify({
        verdict: 'MATCH', confidence: 0.95, summary: 'e2e MOCK MATCH',
        discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION'
      }) } }] })
    };
    global.fetch = async (url, opts) => {
      if (typeof url === 'string' && url.startsWith(appConfig.metaApiBaseUrl)) return canned;
      return realFetch(url, opts);
    };
    const app = require('../../src/server.js');
    const policyPort = await new Promise((resolve, reject) => {
      policyServer = app.listen(0, '127.0.0.1', () => resolve(policyServer.address().port));
      policyServer.on('error', reject);
    });
    const policyBase = `http://127.0.0.1:${policyPort}`;
    console.log(`  policy app up on ${policyPort}`);

    // Signer as a separate OS process.
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
      return h && h.ok === true && h.address.toLowerCase() === A0.toLowerCase() ? h : null;
    }, 30000, 'signer boot').catch((err) => { throw new Error(`${err.message}. signer stderr: ${signerStderr}`); });
    console.log(`  signer up on ${signerPort} (separate process)`);

    const post = async (url, body, status) => {
      const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
      const json = await res.json().catch(() => ({}));
      assert.strictEqual(res.status, status === undefined ? 200 : status, `POST ${url} -> ${res.status}: ${JSON.stringify(json).slice(0, 400)}`);
      return json;
    };
    const get = async (url, status) => {
      const res = await fetch(url);
      const json = await res.json().catch(() => ({}));
      assert.strictEqual(res.status, status === undefined ? 200 : status, `GET ${url} -> ${res.status}`);
      return json;
    };
    const ERC20 = parseAbi(['function transfer(address to, uint256 value)', 'function approve(address spender, uint256 value)']);
    const transferData = (to, v) => encodeFunctionData({ abi: ERC20, functionName: 'transfer', args: [to, v] });
    const approveData = (s, v) => encodeFunctionData({ abi: ERC20, functionName: 'approve', args: [s, v] });
    const waitExecution = (requestId) => waitFor(async () => {
      const s = await get(`${policyBase}/api/v1/agent/requests/${requestId}`);
      return s.execution && s.execution.outcome ? s : null;
    }, 20000, 'execution record');

    // B7-E1: plain transfer reconciles EFFECTS_MATCHED on a real receipt.
    {
      const out = await post(`${policyBase}/api/v1/agent/propose`, {
        agentId: 'e2e-b7', intent: { purpose: 'pay 100 TT' },
        transaction: { from: A0, to: TOKEN, data: transferData(A1, 100n), value: '0x0', chainId: '0x7a69' }
      });
      assert.strictEqual(out.decision, 'ALLOW', JSON.stringify(out).slice(0, 500));
      const signed = await post(`${signerBase}/sign`, {
        requestId: out.requestId,
        transaction: { from: A0, to: TOKEN, data: transferData(A1, 100n), value: '0x0', chainId: '0x7a69' },
        approval: out.approval
      });
      assert.strictEqual(signed.ok, true, JSON.stringify(signed.error || 'signed'));
      const st = await waitExecution(out.requestId);
      assert.strictEqual(st.execution.outcome, 'EXECUTED');
      assert.strictEqual(st.execution.verification.effects, 'EFFECTS_MATCHED');
      const receipt = await rpc(anvilRpc, 'eth_getTransactionReceipt', [signed.txHash]);
      assert.strictEqual(receipt.logs.length, 1, 'independent log count check');
      assert.strictEqual(BigInt(receipt.logs[0].data).toString(), '100');
      console.log(`✔ B7-E1 Passed: real transfer MATCHED. REAL_TX=${signed.txHash}`);
    }

    // B7-E2: fee-token shortfall reconciles EFFECTS_DIVERGED (genuine).
    {
      const out = await post(`${policyBase}/api/v1/agent/propose`, {
        agentId: 'e2e-b7', intent: { purpose: 'pay 100 FEE' },
        transaction: { from: A0, to: FEE, data: transferData(A1, 100n), value: '0x0', chainId: '0x7a69' }
      });
      assert.strictEqual(out.decision, 'ALLOW', JSON.stringify(out).slice(0, 500));
      const signed = await post(`${signerBase}/sign`, {
        requestId: out.requestId,
        transaction: { from: A0, to: FEE, data: transferData(A1, 100n), value: '0x0', chainId: '0x7a69' },
        approval: out.approval
      });
      assert.strictEqual(signed.ok, true);
      const st = await waitExecution(out.requestId);
      assert.strictEqual(st.execution.outcome, 'EFFECTS_DIVERGED');
      assert.deepStrictEqual(st.execution.verification.missing, ['EF-001']);
      assert.ok(st.execution.verification.unexpectedLogs.length >= 1);
      const receipt = await rpc(anvilRpc, 'eth_getTransactionReceipt', [signed.txHash]);
      assert.strictEqual(receipt.status, '0x1', 'chain execution succeeded; divergence is reconciliation-level');
      assert.strictEqual(receipt.logs.length, 2, 'net + fee logs observed independently');
      console.log(`✔ B7-E2 Passed: genuine fee shortfall DIVERGED. REAL_TX=${signed.txHash}`);
    }

    // B7-E3: bounded approve needs operator release, then MATCHES.
    {
      const out = await post(`${policyBase}/api/v1/agent/propose`, {
        agentId: 'e2e-b7', intent: { purpose: 'approve 500 TT' },
        transaction: { from: A0, to: TOKEN, data: approveData(A1, 500n), value: '0x0', chainId: '0x7a69' }
      });
      assert.strictEqual(out.decision, 'REVIEW', 'persistent approval held for review');
      const auth = await post(`${policyBase}/api/v1/agent/requests/${out.requestId}/authorize`, { operatorSecret: OPERATOR_SECRET });
      assert.strictEqual(auth.authorized, true);
      const signed = await post(`${signerBase}/sign`, {
        requestId: out.requestId,
        transaction: { from: A0, to: TOKEN, data: approveData(A1, 500n), value: '0x0', chainId: '0x7a69' },
        approval: auth.approval
      });
      assert.strictEqual(signed.ok, true);
      const st = await waitExecution(out.requestId);
      assert.strictEqual(st.execution.outcome, 'EXECUTED');
      assert.strictEqual(st.execution.verification.effects, 'EFFECTS_MATCHED');
      console.log(`✔ B7-E3 Passed: operator-released approve MATCHED. REAL_TX=${signed.txHash}`);
    }

    console.log('\nAll B7 E2E Scenarios Passed Successfully!\n');
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
  runEffectVerificationTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runEffectVerificationTests };
