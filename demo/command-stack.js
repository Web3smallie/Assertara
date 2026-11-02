/**
 * Command-centre stack: boots real Anvil + policy app + controlled
 * signer with the reference agent-testing mandate, then serves the
 * live command UI at /command.
 *
 * Run: node demo/command-stack.js [--app-port 3001] [--anvil-port 8545] [--signer-port 3002] [--mock-model]
 *   --mock-model sets a mock MODEL_API_KEY (heuristic path, labeled);
 *   otherwise the investigation uses the live model from .env.
 *
 * Reference mandate (matches demo/scenarios.js expectations):
 * - recipients allow: contributor, router, unknown-probe, USDC-label;
 *   deny: stranger. contracts allow: router, unknown-probe, USDC-label.
 * - selectors allow: multicall, approve, transfer, 0xdeadbeef probe.
 * - native <= 0.1 ETH/tx; REVIEW above 0.01 ETH; unlimited approvals
 *   banned; approval spenders allowlisted to the contributor.
 *
 * Secrets (approval/operator keys, signer key) are generated per boot
 * and never printed, served, or written outside the temp dir.
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { encodeFunctionData } = require('viem');
const { ERC20_ABI, UNISWAP_V3_ROUTER_ABI } = require('../src/utils/abiSignatures');
const { LOCAL_ADDRS } = require('./scenarios');

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
    await new Promise((r) => setTimeout(r, 500));
  }
}

function selectorOf(abi, name) {
  return encodeFunctionData({ abi, functionName: name, args: name === 'multicall' ? [[]] : (name === 'approve' ? ['0x0000000000000000000000000000000000000001', 0n] : ['0x0000000000000000000000000000000000000001', 0n]) }).slice(0, 10).toLowerCase();
}

function referenceMandate(anvilRpc) {
  return {
    id: 'command-mandate', version: 1, issuer: 'command-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: LOCAL_ADDRS.a0, senders: [LOCAL_ADDRS.a0],
    chains: [{ id: 31337, rpcUrl: anvilRpc, name: 'anvil-command' }],
    recipients: { allow: [LOCAL_ADDRS.a1, LOCAL_ADDRS.router, LOCAL_ADDRS.unknown, LOCAL_ADDRS.usdc], deny: [LOCAL_ADDRS.stranger] },
    contracts: { allow: [LOCAL_ADDRS.router, LOCAL_ADDRS.unknown, LOCAL_ADDRS.usdc] },
    selectors: {
      allow: [
        selectorOf(UNISWAP_V3_ROUTER_ABI, 'multicall'),
        selectorOf(ERC20_ABI, 'approve'),
        selectorOf(ERC20_ABI, 'transfer'),
        '0xdeadbeef'
      ]
    },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [LOCAL_ADDRS.a1] },
    spendingLimits: [{ windowMs: 86400000, maxNativeWei: '1000000000000000000' }],
    reviewRules: [{ when: 'nativeValueAboveWei', value: '10000000000000000' }]
  };
}

async function bootStack({ appPort, anvilPort, signerPort, mockModel, tmpBase } = {}) {
  const base = tmpBase || path.join(__dirname, 'tmp');
  fs.mkdirSync(base, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(base, 'cmd-'));
  const killAll = [];
  const onExit = (fn) => killAll.push(fn);

  const APPROVAL_SECRET = crypto.randomBytes(32).toString('hex');
  const OPERATOR_SECRET = crypto.randomBytes(32).toString('hex');

  const { mnemonicToAccount, generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
  const anvilAccount = mnemonicToAccount(ANVIL_MNEMONIC);
  if (anvilAccount.address.toLowerCase() !== LOCAL_ADDRS.a0.toLowerCase()) throw new Error('derived key is not Anvil account[0]');
  const SIGNER_KEY = `0x${Buffer.from(anvilAccount.getHdKey().privateKey).toString('hex')}`;
  const OPERATOR_KEY = generatePrivateKey();
  const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address;

  const anvilP = anvilPort || await freePort();
  const signerP = signerPort || await freePort();
  const appP = appPort || await freePort();
  const anvilRpc = `http://127.0.0.1:${anvilP}`;

  const mandateFile = path.join(tmp, 'mandate.json');
  fs.writeFileSync(mandateFile, JSON.stringify(referenceMandate(anvilRpc)), 'utf8');
  const { sealMandateFile } = require('../src/signer/signMandate');
  await sealMandateFile(mandateFile, OPERATOR_KEY);

  const anvilCandidates = [
    process.env.ANVIL_BIN,
    path.join(os.homedir(), '.foundry', 'bin', process.platform === 'win32' ? 'anvil.exe' : 'anvil'),
    'anvil'
  ].filter(Boolean);
  const anvilBin = anvilCandidates.find((c) => { try { return fs.existsSync(c); } catch { return false; } }) || 'anvil';
  const anvil = spawn(anvilBin, ['--port', String(anvilP)], { stdio: ['ignore', 'ignore', 'pipe'] });
  anvil.on('error', () => {});
  onExit(() => { try { anvil.kill('SIGKILL'); } catch {} });

  await waitFor(async () => (await rpc(anvilRpc, 'eth_chainId', [])) === '0x7a69', 30000, 'anvil boot');

  // Policy app in-process (env set BEFORE require: config reads at load).
  process.env.MANDATE_FILE = mandateFile;
  process.env.APPROVAL_SECRET = APPROVAL_SECRET;
  process.env.OPERATOR_SECRET = OPERATOR_SECRET;
  process.env.TRUSTED_MANDATE_AUTHORITIES = OPERATOR_ADDR;
  process.env.AGENT_LEDGER_FILE = path.join(tmp, 'agent-ledger.jsonl');
  process.env.SPENDING_LEDGER_FILE = path.join(tmp, 'agent-spending.jsonl');
  process.env.AGENT_SNAPSHOT_FILE = path.join(tmp, 'agent-requests.json');
  process.env.AGENT_AUTH_MODE = process.env.AGENT_AUTH_MODE || 'development';
  process.env.INVESTIGATIONS_FILE = path.join(tmp, 'investigations.jsonl');
  if (mockModel) process.env.MODEL_API_KEY = 'mock_command_stack';
  const app = require('../src/server.js');
  const policyServer = await new Promise((resolve, reject) => {
    const s = app.listen(appP, '127.0.0.1', () => resolve(s));
    s.on('error', reject);
  });
  onExit(() => { try { policyServer.close(); } catch {} });
  const policyBase = `http://127.0.0.1:${appP}`;

  const signerProc = spawn('node', [path.join(__dirname, '..', 'src', 'signer', 'server.js')], {
    env: {
      ...process.env,
      APPROVAL_SECRET, OPERATOR_SECRET, MANDATE_FILE: mandateFile,
      SIGNER_TRUSTED_MANDATE_AUTHORITIES: OPERATOR_ADDR,
      SIGNER_PRIVATE_KEY: SIGNER_KEY, SIGNER_PORT: String(signerP),
      SIGNER_CONSUMED_FILE: path.join(tmp, 'signer-consumed.jsonl'),
      POLICY_CALLBACK_URL: `${policyBase}/api/v1/internal/signer-callback`
    },
    stdio: ['ignore', 'ignore', 'pipe']
  });
  let signerStderr = '';
  if (signerProc.stderr) signerProc.stderr.on('data', (d) => { signerStderr += String(d).slice(-2000); });
  signerProc.on('error', () => {});
  onExit(() => { try { signerProc.kill('SIGKILL'); } catch {} });
  const signerBase = `http://127.0.0.1:${signerP}`;
  await waitFor(async () => {
    const h = await (await fetch(`${signerBase}/health`)).json();
    return h && h.ok === true && h.address.toLowerCase() === LOCAL_ADDRS.a0.toLowerCase() && h.mandateVersion === 1 ? h : null;
  }, 30000, 'signer boot').catch((err) => { throw new Error(`${err.message}. signer stderr: ${signerStderr}`); });

  // Browser demo support: attach the genuine agent runtime to the
  // policy server's task surface (no-op on mock-model stacks).
  let agentTasksAttached = false;
  try {
    // eslint-disable-next-line global-require
    const { attachAgentTaskRunner } = require('./agentTaskRunner');
    agentTasksAttached = attachAgentTaskRunner({ policyBase, signerBase });
  } catch (err) {
    console.warn(`[Agent] task runner not attached (${err && err.message ? err.message : err}); browser demos unavailable.`);
  }

  const kill = () => { for (const fn of killAll.splice(0)) { try { fn(); } catch {} } };
  return {
    tmp, policyBase, signerBase, anvilRpc, mandateFile, agentTasksAttached,
    addrs: LOCAL_ADDRS,
    // Operator secret: returned to the IN-PROCESS caller only (scripted
    // runner acting as operator stand-in). Never served over HTTP.
    operatorSecret: OPERATOR_SECRET,
    mockModel: Boolean(mockModel),
    kill
  };
}

async function main() {
  const args = process.argv.slice(2);
  const num = (flag) => {
    const i = args.indexOf(flag);
    return i !== -1 && args[i + 1] ? Number(args[i + 1]) : undefined;
  };
  const stack = await bootStack({
    appPort: num('--app-port') || 3001,
    anvilPort: num('--anvil-port') || 8545,
    signerPort: num('--signer-port') || 3002,
    mockModel: args.includes('--mock-model')
  });
  console.log('Assertara command stack is up (Ctrl+C to stop):');
  console.log(`  app:    ${stack.policyBase}`);
  console.log(`  signer: ${stack.signerBase}`);
  console.log(`  anvil:  ${stack.anvilRpc}`);
  console.log(`  model:  ${stack.mockModel ? 'MOCK (heuristic path, labeled)' : 'LIVE (MODEL_API_KEY from .env)'}`);
  console.log(`  agent tasks: ${stack.agentTasksAttached ? 'attached (browser demos enabled)' : 'unavailable (browser demos disabled)'}`);
  console.log('');
  console.log(`Open this URL in your browser:`);
  console.log(`  ${stack.policyBase}/command/?signer=${encodeURIComponent(stack.signerBase)}`);
  const shutdown = () => { stack.kill(); process.exit(0); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  await new Promise(() => {});
}

if (require.main === module) {
  main().catch((err) => { console.error(`command stack failed: ${err.message}`); process.exit(2); });
}

module.exports = { bootStack, referenceMandate };
