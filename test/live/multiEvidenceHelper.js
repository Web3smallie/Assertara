// Shared helpers for Capability 3 live batteries. Genuine live API;
// nothing here mocks the model transport.
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const config = require('../../src/config/env');
const { refSourceRoot } = require('../../src/services/reasoningRubric');

const REVIEW_FILE = path.join(__dirname, '..', 'tmp', 'cap3-review.jsonl');

function liveEnabled() {
  if (process.env.LIVE_MODEL_TESTS !== '1') return { ok: false, reason: 'LIVE_MODEL_TESTS!=1' };
  const key = config.modelApiKey || '';
  if (!key || key.startsWith('mock_') || key.includes('your_meta')) return { ok: false, reason: 'no real MODEL_API_KEY' };
  return { ok: true };
}

function fixtureScreenshot() {
  return fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'sam', 'dapp-screenshot.png')).toString('base64');
}

async function runController(body, internal) {
  const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const req = { body };
  const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(p) { resolve({ status: this.statusCode, body: p }); } };
  const t0 = Date.now();
  await handleEvaluateTransaction(req, res, internal);
  const out = await done;
  return { ...out, wallMs: Date.now() - t0 };
}

// Marginal-cap retries: hard scenarios can exhaust the output budget
// mid-JSON (labeled fallback, safe direction) even at temperature 0.
// Retry for a model-origin response; fail only when all attempts
// exhaust. Retries never weaken assertions — the strict origin check
// still runs on the final attempt's output.
async function attemptModel(label, body, internal, tries = 3) {
  let last = null;
  for (let i = 1; i <= tries; i += 1) {
    last = await runController(body, internal);
    console.log(`  [${label}] try ${i}: ${last.wallMs}ms origin=${last.body.reasoningOrigin}`);
    if (last.body.reasoningOrigin === 'model') return last;
  }
  return last;
}

async function attemptReasoner(label, args, tries = 3) {
  const { evaluateSemanticDiscrepancy } = require('../../src/services/reasonerService');
  let last = null;
  for (let i = 1; i <= tries; i += 1) {
    const t0 = Date.now();
    last = await evaluateSemanticDiscrepancy(...args);
    console.log(`  [${label}] try ${i}: ${Date.now() - t0}ms origin=${last.origin}`);
    if (last.origin === 'model') return last;
  }
  return last;
}

function rootsOf(refs) {
  return [...new Set((refs || []).map(refSourceRoot).filter((r) => r !== 'unknown'))];
}

// A discrepancy/contradiction counts as joint when its refs span 2+ roots.
function jointItems(investigation) {
  const inv = investigation || {};
  const items = [...(inv.discrepancies || []), ...(inv.contradictions || []).map((c) => ({ supportingRefs: c.sources || [], contradictingRefs: [] }))];
  return items.filter((d) => rootsOf([...(d.supportingRefs || []), ...(d.contradictingRefs || [])]).length >= 2);
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

async function bootAnvil() {
  const port = await freePort();
  const rpcUrl = `http://127.0.0.1:${port}`;
  const cands = [process.env.ANVIL_BIN,
    path.join(os.homedir(), '.foundry', 'bin', process.platform === 'win32' ? 'anvil.exe' : 'anvil'), 'anvil'].filter(Boolean);
  const bin = cands.find((c) => { try { return fs.existsSync(c); } catch { return false; } }) || 'anvil';
  const proc = spawn(bin, ['--port', String(port)], { stdio: ['ignore', 'ignore', 'pipe'] });
  proc.on('error', () => {});
  const start = Date.now();
  for (;;) {
    try {
      const r = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }) });
      if ((await r.json()).result === '0x7a69') break;
    } catch { /* booting */ }
    if (Date.now() - start > 30000) { try { proc.kill('SIGKILL'); } catch {} throw new Error('anvil did not boot'); }
    await new Promise((r) => setTimeout(r, 500));
  }
  return { proc, rpcUrl, kill() { try { proc.kill('SIGKILL'); } catch {} } };
}

module.exports = { liveEnabled, fixtureScreenshot, runController, attemptModel, attemptReasoner, rootsOf, jointItems, bootAnvil, REVIEW_FILE, config };
