/**
 * agentDriven reuse-mode arg parsing + preflight validation.
 * No network, no model, no stack boot: fetch is fully stubbed.
 */
const assert = require('node:assert/strict');
const { parseAgentDrivenArgs, validateReuseTargets } = require('../../demo/agentDriven');
const { LOCAL_ADDRS } = require('../../demo/scenarios');

const ENV_KEYS = ['ASSERTARA_POLICY_BASE', 'ASSERTARA_SIGNER_BASE', 'ASSERTARA_ANVIL_RPC', 'ASSERTARA_API_KEY'];
const savedEnv = {};
for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
function clearEnv() { for (const k of ENV_KEYS) delete process.env[k]; }
function restoreEnv() {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
}

function stubFetch(routes) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push(String(url));
    const u = String(url);
    for (const [match, handler] of routes) {
      if (u.includes(match)) return handler(u, init);
    }
    throw new Error(`unstubbed url ${u}`);
  };
  fn.calls = calls;
  return fn;
}
const json = (body, ok = true, status = 200) => ({ ok, status, json: async () => body });

function healthyRoutes() {
  return [
    ['/health', (u) => (u.includes(':3002') || u.includes('signer')
      ? json({ ok: true, address: LOCAL_ADDRS.a0, mandateId: 'command-mandate', mandateVersion: 1 })
      : json({ status: 'healthy', service: 'Assertara Visual Sentry' }))],
    ['/api/v1/agent/mandate', () => json({ configured: true, id: 'command-mandate', version: 1 })],
    [':8545', () => json({ result: '0x7a69' })]
  ];
}
const REUSE = { policyBase: 'http://127.0.0.1:3001', signerBase: 'http://127.0.0.1:3002', anvilRpc: 'http://127.0.0.1:8545', apiKey: null };

async function main() {
  clearEnv();
  try {
    // --- arg parsing: standalone preserved ---
    let p = parseAgentDrivenArgs([]);
    assert.equal(p.runA, true); assert.equal(p.runB, true); assert.equal(p.reuse, null);
    p = parseAgentDrivenArgs(['a']);
    assert.equal(p.runA, true); assert.equal(p.runB, false); assert.equal(p.reuse, null);
    p = parseAgentDrivenArgs(['B']);
    assert.equal(p.runA, false); assert.equal(p.runB, true); assert.equal(p.reuse, null);
    assert.throws(() => parseAgentDrivenArgs(['c']), /usage/);
    assert.throws(() => parseAgentDrivenArgs(['a', 'b']), /usage/);
    assert.throws(() => parseAgentDrivenArgs(['--bogus']), /unknown option/);
    assert.throws(() => parseAgentDrivenArgs(['--policy-base']), /requires a value/);

    // --- arg parsing: reuse via flags (flags accepted anywhere) ---
    p = parseAgentDrivenArgs(['a', '--policy-base', 'http://127.0.0.1:3001/', '--signer-base', 'http://127.0.0.1:3002', '--anvil-rpc', 'http://127.0.0.1:8545']);
    assert.equal(p.runA, true); assert.equal(p.runB, false);
    assert.equal(p.reuse.policyBase, 'http://127.0.0.1:3001'); // trailing slash trimmed
    assert.equal(p.reuse.signerBase, 'http://127.0.0.1:3002');
    assert.equal(p.reuse.anvilRpc, 'http://127.0.0.1:8545');
    assert.equal(p.reuse.apiKey, null);

    // --- reuse requires signer + anvil; never silently standalone ---
    assert.throws(() => parseAgentDrivenArgs(['--policy-base', 'http://x:3001']), /no silent fallback/);
    assert.throws(
      () => parseAgentDrivenArgs(['--policy-base', 'http://x:3001', '--signer-base', 'http://x:3002']),
      /--anvil-rpc/
    );

    // --- env fallback + flag precedence ---
    process.env.ASSERTARA_POLICY_BASE = 'http://env:3001';
    process.env.ASSERTARA_SIGNER_BASE = 'http://env:3002';
    process.env.ASSERTARA_ANVIL_RPC = 'http://env:8545';
    process.env.ASSERTARA_API_KEY = 'env-key';
    p = parseAgentDrivenArgs(['b']);
    assert.equal(p.reuse.policyBase, 'http://env:3001');
    assert.equal(p.reuse.apiKey, 'env-key');
    p = parseAgentDrivenArgs(['--policy-base', 'http://flag:3001']);
    assert.equal(p.reuse.policyBase, 'http://flag:3001');
    assert.equal(p.reuse.signerBase, 'http://env:3002'); // env fills the rest
    clearEnv();

    // --- preflight: happy path ---
    let out = await validateReuseTargets(REUSE, { fetchImpl: stubFetch(healthyRoutes()) });
    assert.equal(out.mandate.id, 'command-mandate');
    assert.equal(out.signer.address, LOCAL_ADDRS.a0);
    assert.equal(out.chainId, '0x7a69');

    // --- preflight: policy unreachable ---
    await assert.rejects(
      validateReuseTargets(REUSE, { fetchImpl: stubFetch([[':3001', async () => { throw new Error('ECONNREFUSED'); }]]) }),
      /refusing to boot a fallback stack/
    );
    // --- preflight: mandate not configured ---
    await assert.rejects(
      validateReuseTargets(REUSE, {
        fetchImpl: stubFetch([
          ['/api/v1/agent/mandate', () => json({ configured: false })],
          ['/health', () => json({ status: 'healthy' })],
          [':8545', () => json({ result: '0x7a69' })]
        ])
      }),
      /No active mandate/
    );
    // --- preflight: signer unhealthy ---
    await assert.rejects(
      validateReuseTargets(REUSE, {
        fetchImpl: stubFetch([
          ['/api/v1/agent/mandate', () => json({ configured: true })],
          ['/health', (u) => (u.includes(':3002') ? json({ ok: false }, false, 503) : json({ status: 'healthy' }))],
          [':8545', () => json({ result: '0x7a69' })]
        ])
      }),
      /signer unhealthy/
    );
    // --- preflight: signer identity mismatch ---
    await assert.rejects(
      validateReuseTargets(REUSE, {
        fetchImpl: stubFetch([
          ['/api/v1/agent/mandate', () => json({ configured: true })],
          ['/health', (u) => (u.includes(':3002')
            ? json({ ok: true, address: '0x0000000000000000000000000000000000000001' })
            : json({ status: 'healthy' }))],
          [':8545', () => json({ result: '0x7a69' })]
        ])
      }),
      /identity mismatch/
    );
    // --- preflight: wrong chain ---
    await assert.rejects(
      validateReuseTargets(REUSE, {
        fetchImpl: stubFetch([
          ['/api/v1/agent/mandate', () => json({ configured: true })],
          ['/health', (u) => (u.includes(':3002')
            ? json({ ok: true, address: LOCAL_ADDRS.a0 })
            : json({ status: 'healthy' }))],
          [':8545', () => json({ result: '0x1' })]
        ])
      }),
      /chain mismatch/
    );
    // --- preflight: anvil unreachable ---
    await assert.rejects(
      validateReuseTargets(REUSE, {
        fetchImpl: stubFetch([
          ['/api/v1/agent/mandate', () => json({ configured: true })],
          ['/health', (u) => (u.includes(':3002')
            ? json({ ok: true, address: LOCAL_ADDRS.a0 })
            : json({ status: 'healthy' }))],
          [':8545', async () => { throw new Error('ECONNREFUSED'); }]
        ])
      }),
      /chain unreachable/
    );
  } finally {
    restoreEnv();
  }
  console.log('agentDrivenReuse: all assertions passed');
}

main().catch((err) => { console.error(err); process.exit(1); });
