// LIVE verification for the retained model-calling runners.
// NOT wired into `npm test`: spends real API budget, needs network + key.
// Run explicitly: node test/unit/legacyRunners.live.test.js
// Self-skips (exit 0) when no key is configured. Never prints secrets.
// Each runner is exercised individually with a small fixture; failures are
// attributed per runner and the script exits nonzero if any runner fails.
const assert = require('assert');
const { SparkAdapter } = require('../../src/agent/sparkAdapter');
const { modelApiKey } = require('../../src/config/env');
const {
  runTranslator, runTriage, runAdvanced, runLocalize
} = require('../../src/agent/features');

const ADDR_B = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const APPROVE_DATA = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

const results = [];
function record(runner, ok, detail, meta) {
  results.push({ runner, ok, detail, ...(meta || {}) });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${runner}: ${detail}`);
}

// Wraps live.complete to capture per-call provenance without touching behavior.
function instrumentedAdapter() {
  const adapter = new SparkAdapter({ apiKey: modelApiKey });
  const calls = [];
  const orig = adapter.complete.bind(adapter);
  adapter.complete = async (args) => {
    const out = await orig(args);
    calls.push({ responseId: out.responseId || null, repaired: out.repaired === true, usage: out.usage || null, cost: out.estimatedCostUsd ?? null });
    return out;
  };
  return { adapter, calls };
}

function costStr(calls) {
  const c = calls[calls.length - 1] || {};
  const u = c.usage ? `in=${c.usage.input_tokens ?? '?'} out=${c.usage.output_tokens ?? '?'}` : 'usage unknown';
  return `${u} cost=${c.cost == null ? 'unknown' : c.cost} repaired=${c.repaired}`;
}

function assertNoSecrets(obj, where) {
  const blob = JSON.stringify(obj);
  assert.ok(!/sk-[A-Za-z0-9-]{8,}/.test(blob), `${where}: no key material`);
  assert.ok(!/Bearer\s+\S+/.test(blob), `${where}: no auth headers`);
}

async function main() {
  const probe = new SparkAdapter({ apiKey: modelApiKey || '' });
  if (!probe.configured) {
    console.log('SKIP: no MODEL_API_KEY configured; legacy live verification not run.');
    return;
  }

  // F4 — translator over a bounded approval.
  try {
    const { adapter, calls } = instrumentedAdapter();
    const r = await runTranslator({ tx: { to: ADDR_B, data: APPROVE_DATA, value: '0x0' } }, { model: adapter });
    assert.ok(['OK', 'UNVERIFIED_QUOTES'].includes(r.status));
    assert.strictEqual(r.output.type, 'TranslatorOutput');
    assert.strictEqual(typeof r.output.action, 'string');
    assert.strictEqual(r.output.verifiedAgainst.function, 'approve', 'Output grounded in decoded facts');
    assert.ok(Array.isArray(r.issues));
    assertNoSecrets(r, 'F4');
    record('F4_translator', true, `status=${r.status} issues=${r.issues.length} (${costStr(calls)})`);
  } catch (e) { record('F4_translator', false, `threw: ${e.message.slice(0, 160)}`); }

  // F5 — triage over the same approval (deterministic screen + model triage).
  try {
    const { adapter, calls } = instrumentedAdapter();
    const r = await runTriage({ tx: { to: ADDR_B, data: APPROVE_DATA, value: '0x0' } }, { model: adapter });
    assert.ok(['GREEN', 'AMBER', 'RED', 'INCONCLUSIVE'].includes(r.signal));
    assert.ok(Array.isArray(r.reasons) && typeof r.escalate === 'boolean');
    assertNoSecrets(r, 'F5');
    record('F5_interceptor', true, `signal=${r.signal} reasons=${r.reasons.length} escalate=${r.escalate} (${costStr(calls)})`);
  } catch (e) { record('F5_interceptor', false, `threw: ${e.message.slice(0, 160)}`); }

  // F2 reviewer — live core (1 turn) + live adversarial review.
  try {
    const { adapter, calls } = instrumentedAdapter();
    const r = await runAdvanced(
      { goal: 'Decode the approval.', inputs: { tx: { to: ADDR_B, data: APPROVE_DATA, value: '0x0' } }, hypotheses: [{ id: 'H-1', claim: 'The transaction calls approve.', supporting: [], contradicting: [] }] },
      { live: true, adapter }
    );
    assert.strictEqual(r.status, 'OK');
    assert.strictEqual(r.reviewed.length, 1);
    assert.ok(['VERIFIED', 'LIKELY', 'HYPOTHESIS', 'REJECTED', 'INCONCLUSIVE', 'INCOMPLETE'].includes(r.reviewed[0].adjudication.status));
    assertNoSecrets({ reviewed: r.reviewed }, 'F2');
    record('F2_reviewer', true, `adjudication=${r.reviewed[0].adjudication.status} calls=${calls.length}`);
  } catch (e) { record('F2_reviewer', false, `threw: ${e.message.slice(0, 160)}`); }

  // F12 — localize a finding to Spanish; protected values must survive verbatim.
  try {
    const { adapter, calls } = instrumentedAdapter();
    const finding = {
      claim: `Spender ${SPENDER} holds an unlimited allowance (E-001).`,
      recommendedAction: 'Review before signing.',
      severity: 'HIGH', contract: ADDR_B, functionName: 'approve'
    };
    const r = await runLocalize({ finding, targetLang: 'es' }, { model: adapter });
    assert.strictEqual(r.status, 'OK');
    assert.strictEqual(r.finding.severity, 'HIGH');
    assert.ok(String(r.finding.claim).includes(SPENDER), 'Protected address survives verbatim');
    assertNoSecrets(r, 'F12');
    record('F12_localize', true, `status=${r.status} language=${r.language} (${costStr(calls)})`);
  } catch (e) { record('F12_localize', false, `threw: ${e.message.slice(0, 160)}`); }

  console.log('\n— summary —');
  const failed = results.filter((r) => !r.ok);
  console.log(`${results.length - failed.length}/${results.length} checks passed (live calls).`);
  if (failed.length > 0) {
    console.log('Failed:', failed.map((f) => `${f.runner}: ${f.detail}`).join(' | '));
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main().catch((err) => { console.error('LIVE_VERIFY_FAILED:', err.message); process.exitCode = 1; });
}
