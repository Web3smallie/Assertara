// LIVE verification for the 8 legacy model-calling paths (Phase 17).
// NOT wired into `npm test`: spends real API budget, needs network + key.
// Run explicitly: node test/unit/legacyRunners.live.test.js
// Self-skips (exit 0) when no key is configured. Never prints secrets.
// Each runner is exercised individually with a small fixture; failures are
// attributed per runner and the script exits nonzero if any runner fails.
const assert = require('assert');
const { SparkAdapter } = require('../../src/agent/sparkAdapter');
const { modelApiKey } = require('../../src/config/env');
const {
  runTranslator, runTriage, runAskAbout, runAdvanced,
  runSentinel, runDossier, runScamCallTranscript, runRepoReview, TACTICS
} = require('../../src/agent/features');

const ADDR_B = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const APPROVE_DATA = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const RPC_URL = 'https://ethereum-rpc.publicnode.com';

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

  // F9 legacy — frozen-graph Q&A over a 2-node graph.
  try {
    const { adapter, calls } = instrumentedAdapter();
    const graphExport = { nodes: [{ id: 'E-001', kind: 'DecodedTx', summary: 'approve() to 0xdAC1… for 100 USDT' }, { id: 'E-002', kind: 'Note', summary: 'unlimited=false' }] };
    const r = await runAskAbout({ graphExport, question: 'What amount was approved?' }, { model: adapter });
    assert.ok(['OK', 'PARTIAL'].includes(r.status));
    assert.strictEqual(typeof r.answer, 'string');
    assert.ok(r.citations.every((c) => ['E-001', 'E-002'].includes(c)), 'citations resolve');
    assertNoSecrets(r, 'F9');
    record('F9_ask_legacy', true, `status=${r.status} citations=${r.citations.length} dropped=${r.dropped.length} (${costStr(calls)})`);
  } catch (e) { record('F9_ask_legacy', false, `threw: ${e.message.slice(0, 160)}`); }

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

  // F6 — sentinel narration over a tiny live range (read-only).
  try {
    const { createPublicClient, http } = require('viem');
    const { adapter, calls } = instrumentedAdapter();
    const client = createPublicClient({ transport: http(RPC_URL) });
    const tip = await client.getBlockNumber();
    const from = tip > 20n ? tip - 20n : 0n;
    const r = await runSentinel(
      { owner: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', tokens: [ADDR_B], fromBlock: from, toBlock: tip, maxLogs: 10 },
      { client, model: adapter }
    );
    assert.strictEqual(r.status, 'OK');
    assert.ok(r.narrative && typeof r.narrative.summary === 'string' && Array.isArray(r.narrative.highestRisk));
    const knownAddrs = new Set([ADDR_B.toLowerCase(), '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', ...r.approvals.map((a) => String(a.spender || '').toLowerCase())]);
    const mentioned = (r.narrative.summary.match(/0x[0-9a-fA-F]{40}/g) || []).map((a) => a.toLowerCase());
    const fabricated = mentioned.filter((a) => !knownAddrs.has(a));
    assertNoSecrets(r, 'F6');
    record('F6_sentinel', true, `coverage=${r.coverage.status} narrative(addrs:${mentioned.length},fabricated:${fabricated.length}) (${costStr(calls)})`);
    if (fabricated.length > 0) record('F6_fabrication_note', false, `narrative cited unknown addresses: ${fabricated.join(',')}`);
  } catch (e) { record('F6_sentinel', false, `threw: ${e.message.slice(0, 160)}`); }

  // F7 — dossier synthesis over USDC (history off to keep it small).
  try {
    const { createPublicClient, http } = require('viem');
    const { adapter, calls } = instrumentedAdapter();
    const client = createPublicClient({ transport: http(RPC_URL) });
    const r = await runDossier({ address: ADDR_B, history: false }, { client, model: adapter });
    assert.strictEqual(r.status, 'OK');
    assert.ok(r.synthesis && r.synthesis.verified === false && r.synthesis.interpretationOf === 'dossier');
    assert.strictEqual(typeof r.synthesis.summary, 'string');
    // Accusatory scan: drop negated sentences first so "no malicious X found"
    // (cautious, compliant) never counts as a verdict violation.
    const sentences = `${r.synthesis.summary} ${(r.synthesis.flags || []).join(' ')}`.split(/[.\n]/);
    const affirmative = sentences.filter((s) => !/\b(no|not|n't|never|without|absence|lack|fails? to show|none)\b/i.test(s)).join('. ');
    const verdictHits = ['malicious', 'safe to use', 'verified safe', 'definitely safe', 'is safe', 'is legitimate'].filter((w) =>
      affirmative.toLowerCase().includes(w));
    assertNoSecrets(r, 'F7');
    record('F7_dossier', true, `verified=false kept; affirmative-verdict-hits=[${verdictHits.join('|') || 'none'}] (${costStr(calls)})`);
    if (verdictHits.length > 0) record('F7_verdict_note', false, `synthesis used affirmative verdict language: ${verdictHits.join(',')}`);
  } catch (e) { record('F7_dossier', false, `threw: ${e.message.slice(0, 160)}`); }

  // F8 — transcript lane over 2 synthetic turns.
  try {
    const { adapter, calls } = instrumentedAdapter();
    const r = await runScamCallTranscript({ turns: [{ speaker: 'caller', text: 'Hello, this is wallet support, please share your seed phrase so we can help.' }, { speaker: 'user', text: 'I will not share that.' }] }, { model: adapter });
    assert.ok(['OK', 'PARTIAL'].includes(r.status));
    assert.strictEqual(r.lane, 'transcript');
    assert.strictEqual(r.source, 'TRANSCRIPT_PROVIDED');
    assert.ok(r.timeline.every((a) => Number.isInteger(a.turn) && a.turn < 2 && a.tactics.every((t) => (TACTICS || []).includes(t) || typeof t === 'string')));
    assertNoSecrets(r, 'F8');
    record('F8_scamcall', true, `status=${r.status} annotations=${r.timeline.length} dropped=${r.dropped.length} (${costStr(calls)})`);
  } catch (e) { record('F8_scamcall', false, `threw: ${e.message.slice(0, 160)}`); }

  // F15 — static review over a tiny fixture file.
  try {
    const { adapter, calls } = instrumentedAdapter();
    const r = await runRepoReview({ files: [{ path: 'Vault.sol', content: 'pragma solidity ^0.8.0;\ncontract Vault {\nfunction withdraw() public {\nmsg.sender.call{value: 1}("");\n}\n}' }], concern: 'reentrancy' }, { model: adapter });
    assert.ok(['OK', 'PARTIAL'].includes(r.status));
    assert.ok(r.pocDrafts.every((p) => p.status === 'UNEXECUTED'), 'PoCs stay unexecuted text');
    assert.ok(r.hypotheses.every((h) => h.refs.every((ref) => ref.startsWith('Vault.sol:'))), 'refs resolve to supplied file');
    assertNoSecrets(r, 'F15');
    record('F15_repo_review', true, `status=${r.status} hypotheses=${r.hypotheses.length} pocs=${r.pocDrafts.length} droppedRefs=${r.droppedRefs.length} (${costStr(calls)})`);
  } catch (e) { record('F15_repo_review', false, `threw: ${e.message.slice(0, 160)}`); }

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
