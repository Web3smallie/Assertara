// LIVE smoke test for the F1/F2 model driver. NOT wired into `npm test`:
// it spends real API budget and needs network + MODEL_API_KEY. Run explicitly:
//   node test/unit/modelDriver.live.test.js
// Self-skips (exit 0) when no key is configured. Never prints the key.
const assert = require('assert');
const { SparkAdapter } = require('../../src/agent/sparkAdapter');
const { runCoreInvestigation, runAdvanced } = require('../../src/agent/features');

const ADDR_B = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const APPROVE_DATA = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

async function main() {
  const { modelApiKey } = require('../../src/config/env');
  const adapter = new SparkAdapter({ apiKey: modelApiKey || '' });
  if (!adapter.configured) {
    console.log('SKIP: no MODEL_API_KEY configured; live driver smoke test not run.');
    return;
  }
  console.log('Live driver smoke: F1 core investigation (maxTurns 3, maxToolCalls 6)...');
  const f1 = await runCoreInvestigation(
    {
      goal: 'Decode the supplied approval transaction and report the spender and allowance.',
      inputs: { tx: { to: ADDR_B, data: APPROVE_DATA, value: '0x0' } },
      budget: { maxTurns: 3, maxToolCalls: 6 }
    },
    { live: true }
  );
  const tools = f1.record.graph.byKind('ToolResult');
  console.log(`F1 live: status=${f1.record.status} turns=${f1.record.turns.length} toolResults=${tools.length} modelCalls=${f1.record.ledger.modelCalls}`);
  console.log(`F1 live stopReason: ${(f1.record.stopReason || '').slice(0, 200)}`);
  assert.ok(['COMPLETE', 'INCOMPLETE'].includes(f1.record.status));
  assert.ok(f1.record.ledger.modelCalls >= 1, 'At least one live model turn ran');
  const blob = JSON.stringify(f1.record).slice(0, 40000);
  assert.ok(!/sk-[A-Za-z0-9]{16,}/.test(blob), 'No key material in the record');

  console.log('Live driver smoke: F2 review of the decoded approval (maxTurns 2)...');
  const f2 = await runAdvanced(
    {
      goal: 'Confirm the approval spender via tools.',
      inputs: { tx: { to: ADDR_B, data: APPROVE_DATA, value: '0x0' } },
      hypotheses: [{ id: 'H-live', claim: 'The approval grants an allowance to a spender.', supporting: [], contradicting: [] }]
    },
    { live: true }
  );
  console.log(`F2 live: status=${f2.record.status} reviewed=${f2.reviewed.map((r) => `${r.id}:${r.adjudication.status}`).join(',')}`);
  // Empty support can never verify, live or not.
  assert.ok(!f2.reviewed.some((r) => r.adjudication.status === 'VERIFIED'), 'Unsupported live hypothesis must not verify');
  console.log('\nLive driver smoke PASSED.');
}

if (require.main === module) {
  // exitCode (not process.exit) so open handles drain and Windows teardown stays clean.
  main().catch((err) => { console.error('LIVE_SMOKE_FAILED:', err.message); process.exitCode = 1; });
}
