const assert = require('assert');
const T = require('../../src/services/investigationTelemetry');

async function run() {
  console.log('Testing investigation telemetry...\n');

  // Lifecycle + spans + events.
  {
    const tr = T.createTrace({ kind: 'agent', requestId: 'agent_1', label: 'swap' });
    assert.ok(tr.id.startsWith('tr_') && tr.status === 'RUNNING');
    assert.strictEqual(tr.events.length, 1, 'trace-start emitted');
    const h = T.startSpan(tr, 'decoder', '0x CLS');
    assert.ok(h);
    assert.strictEqual(T.spanOf(tr, 'decoder').status, 'RUNNING');
    h.finish('approve(address,uint256)', { functionName: 'approve' });
    const s = tr.spans[0];
    assert.strictEqual(s.status, 'COMPLETED');
    assert.ok(Number.isInteger(s.durationMs) && s.durationMs >= 0);
    assert.strictEqual(s.group, 'Transaction analysis');
    T.finishTrace(tr, { decision: 'ALLOW' });
    assert.strictEqual(tr.status, 'COMPLETED');
    assert.deepStrictEqual(tr.outcome, { decision: 'ALLOW' });
    // Late finish is a no-op, never a second event.
    const n = tr.events.length;
    h.finish('again');
    assert.strictEqual(tr.events.length, n);
    console.log('  ✔ lifecycle, spans, idempotent finish');
  }

  // fail / skip paths.
  {
    const tr = T.createTrace({ kind: 'evaluate' });
    T.startSpan(tr, 'sam', '').fail(new Error('no screenshot'));
    T.markSkipped(tr, 'simulation-pre', 'not triggered');
    assert.strictEqual(tr.spans[0].status, 'FAILED');
    assert.strictEqual(tr.spans[0].error, 'no screenshot');
    assert.strictEqual(tr.spans[1].status, 'SKIPPED');
    T.failTrace(tr, 'boom');
    assert.strictEqual(tr.status, 'FAILED');
    console.log('  ✔ fail, skip, trace failure');
  }

  // timed() sync/async/throw.
  {
    const tr = T.createTrace({});
    const v = T.timed(tr, 'decoder', '', () => 42, (x) => `n=${x}`);
    assert.strictEqual(v, 42);
    assert.strictEqual(tr.spans[0].summary, 'n=42');
    const a = await T.timed(tr, 'ocr', '', async () => 'txt');
    assert.strictEqual(a, 'txt');
    assert.strictEqual(tr.spans[1].status, 'COMPLETED');
    await assert.rejects(T.timed(tr, 'sam', '', async () => { throw new Error('x'); }));
    assert.strictEqual(tr.spans[2].status, 'FAILED');
    console.log('  ✔ timed sync/async/throw');
  }

  // Secret screening: credential-shaped keys never survive.
  {
    const tr = T.createTrace({});
    T.startSpan(tr, 'approval-issue', '').finish('issued', {
      approval: 'appr_deadbeef', operatorSecret: 's3cr3t', nested: { token: 'abc' }, nonce: 'n1'
    });
    const ex = tr.spans[0].extra;
    assert.strictEqual(ex.approval, 'appr_deadbeef', 'non-matching keys pass through');
    assert.strictEqual(ex.operatorSecret, '[redacted]');
    assert.strictEqual(ex.nested.token, '[redacted]');
    assert.strictEqual(ex.nonce, 'n1');
    const snap = T.snapshot(tr);
    assert.strictEqual(snap.spans[0].extra.operatorSecret, '[redacted]');
    assert.ok(snap.catalog['muse-spark']);
    console.log('  ✔ secret screening in extras + snapshots');
  }

  // subscribe fan-out + unsubscribe; dead listeners cannot break recording.
  {
    const tr = T.createTrace({});
    const got = [];
    const off = T.subscribe(tr.id, (e) => got.push(e.type));
    T.subscribe(tr.id, () => { throw new Error('dead'); });
    T.startSpan(tr, 'decoder', '').finish('ok');
    assert.ok(got.includes('span-start') && got.includes('span-finish'));
    off();
    const n = got.length;
    T.startSpan(tr, 'ocr', '').finish('ok');
    assert.strictEqual(got.length, n, 'unsubscribed listener hears nothing');
    console.log('  ✔ subscribe, dead-listener tolerance, unsubscribe');
  }

  // Ring bound + lookup + null-trace safety.
  {
    for (let i = 0; i < T.MAX_TRACES + 5; i += 1) T.createTrace({ label: `t${i}` });
    assert.ok(T.listTraces().length <= T.MAX_TRACES);
    const tr = T.createTrace({ requestId: 'agent_findme' });
    assert.strictEqual(T.findByRequest('agent_findme').id, tr.id);
    assert.strictEqual(T.findByRequest('nope'), null);
    assert.strictEqual(T.getTrace('nope'), null);
    assert.strictEqual(T.snapshot(null), null);
    assert.strictEqual(T.startSpan(null, 'decoder'), null);
    assert.strictEqual(T.timed(null, 'decoder', '', () => 7), 7, 'null trace passes through');
    T.markSkipped(null, 'sam', 'x');
    T.finishTrace(null); T.failTrace(null);
    console.log('  ✔ ring bound, lookup, null-trace safety');
  }

  // Unknown components are admitted with their raw id (never dropped).
  {
    const tr = T.createTrace({});
    T.startSpan(tr, 'future-widget', '').finish('ok');
    assert.strictEqual(tr.spans[0].group, 'Other');
    assert.strictEqual(tr.spans[0].name, 'future-widget');
    console.log('  ✔ unknown component passthrough');
  }

  console.log('\nAll Telemetry Tests Passed Successfully!');
}

if (require.main === module) run().catch((err) => { console.error(err); process.exit(1); });
module.exports = { run };
