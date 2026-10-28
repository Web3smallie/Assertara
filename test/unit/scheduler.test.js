const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { WatchScheduler } = require('../../src/agent/scheduler');
const { runWatchCheck } = require('../../src/agent/features');

const ADDR_A = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const ADDR_B = '0xdAC17F958D2ee523a2206206994597C13D831ec7';

// Scriptable stub chain client: meta per address, optional failure injection.
function stubClient(scenarios) {
  const calls = { count: 0 };
  return {
    calls,
    async getBytecode({ address }) {
      calls.count += 1;
      const s = scenarios[address.toLowerCase()];
      if (!s) throw new Error('no scenario');
      if (s.fail) throw new Error(s.fail);
      return s.bytecode;
    },
    async getStorageAt() {
      return '0x0000000000000000000000000000000000000000000000000000000000000000';
    }
  };
}

const scratchDirs = [];
function tempDir() {
  // Sandbox-safe scratch dirs: under the project (gitignored data/), cleaned up after tests.
  const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
  fs.mkdirSync(root, { recursive: true });
  const dir = fs.mkdtempSync(path.join(root, 'assertara-sched-'));
  scratchDirs.push(dir);
  return dir;
}
function cleanupScratch() {
  for (const dir of scratchDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
  try { fs.rmdirSync(root); } catch { /* non-empty or gone: leave it */ }
}

function makeScheduler(dir, opts = {}) {
  let now = opts.now0 === undefined ? 1000000 : opts.now0;
  const clock = { get: () => now, advance: (ms) => { now += ms; } };
  const sched = new WatchScheduler({ dir, now: clock.get, ...(opts.extra || {}) });
  if (opts.client) sched.client = opts.client;
  return { sched, clock };
}

async function runSchedulerTests() {
  console.log('Testing Night Watch Scheduler: CRUD, Persistence, Locks, Alerts...\n');

  // Test 1: CRUD + pause/resume/remove + validation.
  {
    const { sched } = makeScheduler(tempDir());
    const t = sched.addTarget({ address: ADDR_A, label: 'vault', intervalMs: 60000 });
    assert.ok(/^w_[0-9a-f]+$/.test(t.id), 'Target ids are internal');
    assert.strictEqual(t.paused, false);
    assert.strictEqual(sched.listTargets().length, 1);
    assert.strictEqual(sched.pauseTarget(t.id).paused, true);
    assert.strictEqual(sched.resumeTarget(t.id).paused, false);
    assert.strictEqual(sched.removeTarget(t.id), true);
    assert.strictEqual(sched.listTargets().length, 0);
    assert.throws(() => sched.addTarget({ address: '0x123', intervalMs: 60000 }), /0x address/);
    assert.throws(() => sched.addTarget({ address: ADDR_A, intervalMs: 5 }), /between/);
    assert.throws(() => sched.pauseTarget('w_nope'), /unknown target/);
    console.log('✔ Test 1 Passed: Target CRUD with validation.');
  }

  // Test 2: persistence across restart.
  {
    const dir = tempDir();
    const { sched } = makeScheduler(dir);
    sched.addTarget({ address: ADDR_A, intervalMs: 60000 });
    const { sched: reopened } = makeScheduler(dir);
    const targets = reopened.listTargets();
    assert.strictEqual(targets.length, 1);
    assert.strictEqual(targets[0].address, ADDR_A);
    console.log('✔ Test 2 Passed: Targets persist across restart.');
  }

  // Test 3: corrupt state quarantined, never silent, never crashing.
  {
    const dir = tempDir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'nightwatch.json'), '{not json');
    const { sched } = makeScheduler(dir);
    const summary = await sched.tickOnce();
    assert.strictEqual(summary.recovered, true, 'Corruption must be reported');
    assert.deepStrictEqual(sched.listTargets(), []);
    const leftovers = fs.readdirSync(dir).filter((f) => f.startsWith('nightwatch.corrupt-'));
    assert.strictEqual(leftovers.length, 1, 'Corrupt file must be quarantined, not deleted');
    // Malformed entries dropped, valid ones kept.
    fs.writeFileSync(path.join(dir, 'nightwatch.json'), JSON.stringify({
      version: 1,
      targets: {
        w_abc: { address: 'bogus', intervalMs: 60000 },
        w_def: { address: ADDR_A, intervalMs: 60000, paused: true }
      },
      alerts: []
    }));
    const summary2 = await sched.tickOnce();
    assert.strictEqual(summary2.droppedEntries, 1);
    assert.strictEqual(sched.listTargets().length, 1);
    console.log('✔ Test 3 Passed: Corrupt state quarantined; bad entries dropped.');
  }

  // Test 4: missed runs fire exactly once, no backlog replay.
  {
    const dir = tempDir();
    const client = stubClient({ [ADDR_A.toLowerCase()]: { bytecode: '0x11' } });
    const { sched, clock } = makeScheduler(dir, { client });
    sched.addTarget({ address: ADDR_A, intervalMs: 60000 });
    clock.advance(10 * 3600 * 1000); // far past due
    const summary = await sched.tickOnce();
    assert.strictEqual(summary.checked, 1, 'Missed schedule must fire exactly once');
    assert.strictEqual(client.calls.count, 1);
    const [t] = sched.listTargets();
    assert.strictEqual(t.nextDue, clock.get() + 60000, 'Schedule restarts from now');
    console.log('✔ Test 4 Passed: Single catch-up check, no backlog.');
  }

  // Test 5: locks — duplicates blocked, stale recovered, release on stop.
  {
    const dir = tempDir();
    const { sched: a } = makeScheduler(dir);
    const { sched: b } = makeScheduler(dir);
    await a.start();
    await assert.rejects(b.start(), /another scheduler instance/, 'Second instance must be blocked');
    await a.stop();
    assert.strictEqual(fs.existsSync(path.join(dir, '.nightwatch.lock')), false, 'Stop must release the lock');
    await b.start();
    await b.stop();
    // Stale lock (crashed holder) is recoverable.
    fs.writeFileSync(path.join(dir, '.nightwatch.lock'), JSON.stringify({ token: 'dead', pid: 999999, at: 1 }));
    const { sched: c } = makeScheduler(dir);
    await c.start();
    await c.stop();
    console.log('✔ Test 5 Passed: Locking, duplicate prevention, stale recovery.');
  }

  // Test 6: change detection with duplicate-alert suppression.
  {
    const dir = tempDir();
    let code = '0x11';
    const client = {
      calls: { count: 0 },
      async getBytecode() { client.calls.count += 1; return code; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    const { sched, clock } = makeScheduler(dir, { client });
    sched.addTarget({ address: ADDR_A, intervalMs: 5000 });
    clock.advance(6000);
    const t1 = await sched.tickOnce();
    assert.strictEqual(t1.alerted, 0, 'First snapshot establishes a baseline, not an alert');
    clock.advance(6000);
    const t2 = await sched.tickOnce();
    assert.strictEqual(t2.alerted, 0, 'Unchanged state must not alert');
    code = '0x1122';
    clock.advance(6000);
    const t3 = await sched.tickOnce();
    assert.strictEqual(t3.alerted, 1, 'Real change must alert once');
    assert.strictEqual(sched.getAlerts({}).length, 1);
    assert.strictEqual(sched.getAlerts({})[0].changes[0].field, 'bytecodeLength');
    clock.advance(6000);
    const t4 = await sched.tickOnce();
    assert.strictEqual(t4.alerted, 0, 'Same change must not re-alert');
    assert.strictEqual(sched.getAlerts({}).length, 1);
    console.log('✔ Test 6 Passed: Change alerts fire once per change.');
  }

  // Test 7: per-target failure backs off without stopping healthy targets.
  {
    const dir = tempDir();
    const client = stubClient({
      [ADDR_A.toLowerCase()]: { fail: 'RPC down' },
      [ADDR_B.toLowerCase()]: { bytecode: '0x22' }
    });
    const { sched, clock } = makeScheduler(dir, { client });
    sched.addTarget({ address: ADDR_A, intervalMs: 5000 });
    sched.addTarget({ address: ADDR_B, intervalMs: 5000 });
    clock.advance(6000);
    const summary = await sched.tickOnce();
    assert.strictEqual(summary.failed, 1);
    assert.strictEqual(summary.checked, 1, 'Healthy target must still be checked');
    const byAddr = Object.fromEntries(sched.listTargets().map((t) => [t.address, t]));
    assert.strictEqual(byAddr[ADDR_A].consecutiveFailures, 1);
    assert.ok(byAddr[ADDR_A].nextDue > clock.get() + 5000, 'Failures must back off past the normal interval');
    assert.ok(byAddr[ADDR_A].lastError.includes('RPC down'));
    console.log('✔ Test 7 Passed: Isolated failures with backoff.');
  }

  // Test 8: graceful shutdown stops scheduling and frees the lock.
  {
    const dir = tempDir();
    const { sched } = makeScheduler(dir, { extra: { tickMs: 20 } });
    await sched.start();
    assert.strictEqual(sched.running, true);
    await sched.stop();
    assert.strictEqual(sched.running, false);
    assert.strictEqual(fs.existsSync(path.join(dir, '.nightwatch.lock')), false);
    await sched.stop(); // idempotent, must not throw
    console.log('✔ Test 8 Passed: Clean shutdown and idempotent stop.');
  }

  // Test 9: invalid inputs rejected everywhere (covered in T1/T3, plus update paths).
  {
    const dir = tempDir();
    const { sched } = makeScheduler(dir);
    const t = sched.addTarget({ address: ADDR_A, intervalMs: 60000 });
    assert.throws(() => sched.updateTarget(t.id, { intervalMs: 1 }), /between/);
    assert.throws(() => sched.updateTarget('w_missing', { paused: true }), /unknown target/);
    assert.throws(() => sched.removeTarget('w_missing'), /unknown target/);
    console.log('✔ Test 9 Passed: Invalid inputs rejected on all paths.');
  }

  // Test 10: existing manual runner behavior unchanged (regression guard).
  {
    const client = stubClient({ [ADDR_A.toLowerCase()]: { bytecode: '0x11' } });
    const first = await runWatchCheck({ watch: { address: ADDR_A } }, { client });
    assert.strictEqual(first.lane, 'manual');
    assert.ok(first.baselineEstablished, 'Manual runner still establishes baselines');
    assert.strictEqual(first.changed, false);
    console.log('✔ Test 10 Passed: Manual runner behavior preserved.');
  }

  console.log('\nAll Scheduler Tests Passed Successfully!\n');
}

if (require.main === module) {
  runSchedulerTests()
    .then(() => { cleanupScratch(); })
    .catch((err) => { cleanupScratch(); console.error(err); process.exit(1); });
}

module.exports = { runSchedulerTests };
