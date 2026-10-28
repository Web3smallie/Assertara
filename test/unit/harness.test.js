const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { submitHarnessRun, detectCapabilities, parseVersion } = require('../../src/agent/harness');
const { runTool } = require('../../src/agent/toolRegistry');
const { runFeature } = require('../../src/agent/features');

// ---- Scripted test-double executor ----
// Exercises the RUNNER's logic (validation, timeout, truncation, cleanup,
// adjudication). It never executes anything; production has no executor and
// returns EXECUTION_UNAVAILABLE (proven by Test 2 with no double).
function testDouble(script) {
  const calls = [];
  let aborts = 0;
  let n = 0;
  return {
    calls,
    aborted: () => aborts,
    name: 'test-double',
    async run(job) {
      const step = script[Math.min(n, script.length - 1)];
      n += 1;
      calls.push({ workspaceDir: job.workspaceDir, entry: job.entry });
      if (step.delayMs) await new Promise((r) => { const t = setTimeout(r, step.delayMs); if (t.unref) t.unref(); });
      if (step.throw) throw new Error(step.throw);
      if (step.malformed) return { noExitCode: true };
      return { exitCode: step.exitCode === undefined ? 0 : step.exitCode, signal: null, stdout: step.stdout || '', stderr: step.stderr || '' };
    },
    async abort() { aborts += 1; }
  };
}

const FILES = [{ path: 'test/Poc.t.sol', content: '// synthetic poc\ncontract P {}\n' }];
const ENTRY = { tool: 'forge', args: ['test', '--match-test', 'testPoc'] };

const scratchDirs = [];
function tempRoot() {
  const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
  fs.mkdirSync(root, { recursive: true });
  const dir = fs.mkdtempSync(path.join(root, 'assertara-harness-'));
  scratchDirs.push(dir);
  return dir;
}
function cleanupScratch() {
  for (const dir of scratchDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
  try { fs.rmdirSync(root); } catch { /* non-empty or gone: leave it */ }
}

async function runHarnessTests() {
  console.log('Testing Harness: Detection, Validation, Timeouts & Adjudication...\n');

  // Test 1: capability detection — real negative plus parser branches.
  {
    const live = await detectCapabilities();
    assert.strictEqual(live.docker.available, false, 'Docker must be honestly absent here');
    assert.strictEqual(live.podman.available, false, 'Podman must be honestly absent here');
    assert.strictEqual(live.canExecuteIsolated, false);
    assert.ok(typeof live.checkedAt === 'string');
    assert.strictEqual(parseVersion('Docker version 28.1.1, build abc'), '28.1.1');
    assert.strictEqual(parseVersion('no version here'), null);
    // Stubbed probe proves the daemon-down branch without a daemon.
    const stubProbe = async (bin, args) => {
      if (args[0] === '--version') return { ok: true, code: 0, stdout: `${bin} version 1.2.3` };
      return { ok: false, code: 1, stdout: '' };
    };
    const down = await detectCapabilities({ probe: stubProbe });
    assert.strictEqual(down.docker.available, false);
    assert.ok(down.docker.error.includes('daemon-unreachable'));
    assert.strictEqual(down.canExecuteIsolated, false);
    console.log('✔ Test 1 Passed: Detection reports absence honestly; parser covered.');
  }

  // Test 2: no executor -> EXECUTION_UNAVAILABLE; static needs nothing.
  {
    const res = await submitHarnessRun({ kind: 'execute', files: FILES, entry: ENTRY }, { workspaceRoot: tempRoot() });
    assert.strictEqual(res.status, 'EXECUTION_UNAVAILABLE');
    assert.strictEqual(res.environment.executor, 'none');
    assert.ok(res.capabilities && res.capabilities.canExecuteIsolated === false);
    assert.ok(res.requirements.length >= 2, 'Must state what is missing');
    assert.strictEqual(res.testEvidence, undefined, 'Unavailable runs carry no proof');
    const viaTool = await runTool('sandbox_exec', { kind: 'execute', files: FILES, entry: ENTRY });
    assert.strictEqual(viaTool.status, 'EXECUTION_UNAVAILABLE');
    const viaFeature = await runFeature('F15_harness', { execute: true, kind: 'execute', files: FILES, entry: ENTRY }, {});
    assert.strictEqual(viaFeature.status, 'EXECUTION_UNAVAILABLE');
    const statik = await submitHarnessRun({ kind: 'static', files: FILES });
    assert.strictEqual(statik.status, 'STATIC_ANALYSIS_ONLY');
    console.log('✔ Test 2 Passed: Unavailable execution is honest on all entry points.');
  }

  // Test 3: request validation accepts valid, rejects invalid with codes.
  {
    const ok = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { executor: testDouble([{}]), workspaceRoot: tempRoot() }
    );
    assert.strictEqual(ok.status, 'EXECUTION_COMPLETED');
    assert.deepStrictEqual(ok.command, ['forge', 'test', '--match-test', 'testPoc']);
    assert.ok(/^[0-9a-f]{64}$/.test(ok.requestHash) && /^[0-9a-f]{64}$/.test(ok.filesHash));
    const bad = [
      [{}, 'INVALID_KIND'],
      [{ kind: 'execute', files: [] }, 'INVALID_FILES'],
      [{ kind: 'execute', files: [{ path: '/abs.sol', content: 'x' }], entry: ENTRY }, 'BAD_PATH'],
      [{ kind: 'execute', files: [{ path: '../escape.sol', content: 'x' }], entry: ENTRY }, 'BAD_PATH'],
      [{ kind: 'execute', files: [{ path: 'a.sol', content: 'x'.repeat(300 * 1024) }], entry: ENTRY }, 'FILE_TOO_LARGE'],
      [{ kind: 'execute', files: FILES, entry: { tool: 'bash', args: ['-c', 'evil'] } }, 'TOOL_DENIED'],
      [{ kind: 'execute', files: FILES, entry: { tool: 'forge', args: 'not-array' } }, 'BAD_ARGS'],
      [{ kind: 'reproduce', files: FILES, entry: ENTRY }, 'CRITERION_REQUIRED'],
      [{ kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'stdout-regex', pattern: '([' } }, 'BAD_CRITERION'],
      [{ kind: 'execute', files: FILES, entry: ENTRY, timeoutMs: 1 }, 'BAD_LIMITS'],
      [{ kind: 'verify-patch', files: FILES, poc: { entry: ENTRY, criterion: { type: 'exit-code', code: 0 } } }, 'PATCH_REQUEST_INCOMPLETE']
    ];
    for (const [input, code] of bad) {
      await assert.rejects(submitHarnessRun(input, { workspaceRoot: tempRoot() }), (e) => e.code === code, `expected ${code}`);
    }
    await assert.rejects(runTool('sandbox_exec', { kind: 'execute', files: [] }), /non-empty array/, 'Tool pre-validates');
    console.log('✔ Test 3 Passed: Valid requests run; invalid ones throw coded errors.');
  }

  // Test 4: wall-clock timeout aborts and never hangs the runner.
  {
    const root = tempRoot();
    const ex = testDouble([{ delayMs: 5000, stdout: 'slow' }]);
    const res = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY, timeoutMs: 1000 },
      { executor: ex, workspaceRoot: root }
    );
    assert.strictEqual(res.status, 'EXECUTION_TIMED_OUT');
    assert.strictEqual(ex.aborted(), 1, 'Abort must be requested on timeout');
    assert.strictEqual(fs.existsSync(path.join(root, res.runId)), false, 'Workspace cleaned after timeout');
    assert.strictEqual(res.testEvidence, undefined);
    console.log('✔ Test 4 Passed: Timeouts abort, clean up, and carry no proof.');
  }

  // Test 5: output truncation + structured executor errors.
  {
    const big = 'A'.repeat(5000);
    const res = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY, maxLogChars: 1000 },
      { executor: testDouble([{ stdout: big, stderr: big }]), workspaceRoot: tempRoot() }
    );
    assert.strictEqual(res.status, 'EXECUTION_COMPLETED');
    assert.strictEqual(res.run.stdout.truncated, true);
    assert.ok(res.run.stdout.text.includes('…[truncated 4000 chars]'));
    assert.ok(res.run.stdout.text.length < 1200);
    const failed = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { executor: testDouble([{ throw: 'container died' }]), workspaceRoot: tempRoot() }
    );
    assert.strictEqual(failed.status, 'EXECUTION_FAILED');
    assert.ok(String(failed.error).length > 0 && !('stack' in failed), 'Structured error, no stack leak');
    const malformed = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { executor: testDouble([{ malformed: true }]), workspaceRoot: tempRoot() }
    );
    assert.strictEqual(malformed.status, 'EXECUTION_FAILED');
    const nonzero = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { executor: testDouble([{ exitCode: 3 }]), workspaceRoot: tempRoot() }
    );
    assert.strictEqual(nonzero.status, 'EXECUTION_FAILED');
    console.log('✔ Test 5 Passed: Logs truncate explicitly; errors stay structured.');
  }

  // Test 6: workspaces are staged per run and always cleaned.
  {
    const root = tempRoot();
    const ex = testDouble([{}, { throw: 'boom' }]);
    const first = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { executor: ex, workspaceRoot: root }
    );
    assert.strictEqual(ex.calls.length, 1);
    assert.ok(ex.calls[0].workspaceDir.startsWith(root), 'Run executes in its own workspace');
    assert.strictEqual(fs.existsSync(path.join(root, first.runId)), false, 'Workspace cleaned after success');
    const second = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { executor: ex, workspaceRoot: root }
    );
    assert.strictEqual(second.status, 'EXECUTION_FAILED');
    assert.strictEqual(fs.existsSync(path.join(root, second.runId)), false, 'Workspace cleaned after failure');
    assert.notStrictEqual(first.runId, second.runId, 'Run ids are unique');
    console.log('✔ Test 6 Passed: Per-run workspaces staged and removed.');
  }

  // Test 7: completion is not reproduction; criterion decides.
  {
    const root = tempRoot();
    const repro = await submitHarnessRun(
      { kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'stdout-contains', text: 'EXPLOIT_OK' } },
      { executor: testDouble([{ exitCode: 0, stdout: 'line1\nEXPLOIT_OK\n' }]), workspaceRoot: root }
    );
    assert.strictEqual(repro.status, 'VULNERABILITY_REPRODUCED');
    assert.strictEqual(repro.criterionMet, true);
    const missed = await submitHarnessRun(
      { kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'stdout-contains', text: 'EXPLOIT_OK' } },
      { executor: testDouble([{ exitCode: 0, stdout: 'all tests passed, nothing found' }]), workspaceRoot: root }
    );
    assert.strictEqual(missed.status, 'NOT_REPRODUCED', 'Exit 0 without the marker must not reproduce');
    assert.strictEqual(missed.criterionMet, false);
    const regexHit = await submitHarnessRun(
      { kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'stdout-regex', pattern: 'drained:\\s*\\d+' } },
      { executor: testDouble([{ exitCode: 1, stdout: 'drained: 100' }]), workspaceRoot: root }
    );
    assert.strictEqual(regexHit.status, 'VULNERABILITY_REPRODUCED', 'Criterion decides, not the exit code');
    console.log('✔ Test 7 Passed: Only satisfied criteria reproduce; completion alone never does.');
  }

  // Test 8: weak evidence can never yield a verified status.
  {
    const root = tempRoot();
    const weak = [
      await submitHarnessRun({ kind: 'execute', files: FILES, entry: ENTRY }, { workspaceRoot: root }),
      await submitHarnessRun({ kind: 'execute', files: FILES, entry: ENTRY }, { executor: testDouble([{ throw: 'x' }]), workspaceRoot: root }),
      await submitHarnessRun({ kind: 'execute', files: FILES, entry: ENTRY, timeoutMs: 1000 }, { executor: testDouble([{ delayMs: 5000 }]), workspaceRoot: root }),
      await submitHarnessRun(
        { kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'exit-code', code: 0 } },
        { executor: testDouble([{ exitCode: 7 }]), workspaceRoot: root }
      )
    ];
    assert.deepStrictEqual(weak.map((r) => r.status), ['EXECUTION_UNAVAILABLE', 'EXECUTION_FAILED', 'EXECUTION_TIMED_OUT', 'NOT_REPRODUCED']);
    assert.ok(weak.every((r) => r.testEvidence === undefined), 'No proof may ride on weak runs');
    assert.ok(weak.every((r) => r.status !== 'PATCH_VERIFIED' && r.status !== 'VULNERABILITY_REPRODUCED'));
    console.log('✔ Test 8 Passed: Unavailable/failed/timed-out/missed runs stay unverified.');
  }

  // Test 9: patch verification demands blocked-PoC AND green suite.
  {
    const root = tempRoot();
    const mkPatch = (pocOut, suiteCode) => ({
      kind: 'verify-patch',
      files: [{ path: 'src/Vault.sol', content: '// patched\n' }],
      poc: { entry: ENTRY, criterion: { type: 'stdout-contains', text: 'EXPLOIT_OK' } },
      suite: { entry: { tool: 'forge', args: ['test'] }, criterion: { type: 'exit-code', code: 0 } },
      __script: [{ stdout: pocOut }, { exitCode: suiteCode, stdout: 'suite done' }]
    });
    const goodInput = mkPatch('poc blocked: no marker here', 0);
    const good = await submitHarnessRun(goodInput, { executor: testDouble(goodInput.__script), workspaceRoot: root });
    assert.strictEqual(good.status, 'PATCH_VERIFIED');
    assert.deepStrictEqual(good.testEvidence.passed, true);
    assert.ok(good.testEvidence.logs.includes('poc-blocked'));
    // Mapping proof: harness evidence feeds the ledger transition (ledger decides).
    const { runAuditIntake, runAuditTransition } = require('../../src/agent/features');
    const intake = runAuditIntake({ findings: [{ id: 'H-1', description: 'x' }] });
    const opened = runAuditTransition({ record: intake.records[0], newStatus: 'OPEN' });
    const claimed = runAuditTransition({ record: opened.record, newStatus: 'FIX_CLAIMED' });
    const fixed = runAuditTransition({ record: claimed.record, newStatus: 'VERIFIED_FIXED', testEvidence: good.testEvidence });
    assert.strictEqual(fixed.status, 'OK', 'Ledger accepts harness proof via its own transition');
    const badPoc = mkPatch('EXPLOIT_OK still here', 0);
    const stillVuln = await submitHarnessRun(badPoc, { executor: testDouble(badPoc.__script), workspaceRoot: root });
    assert.strictEqual(stillVuln.status, 'EXECUTION_COMPLETED');
    assert.strictEqual(stillVuln.patchVerdict, 'STILL_VULNERABLE');
    assert.strictEqual(stillVuln.testEvidence, undefined);
    const badSuite = mkPatch('poc blocked', 4);
    const suiteFail = await submitHarnessRun(badSuite, { executor: testDouble(badSuite.__script), workspaceRoot: root });
    assert.strictEqual(suiteFail.status, 'EXECUTION_COMPLETED');
    assert.strictEqual(suiteFail.patchVerdict, 'SUITE_FAILED');
    console.log('✔ Test 9 Passed: PATCH_VERIFIED needs blocked PoC + green suite; ledger mapping proven.');
  }

  // Test 10: Phase 1–3 regression (experimental cap, scheduler, PDF ingest).
  {
    const { adjudicate } = require('../../src/agent/verifier');
    const { EvidenceGraph } = require('../../src/agent/evidenceGraph');
    const g = new EvidenceGraph('inv_phase4reg');
    const exp = g.append({ kind: 'ModelReading', producer: 'MODEL', payload: { experimental: true }, created_turn: 1 });
    const capped = adjudicate({ supporting: [exp.id], conflicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(capped.status, 'HYPOTHESIS', 'Phase 1 experimental safeguard intact');
    const { WatchScheduler } = require('../../src/agent/scheduler');
    let now = Date.now();
    const sched = new WatchScheduler({ dir: tempRoot(), now: () => now });
    sched.client = {
      async getBytecode() { return '0x11'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    sched.addTarget({ address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', intervalMs: 5000 });
    now += 6000;
    const summary = await sched.tickOnce();
    assert.strictEqual(summary.checked, 1, 'Phase 2 scheduler intact');
    const { buildPdf } = require('./pdfIngest.test.js');
    const { ingestAuditPdf } = require('../../src/agent/pdfIngest');
    const pdf = await ingestAuditPdf({ data: buildPdf([['H-01 Regression check', 'Body.']]) });
    assert.strictEqual(pdf.findings.length, 1, 'Phase 3 PDF ingest intact');
    assert.strictEqual(pdf.findings[0].sourceId, 'H-01');
    console.log('✔ Test 10 Passed: Phases 1–3 behavior preserved.');
  }

  console.log('\nAll Harness Tests Passed Successfully!\n');
}

if (require.main === module) {
  runHarnessTests()
    .then(() => { cleanupScratch(); })
    .catch((err) => { cleanupScratch(); console.error(err); process.exit(1); });
}

module.exports = { runHarnessTests };
