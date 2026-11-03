const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Demo A orchestrator tests: argument validation, artifact rules,
// stage ordering/fail-fast, and secret redaction. All stages run
// through injected fakes: no network, no chain, no model, no keys.

const { runDemoA, parseArgs, setupOutDir, DEFAULTS } = require('../../demo/demoA');

const TMP = path.join(__dirname, '..', 'tmp');
const DIGEST = 'e'.repeat(64);
const ATTESTER = `0x${'c'.repeat(40)}`;
const KEY_A = `0x${'a'.repeat(63)}1`;
const KEY_B = `0x${'b'.repeat(63)}2`;

function fixtureKeys(tag) {
  const dir = fs.mkdtempSync(path.join(TMP, `demoA-${tag}-`));
  const attFile = path.join(dir, 'att.key');
  const pubFile = path.join(dir, 'pub.key');
  const regFile = path.join(dir, 'registry.json');
  fs.writeFileSync(attFile, `${KEY_A}\n`, 'utf8');
  fs.writeFileSync(pubFile, `${KEY_B}\n`, 'utf8');
  fs.writeFileSync(regFile, JSON.stringify({ keys: {} }), 'utf8');
  return { dir, attFile, pubFile, regFile };
}

function baseArgv(fx, extra) {
  return ['--policy-base', 'http://127.0.0.1:3001', '--signer-base', 'http://127.0.0.1:3002',
    '--anvil-rpc', 'http://127.0.0.1:8545', '--registry', fx.regFile,
    '--trusted-root', `0x${'d'.repeat(40)}`, '--trusted-authorities', ATTESTER,
    '--attestation-key-file', fx.attFile, '--publisher-key-file', fx.pubFile,
    '--out-dir', path.join(fx.dir, 'run'), ...(extra || [])];
}

function fakeDeps(calls, overrides) {
  const order = [];
  const deps = {
    validateReuse: async () => { order.push('validate'); calls.push('validateReuse'); },
    health: async () => { calls.push('health'); return { ok: true }; },
    provenanceSurface: async () => { calls.push('provenanceSurface'); return true; },
    runAgent: async () => {
      order.push('agent'); calls.push('runAgent');
      return { actions: [{ requestId: 'req_1', traceId: 'tr_1', decision: 'ALLOW', txHash: `0x${'ab'.repeat(32)}`, provenance: { manifestDigest: DIGEST } }] };
    },
    postJson: async () => {
      order.push('manifest'); calls.push('postJson');
      return { manifestDigest: DIGEST, manifest: { investigationId: 'eval_1', decision: { agent: 'ALLOW' } } };
    },
    findStackTmp: () => { calls.push('findStackTmp'); return path.join(TMP, 'none'); },
    buildV1Package: () => { order.push('package'); calls.push('buildV1Package'); return { manifest: { investigationId: 'eval_1' } }; },
    ceremony: async ({ confirm }) => {
      order.push(confirm ? 'sign' : 'preview'); calls.push(confirm ? 'sign' : 'preview');
      if (!confirm) return { code: 'ATTEST_PREVIEW', preview: { manifestDigest: DIGEST }, caseInfo: { case: 'D' } };
      return { attested: true, code: 'ATTEST_COMPLETED', attestation: { authority: ATTESTER, body: {} } };
    },
    runExport: async ({ outFile }) => {
      order.push('export'); calls.push('runExport');
      fs.writeFileSync(outFile, JSON.stringify({ format: 'assertara-attestation-export-1', manifestDigest: DIGEST, package: { manifest: { investigationId: 'eval_1' } } }), 'utf8');
      return { code: 0, stdout: 'exported', stderr: '' };
    },
    publish: async () => { order.push('publish'); calls.push('publish'); return { ok: true, submitted: true, txHash: `0x${'cd'.repeat(32)}` }; },
    runJudge: async (args) => { order.push('judge'); calls.push('runJudge'); calls.push(`runJudge:submitTx=${(args && args.submitTx) || '(none)'}`); return { code: 0, stdout: 'judge: [PASS] chain-record\njudge: VERDICT PASS\n', stderr: '' }; },
    openCommandCentre: async () => { calls.push('open'); return { code: 0, stdout: '', stderr: '' }; },
    ...(overrides || {})
  };
  return { deps, order };
}

function captureIo() {
  const lines = [];
  return { io: { log: (...a) => lines.push(a.join(' ')), error: (...a) => lines.push(a.join(' ')) }, lines };
}

async function runDemoATests() {
  console.log('Testing Demo A orchestrator...\n');
  fs.mkdirSync(TMP, { recursive: true });

  // Test 1: argument parsing + validation.
  {
    const fx = fixtureKeys('args');
    const o = parseArgs(baseArgv(fx));
    assert.strictEqual(o.policyBase, 'http://127.0.0.1:3001', 'policy base parsed');
    assert.strictEqual(o.contract, DEFAULTS.contract, 'contract default');
    assert.strictEqual(o.chainId, 5042002, 'chain default');
    assert.strictEqual(o.open, true, 'browser opens by default');
    assert.throws(() => parseArgs(baseArgv(fx).filter((a, i, arr) => a !== '--registry' && arr[i - 1] !== '--registry')), /--registry is required/, 'registry required');
    assert.throws(() => parseArgs([...baseArgv(fx), '--nope']), /unknown option/, 'unknown flag rejected');
    const badRoot = baseArgv(fx).slice();
    badRoot[badRoot.indexOf('--trusted-root') + 1] = 'zzz';
    assert.throws(() => parseArgs(badRoot), /--trusted-root must be an address/, 'root validated');
    const badVer = baseArgv(fx).concat(['--contract-version', '3']);
    assert.throws(() => parseArgs(badVer), /--contract-version must be 1 or 2/, 'version validated');
    assert.deepStrictEqual(parseArgs(['--help']), { help: true }, '--help short-circuits');
    console.log('✔ Test 1 Passed: argument parsing + validation.');
  }

  // Test 2: artifact directory rules (no silent overwrite).
  {
    const d1 = setupOutDir(null, false);
    const d2 = setupOutDir(null, false);
    assert.notStrictEqual(d1, d2, 'default runs get unique dirs');
    assert.ok(fs.statSync(d1).isDirectory() && fs.statSync(d2).isDirectory(), 'default dirs created');
    const explicit = path.join(TMP, `demoA-explicit-${Date.now()}`);
    assert.strictEqual(setupOutDir(explicit, false), path.resolve(explicit), 'fresh explicit dir accepted');
    fs.writeFileSync(path.join(explicit, 'x.txt'), 'x', 'utf8');
    assert.throws(() => setupOutDir(explicit, false), /refusing to overwrite/, 'non-empty dir refused');
    assert.strictEqual(setupOutDir(explicit, true), path.resolve(explicit), '--force reuses');
    console.log('✔ Test 2 Passed: unique runs; overwrite requires --force.');
  }

  // Test 3: full success path through fakes, in order.
  {
    const fx = fixtureKeys('ok');
    const calls = [];
    const { deps, order } = fakeDeps(calls);
    const { io, lines } = captureIo();
    const res = await runDemoA(baseArgv(fx), deps, io);
    assert.strictEqual(res.ok, true, 'run ok');
    assert.strictEqual(res.summary.judge, 'PASS', 'summary judge');
    assert.strictEqual(res.summary.manifestDigest, DIGEST, 'summary digest');
    assert.strictEqual(res.summary.attester, ATTESTER, 'summary attester');
    assert.ok(res.summary.txHash, 'summary txHash');
    assert.ok(res.centre.includes('trace=tr_1'), 'centre URL carries trace');
    assert.deepStrictEqual(order, ['validate', 'agent', 'manifest', 'package', 'preview', 'sign', 'export', 'publish', 'judge'], 'stages in order');
    for (const f of ['outcome.json', 'manifest.json', 'demo-run.v1.json', 'ceremony-preview.json', 'ceremony.json', 'demo-run.att.json', 'publish.json', 'judge.txt', 'run.json']) {
      assert.ok(fs.existsSync(path.join(fx.dir, 'run', f)), `artifact ${f} written`);
    }
    assert.ok(lines.some((l) => l.includes('DEMO A PASSED')), 'final PASSED line printed');
    assert.ok(calls.includes(`runJudge:submitTx=0x${'cd'.repeat(32)}`), 'judge receives the publication hash (skips log discovery)');
    console.log('✔ Test 3 Passed: success path runs every stage in order + summary.');
  }

  // Test 4: fail-fast — a refused preview aborts before sign/publish/judge.
  {
    const fx = fixtureKeys('fail');
    const calls = [];
    const { deps } = fakeDeps(calls, {
      ceremony: async ({ confirm }) => {
        calls.push(confirm ? 'sign' : 'preview');
        if (!confirm) return { attested: false, code: 'ATTEST_PACKAGE_INVALID', failedChecks: [] };
        throw new Error('sign must not run after a refused preview');
      }
    });
    const { io } = captureIo();
    await assert.rejects(runDemoA(baseArgv(fx), deps, io), /FAILED at stage ceremony-preview/, 'refusal aborts at preview');
    assert.ok(!calls.includes('sign'), 'sign never ran');
    assert.ok(!calls.includes('publish'), 'publish never ran');
    assert.ok(!calls.includes('runJudge'), 'judge never ran');
    console.log('✔ Test 4 Passed: preview refusal aborts; nothing downstream runs.');
  }

  // Test 5: non-ALLOW agent outcome aborts before provenance.
  {
    const fx = fixtureKeys('block');
    const calls = [];
    const { deps } = fakeDeps(calls, {
      runAgent: async () => {
        calls.push('runAgent');
        return { actions: [{ requestId: 'req_b', traceId: 'tr_b', decision: 'BLOCK' }] };
      }
    });
    const { io } = captureIo();
    await assert.rejects(runDemoA(baseArgv(fx), deps, io), /Demo A must ALLOW/, 'BLOCK aborts');
    assert.ok(!calls.includes('postJson'), 'no manifest after non-ALLOW');
    console.log('✔ Test 5 Passed: non-ALLOW aborts before provenance.');
  }

  // Test 6: secrets never appear in logs or artifacts, including on failure.
  {
    const fx = fixtureKeys('redact');
    const calls = [];
    const { deps } = fakeDeps(calls, {
      publish: async () => { calls.push('publish'); throw new Error('rpc refused: quota exceeded'); }
    });
    const { io, lines } = captureIo();
    await assert.rejects(runDemoA(baseArgv(fx), deps, io), /FAILED at stage publish/, 'publish failure surfaces');
    const haystack = [lines.join('\n')];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else haystack.push(fs.readFileSync(full, 'utf8'));
      }
    };
    walk(path.join(fx.dir, 'run'));
    for (const blob of haystack) {
      assert.ok(!blob.includes(KEY_A), 'attestation key absent from output/artifacts');
      assert.ok(!blob.includes(KEY_B), 'publisher key absent from output/artifacts');
      assert.ok(!blob.includes(KEY_A.slice(2)), 'attestation key (unprefixed) absent');
    }
    console.log('✔ Test 6 Passed: key material never leaks into logs or artifacts.');
  }

  // Test 7: --skip-publish stops after export with an honest summary.
  {
    const fx = fixtureKeys('skip');
    const calls = [];
    const { deps } = fakeDeps(calls);
    const { io, lines } = captureIo();
    const res = await runDemoA(baseArgv(fx, ['--skip-publish', '--no-open']), deps, io);
    assert.strictEqual(res.ok, true, 'skip run ok');
    assert.ok(!calls.includes('publish'), 'no publish attempted');
    assert.ok(!calls.includes('runJudge'), 'no judge attempted');
    assert.ok(!calls.includes('open'), 'browser suppressed');
    assert.ok(String(res.summary.judge).startsWith('SKIPPED'), 'summary says SKIPPED, never PASS');
    assert.ok(lines.some((l) => l.includes('COMPLETED (unpublished)')), 'no false PASSED line');
    console.log('✔ Test 7 Passed: --skip-publish ends honestly after export.');
  }

  // Test 8: stale backend (no provenance surface) aborts in preflight.
  {
    const fx = fixtureKeys('stale');
    const calls = [];
    const { deps } = fakeDeps(calls, {
      provenanceSurface: async () => {
        calls.push('provenanceSurface');
        throw new Error('policy backend does not serve the provenance API (stale stack?)');
      }
    });
    const { io } = captureIo();
    await assert.rejects(runDemoA(baseArgv(fx), deps, io), /FAILED at stage preflight.*stale stack/, 'stale backend aborts early');
    assert.ok(!calls.includes('runAgent'), 'no agent run against a stale backend');
    console.log('✔ Test 8 Passed: stale backend detected before any live work.');
  }

  // Test 9: judge verdict parsing matches the real CLI format
  // (`judge: VERDICT PASS`, no colon) and still rejects failures.
  {
    const fx = fixtureKeys('judgeverdict');
    const good = [];
    const { deps: goodDeps } = fakeDeps(good, {
      runJudge: async () => ({ code: 0, stdout: 'judge: [PASS] chain-record\njudge: VERDICT PASS\n', stderr: '' })
    });
    const res = await runDemoA(baseArgv(fx, ['--out-dir', path.join(fx.dir, 'run-good')]), goodDeps, captureIo().io);
    assert.strictEqual(res.summary.judge, 'PASS', 'real CLI verdict format accepted');
    const bad = [];
    const { deps: badDeps } = fakeDeps(bad, {
      runJudge: async () => ({ code: 0, stdout: 'judge: [FAIL] chain-record\njudge: VERDICT FAIL\n', stderr: '' })
    });
    await assert.rejects(
      runDemoA(baseArgv(fx, ['--out-dir', path.join(fx.dir, 'run-bad')]), badDeps, captureIo().io),
      /FAILED at stage judge/, 'VERDICT FAIL with exit 0 still fails the stage'
    );
    const nz = [];
    const { deps: nzDeps } = fakeDeps(nz, {
      runJudge: async () => ({ code: 1, stdout: 'judge: VERDICT FAIL\n', stderr: '' })
    });
    await assert.rejects(
      runDemoA(baseArgv(fx, ['--out-dir', path.join(fx.dir, 'run-nz')]), nzDeps, captureIo().io),
      /FAILED at stage judge/, 'nonzero judge exit still fails the stage'
    );
    console.log('✔ Test 9 Passed: judge verdict parsing matches the real CLI; failures still fail.');
  }

  console.log('\nAll Demo A orchestrator tests passed.');
}

if (require.main === module) {
  runDemoATests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runDemoATests };
