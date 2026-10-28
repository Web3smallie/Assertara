const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { submitHarnessRun } = require('../../src/agent/harness');
const { runTool } = require('../../src/agent/toolRegistry');
const { verifySandbox, createSandboxExecutor, buildRunArgv } = require('../../src/agent/sandbox');

// ---- Injected runtime doubles ----
// Every test below injects spawnFn: no real container runtime is touched.
// The double records every argv so tests can prove WHAT would have run
// (restrictions, no pulls, no shell) without executing anything.
const IMAGE = 'assertara/sandbox-foundry:1.0.0';
const DIGEST = `sha256:${'a'.repeat(64)}`;
const OTHER_DIGEST = `sha256:${'b'.repeat(64)}`;

function enoent(bin) {
  const err = new Error(`spawn ${bin} ENOENT`);
  err.code = 'ENOENT';
  return err;
}

// Healthy docker: version ok, daemon ok, image present with DIGEST.
function healthyHandler(opts = {}) {
  const calls = [];
  const runQueue = opts.runQueue ? [...opts.runQueue] : null;
  const single = opts.runResult || { exitCode: 0, stdout: 'container ok\n', stderr: '' };
  const fn = async (argv) => {
    calls.push(argv);
    const rest = argv.slice(1);
    if (rest[0] === '--version') return { exitCode: 0, stdout: 'Docker version 28.1.1, build abc\n', stderr: '' };
    if (rest[0] === 'info') return { exitCode: 0, stdout: '28.1.1\n', stderr: '' };
    if (rest[0] === 'image') {
      const id = opts.imageId === undefined ? DIGEST : opts.imageId;
      const digests = opts.repoDigests === undefined ? [`${IMAGE}@${DIGEST}`] : opts.repoDigests;
      if (opts.imageMissing) return { exitCode: 1, stdout: '', stderr: 'Error: No such image' };
      return { exitCode: 0, stdout: `${id} ${JSON.stringify(digests)}\n`, stderr: '' };
    }
    if (rest[0] === 'run') {
      if (opts.hangRun) return new Promise(() => {});
      const r = runQueue ? runQueue.shift() || runQueue[runQueue.length - 1] : single;
      if (r && r.throw) throw new Error(r.throw);
      if (r && r.malformed) return { noExitCode: true };
      return { exitCode: r.exitCode === undefined ? 0 : r.exitCode, stdout: r.stdout || '', stderr: r.stderr || '', ...(r.signal ? { signal: r.signal } : {}) };
    }
    if (rest[0] === 'rm' || rest[0] === 'kill') return { exitCode: 0, stdout: '', stderr: '' };
    throw new Error(`unexpected argv: ${argv.join(' ')}`);
  };
  fn.calls = calls;
  return fn;
}

const scratchDirs = [];
function tempRoot() {
  const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
  fs.mkdirSync(root, { recursive: true });
  const dir = fs.mkdtempSync(path.join(root, 'assertara-sandbox-'));
  scratchDirs.push(dir);
  return dir;
}
function cleanupScratch() {
  for (const dir of scratchDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
  try { fs.rmdirSync(root); } catch { /* non-empty or gone: leave it */ }
}

const FILES = [{ path: 'test/Poc.t.sol', content: '// synthetic poc\ncontract P {}\n' }];
const ENTRY = { tool: 'forge', args: ['test', '--match-test', 'testPoc'] };

function runArgv(calls) {
  const found = calls.find((a) => a[1] === 'run');
  assert.ok(found, 'expected a container run invocation');
  return found;
}

async function runSandboxTests() {
  console.log('Testing Sandbox: Verification, Isolation Flags & Fail-Closed Routing...\n');

  // Test 1: missing runtime binaries fail closed; no run is ever attempted.
  {
    const spawnFn = healthyHandler();
    const missing = async (argv) => { spawnFn.calls.push(argv); throw enoent(argv[0]); };
    missing.calls = spawnFn.calls;
    const check = await verifySandbox({ runtime: 'auto', image: IMAGE, workspaceRoot: tempRoot(), spawnFn: missing });
    assert.strictEqual(check.ok, false);
    assert.strictEqual(check.stage, 'runtime');
    assert.ok(check.requirements.length >= 1);
    assert.ok(missing.calls.every((a) => a[1] === '--version'), 'only version probes are issued');
    assert.ok(missing.calls.length === 2, 'both docker and podman probed');
    const res = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { workspaceRoot: tempRoot(), sandbox: { enabled: true, image: IMAGE, spawnFn: missing } }
    );
    assert.strictEqual(res.status, 'EXECUTION_UNAVAILABLE');
    assert.strictEqual(res.sandbox.stage, 'runtime');
    assert.ok(res.note.includes('nothing was executed'));
    console.log('✔ Test 1 Passed: Missing runtime fails closed with requirements.');
  }

  // Test 2: binary present but daemon unreachable is a distinct stage.
  {
    const calls = [];
    const spawnFn = async (argv) => {
      calls.push(argv);
      if (argv[1] === '--version') return { exitCode: 0, stdout: 'Docker version 28.1.1, build x\n', stderr: '' };
      if (argv[1] === 'info') return { exitCode: 1, stdout: '', stderr: 'Cannot connect to the Docker daemon' };
      throw new Error(`unexpected argv: ${argv.join(' ')}`);
    };
    const check = await verifySandbox({ runtime: 'docker', image: IMAGE, workspaceRoot: tempRoot(), spawnFn });
    assert.strictEqual(check.ok, false);
    assert.strictEqual(check.stage, 'daemon');
    assert.ok(check.requirements.some((r) => r.includes('daemon')));
    console.log('✔ Test 2 Passed: Daemon-down is reported distinctly from binary-missing.');
  }

  // Test 3: missing image refuses execution; nothing runs.
  {
    const spawnFn = healthyHandler({ imageMissing: true });
    const check = await verifySandbox({
      runtime: 'docker', image: IMAGE, expectedDigest: DIGEST, workspaceRoot: tempRoot(), spawnFn,
    });
    assert.strictEqual(check.ok, false);
    assert.strictEqual(check.stage, 'image');
    assert.ok(check.error.includes(IMAGE));
    assert.ok(!spawnFn.calls.some((a) => a[1] === 'run'), 'no container runs before image verification');
    console.log('✔ Test 3 Passed: Missing image fails closed before any run.');
  }

  // Test 4: digest mismatch refuses execution even when the image is present.
  {
    const spawnFn = healthyHandler({ imageId: OTHER_DIGEST, repoDigests: [`${IMAGE}@${OTHER_DIGEST}`] });
    const check = await verifySandbox({
      runtime: 'docker', image: IMAGE, expectedDigest: DIGEST, workspaceRoot: tempRoot(), spawnFn,
    });
    assert.strictEqual(check.ok, false);
    assert.strictEqual(check.stage, 'image');
    assert.ok(check.error.includes('does not match'));
    assert.ok(!spawnFn.calls.some((a) => a[1] === 'run'));
    // And a matching digest verifies.
    const good = healthyHandler();
    const ok = await verifySandbox({
      runtime: 'docker', image: IMAGE, expectedDigest: DIGEST, workspaceRoot: tempRoot(), spawnFn: good,
    });
    assert.strictEqual(ok.ok, true);
    assert.strictEqual(ok.digestVerified, true);
    assert.strictEqual(ok.executor.mode, 'sandboxed');
    console.log('✔ Test 4 Passed: Digest mismatch refuses; matching digest verifies.');
  }

  // Test 5: verified runs carry every mandatory restriction, argv-only, no pulls.
  {
    const root = tempRoot();
    const ws = path.join(root, 'h_abc123');
    fs.mkdirSync(ws, { recursive: true });
    const spawnFn = healthyHandler();
    const check = await verifySandbox({ runtime: 'docker', image: IMAGE, workspaceRoot: root, spawnFn });
    assert.strictEqual(check.ok, true);
    const out = await check.executor.run({ workspaceDir: ws, entry: ENTRY, timeoutMs: 5000 });
    assert.strictEqual(out.exitCode, 0);
    const argv = runArgv(spawnFn.calls);
    const has = (flag, val) => {
      const at = argv.indexOf(flag);
      return at !== -1 && (val === undefined || argv[at + 1] === val);
    };
    assert.ok(has('--rm'), '--rm present');
    assert.ok(has('--pull', 'never'), 'image pulls disabled');
    assert.ok(has('--network', 'none'), 'network disabled');
    assert.ok(has('--cap-drop', 'ALL'), 'capabilities dropped');
    assert.ok(has('--security-opt', 'no-new-privileges'), 'no-new-privileges set');
    assert.ok(has('--read-only'), 'read-only rootfs');
    assert.ok(has('--memory', '512m') && has('--cpus', '1.0') && has('--pids-limit', '128'), 'resource limits set');
    assert.ok(has('--stop-timeout', '5'), 'stop timeout set');
    const tmpfs = argv[argv.indexOf('--tmpfs') + 1];
    assert.ok(tmpfs.includes('noexec') && tmpfs.includes('nosuid') && tmpfs.includes('size='), 'tmpfs hardened + bounded');
    assert.ok(has('-v', `${ws}:/work`), 'only the per-run workspace is mounted');
    assert.ok(has('--workdir', '/work'));
    assert.ok(!argv.includes('--privileged'), 'privileged mode never set');
    assert.ok(!argv.some((a) => a.includes('.env') || a.includes('docker.sock')), 'no secrets or daemon socket mounted');
    assert.ok(!argv.some((a, i) => i > 1 && a === 'pull'), 'no pull subcommand anywhere');
    const imgAt = argv.indexOf(IMAGE);
    assert.ok(imgAt !== -1, 'pinned image used');
    assert.ok(has('--entrypoint', 'forge'), 'image ENTRYPOINT overridden with the validated tool');
    assert.ok(argv.indexOf('--entrypoint') < imgAt, 'entrypoint flag precedes the image');
    assert.deepStrictEqual(argv.slice(imgAt + 1), ['test', '--match-test', 'testPoc'], 'args forwarded as argv, unmodified');
    assert.ok(!argv.includes('/bin/sh'), 'no shell binary in argv');
    assert.ok(!argv.some((a) => /[;&|`$]/.test(a) && a !== argv[argv.indexOf('--tmpfs') + 1]), 'no shell metachar assembly');
    console.log('✔ Test 5 Passed: Every restriction present; entry forwarded argv-only.');
  }

  // Test 6: invalid operator configuration is rejected loudly (never defaulted).
  {
    const root = tempRoot();
    const noop = async () => { throw new Error('must not probe'); };
    for (const bad of ['BAD IMAGE', '', 'x'.repeat(301), 'evil;rm -rf', '../escape:tag', 'UPPERCASE_OK?no:bad char!']) {
      await assert.rejects(
        verifySandbox({ runtime: 'docker', image: bad, workspaceRoot: root, spawnFn: noop }),
        (e) => e.code === 'SANDBOX_CONFIG', `bad image rejected: ${String(bad).slice(0, 20)}`
      );
    }
    await assert.rejects(verifySandbox({ runtime: 'lxc', image: IMAGE, workspaceRoot: root, spawnFn: noop }), (e) => e.code === 'SANDBOX_CONFIG');
    await assert.rejects(verifySandbox({ runtime: 'docker', workspaceRoot: root, spawnFn: noop }), (e) => e.code === 'SANDBOX_CONFIG');
    await assert.rejects(verifySandbox({ runtime: 'docker', image: IMAGE, workspaceRoot: 'relative/path', spawnFn: noop }), (e) => e.code === 'SANDBOX_CONFIG');
    await assert.rejects(
      verifySandbox({ runtime: 'docker', image: IMAGE, expectedDigest: 'sha256:zzz', workspaceRoot: root, spawnFn: noop }),
      (e) => e.code === 'SANDBOX_CONFIG'
    );
    assert.throws(() => createSandboxExecutor({ image: IMAGE, workspaceRoot: root }), (e) => e.code === 'SANDBOX_CONFIG', 'auto runtime needs verifySandbox first');
    assert.throws(() => createSandboxExecutor({ runtime: 'docker', workspaceRoot: root }), (e) => e.code === 'SANDBOX_CONFIG', 'image is required');
    // Invalid config through the harness fails closed to UNAVAILABLE (no throw, no run).
    const res = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { workspaceRoot: tempRoot(), sandbox: { enabled: true, image: 'BAD IMAGE', spawnFn: noop } }
    );
    assert.strictEqual(res.status, 'EXECUTION_UNAVAILABLE');
    assert.strictEqual(res.sandbox.stage, 'config');
    console.log('✔ Test 6 Passed: Bad config rejected; harness maps it to UNAVAILABLE.');
  }

  // Test 7: workspace escapes and unsafe names are rejected; runtime untouched.
  {
    const root = tempRoot();
    const spawnFn = healthyHandler();
    const check = await verifySandbox({ runtime: 'docker', image: IMAGE, workspaceRoot: root, spawnFn });
    const ex = check.executor;
    const before = spawnFn.calls.length;
    for (const bad of [
      path.join(root, '..', 'escape'),
      path.resolve(root, '..'),
      'relative/dir',
      `${root}\0x`,
      path.join(root, 'has space'),
      path.join(root, '..'),
    ]) {
      await assert.rejects(ex.run({ workspaceDir: bad, entry: ['true'], timeoutMs: 1000 }), (e) => e.code === 'SANDBOX_WORKSPACE', `escape rejected: ${bad}`);
    }
    assert.strictEqual(spawnFn.calls.length, before, 'no runtime invocation on rejected paths');
    // A valid nested workspace proceeds.
    const ws = path.join(root, 'h_valid1');
    fs.mkdirSync(ws, { recursive: true });
    await ex.run({ workspaceDir: ws, entry: ['true'], timeoutMs: 1000 });
    assert.ok(spawnFn.calls.length > before);
    console.log('✔ Test 7 Passed: Workspace escapes rejected before any runtime call.');
  }

  // Test 8: invalid commands are rejected; runtime untouched.
  {
    const root = tempRoot();
    const spawnFn = healthyHandler();
    const check = await verifySandbox({ runtime: 'docker', image: IMAGE, workspaceRoot: root, spawnFn });
    const ex = check.executor;
    const ws = path.join(root, 'h_cmd1');
    fs.mkdirSync(ws, { recursive: true });
    const before = spawnFn.calls.length;
    for (const bad of [null, undefined, [], [''], ['ok', 42], { tool: '', args: [] }, { tool: 'forge' }, { tool: 'x\0y', args: [] }, 'forge test']) {
      await assert.rejects(ex.run({ workspaceDir: ws, entry: bad, timeoutMs: 1000 }), (e) => e.code === 'SANDBOX_COMMAND');
    }
    assert.strictEqual(spawnFn.calls.length, before, 'no runtime invocation on rejected commands');
    console.log('✔ Test 8 Passed: Malformed entries rejected before any runtime call.');
  }

  // Test 9: abort kills the container by name and cleans up; idle abort is a no-op.
  {
    const root = tempRoot();
    const spawnFn = healthyHandler({ hangRun: true });
    const check = await verifySandbox({ runtime: 'docker', image: IMAGE, workspaceRoot: root, spawnFn });
    const ex = check.executor;
    const idle = await ex.abort();
    assert.deepStrictEqual(idle, { aborted: false });
    const ws = path.join(root, 'h_abort1');
    fs.mkdirSync(ws, { recursive: true });
    const pending = ex.run({ workspaceDir: ws, entry: ['sleep', '60'], timeoutMs: 60000 });
    await new Promise((r) => setTimeout(r, 25));
    const ab = await ex.abort();
    assert.strictEqual(ab.aborted, true);
    assert.ok(ab.container.startsWith('assertara-h_abort1-'), `container name derived from workspace: ${ab.container}`);
    const kinds = spawnFn.calls.map((a) => a[1]);
    assert.ok(kinds.includes('kill'), 'kill issued on abort');
    assert.ok(kinds.includes('rm'), 'rm -f issued on abort');
    const kill = spawnFn.calls.find((a) => a[1] === 'kill');
    assert.deepStrictEqual(kill, ['docker', 'kill', ab.container]);
    await Promise.race([pending, new Promise((r) => setTimeout(r, 100))]); // let the hung run settle-dangling
    console.log('✔ Test 9 Passed: Abort kills + removes the container; idle abort is a no-op.');
  }

  // Test 10: harness routes execute-kind runs through the sandbox only when strictly enabled.
  {
    const root = tempRoot();
    const spawnFn = healthyHandler();
    const res = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { workspaceRoot: root, sandbox: { enabled: true, runtime: 'docker', image: IMAGE, expectedDigest: DIGEST, spawnFn } }
    );
    assert.strictEqual(res.status, 'EXECUTION_COMPLETED');
    assert.strictEqual(res.environment.executor, 'sandbox:docker');
    assert.strictEqual(res.environment.mode, 'sandboxed');
    assert.strictEqual(res.environment.sandbox.image, IMAGE);
    assert.strictEqual(res.environment.sandbox.digestVerified, true);
    assert.strictEqual(fs.readdirSync(root).length, 0, 'per-run workspace cleaned after success');
    // Strict enablement: truthy-but-not-true and false both stay unavailable.
    for (const enabled of [false, 'yes', 1, undefined]) {
      const r = await submitHarnessRun(
        { kind: 'execute', files: FILES, entry: ENTRY },
        { workspaceRoot: tempRoot(), sandbox: { enabled, image: IMAGE, spawnFn: healthyHandler() } }
      );
      assert.strictEqual(r.status, 'EXECUTION_UNAVAILABLE', `enabled=${String(enabled)} must not enable`);
      assert.strictEqual(r.sandbox, undefined, 'disabled sandbox leaves no sandbox block');
    }
    console.log('✔ Test 10 Passed: Explicit-enable routing with sandboxed labeling + cleanup.');
  }

  // Test 11: the production path can only ever invoke the container runtime CLI.
  {
    const root = tempRoot();
    const spawnFn = healthyHandler({ runResult: { exitCode: 0, stdout: 'EXPLOIT_OK\n', stderr: '' } });
    const res = await submitHarnessRun(
      { kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'stdout-contains', text: 'EXPLOIT_OK' } },
      { workspaceRoot: root, sandbox: { enabled: true, runtime: 'docker', image: IMAGE, spawnFn } }
    );
    assert.strictEqual(res.status, 'VULNERABILITY_REPRODUCED');
    assert.ok(spawnFn.calls.length > 0);
    assert.ok(spawnFn.calls.every((a) => a[0] === 'docker'), 'every host process is the docker CLI');
    assert.ok(spawnFn.calls.every((a) => Array.isArray(a)), 'argv arrays only, never a shell string');
    // Source guard: only argv-form spawn exists; no shell exec anywhere.
    const sandboxSrc = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'agent', 'sandbox.js'), 'utf8');
    const harnessSrc = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'agent', 'harness.js'), 'utf8');
    for (const [name, src] of [['sandbox.js', sandboxSrc], ['harness.js', harnessSrc]]) {
      assert.ok(!src.includes('execSync'), `${name}: no execSync`);
      assert.ok(!/shell\s*:\s*true/.test(src), `${name}: no shell:true`);
      const imports = [...src.matchAll(/const\s*\{\s*([^{}]*)\}\s*=\s*require\(['"]child_process['"]\)/g)];
      assert.ok(imports.length >= 1, `${name}: child_process import visible to guard`);
      for (const m of imports) assert.strictEqual(m[1].trim(), 'spawn', `${name}: only spawn is imported`);
    }
    assert.ok(sandboxSrc.includes('spawn(argv[0], argv.slice(1)'), 'argv-only spawn preserved');
    console.log('✔ Test 11 Passed: Only the runtime CLI is invoked; source guard holds.');
  }

  // Test 12: reproduction vs patch-verification boundaries survive sandbox routing.
  {
    const root = tempRoot();
    const mk = (runQueue) => healthyHandler({ runQueue });
    // Reproduce met / not met.
    const met = await submitHarnessRun(
      { kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'stdout-contains', text: 'EXPLOIT_OK' } },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn: mk([{ exitCode: 0, stdout: 'line\nEXPLOIT_OK\n' }]) } }
    );
    assert.strictEqual(met.status, 'VULNERABILITY_REPRODUCED');
    assert.strictEqual(met.environment.mode, 'sandboxed');
    const unmet = await submitHarnessRun(
      { kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'stdout-contains', text: 'EXPLOIT_OK' } },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn: mk([{ exitCode: 0, stdout: 'nothing found' }]) } }
    );
    assert.strictEqual(unmet.status, 'NOT_REPRODUCED');
    assert.ok(unmet.note.includes('not proof of safety'));
    // Patch verified: PoC blocked + suite green.
    const poc = { entry: ENTRY, criterion: { type: 'stdout-contains', text: 'EXPLOIT_OK' } };
    const suite = { entry: { tool: 'forge', args: ['test'] }, criterion: { type: 'exit-code', code: 0 } };
    const good = await submitHarnessRun(
      { kind: 'verify-patch', files: FILES, poc, suite },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn: mk([{ exitCode: 0, stdout: 'blocked' }, { exitCode: 0, stdout: 'suite green' }]) } }
    );
    assert.strictEqual(good.status, 'PATCH_VERIFIED');
    assert.strictEqual(good.testEvidence.passed, true);
    // Patch rejected: PoC still reproduces.
    const bad = await submitHarnessRun(
      { kind: 'verify-patch', files: FILES, poc, suite },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn: mk([{ exitCode: 0, stdout: 'EXPLOIT_OK' }, { exitCode: 0, stdout: 'suite green' }]) } }
    );
    assert.strictEqual(bad.status, 'EXECUTION_COMPLETED');
    assert.strictEqual(bad.patchVerdict, 'STILL_VULNERABLE');
    assert.strictEqual(bad.testEvidence, undefined, 'rejected patches carry no proof');
    console.log('✔ Test 12 Passed: Repro/patch boundaries preserved through the sandbox.');
  }

  // Test 13: oversized output truncates; executor failures become FAILED (never crash, always cleaned).
  {
    const root = tempRoot();
    const big = 'x'.repeat(60000);
    const trunc = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn: healthyHandler({ runResult: { exitCode: 0, stdout: big, stderr: big } }) } }
    );
    assert.strictEqual(trunc.status, 'EXECUTION_COMPLETED');
    assert.strictEqual(trunc.run.stdout.truncated, true);
    assert.strictEqual(trunc.run.stderr.truncated, true);
    const boom = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn: healthyHandler({ runQueue: [{ throw: 'container died' }] }) } }
    );
    assert.strictEqual(boom.status, 'EXECUTION_FAILED');
    assert.ok(boom.error.includes('container died'));
    const malformed = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn: healthyHandler({ runQueue: [{ malformed: true }] }) } }
    );
    assert.strictEqual(malformed.status, 'EXECUTION_FAILED');
    const exit3 = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn: healthyHandler({ runQueue: [{ exitCode: 3 }] }) } }
    );
    assert.strictEqual(exit3.status, 'EXECUTION_FAILED');
    assert.strictEqual(fs.readdirSync(root).length, 0, 'workspaces cleaned after failures too');
    console.log('✔ Test 13 Passed: Truncation + structured failure handling hold.');
  }

  // Test 14: wall-clock timeout kills the container and cleans the workspace.
  {
    const root = tempRoot();
    const spawnFn = healthyHandler({ hangRun: true });
    const res = await submitHarnessRun(
      { kind: 'execute', files: FILES, entry: ENTRY, timeoutMs: 1000 },
      { workspaceRoot: root, sandbox: { enabled: true, image: IMAGE, spawnFn } }
    );
    assert.strictEqual(res.status, 'EXECUTION_TIMED_OUT');
    assert.strictEqual(res.abortRequested, true);
    const kinds = spawnFn.calls.map((a) => a[1]);
    assert.ok(kinds.includes('kill'), 'timed-out run kills the container');
    assert.ok(kinds.filter((k) => k === 'rm').length >= 1, 'cleanup runs after timeout');
    assert.strictEqual(fs.readdirSync(root).length, 0, 'workspace cleaned after timeout');
    console.log('✔ Test 14 Passed: Timeout kills the container; workspace cleaned.');
  }

  // Test 15: static lane needs no sandbox; the model-callable tool cannot enable it.
  {
    const spawnFn = healthyHandler();
    const statik = await submitHarnessRun(
      { kind: 'static', files: FILES },
      { workspaceRoot: tempRoot(), sandbox: { enabled: true, image: IMAGE, spawnFn } }
    );
    assert.strictEqual(statik.status, 'STATIC_ANALYSIS_ONLY');
    assert.strictEqual(spawnFn.calls.length, 0, 'static lane never probes the runtime');
    const viaTool = await runTool('sandbox_exec', { kind: 'execute', files: FILES, entry: ENTRY });
    assert.strictEqual(viaTool.status, 'EXECUTION_UNAVAILABLE', 'tool path cannot pass operator sandbox config');
    assert.strictEqual(viaTool.sandbox, undefined);
    console.log('✔ Test 15 Passed: Static lane clean; tool path cannot enable sandbox.');
  }

  // Test 17: the image ENTRYPOINT is overridden so the command executes
  // directly with no shell. Placed before T16 (which stays last) because
  // T16's live negative is environment-sensitive. E.g.
  // ghcr.io/foundry-rs/foundry ships ENTRYPOINT ["/bin/sh","-c"], which
  // would otherwise swallow every argument after the image name.
  {
    const root = tempRoot();
    const ws = path.join(root, 'h_entry1');
    fs.mkdirSync(ws, { recursive: true });
    const spawnFn = healthyHandler();
    const check = await verifySandbox({ runtime: 'docker', image: IMAGE, workspaceRoot: root, spawnFn });
    assert.strictEqual(check.ok, true);
    // Object-form entry: the tool becomes --entrypoint, args trail the image.
    await check.executor.run({ workspaceDir: ws, entry: { tool: 'forge', args: ['--version'] }, timeoutMs: 1000 });
    let argv = runArgv(spawnFn.calls);
    let imgAt = argv.indexOf(IMAGE);
    let epAt = argv.indexOf('--entrypoint');
    assert.ok(epAt !== -1, '--entrypoint override present');
    assert.strictEqual(argv[epAt + 1], 'forge', 'entrypoint is the validated tool');
    assert.ok(epAt < imgAt, 'entrypoint flag precedes the image');
    assert.deepStrictEqual(argv.slice(imgAt + 1), ['--version'], 'args trail the image verbatim');
    assert.ok(!argv.includes('/bin/sh'), 'no shell binary anywhere in argv');
    assert.ok(!argv.some((a) => a === '-c'), 'no shell -c anywhere in argv');
    // Args carrying spaces and shell metacharacters survive as single tokens
    // (a shell would split or expand them).
    const tricky = ['test', '--match-test', 'a b;c|d$e`f"g'];
    await check.executor.run({ workspaceDir: ws, entry: { tool: 'forge', args: tricky }, timeoutMs: 1000 });
    const runs = spawnFn.calls.filter((a) => a[1] === 'run');
    assert.strictEqual(runs.length, 2);
    argv = runs[1];
    imgAt = argv.indexOf(IMAGE);
    assert.deepStrictEqual(argv.slice(imgAt + 1), tricky, 'metachar args pass through unsplit, unexpanded');
    assert.strictEqual(argv[argv.indexOf('--entrypoint') + 1], 'forge');
    // Single-token entries run with no trailing args.
    await check.executor.run({ workspaceDir: ws, entry: ['true'], timeoutMs: 1000 });
    argv = spawnFn.calls.filter((a) => a[1] === 'run')[2];
    imgAt = argv.indexOf(IMAGE);
    assert.strictEqual(argv[argv.indexOf('--entrypoint') + 1], 'true');
    assert.deepStrictEqual(argv.slice(imgAt + 1), [], 'bare entrypoint, no trailing args');
    // buildRunArgv rejects an empty entry directly (defense in depth).
    assert.throws(
      () => buildRunArgv({ runtime: 'docker', image: IMAGE, workspaceDir: ws, entry: [], limits: undefined, containerName: 'x' }),
      (e) => e.code === 'SANDBOX_COMMAND'
    );
    console.log('✔ Test 17 Passed: Entrypoint overridden; command executes directly, no shell.');
  }

  // Test 16: unavailable states are never success-shaped; real negative probe here.
  {
    const spawnFn = async (argv) => { throw enoent(argv[0]); };
    const res = await submitHarnessRun(
      { kind: 'reproduce', files: FILES, entry: ENTRY, criterion: { type: 'stdout-contains', text: 'EXPLOIT_OK' } },
      { workspaceRoot: tempRoot(), sandbox: { enabled: true, image: IMAGE, spawnFn } }
    );
    assert.strictEqual(res.status, 'EXECUTION_UNAVAILABLE');
    assert.strictEqual(res.testEvidence, undefined);
    assert.strictEqual(res.run, undefined);
    assert.ok(Array.isArray(res.requirements) && res.requirements.length > 0);
    // Real probe against this machine (no doubles): must fail closed, honestly.
    const live = await verifySandbox({ runtime: 'auto', image: IMAGE, workspaceRoot: tempRoot() });
    assert.strictEqual(live.ok, false, 'no runtime here, so verification must fail');
    assert.strictEqual(live.stage, 'runtime');
    const { checkReadiness } = require('../../src/agent/readiness');
    const rec = await checkReadiness('exec.harness');
    assert.strictEqual(rec.status, 'UNAVAILABLE');
    assert.strictEqual(rec.evidence.adapter, 'shipped');
    console.log('✔ Test 16 Passed: Unavailable is never success-shaped; live negative verified.');
  }

  console.log('\nAll Sandbox Tests Passed Successfully!\n');
}

if (require.main === module) {
  runSandboxTests()
    .then(() => { cleanupScratch(); })
    .catch((err) => { cleanupScratch(); console.error(err); process.exit(1); });
}

module.exports = { runSandboxTests };
