/**
 * Assertara Harness — isolated execution foundation for F15 (Agent-Harness
 * Power Tools). Internal interface only: no routes, no UI.
 *
 * What this module IS: request validation, per-run workspace staging,
 * capability detection, timeout enforcement, output truncation, guaranteed
 * cleanup, reproduction/patch adjudication against explicit criteria, and
 * evidence records with hashes. All of that is implemented and tested.
 *
 * Phase 18 ships the isolation boundary as ./sandbox (Docker/Podman
 * adapter): when explicitly enabled by OPERATOR configuration
 * (deps.sandbox.enabled === true, never model-callable), dynamic lanes run
 * inside a verified, network-disabled container. No Docker/Podman runtime is
 * available in this environment, so live sandbox execution is unverified
 * here and execute-kind requests honestly return EXECUTION_UNAVAILABLE.
 * Untrusted code is NEVER run on the host as a substitute. The executor
 * contract is documented in contracts.md §13/§27; tests exercise runner
 * logic through scripted doubles and the sandbox adapter's injected probes.
 *
 * Status vocabulary (never interchangeable):
 * - STATIC_ANALYSIS_ONLY: no execution requested; static review output only.
 * - EXECUTION_UNAVAILABLE: no isolation-capable executor in this environment.
 * - EXECUTION_FAILED: the run errored (spawn failure, nonzero exit without
 *   a satisfied criterion, malformed executor result).
 * - EXECUTION_TIMED_OUT: wall-clock limit exceeded; abort requested.
 * - EXECUTION_COMPLETED: finished without satisfying any reproduction
 *   criterion. Completion is NOT reproduction.
 * - VULNERABILITY_REPRODUCED: finished AND output satisfied the explicit
 *   reproduction criterion in the request.
 * - NOT_REPRODUCED: finished, criterion evaluated, NOT met. Absence of
 *   reproduction is NOT proof of safety.
 * - PATCH_VERIFIED: verify-patch request where the PoC no longer reproduces
 *   AND the regression suite passes. This result *supplies* testEvidence
 *   for the audit ledger; only runAuditTransition sets VERIFIED_FIXED.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const RUN_STATUSES = [
  'STATIC_ANALYSIS_ONLY', 'EXECUTION_UNAVAILABLE', 'EXECUTION_FAILED',
  'EXECUTION_TIMED_OUT', 'EXECUTION_COMPLETED', 'VULNERABILITY_REPRODUCED',
  'NOT_REPRODUCED', 'PATCH_VERIFIED'
];

const DEFAULT_LIMITS = {
  timeoutMs: 60000, minTimeoutMs: 1000, maxTimeoutMs: 600000,
  maxLogChars: 20000, maxLogCharsCap: 200000,
  maxFileBytes: 200 * 1024, maxTotalBytes: 1024 * 1024, maxFiles: 50,
  maxPathChars: 200, maxArgs: 30, maxArgChars: 500
};

// No shell is ever used (argv exec only); the tool itself is allowlisted.
const ALLOWED_TOOLS = ['forge', 'node', 'python3'];

function harnessError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function stableFiles(files) {
  return [...files]
    .sort((a, b) => (a.path < b.path ? -1 : 1))
    .map((f) => ({ path: f.path, sha256: sha256Hex(f.content) }));
}

function validatePath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > DEFAULT_LIMITS.maxPathChars) {
    throw harnessError('BAD_PATH', `file path must be 1-${DEFAULT_LIMITS.maxPathChars} chars`);
  }
  if (p.includes('\0')) throw harnessError('BAD_PATH', 'file path contains NUL');
  if (path.isAbsolute(p) || /^[A-Za-z]:[\\/]/.test(p)) throw harnessError('BAD_PATH', `absolute paths forbidden: ${p}`);
  const segs = p.split(/[\\/]/);
  if (segs.some((s) => s === '' || s === '.' || s === '..')) {
    throw harnessError('BAD_PATH', `path traversal forbidden: ${p}`);
  }
  return segs.join('/');
}

function validateFiles(files) {
  if (!Array.isArray(files) || files.length === 0) throw harnessError('INVALID_FILES', 'files must be a non-empty array');
  if (files.length > DEFAULT_LIMITS.maxFiles) throw harnessError('TOO_MANY_FILES', `at most ${DEFAULT_LIMITS.maxFiles} files per run`);
  let total = 0;
  const seen = new Set();
  for (const f of files) {
    if (!f || typeof f.content !== 'string') throw harnessError('INVALID_FILES', 'each file needs string path and content');
    const clean = validatePath(f.path);
    if (seen.has(clean)) throw harnessError('INVALID_FILES', `duplicate file path: ${clean}`);
    seen.add(clean);
    const bytes = Buffer.byteLength(f.content, 'utf8');
    if (bytes > DEFAULT_LIMITS.maxFileBytes) throw harnessError('FILE_TOO_LARGE', `${clean} exceeds ${DEFAULT_LIMITS.maxFileBytes} bytes`);
    total += bytes;
  }
  if (total > DEFAULT_LIMITS.maxTotalBytes) throw harnessError('FILE_TOO_LARGE', `total input exceeds ${DEFAULT_LIMITS.maxTotalBytes} bytes`);
  return files.map((f) => ({ path: validatePath(f.path), content: f.content }));
}

function validateEntry(entry, where) {
  if (!entry || typeof entry !== 'object') throw harnessError('BAD_ARGS', `${where}: entry {tool, args} required`);
  if (!ALLOWED_TOOLS.includes(entry.tool)) {
    throw harnessError('TOOL_DENIED', `${where}: tool must be one of ${ALLOWED_TOOLS.join(', ')}`);
  }
  if (!Array.isArray(entry.args)) throw harnessError('BAD_ARGS', `${where}: args must be an array`);
  if (entry.args.length > DEFAULT_LIMITS.maxArgs) throw harnessError('BAD_ARGS', `${where}: at most ${DEFAULT_LIMITS.maxArgs} args`);
  for (const a of entry.args) {
    if (typeof a !== 'string' || a.length === 0 || a.length > DEFAULT_LIMITS.maxArgChars || a.includes('\0')) {
      throw harnessError('BAD_ARGS', `${where}: each arg must be 1-${DEFAULT_LIMITS.maxArgChars} chars, no NUL`);
    }
  }
  return { tool: entry.tool, args: [...entry.args] };
}

function validateCriterion(c, where) {
  if (!c || typeof c !== 'object') throw harnessError('CRITERION_REQUIRED', `${where}: an explicit criterion is required`);
  if (c.type === 'exit-code') {
    if (!Number.isInteger(c.code)) throw harnessError('BAD_CRITERION', `${where}: exit-code criterion needs integer code`);
    return { type: 'exit-code', code: c.code };
  }
  if (c.type === 'stdout-contains') {
    if (typeof c.text !== 'string' || c.text.length === 0 || c.text.length > 500) {
      throw harnessError('BAD_CRITERION', `${where}: stdout-contains needs 1-500 chars of text`);
    }
    return { type: 'stdout-contains', text: c.text };
  }
  if (c.type === 'stdout-regex') {
    if (typeof c.pattern !== 'string' || c.pattern.length === 0 || c.pattern.length > 300) {
      throw harnessError('BAD_CRITERION', `${where}: stdout-regex needs a 1-300 char pattern`);
    }
    try { new RegExp(c.pattern); } catch { throw harnessError('BAD_CRITERION', `${where}: invalid regex pattern`); }
    return { type: 'stdout-regex', pattern: c.pattern };
  }
  throw harnessError('BAD_CRITERION', `${where}: criterion type must be exit-code, stdout-contains, or stdout-regex`);
}

function validateLimits(input) {
  const timeoutMs = input.timeoutMs === undefined ? DEFAULT_LIMITS.timeoutMs : input.timeoutMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs < DEFAULT_LIMITS.minTimeoutMs || timeoutMs > DEFAULT_LIMITS.maxTimeoutMs) {
    throw harnessError('BAD_LIMITS', `timeoutMs must be ${DEFAULT_LIMITS.minTimeoutMs}-${DEFAULT_LIMITS.maxTimeoutMs}ms`);
  }
  const maxLogChars = input.maxLogChars === undefined ? DEFAULT_LIMITS.maxLogChars : input.maxLogChars;
  if (!Number.isInteger(maxLogChars) || maxLogChars < 100 || maxLogChars > DEFAULT_LIMITS.maxLogCharsCap) {
    throw harnessError('BAD_LIMITS', `maxLogChars must be 100-${DEFAULT_LIMITS.maxLogCharsCap}`);
  }
  return { timeoutMs, maxLogChars };
}

function validateRequest(input) {
  if (!input || typeof input !== 'object') throw harnessError('INVALID_KIND', 'request must be an object with kind + files');
  const { kind } = input;
  if (!['static', 'execute', 'reproduce', 'verify-patch'].includes(kind)) {
    throw harnessError('INVALID_KIND', 'kind must be static, execute, reproduce, or verify-patch');
  }
  const files = validateFiles(input.files);
  const limits = validateLimits(input);
  const req = { kind, files, limits };
  if (kind === 'static') return req;
  if (kind === 'verify-patch') {
    if (!input.poc || !input.suite) throw harnessError('PATCH_REQUEST_INCOMPLETE', 'verify-patch requires poc {entry, criterion} and suite {entry, criterion}');
    req.poc = { entry: validateEntry(input.poc.entry, 'poc'), criterion: validateCriterion(input.poc.criterion, 'poc') };
    req.suite = { entry: validateEntry(input.suite.entry, 'suite'), criterion: validateCriterion(input.suite.criterion, 'suite') };
    return req;
  }
  req.entry = validateEntry(input.entry, 'entry');
  req.criterion = input.criterion === undefined ? null : validateCriterion(input.criterion, 'criterion');
  if (kind === 'reproduce' && !req.criterion) {
    throw harnessError('CRITERION_REQUIRED', 'reproduce requires an explicit criterion');
  }
  return req;
}

// ---- Capability detection (binary presence + daemon reachability) ----

function defaultProbe(bin, args, timeoutMs = 5000) {
  return new Promise((resolve) => {
    let stdout = '';
    let settled = false;
    const done = (result) => { if (!settled) { settled = true; resolve(result); } };
    let child;
    try {
      child = spawn(bin, args, { timeout: timeoutMs, windowsHide: true });
    } catch (err) {
      done({ ok: false, error: `spawn-failed: ${err.message}` });
      return;
    }
    child.stdout.on('data', (d) => { stdout += d.toString('utf8').slice(0, 4096); });
    child.on('error', (err) => done({ ok: false, error: err.code === 'ENOENT' ? 'not-installed' : `spawn-error: ${err.message}` }));
    child.on('close', (code) => done({ ok: code === 0, code, stdout: stdout.slice(0, 2000) }));
    setTimeout(() => { try { child.kill(); } catch {} done({ ok: false, error: 'probe-timeout' }); }, timeoutMs + 500).unref?.();
  });
}

function parseVersion(text) {
  const m = /(\d+\.\d+\.\d+)/.exec(String(text || ''));
  return m ? m[1] : null;
}

async function detectRuntime(name, versionArgs, daemonArgs, probe) {
  const ver = await probe(name, versionArgs);
  if (!ver.ok) {
    return { available: false, error: ver.error || `exit-${ver.code}` };
  }
  const daemon = await probe(name, daemonArgs);
  if (!daemon.ok) {
    return { available: false, version: parseVersion(ver.stdout), error: `daemon-unreachable: ${daemon.error || `exit-${daemon.code}`}` };
  }
  return { available: true, version: parseVersion(ver.stdout) || parseVersion(daemon.stdout) };
}

/**
 * Probe isolation-capable runtimes. WSL is deliberately NOT reported: even
 * when installed it provides no containment (network, fs, limits) and is
 * not an acceptable substitute for a sandbox.
 */
async function detectCapabilities(deps = {}) {
  const probe = deps.probe || defaultProbe;
  const docker = await detectRuntime('docker', ['--version'], ['info', '--format', '{{.ServerVersion}}'], probe);
  const podman = await detectRuntime('podman', ['--version'], ['info', '--format', '{{.Version.Version}}'], probe);
  return {
    docker, podman,
    canExecuteIsolated: docker.available || podman.available,
    checkedAt: new Date().toISOString(),
    note: 'Isolation requires a container runtime with no-network, read-only inputs, and enforced limits (see contracts §13).'
  };
}

// ---- Execution ----

let runCounter = 0;

function truncateLog(text, maxChars) {
  const s = String(text === undefined || text === null ? '' : text);
  if (s.length <= maxChars) return { text: s, truncated: false, dropped: 0 };
  return { text: `${s.slice(0, maxChars)}…[truncated ${s.length - maxChars} chars]`, truncated: true, dropped: s.length - maxChars };
}

function evaluateCriterion(criterion, result) {
  if (criterion.type === 'exit-code') return result.exitCode === criterion.code;
  const out = `${result.stdout || ''}\n${result.stderr || ''}`;
  if (criterion.type === 'stdout-contains') return out.includes(criterion.text);
  return new RegExp(criterion.pattern).test(out);
}

function stageWorkspace(root, runId, files) {
  const dir = path.join(root, runId);
  fs.mkdirSync(dir, { recursive: true });
  for (const f of files) {
    const dest = path.join(dir, f.path);
    if (path.relative(dir, dest).startsWith('..')) {
      throw harnessError('BAD_PATH', `staging escaped workspace: ${f.path}`);
    }
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, f.content, 'utf8');
  }
  return dir;
}

function cleanupWorkspace(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); return true; }
  catch { return false; }
}

async function runWithTimeout(executor, job, timeoutMs) {
  let timer = null;
  try {
    const result = await Promise.race([
      Promise.resolve().then(() => executor.run(job)),
      new Promise((resolve) => { timer = setTimeout(() => resolve({ __timeout: true }), timeoutMs); })
    ]);
    return result;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function baseRecord(runId, req, filesHash) {
  return {
    runId,
    kind: req.kind,
    requestHash: sha256Hex(JSON.stringify({ kind: req.kind, files: stableFiles(req.files), entry: req.entry || null, criterion: req.criterion || null, poc: req.poc || null, suite: req.suite || null })),
    filesHash,
    fileCount: req.files.length,
    environment: {
      executor: 'none',
      network: 'none-required',
      constraints: { timeoutMs: req.limits.timeoutMs, maxLogChars: req.limits.maxLogChars }
    },
    warnings: []
  };
}

/**
 * Submit one bounded harness run.
 * @param {Object} input — validated request (see validateRequest).
 * @param {{ executor?: { name, run({workspaceDir, entry, timeoutMs}), abort?() }, workspaceRoot?: string, capabilities?: Object, sandbox?: { enabled: boolean, runtime?: string, image?: string, expectedDigest?: string, limits?: Object, spawnFn?: Function } }} deps
 * Phase 18: deps.sandbox is OPERATOR configuration (strict enabled === true).
 * The sandbox_exec tool never passes it, so model calls cannot enable it.
 */
async function submitHarnessRun(input, deps = {}) {
  const req = validateRequest(input);
  const filesHash = sha256Hex(JSON.stringify(stableFiles(req.files)));
  runCounter += 1;
  const runId = `h_${sha256Hex(`${filesHash}:${Date.now()}:${runCounter}`).slice(0, 12)}`;
  const record = baseRecord(runId, req, filesHash);

  if (req.kind === 'static') {
    return {
      status: 'STATIC_ANALYSIS_ONLY', feature: 'F15_harness', lane: 'static',
      ...record,
      note: 'Static lane: no execution requested. PoC drafts remain UNEXECUTED until an isolated run exists.'
    };
  }

  // Phase 18 executor resolution order: (1) injected executor (scripted
  // test doubles in tests only), (2) operator-enabled sandbox adapter, (3)
  // none -> EXECUTION_UNAVAILABLE. The sandbox enables ONLY when
  // deps.sandbox.enabled === true (strict), which is operator configuration,
  // never model-callable. There is no host executor and no host fallback.
  const root = deps.workspaceRoot || path.join(__dirname, '..', '..', 'data', '.harness-runs');
  let executor = deps.executor && typeof deps.executor.run === 'function' ? deps.executor : null;
  let sandboxInfo = null;
  if (!executor && deps.sandbox && deps.sandbox.enabled === true) {
    const resolution = await resolveSandboxExecutor(deps.sandbox, root);
    if (!resolution.ok) {
      const capabilities = deps.capabilities || await detectCapabilities();
      return {
        status: 'EXECUTION_UNAVAILABLE', feature: 'F15_harness', lane: 'execute',
        ...record,
        capabilities,
        sandbox: { ok: false, stage: resolution.stage, error: resolution.error },
        requirements: resolution.requirements,
        note: 'Sandboxed execution was requested but sandbox verification failed; nothing was executed.'
      };
    }
    executor = resolution.executor;
    sandboxInfo = resolution.summary;
  }
  if (!executor || typeof executor.run !== 'function') {
    const capabilities = deps.capabilities || await detectCapabilities();
    return {
      status: 'EXECUTION_UNAVAILABLE', feature: 'F15_harness', lane: 'execute',
      ...record,
      capabilities,
      requirements: [
        'An isolation-capable container runtime (Docker or Podman) with a reachable daemon.',
        'No-network execution, read-only source inputs, per-run workspace, CPU/memory/output/time limits.',
        'See contracts §13/§27 for the sandbox executor contract and enablement steps.'
      ],
      note: 'Nothing was executed. Untrusted code is never run on the host as a substitute for a sandbox.'
    };
  }

  fs.mkdirSync(root, { recursive: true });
  const workspaceDir = stageWorkspace(root, runId, req.files);
  record.environment.executor = executor.name || 'unnamed-executor';
  record.environment.mode = executor.mode || 'test-double';
  if (sandboxInfo) record.environment.sandbox = sandboxInfo;
  const startedAt = Date.now();
  let cleaned = false;

  async function runStep(step) {
    const started = Date.now();
    let raw;
    try {
      raw = await runWithTimeout(executor, { workspaceDir, entry: step.entry, timeoutMs: req.limits.timeoutMs }, req.limits.timeoutMs);
    } catch (err) {
      return { failed: true, error: `executor error: ${String(err && err.message || err).slice(0, 1000)}`, durationMs: Date.now() - started };
    }
    if (raw && raw.__timeout === true) {
      try { if (typeof executor.abort === 'function') await executor.abort(); record.abortRequested = true; }
      catch (err) { record.warnings.push(`abort-failed: ${err.message}`); }
      return { timedOut: true, durationMs: Date.now() - started };
    }
    if (!raw || typeof raw !== 'object' || !Number.isInteger(raw.exitCode)) {
      return { failed: true, error: 'malformed executor result (missing integer exitCode)', durationMs: Date.now() - started };
    }
    return {
      command: [step.entry.tool, ...step.entry.args],
      exitCode: raw.exitCode,
      signal: typeof raw.signal === 'string' ? raw.signal : null,
      stdout: truncateLog(raw.stdout, req.limits.maxLogChars),
      stderr: truncateLog(raw.stderr, req.limits.maxLogChars),
      durationMs: Date.now() - started
    };
  }

  try {
    if (req.kind === 'verify-patch') {
      const pocRun = await runStep(req.poc);
      if (pocRun.timedOut) return finishTimedOut(record, startedAt, 'poc');
      if (pocRun.failed) return finishFailed(record, startedAt, { step: 'poc', ...pocRun });
      const suiteRun = await runStep(req.suite);
      if (suiteRun.timedOut) return finishTimedOut(record, startedAt, 'suite');
      if (suiteRun.failed) return finishFailed(record, startedAt, { step: 'suite', ...suiteRun });
      const pocReproduced = evaluateCriterion(req.poc.criterion, { exitCode: pocRun.exitCode, stdout: pocRun.stdout.text, stderr: pocRun.stderr.text });
      const suitePassed = evaluateCriterion(req.suite.criterion, { exitCode: suiteRun.exitCode, stdout: suiteRun.stdout.text, stderr: suiteRun.stderr.text });
      record.poc = pocRun;
      record.suite = suiteRun;
      record.durationMs = Date.now() - startedAt;
      if (!pocReproduced && suitePassed) {
        return {
          status: 'PATCH_VERIFIED', feature: 'F15_harness', lane: 'execute', ...record,
          testEvidence: { passed: true, logs: `poc-blocked; suite-passed\n--- poc ---\n${pocRun.stdout.text}\n--- suite ---\n${suiteRun.stdout.text}`.slice(0, req.limits.maxLogChars) },
          note: 'PoC no longer reproduces and the regression suite passes. This result SUPPLIES ledger testEvidence; only runAuditTransition sets VERIFIED_FIXED.'
        };
      }
      return {
        status: 'EXECUTION_COMPLETED', feature: 'F15_harness', lane: 'execute', ...record,
        patchVerdict: pocReproduced ? 'STILL_VULNERABLE' : 'SUITE_FAILED',
        note: pocReproduced
          ? 'Patch rejected: the PoC still reproduces.'
          : 'Patch rejected: the PoC is blocked but the regression suite did not pass.'
      };
    }

    const run = await runStep(req);
    record.durationMs = Date.now() - startedAt;
    if (run.timedOut) return finishTimedOut(record, startedAt, null);
    if (run.failed) return finishFailed(record, startedAt, run);
    record.run = run;
    record.command = [req.entry.tool, ...req.entry.args];
    if (req.kind === 'reproduce') {
      const met = evaluateCriterion(req.criterion, { exitCode: run.exitCode, stdout: run.stdout.text, stderr: run.stderr.text });
      return {
        status: met ? 'VULNERABILITY_REPRODUCED' : 'NOT_REPRODUCED', feature: 'F15_harness', lane: 'execute',
        ...record, criterion: req.criterion, criterionMet: met,
        note: met
          ? 'Output satisfied the explicit reproduction criterion.'
          : 'Criterion evaluated and NOT met. Failure to reproduce is not proof of safety.'
      };
    }
    // kind === 'execute' without a criterion: completion is all we can claim.
    if (run.exitCode !== 0) {
      return { status: 'EXECUTION_FAILED', feature: 'F15_harness', lane: 'execute', ...record, error: `exit code ${run.exitCode}` };
    }
    return {
      status: 'EXECUTION_COMPLETED', feature: 'F15_harness', lane: 'execute', ...record,
      note: 'Finished with exit 0 and no reproduction criterion. Completion does not prove a vulnerability reproduced.'
    };
  } finally {
    cleaned = cleanupWorkspace(workspaceDir);
    if (!cleaned) record.warnings.push('workspace-cleanup-failed');
  }
}

function finishTimedOut(record, startedAt, step) {
  record.durationMs = Date.now() - startedAt;
  return {
    status: 'EXECUTION_TIMED_OUT', feature: 'F15_harness', lane: 'execute', ...record,
    ...(step ? { step } : {}),
    note: 'Wall-clock limit exceeded; abort was requested. Timeouts are never promoted to findings.'
  };
}

function finishFailed(record, startedAt, detail) {
  record.durationMs = Date.now() - startedAt;
  return {
    status: 'EXECUTION_FAILED', feature: 'F15_harness', lane: 'execute', ...record,
    error: detail.error || 'executor run failed',
    ...(detail.step ? { step: detail.step } : {}),
    note: 'The run errored before any criterion could be evaluated.'
  };
}

// Phase 18: build a verified sandbox executor from OPERATOR configuration.
// Never throws for missing infrastructure (structured unavailable result);
// invalid operator config also fails closed to unavailable. Returns
// { ok:true, executor, summary } or { ok:false, stage, error, requirements }.
async function resolveSandboxExecutor(sandboxOpts, root) {
  let adapter;
  try {
    adapter = require('./sandbox');
  } catch (err) {
    return {
      ok: false, stage: 'adapter',
      error: `sandbox adapter module unavailable: ${String(err && err.message || err).slice(0, 300)}`,
      requirements: ['Restore src/agent/sandbox.js (the F15 sandbox adapter).']
    };
  }
  const opts = sandboxOpts || {};
  let check;
  try {
    check = await adapter.verifySandbox({
      runtime: opts.runtime,
      image: opts.image,
      expectedDigest: opts.expectedDigest,
      limits: opts.limits,
      workspaceRoot: root,
      spawnFn: typeof opts.spawnFn === 'function' ? opts.spawnFn : undefined,
    });
  } catch (err) {
    return {
      ok: false, stage: 'config',
      error: `invalid sandbox configuration: ${String(err && err.message || err).slice(0, 500)}`,
      requirements: ['Correct the sandbox operator configuration (runtime, pinned image, expectedDigest, limits). See contracts §27.']
    };
  }
  if (!check.ok) return check;
  return {
    ok: true,
    executor: check.executor,
    summary: {
      runtime: check.runtime,
      version: check.version,
      image: check.image,
      imageId: check.imageId,
      digestVerified: check.digestVerified,
      limits: check.limits,
    },
  };
}

module.exports = {
  RUN_STATUSES, DEFAULT_LIMITS, ALLOWED_TOOLS,
  submitHarnessRun, detectCapabilities, validateRequest,
  evaluateCriterion, parseVersion
};
