'use strict';

/**
 * Phase 18: container-backed execution adapter for the F15 agent harness.
 *
 * Produces an executor object compatible with `submitHarnessRun`'s deps.executor
 * contract ({ name, run(job) -> { exitCode, stdout, stderr, signal? }, abort?() }).
 * All proof-of-concept / test execution runs inside an explicitly configured,
 * isolated container. This module NEVER executes untrusted code on the host:
 * the only host processes it spawns are the container-runtime CLI itself
 * (`docker`/`podman` with argv arrays) for probing, running, and cleanup.
 *
 * Fail-closed: any missing runtime, unreachable daemon, unverifiable image,
 * or unenforceable restriction yields a structured unavailable result from
 * verifySandbox(); submitHarnessRun surfaces that as EXECUTION_UNAVAILABLE.
 */

const { spawn } = require('child_process');
const path = require('path');
const { randomUUID } = require('crypto');

const SUPPORTED_RUNTIMES = ['docker', 'podman'];
const AUTO = 'auto';
const MAX_IMAGE_CHARS = 300;
const IMAGE_RE = /^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const WORKSPACE_BASENAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const VERSION_RE = /^(docker|podman)\s+version\s+(\S+)/i;

// Mandatory container restrictions, applied to every run. Absence of any of
// these in the generated argv is a programming error, not a fallback case.
const REQUIRED_FLAGS = ['--pull', 'never', '--network', 'none', '--cap-drop', 'ALL'];
const REQUIRED_OPTS = [
  ['--security-opt', 'no-new-privileges'],
  ['--read-only', null],
];
const DEFAULT_LIMITS = Object.freeze({
  cpus: '1.0',
  memory: '512m',
  pidsLimit: '128',
  tmpfsSize: '64m',
  stopTimeoutSec: '5',
});
const PROBE_TIMEOUT_MS = 10000;
const CAPTURE_CAP_BYTES = 1024 * 1024; // 1 MiB per stream; harness truncates further.

function sandboxError(code, message, detail) {
  const err = new Error(message);
  err.code = code;
  if (detail !== undefined) err.detail = detail;
  return err;
}

function normalizeRuntime(runtime) {
  if (runtime === undefined || runtime === null || runtime === AUTO) return AUTO;
  if (typeof runtime !== 'string' || !SUPPORTED_RUNTIMES.includes(runtime)) {
    throw sandboxError('SANDBOX_CONFIG', `sandbox: runtime must be one of ${[...SUPPORTED_RUNTIMES, AUTO].join(', ')}`);
  }
  return runtime;
}

function validateImage(image) {
  if (typeof image !== 'string' || image.length === 0 || image.length > MAX_IMAGE_CHARS || !IMAGE_RE.test(image)) {
    throw sandboxError('SANDBOX_CONFIG', 'sandbox: image must be a pinned registry/repository[:tag][@digest] reference');
  }
  return image;
}

function validateDigest(digest) {
  if (digest === undefined || digest === null) return null;
  if (typeof digest !== 'string' || !DIGEST_RE.test(digest)) {
    throw sandboxError('SANDBOX_CONFIG', 'sandbox: expectedDigest must look like "sha256:<64 hex>"');
  }
  return digest;
}

function validateWorkspaceRoot(root) {
  if (typeof root !== 'string' || root.length === 0 || !path.isAbsolute(root)) {
    throw sandboxError('SANDBOX_CONFIG', 'sandbox: workspaceRoot must be an absolute host path');
  }
  return path.normalize(root);
}

function validateWorkspaceDir(dir, root) {
  if (typeof dir !== 'string' || dir.length === 0 || dir.includes('\0') || !path.isAbsolute(dir)) {
    throw sandboxError('SANDBOX_WORKSPACE', 'sandbox: workspaceDir must be an absolute path');
  }
  const abs = path.normalize(dir);
  const rel = path.relative(root, abs);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw sandboxError('SANDBOX_WORKSPACE', 'sandbox: workspaceDir escapes the configured workspaceRoot');
  }
  if (!WORKSPACE_BASENAME_RE.test(path.basename(abs))) {
    throw sandboxError('SANDBOX_WORKSPACE', 'sandbox: workspaceDir basename has unsafe characters');
  }
  return abs;
}

function defaultSpawn(argv, opts) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, ...(opts || {}) });
    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let stdoutCut = false;
    let stderrCut = false;
    const onData = (chunk, which) => {
      let text = chunk.toString('utf8');
      if (which === 'out') {
        if (stdoutBytes + text.length > CAPTURE_CAP_BYTES) {
          text = text.slice(0, Math.max(0, CAPTURE_CAP_BYTES - stdoutBytes));
          stdoutCut = true;
        }
        stdout += text;
        stdoutBytes += text.length;
      } else {
        if (stderrBytes + text.length > CAPTURE_CAP_BYTES) {
          text = text.slice(0, Math.max(0, CAPTURE_CAP_BYTES - stderrBytes));
          stderrCut = true;
        }
        stderr += text;
        stderrBytes += text.length;
      }
    };
    child.stdout.on('data', (c) => onData(c, 'out'));
    child.stderr.on('data', (c) => onData(c, 'err'));
    child.on('error', (err) => reject(err));
    child.on('close', (code, signal) => {
      if (stdoutCut) stdout += `\n[truncated: stdout exceeded ${CAPTURE_CAP_BYTES} bytes]`;
      if (stderrCut) stderr += `\n[truncated: stderr exceeded ${CAPTURE_CAP_BYTES} bytes]`;
      resolve({ exitCode: code, signal: signal || undefined, stdout, stderr });
    });
  });
}

// Probe helper: short timeout, ENOENT and timeouts become structured results,
// never thrown, so callers can report fail-closed unavailability.
function runProbe(spawnFn, argv, timeoutMs) {
  let timer = null;
  const killer = { killed: false };
  const p = spawnFn(argv, { timeout: timeoutMs });
  const guarded = Promise.resolve(p).then(
    (r) => ({ ok: true, ...r }),
    (err) => ({ ok: false, error: err })
  );
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      killer.killed = true;
      resolve({ ok: false, error: new Error(`probe timed out after ${timeoutMs}ms: ${argv.join(' ')}`) });
    }, timeoutMs);
    if (timer.unref) timer.unref();
  });
  return Promise.race([guarded, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function isMissingBinary(err) {
  return !!err && (err.code === 'ENOENT' || /not recognized|not found|no such file/i.test(String(err.message || '')));
}

async function probeRuntime(spawnFn, runtime) {
  const version = await runProbe(spawnFn, [runtime, '--version'], PROBE_TIMEOUT_MS);
  if (!version.ok) {
    return { available: false, reason: isMissingBinary(version.error) ? 'binary-missing' : 'probe-failed', error: String(version.error && version.error.message || version.error) };
  }
  if (version.exitCode !== 0) {
    return { available: false, reason: 'probe-failed', error: (version.stderr || version.stdout || `exit ${version.exitCode}`).slice(0, 500) };
  }
  const m = VERSION_RE.exec(version.stdout || '');
  const info = await runProbe(spawnFn, [runtime, 'info', '--format', '{{.ServerVersion}}'], PROBE_TIMEOUT_MS);
  if (!info.ok) {
    return { available: false, reason: 'daemon-unreachable', version: m ? m[2] : undefined, error: String(info.error && info.error.message || info.error) };
  }
  if (info.exitCode !== 0) {
    return { available: false, reason: 'daemon-unreachable', version: m ? m[2] : undefined, error: (info.stderr || info.stdout || `exit ${info.exitCode}`).slice(0, 500) };
  }
  return { available: true, version: m ? m[2] : undefined, serverVersion: (info.stdout || '').trim().slice(0, 64) || undefined };
}

async function inspectImage(spawnFn, runtime, image) {
  const res = await runProbe(spawnFn, [runtime, 'image', 'inspect', '--format', '{{.Id}} {{json .RepoDigests}}', image], PROBE_TIMEOUT_MS);
  if (!res.ok) return { present: false, reason: 'inspect-failed', error: String(res.error && res.error.message || res.error) };
  if (res.exitCode !== 0) {
    return { present: false, reason: 'image-missing', error: (res.stderr || res.stdout || `exit ${res.exitCode}`).slice(0, 500) };
  }
  const out = (res.stdout || '').trim();
  const space = out.indexOf(' ');
  const id = space === -1 ? out : out.slice(0, space);
  let digests = [];
  try {
    const parsed = JSON.parse(space === -1 ? '[]' : out.slice(space + 1));
    if (Array.isArray(parsed)) digests = parsed.filter((d) => typeof d === 'string');
  } catch { digests = []; }
  return { present: true, id: id || undefined, repoDigests: digests };
}

function digestMatches(expectedDigest, inspect) {
  if (!expectedDigest) return { required: false, matched: true };
  const want = expectedDigest.toLowerCase();
  if ((inspect.id || '').toLowerCase() === want) return { required: true, matched: true, via: 'image-id' };
  const hit = (inspect.repoDigests || []).find((d) => {
    const at = d.lastIndexOf('@');
    return at !== -1 && d.slice(at + 1).toLowerCase() === want;
  });
  return { required: true, matched: !!hit, via: hit ? 'repo-digest' : undefined };
}

function requirementsFor(stage) {
  const base = [
    'Install a supported container runtime (Docker or Podman) with a running daemon/service.',
    'Obtain the pinned sandbox image out-of-band and verify its digest before enabling execution.',
  ];
  if (stage === 'runtime') return [base[0], 'Set sandbox.runtime ("docker"/"podman") or "auto" with at least one working daemon.'];
  if (stage === 'daemon') return ['Start the container daemon/service and ensure the current user can reach it.'];
  if (stage === 'image') return [base[1], 'Set sandbox.image to the pinned reference and sandbox.expectedDigest to its sha256 digest.'];
  return base;
}

function buildRunArgv({ runtime, image, workspaceDir, entry, limits, containerName }) {
  const L = { ...DEFAULT_LIMITS, ...(limits || {}) };
  // The entry's first token becomes the container entrypoint, overriding any
  // ENTRYPOINT baked into the image (e.g. ["/bin/sh","-c"], which would
  // otherwise swallow every argument after the image name). The command then
  // executes directly: no shell exists anywhere on this path.
  if (!Array.isArray(entry) || entry.length === 0 ||
      entry.some((a) => typeof a !== 'string' || a.length === 0 || a.includes('\0'))) {
    throw sandboxError('SANDBOX_COMMAND', 'sandbox: entry must be a non-empty argv array of strings');
  }
  const [entrypoint, ...cmdArgs] = entry;
  const argv = [
    runtime, 'run', '--rm',
    '--pull', 'never',
    '--network', 'none',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--read-only',
    '--tmpfs', `/tmp:rw,noexec,nosuid,size=${L.tmpfsSize}`,
    '--memory', L.memory,
    '--cpus', L.cpus,
    '--pids-limit', String(L.pidsLimit),
    '--stop-timeout', String(L.stopTimeoutSec),
    '--name', containerName,
    '-v', `${workspaceDir}:/work`,
    '--workdir', '/work',
    '--entrypoint', entrypoint,
    image,
    ...cmdArgs,
  ];
  // Self-check: every mandatory restriction must be present verbatim.
  for (let i = 0; i < REQUIRED_FLAGS.length; i += 2) {
    const flag = REQUIRED_FLAGS[i];
    const want = REQUIRED_FLAGS[i + 1];
    const at = argv.indexOf(flag);
    if (at === -1 || argv[at + 1] !== want) {
      throw sandboxError('SANDBOX_INTERNAL', `sandbox: mandatory restriction missing from run argv (${flag} ${want})`);
    }
  }
  for (const [flag, want] of REQUIRED_OPTS) {
    const at = argv.indexOf(flag);
    if (at === -1 || (want !== null && argv[at + 1] !== want)) {
      throw sandboxError('SANDBOX_INTERNAL', `sandbox: mandatory restriction missing from run argv (${flag})`);
    }
  }
  const epAt = argv.indexOf('--entrypoint');
  if (epAt === -1 || argv[epAt + 1] !== entrypoint) {
    throw sandboxError('SANDBOX_INTERNAL', 'sandbox: entrypoint override missing from run argv');
  }
  if (argv.some((a, i) => i > 1 && a === 'pull')) throw sandboxError('SANDBOX_INTERNAL', 'sandbox: image pull is never permitted at run time');
  return argv;
}

/**
 * Verify runtime, daemon, and image identity WITHOUT executing anything
 * untrusted. Resolves to { ok:true, executor, runtime, version, image, imageId,
 * limits } or { ok:false, stage, error, requirements }. Throws ONLY on invalid
 * operator configuration (bad image/workspace/limits values); missing
 * infrastructure is a structured unavailable result.
 */
async function verifySandbox(opts) {
  const options = opts || {};
  const runtimeChoice = normalizeRuntime(options.runtime);
  const image = validateImage(options.image);
  const expectedDigest = validateDigest(options.expectedDigest);
  const workspaceRoot = validateWorkspaceRoot(options.workspaceRoot);
  const spawnFn = options.spawnFn || defaultSpawn;
  const limits = { ...DEFAULT_LIMITS, ...(options.limits || {}) };

  const candidates = runtimeChoice === AUTO ? [...SUPPORTED_RUNTIMES] : [runtimeChoice];
  const attempts = [];
  let selected = null;
  for (const candidate of candidates) {
    const probe = await probeRuntime(spawnFn, candidate);
    attempts.push({ runtime: candidate, ...probe });
    if (probe.available) {
      selected = { runtime: candidate, version: probe.version, serverVersion: probe.serverVersion };
      break;
    }
  }
  if (!selected) {
    const daemonSeen = attempts.some((a) => a.reason === 'daemon-unreachable');
    return {
      ok: false,
      stage: daemonSeen ? 'daemon' : 'runtime',
      error: daemonSeen
        ? 'sandbox: container runtime installed but daemon/service unreachable'
        : 'sandbox: no supported container runtime available (need docker or podman with a running daemon)',
      attempts: attempts.map((a) => ({ runtime: a.runtime, reason: a.reason, error: a.error })),
      requirements: requirementsFor(daemonSeen ? 'daemon' : 'runtime'),
    };
  }

  const inspect = await inspectImage(spawnFn, selected.runtime, image);
  if (!inspect.present) {
    return {
      ok: false, stage: 'image', runtime: selected.runtime,
      error: `sandbox: image not present locally or not inspectable: ${image}`,
      detail: inspect.error,
      requirements: requirementsFor('image'),
    };
  }
  const digest = digestMatches(expectedDigest, inspect);
  if (!digest.matched) {
    return {
      ok: false, stage: 'image', runtime: selected.runtime,
      error: 'sandbox: image identity does not match sandbox.expectedDigest; refusing execution',
      detail: `imageId=${inspect.id || 'unknown'} repoDigests=${JSON.stringify(inspect.repoDigests || [])}`,
      requirements: requirementsFor('image'),
    };
  }

  const executor = createSandboxExecutor({
    runtime: selected.runtime,
    image,
    expectedDigest,
    workspaceRoot,
    limits,
    spawnFn,
    verified: { version: selected.version, serverVersion: selected.serverVersion, imageId: inspect.id, digestVia: digest.via || null },
  });
  return {
    ok: true,
    executor,
    runtime: selected.runtime,
    version: selected.version,
    serverVersion: selected.serverVersion,
    image,
    imageId: inspect.id,
    digestVerified: digest.required,
    digestVia: digest.via || null,
    limits,
  };
}

/**
 * Build the harness-compatible executor. Construction performs NO I/O; call
 * verifySandbox() first so missing infrastructure fails closed before any run.
 */
function createSandboxExecutor(opts) {
  const options = opts || {};
  if (!options.image) throw sandboxError('SANDBOX_CONFIG', 'sandbox: image is required');
  const runtime = normalizeRuntime(options.runtime);
  if (runtime === AUTO) throw sandboxError('SANDBOX_CONFIG', 'sandbox: executor requires a verified runtime ("docker"/"podman"); call verifySandbox() first');
  const image = validateImage(options.image);
  const workspaceRoot = validateWorkspaceRoot(options.workspaceRoot);
  const spawnFn = options.spawnFn || defaultSpawn;
  const limits = { ...DEFAULT_LIMITS, ...(options.limits || {}) };
  const verified = options.verified || null;
  let activeContainer = null;
  let runSeq = 0;

  async function cleanupContainer(name) {
    try {
      await spawnFn([runtime, 'rm', '-f', name], { timeout: PROBE_TIMEOUT_MS });
    } catch { /* best effort; --rm already covers the normal path */ }
  }

  function normalizeEntry(entry) {
    // Harness contract shape: { tool, args } already validated by harness
    // validateRequest; re-validated here (defense in depth, never trusted).
    if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
      if (typeof entry.tool !== 'string' || entry.tool.length === 0 || entry.tool.includes('\0')) {
        throw sandboxError('SANDBOX_COMMAND', 'sandbox: entry.tool must be a non-empty string');
      }
      if (!Array.isArray(entry.args) || entry.args.some((a) => typeof a !== 'string' || a.includes('\0'))) {
        throw sandboxError('SANDBOX_COMMAND', 'sandbox: entry.args must be an array of strings');
      }
      return [entry.tool, ...entry.args];
    }
    if (!Array.isArray(entry) || entry.length === 0 || entry.some((a) => typeof a !== 'string' || a.length === 0 || a.includes('\0'))) {
      throw sandboxError('SANDBOX_COMMAND', 'sandbox: entry must be { tool, args } or a non-empty argv array of strings');
    }
    return entry;
  }

  async function run(job) {
    const j = job || {};
    const workspaceDir = validateWorkspaceDir(j.workspaceDir, workspaceRoot);
    const entryArgv = normalizeEntry(j.entry);
    runSeq += 1;
    const containerName = `assertara-${path.basename(workspaceDir)}-${process.pid}-${runSeq}`;
    const argv = buildRunArgv({ runtime, image, workspaceDir, entry: entryArgv, limits, containerName });
    activeContainer = containerName;
    try {
      const res = await spawnFn(argv);
      const out = res && typeof res === 'object' ? res : {};
      return {
        exitCode: Number.isInteger(out.exitCode) ? out.exitCode : 1,
        stdout: typeof out.stdout === 'string' ? out.stdout : '',
        stderr: typeof out.stderr === 'string' ? out.stderr : '',
        ...(out.signal ? { signal: out.signal } : {}),
      };
    } finally {
      activeContainer = null;
      await cleanupContainer(containerName);
    }
  }

  async function abort() {
    const name = activeContainer;
    activeContainer = null;
    if (!name) return { aborted: false };
    try {
      await spawnFn([runtime, 'kill', name], { timeout: PROBE_TIMEOUT_MS });
    } catch { /* container may already be gone; rm -f still ensures cleanup */ }
    await cleanupContainer(name);
    return { aborted: true, container: name };
  }

  return {
    name: `sandbox:${runtime}`,
    mode: 'sandboxed',
    image,
    expectedDigest: options.expectedDigest || null,
    verified,
    limits,
    run,
    abort,
    runId: randomUUID(),
  };
}

module.exports = {
  SUPPORTED_RUNTIMES,
  DEFAULT_LIMITS,
  CAPTURE_CAP_BYTES,
  verifySandbox,
  createSandboxExecutor,
  buildRunArgv,
  requirementsFor,
};
