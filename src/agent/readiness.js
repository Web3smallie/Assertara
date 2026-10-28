/**
 * Assertara Capability Readiness — code-grounded inventory of experimental
 * capabilities plus deterministic readiness checks (F3 audit, Phase 13).
 *
 * Two related but distinct things live here:
 *
 * 1. CAPABILITIES: the curated inventory. Each entry records what the
 *    capability is, where it is implemented, what it depends on, how it
 *    executes, and its readiness CLASSIFICATION with dated evidence. The
 *    classification may cite prior live verification recorded in contracts.
 *
 * 2. Automated checks (`checkReadiness` / `checkAllReadiness`): fresh,
 *    offline-safe probes that return validated readiness records. A check
 *    reports only what IT verified, labeled by how the evidence was obtained
 *    (`live` | `fixture` | `mock` | `model` | `probe`). Network access happens
 *    only when a caller explicitly opts into a live branch — the unit suite
 *    never does.
 *
 * Readiness records are diagnostic evidence, not findings: they never enter
 * the evidence graph as support and never bypass the verifier's experimental
 * gate. No check records secrets — the validator rejects secret-shaped
 * evidence structurally.
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const READINESS_STATUSES = ['READY', 'PARTIAL', 'UNAVAILABLE', 'TEST_ONLY', 'FAILED_CHECK'];
const EXECUTION_EVIDENCE = ['live', 'fixture', 'mock', 'model', 'probe'];
const EXECUTION_KINDS = ['deterministic', 'model-assisted', 'external-state'];

function readinessError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function isIsoDate(s) {
  return typeof s === 'string' && !Number.isNaN(Date.parse(s));
}

function containsSecretShape(value, seen = new Set()) {
  if (typeof value === 'string') {
    return /sk-[A-Za-z0-9]{16,}/.test(value)
      || /Bearer\s+[A-Za-z0-9\-._~+/=]{8,}/.test(value)
      || /BEGIN .*PRIVATE KEY/.test(value);
  }
  if (!value || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  const vs = Array.isArray(value) ? value : Object.values(value);
  return vs.some((v) => containsSecretShape(v, seen));
}

/**
 * Validate a readiness record. Structural checks plus semantic invariants:
 * READY tolerates no failures/unknowns; UNAVAILABLE claims no successes;
 * PARTIAL needs both a success and a gap; FAILED_CHECK names a failure;
 * TEST_ONLY must explain why it is not production. Throws coded errors.
 */
function validateReadinessRecord(rec) {
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) {
    throw readinessError('BAD_RECORD', 'readiness record must be an object');
  }
  if (typeof rec.capability !== 'string' || rec.capability.length === 0) {
    throw readinessError('BAD_RECORD', 'capability id must be a non-empty string');
  }
  if (typeof rec.name !== 'string' || rec.name.length === 0) {
    throw readinessError('BAD_RECORD', 'capability name must be a non-empty string');
  }
  if (!READINESS_STATUSES.includes(rec.status)) {
    throw readinessError('BAD_STATUS', `status must be one of ${READINESS_STATUSES.join(',')}`);
  }
  if (!EXECUTION_EVIDENCE.includes(rec.executedWith)) {
    throw readinessError('BAD_EVIDENCE_KIND', `executedWith must be one of ${EXECUTION_EVIDENCE.join(',')}`);
  }
  for (const k of ['checked', 'succeeded', 'failed', 'unknown']) {
    if (!Array.isArray(rec[k]) || rec[k].some((s) => typeof s !== 'string')) {
      throw readinessError('BAD_RECORD', `${k} must be an array of strings`);
    }
  }
  if (rec.checked.length === 0) throw readinessError('BAD_RECORD', 'checked must name at least one check');
  if (!Array.isArray(rec.dependencies) || rec.dependencies.some((d) => !d || typeof d.name !== 'string' || typeof d.state !== 'string')) {
    throw readinessError('BAD_RECORD', 'dependencies must be an array of {name, state}');
  }
  if (!rec.evidence || typeof rec.evidence !== 'object' || Array.isArray(rec.evidence)) {
    throw readinessError('BAD_RECORD', 'evidence must be an object');
  }
  if (!isIsoDate(rec.checkedAt)) throw readinessError('BAD_RECORD', 'checkedAt must be an ISO timestamp');
  if (containsSecretShape(rec.evidence)) {
    throw readinessError('SECRET_LEAK', 'readiness evidence must never contain secret values');
  }
  if (rec.status === 'READY' && (rec.failed.length > 0 || rec.unknown.length > 0)) {
    throw readinessError('READY_WITH_GAPS', 'READY forbids failures and unknowns — use PARTIAL');
  }
  if (rec.status === 'UNAVAILABLE' && rec.succeeded.length > 0) {
    throw readinessError('UNAVAILABLE_WITH_SUCCESS', 'UNAVAILABLE forbids successes — use PARTIAL');
  }
  if (rec.status === 'PARTIAL' && (rec.succeeded.length === 0 || (rec.failed.length === 0 && rec.unknown.length === 0))) {
    throw readinessError('BAD_PARTIAL', 'PARTIAL needs at least one success and at least one failure or unknown');
  }
  if (rec.status === 'FAILED_CHECK' && rec.failed.length === 0) {
    throw readinessError('BAD_FAILED_CHECK', 'FAILED_CHECK must name at least one failure');
  }
  if (rec.status === 'TEST_ONLY' && (typeof rec.evidence.testOnlyReason !== 'string' || rec.evidence.testOnlyReason.length === 0)) {
    throw readinessError('BAD_TEST_ONLY', 'TEST_ONLY must explain why in evidence.testOnlyReason');
  }
  return true;
}

function makeRecord(fields) {
  const rec = { checkedAt: new Date().toISOString(), ...fields };
  validateReadinessRecord(rec);
  return rec;
}

function parseVersion(text) {
  const m = /(\d+\.\d+\.\d+)/.exec(String(text || ''));
  return m ? m[1] : null;
}

/** Offline-safe local binary probe. Never touches the network. */
function probeBin(bin, args = ['--version'], timeoutMs = 5000) {
  return new Promise((resolve) => {
    let out = '';
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    let child;
    try {
      child = spawn(bin, args, { timeout: timeoutMs, windowsHide: true });
    } catch (err) {
      done({ ok: false, error: `spawn-failed: ${err.message}` });
      return;
    }
    child.stdout.on('data', (d) => { out += d.toString('utf8').slice(0, 2048); });
    child.on('error', (err) => done({ ok: false, error: err.code === 'ENOENT' ? 'not-installed' : `spawn-error: ${err.message}` }));
    child.on('close', (code) => done(code === 0
      ? { ok: true, version: parseVersion(out), raw: out.slice(0, 300) }
      : { ok: false, error: `exit-${code}` }));
    setTimeout(() => { try { child.kill(); } catch {} done({ ok: false, error: 'probe-timeout' }); }, timeoutMs + 500).unref?.();
  });
}

// Check scratch lives under the project's gitignored data/ dir: system temp
// is not reliably writable (sandbox EPERM) and project temp keeps the mess
// contained. Directories are removed after each check.
function scratchRoot() {
  const root = path.join(__dirname, '..', '..', 'data', '.readiness-tmp');
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function releaseScratch(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  try { fs.rmdirSync(path.join(__dirname, '..', '..', 'data', '.readiness-tmp')); } catch { /* non-empty or gone */ }
}

async function withTempDirAsync(prefix, fn) {
  const dir = fs.mkdtempSync(path.join(scratchRoot(), prefix));
  try {
    return await fn(dir);
  } finally {
    releaseScratch(dir);
  }
}

// ---------- Capability checks ----------
// Each check returns a validated record. Injected doubles (probe, client,
// fs, apiKey) are labeled `mock`; real local execution is `live`; local
// config/binary/file inspection is `probe`. Nothing here touches the network
// unless the caller passes an explicit live branch ({ live: true, ... }).

function scriptedNow(deps) {
  return deps && typeof deps.now === 'function' ? deps.now() : Date.now();
}

async function checkExperimentalRunners(deps = {}) {
  const { runExperimental } = require('./features');
  const gated = runExperimental({});
  const opted = runExperimental({ allowExperimental: true });
  void scriptedNow(deps);
  return makeRecord({
    capability: 'f3.runners',
    name: 'Experimental runners lane',
    status: 'TEST_ONLY',
    checked: ['gate without opt-in', 'gate with opt-in', 'registered production runners'],
    succeeded: [`gate without opt-in → ${gated.status}`, `gate with opt-in → ${opted.status}`],
    failed: ['registered production runners (0 enabled)'],
    unknown: [],
    dependencies: [],
    executedWith: 'live',
    evidence: {
      testOnlyReason: 'The gate executes for real, but zero experimental runners exist — there is nothing production to run.',
      gatedStatus: gated.status,
      optedStatus: opted.status
    }
  });
}

async function checkLocalCore(deps = {}) {
  const { EvidenceGraph } = require('./evidenceGraph');
  const { Recorder, replayRecording } = require('./replay');
  const { WatchScheduler } = require('./scheduler');
  const g = new EvidenceGraph('inv_readiness');
  const node = g.append({ kind: 'ReadinessProbe', producer: 'TOOL', payload: { probe: true }, created_turn: 0 });
  const rec = new Recorder({ investigationId: 'inv_readiness', runId: 'run_readiness', now: () => scriptedNow(deps) });
  rec.append('investigation.started', { data: { featureId: 'readiness' } });
  rec.append('evidence.appended', { data: { evidenceId: node.id, kind: node.kind }, evidenceRefs: [node.id] });
  rec.append('investigation.stopped', { data: { status: 'COMPLETE' } });
  const replayed = replayRecording(rec.export());
  if (replayed.status !== 'OK' || replayed.integrity.verified !== true) {
    throw readinessError('CORE_PROBE_FAILED', 'local record/replay round-trip did not verify');
  }
  const alerts = await withTempDirAsync('assertara-ready-sched-', async (dir) => {
    const sched = new WatchScheduler({ dir, now: () => scriptedNow(deps) });
    sched.client = {
      async getBytecode() { return '0x11'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    sched.addTarget({ address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', intervalMs: 5000 });
    await sched.tickOnce();
    return sched.getAlerts({});
  });
  return makeRecord({
    capability: 'core.local',
    name: 'Local deterministic core',
    status: 'READY',
    checked: ['evidence graph append', 'event record + hash chain', 'historical replay verify', 'scheduler tick + alert store'],
    succeeded: ['evidence graph append', 'event record + hash chain', 'historical replay verify', 'scheduler tick + alert store'],
    failed: [],
    unknown: [],
    dependencies: [{ name: 'chain client (scheduler)', state: 'scripted-read-only for this probe; production injects a viem client' }],
    executedWith: 'live',
    evidence: { graphNode: node.id, replayEvents: replayed.integrity.checkedEvents, schedulerAlerts: alerts.length }
  });
}

async function checkHarness(deps = {}) {
  const { detectCapabilities } = require('./harness');
  const caps = await detectCapabilities(deps.probe ? { probe: deps.probe } : {});
  const docker = caps.docker && caps.docker.available === true;
  const podman = caps.podman && caps.podman.available === true;
  // Phase 18: the sandbox adapter ships (src/agent/sandbox.js) but live
  // execution stays UNAVAILABLE until a runtime + verified image exist here.
  let adapterState = 'shipped';
  try { require('./sandbox'); } catch { adapterState = 'not-shipped'; }
  const failed = [];
  if (adapterState !== 'shipped') failed.push('isolated executor adapter (not shipped; contracts §13/§27)');
  if (!docker) failed.push(`docker (${(caps.docker && caps.docker.error) || 'unavailable'})`);
  if (!podman) failed.push(`podman (${(caps.podman && caps.podman.error) || 'unavailable'})`);
  failed.push('verified sandbox image (no pinned image + digest configured for this environment; contracts §27)');
  return makeRecord({
    capability: 'exec.harness',
    name: 'Isolated PoC execution',
    status: 'UNAVAILABLE',
    checked: ['docker binary+daemon', 'podman binary+daemon', 'isolated executor adapter', 'verified sandbox image'],
    succeeded: [],
    failed,
    unknown: [],
    dependencies: [
      { name: 'container runtime (docker/podman)', state: docker || podman ? 'present' : 'absent' },
      { name: 'executor adapter', state: adapterState },
      { name: 'verified sandbox image', state: 'unconfigured' }
    ],
    executedWith: deps.probe ? 'mock' : 'probe',
    evidence: {
      docker: caps.docker || null, podman: caps.podman || null, canExecuteIsolated: false, adapter: adapterState,
      adapterNote: adapterState === 'shipped'
        ? 'src/agent/sandbox.js ships; unit-tested via injected doubles, live execution unverified here'
        : 'sandbox adapter module missing'
    }
  });
}

async function checkStt(deps = {}) {
  const { detectAudioCapabilities } = require('./audioIngest');
  const caps = await detectAudioCapabilities(deps.probe ? { probe: deps.probe } : {});
  return makeRecord({
    capability: 'media.stt',
    name: 'Audio transcription backend',
    status: 'UNAVAILABLE',
    checked: ['ffmpeg decoder', 'STT backend'],
    succeeded: [],
    failed: [
      `ffmpeg (${caps.ffmpeg && caps.ffmpeg.available ? `present ${caps.ffmpeg.version || ''}`.trim() : (caps.ffmpeg && caps.ffmpeg.error) || 'absent'}) — non-WAV decoding blocked`,
      `STT backend (${(caps.sttBackend && caps.sttBackend.error) || 'none installed'})`
    ],
    unknown: [],
    dependencies: [
      { name: 'ffmpeg', state: caps.ffmpeg && caps.ffmpeg.available ? 'present' : 'absent' },
      { name: 'local STT backend', state: 'none-ships' }
    ],
    executedWith: deps.probe ? 'mock' : 'probe',
    evidence: { ffmpeg: caps.ffmpeg || null, sttBackend: caps.sttBackend || null, canTranscribe: caps.canTranscribe === true, decodableFormats: caps.decodableFormats || [] }
  });
}

async function checkFrames(deps = {}) {
  const { detectVideoCapabilities } = require('./videoIngest');
  const caps = await detectVideoCapabilities(deps.probe ? { probe: deps.probe } : {});
  return makeRecord({
    capability: 'media.frames',
    name: 'Video frame extraction',
    status: 'UNAVAILABLE',
    checked: ['ffmpeg extractor', 'frame extractor backend', 'vision model input path'],
    succeeded: [],
    failed: [
      `ffmpeg (${caps.ffmpeg && caps.ffmpeg.available ? 'present' : (caps.ffmpeg && caps.ffmpeg.error) || 'absent'})`,
      `frame extractor (${(caps.frameExtraction && caps.frameExtraction.error) || 'none installed'})`
    ],
    unknown: [],
    dependencies: [
      { name: 'ffmpeg', state: caps.ffmpeg && caps.ffmpeg.available ? 'present' : 'absent' },
      { name: 'frame extractor', state: 'none-ships' },
      { name: 'vision model (input_image)', state: caps.visionModel && caps.visionModel.available ? 'probe-verified' : 'unknown' }
    ],
    executedWith: deps.probe ? 'mock' : 'probe',
    evidence: { ffmpeg: caps.ffmpeg || null, frameExtraction: caps.frameExtraction || null, canProcessVideo: caps.canProcessVideo === true }
  });
}

async function checkOcr(deps = {}) {
  let installed = false;
  let version = null;
  try {
    const resolve = deps.resolve || require.resolve;
    resolve('tesseract.js');
    installed = true;
    try {
      version = require('tesseract.js/package.json').version || null;
    } catch { /* version best-effort */ }
  } catch {
    installed = false;
  }
  if (!installed) {
    return makeRecord({
      capability: 'media.ocr',
      name: 'Tesseract OCR text extraction',
      status: 'UNAVAILABLE',
      checked: ['tesseract.js module resolution'],
      succeeded: [],
      failed: ['tesseract.js module resolution (not installed)'],
      unknown: [],
      dependencies: [{ name: 'tesseract.js', state: 'absent' }],
      executedWith: deps.resolve ? 'mock' : 'probe',
      evidence: { installed: false }
    });
  }
  return makeRecord({
    capability: 'media.ocr',
    name: 'Tesseract OCR text extraction',
    status: 'PARTIAL',
    checked: ['tesseract.js module resolution'],
    succeeded: [`tesseract.js module resolution (${version || 'unknown version'})`],
    failed: [],
    unknown: ['live recognition run (needs traineddata; exercised outside the unit suite, not re-probed here)'],
    dependencies: [{ name: 'tesseract.js', state: 'present' }, { name: 'eng traineddata', state: 'unprobed' }],
    executedWith: deps.resolve ? 'mock' : 'probe',
    evidence: { installed: true, version, lastLiveEvidence: 'Phase 10 walkthrough run: real OCR exact on synthetic frames (contracts §19)' }
  });
}

async function checkForge(deps = {}) {
  const probe = deps.probe || probeBin;
  const existsSync = deps.existsSync || fs.existsSync;
  const root = path.join(__dirname, '..', '..');
  const bin = await probe('forge', ['--version']);
  const stdLib = existsSync(path.join(root, 'lib', 'forge-std'));
  const stdModules = existsSync(path.join(root, 'node_modules', 'forge-std'));
  const stdFoundryToml = existsSync(path.join(root, 'foundry.toml'));
  const executedWith = deps.probe || deps.existsSync ? 'mock' : 'probe';
  if (!bin.ok) {
    return makeRecord({
      capability: 'sim.forge',
      name: 'Foundry EVM simulation',
      status: 'UNAVAILABLE',
      checked: ['forge binary'],
      succeeded: [],
      failed: [`forge binary (${bin.error || 'absent'}) — genuine EXECUTED path blocked; deterministic fallback still covers`],
      unknown: [],
      dependencies: [{ name: 'forge', state: 'absent' }, { name: 'forge-std', state: 'unprobed' }],
      executedWith,
      evidence: { forge: bin }
    });
  }
  const version = bin.version || null;
  if (stdLib || stdModules) {
    return makeRecord({
      capability: 'sim.forge',
      name: 'Foundry EVM simulation',
      status: 'PARTIAL',
      checked: ['forge binary', 'forge-std resolution'],
      succeeded: [`forge binary (${version || 'unknown version'})`, `forge-std resolution (${stdLib ? 'lib/forge-std' : 'node_modules/forge-std'})`],
      failed: [],
      unknown: ['end-to-end forge test run of a generated case (binary+stdlib present; full workflow still unverified)'],
      dependencies: [{ name: 'forge', state: 'present' }, { name: 'forge-std', state: 'present' }],
      executedWith,
      evidence: { forge: { ok: true, version }, stdPath: stdLib ? 'lib/forge-std' : 'node_modules/forge-std' }
    });
  }
  return makeRecord({
    capability: 'sim.forge',
    name: 'Foundry EVM simulation',
    status: 'PARTIAL',
    checked: ['forge binary', 'forge-std resolution'],
    succeeded: [`forge binary (${version || 'unknown version'})`],
    failed: ['forge-std resolution (lib/forge-std and node_modules/forge-std both absent; generated tests fail to compile)'],
    unknown: [],
    dependencies: [{ name: 'forge', state: 'present' }, { name: 'forge-std', state: 'absent' }, { name: 'foundry.toml', state: stdFoundryToml ? 'present' : 'absent' }],
    executedWith,
    evidence: { forge: { ok: true, version }, stdFound: false }
  });
}

function fixtureChainClient() {
  return {
    async getChainId() { return 1; },
    async getBlockNumber() { return 100n; },
    async getLogs() { return []; },
    async readContract() { return 0n; }
  };
}

async function checkChainHistory(deps = {}) {
  const { discoverApprovals } = require('./chain');
  const live = deps.live === true;
  if (live && !deps.client && !deps.rpcUrl) {
    throw readinessError('LIVE_NEEDS_TARGET', 'live chain probe requires an explicit client or rpcUrl');
  }
  if (!live && !deps.client) {
    const fetched = await discoverApprovals({
      owner: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      tokens: ['0xdAC17F958D2ee523a2206206994597C13D831ec7'],
      fromBlock: 90n, toBlock: 100n, client: fixtureChainClient()
    });
    return makeRecord({
      capability: 'chain.history',
      name: 'Bounded approval history discovery',
      status: 'PARTIAL',
      checked: ['bounded discovery logic (fixture)', 'coverage accounting (fixture)'],
      succeeded: [`bounded discovery logic (fixture → ${fetched.coverage.status})`, 'coverage accounting (fixture)'],
      failed: [],
      unknown: ['live provider reachability (network checks are explicit opt-in; last verified 2026-10-27 per contracts §15)'],
      dependencies: [{ name: 'RPC provider', state: 'unprobed' }, { name: 'archive access', state: 'unavailable-on-free-tier' }],
      executedWith: 'fixture',
      evidence: { coverage: fetched.coverage.status }
    });
  }
  const label = deps.client ? 'mock' : 'live';
  const fetched = await discoverApprovals({
    owner: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    tokens: ['0xdAC17F958D2ee523a2206206994597C13D831ec7'],
    fromBlock: 90n, toBlock: 100n,
    ...(deps.client ? { client: deps.client } : { rpcUrl: deps.rpcUrl })
  });
  if (label === 'mock') {
    return makeRecord({
      capability: 'chain.history',
      name: 'Bounded approval history discovery',
      status: 'PARTIAL',
      checked: ['bounded discovery logic (scripted client)'],
      succeeded: ['bounded discovery logic (scripted client)'],
      failed: [],
      unknown: ['live provider behavior (a scripted client proves nothing about production RPC)'],
      dependencies: [{ name: 'RPC provider', state: 'scripted-double' }],
      executedWith: 'mock',
      evidence: { coverage: fetched.coverage.status }
    });
  }
  // Archive depth is out of scope for the BOUNDED capability: it lives in
  // dependencies, not unknowns. READY here means recent-range discovery
  // works; it never means full history.
  const complete = fetched.coverage.status === 'COMPLETE_WITHIN_REQUESTED_SCOPE';
  return makeRecord({
    capability: 'chain.history',
    name: 'Bounded approval history discovery',
    status: complete ? 'READY' : 'PARTIAL',
    checked: ['tip read', 'bounded address+topic query'],
    succeeded: ['tip read', `bounded address+topic query (${fetched.coverage.status})`],
    failed: [],
    unknown: complete ? [] : [`requested-scope gaps present (${fetched.coverage.status})`],
    dependencies: [{ name: 'RPC provider', state: 'reachable' }, { name: 'archive access', state: 'unavailable-on-free-tier' }],
    executedWith: 'live',
    evidence: { coverage: fetched.coverage.status, events: fetched.approvals.length }
  });
}

async function checkChainSource(deps = {}) {
  const { buildDossier } = require('./dossier');
  const dossier = await buildDossier({
    address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    client: deps.client || {
      async getBytecode() { return '0x'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; },
      async getBlockNumber() { return 100n; },
      async getLogs() { return []; },
      async readContract() { return 0n; },
      async getChainId() { return 1; }
    },
    history: false
  });
  const section = dossier.source || {};
  return makeRecord({
    capability: 'chain.source',
    name: 'Verified-source retrieval',
    status: 'UNAVAILABLE',
    checked: ['dossier source section without a provider'],
    succeeded: [],
    failed: [`verified-source provider (none configured; section standing: ${section.standing || 'missing'})`],
    unknown: [],
    dependencies: [{ name: 'explorer API + key', state: 'not-configured (registration required; needs approval)' }],
    executedWith: 'mock',
    evidence: { standing: section.standing || null, requirements: section.requirements || [] }
  });
}

function keyConfigured(apiKey) {
  return Boolean(apiKey) && !String(apiKey).includes('your_meta') && !String(apiKey).startsWith('mock_');
}

async function checkSpark(deps = {}) {
  const apiKey = deps.apiKey !== undefined ? deps.apiKey : require('../config/env').modelApiKey;
  const configured = keyConfigured(apiKey);
  if (!configured) {
    return makeRecord({
      capability: 'model.spark',
      name: 'Muse Spark model reasoning',
      status: 'UNAVAILABLE',
      checked: ['api key presence (value never recorded)'],
      succeeded: [],
      failed: ['api key presence (missing or placeholder)'],
      unknown: [],
      dependencies: [{ name: 'MODEL_API_KEY', state: 'missing-or-placeholder' }],
      executedWith: deps.apiKey !== undefined ? 'mock' : 'probe',
      evidence: { configured: false }
    });
  }
  return makeRecord({
    capability: 'model.spark',
    name: 'Muse Spark model reasoning',
    status: 'PARTIAL',
    checked: ['api key presence (value never recorded)'],
    succeeded: ['api key presence (configured)'],
    failed: [],
    unknown: ['live reachability (not re-probed offline; probe script PASSED live 2026-10-27; F9/F10/F12 strict-schema lanes live-verified per contracts)'],
    dependencies: [{ name: 'MODEL_API_KEY', state: 'configured' }, { name: 'Meta Model API', state: 'unprobed-this-run' }],
    executedWith: deps.apiKey !== undefined ? 'mock' : 'probe',
    evidence: { configured: true }
  });
}

async function checkSam(deps = {}) {
  const apiKey = deps.apiKey !== undefined ? deps.apiKey : require('../config/env').modelApiKey;
  const configured = keyConfigured(apiKey);
  if (!configured) {
    return makeRecord({
      capability: 'model.sam',
      name: 'SAM 3.1 visual segmentation',
      status: 'UNAVAILABLE',
      checked: ['api key presence (value never recorded)'],
      succeeded: [],
      failed: ['api key presence (missing or placeholder) — live path closed; mock mode is labeled, never silent'],
      unknown: [],
      dependencies: [{ name: 'MODEL_API_KEY', state: 'missing-or-placeholder' }],
      executedWith: deps.apiKey !== undefined ? 'mock' : 'probe',
      evidence: { configured: false }
    });
  }
  return makeRecord({
    capability: 'model.sam',
    name: 'SAM 3.1 visual segmentation',
    status: 'PARTIAL',
    checked: ['api key presence (value never recorded)', 'request/response codec (unit-tested)'],
    succeeded: ['api key presence (configured)', 'request/response codec (samSchema suite)'],
    failed: [],
    unknown: ['positive-match segmentation on a real UI (live probe uses a 1px fixture: reachability proven, discrimination unproven)'],
    dependencies: [{ name: 'MODEL_API_KEY', state: 'configured' }, { name: 'Meta Model API', state: 'probe-verified-live-2026-10-27' }],
    executedWith: deps.apiKey !== undefined ? 'mock' : 'probe',
    evidence: { configured: true, mockModeLabeled: true }
  });
}

async function checkMonitorPush(deps = {}) {
  const { WatchScheduler } = require('./scheduler');
  const seen = await withTempDirAsync('assertara-ready-mon-', async (dir) => {
    let now = scriptedNow(deps);
    const sched = new WatchScheduler({ dir, now: () => now });
    sched.client = {
      async getBytecode() { return '0x11'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    sched.addTarget({ address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', intervalMs: 5000 });
    now += 6000;
    await sched.tickOnce();
    return sched.getAlerts({});
  });
  return makeRecord({
    capability: 'monitor.push',
    name: 'Night Watch alert delivery',
    status: 'PARTIAL',
    checked: ['change detection + alert store (live local run)', 'push delivery transport'],
    succeeded: [`change detection + alert store (live local run; ${seen.length} alerts readable via getAlerts)`],
    failed: ['push delivery transport (none exists; alerts are pull-only)'],
    unknown: [],
    dependencies: [{ name: 'scheduler store', state: 'working' }, { name: 'push transport', state: 'none-ships' }],
    executedWith: 'live',
    evidence: { alertsReadable: seen.length }
  });
}

async function checkWebIntel() {
  const { describeTools } = require('./toolRegistry');
  const found = describeTools().filter((t) => /web|search|intel|browser/i.test(`${t.name} ${t.description}`));
  if (found.length === 0) {
    return makeRecord({
      capability: 'web.intel',
      name: 'Public incident intel / web research',
      status: 'UNAVAILABLE',
      checked: ['tool registry scan for web/intel tools'],
      succeeded: [],
      failed: ['web research tool (none registered; F7 incident synthesis has no source)'],
      unknown: [],
      dependencies: [{ name: 'web research tool', state: 'none-ships' }],
      executedWith: 'probe',
      evidence: { registeredTools: describeTools().length }
    });
  }
  return makeRecord({
    capability: 'web.intel',
    name: 'Public incident intel / web research',
    status: 'PARTIAL',
    checked: ['tool registry scan for web/intel tools'],
    succeeded: [`tool registry scan (${found.map((t) => t.name).join(',')})`],
    failed: [],
    unknown: ['tool behavior (registered but unverified by this check)'],
    dependencies: [{ name: 'web research tool', state: 'registered-unverified' }],
    executedWith: 'probe',
    evidence: { found: found.map((t) => t.name) }
  });
}

// ---------- Inventory ----------
// Curated classifications with dated evidence. `classification` is what the
// project claims overall (it may cite prior live verification); the automated
// `check` beside it reports only what it verified itself, freshly.

const CAPABILITIES = {
  'f3.runners': {
    id: 'f3.runners', name: 'Experimental runners lane',
    purpose: 'Opt-in frontier workflows (F3) isolated from verified findings.',
    entryPoint: 'runExperimental (src/agent/features.js)',
    dependencies: [], executionKind: 'deterministic',
    classification: 'TEST_ONLY',
    classificationEvidence: 'Gate returns GATED/EXPERIMENTAL correctly (agent T19); zero runners registered, so nothing production exists to run.',
    lastLiveEvidence: null,
    limitations: ['No experimental runners are enabled; frontier workflows land here only after evaluation.'],
    tests: ['test/unit/agent.test.js T19', 'test/unit/readiness.test.js T2/T5'],
    check: checkExperimentalRunners
  },
  'core.local': {
    id: 'core.local', name: 'Local deterministic core',
    purpose: 'Evidence graph, event recording, replay, scheduler store — the offline foundation every feature builds on.',
    entryPoint: 'evidenceGraph.js, replay.js, scheduler.js',
    dependencies: ['chain client (injected, read-only)'], executionKind: 'deterministic',
    classification: 'READY',
    classificationEvidence: 'Exercised live by its own check (graph append, hash-chained record, verified replay, scheduler tick) with no network.',
    lastLiveEvidence: null,
    limitations: ['Scheduler runs only while the process is alive (no 24/7 claim).'],
    tests: ['test/unit/readiness.test.js T2'],
    check: checkLocalCore
  },
  'exec.harness': {
    id: 'exec.harness', name: 'Isolated PoC execution',
    purpose: 'Run exploit reproductions and patch verifications inside containment (F15 execute lane).',
    entryPoint: 'submitHarnessRun (src/agent/harness.js), src/agent/sandbox.js, sandbox_exec tool',
    dependencies: ['container runtime (docker/podman)', 'sandbox adapter (contracts §27)', 'verified sandbox image'], executionKind: 'external-state',
    classification: 'UNAVAILABLE',
    classificationEvidence: 'Sandbox adapter ships (Phase 18) but no runtime/verified image here: Docker absent, Podman absent 2026-10-28. Execute-kind requests return EXECUTION_UNAVAILABLE (harness T2, sandbox tests).',
    lastLiveEvidence: null,
    limitations: ['No Docker/Podman or verified image here; untrusted code is never run on the host as a substitute.'],
    tests: ['test/unit/harness.test.js T1/T2', 'test/unit/sandbox.test.js', 'test/unit/readiness.test.js T2/T3'],
    check: checkHarness
  },
  'media.stt': {
    id: 'media.stt', name: 'Audio transcription backend',
    purpose: 'Turn call audio into timestamped segments for Scam-Call Analyzer (F8 audio lane).',
    entryPoint: 'ingestAudio (src/agent/audioIngest.js), transcribe_audio tool',
    dependencies: ['ffmpeg (decoding)', 'local STT backend (contracts §14)'], executionKind: 'external-state',
    classification: 'UNAVAILABLE',
    classificationEvidence: 'No STT backend ships; ffmpeg/ffprobe absent 2026-10-27. Valid audio returns TRANSCRIPTION_UNAVAILABLE; transcript-only lane unaffected.',
    lastLiveEvidence: null,
    limitations: ['Only WAV/PCM is parseable; transcription needs an STT backend + ffmpeg.'],
    tests: ['test/unit/audioIngest.test.js T1/T4', 'test/unit/readiness.test.js T8'],
    check: checkStt
  },
  'media.frames': {
    id: 'media.frames', name: 'Video frame extraction',
    purpose: 'Decode walkthrough video into timestamped frames for F11 ingest lane.',
    entryPoint: 'ingestVideo (src/agent/videoIngest.js), video_analysis tool',
    dependencies: ['ffmpeg', 'frame extractor (contracts §19)'], executionKind: 'external-state',
    classification: 'UNAVAILABLE',
    classificationEvidence: 'No extractor ships; ffmpeg absent 2026-10-27. Valid video returns VIDEO_PROCESSING_UNAVAILABLE; caller-supplied frames use the analysis lane instead.',
    lastLiveEvidence: null,
    limitations: ['Frame analysis works on supplied frames only (provenance labeled).'],
    tests: ['test/unit/videoIngest.test.js T1/T7', 'test/unit/readiness.test.js T8'],
    check: checkFrames
  },
  'media.ocr': {
    id: 'media.ocr', name: 'Tesseract OCR text extraction',
    purpose: 'Extract on-screen text from SAM regions (core pipeline + F11 frames).',
    entryPoint: 'extractUiTexts (src/services/ocrService.js), ocr_region tool',
    dependencies: ['tesseract.js', 'eng traineddata'], executionKind: 'deterministic',
    classification: 'READY',
    classificationEvidence: 'tesseract.js installed; real OCR ran exact on synthetic frames in the Phase 10 live walkthrough (contracts §19).',
    lastLiveEvidence: '2026-10-27: Phase 10 live walkthrough, real OCR exact.',
    limitations: ['Automated check verifies installation only; recognition needs traineddata and is not re-probed in the unit suite.'],
    tests: ['test/unit/readiness.test.js T2'],
    check: checkOcr
  },
  'sim.forge': {
    id: 'sim.forge', name: 'Foundry EVM simulation',
    purpose: 'Genuine EVM execution of suspicious transactions (core pipeline simulator).',
    entryPoint: 'simulateTransactionWithFoundry (src/services/simulatorService.js), simulate_tx tool',
    dependencies: ['forge', 'forge-std'], executionKind: 'external-state',
    classification: 'PARTIAL',
    classificationEvidence: 'forge 1.7.1 present 2026-10-27, but generated tests fail to compile (forge-std unresolvable; no lib/forge-std, no node_modules/forge-std) → honest FALLBACK verified by direct run. Binary presence alone is not readiness.',
    lastLiveEvidence: '2026-10-27: real run → FALLBACK (compilation failed), executed:false.',
    limitations: ['EXECUTED path blocked on forge-std wiring; no fork simulation (plain forge test, no --fork-url).'],
    tests: ['test/unit/readiness.test.js T2'],
    check: checkForge
  },
  'chain.history': {
    id: 'chain.history', name: 'Bounded approval history discovery',
    purpose: 'Address-scoped Approval log discovery with honest coverage (F6).',
    entryPoint: 'discoverApprovals (src/agent/chain.js), chain_history tool',
    dependencies: ['RPC provider', 'archive access (deep ranges)'], executionKind: 'external-state',
    classification: 'PARTIAL',
    classificationEvidence: 'Live 2026-10-27 on publicnode: address+topic queries over recent ranges succeed (empty + positive cases, live allowance ground truth); topic-only and ~20k+ block ranges rejected; no indexing API configured (contracts §15).',
    lastLiveEvidence: '2026-10-27: publicnode recent-range discovery verified; deep ranges rejected (403).',
    limitations: ['Recent ranges only on the free tier; full-history claims unsupported by construction.'],
    tests: ['test/unit/history.test.js', 'test/unit/readiness.test.js T2'],
    check: checkChainHistory
  },
  'chain.source': {
    id: 'chain.source', name: 'Verified-source retrieval',
    purpose: 'Fetch verified contract source for dossiers (F7 source section).',
    entryPoint: 'buildDossier sourceProvider (src/agent/dossier.js)',
    dependencies: ['explorer API + key (registration required)'], executionKind: 'external-state',
    classification: 'UNAVAILABLE',
    classificationEvidence: 'No sourceProvider is configured; dossier source sections report UNAVAILABLE with requirements (dossier T4).',
    lastLiveEvidence: null,
    limitations: ['Source sections unavailable; ABI/provided-source analysis labeled accordingly.'],
    tests: ['test/unit/dossier.test.js T4', 'test/unit/readiness.test.js T2'],
    check: checkChainSource
  },
  'model.spark': {
    id: 'model.spark', name: 'Muse Spark model reasoning',
    purpose: 'Model-backed investigation, Q&A, assessment, vision, and localization lanes.',
    entryPoint: 'SparkAdapter (src/agent/sparkAdapter.js)',
    dependencies: ['MODEL_API_KEY', 'Meta Model API'], executionKind: 'model-assisted',
    classification: 'READY',
    classificationEvidence: 'Probe script PASSED (live) 2026-10-27; F9/F10/F12 strict-schema lanes live-verified (contracts §17/§18/§20); vision input_image live-verified (§19).',
    lastLiveEvidence: '2026-10-27: probe script PASSED (live), 9.4s.',
    limitations: ['Other feature-runner schemas are stub-tested only; live behavior unverified (contracts §17).'],
    tests: ['src/scripts/probeMetaApi.js (live, outside unit suite)', 'test/unit/agent.test.js T3/T4 (stubbed)'],
    check: checkSpark
  },
  'model.sam': {
    id: 'model.sam', name: 'SAM 3.1 visual segmentation',
    purpose: 'Segment UI concepts into regions with boxes for OCR + comparison.',
    entryPoint: 'segmentUiRegions (src/services/samService.js), segment_concept tool',
    dependencies: ['MODEL_API_KEY', 'Meta Model API'], executionKind: 'model-assisted',
    classification: 'PARTIAL',
    classificationEvidence: 'Probe script PASSED (live) 2026-10-27 on a 1px fixture (reachability proven); request/response codec unit-tested (samSchema suite). Positive-match segmentation on a real UI undemonstrated.',
    lastLiveEvidence: '2026-10-27: probe script PASSED (live) on 1px fixture (zero-match case).',
    limitations: ['Discrimination on real UIs unproven; keyless runs use labeled mock regions (never silent).'],
    tests: ['test/unit/samSchema.test.js', 'src/scripts/probeMetaApi.js (live, outside unit suite)'],
    check: checkSam
  },
  'monitor.push': {
    id: 'monitor.push', name: 'Night Watch alert delivery',
    purpose: 'Deliver monitoring alerts beyond pull-based getAlerts (F14).',
    entryPoint: 'WatchScheduler.getAlerts (src/agent/scheduler.js)',
    dependencies: ['scheduler store', 'push transport (none ships)'], executionKind: 'deterministic',
    classification: 'PARTIAL',
    classificationEvidence: 'Detection + alert store run live locally (scheduler T6; this check re-runs them); no push transport exists.',
    lastLiveEvidence: null,
    limitations: ['Alerts are pull-only; no push delivery, routes, or UI.'],
    tests: ['test/unit/scheduler.test.js T6', 'test/unit/readiness.test.js T2'],
    check: checkMonitorPush
  },
  'web.intel': {
    id: 'web.intel', name: 'Public incident intel / web research',
    purpose: 'Source public incident reports for dossier synthesis (F7).',
    entryPoint: null,
    classification: 'UNAVAILABLE',
    classificationEvidence: 'No web/intel tool is registered in the tool registry (this check scans it); F7 limitations document the gap.',
    dependencies: [], executionKind: 'external-state',
    lastLiveEvidence: null,
    limitations: ['Gap documented, not filled: no approved web source, no retrieval tool.'],
    tests: ['test/unit/readiness.test.js T2'],
    check: checkWebIntel
  }
};

function listCapabilities() {
  return Object.keys(CAPABILITIES);
}

async function checkReadiness(id, deps = {}) {
  const cap = CAPABILITIES[id];
  if (!cap) throw readinessError('UNKNOWN_CAPABILITY', `unknown capability: ${String(id).slice(0, 120)}`);
  try {
    const rec = await cap.check(deps);
    validateReadinessRecord(rec);
    return rec;
  } catch (err) {
    if (err && err.code === 'LIVE_NEEDS_TARGET') throw err;
    return makeRecord({
      capability: id,
      name: cap.name,
      status: 'FAILED_CHECK',
      checked: ['capability check execution'],
      succeeded: [],
      failed: [`capability check execution (${String((err && err.message) || err).slice(0, 300)})`],
      unknown: [],
      dependencies: (cap.dependencies || []).map((name) => ({ name, state: 'unchecked (check failed)' })),
      executedWith: deps && (deps.probe || deps.client || deps.apiKey !== undefined || deps.resolve || deps.existsSync) ? 'mock' : 'probe',
      evidence: { checkError: String((err && err.message) || err).slice(0, 500) }
    });
  }
}

async function checkAllReadiness(depsById = {}) {
  const results = {};
  for (const id of Object.keys(CAPABILITIES)) {
    results[id] = await checkReadiness(id, (depsById && depsById[id]) || {});
  }
  const summary = {};
  for (const s of READINESS_STATUSES) summary[s] = 0;
  for (const r of Object.values(results)) summary[r.status] += 1;
  return { checkedAt: new Date().toISOString(), results, summary };
}

module.exports = {
  READINESS_STATUSES, EXECUTION_EVIDENCE, EXECUTION_KINDS,
  CAPABILITIES, listCapabilities,
  validateReadinessRecord, checkReadiness, checkAllReadiness
};

