/**
 * Demo A end-to-end orchestrator: ONE command for the complete
 * agent → investigate → execute → manifest → attest → publish →
 * judge → Command-Centre flow.
 *
 * Usage:
 *   node demo/demoA.js --policy-base URL --signer-base URL --anvil-rpc URL
 *     --registry <registry.json> --trusted-root <addr>
 *     --trusted-authorities <addr,addr> --attestation-key-file <file>
 *     --publisher-key-file <file> [--api-key KEY]
 *     [--rpc <url>] [--contract <addr>] [--chain-id N]
 *     [--contract-version 1|2] [--confirmations N]
 *     [--out-dir <dir>] [--force] [--skip-publish] [--no-open]
 *
 * Prerequisites (running before this command): policy backend,
 * controlled signer, and Anvil (e.g. `node demo/command-stack.js`;
 * pass its printed URLs via the reuse flags). A real MODEL_API_KEY
 * must be configured: Demo A always runs the live model.
 *
 * Every stage reuses the existing implementation: agentDriven's Demo A
 * runner, the provenance HTTP + service modules, the export/judge
 * CLIs (spawned, never reimplemented). Private keys are read from
 * FILES only, never from arguments, and never printed. Stages run in
 * order and the first failure aborts with a non-zero exit; nothing
 * continues silently after a failed attestation or publication.
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const REPO_ROOT = path.join(__dirname, '..');
const HEX64 = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const PRIVKEY = /^0x[0-9a-fA-F]{64}$/;

const DEFAULTS = {
  rpc: 'https://rpc.testnet.arc.io',
  contract: '0xaa216f7679d1701e8f5121cada4d45aa524c8e30',
  chainId: 5042002,
  contractVersion: 2,
  confirmations: 2
};

const USAGE = 'usage: node demo/demoA.js --policy-base URL --signer-base URL --anvil-rpc URL --registry <file> --trusted-root <addr> --trusted-authorities <csv> --attestation-key-file <file> --publisher-key-file <file> [--api-key KEY] [--rpc <url>] [--contract <addr>] [--chain-id N] [--contract-version 1|2] [--confirmations N] [--out-dir <dir>] [--force] [--skip-publish] [--no-open]';

function fail(message) {
  const err = new Error(message);
  err.demoAUsage = true;
  throw err;
}

function parseArgs(argv) {
  const values = new Set(['--policy-base', '--signer-base', '--anvil-rpc', '--api-key',
    '--registry', '--trusted-root', '--trusted-authorities',
    '--attestation-key-file', '--publisher-key-file',
    '--rpc', '--contract', '--chain-id', '--contract-version',
    '--confirmations', '--out-dir']);
  const flags = new Set(['--force', '--skip-publish', '--no-open', '--help', '-h']);
  const o = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (values.has(a)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) fail(`${USAGE} (${a} requires a value)`);
      o[a] = v;
      i += 1;
    } else if (flags.has(a)) {
      o[a] = true;
    } else {
      fail(`${USAGE} (unknown option ${a})`);
    }
  }
  if (o['--help'] || o['-h']) {
    return { help: true };
  }
  for (const f of ['--policy-base', '--signer-base', '--anvil-rpc', '--registry',
    '--trusted-root', '--trusted-authorities',
    '--attestation-key-file', '--publisher-key-file']) {
    if (!o[f]) fail(`${USAGE} (${f} is required)`);
  }
  // agentDriven-compatible env fallbacks for the reuse endpoints only.
  const out = {
    policyBase: o['--policy-base'] || process.env.ASSERTARA_POLICY_BASE,
    signerBase: o['--signer-base'] || process.env.ASSERTARA_SIGNER_BASE,
    anvilRpc: o['--anvil-rpc'] || process.env.ASSERTARA_ANVIL_RPC,
    apiKey: o['--api-key'] || process.env.ASSERTARA_API_KEY || null,
    registry: o['--registry'],
    trustedRoot: o['--trusted-root'],
    trustedAuthorities: o['--trusted-authorities'],
    attestationKeyFile: o['--attestation-key-file'],
    publisherKeyFile: o['--publisher-key-file'],
    rpc: o['--rpc'] || DEFAULTS.rpc,
    contract: o['--contract'] || DEFAULTS.contract,
    chainId: o['--chain-id'] === undefined ? DEFAULTS.chainId : Number(o['--chain-id']),
    contractVersion: o['--contract-version'] === undefined ? DEFAULTS.contractVersion : Number(o['--contract-version']),
    confirmations: o['--confirmations'] === undefined ? DEFAULTS.confirmations : Number(o['--confirmations']),
    outDir: o['--out-dir'] || null,
    force: o['--force'] === true,
    skipPublish: o['--skip-publish'] === true,
    open: o['--no-open'] !== true
  };
  if (!ADDRESS.test(out.trustedRoot)) fail(`${USAGE} (--trusted-root must be an address)`);
  for (const a of out.trustedAuthorities.split(',').map((s) => s.trim()).filter(Boolean)) {
    if (!ADDRESS.test(a)) fail(`${USAGE} (--trusted-authorities must be a comma-separated address list)`);
  }
  if (!ADDRESS.test(out.contract)) fail(`${USAGE} (--contract must be an address)`);
  if (!Number.isInteger(out.chainId) || out.chainId <= 0) fail(`${USAGE} (--chain-id must be a positive integer)`);
  if (out.contractVersion !== 1 && out.contractVersion !== 2) fail(`${USAGE} (--contract-version must be 1 or 2)`);
  if (!Number.isInteger(out.confirmations) || out.confirmations < 0) fail(`${USAGE} (--confirmations must be a non-negative integer)`);
  for (const [label, file] of [['--registry', out.registry], ['--attestation-key-file', out.attestationKeyFile], ['--publisher-key-file', out.publisherKeyFile]]) {
    if (!fs.existsSync(file)) fail(`${label}: file not found: ${file}`);
  }
  return out;
}

function setupOutDir(outDir, force) {
  if (outDir) {
    const resolved = path.resolve(outDir);
    if (fs.existsSync(resolved)) {
      const entries = fs.readdirSync(resolved);
      if (entries.length > 0 && !force) {
        fail(`--out-dir ${resolved} already exists and is not empty (refusing to overwrite; pass --force to reuse it)`);
      }
    } else {
      fs.mkdirSync(resolved, { recursive: true });
    }
    return resolved;
  }
  const base = path.join(REPO_ROOT, 'demo', 'tmp');
  fs.mkdirSync(base, { recursive: true });
  return fs.mkdtempSync(path.join(base, 'demoA-'));
}

function readKeyFile(label, file) {
  let content;
  try {
    content = fs.readFileSync(file, 'utf8').trim();
  } catch (err) {
    fail(`${label}: unreadable file ${file} (${(err && err.message) || err})`);
  }
  if (!PRIVKEY.test(content)) fail(`${label}: ${file} does not contain a 0x 32-byte key`);
  return content;
}

function spawnCapture(cmd, args, opts) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 300000, maxBuffer: 1024 * 1024, ...(opts || {}) }, (error, stdout, stderr) => {
      resolve({ error, stdout: String(stdout || ''), stderr: String(stderr || ''), code: error && typeof error.code === 'number' ? error.code : (error ? 1 : 0) });
    });
  });
}

function openBrowser(url, platform) {
  const plat = platform || process.platform;
  const cmd = plat === 'win32' ? 'cmd' : plat === 'darwin' ? 'open' : 'xdg-open';
  const args = plat === 'win32' ? ['/c', 'start', '""', url] : [url];
  return spawnCapture(cmd, args);
}

// Default (real) stage implementations. Each is a small adapter over
// the existing module or CLI — no reimplemented logic.
const realDeps = {
  async validateReuse({ policyBase, signerBase, anvilRpc }) {
    const { validateReuseTargets } = require('./agentDriven');
    return validateReuseTargets({ policyBase, signerBase, anvilRpc });
  },
  async health(url, apiKey) {
    const res = await fetch(url, { headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {} });
    const parsed = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return parsed;
  },
  // Proves the backend serves the provenance API (not a stale stack
  // predating it): an invalid digest must answer 400 JSON, never the
  // Express HTML 404. Cheap, read-only, no side effects.
  async provenanceSurface(policyBase, apiKey) {
    const res = await fetch(`${policyBase}/api/v1/provenance/manifests/0`, {
      headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {}
    });
    const text = await res.text();
    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch { /* HTML 404 falls through to the error below */ }
    if (res.status !== 400 || !parsed || parsed.code !== 'DIGEST_INVALID') {
      throw new Error('policy backend does not serve the provenance API (stale stack?) — restart the command stack from current code');
    }
    return true;
  },
  async runAgent({ policyBase, signerBase, apiKey, tmpDir, log }) {
    const { runDemoATask } = require('./agentDriven');
    return runDemoATask({ policyBase, signerBase, tmpDir, apiKey, onEvent: (e) => log(`  [${e.event}] ${e.detail || ''}`) });
  },
  async postJson(url, body, apiKey) {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {})
      },
      body: JSON.stringify(body)
    });
    const parsed = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`POST ${url} -> ${res.status}: ${parsed.error || parsed.code || 'request failed'}`);
    return parsed;
  },
  buildV1Package({ requestId, expectDigest, stackTmp }) {
    const { findByEvalId } = require('../src/services/investigationStore');
    const { buildManifest, buildVerificationPackage } = require('../src/services/provenanceManifest');
    const snap = JSON.parse(fs.readFileSync(path.join(stackTmp, 'agent-requests.json'), 'utf8'));
    const request = (snap.requests || []).find((r) => r.id === requestId);
    if (!request) throw new Error(`request ${requestId} not in stack snapshot ${stackTmp}`);
    const found = findByEvalId(request.evalId, path.join(stackTmp, 'investigations.jsonl'));
    if (!found.ok) throw new Error(`no persisted investigation record for eval ${request.evalId}`);
    const built = buildManifest({ record: found.record, request });
    if (built.manifestDigest !== String(expectDigest).toLowerCase()) {
      throw new Error(`rebuilt digest ${built.manifestDigest} differs from manifest route digest ${expectDigest}`);
    }
    return buildVerificationPackage(built);
  },
  findStackTmp(requestId) {
    const base = path.join(REPO_ROOT, 'demo', 'tmp');
    if (!fs.existsSync(base)) throw new Error(`stack tmp base missing: ${base} (is the command stack running?)`);
    const dirs = fs.readdirSync(base)
      .filter((d) => d.startsWith('cmd-'))
      .map((d) => path.join(base, d))
      .filter((d) => { try { return fs.statSync(d).isDirectory(); } catch { return false; } })
      .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
    for (const dir of dirs) {
      try {
        const snap = JSON.parse(fs.readFileSync(path.join(dir, 'agent-requests.json'), 'utf8'));
        if ((snap.requests || []).some((r) => r.id === requestId)) return dir;
      } catch { /* not this one */ }
    }
    throw new Error(`no command-stack snapshot under ${base} contains request ${requestId}`);
  },
  async ceremony({ pkg, registry, trustedRoot, trustedAuthorities, signingKey, expectDigest, confirm }) {
    const { attestPackage, parseAddressList } = require('../src/services/provenanceAttestation');
    return attestPackage({
      pkg, registry, trustedRoot,
      trustedAuthorities: parseAddressList(trustedAuthorities.join(','), '--trusted-authorities'),
      denyList: [],
      privateKey: signingKey,
      expectDigest,
      confirm,
      storeDir: path.join(REPO_ROOT, 'data'),
      manifestStore: path.join(REPO_ROOT, 'data', 'manifests.jsonl')
    });
  },
  runExport({ v1File, attFile, expectDigest, outFile }) {
    return spawnCapture(process.execPath, [
      path.join(REPO_ROOT, 'src', 'attestation', 'exportPackage.js'),
      '--package', v1File, '--attestation', attFile,
      '--expect-digest', expectDigest, '--out', outFile
    ], { cwd: REPO_ROOT });
  },
  async publish({ exported, registry, trustedRoot, trustedAuthorities, publisherKey, rpc, chainId, contract, contractVersion, confirmations }) {
    const { publishAttestation } = require('../src/services/attestationPublisher');
    const { parseAddressList } = require('../src/services/provenanceAttestation');
    return publishAttestation({
      signedPackage: exported.package, registry, trustedRoot,
      trustedAuthorities: parseAddressList(trustedAuthorities.join(','), '--trusted-authorities'),
      denyList: [],
      rpcUrl: rpc, publisherKey, chainId,
      contractAddress: contract, contractVersion, confirmations
    });
  },
  runJudge({ rpc, contract, investigation, attester, exportFile, registryFile, trustedRoot, contractVersion, submitTx }) {
    const args = [
      path.join(REPO_ROOT, 'src', 'attestation', 'judge.js'),
      '--rpc', rpc, '--contract', contract,
      '--investigation', investigation, '--attester', attester,
      '--manifest-file', exportFile,
      '--registry', registryFile, '--trusted-root', trustedRoot,
      '--contract-version', String(contractVersion)
    ];
    if (submitTx) args.push('--submit-tx', submitTx);
    return spawnCapture(process.execPath, args, { cwd: REPO_ROOT });
  },
  openCommandCentre: openBrowser
};

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function runDemoA(argv, deps, io) {
  const out = io || { log: console.log, error: console.error };
  const log = (...a) => out.log(...a);
  const d = deps || realDeps;
  const opts = parseArgs(argv);
  if (opts.help) {
    log(USAGE);
    return { ok: true, help: true };
  }
  const runDir = setupOutDir(opts.outDir, opts.force);
  log(`demoA: artifacts -> ${runDir}`);
  const failStage = (stage, detail) => {
    const err = new Error(`demoA FAILED at stage ${stage}: ${detail} (artifacts so far: ${runDir})`);
    err.demoAStage = stage;
    throw err;
  };

  // Preflight: keys (files only), registry, backend reachability.
  const attestationKey = readKeyFile('--attestation-key-file', opts.attestationKeyFile);
  const publisherKey = readKeyFile('--publisher-key-file', opts.publisherKeyFile);
  let registry;
  try {
    registry = JSON.parse(fs.readFileSync(opts.registry, 'utf8'));
  } catch (err) {
    failStage('preflight', `--registry is not valid JSON (${(err && err.message) || err})`);
  }
  if (!registry || typeof registry !== 'object' || !registry.keys) {
    failStage('preflight', '--registry is not a key registry object');
  }
  const authorities = opts.trustedAuthorities.split(',').map((s) => s.trim()).filter(Boolean);
  try {
    await d.health(`${opts.policyBase}/health`, opts.apiKey);
  } catch (err) {
    failStage('preflight', `policy backend unreachable at ${opts.policyBase} (${(err && err.message) || err})`);
  }
  try {
    await d.validateReuse({ policyBase: opts.policyBase, signerBase: opts.signerBase, anvilRpc: opts.anvilRpc });
  } catch (err) {
    failStage('preflight', `stack preflight failed (${(err && err.message) || err})`);
  }
  try {
    await d.provenanceSurface(opts.policyBase, opts.apiKey);
  } catch (err) {
    failStage('preflight', (err && err.message) || err);
  }
  log(`demoA: backend ok (${opts.policyBase}); starting Demo A agent run...`);

  // Stage 1: agent run (existing Demo A flow).
  let outcome;
  try {
    outcome = await d.runAgent({
      policyBase: opts.policyBase, signerBase: opts.signerBase,
      apiKey: opts.apiKey, tmpDir: path.join(runDir, 'agent-tmp'), log
    });
  } catch (err) {
    failStage('agent-run', (err && err.message) || err);
  }
  const action = outcome && outcome.actions && outcome.actions[0];
  if (!action || !action.requestId) failStage('agent-run', 'agent outcome carries no action/requestId');
  if (action.decision !== 'ALLOW') {
    failStage('agent-run', `Demo A must ALLOW; got ${action.decision} (see outcome.json)`);
  }
  writeJson(path.join(runDir, 'outcome.json'), outcome);
  const { requestId, traceId } = action;
  log(`demoA: ALLOW requestId=${requestId} traceId=${traceId} txHash=${action.txHash || '(none)'}`);

  // Stage 2: manifest (existing provenance route) + digest cross-check.
  let manifestDigest;
  let manifest;
  try {
    const built = await d.postJson(`${opts.policyBase}/api/v1/provenance/manifests`, { requestId }, opts.apiKey);
    manifestDigest = built.manifestDigest;
    manifest = built.manifest;
    if (!HEX64.test(manifestDigest || '')) throw new Error('route returned no manifest digest');
  } catch (err) {
    failStage('manifest', (err && err.message) || err);
  }
  const captured = action.provenance && action.provenance.manifestDigest;
  if (captured && captured !== manifestDigest) {
    failStage('manifest', `agent-captured digest ${captured} differs from route digest ${manifestDigest}`);
  }
  writeJson(path.join(runDir, 'manifest.json'), { manifestDigest, manifest });
  log(`demoA: manifest ${manifestDigest}`);

  // Stage 3: v1 package (existing builder) from the stack snapshot.
  let pkg;
  try {
    const stackTmp = d.findStackTmp(requestId);
    pkg = d.buildV1Package({ requestId, expectDigest: manifestDigest, stackTmp });
  } catch (err) {
    failStage('package', (err && err.message) || err);
  }
  const v1File = path.join(runDir, 'demo-run.v1.json');
  writeJson(v1File, pkg);
  log('demoA: v1 package built + digest cross-checked');

  // Stage 4: ceremony preview (must be signable) then sign.
  let preview;
  try {
    preview = await d.ceremony({
      pkg, registry, trustedRoot: opts.trustedRoot, trustedAuthorities: authorities,
      signingKey: attestationKey, expectDigest: manifestDigest, confirm: false
    });
  } catch (err) {
    failStage('ceremony-preview', (err && err.message) || err);
  }
  if (!preview || preview.code !== 'ATTEST_PREVIEW' || !preview.preview) {
    failStage('ceremony-preview', `package refused (${(preview && preview.code) || 'no preview returned'})`);
  }
  writeJson(path.join(runDir, 'ceremony-preview.json'), preview);
  log(`demoA: ceremony preview ok (case ${preview.caseInfo ? preview.caseInfo.case : 'unknown'}); signing...`);
  let ceremony;
  try {
    ceremony = await d.ceremony({
      pkg, registry, trustedRoot: opts.trustedRoot, trustedAuthorities: authorities,
      signingKey: attestationKey, expectDigest: manifestDigest, confirm: true
    });
  } catch (err) {
    failStage('ceremony-sign', (err && err.message) || err);
  }
  if (!ceremony || ceremony.attested !== true || !ceremony.attestation) {
    failStage('ceremony-sign', `attestation not completed (${(ceremony && ceremony.code) || 'no attestation returned'})`);
  }
  writeJson(path.join(runDir, 'ceremony.json'), ceremony);
  const attFile = path.join(runDir, 'demo-run.att.json');
  writeJson(attFile, ceremony.attestation);
  log(`demoA: attested by ${ceremony.attestation.authority}`);

  // Stage 5: export (existing CLI, spawned).
  const exportFile = path.join(runDir, 'demo-run.export.json');
  const exp = await d.runExport({ v1File, attFile, expectDigest: manifestDigest, outFile: exportFile });
  if (exp.code !== 0) {
    failStage('export', (exp.stderr || exp.stdout || `exit ${exp.code}`).trim().slice(0, 500));
  }
  log('demoA: export written');

  const summary = {
    demo: 'A', ok: false,
    investigationId: manifest.investigationId,
    requestId, traceId, manifestDigest,
    decision: action.decision,
    attested: true,
    attester: ceremony.attestation.authority,
    txHash: null, duplicate: false, judge: null,
    artifacts: runDir
  };

  if (!opts.skipPublish) {
    // Stage 6: publish (existing publisher service).
    let exported;
    try {
      exported = JSON.parse(fs.readFileSync(exportFile, 'utf8'));
    } catch (err) {
      failStage('publish', `cannot re-read export (${(err && err.message) || err})`);
    }
    let pub;
    try {
      pub = await d.publish({
        exported, registry, trustedRoot: opts.trustedRoot, trustedAuthorities: authorities,
        publisherKey, rpc: opts.rpc, chainId: opts.chainId,
        contract: opts.contract, contractVersion: opts.contractVersion,
        confirmations: opts.confirmations
      });
    } catch (err) {
      failStage('publish', (err && err.message) || err);
    }
    if (!pub || pub.ok !== true) {
      failStage('publish', `publisher refused (${(pub && pub.code) || 'no result'})`);
    }
    writeJson(path.join(runDir, 'publish.json'), pub);
    summary.txHash = pub.txHash || null;
    summary.duplicate = pub.duplicate === true;
    if (summary.duplicate) {
      log('demoA: attestation already on-chain (idempotent duplicate, no resubmission)');
    } else {
      log(`demoA: published txHash=${pub.txHash}`);
    }

    // Stage 7: judge (existing CLI, spawned). Fresh publications pass the
    // known submission hash so the judge skips on-chain log discovery;
    // idempotent duplicates fall back to the judge's bounded log search.
    const judge = await d.runJudge({
      rpc: opts.rpc, contract: opts.contract,
      investigation: manifest.investigationId,
      attester: ceremony.attestation.authority,
      exportFile, registryFile: opts.registry,
      trustedRoot: opts.trustedRoot, contractVersion: opts.contractVersion,
      submitTx: summary.duplicate ? null : summary.txHash
    });
    fs.writeFileSync(path.join(runDir, 'judge.txt'), `${judge.stdout}\n--- stderr ---\n${judge.stderr}\n`, 'utf8');
    const pass = judge.code === 0 && /judge:\s*VERDICT\s*:?\s*PASS/.test(judge.stdout);
    if (!pass) {
      failStage('judge', `judge did not PASS (exit ${judge.code}; see judge.txt)`);
    }
    summary.judge = 'PASS';
    log('demoA: judge VERDICT: PASS');
  } else {
    summary.judge = 'SKIPPED (--skip-publish: no on-chain record to verify against)';
    log('demoA: --skip-publish: stopping after export (no publication, no judge)');
  }

  summary.ok = true;
  writeJson(path.join(runDir, 'run.json'), summary);
  const centre = `${opts.policyBase}/command/?signer=${encodeURIComponent(opts.signerBase)}&trace=${encodeURIComponent(traceId)}`;
  log('');
  log(`DEMO A ${summary.judge === 'PASS' ? 'PASSED' : 'COMPLETED (unpublished)'}: investigation=${summary.investigationId} digest=${manifestDigest}`);
  log(`  attested=${summary.attested} attester=${summary.attester} txHash=${summary.txHash || '(none)'} judge=${summary.judge}`);
  log(`  artifacts: ${runDir}`);
  log(`  command centre: ${centre}`);
  if (opts.open) {
    const opened = await d.openCommandCentre(centre);
    if (opened.code !== 0) {
      log(`demoA: could not open a browser automatically (exit ${opened.code}); open the URL above manually.`);
    }
  }
  return { ok: true, summary, centre };
}

if (require.main === module) {
  runDemoA(process.argv.slice(2)).then(
    () => { process.exitCode = 0; },
    (err) => {
      if (err && err.demoAUsage) {
        console.error(`demoA: ${err.message}`);
      } else {
        console.error((err && err.stack) || err);
      }
      process.exitCode = 1;
    }
  );
}

module.exports = { runDemoA, parseArgs, setupOutDir, DEFAULTS };
