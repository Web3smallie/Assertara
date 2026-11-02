#!/usr/bin/env node
/**
 * Assertara Phase 3 — offline attestation ceremony.
 *
 * Signs a Phase 2 verification package with the dedicated Assertara
 * attestation key (via ATTESTATION_SIGNING_KEY at ceremony time) and
 * records the attestation plus its audit event in the append-only
 * stores. Human preview + explicit --confirm + --expect-digest required.
 *
 * Ceremony (default):
 *   node src/attestation/attest.js --package <pkg.json> --expect-digest <hex>
 *     --registry <registry.json> [--confirm] [--store-dir <dir>]
 *     [--manifest-store <file>] [--allow-superseded]
 *     [--allow-unverified-execution] [--allow-stale-registry]
 *     [--min-registry-version N] [--max-registry-age-days N]
 *     [--acknowledge '<json>|@<file>']... [--lock-broken <quarantined-lock>]
 *     [--json]
 *
 * Other modes (exclusive with the ceremony):
 *   --status [--digest <hex>] [--investigation <id>] [--json]
 *   --verify --digest <hex> [--key-id <addr>] [--json]
 *   --reconcile [--json]
 *   --amend --amends <ackId> --endorsed <sha> --rationale <text>
 *     --operator <name> [--new-classification <c>]
 *   --note --text <text> --operator <name> [--ref <ackId>]
 *   --break-lock [--max-age-ms <n>]
 *
 * Environment: ATTESTATION_SIGNING_KEY, TRUSTED_ATTESTATION_AUTHORITIES,
 * TRUSTED_REGISTRY_ROOT, ATTESTATION_DENY_ADDRESSES (optional).
 */

const fs = require('fs');
const path = require('path');
const {
  AttestationError,
  attestPackage,
  breakStaleLock,
  ceremonyStatus,
  parseAddressList,
  reconcileShow,
  verifyCompletion,
  appendAmendment,
  appendNote
} = require('../services/provenanceAttestation');

function die(message, code) {
  process.stderr.write(`attest: ${message}\n`);
  process.exit(code === undefined ? 2 : code);
}

function usage() {
  return [
    'usage: node src/attestation/attest.js --package <pkg> --expect-digest <hex> --registry <reg> [--confirm] [options]',
    '       node src/attestation/attest.js --status [--digest <hex>] [--investigation <id>] [--json]',
    '       node src/attestation/attest.js --verify --digest <hex> [--key-id <addr>] [--json]   (locked completion check)',
    '       node src/attestation/attest.js --reconcile [--json]',
    '       node src/attestation/attest.js --amend --amends <ack> --endorsed <sha> --rationale <t> --operator <n>',
    '       node src/attestation/attest.js --note --text <t> --operator <n> [--ref <ack>]',
    '       node src/attestation/attest.js --break-lock [--max-age-ms <n>]',
    '',
    'Without --confirm the ceremony prints its preview and stops (attested:false).',
    '',
    '--verify here checks ceremony completion under the store lock (attestation+audit persisted);',
    'it does NOT verify registry signatures (see registry.js verify) or Phase 2 packages.'
  ].join('\n');
}

function toCamel(flag) {
  return flag.slice(2).replace(/-./g, (m) => m[1].toUpperCase());
}

function parseArgs(argv) {
  const o = { acknowledge: [] };
  const flags = new Set(['--confirm', '--json', '--status', '--verify', '--reconcile', '--amend', '--note', '--break-lock', '--allow-superseded', '--allow-unverified-execution', '--allow-stale-registry']);
  const values = new Set(['--package', '--expect-digest', '--registry', '--store-dir', '--manifest-store', '--min-registry-version', '--max-registry-age-days', '--acknowledge', '--lock-broken', '--digest', '--investigation', '--key-id', '--max-age-ms', '--amends', '--endorsed', '--rationale', '--operator', '--new-classification', '--text', '--ref']);
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') die(usage());
    if (flags.has(a)) {
      o[toCamel(a)] = true;
    } else if (values.has(a)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) die(`${a} requires a value`);
      if (a === '--acknowledge') o.acknowledge.push(v);
      else o[toCamel(a)] = v;
      i += 1;
    } else {
      die(`unknown argument: ${a}\n${usage()}`);
    }
  }
  return o;
}

function parseNonNegativeInt(raw, flag) {
  // Strict: malformed numerics must never silently disable a safety
  // check (Number('') === 0 and Number('abc') === NaN would). Digits
  // only — no signs, exponents, hex, or decimals.
  const text = String(raw).trim();
  if (!/^\d+$/.test(text)) die(`${flag} must be a non-negative integer (got ${JSON.stringify(raw)})`, 1);
  const n = Number(text);
  if (!Number.isSafeInteger(n)) die(`${flag} is out of range: ${text}`, 1);
  return n;
}

function parseNonNegativeNumber(raw, flag) {
  // Strict: empty/NaN/Infinity/negative never pass. Decimals allowed
  // (ages are fractional-day capable); core re-validates identically.
  const text = String(raw).trim();
  if (text.length === 0) die(`${flag} requires a non-negative number (got empty value)`, 1);
  const n = Number(text);
  if (!Number.isFinite(n) || n < 0) die(`${flag} must be a finite non-negative number (got ${JSON.stringify(raw)})`, 1);
  return n;
}

function readJsonFile(file, what) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    die(`${what} unreadable (${file}): ${err.message}`, 1);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    die(`${what} is not valid JSON (${file}): ${err.message}`, 1);
  }
  return null;
}

function parseAcknowledgments(values) {
  const out = [];
  for (const v of values) {
    const text = v.startsWith('@') ? fs.readFileSync(path.resolve(v.slice(1)), 'utf8') : v;
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      die(`--acknowledge is not valid JSON: ${err.message}`);
    }
    if (Array.isArray(parsed)) out.push(...parsed);
    else out.push(parsed);
  }
  return out;
}

function printPreview(p) {
  const L = [];
  L.push('=== ATTESTATION PREVIEW — operator review required ===');
  L.push(`investigation : ${p.investigationId}`);
  L.push(`manifestDigest: ${p.manifestDigest}`);
  L.push(`traceId     : ${p.traceId}`);
  L.push(`requestId     : ${p.requestId === null ? '(none)' : p.requestId}`);
  L.push('--- Muse Spark ---');
  L.push(`  status=${p.museSpark.status} contribution=${p.museSpark.contribution} observed=${p.museSpark.observedModel === null ? '(none)' : p.museSpark.observedModel} verdict=${p.museSpark.modelVerdict === null ? '(none)' : p.museSpark.modelVerdict} accepted=${p.museSpark.verdictAccepted}`);
  L.push('--- SAM 3.1 ---');
  L.push(`  aggregate=${p.sam.aggregateStatus} contribution=${p.sam.contribution} detected=${p.sam.detectedCount} regionsInPrompt=${p.sam.regionsInPrompt} refsValidated=${p.sam.refsValidated}`);
  for (const pr of p.sam.prompts) L.push(`    #${pr.index} ${pr.prompt} status=${pr.status} detections=${pr.detections}`);
  L.push('--- decision ---');
  L.push(`  agent=${p.decision.agent} evaluation=${p.decision.evaluation} evalVerdict=${p.decision.evalVerdict} reasoningOrigin=${p.decision.reasoningOrigin}`);
  L.push(`  safeguards: ${p.safeguards.length === 0 ? '(none recorded)' : p.safeguards.join(', ')}`);
  L.push('--- evidence ---');
  L.push(`  evidenceDigest=${p.evidence.digest}`);
  L.push(`  publicDigest  =${p.evidence.publicDigest}`);
  L.push('--- transaction ---');
  L.push(`  hash=${p.transaction.transactionHash === null ? '(none)' : p.transaction.transactionHash} execution=${p.transaction.executionStatus} receipt=${p.transaction.receiptStatus === null ? '(none)' : p.transaction.receiptStatus} block=${p.transaction.blockNumber === null ? '(none)' : p.transaction.blockNumber} chain=${p.transaction.chainId} grade=${p.transaction.grade}`);
  L.push('--- key ---');
  L.push(`  address=${p.key.address} state=${p.key.state} registryVersion=${p.registryVersion} manifestStore=${p.manifestStore}`);
  L.push(`--- case ${p.case} (action: ${p.action})${p.incompleteEvidence ? ' INCOMPLETE MODEL EVIDENCE' : ''} ---`);
  L.push(`warnings (${p.warnings.length}):`);
  for (const w of p.warnings) L.push(`  - ${w}`);
  return L.join('\n');
}

async function runCeremony(o) {
  if (!o.package || !o.expectDigest || !o.registry) die(`ceremony requires --package --expect-digest --registry\n${usage()}`);
  const pkg = readJsonFile(o.package, 'verification package');
  const registry = readJsonFile(o.registry, 'key registry');
  const signingKey = process.env.ATTESTATION_SIGNING_KEY;
  if (!signingKey) die('ATTESTATION_SIGNING_KEY is not set: refusing to run without the ceremony key', 1);
  const trustedRoot = process.env.TRUSTED_REGISTRY_ROOT;
  if (!trustedRoot) die('TRUSTED_REGISTRY_ROOT is not set: refusing to run without an independently obtained root', 1);
  let trustedAuthorities;
  let denyList = [];
  try {
    trustedAuthorities = parseAddressList(process.env.TRUSTED_ATTESTATION_AUTHORITIES, 'TRUSTED_ATTESTATION_AUTHORITIES');
    denyList = parseAddressList(process.env.ATTESTATION_DENY_ADDRESSES, 'ATTESTATION_DENY_ADDRESSES');
  } catch (err) {
    die(err.message, 1);
  }
  if (trustedAuthorities.length === 0) die('TRUSTED_ATTESTATION_AUTHORITIES is empty: refusing to run with no trusted keys', 1);
  let lockBroken = null;
  if (o.lockBroken) {
    const qb = readJsonFile(o.lockBroken, 'quarantined lock');
    const startedAt = typeof qb.startedAt === 'number' ? qb.startedAt : null;
    lockBroken = {
      quarantined: path.resolve(o.lockBroken),
      previous: { pid: qb.pid, startedAt, ageMs: startedAt === null ? null : Date.now() - startedAt }
    };
  }
  let result;
  try {
    result = await attestPackage({
      pkg,
      registry,
      trustedRoot,
      trustedAuthorities,
      denyList,
      privateKey: signingKey,
      expectDigest: o.expectDigest,
      confirm: o.confirm === true,
      storeDir: o.storeDir,
      manifestStore: o.manifestStore,
      allowSuperseded: o.allowSuperseded === true,
      allowUnverifiedExecution: o.allowUnverifiedExecution === true,
      allowStaleRegistry: o.allowStaleRegistry === true,
      minRegistryVersion: o.minRegistryVersion === undefined ? undefined : parseNonNegativeInt(o.minRegistryVersion, '--min-registry-version'),
      maxRegistryAgeDays: o.maxRegistryAgeDays === undefined ? undefined : parseNonNegativeNumber(o.maxRegistryAgeDays, '--max-registry-age-days'),
      acknowledge: parseAcknowledgments(o.acknowledge),
      lockBroken
    });
  } catch (err) {
    if (err instanceof AttestationError) die(`${err.code}: ${err.message}`, 1);
    throw err;
  }
  if (o.json === true) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    if (result.preview) process.stdout.write(`${printPreview(result.preview)}\n`);
    process.stdout.write(`phase=${result.phase} attested=${result.attested} opId=${result.opId === null ? '(none)' : result.opId}\n`);
    process.stdout.write(`${result.message}\n`);
    if (result.details) process.stdout.write(`details=${JSON.stringify(result.details)}\n`);
    if (result.acksRecorded && result.acksRecorded.length > 0) {
      process.stdout.write(`acksRecorded=${result.acksRecorded.join(',')}\n`);
    }
    if (result.adopted) process.stdout.write(`adoptedAttestation=${result.adopted.attestation} adoptedAudit=${result.adopted.audit}\n`);
    process.stdout.write(`lockReleased=${result.lockReleased}\n`);
  }
  if (result.attested !== true) process.exit(1);
  if (result.lockReleased !== true) {
    process.stderr.write('attest: WARNING: attestation completed but the lock release is unconfirmed. Inspect the lock file before the next ceremony.\n');
    process.exit(1);
  }
}

function runStatus(o) {
  const result = ceremonyStatus({ storeDir: o.storeDir, manifestDigest: o.digest, investigationId: o.investigation });
  if (o.json === true) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  process.stdout.write('=== OBSERVATIONAL STATUS — not authoritative, never attested:true ===\n');
  process.stdout.write(`observedAt=${new Date(result.observedAt).toISOString()} lock=${result.lock.present ? 'PRESENT' : 'absent'}\n`);
  if (result.lock.present && result.lock.holder) {
    process.stdout.write(`lockHolder pid=${result.lock.holder.pid} host=${result.lock.holder.host} startedAt=${result.lock.holder.startedAt}\n`);
  }
  const c = result.corruptionObserved;
  process.stdout.write(`corruptionObserved attestations(m=${c.attestations.malformed},b=${c.attestations.blanks},s=${c.attestations.shapeInvalid}) audit(m=${c.audit.malformed},b=${c.audit.blanks},s=${c.audit.shapeInvalid}) journal(m=${c.journal.malformed},b=${c.journal.blanks},s=${c.journal.shapeInvalid}) [m=malformed b=blank s=shape-invalid]\n`);
  for (const t of result.tailsObserved) {
    process.stdout.write(`tailObserved ${t.store} offset=${t.offset} length=${t.length} verdict=${t.verdict.verdict}(${t.verdict.reason})\n`);
  }
  process.stdout.write(`journalObserved acks=${result.journalObserved.events} amendments=${result.journalObserved.amendments} notes=${result.journalObserved.notes} contested=${result.journalObserved.contested.length} chainBreak=${result.journalObserved.chainBreak === null ? 'none' : result.journalObserved.chainBreak}\n`);
  for (const id of result.identitiesObserved) {
    process.stdout.write(`identityObserved digest=${id.manifestDigest} key=${id.keyId} attestation=${id.observedAttestation} audit=${id.observedAudit}\n`);
  }
  if (result.identitiesObserved.length === 0) process.stdout.write('(no identities observed)\n');
}

async function runVerify(o) {
  if (!o.digest) die('--verify requires --digest');
  const result = await verifyCompletion({ storeDir: o.storeDir, manifestDigest: o.digest, keyId: o.keyId });
  if (o.json === true) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(`phase=${result.phase} attested=${result.attested}\n`);
    process.stdout.write(`${result.message}\n`);
    for (const id of result.identities) {
      process.stdout.write(`identity digest=${id.manifestDigest} key=${id.keyId} opId=${id.opId} attestation=${id.attestation} audit=${id.audit} complete=${id.complete}\n`);
    }
  }
  if (result.attested !== true) process.exit(1);
}

function runReconcile(o) {
  const result = reconcileShow({ storeDir: o.storeDir });
  if (o.json === true) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  process.stdout.write('=== OBSERVATIONAL RECONCILIATION VIEW — re-verified at act time ===\n');
  if (result.items.length === 0) process.stdout.write('(no attestation/audit debris observed)\n');
  for (const it of result.items) {
    process.stdout.write(`${it.store} ${it.kind} offset=${it.offset} length=${it.length} sha=${it.bytesSha256} ack=${it.ackId} coverage=${it.coverage} suggest=${it.suggestedClassification}\n`);
  }
  if (result.chainBreak !== null && result.chainBreak !== undefined) {
    process.stdout.write(`JOURNAL CHAIN BREAK at line ${result.chainBreak}: ceremonies and journal mutations are BLOCKED for this store (forensic reads only; preserve the store, do not delete it)\n`);
  }
  if (result.journalDebris.length === 0) process.stdout.write('(no journal debris observed)\n');
  for (const jd of result.journalDebris) {
    if (jd.kind === 'tail') {
      process.stdout.write(`journal tail offset=${jd.offset} length=${jd.length} sha=${jd.bytesSha256} verdict=${jd.verdict.verdict}(${jd.verdict.reason}) coverage=${jd.coverage}\n`);
    } else {
      process.stdout.write(`journal BLOCKING ${jd.kind} offset=${jd.offset} length=${jd.length} sha=${jd.bytesSha256} ack=${jd.ackId} coverage=${jd.coverage} suggest=${jd.suggestedClassification}\n`);
    }
  }
}

function runAmend(o) {
  if (!o.amends || !o.endorsed || !o.rationale || !o.operator) die('--amend requires --amends --endorsed --rationale --operator');
  try {
    const result = appendAmendment({
      storeDir: o.storeDir,
      amendsAckId: o.amends,
      endorsedRecordSha256: o.endorsed,
      newRationale: o.rationale,
      newClassification: o.newClassification,
      operator: o.operator
    });
    process.stdout.write(`${result.appended ? 'amendment appended' : 'duplicate amendment (not appended)'}: ${result.amendmentId}\n`);
  } catch (err) {
    if (err instanceof AttestationError) die(`${err.code}: ${err.message}`, 1);
    throw err;
  }
}

function runNote(o) {
  if (!o.text || !o.operator) die('--note requires --text --operator');
  try {
    const result = appendNote({ storeDir: o.storeDir, refAckId: o.ref, text: o.text, operator: o.operator });
    process.stdout.write(`${result.appended ? 'note appended' : 'duplicate note (not appended)'}: ${result.noteId}\n`);
  } catch (err) {
    if (err instanceof AttestationError) die(`${err.code}: ${err.message}`, 1);
    throw err;
  }
}

function runBreakLock(o) {
  const storeDir = o.storeDir === undefined ? path.join(process.cwd(), 'data') : o.storeDir;
  try {
    const result = breakStaleLock(storeDir, o.maxAgeMs === undefined ? {} : { maxAgeMs: parseNonNegativeInt(o.maxAgeMs, '--max-age-ms') });
    if (!result.broken) {
      process.stdout.write('no lock present: nothing to break\n');
      return;
    }
    process.stdout.write(`stale lock quarantined: ${result.quarantined}\n`);
    process.stdout.write(`previous pid=${result.previous.pid} host=${result.previous.hostname} ageMs=${result.previous.ageMs}\n`);
    process.stderr.write('attest: re-run the ceremony with --lock-broken <quarantined-path> to record this break in the audit event.\n');
  } catch (err) {
    if (err instanceof AttestationError) die(`${err.code}: ${err.message}`, 1);
    throw err;
  }
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  const modes = [o.status, o.verify, o.reconcile, o.amend, o.note, o.breakLock].filter(Boolean).length;
  const ceremonyFlags = o.package !== undefined || o.expectDigest !== undefined || o.confirm === true;
  if (modes > 1 || (modes === 1 && ceremonyFlags)) die(`modes are exclusive\n${usage()}`);
  try {
    if (o.status === true) runStatus(o);
    else if (o.verify === true) await runVerify(o);
    else if (o.reconcile === true) runReconcile(o);
    else if (o.amend === true) runAmend(o);
    else if (o.note === true) runNote(o);
    else if (o.breakLock === true) runBreakLock(o);
    else await runCeremony(o);
  } catch (err) {
    if (err instanceof AttestationError) die(`${err.code}: ${err.message}`, 1);
    process.stderr.write(`attest: unexpected failure: ${(err && err.message) || err}\n`);
    process.exit(1);
  }
}

main();
