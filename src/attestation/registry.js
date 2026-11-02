#!/usr/bin/env node
/**
 * Assertara Phase 3 — root-signed key registry management.
 *
 * The registry is the public authority record for attestation keys. Every
 * mutation is built from a signature-VERIFIED predecessor (monotonic
 * version + monotonic key states) and takes effect only after offline
 * root signing. The root private key arrives via REGISTRY_ROOT_KEY at
 * ceremony time and is never stored, logged, or echoed.
 *
 *   init    --out <file> [--key <addr> --reason <text>] [--version N]
 *   add     --registry <signed> --trusted-root <addr> --out <file> --key <addr> --reason <text>
 *   retire  --registry <signed> --trusted-root <addr> --out <file> --key <addr> --reason <text> [--superseded-by <addr>]
 *   revoke  --registry <signed> --trusted-root <addr> --out <file> --key <addr> --reason <text> --status REVOKED|COMPROMISED
 *   sign    --registry <unsigned> --out <file>
 *   verify  --registry <file> --trusted-root <addr> [--min-version N] [--max-age-days N] [--allow-stale]
 *   show    --registry <file>
 *
 * init/add/retire/revoke write UNSIGNED successors (--out must not exist).
 * sign writes the SIGNED registry (--out must not exist). verify/show read.
 */

const fs = require('fs');
const path = require('path');
const {
  AttestationError,
  assertAddress,
  assertRegistryKeyEntry,
  buildRegistrySkeleton,
  deriveAddress,
  fingerprintOfAddress,
  prepareRegistryUpdate,
  signRegistry,
  verifyRegistry
} = require('../services/provenanceAttestation');

function die(message, code) {
  process.stderr.write(`registry: ${message}\n`);
  process.exit(code === undefined ? 2 : code);
}

function usage() {
  return [
    'usage: node src/attestation/registry.js <init|add|retire|revoke|sign|verify|show> [options]',
    '  init    --out <file> [--key <addr> --reason <text>] [--version N]',
    '  add     --registry <signed> --trusted-root <addr> --out <file> --key <addr> --reason <text>',
    '  retire  --registry <signed> --trusted-root <addr> --out <file> --key <addr> --reason <text> [--superseded-by <addr>]',
    '  revoke  --registry <signed> --trusted-root <addr> --out <file> --key <addr> --reason <text> --status REVOKED|COMPROMISED',
    '  sign    --registry <unsigned> --out <file>   (reads REGISTRY_ROOT_KEY from env)',
    '  verify  --registry <file> --trusted-root <addr> [--min-version N] [--max-age-days N] [--allow-stale]   (root-signature + freshness check)',
    '  show    --registry <file>   (UNVERIFIED raw dump; verify before trusting)',
    '',
    'verify checks the registry root signature and freshness;',
    'it does NOT check attestation completion (see attest.js --verify).'
  ].join('\n');
}

function parseArgs(argv) {
  const cmd = argv[0];
  if (!cmd || cmd === '--help' || cmd === '-h') die(usage());
  if (!['init', 'add', 'retire', 'revoke', 'sign', 'verify', 'show'].includes(cmd)) die(`unknown command: ${cmd}\n${usage()}`);
  const o = { command: cmd };
  const flags = new Set(['--allow-stale']);
  const values = new Set(['--out', '--key', '--reason', '--version', '--registry', '--trusted-root', '--superseded-by', '--status', '--min-version', '--max-age-days', '--at']);
  for (let i = 1; i < argv.length; i += 1) {
    const a = argv[i];
    if (flags.has(a)) {
      o[a.slice(2).replace(/-./g, (m) => m[1].toUpperCase())] = true;
    } else if (values.has(a)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) die(`${a} requires a value`);
      o[a.slice(2).replace(/-./g, (m) => m[1].toUpperCase())] = v;
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
  const text = String(raw).trim();
  if (text.length === 0) die(`${flag} requires a non-negative number (got empty value)`, 1);
  const n = Number(text);
  if (!Number.isFinite(n) || n < 0) die(`${flag} must be a finite non-negative number (got ${JSON.stringify(raw)})`, 1);
  return n;
}

function readJson(file, what) {
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

function writeNew(file, obj) {
  const resolved = path.resolve(file);
  if (fs.existsSync(resolved)) die(`refusing to overwrite existing file: ${resolved}`, 1);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.writeFileSync(resolved, `${JSON.stringify(obj, null, 2)}\n`);
  return resolved;
}

function stampMs(value, name) {
  if (value === undefined) return Date.now();
  if (typeof value !== 'string' || value.trim().length === 0) die(`${name} must be integer milliseconds (got empty value)`, 1);
  const n = Number(value);
  if (!Number.isSafeInteger(n)) die(`${name} must be integer milliseconds`, 1);
  return n;
}

async function requireVerifiedRegistry(file, trustedRoot, what) {
  const registry = readJson(file, what);
  const check = await verifyRegistry({ registry, trustedRoot });
  if (!check.ok) die(`${what} failed verification (${check.code}: ${check.detail})`, 1);
  return registry;
}

async function cmdInit(o) {
  if (!o.out) die('init requires --out');
  const version = o.version === undefined ? 0 : parseNonNegativeInt(o.version, '--version');
  const at = stampMs(o.at, '--at');
  const skeleton = buildRegistrySkeleton({ version, publishedAt: at });
  if (o.key !== undefined || o.reason !== undefined) {
    if (!o.key || !o.reason) die('init --key requires --reason (and vice versa)');
    const addr = assertAddress(o.key, '--key');
    const entry = { reason: o.reason, status: 'ACTIVE', statusChangedAt: at, supersededBy: null, validFrom: at };
    assertRegistryKeyEntry(entry, 'genesis key');
    skeleton.keys[addr] = entry;
  }
  const written = writeNew(o.out, skeleton);
  process.stdout.write(`unsigned registry skeleton v${version} written to ${written}\n`);
  process.stderr.write('registry: skeleton is UNSIGNED and untrusted until signed with the offline root key.\n');
}

async function cmdMutate(o, kind) {
  if (!o.registry || !o.trustedRoot || !o.out || !o.key || !o.reason) {
    die(`${kind} requires --registry --trusted-root --out --key --reason`);
  }
  const current = await requireVerifiedRegistry(o.registry, o.trustedRoot, 'current registry');
  const at = stampMs(o.at, '--at');
  const addr = assertAddress(o.key, '--key');
  let change;
  if (kind === 'add') {
    change = { add: { [addr]: { reason: o.reason, status: 'ACTIVE', statusChangedAt: at, supersededBy: null, validFrom: at } }, publishedAt: at, retire: {}, revoke: {}, version: current.version + 1 };
  } else if (kind === 'retire') {
    const prev = current.keys[addr] || current.keys[addr.toLowerCase()] || null;
    if (!prev) die(`retire: unknown key ${addr}`, 1);
    const supersededBy = o.supersededBy === undefined ? null : assertAddress(o.supersededBy, '--superseded-by');
    change = { add: {}, publishedAt: at, retire: { [addr]: { reason: o.reason, status: 'RETIRED', statusChangedAt: at, supersededBy, validFrom: prev.validFrom } }, revoke: {}, version: current.version + 1 };
  } else {
    if (o.status !== 'REVOKED' && o.status !== 'COMPROMISED') die('revoke requires --status REVOKED|COMPROMISED');
    const prev = current.keys[addr] || current.keys[addr.toLowerCase()] || null;
    if (!prev) die(`revoke: unknown key ${addr}`, 1);
    change = { add: {}, publishedAt: at, retire: {}, revoke: { [addr]: { reason: o.reason, status: o.status, statusChangedAt: at, supersededBy: prev.supersededBy, validFrom: prev.validFrom } }, version: current.version + 1 };
  }
  let next;
  try {
    next = prepareRegistryUpdate(current, change);
  } catch (err) {
    die(`transition rejected: ${err.message}`, 1);
  }
  const written = writeNew(o.out, next);
  process.stdout.write(`unsigned registry v${next.version} written to ${written}\n`);
  process.stderr.write('registry: successor is UNSIGNED and untrusted until signed with the offline root key.\n');
}

async function cmdSign(o) {
  if (!o.registry || !o.out) die('sign requires --registry --out');
  const rootKey = process.env.REGISTRY_ROOT_KEY;
  if (!rootKey) die('REGISTRY_ROOT_KEY is not set: refusing to sign without the offline root key', 1);
  const registry = readJson(o.registry, 'unsigned registry');
  let rootAddr;
  try {
    rootAddr = deriveAddress(rootKey);
  } catch (err) {
    die(`root key rejected: ${err.message}`, 1);
  }
  const keyAddrs = Object.keys(registry.keys || {}).map((a) => String(a).toLowerCase());
  if (keyAddrs.includes(rootAddr)) {
    die('root key must never double as a day-to-day attestation key: refusing to sign', 1);
  }
  let signed;
  try {
    signed = await signRegistry({ registry, rootPrivateKey: rootKey });
  } catch (err) {
    die(`signing failed: ${err.message}`, 1);
  }
  const written = writeNew(o.out, signed);
  process.stdout.write(`signed registry v${signed.version} written to ${written}\n`);
  process.stdout.write(`root=${rootAddr}\n`);
  process.stdout.write(`fingerprint=${fingerprintOfAddress(rootAddr)}\n`);
  process.stderr.write('registry: publish the signed registry AND verify its fingerprint out-of-band before trusting it.\n');
}

async function cmdVerify(o) {
  if (!o.registry || !o.trustedRoot) die('verify requires --registry --trusted-root');
  const registry = readJson(o.registry, 'registry');
  const check = await verifyRegistry({
    registry,
    trustedRoot: o.trustedRoot,
    minVersion: o.minVersion === undefined ? null : parseNonNegativeInt(o.minVersion, '--min-version'),
    maxAgeDays: o.maxAgeDays === undefined ? undefined : parseNonNegativeNumber(o.maxAgeDays, '--max-age-days'),
    allowStale: o.allowStale === true
  });
  if (!check.ok) {
    process.stdout.write(`registry INVALID: ${check.code} ${check.detail}\n`);
    process.exit(1);
  }
  process.stdout.write(`registry VALID: version=${check.version}\n`);
  for (const [addr, entry] of Object.entries(check.keys)) {
    process.stdout.write(`  ${addr} ${entry.status} validFrom=${entry.validFrom} changed=${entry.statusChangedAt}\n`);
  }
}

async function cmdShow(o) {
  if (!o.registry) die('show requires --registry');
  const registry = readJson(o.registry, 'registry');
  process.stderr.write('registry: UNVERIFIED output — this file was NOT signature-checked. Verify with `registry verify --trusted-root <addr>` before trusting any key state shown here.\n');
  process.stdout.write(`${JSON.stringify(registry, null, 2)}\n`);
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  try {
    if (o.command === 'init') await cmdInit(o);
    else if (o.command === 'sign') await cmdSign(o);
    else if (o.command === 'verify') await cmdVerify(o);
    else if (o.command === 'show') await cmdShow(o);
    else await cmdMutate(o, o.command);
  } catch (err) {
    if (err instanceof AttestationError) die(err.message, 1);
    throw err;
  }
}

main().catch((err) => {
  process.stderr.write(`registry: unexpected failure: ${(err && err.message) || err}\n`);
  process.exit(1);
});
