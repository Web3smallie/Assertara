#!/usr/bin/env node
/**
 * Assertara Phase 3 — attestation/root key generation.
 *
 * Generates a FRESH Assertara-owned key (secp256k1, OS CSPRNG) and exports
 * it ONLY through an explicitly requested channel. There is no import path:
 * this tool cannot read, convert, or re-export any existing key — user,
 * signer, operator, or deployment.
 *
 *   node src/attestation/keygen.js --out <path> [--role attestation|root]
 *   node src/attestation/keygen.js --export [--role attestation|root]
 *
 * --out:     write the private key to exactly one new protected file.
 * --export:  print the private key to STDOUT ONLY (diagnostics to stderr).
 * No export flag: refuse (a generated-but-unexported key would be lost).
 *
 * The private key NEVER appears in diagnostics, logs, or audit records.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  generateAttestationKey,
  fingerprintOfAddress
} = require('../services/provenanceAttestation');

function die(message, code) {
  process.stderr.write(`keygen: ${message}\n`);
  process.exit(code === undefined ? 2 : code);
}

function usage() {
  return [
    'usage:',
    '  node src/attestation/keygen.js --out <path> [--role attestation|root]',
    '  node src/attestation/keygen.js --export [--role attestation|root]',
    '',
    'Generates a fresh Assertara-owned key. One export channel is required:',
    '  --out <path>   write key to a new protected file (refuses to overwrite,',
    '                 refuses paths inside the repository working tree)',
    '  --export       print key to stdout only (all diagnostics go to stderr)',
    '  --role <r>     label only: attestation (default) or root'
  ].join('\n');
}

function parseArgs(argv) {
  const out = { out: null, export: false, role: 'attestation' };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--out') {
      const v = argv[i + 1];
      if (!v || v.startsWith('--')) die('--out requires a path');
      out.out = v;
      i += 1;
    } else if (a === '--export') {
      out.export = true;
    } else if (a === '--role') {
      const v = argv[i + 1];
      if (v !== 'attestation' && v !== 'root') die('--role must be attestation or root');
      out.role = v;
      i += 1;
    } else if (a === '--help' || a === '-h') {
      process.stderr.write(`${usage()}\n`);
      process.exit(2);
    } else {
      die(`unknown argument: ${a}\n${usage()}`);
    }
  }
  return out;
}

function refuseInsideRepo(resolved) {
  const cwd = path.resolve(process.cwd());
  if (resolved === cwd || resolved.startsWith(`${cwd}${path.sep}`)) {
    die(`refusing to write key material inside the repository working tree (${cwd})`);
  }
}

function protectPosix(file) {
  fs.chmodSync(file, 0o600);
  const mode = fs.statSync(file).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    process.stderr.write(`keygen: WARNING: could not restrict ${file} to owner-only (mode ${mode.toString(8)}). Fix permissions manually.\n`);
    return false;
  }
  return true;
}

function icaclsExe() {
  // Absolute path: never resolve a security tool via PATH.
  const root = process.env.SystemRoot || 'C:\\Windows';
  return path.join(root, 'System32', 'icacls.exe');
}

function protectWindows(file) {
  // Returns true (hardened), 'fallback' (directory-default ACLs with a
  // loud warning), or false (unusable: caller must fail closed).
  const who = process.env.USERNAME || process.env.USER || '';
  const exe = icaclsExe();
  const locked = spawnSync(exe, [file, '/inheritance:r', '/grant:r', `${who}:F`], { encoding: 'utf8' });
  if (!locked.error && locked.status === 0) {
    try {
      fs.writeFileSync(file, 'canary2\n');
      if (fs.readFileSync(file, 'utf8') === 'canary2\n') return true;
    } catch {
      // Locked ourselves out (service/sandbox token differs from
      // USERNAME): fall through to restore directory-default ACLs.
    }
  }
  const detail = locked.error ? locked.error.message : (locked.stderr || '').trim().slice(0, 160);
  const reset = spawnSync(exe, [file, '/reset'], { encoding: 'utf8' });
  if (!reset.error && reset.status === 0) {
    try {
      fs.writeFileSync(file, 'canary2\n');
      if (fs.readFileSync(file, 'utf8') === 'canary2\n') {
        process.stderr.write(`keygen: WARNING: per-file ACL hardening unavailable (${detail || 'lockout detected'}). File uses directory-default permissions — ensure the directory is private to your account.\n`);
        return 'fallback';
      }
    } catch {
      // Unreachable through restored ACLs either.
    }
  }
  process.stderr.write(`keygen: Windows file protection failed (${detail || 'unknown'}): refusing to write key material.\n`);
  return false;
}

function writeProtected(file, privateKey) {
  // Order matters: prove the protected channel BEFORE the key exists in
  // it. A lockdown that locks out the operator must fail closed while
  // the key is still only in memory (retryable), never after the key is
  // written (key loss). Any failure removes the partial file.
  const resolved = path.resolve(file);
  refuseInsideRepo(resolved);
  if (fs.existsSync(resolved)) die(`refusing to overwrite existing file: ${resolved}`, 1);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  const cleanup = () => {
    try {
      fs.unlinkSync(resolved);
    } catch {
      // Best effort; the operator is told the filename either way.
    }
  };
  try {
    fs.writeFileSync(resolved, 'canary\n', { mode: 0o600, flag: 'wx' });
  } catch (err) {
    if (err && err.code === 'EEXIST') die(`refusing to overwrite existing file: ${resolved}`, 1);
    die(`cannot create output file: ${(err && err.message) || err}`, 1);
  }
  try {
    if (process.platform === 'win32') {
      const verdict = protectWindows(resolved);
      if (verdict === false) {
        cleanup();
        die('file protection failed: no key was written.', 1);
      }
      // protectWindows already proved read+write (canary2) in both
      // the hardened and the warned-fallback outcomes.
    } else {
      if (!protectPosix(resolved)) {
        cleanup();
        die('could not restrict file to owner-only: no key was written.', 1);
      }
      fs.writeFileSync(resolved, 'canary2\n');
      if (fs.readFileSync(resolved, 'utf8') !== 'canary2\n') {
        cleanup();
        die('protected file is not readable back: no key was written.', 1);
      }
    }
    fs.writeFileSync(resolved, `${privateKey}\n`);
    if (fs.readFileSync(resolved, 'utf8') !== `${privateKey}\n`) {
      cleanup();
      die('key write verification failed: removing partial file.', 1);
    }
  } catch (err) {
    cleanup();
    die(`protected export failed (${(err && err.message) || err}): no key was written.`, 1);
  }
  return resolved;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if ((args.out === null) === (args.export === false)) {
    if (args.out !== null && args.export) die('choose exactly one export channel: --out or --export');
    die(`no export channel given: a generated key without --out or --export would be lost\n${usage()}`);
  }
  const { privateKey, address } = generateAttestationKey();
  const fingerprint = fingerprintOfAddress(address);
  const label = args.role === 'root' ? 'registry-root' : 'attestation';

  if (args.export) {
    process.stderr.write(`keygen: ${label} key generated. Private key follows on STDOUT ONLY — handle accordingly.\n`);
    process.stderr.write(`keygen: address=${address} fingerprint=${fingerprint}\n`);
    process.stdout.write(`${privateKey}\n`);
    return;
  }
  let written;
  try {
    written = writeProtected(args.out, privateKey);
  } catch (err) {
    if (err && err.code === 'EEXIST') die(`refusing to overwrite existing file: ${path.resolve(args.out)}`, 1);
    die(`cannot write protected file: ${(err && err.message) || err}`, 1);
  }
  process.stderr.write(`keygen: ${label} key written to protected file (key material is ONLY in that file).\n`);
  process.stdout.write(`address=${address}\n`);
  process.stdout.write(`fingerprint=${fingerprint}\n`);
  process.stdout.write(`file=${written}\n`);
  if (args.role === 'root') {
    process.stderr.write('keygen: publish this fingerprint through TWO independent channels before use (see docs/attestation.md).\n');
  }
  process.stderr.write('keygen: back up the file offline now; loss without backup is unrecoverable.\n');
}

main();
