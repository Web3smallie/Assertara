#!/usr/bin/env node
/**
 * Manifest export (Step 6): assemble a portable, digest-bound export
 * file for off-chain publication (release artifact, static hosting,
 * direct handoff). The judge CLI consumes this file.
 *
 * Inputs: the v1 verification package PLUS the ceremony-produced
 * attestation object. Both are operator-held artifacts; nothing is
 * read from the live stores, and nothing here verifies signatures —
 * cryptographic trust is established by the publisher before
 * submission and by the judge on receipt.
 *
 * Exported content is limited to the manifest, the attestation, and
 * the public projections already present in the v1 package. Private
 * keys, audit records, operator secrets, and internal evidence bytes
 * never enter the export (the v1 package provably excludes them, and
 * this tool adds nothing but the attestation and a format tag).
 *
 * This file deliberately imports only unpinned modules (fs, path,
 * provenanceManifest, canonicalJson). It must never require the
 * attestation core: N9 enforces that.
 */

const fs = require('fs');
const path = require('path');
const { verifyPackage } = require('../services/provenanceManifest');
const { canonicalStringify, sha256Hex } = require('../utils/canonicalJson');

const EXPORT_FORMAT = 'assertara-attestation-export-1';

function die(message, code) {
  process.stderr.write(`exportPackage: ${message}\n`);
  process.exit(code === undefined ? 2 : code);
}

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') return { help: true };
    if (!a.startsWith('--')) die(`unexpected argument: ${a}`);
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) die(`missing value for --${key}`);
    o[key] = next;
    i += 1;
  }
  return o;
}

function usage() {
  return [
    'Usage:',
    '  node src/attestation/exportPackage.js --package <v1package.json> --attestation <attestation.json> --expect-digest <64hex> --out <file>',
    '',
    '--package:      v1 verification package (assertara-verify-1). Fully validated.',
    '--attestation:  ceremony-produced attestation object (result.attestation saved as JSON).',
    '                Linkage-checked against the digest; signature verified by publisher/judge.',
    '--expect-digest: full 64-hex manifest digest binding operator intent.',
    '--out:          destination file. Refused when it already exists (no silent overwrite).',
    '',
    'Writes { format, exportedAt, manifestDigest, package } where package is',
    'the v2 verification package (v1 fields plus the attestation object).'
  ].join('\n');
}

function readJson(file, what) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    die(`${what} unreadable: ${file} (${(err && err.message) || err})`, 1);
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    die(`${what} is not valid JSON: ${file}`, 1);
    return null;
  }
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (!o.package) die('--package is required');
  if (!o.attestation) die('--attestation is required');
  if (!o['expect-digest']) die('--expect-digest is required');
  if (!/^[0-9a-f]{64}$/.test(o['expect-digest'])) die('--expect-digest must be 64 lowercase hex');
  if (!o.out) die('--out is required');
  if (fs.existsSync(o.out)) die(`refusing to overwrite existing file: ${path.resolve(o.out)}`, 1);

  const pkg = readJson(o.package, 'package');
  const attestation = readJson(o.attestation, 'attestation');

  // Full v1 semantic + digest validation (unpinned import; safe here).
  const pv = verifyPackage(pkg);
  if (!pv.ok) {
    const failed = pv.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join('; ');
    die(`package verification failed: ${failed}`, 1);
  }
  // Digest binding: recompute from manifest bytes, never trust envelopes.
  const recomputed = sha256Hex(canonicalStringify(pkg.manifest));
  if (recomputed !== o['expect-digest']) {
    die(`digest mismatch: recomputed ${recomputed} !== expected ${o['expect-digest']}`, 1);
  }
  // Attestation linkage (structural; signature verified by publisher/judge).
  if (!attestation || typeof attestation !== 'object' || !attestation.body || typeof attestation.body !== 'object') {
    die('attestation: object with body required', 1);
  }
  if (typeof attestation.signature !== 'string' || typeof attestation.authority !== 'string') {
    die('attestation: signature + authority strings required', 1);
  }
  if (attestation.body.manifestDigest !== recomputed) die('attestation does not bind this manifest digest', 1);
  if (attestation.body.investigationId !== pkg.manifest.investigationId
    || attestation.body.traceId !== pkg.manifest.traceId) {
    die('attestation ids do not match the manifest', 1);
  }

  const exported = {
    format: EXPORT_FORMAT,
    exportedAt: Date.now(),
    manifestDigest: recomputed,
    package: { ...pkg, packageVersion: 'assertara-verify-2', attestation }
  };
  try {
    fs.writeFileSync(o.out, `${JSON.stringify(exported, null, 2)}\n`, { flag: 'wx' });
  } catch (err) {
    if (err && err.code === 'EEXIST') die(`refusing to overwrite existing file: ${path.resolve(o.out)}`, 1);
    die(`cannot write output: ${(err && err.message) || err}`, 1);
  }
  process.stdout.write(`exported digest=${recomputed}\n`);
  process.stdout.write(`exported attester=${attestation.authority}\n`);
  process.stdout.write(`exported file=${path.resolve(o.out)}\n`);
}

main().catch((err) => die((err && err.stack) || err, 1));
