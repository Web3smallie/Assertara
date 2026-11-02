#!/usr/bin/env node
/**
 * Independent judge verification (Step 6): read-only, no private keys.
 *
 * Verifies one published attestation end to end: on-chain record,
 * off-chain manifest, digest binding, Phase 3 signature, registry
 * trust, bitmap/decision/hash agreement, receipt + event, and the
 * BLOCK/REVIEW no-payment statement.
 *
 * Independence statement (read carefully): this tool reuses Assertara's
 * own verification code, so a judge running it trusts this codebase to
 * check itself. Genuine independence comes from the published evidence
 * being re-checkable WITHOUT this tool: canonical JSON + SHA-256
 * vectors are documented, the manifest digest is recomputable with any
 * SHA-256 implementation, the EIP-191 signature verifies with any
 * secp256k1 library, and the on-chain record is world-readable.
 * "Independent verification" here means: no access to Assertara's
 * private keys, servers, or internal stores is required.
 */

const fs = require('fs');
const path = require('path');
const { verifyPackage } = require('../services/provenanceManifest');
const {
  verifyAttestation, verifyRegistry, recoverAttestationAddress
} = require('../services/provenanceAttestation');
const { deriveModelBitmap, DECISION_MAP } = require('../services/attestationPublisher');
const { canonicalStringify, sha256Hex } = require('../utils/canonicalJson');

function die(message, code) {
  process.stderr.write(`judge: ${message}\n`);
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
    '  node src/attestation/judge.js --rpc <url> --contract <addr> --investigation <id> --attester <addr>',
    '    --manifest-file <export.json> | --manifest-url <url>',
    '    --registry <registry.json> --trusted-root <addr>',
    '    [--min-version N] [--max-age-days N] [--submit-tx <hash>] [--now <ms>]',
    '',
    'Read-only. No private keys are used or accepted. Exit 0 only when',
    'every required check passes; per-step PASS/FAIL lines name the rest.'
  ].join('\n');
}

function parseNonNegativeInt(raw, flag) {
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
    die(`${what} unreadable: ${file} (${(err && err.message) || err})`, 1);
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch {
    die(`${what} is not valid JSON: ${file}`, 1);
    return null;
  }
}

async function rpc(rpcUrl, method, params) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: params || [] })
  });
  if (!res.ok) throw new Error(`rpc http ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(body.error.message || 'rpc error');
  return body.result;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (o.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  for (const f of ['rpc', 'contract', 'investigation', 'attester', 'registry', 'trusted-root']) {
    if (!o[f]) die(`--${f} is required`);
  }
  if ((o['manifest-file'] && o['manifest-url']) || (!o['manifest-file'] && !o['manifest-url'])) {
    die('exactly one of --manifest-file / --manifest-url is required');
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(o.contract)) die('--contract must be an address');
  if (!/^0x[0-9a-fA-F]{40}$/.test(o.attester)) die('--attester must be an address');
  if (!/^0x[0-9a-fA-F]{40}$/.test(o['trusted-root'])) die('--trusted-root must be an address');
  if (o['submit-tx'] && !/^0x[0-9a-fA-F]{64}$/.test(o['submit-tx'])) die('--submit-tx must be a 32-byte hash');
  const minVersion = o['min-version'] === undefined ? null : parseNonNegativeInt(o['min-version'], '--min-version');
  const maxAgeDays = o['max-age-days'] === undefined ? undefined : parseNonNegativeNumber(o['max-age-days'], '--max-age-days');
  const now = o.now === undefined ? Date.now() : parseNonNegativeInt(o.now, '--now');

  const { encodeFunctionData, decodeFunctionResult, decodeEventLog, keccak256, toHex, parseAbi } = require('viem');
  const { CONTRACT_ABI } = require('../services/attestationPublisher');
  const abi = parseAbi(CONTRACT_ABI);
  const attester = o.attester.toLowerCase();
  const contract = o.contract;
  const investigationId = o.investigation;
  const results = [];
  const step = (name, ok, detail) => {
    results.push({ name, ok });
    process.stdout.write(`judge: [${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ` — ${detail}` : ''}\n`);
    return ok;
  };

  // 1. Read the on-chain attestation record.
  let record;
  try {
    const raw = await rpc(o.rpc, 'eth_call', [{
      to: contract,
      data: encodeFunctionData({ abi, functionName: 'getAttestation', args: [investigationId, attester] })
    }, 'latest']);
    const out = decodeFunctionResult({ abi, functionName: 'getAttestation', data: raw });
    record = {
      investigationId: out[0], manifestDigest: out[1], modelBitmap: Number(out[2]),
      decision: Number(out[3]), txHash: out[4], attester: String(out[5]).toLowerCase()
    };
  } catch (err) {
    step('chain-record', false, `no on-chain record (${(err && err.message) || err})`);
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  step('chain-record', true, `decision=${record.decision} bitmap=${record.modelBitmap}`);

  // 2+3. Retrieve the manifest export and recompute its digest.
  let exported;
  if (o['manifest-file']) {
    exported = readJson(o['manifest-file'], 'manifest export');
  } else {
    let res;
    try {
      res = await fetch(o['manifest-url']);
    } catch (err) {
      step('manifest-fetch', false, `fetch failed (${(err && err.message) || err})`);
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exit(1);
      return;
    }
    if (!res.ok) {
      step('manifest-fetch', false, `http ${res.status}`);
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exit(1);
      return;
    }
    try {
      exported = await res.json();
    } catch {
      step('manifest-fetch', false, 'response is not JSON');
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exit(1);
      return;
    }
  }
  step('manifest-fetch', true, o['manifest-file'] ? 'file' : 'url');
  if (!exported || exported.format !== 'assertara-attestation-export-1' || !exported.package || !exported.package.manifest) {
    step('export-shape', false, 'not an attestation export file');
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  step('export-shape', true, exported.format);
  const pkg = exported.package;
  const manifest = pkg.manifest;
  const recomputed = sha256Hex(canonicalStringify(manifest));
  if (!step('digest-recompute', recomputed === exported.manifestDigest, recomputed)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  if (!step('digest-onchain', `0x${recomputed.toLowerCase()}` === String(record.manifestDigest).toLowerCase(), 'manifest binds the chain record')) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }

  // 4. Package integrity (digests + semantics + contribution claims).
  const pv = verifyPackage(pkg);
  if (!step('package', pv.ok, pv.ok ? 'verifyPackage ok' : `verifyPackage: ${pv.code}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  if (!pkg.attestation || typeof pkg.attestation !== 'object') {
    step('attestation-present', false, 'export carries no attestation object');
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  step('attestation-present', true, '');

  // 5+6. Signature validity + recovered signer matches the attester.
  const av = await verifyAttestation({
    manifest,
    attestation: pkg.attestation,
    trustedAuthorities: [attester],
    keyRegistry: readJson(o.registry, 'registry'),
    trustedRoot: o['trusted-root'],
    maxRegistryAgeDays: maxAgeDays,
    now
  });
  if (!step('signature', av.ok, av.ok ? `verifyAttestation ${av.code}` : `verifyAttestation: ${av.code}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  let recovered;
  try {
    recovered = (await recoverAttestationAddress(pkg.attestation)).toLowerCase();
  } catch (err) {
    step('signer-match', false, `recovery failed (${(err && err.message) || err})`);
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  if (!step('signer-match', recovered === attester && recovered === String(record.attester).toLowerCase(), recovered)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }

  // 7. Registry trust chain + key status, reported explicitly.
  const reg = await verifyRegistry({
    registry: readJson(o.registry, 'registry'),
    trustedRoot: o['trusted-root'],
    minVersion,
    maxAgeDays,
    now
  });
  if (!step('registry', reg.ok, reg.ok ? 'root signature + freshness ok' : `registry: ${reg.code}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  const entry = (reg.keys && (reg.keys[attester] || reg.keys[attester.toLowerCase()])) || null;
  if (!entry) {
    step('key-status', false, 'attester absent from registry');
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  if (!step('key-status', entry.status === 'ACTIVE', `registry status=${entry.status}`)) {
    process.stdout.write('judge: VERDICT FAIL: key not ACTIVE (retired keys need corroboration review outside this tool)\n');
    process.exit(1);
    return;
  }

  // 8. Decision + bitmap + txHash agreement with the manifest.
  const bitmap = deriveModelBitmap(manifest);
  const agentDecision = manifest.decision ? manifest.decision.agent : null;
  const decisionOk = Object.prototype.hasOwnProperty.call(DECISION_MAP, agentDecision || '')
    && DECISION_MAP[agentDecision] === record.decision;
  if (!step('decision-match', decisionOk, `${String(agentDecision)} vs on-chain ${record.decision}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  if (!step('bitmap-match', bitmap === record.modelBitmap, `recomputed=${bitmap} on-chain=${record.modelBitmap}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  const manifestTx = manifest.transaction && manifest.transaction.transactionHash != null
    ? String(manifest.transaction.transactionHash).toLowerCase()
    : `0x${'00'.repeat(32)}`;
  if (!step('txhash-match', manifestTx === String(record.txHash).toLowerCase(), manifestTx)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }

  // 9. Receipt + event verification.
  let submitTx = o['submit-tx'] || null;
  if (submitTx === null) {
    const sig = keccak256(toHex('Attested(string,bytes32,address,uint8,uint8,bytes32)'));
    const idTopic = keccak256(toHex(investigationId));
    const logs = await rpc(o.rpc, 'eth_getLogs', [{
      address: contract,
      topics: [sig, idTopic, String(record.manifestDigest).toLowerCase(), `0x000000000000000000000000${attester.slice(2)}`],
      fromBlock: '0x0', toBlock: 'latest'
    }]);
    if (!Array.isArray(logs) || logs.length === 0) {
      step('event-found', false, 'no Attested log for this investigation+attester');
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exit(1);
      return;
    }
    step('event-found', true, `${logs.length} matching log(s)`);
    submitTx = logs[0].transactionHash;
  } else {
    step('event-found', true, `using --submit-tx ${submitTx}`);
  }
  let receipt;
  try {
    receipt = await rpc(o.rpc, 'eth_getTransactionReceipt', [submitTx]);
  } catch (err) {
    receipt = null;
  }
  if (!receipt) {
    step('receipt', false, 'receipt unavailable');
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  if (!step('receipt', Number(receipt.status) === 1, `status=${String(receipt.status)} block=${String(receipt.blockNumber)}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }
  const decoded = [];
  for (const log of receipt.logs || []) {
    if (String(log.address).toLowerCase() !== contract.toLowerCase()) continue;
    try {
      const evt = decodeEventLog({ abi, data: log.data, topics: log.topics });
      if (evt.eventName === 'Attested') decoded.push(evt.args);
    } catch {
      continue;
    }
  }
  const match = decoded.find((a) =>
    String(a.manifestDigest).toLowerCase() === String(record.manifestDigest).toLowerCase()
    && String(a.attester).toLowerCase() === attester
    && Number(a.modelBitmap) === record.modelBitmap
    && Number(a.decision) === record.decision
    && String(a.txHash).toLowerCase() === String(record.txHash).toLowerCase()
  );
  if (!step('event-match', Boolean(match), match ? 'Attested log matches the record' : 'no matching Attested log in receipt')) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exit(1);
    return;
  }

  // 10. No-payment statement for non-allow decisions.
  if (record.decision !== 0) {
    const zero = String(record.txHash).toLowerCase() === `0x${'00'.repeat(32)}`;
    if (!step('no-payment', zero, record.decision === 1 ? 'BLOCK carries a zero hash: no payment executed or implied' : 'REVIEW carries a zero hash: no payment executed or implied')) {
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exit(1);
      return;
    }
  } else if (String(record.txHash).toLowerCase() === `0x${'00'.repeat(32)}`) {
    step('no-payment', true, 'ALLOW with zero hash: pre-execution attestation, no payment claimed');
  } else {
    step('no-payment', true, 'ALLOW with hash: payment claim requires independent explorer/receipt verification (different chain possible)');
  }

  process.stdout.write('judge: VERDICT PASS\n');
}

main().catch((err) => die((err && err.stack) || err, 1));
