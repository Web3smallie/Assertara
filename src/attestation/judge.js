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
const { deriveModelBitmap, deriveCompatBitmap, deriveModelMetadata, sameModels, DECISION_MAP } = require('../services/attestationPublisher');
const { canonicalStringify, sha256Hex } = require('../utils/canonicalJson');

function die(message, code) {
  process.stderr.write(`judge: ${message}\n`);
  process.exitCode = code === undefined ? 2 : code;
  // Never process.exit(): hard exits during closing sockets trigger a
  // libuv assertion on Windows teardown. Unwind to the top-level
  // handler instead and let Node drain its handles.
  throw { judgeDie: true };
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
    '    [--min-version N] [--max-age-days N] [--submit-tx <hash>] [--now <ms>] [--contract-version 1|2]',
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

const LOG_CHUNK_BLOCKS = 2000;
const LOG_MAX_CHUNKS = 50;

function hexBlock(n) {
  return `0x${n.toString(16)}`;
}

// Bounded submission-tx discovery. Some RPC providers (including Arc)
// reject wide eth_getLogs ranges, so scan backwards from the head in
// small chunks instead of querying 0x0..latest. Returns { tx, blocks } on
// success or { error } when the log is out of window or unreachable;
// never throws, so a provider failure becomes a FAIL step, not a crash.
async function findSubmissionTx(call, contract, topics) {
  let head;
  try {
    head = parseInt(await call('eth_blockNumber', []), 16);
  } catch (err) {
    return { error: `head lookup failed (${(err && err.message) || err})` };
  }
  if (!Number.isSafeInteger(head) || head < 0) return { error: 'head lookup returned an invalid block number' };
  let size = LOG_CHUNK_BLOCKS;
  let scanned = 0;
  for (let chunks = 0; chunks < LOG_MAX_CHUNKS; chunks += 1) {
    const to = head - scanned;
    if (to < 0) break;
    const from = Math.max(0, to - size + 1);
    let logs;
    try {
      logs = await call('eth_getLogs', [{
        address: contract, topics, fromBlock: hexBlock(from), toBlock: hexBlock(to)
      }]);
    } catch (err) {
      const msg = String((err && err.message) || err).toLowerCase();
      if (/range|too large|limit|exceed/.test(msg) && size > 100) {
        size = Math.max(100, Math.floor(size / 2));
        chunks -= 1;
        continue;
      }
      return { error: `log query failed (${(err && err.message) || err})` };
    }
    if (Array.isArray(logs) && logs.length > 0) {
      return { tx: logs[logs.length - 1].transactionHash, blocks: scanned + (to - from + 1) };
    }
    scanned += (to - from + 1);
    if (from === 0) break;
  }
  return { error: `no matching log in the last ${scanned} blocks; pass --submit-tx with the publication hash` };
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
  if (o['contract-version'] !== undefined && o['contract-version'] !== '1' && o['contract-version'] !== '2') {
    die('--contract-version must be 1 or 2');
  }
  const v2 = o['contract-version'] === '2';

  const { encodeFunctionData, decodeFunctionResult, decodeEventLog, keccak256, toHex, parseAbi } = require('viem');
  const { CONTRACT_ABI, CONTRACT_ABI_V2 } = require('../services/attestationPublisher');
  const abi = v2 ? CONTRACT_ABI_V2 : parseAbi(CONTRACT_ABI);
  const eventName = v2 ? 'AttestedWithModels' : 'Attested';
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
      decision: Number(out[3]), txHash: out[4], attester: String(out[5]).toLowerCase(),
      ...(v2 ? { models: out[6] } : {})
    };
  } catch (err) {
    step('chain-record', false, `no on-chain record (${(err && err.message) || err})`);
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
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
      process.exitCode = 1;
      return;
    }
    if (!res.ok) {
      step('manifest-fetch', false, `http ${res.status}`);
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exitCode = 1;
      return;
    }
    try {
      exported = await res.json();
    } catch {
      step('manifest-fetch', false, 'response is not JSON');
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exitCode = 1;
      return;
    }
  }
  step('manifest-fetch', true, o['manifest-file'] ? 'file' : 'url');
  if (!exported || exported.format !== 'assertara-attestation-export-1' || !exported.package || !exported.package.manifest) {
    step('export-shape', false, 'not an attestation export file');
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }
  step('export-shape', true, exported.format);
  const pkg = exported.package;
  const manifest = pkg.manifest;
  const recomputed = sha256Hex(canonicalStringify(manifest));
  if (!step('digest-recompute', recomputed === exported.manifestDigest, recomputed)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }
  if (!step('digest-onchain', `0x${recomputed.toLowerCase()}` === String(record.manifestDigest).toLowerCase(), 'manifest binds the chain record')) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }

  // 4. Package integrity (digests + semantics + contribution claims).
  const pv = verifyPackage(pkg);
  if (!step('package', pv.ok, pv.ok ? 'verifyPackage ok' : `verifyPackage: ${pv.code}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }
  if (!pkg.attestation || typeof pkg.attestation !== 'object') {
    step('attestation-present', false, 'export carries no attestation object');
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
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
    process.exitCode = 1;
    return;
  }
  let recovered;
  try {
    recovered = (await recoverAttestationAddress(pkg.attestation)).toLowerCase();
  } catch (err) {
    step('signer-match', false, `recovery failed (${(err && err.message) || err})`);
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }
  if (!step('signer-match', recovered === attester && recovered === String(record.attester).toLowerCase(), recovered)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
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
    process.exitCode = 1;
    return;
  }
  const entry = (reg.keys && (reg.keys[attester] || reg.keys[attester.toLowerCase()])) || null;
  if (!entry) {
    step('key-status', false, 'attester absent from registry');
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }
  if (!step('key-status', entry.status === 'ACTIVE', `registry status=${entry.status}`)) {
    process.stdout.write('judge: VERDICT FAIL: key not ACTIVE (retired keys need corroboration review outside this tool)\n');
    process.exitCode = 1;
    return;
  }

  // 8. Decision + bitmap + txHash agreement with the manifest.
  const bitmap = v2 ? deriveCompatBitmap(manifest) : deriveModelBitmap(manifest);
  const agentDecision = manifest.decision ? manifest.decision.agent : null;
  const decisionOk = Object.prototype.hasOwnProperty.call(DECISION_MAP, agentDecision || '')
    && DECISION_MAP[agentDecision] === record.decision;
  if (!step('decision-match', decisionOk, `${String(agentDecision)} vs on-chain ${record.decision}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }
  if (!step('bitmap-match', bitmap === record.modelBitmap, `recomputed=${bitmap} on-chain=${record.modelBitmap}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }
  const manifestTx = manifest.transaction && manifest.transaction.transactionHash != null
    ? String(manifest.transaction.transactionHash).toLowerCase()
    : `0x${'00'.repeat(32)}`;
  if (!step('txhash-match', manifestTx === String(record.txHash).toLowerCase(), manifestTx)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }

  // 8b. V2 only: on-chain model metadata must exactly match the models
  // derived from the verified manifest. Shown as INFO so a judge sees
  // which models participated; the match itself gates the verdict.
  if (v2) {
    let expected;
    try {
      expected = deriveModelMetadata(manifest);
    } catch (err) {
      step('models-match', false, `derivation failed (${(err && err.message) || err})`);
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exitCode = 1;
      return;
    }
    expected.forEach((m, i) => {
      process.stdout.write(`judge: [INFO] model[${i}] name=${m.name} provider=${m.provider || '(none)'} modelId=${m.modelId || '(none)'} status=${m.status} contribution=${m.contribution}\n`);
    });
    if (!step('models-match', sameModels(record.models, expected), `${expected.length} model(s) agree with manifest`)) {
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exitCode = 1;
      return;
    }
  }

  // 9. Receipt + event verification.
  let submitTx = o['submit-tx'] || null;
  if (submitTx === null) {
    const sig = v2
      ? keccak256(toHex('AttestedWithModels(string,bytes32,address,uint8,uint8,bytes32,(string,string,string,string,string,string,string,bytes32,bytes32)[])'))
      : keccak256(toHex('Attested(string,bytes32,address,uint8,uint8,bytes32)'));
    const idTopic = keccak256(toHex(investigationId));
    const found = await findSubmissionTx(
      (method, params) => rpc(o.rpc, method, params),
      contract,
      [sig, idTopic, String(record.manifestDigest).toLowerCase(), `0x000000000000000000000000${attester.slice(2)}`]
    );
    if (!found.tx) {
      step('event-found', false, found.error || `no ${eventName} log for this investigation+attester`);
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exitCode = 1;
      return;
    }
    step('event-found', true, `submission tx found (scanned ${found.blocks} block(s))`);
    submitTx = found.tx;
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
    process.exitCode = 1;
    return;
  }
  if (!step('receipt', Number(receipt.status) === 1, `status=${String(receipt.status)} block=${String(receipt.blockNumber)}`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }
  const decoded = [];
  for (const log of receipt.logs || []) {
    if (String(log.address).toLowerCase() !== contract.toLowerCase()) continue;
    try {
      const evt = decodeEventLog({ abi, data: log.data, topics: log.topics });
      if (evt.eventName === eventName) decoded.push(evt.args);
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
    && (!v2 || sameModels(a.models, deriveModelMetadata(manifest)))
  );
  if (!step('event-match', Boolean(match), match ? `${eventName} log matches the record` : `no matching ${eventName} log in receipt`)) {
    process.stdout.write('judge: VERDICT FAIL\n');
    process.exitCode = 1;
    return;
  }

  // 10. No-payment statement for non-allow decisions.
  if (record.decision !== 0) {
    const zero = String(record.txHash).toLowerCase() === `0x${'00'.repeat(32)}`;
    if (!step('no-payment', zero, record.decision === 1 ? 'BLOCK carries a zero hash: no payment executed or implied' : 'REVIEW carries a zero hash: no payment executed or implied')) {
      process.stdout.write('judge: VERDICT FAIL\n');
      process.exitCode = 1;
      return;
    }
  } else if (String(record.txHash).toLowerCase() === `0x${'00'.repeat(32)}`) {
    step('no-payment', true, 'ALLOW with zero hash: pre-execution attestation, no payment claimed');
  } else {
    step('no-payment', true, 'ALLOW with hash: payment claim requires independent explorer/receipt verification (different chain possible)');
  }

  process.stdout.write('judge: VERDICT PASS\n');
}

if (require.main === module) {
  main().catch((err) => {
    if (err && err.judgeDie) return;
    process.stderr.write(`judge: ${(err && err.stack) || err}\n`);
    process.exitCode = 1;
  });
}

module.exports = { findSubmissionTx, LOG_CHUNK_BLOCKS, LOG_MAX_CHUNKS };
