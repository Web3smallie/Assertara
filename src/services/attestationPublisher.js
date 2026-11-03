/**
 * Attestation publisher (Step 6): submits verified signed packages to
 * the on-chain ProvenanceAttestation registry.
 *
 * Trust position:
 * - Consumes Phase 3 verification (verifyPackage, verifyAttestation)
 *   but NEVER signs provenance records and NEVER generates keys. It
 *   cannot mint attestation authority; it only relays an already-signed
 *   package after re-verifying it.
 * - Signs only the submission transaction, with a dedicated publisher
 *   transaction key that must differ from the attester, the registry
 *   root, and every deny-listed address. The controlled transaction
 *   signer is never involved: attestation publication moves no value
 *   and executes no agent action.
 * - Private key material never appears in results, errors, or logs:
 *   keys are shape-validated, used to construct a signer, and never
 *   echoed. Transport is injectable so unit tests run without a chain.
 */

const { verifyPackage } = require('./provenanceManifest');
const {
  verifyAttestation, recoverAttestationAddress
} = require('./provenanceAttestation');
const { canonicalStringify, sha256Hex } = require('../utils/canonicalJson');

const DECISION_MAP = { ALLOW: 0, BLOCK: 1, REVIEW: 2 };

// Success levels that set a model bitmap bit. Anything else —
// NOT_INVOKED, INVOKED, MOCK, FAILED, TIMEOUT, PARTIAL, or unknown —
// clears it. PARTIAL is deliberately excluded: incomplete evidence
// must not be presented as successful contribution.
const MUSE_SUCCESS_LEVELS = new Set(['SUCCEEDED', 'OUTPUT_INCLUDED', 'VERDICT_ACCEPTED']);
const SAM_SUCCESS_LEVELS = new Set(['SUCCEEDED', 'OUTPUT_INCLUDED', 'PROMPT_INCLUDED', 'VALIDATED_AGAINST']);

const ZERO_BYTES32 = `0x${'00'.repeat(32)}`;
// Selector of the contract's UnknownAttestation() custom error, computed
// from the canonical signature (never hand-copied): the duplicate
// pre-check treats exactly this revert as "no record yet".
const UNKNOWN_ATTESTATION_SELECTOR = (() => {
  const { keccak256, toHex } = require('viem');
  return keccak256(toHex('UnknownAttestation()')).slice(2, 10).toLowerCase();
})();

// True only when the error carries the exact UnknownAttestation()
// selector, wherever the transport/client nested it. Viem wraps the
// RPC error (which holds `data`) in a `cause` chain whose top-level
// message varies by endpoint ("custom error 0x…" on Anvil, "unknown
// reason" on Arc) — so walk the whole chain plus viem's .walk().
// Anything else rethrows: fail-closed duplicate protection.
function isUnknownAttestationRevert(err) {
  const sel = UNKNOWN_ATTESTATION_SELECTOR.toLowerCase();
  const textOf = (v) => (typeof v === 'string'
    ? v
    : (Array.isArray(v) ? v.filter((x) => typeof x === 'string').join('\n') : ''));
  const seen = new Set();
  let cur = err;
  for (let depth = 0; depth < 10 && cur !== null && cur !== undefined; depth += 1) {
    if (typeof cur === 'string') return cur.toLowerCase().includes(sel);
    if (typeof cur !== 'object' || seen.has(cur)) return false;
    seen.add(cur);
    for (const k of ['data', 'message', 'shortMessage', 'details', 'metaMessages']) {
      if (textOf(cur[k]).toLowerCase().includes(sel)) return true;
    }
    cur = cur.cause;
  }
  if (err && typeof err.walk === 'function') {
    try {
      const hit = err.walk((e) => e !== null && e !== undefined && textOf(e.data).toLowerCase().includes(sel));
      if (hit) return true;
    } catch {
      /* fall through to false */
    }
  }
  return false;
}

const CONTRACT_ABI = [
  'function attest(string investigationId, bytes32 manifestDigest, uint8 modelBitmap, uint8 decision, bytes32 txHash, address attester)',
  'function getAttestation(string investigationId, address attester) view returns (string, bytes32, uint8, uint8, bytes32, address)',
  'event Attested(string indexed investigationId, bytes32 indexed manifestDigest, address indexed attester, uint8 modelBitmap, uint8 decision, bytes32 txHash)'
];

// V2 ABI (ProvenanceAttestationV2): same core record plus a dynamic
// per-model metadata array. Tuple components must match the Solidity
// ModelProvenance struct field order exactly. Written as an ABI
// object because human-readable ABIs cannot express tuple arrays.
const MODEL_COMPONENTS = [
  { name: 'name', type: 'string' },
  { name: 'provider', type: 'string' },
  { name: 'modelId', type: 'string' },
  { name: 'endpoint', type: 'string' },
  { name: 'status', type: 'string' },
  { name: 'contribution', type: 'string' },
  { name: 'verdict', type: 'string' },
  { name: 'inputDigest', type: 'bytes32' },
  { name: 'outputDigest', type: 'bytes32' }
];
const CONTRACT_ABI_V2 = [
  {
    type: 'function', name: 'attest', stateMutability: 'nonpayable',
    inputs: [
      { name: 'investigationId', type: 'string' },
      { name: 'manifestDigest', type: 'bytes32' },
      { name: 'modelBitmap', type: 'uint8' },
      { name: 'decision', type: 'uint8' },
      { name: 'txHash', type: 'bytes32' },
      { name: 'attester', type: 'address' },
      { name: 'models', type: 'tuple[]', components: MODEL_COMPONENTS }
    ],
    outputs: []
  },
  {
    type: 'function', name: 'getAttestation', stateMutability: 'view',
    inputs: [
      { name: 'investigationId', type: 'string' },
      { name: 'attester', type: 'address' }
    ],
    outputs: [
      { name: 'outInvestigationId', type: 'string' },
      { name: 'outManifestDigest', type: 'bytes32' },
      { name: 'outModelBitmap', type: 'uint8' },
      { name: 'outDecision', type: 'uint8' },
      { name: 'outTxHash', type: 'bytes32' },
      { name: 'outAttester', type: 'address' },
      { name: 'outModels', type: 'tuple[]', components: MODEL_COMPONENTS }
    ]
  },
  {
    type: 'event', name: 'AttestedWithModels',
    inputs: [
      { name: 'investigationId', type: 'string', indexed: true },
      { name: 'manifestDigest', type: 'bytes32', indexed: true },
      { name: 'attester', type: 'address', indexed: true },
      { name: 'modelBitmap', type: 'uint8' },
      { name: 'decision', type: 'uint8' },
      { name: 'txHash', type: 'bytes32' },
      { name: 'models', type: 'tuple[]', components: MODEL_COMPONENTS }
    ]
  }
];

class PublisherError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'PublisherError';
    this.code = code;
    this.details = details === undefined ? null : details;
  }
}

function fail(code, message, details) {
  throw new PublisherError(code, message, details);
}

function isHex64(v) {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{64}$/.test(v);
}

function isAddress(v) {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
}

// Manifest digests are stored as bare 64-hex; the contract wants
// bytes32. Accept both spellings, emit canonical 0x-lowercase.
function toBytes32(v, name) {
  if (typeof v === 'string' && /^[0-9a-f]{64}$/.test(v)) return `0x${v}`;
  if (typeof v === 'string' && /^0x[0-9a-fA-F]{64}$/.test(v)) return v.toLowerCase();
  fail('PUBLISH_INVALID_PACKAGE', `${name}: 32-byte hex (with or without 0x) required`);
  return null;
}

/**
 * Derive the on-chain model bitmap from verified manifest
 * contribution levels. Pure: no I/O, no secrets. Throws
 * PUBLISH_INVALID_PACKAGE when the manifest lacks contribution data
 * (never defaults a bit to 1).
 */
function deriveModelBitmap(manifest) {
  if (!manifest || typeof manifest !== 'object' || !manifest.modelCalls || typeof manifest.modelCalls !== 'object') {
    fail('PUBLISH_INVALID_PACKAGE', 'manifest.modelCalls: contribution block required');
  }
  const muse = manifest.modelCalls.museSpark;
  const sam = manifest.modelCalls.sam;
  if (!muse || typeof muse.contribution !== 'string') {
    fail('PUBLISH_INVALID_PACKAGE', 'manifest.modelCalls.museSpark.contribution: string required');
  }
  if (!sam || typeof sam.contribution !== 'string') {
    fail('PUBLISH_INVALID_PACKAGE', 'manifest.modelCalls.sam.contribution: string required');
  }
  let bitmap = 0;
  if (MUSE_SUCCESS_LEVELS.has(muse.contribution)) bitmap |= 1;
  if (SAM_SUCCESS_LEVELS.has(sam.contribution)) bitmap |= 2;
  return bitmap;
}

// Derive the V2 compat bitmap: same bit semantics as deriveModelBitmap,
// but tolerant of absent legacy slots (missing slot contributes 0).
// Unknown/future model slots never affect this legacy field; they are
// represented in full in the models array instead.
function deriveCompatBitmap(manifest) {
  if (!manifest || typeof manifest !== 'object' || !manifest.modelCalls || typeof manifest.modelCalls !== 'object') {
    fail('PUBLISH_INVALID_PACKAGE', 'manifest.modelCalls: contribution block required');
  }
  let bitmap = 0;
  const muse = manifest.modelCalls.museSpark;
  if (muse && typeof muse === 'object' && typeof muse.contribution === 'string' && MUSE_SUCCESS_LEVELS.has(muse.contribution)) {
    bitmap |= 1;
  }
  const sam = manifest.modelCalls.sam;
  if (sam && typeof sam === 'object' && typeof sam.contribution === 'string' && SAM_SUCCESS_LEVELS.has(sam.contribution)) {
    bitmap |= 2;
  }
  return bitmap;
}

// Derive on-chain model entries from the verified manifest. Fully
// dynamic: iterates whatever model slots the manifest carries and
// passes each slot's own status, contribution, and digests through.
// Unavailable text becomes "" and unavailable digests become zero —
// never fabricated success. Only manifest schema SHAPE is known here
// (field names shared by all slots); no model, provider, or outcome
// name appears anywhere in this function.
function deriveModelMetadata(manifest) {
  if (!manifest || typeof manifest !== 'object' || !manifest.modelCalls || typeof manifest.modelCalls !== 'object') {
    fail('PUBLISH_INVALID_PACKAGE', 'manifest.modelCalls: contribution block required');
  }
  const entries = Object.entries(manifest.modelCalls);
  if (entries.length === 0) {
    fail('PUBLISH_INVALID_PACKAGE', 'manifest.modelCalls: at least one model entry required');
  }
  return entries.map(([slot, s]) => {
    if (!s || typeof s !== 'object') fail('PUBLISH_INVALID_PACKAGE', `manifest.modelCalls.${slot}: object required`);
    const rawStatus = (s.status === null || s.status === undefined) ? s.aggregateStatus : s.status;
    if (typeof rawStatus !== 'string' || rawStatus.length === 0) {
      fail('PUBLISH_INVALID_PACKAGE', `manifest.modelCalls.${slot}: status string required`);
    }
    if (typeof s.contribution !== 'string' || s.contribution.length === 0) {
      fail('PUBLISH_INVALID_PACKAGE', `manifest.modelCalls.${slot}: contribution string required`);
    }
    const str = (v) => (v === null || v === undefined ? '' : String(v));
    const digest = (v) => (v === null || v === undefined ? ZERO_BYTES32 : toBytes32(v, `manifest.modelCalls.${slot} digest`));
    return {
      name: String(slot),
      provider: str(s.provider),
      modelId: str((s.observedModel === null || s.observedModel === undefined) ? s.configuredModel : s.observedModel),
      endpoint: str(s.endpoint),
      status: rawStatus,
      contribution: s.contribution,
      verdict: str(s.modelVerdict),
      inputDigest: digest(s.inputDigest),
      outputDigest: digest(s.outputDigest)
    };
  });
}

function sameModels(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  const STR = ['name', 'provider', 'modelId', 'endpoint', 'status', 'contribution', 'verdict'];
  return a.every((x, i) => {
    const y = b[i];
    if (!x || typeof x !== 'object' || !y || typeof y !== 'object') return false;
    for (const k of STR) {
      if (String(x[k]) !== String(y[k])) return false;
    }
    return String(x.inputDigest).toLowerCase() === String(y.inputDigest).toLowerCase()
      && String(x.outputDigest).toLowerCase() === String(y.outputDigest).toLowerCase();
  });
}

function createViemTransport({ rpcUrl, publisherKey, chainId }) {
  if (typeof rpcUrl !== 'string' || rpcUrl.length === 0) fail('PUBLISH_INVALID_INPUT', 'rpcUrl: non-empty string required');
  if (!isHex64(publisherKey)) fail('PUBLISH_INVALID_KEY', 'publisher transaction key: 0x 32-byte hex required');
  // Key material enters the signer only; it is never returned, logged,
  // or embedded in any error or result object below.
  const { createWalletClient, createPublicClient, http, defineChain } = require('viem');
  const { privateKeyToAccount } = require('viem/accounts');
  const account = privateKeyToAccount(publisherKey);
  const chain = defineChain({ id: chainId, name: `attestation-${chainId}`, nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [rpcUrl] } } });
  const wallet = createWalletClient({ account, chain, transport: http(rpcUrl) });
  const pub = createPublicClient({ chain, transport: http(rpcUrl) });
  return {
    address: account.address.toLowerCase(),
    chainId: async () => chainId,
    call: async ({ to, data }) => pub.call({ to, data }),
    sendTransaction: async ({ to, data }) => wallet.sendTransaction({ to, data }),
    getReceipt: async (hash) => pub.getTransactionReceipt({ hash }).catch(() => null),
    getBlockNumber: async () => pub.getBlockNumber(),
    getLogs: async (filter) => pub.getLogs(filter)
  };
}

async function waitFor(fn, timeoutMs, label) {
  const start = Date.now();
  for (;;) {
    const out = await fn();
    if (out) return out;
    if (Date.now() - start > timeoutMs) fail('PUBLISH_RECEIPT_TIMEOUT', `timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

function sameRecord(a, b) {
  return a.manifestDigest.toLowerCase() === b.manifestDigest.toLowerCase()
    && Number(a.modelBitmap) === Number(b.modelBitmap)
    && Number(a.decision) === Number(b.decision)
    && a.txHash.toLowerCase() === b.txHash.toLowerCase()
    && a.attester.toLowerCase() === b.attester.toLowerCase();
}

/**
 * Publish one signed package to the on-chain registry.
 *
 * @param {object} o
 * @param {object} o.signedPackage  v2 package ({manifest, attestation, ...})
 * @param {object} o.registry  signed key registry object
 * @param {string} o.trustedRoot  independently trusted root address
 * @param {string[]} o.trustedAuthorities  authority allowlist (must include the attester)
 * @param {string[]} [o.denyList]  addresses the publisher key must avoid
 * @param {string} o.rpcUrl  chain RPC endpoint
 * @param {number} o.chainId  numeric chain id for the wallet client
 * @param {string} o.contractAddress  deployed ProvenanceAttestation address
 * @param {string} o.publisherKey  0x 32-byte transaction key (never echoed)
 * @param {number} [o.confirmations]  required confirmations (default 1)
 * @param {number} [o.confirmTimeoutMs]  receipt/confirmation budget
 * @param {number} [o.maxRegistryAgeDays]  registry freshness bound
 * @param {boolean} [o.allowStaleRegistry]  explicit staleness override
 * @param {object} [o.transport]  injected transport (tests); default viem
 * @param {number} [o.now]  injectable clock
 * @param {number} [o.contractVersion]  1 (default) or 2 (dynamic model metadata)
 */
async function publishAttestation(o) {
  const opts = o || {};
  const checks = [];
  const check = (name, ok, detail) => { checks.push({ name, ok, detail: detail || '' }); return ok; };

  // -- 1. Package + digest validation (no trust in envelopes). --
  const pkg = opts.signedPackage;
  if (!pkg || typeof pkg !== 'object' || !pkg.manifest || !pkg.attestation) {
    fail('PUBLISH_INVALID_PACKAGE', 'signedPackage: v2 package with manifest + attestation required');
  }
  const pv = verifyPackage(pkg);
  if (!pv.ok) fail('PUBLISH_INVALID_PACKAGE', `package verification failed: ${pv.code}`, { code: pv.code });
  check('package', true, 'verifyPackage ok');
  const manifest = pkg.manifest;
  const recomputed = sha256Hex(canonicalStringify(manifest));
  const envelopeDigest = pkg.envelope && pkg.envelope.manifestDigest;
  if (recomputed !== manifest.manifestDigest && recomputed !== envelopeDigest) {
    fail('PUBLISH_DIGEST_MISMATCH', 'recomputed manifest digest matches neither manifest nor envelope commitment');
  }
  const manifestDigest = recomputed;
  check('digest', true, manifestDigest);
  const manifestDigest32 = toBytes32(manifestDigest, 'manifest digest');

  // -- 2. Signature + registry trust (existing Phase 3 verifier). --
  if (!isAddress(opts.trustedRoot)) fail('PUBLISH_INVALID_INPUT', 'trustedRoot: address required');
  if (!Array.isArray(opts.trustedAuthorities) || opts.trustedAuthorities.length === 0) {
    fail('PUBLISH_INVALID_INPUT', 'trustedAuthorities: non-empty array required');
  }
  const av = await verifyAttestation({
    manifest,
    attestation: pkg.attestation,
    trustedAuthorities: opts.trustedAuthorities,
    keyRegistry: opts.registry,
    trustedRoot: opts.trustedRoot,
    maxRegistryAgeDays: opts.maxRegistryAgeDays,
    allowStaleRegistry: opts.allowStaleRegistry,
    now: opts.now
  });
  if (!av.ok) fail('PUBLISH_KEY_UNTRUSTED', `attestation trust failed: ${av.code}`, { code: av.code });
  check('signature', true, `verifyAttestation ${av.code}`);
  const attester = await recoverAttestationAddress(pkg.attestation);
  check('attester', true, attester);

  if (opts.contractVersion !== undefined && opts.contractVersion !== 1 && opts.contractVersion !== 2) {
    fail('PUBLISH_INVALID_INPUT', 'contractVersion: 1 or 2 required');
  }
  const v2 = opts.contractVersion === 2;

  // -- 3. Decision + bitmap + txHash derivation from verified data. --
  const agentDecision = manifest.decision ? manifest.decision.agent : null;
  if (!Object.prototype.hasOwnProperty.call(DECISION_MAP, agentDecision || '')) {
    fail('PUBLISH_DECISION_UNSUPPORTED', `decision.agent must be ALLOW, BLOCK, or REVIEW (got ${JSON.stringify(agentDecision)})`);
  }
  const decision = DECISION_MAP[agentDecision];
  const bitmap = v2 ? deriveCompatBitmap(manifest) : deriveModelBitmap(manifest);
  const models = v2 ? deriveModelMetadata(manifest) : null;
  const txHashField = manifest.transaction ? manifest.transaction.transactionHash : null;
  if ((agentDecision === 'BLOCK' || agentDecision === 'REVIEW') && txHashField !== null && txHashField !== undefined) {
    fail('PUBLISH_TXHASH_FORBIDDEN', `${agentDecision} attestation must carry a zero transaction hash`);
  }
  const txHash = (txHashField === null || txHashField === undefined) ? ZERO_BYTES32 : toBytes32(txHashField, 'manifest.transaction.transactionHash');
  check('params', true, `decision=${agentDecision} bitmap=${bitmap}`);
  const investigationId = manifest.investigationId;

  // -- 4. Publisher key separation (mechanical, before any signing). --
  if (!isHex64(opts.publisherKey)) fail('PUBLISH_INVALID_KEY', 'publisher transaction key: 0x 32-byte hex required');
  if (!isAddress(opts.contractAddress)) fail('PUBLISH_INVALID_INPUT', 'contractAddress: address required');
  const deny = new Set((Array.isArray(opts.denyList) ? opts.denyList : []).map((a) => String(a).toLowerCase()));
  const transport = opts.transport || createViemTransport({ rpcUrl: opts.rpcUrl, publisherKey: opts.publisherKey, chainId: opts.chainId });
  const publisherAddr = transport.address
    || (await (async () => {
      const { privateKeyToAccount } = require('viem/accounts');
      return privateKeyToAccount(opts.publisherKey).address.toLowerCase();
    })());
  if (publisherAddr === attester.toLowerCase()) {
    fail('PUBLISH_KEY_CONFLICT', 'publisher transaction key must differ from the attestation signer');
  }
  if (publisherAddr === String(opts.trustedRoot).toLowerCase()) {
    fail('PUBLISH_KEY_CONFLICT', 'publisher transaction key must differ from the registry root');
  }
  if (deny.has(publisherAddr)) fail('PUBLISH_KEY_CONFLICT', 'publisher transaction key is deny-listed');
  check('key-separation', true, `publisher=${publisherAddr}`);

  const { encodeFunctionData, decodeFunctionResult, decodeEventLog, keccak256, toHex } = require('viem');
  const { parseAbi } = require('viem');
  const abi = v2 ? CONTRACT_ABI_V2 : parseAbi(CONTRACT_ABI);
  const eventName = v2 ? 'AttestedWithModels' : 'Attested';
  const contract = opts.contractAddress;
  const timeoutMs = opts.confirmTimeoutMs === undefined ? 120000 : opts.confirmTimeoutMs;
  const confirmations = opts.confirmations === undefined ? 1 : opts.confirmations;
  if (!Number.isSafeInteger(confirmations) || confirmations < 1) {
    fail('PUBLISH_INVALID_INPUT', 'confirmations: positive integer required');
  }

  const readRecord = async () => {
    const data = encodeFunctionData({ abi, functionName: 'getAttestation', args: [investigationId, attester] });
    const raw = await transport.call({ to: contract, data });
    const out = decodeFunctionResult({ abi, functionName: 'getAttestation', data: typeof raw === 'string' ? raw : raw.data });
    return {
      investigationId: out[0], manifestDigest: out[1], modelBitmap: Number(out[2]),
      decision: Number(out[3]), txHash: out[4], attester: out[5],
      ...(v2 ? { models: out[6] } : {})
    };
  };

  const wanted = { manifestDigest: manifestDigest32, modelBitmap: bitmap, decision, txHash, attester };

  // -- 5. Duplicate pre-check: identical skips submission, conflict refuses. --
  try {
    const existing = await readRecord();
    if (sameRecord(existing, wanted) && (!v2 || sameModels(existing.models, models))) {
      check('duplicate', true, 'identical on-chain record: submission skipped');
      return {
        ok: true, duplicate: true, submitted: false, txHash: null, blockNumber: null,
        contractAddress: contract, investigationId, attester, manifestDigest,
        modelBitmap: bitmap, decision: agentDecision, checks,
        ...(v2 ? { models } : {})
      };
    }
    fail('PUBLISH_CONFLICT', 'on-chain record for this investigation+attester differs: refusing conflicting submission');
  } catch (err) {
    if (err instanceof PublisherError) throw err;
    if (!isUnknownAttestationRevert(err)) throw err;
    check('duplicate', true, 'no on-chain record: proceeding');
  }

  // -- 6. Submit + confirm + independently verify. --
  const submitData = encodeFunctionData({
    abi, functionName: 'attest',
    args: v2
      ? [investigationId, manifestDigest32, bitmap, decision, txHash, attester, models]
      : [investigationId, manifestDigest32, bitmap, decision, txHash, attester]
  });
  let submitHash;
  try {
    submitHash = await transport.sendTransaction({ to: contract, data: submitData });
  } catch (err) {
    fail('PUBLISH_TX_FAILED', `submission rejected: ${(err && err.message) || err}`);
  }
  if (typeof submitHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(submitHash)) {
    fail('PUBLISH_TX_FAILED', 'submission returned no transaction hash');
  }
  check('submitted', true, submitHash);
  const receipt = await waitFor(async () => transport.getReceipt(submitHash), timeoutMs, 'submission receipt');
  // Viem returns status 'success'/'reverted'; raw RPC returns 0x1/0x0.
  // Accept both spellings; anything else fails closed.
  const statusOk = receipt.status === '0x1' || receipt.status === 1 || receipt.status === 1n || receipt.status === 'success';
  if (!statusOk) fail('PUBLISH_TX_FAILED', `submission receipt status ${String(receipt.status)}: transaction failed`);
  check('receipt', true, `status=1 block=${receipt.blockNumber}`);
  if (confirmations > 1) {
    const target = BigInt(receipt.blockNumber) + BigInt(confirmations - 1);
    await waitFor(async () => {
      const tip = await transport.getBlockNumber();
      return BigInt(tip) >= target ? true : null;
    }, timeoutMs, `${confirmations} confirmations`);
    check('confirmations', true, String(confirmations));
  }
  const back = await readRecord();
  if (!sameRecord(back, wanted) || (v2 && !sameModels(back.models, models))) {
    fail('PUBLISH_READBACK_MISMATCH', 'on-chain read-back differs from submitted attestation');
  }
  check('read-back', true, 'record matches');
  const logs = receipt.logs || [];
  const attestedLogs = [];
  for (const log of logs) {
    if (String(log.address).toLowerCase() !== contract.toLowerCase()) continue;
    try {
      const evt = decodeEventLog({ abi, data: log.data, topics: log.topics });
      if (evt.eventName === eventName) attestedLogs.push({ args: evt.args, topics: log.topics });
    } catch {
      continue;
    }
  }
  if (attestedLogs.length !== 1) fail('PUBLISH_EVENT_MISMATCH', `expected exactly one ${eventName} event, found ${attestedLogs.length}`);
  const evt = attestedLogs[0].args;
  const idTopic = Array.isArray(attestedLogs[0].topics) ? attestedLogs[0].topics[1] : null;
  const expectedIdTopic = keccak256(toHex(investigationId));
  if (String(evt.manifestDigest).toLowerCase() !== manifestDigest32.toLowerCase()
    || String(evt.attester).toLowerCase() !== attester.toLowerCase()
    || Number(evt.modelBitmap) !== bitmap
    || Number(evt.decision) !== decision
    || String(evt.txHash).toLowerCase() !== txHash.toLowerCase()
    || (v2 && !sameModels(evt.models, models))
    || (idTopic !== null && idTopic !== undefined && String(idTopic).toLowerCase() !== expectedIdTopic.toLowerCase())) {
    fail('PUBLISH_EVENT_MISMATCH', `${eventName} event contents differ from submitted attestation`);
  }
  check('event', true, `${eventName} log matches`);

  return {
    ok: true, duplicate: false, submitted: true, txHash: submitHash,
    blockNumber: typeof receipt.blockNumber === 'bigint' ? Number(receipt.blockNumber) : receipt.blockNumber,
    contractAddress: contract,
    investigationId, attester, manifestDigest, modelBitmap: bitmap,
    decision: agentDecision, checks,
    ...(v2 ? { models } : {})
  };
}

module.exports = {
  PublisherError, deriveModelBitmap, deriveCompatBitmap, deriveModelMetadata, sameModels,
  publishAttestation, createViemTransport,
  CONTRACT_ABI, CONTRACT_ABI_V2, DECISION_MAP, ZERO_BYTES32
};
