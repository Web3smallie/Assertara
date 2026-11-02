/**
 * Assertara Phase 3 — Cryptographic Provenance Signing and Attestation.
 *
 * Offline attestation for Phase 2 provenance manifests. A dedicated
 * Assertara-controlled attestation key (secp256k1, EIP-191) signs a
 * canonical body binding the exact manifest digest; judges verify the
 * signature against a root-signed versioned key registry obtained
 * out-of-band.
 *
 * Hard boundaries (mechanically enforced, see test N1-N9):
 * - No user wallet keys, seed phrases, mnemonics, or keystores anywhere:
 *   no request/collect/import/store/access path exists in this subsystem.
 * - No transaction-signing, wallet, RPC, or broadcasting functionality:
 *   this module exposes message signing over attestation bodies only.
 * - The attestation key never authorizes transactions; the transaction
 *   signer never sees attestation keys. Separate processes, keys, env.
 * - Keys enter ONLY via environment at ceremony time and are validated
 *   against the registry plus a deny-list (signer/operator/deployment
 *   and root addresses). No --import, no key fields in any file format.
 * - Import boundary: fs, path, crypto, canonicalJson, the Phase 2
 *   manifest validators, and viem only. Never signerService,
 *   signerConfig, approvals secrets, agentStore, or app config.
 *
 * What a signature proves: the identified attestation key signed this
 * exact manifest digest in the Arc Testnet attestation context. It does
 * NOT prove provider execution, record truth, or payment success.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { canonicalStringify, sha256Hex } = require('../utils/canonicalJson');
const {
  verifyPackage,
  findManifestByDigest,
  findManifestByInvestigation
} = require('./provenanceManifest');
const { privateKeyToAccount } = require('viem/accounts');
const { recoverMessageAddress } = require('viem');
if (typeof privateKeyToAccount !== 'function' || typeof recoverMessageAddress !== 'function') {
  throw new Error('provenanceAttestation: viem account/recovery functions unavailable');
}

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

const ATTESTATION_BODY_FORMAT = 'assertara-attestation-body-1';
const ATTESTATION_FORMAT = 'assertara-attestation-1';
const ATTESTATION_STORE_FORMAT = 'assertara-attestation-store-1';
const ATTESTATION_AUDIT_FORMAT = 'assertara-attestation-audit-1';
const ATTESTATION_ALGORITHM = 'eip191-secp256k1';
const ATTESTATION_PURPOSE = 'provenance-attestation';
const ATTESTATION_CHAIN_ID = 5042002; // Attestation context (Arc Testnet anchoring), NOT the investigated tx chain.
const ATTESTATION_SCHEMA_VERSION = 'assertara-provenance-1'; // Manifest schema this attestation binds.
const REGISTRY_FORMAT = 'assertara-key-registry-1';
const RECONCILIATION_FORMAT = 'assertara-reconciliation-1';
const RECONCILIATION_AMENDMENT_FORMAT = 'assertara-reconciliation-amendment-1';
const RECONCILIATION_NOTE_FORMAT = 'assertara-reconciliation-note-1';
const GENESIS_STATE = '00'.repeat(32); // 32 zero bytes, 64 hex chars. See corrected vectors; never repeat(64).
const KEY_STATES = ['ACTIVE', 'RETIRED', 'REVOKED', 'COMPROMISED'];
const DEFAULT_MAX_REGISTRY_AGE_DAYS = 180;
const DEFAULT_LOCK_STALE_MS = 60 * 60 * 1000;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^0x[0-9a-fA-F]{40}$/;
const PRIVKEY = /^0x[0-9a-fA-F]{64}$/;
const OPID_SHAPE = /^attop_[0-9a-f]{64}$/;
const ACKID_SHAPE = /^attrec_[0-9a-f]{64}$/;
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const SECP256K1_N_HALF = SECP256K1_N / 2n;

function assertLowS(signatureHex, name) {
  // Canonical-S enforcement: our signer (noble via viem) always emits
  // low-S. A high-S signature is either malleated or foreign — reject
  // at ingest so adoption can never see two valid forms of one body.
  // Precondition: 0x 65-byte hex shape already validated by the caller.
  const s = BigInt(`0x${signatureHex.slice(66, 130)}`);
  if (s > SECP256K1_N_HALF) fail('ATTEST_INVALID', `${name}: non-canonical high-S signature rejected`);
}
const MIN_MS = Date.UTC(2020, 0, 1);
const MAX_MS = Date.UTC(2100, 0, 1);

// ---------------------------------------------------------------------------
// Errors (codes are stable API; messages never echo key material).
// ---------------------------------------------------------------------------

class AttestationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AttestationError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new AttestationError(code, message);
}

// ---------------------------------------------------------------------------
// Small validators (strict; mirror the Phase 2 manifest style).
// ---------------------------------------------------------------------------

function req(v, name) {
  if (v === null || v === undefined) fail('ATTEST_INVALID', `${name}: required`);
  return v;
}

function assertId(v, name) {
  req(v, name);
  if (typeof v !== 'string' || v.length === 0 || v.length > 256) fail('ATTEST_INVALID', `${name}: id string 1..256 required`);
  return v;
}

function assertHex64(v, name) {
  req(v, name);
  if (typeof v !== 'string' || !HEX64.test(v)) fail('ATTEST_INVALID', `${name}: 64 lowercase hex required`);
  return v;
}

function assertAddress(v, name) {
  req(v, name);
  if (typeof v !== 'string' || !HEX40.test(v)) fail('ATTEST_INVALID', `${name}: 0x 20-byte address required`);
  return v.toLowerCase();
}

function assertMs(v, name) {
  req(v, name);
  if (!Number.isSafeInteger(v) || v < MIN_MS || v > MAX_MS) fail('ATTEST_INVALID', `${name}: ms timestamp 2020..2100 required`);
  return v;
}

function assertEnum(v, allowed, name) {
  req(v, name);
  if (!allowed.includes(v)) fail('ATTEST_INVALID', `${name}: one of ${allowed.join('|')}`);
  return v;
}

function optStr(v, name, max) {
  if (v === null || v === undefined) return null;
  if (typeof v !== 'string' || v.length > max) fail('ATTEST_INVALID', `${name}: string <=${max} or null`);
  return v;
}

function assertExactKeys(obj, keys, name) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) fail('ATTEST_INVALID', `${name}: object required`);
  const actual = Object.keys(obj).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((k, i) => k !== expected[i])) {
    fail('ATTEST_INVALID', `${name}: unexpected shape (exactly {${expected.join(',')}})`);
  }
}

function assertValidInput(value, name) {
  // Structural JSON-safety walk (rejects undefined/functions/symbols/
  // BigInt/circular refs); mirrors the Phase 2 manifest guard.
  const seen = new Set();
  const walk = (v) => {
    if (v === null || typeof v === 'string' || typeof v === 'boolean') return;
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) fail('ATTEST_INVALID', `${name}: non-finite number`);
      return;
    }
    if (Array.isArray(v)) {
      if (seen.has(v)) fail('ATTEST_INVALID', `${name}: circular`);
      seen.add(v);
      v.forEach(walk);
      seen.delete(v);
      return;
    }
    if (typeof v === 'object') {
      if (seen.has(v)) fail('ATTEST_INVALID', `${name}: circular`);
      seen.add(v);
      for (const k of Object.keys(v)) walk(v[k]);
      seen.delete(v);
      return;
    }
    fail('ATTEST_INVALID', `${name}: unsupported type ${typeof v}`);
  };
  walk(value);
}

// ---------------------------------------------------------------------------
// Key utilities. Generation uses node:crypto (OS CSPRNG); viem only
// derives addresses. No import path for existing/user keys exists.
// ---------------------------------------------------------------------------

function generateAttestationKey() {
  const privateKey = `0x${crypto.randomBytes(32).toString('hex')}`;
  const account = privateKeyToAccount(privateKey);
  return { privateKey, address: account.address.toLowerCase() };
}

function deriveAddress(privateKey) {
  if (typeof privateKey !== 'string' || !PRIVKEY.test(privateKey)) {
    fail('ATTEST_INVALID_KEY', 'attestation key: 0x 32-byte hex required');
  }
  return privateKeyToAccount(privateKey).address.toLowerCase();
}

function fingerprintOfAddress(address) {
  assertAddress(address, 'address');
  return sha256Hex(address.toLowerCase());
}

function parseAddressList(raw, name) {
  if (raw === null || raw === undefined || String(raw).trim() === '') return [];
  return String(raw).split(',').map((s) => s.trim()).filter((s) => s.length > 0).map((s) => {
    if (!HEX40.test(s)) fail('ATTEST_INVALID', `${name}: invalid address entry`);
    return s.toLowerCase();
  });
}

// ---------------------------------------------------------------------------
// Operation IDs. Correlation only; authoritative dedupe is always the
// full (manifestDigest, keyId) composite (attestations) or exact
// identity match (acks/amendments). Full 256-bit output.
// ---------------------------------------------------------------------------

function attestationOpId(manifestDigest, keyId) {
  assertHex64(manifestDigest, 'manifestDigest');
  assertAddress(keyId, 'keyId');
  return `attop_${sha256Hex(canonicalStringify({ keyId: keyId.toLowerCase(), manifestDigest, purpose: 'attestation-operation' }))}`;
}

// ---------------------------------------------------------------------------
// Attestation body, signing, verification.
// ---------------------------------------------------------------------------

function buildAttestationBody({ manifestDigest, investigationId, traceId, requestId, keyId, issuedAt }) {
  assertHex64(manifestDigest, 'body.manifestDigest');
  assertId(investigationId, 'body.investigationId');
  assertId(traceId, 'body.traceId');
  if (requestId !== null && requestId !== undefined) assertId(requestId, 'body.requestId');
  assertAddress(keyId, 'body.keyId');
  const at = issuedAt === undefined ? Date.now() : issuedAt;
  assertMs(at, 'body.issuedAt');
  return {
    attestationChainId: ATTESTATION_CHAIN_ID,
    format: ATTESTATION_BODY_FORMAT,
    investigationId,
    issuedAt: at,
    keyId: keyId.toLowerCase(),
    manifestDigest,
    manifestSchemaVersion: ATTESTATION_SCHEMA_VERSION,
    purpose: ATTESTATION_PURPOSE,
    requestId: requestId === undefined ? null : requestId,
    traceId
  };
}

function assertAttestationBodyShape(body) {
  assertExactKeys(body, ['attestationChainId', 'format', 'investigationId', 'issuedAt', 'keyId', 'manifestDigest', 'manifestSchemaVersion', 'purpose', 'requestId', 'traceId'], 'attestation.body');
  if (body.attestationChainId !== ATTESTATION_CHAIN_ID) fail('ATTEST_INVALID', 'attestation.body.attestationChainId: wrong context chain');
  if (body.format !== ATTESTATION_BODY_FORMAT) fail('ATTEST_INVALID', 'attestation.body.format: unknown version');
  if (body.purpose !== ATTESTATION_PURPOSE) fail('ATTEST_INVALID', 'attestation.body.purpose: wrong purpose');
  if (body.manifestSchemaVersion !== ATTESTATION_SCHEMA_VERSION) fail('ATTEST_INVALID', 'attestation.body.manifestSchemaVersion: unsupported');
  assertId(body.investigationId, 'attestation.body.investigationId');
  assertId(body.traceId, 'attestation.body.traceId');
  if (body.requestId !== null) assertId(body.requestId, 'attestation.body.requestId');
  assertAddress(body.keyId, 'attestation.body.keyId');
  assertHex64(body.manifestDigest, 'attestation.body.manifestDigest');
  assertMs(body.issuedAt, 'attestation.body.issuedAt');
}

function assertAttestationShape(a) {
  assertExactKeys(a, ['algorithm', 'authority', 'body', 'format', 'signature'], 'attestation');
  if (a.format !== ATTESTATION_FORMAT) fail('ATTEST_INVALID', 'attestation.format: unknown version');
  if (a.algorithm !== ATTESTATION_ALGORITHM) fail('ATTEST_INVALID', 'attestation.algorithm: unsupported');
  assertAddress(a.authority, 'attestation.authority');
  if (typeof a.signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(a.signature)) {
    fail('ATTEST_INVALID', 'attestation.signature: 0x 65-byte required');
  }
  assertLowS(a.signature, 'attestation.signature');
  assertAttestationBodyShape(a.body);
}

async function signAttestation({ body, privateKey }) {
  if (!body || typeof body !== 'object') fail('ATTEST_INVALID', 'body: object required');
  assertAttestationBodyShape(body);
  const address = deriveAddress(privateKey); // Validates shape; never echoes the key.
  if (address !== body.keyId.toLowerCase()) {
    fail('ATTEST_KEY_MISMATCH', 'signing key does not match body.keyId');
  }
  const account = privateKeyToAccount(privateKey);
  const signature = await account.signMessage({ message: canonicalStringify(body) });
  const attestation = {
    algorithm: ATTESTATION_ALGORITHM,
    authority: address,
    body,
    format: ATTESTATION_FORMAT,
    signature
  };
  assertAttestationShape(attestation);
  return attestation;
}

async function recoverAttestationAddress(attestation) {
  assertAttestationShape(attestation);
  const recovered = await recoverMessageAddress({
    message: canonicalStringify(attestation.body),
    signature: attestation.signature
  });
  return recovered.toLowerCase();
}

// ---------------------------------------------------------------------------
// Key registry: root-signed, versioned, monotonic.
// ---------------------------------------------------------------------------

function assertRegistryKeyEntry(entry, name) {
  assertExactKeys(entry, ['reason', 'status', 'statusChangedAt', 'supersededBy', 'validFrom'], name);
  assertEnum(entry.status, KEY_STATES, `${name}.status`);
  assertMs(entry.validFrom, `${name}.validFrom`);
  assertMs(entry.statusChangedAt, `${name}.statusChangedAt`);
  if (typeof entry.reason !== 'string' || entry.reason.length === 0 || entry.reason.length > 500) {
    fail('ATTEST_INVALID', `${name}.reason: string 1..500 required`);
  }
  if (entry.supersededBy !== null) assertAddress(entry.supersededBy, `${name}.supersededBy`);
}

function registryUnsignedBytes(registry) {
  // Canonical bytes covered by the root signature: everything except
  // rootSignature itself (same seal-excluded pattern as mandate seals).
  assertExactKeys(registry, ['format', 'keys', 'publishedAt', 'rootSignature', 'supersedes', 'version'], 'registry');
  if (registry.format !== REGISTRY_FORMAT) fail('ATTEST_INVALID', 'registry.format: unknown version');
  if (!Number.isSafeInteger(registry.version) || registry.version < 0) fail('ATTEST_INVALID', 'registry.version: integer >= 0 required');
  assertMs(registry.publishedAt, 'registry.publishedAt');
  if (registry.supersedes !== null) {
    assertExactKeys(registry.supersedes, ['note', 'root', 'version'], 'registry.supersedes');
    assertAddress(registry.supersedes.root, 'registry.supersedes.root');
    if (!Number.isSafeInteger(registry.supersedes.version) || registry.supersedes.version < 0) {
      fail('ATTEST_INVALID', 'registry.supersedes.version: integer >= 0 required');
    }
    optStr(registry.supersedes.note, 'registry.supersedes.note', 500);
  }
  if (!registry.keys || typeof registry.keys !== 'object' || Array.isArray(registry.keys)) {
    fail('ATTEST_INVALID', 'registry.keys: object required');
  }
  for (const [addr, entry] of Object.entries(registry.keys)) {
    assertAddress(addr, 'registry.keys[] address');
    assertRegistryKeyEntry(entry, `registry.keys[${addr}]`);
  }
  const { rootSignature: _ignored, ...unsigned } = registry;
  return canonicalStringify(unsigned);
}

function buildRegistrySkeleton({ version, publishedAt, supersedes }) {
  if (!Number.isSafeInteger(version) || version < 0) fail('ATTEST_INVALID', 'registry.version: integer >= 0 required');
  assertMs(publishedAt, 'registry.publishedAt');
  return {
    format: REGISTRY_FORMAT,
    keys: {},
    publishedAt,
    rootSignature: null,
    supersedes: supersedes === undefined ? null : supersedes,
    version
  };
}

function prepareRegistryUpdate(current, change) {
  // Pure transition builder: validates monotonic version + monotonic key
  // states (ACTIVE -> terminal only; terminal states never leave).
  if (!current || typeof current !== 'object') fail('ATTEST_INVALID', 'current registry: object required');
  if (!change || typeof change !== 'object') fail('ATTEST_INVALID', 'change: object required');
  assertExactKeys(change, ['add', 'publishedAt', 'retire', 'revoke', 'version'], 'registry change');
  assertMs(change.publishedAt, 'change.publishedAt');
  if (!Number.isSafeInteger(change.version) || change.version !== current.version + 1) {
    fail('ATTEST_INVALID', 'change.version: must be current version + 1');
  }
  const keys = JSON.parse(JSON.stringify(current.keys || {}));
  for (const [k, v] of Object.entries(keys)) {
    if (!HEX40.test(k)) fail('ATTEST_INVALID', 'current registry.keys[] address');
    assertRegistryKeyEntry(v, `current registry.keys[${k}]`);
  }
  const apply = (addr, next, allowedFrom) => {
    const a = assertAddress(addr, 'change address');
    const prev = keys[a] || null;
    if (prev === null && !allowedFrom.includes(null)) fail('ATTEST_INVALID', `change: unknown key ${a}`);
    if (prev !== null && !allowedFrom.includes(prev.status)) {
      fail('ATTEST_INVALID', `change: illegal transition ${prev.status} -> ${next.status} for ${a}`);
    }
    assertRegistryKeyEntry({ ...next }, `change ${a}`);
    keys[a] = { ...next };
  };
  for (const [addr, entry] of Object.entries(change.add || {})) {
    if (entry.status !== 'ACTIVE') fail('ATTEST_INVALID', 'change.add: new keys must be ACTIVE');
    apply(addr, entry, [null]);
  }
  for (const [addr, entry] of Object.entries(change.retire || {})) {
    if (entry.status !== 'RETIRED') fail('ATTEST_INVALID', 'change.retire: status must be RETIRED');
    apply(addr, entry, ['ACTIVE']);
  }
  for (const [addr, entry] of Object.entries(change.revoke || {})) {
    if (entry.status !== 'REVOKED' && entry.status !== 'COMPROMISED') {
      fail('ATTEST_INVALID', 'change.revoke: status must be REVOKED or COMPROMISED');
    }
    apply(addr, entry, ['ACTIVE', 'RETIRED', 'REVOKED', 'COMPROMISED']);
  }
  return {
    format: REGISTRY_FORMAT,
    keys,
    publishedAt: change.publishedAt,
    rootSignature: null,
    supersedes: current.supersedes === undefined ? null : current.supersedes,
    version: change.version
  };
}

async function signRegistry({ registry, rootPrivateKey }) {
  if (!registry || typeof registry !== 'object') fail('ATTEST_INVALID', 'registry: object required');
  const address = deriveAddress(rootPrivateKey);
  const bytes = registryUnsignedBytes(registry);
  const account = privateKeyToAccount(rootPrivateKey);
  const signature = await account.signMessage({ message: bytes });
  const signed = { ...registry, rootSignature: { algorithm: ATTESTATION_ALGORITHM, authority: address, signature } };
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    fail('ATTEST_INVALID', 'registry signature malformed');
  }
  assertLowS(signature, 'registry signature');
  return signed;
}

async function verifyRegistry({ registry, trustedRoot, minVersion, maxAgeDays, allowStale, now }) {
  const failOut = (code, detail) => ({ ok: false, code, detail });
  try {
    if (minVersion !== undefined && minVersion !== null
      && (typeof minVersion !== 'number' || !Number.isSafeInteger(minVersion) || minVersion < 0)) {
      return failOut('registry-invalid-input', 'minVersion: safe non-negative integer required');
    }
    if (maxAgeDays !== undefined && maxAgeDays !== null
      && (typeof maxAgeDays !== 'number' || !Number.isFinite(maxAgeDays) || maxAgeDays < 0)) {
      return failOut('registry-invalid-input', 'maxAgeDays: finite non-negative number required');
    }
    if (!registry || typeof registry !== 'object') return failOut('registry-invalid', 'registry missing');
    const root = assertAddress(trustedRoot, 'trustedRoot');
    const bytes = registryUnsignedBytes(registry);
    const sig = registry.rootSignature;
    if (!sig || typeof sig !== 'object') return failOut('registry-invalid', 'missing root signature');
    if (sig.algorithm !== ATTESTATION_ALGORITHM) return failOut('unsupported-algorithm', 'registry signature algorithm');
    assertAddress(sig.authority, 'registry.rootSignature.authority');
    if (sig.authority.toLowerCase() !== root) return failOut('registry-invalid', 'signed by untrusted root');
    if (typeof sig.signature === 'string' && /^0x[0-9a-fA-F]{130}$/.test(sig.signature)) {
      try {
        assertLowS(sig.signature, 'registry.rootSignature.signature');
      } catch (err) {
        return failOut('registry-invalid', err.message);
      }
    }
    let recovered;
    try {
      recovered = (await recoverMessageAddress({ message: bytes, signature: sig.signature })).toLowerCase();
    } catch {
      return failOut('registry-invalid', 'root signature does not verify');
    }
    if (recovered !== root) return failOut('registry-invalid', 'root signature does not verify');
    if (minVersion !== undefined && minVersion !== null && registry.version < minVersion) {
      return failOut('registry-rollback', `version ${registry.version} below minimum ${minVersion}`);
    }
    const at = now === undefined ? Date.now() : now;
    const maxAge = maxAgeDays === undefined || maxAgeDays === null ? DEFAULT_MAX_REGISTRY_AGE_DAYS : maxAgeDays;
    if (!allowStale && Number.isFinite(maxAge) && registry.publishedAt + maxAge * 86400000 < at) {
      return failOut('stale-registry', `publishedAt older than ${maxAge} days`);
    }
    return { ok: true, code: 'registry-valid', detail: '', version: registry.version, keys: registry.keys };
  } catch (err) {
    if (err instanceof AttestationError) return failOut('registry-invalid', err.message);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Attestation verification. Never throws on hostile input: every failure
// is a distinct code. Registry is required — key-state evaluation has
// no meaning without one. Corroboration is caller-asserted and recorded
// as such; the caller (judge) must have checked the anchor themselves.
// ---------------------------------------------------------------------------

async function verifyAttestation({
  manifest,
  attestation,
  trustedAuthorities,
  keyRegistry,
  trustedRoot,
  corroboration,
  acceptRevoked,
  maxRegistryAgeDays,
  allowStaleRegistry,
  now
}) {
  const failOut = (code, detail) => ({ ok: false, code, detail });
  try {
    if (!manifest || typeof manifest !== 'object') return failOut('manifest-invalid', 'manifest missing');
    assertValidInput(attestation, 'attestation');
    try {
      assertAttestationShape(attestation);
    } catch (err) {
      if (err.code === 'ATTEST_INVALID' && String(err.message).includes('algorithm')) {
        return failOut('unsupported-algorithm', err.message);
      }
      return failOut('attestation-invalid', err.message);
    }
    if (!Array.isArray(trustedAuthorities) || trustedAuthorities.length === 0) {
      return failOut('unknown-key', 'no trusted authorities configured');
    }
    const trusted = trustedAuthorities.map((a) => assertAddress(a, 'trustedAuthorities[]'));
    if (!keyRegistry || typeof keyRegistry !== 'object') return failOut('registry-missing', 'key registry required');
    const reg = await verifyRegistry({
      registry: keyRegistry,
      trustedRoot,
      maxAgeDays: maxRegistryAgeDays,
      allowStale: allowStaleRegistry,
      now
    });
    if (!reg.ok) return failOut(reg.code, reg.detail);
    // Signature recovery.
    let recovered;
    try {
      recovered = await recoverAttestationAddress(attestation);
    } catch {
      return failOut('invalid-signature', 'signature does not verify');
    }
    const body = attestation.body;
    if (recovered !== attestation.authority.toLowerCase() || recovered !== body.keyId.toLowerCase()) {
      return failOut('invalid-signature', 'recovered address does not match authority/keyId');
    }
    if (!trusted.includes(recovered)) return failOut('unknown-key', 'authority not in trusted list');
    // Digest binding: recompute from the manifest bytes, never trust envelopes.
    assertValidInput(manifest, 'manifest');
    const recomputed = sha256Hex(canonicalStringify(manifest));
    if (recomputed !== body.manifestDigest) return failOut('digest-mismatch', 'manifest digest does not match attested digest');
    if (manifest.investigationId !== body.investigationId
      || manifest.traceId !== body.traceId
      || (manifest.requestId === undefined ? null : manifest.requestId) !== body.requestId) {
      return failOut('context-mismatch', 'manifest ids do not match attested ids');
    }
    if (manifest.schemaVersion !== body.manifestSchemaVersion) {
      return failOut('context-mismatch', 'manifest schema version does not match attested version');
    }
    const at = now === undefined ? Date.now() : now;
    if (body.issuedAt > at) return failOut('context-mismatch', 'attestation issued in the future');
    // Key-state evaluation.
    const entry = reg.keys[recovered] || reg.keys[recovered.toLowerCase()] || null;
    if (entry === null) return failOut('unknown-key', 'authority not in registry');
    if (body.issuedAt < entry.validFrom) {
      return failOut('context-mismatch', 'attestation predates key validity window');
    }
    if (entry.status === 'ACTIVE') return { ok: true, code: 'valid', detail: '', keyState: 'ACTIVE' };
    if (entry.status === 'RETIRED') {
      const inWindow = body.issuedAt <= entry.statusChangedAt;
      if (!inWindow) return failOut('retired-uncorroborated', 'issuedAt outside retirement window');
      if (!corroboration || typeof corroboration !== 'object' || !corroboration.type || !corroboration.ref) {
        return failOut('retired-uncorroborated', 'historical trust requires corroboration');
      }
      return {
        ok: true,
        code: 'trusted-historical',
        detail: `corroboration asserted by caller: ${corroboration.type} ${corroboration.ref}`,
        keyState: 'RETIRED',
        corroboration: { assertedBy: 'caller', type: corroboration.type, ref: corroboration.ref }
      };
    }
    if (entry.status === 'REVOKED') {
      if (acceptRevoked === true) {
        return { ok: false, code: 'revoked-key', detail: 'revoked key explicitly overridden by caller', overridden: true };
      }
      return failOut('revoked-key', 'key revoked: untrusted without explicit override');
    }
    return failOut('compromised-key', 'key compromised: untrusted, re-attestation required');
  } catch (err) {
    if (err instanceof AttestationError) return failOut('attestation-invalid', err.message);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Reconciliation journal: cumulative hash chain. Every physical byte of
// every terminated line contributes, in order, including delimiters.
// S_i = sha256(raw32(S_{i-1}) || lineBytes || 0x0A); S_{-1} = GENESIS.
// ---------------------------------------------------------------------------

function chainAdvance(prevHex, lineInput) {
  // lineInput: exact line bytes as Buffer, or a string (UTF-8 encoded).
  // Buffers preserve non-UTF8 debris bytes exactly; strings are exact
  // for all legitimate (valid UTF-8) lines.
  if (typeof prevHex !== 'string' || !HEX64.test(prevHex)) fail('ATTEST_INVALID', 'chain state: 64 hex required');
  const body = Buffer.isBuffer(lineInput) ? lineInput : Buffer.from(String(lineInput), 'utf8');
  return sha256Hex(Buffer.concat([Buffer.from(prevHex, 'hex'), body, Buffer.from([10])]));
}

function normalizeChainLines(lines) {
  if (!Array.isArray(lines)) fail('ATTEST_INVALID', 'journal lines: array required');
  return lines.map((entry) => {
    if (typeof entry === 'string') return { bytes: Buffer.from(entry, 'utf8'), text: entry };
    if (entry && Buffer.isBuffer(entry.bytes) && typeof entry.text === 'string') {
      return { bytes: entry.bytes, text: entry.text };
    }
    fail('ATTEST_INVALID', 'journal lines: strings or {bytes,text} required');
    return null;
  });
}

function verifyJournalChain(lines) {
  // lines: complete terminated lines as strings or {bytes,text} entries.
  // Returns per-line verdicts plus the first break index (null if none).
  // Link rule: every valid event's chainPrev must equal the recomputed
  // cumulative state before its line. Non-event lines contribute their
  // exact bytes but carry no links.
  const entries = normalizeChainLines(lines);
  let state = GENESIS_STATE;
  const verdicts = [];
  let firstBreak = null;
  for (let i = 0; i < entries.length; i += 1) {
    const { bytes, text } = entries[i];
    let event = null;
    let eventKind = null;
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        if (parsed.format === RECONCILIATION_FORMAT
          || parsed.format === RECONCILIATION_AMENDMENT_FORMAT
          || parsed.format === RECONCILIATION_NOTE_FORMAT) {
          event = parsed;
          eventKind = parsed.format;
        }
      }
    } catch {
      event = null;
    }
    if (event !== null) {
      if (typeof event.chainPrev !== 'string' || event.chainPrev !== state) {
        if (firstBreak === null) firstBreak = i;
        verdicts.push({ index: i, kind: eventKind, usable: false, reason: 'chain-link-break' });
      } else {
        verdicts.push({ index: i, kind: eventKind, usable: firstBreak === null, reason: firstBreak === null ? '' : 'after-break' });
      }
    } else {
      verdicts.push({ index: i, kind: 'debris', usable: false, reason: 'not-an-event' });
    }
    state = chainAdvance(state, bytes);
  }
  return { verdicts, firstBreak, tipState: state };
}

// ---------------------------------------------------------------------------
// Acknowledgments, amendments, notes. Deterministic IDs; exact shapes.
// Identity fields participate in the ID; `at` and `chainPrev` are
// informational/positional. Same ID + substantive difference = conflict.
// ---------------------------------------------------------------------------

function acknowledgmentId({ store, offset, length, bytesSha256 }) {
  assertEnum(store, ['attestations', 'audit', 'journal'], 'ack.store');
  if (!Number.isSafeInteger(offset) || offset < 0) fail('ATTEST_INVALID', 'ack.offset: integer >= 0 required');
  if (!Number.isSafeInteger(length) || length < 0) fail('ATTEST_INVALID', 'ack.length: integer >= 0 required');
  assertHex64(bytesSha256, 'ack.bytesSha256');
  return `attrec_${sha256Hex(canonicalStringify({ bytesSha256, length, offset, purpose: 'reconciliation-ack', store }))}`;
}

function buildAcknowledgment({
  store, offset, length, bytesSha256, classification, rationale, operator,
  manifestDigest, keyId, opId, at, chainPrev
}) {
  const ackId = acknowledgmentId({ store, offset, length, bytesSha256 });
  assertEnum(classification, ['foreign-debris', 'ambiguous-debris', 'blank-line', 'torn-fragment'], 'ack.classification');
  if (typeof rationale !== 'string' || rationale.length === 0 || rationale.length > 2000) {
    fail('ATTEST_INVALID', 'ack.rationale: string 1..2000 required');
  }
  if (typeof operator !== 'string' || operator.length === 0 || operator.length > 256) {
    fail('ATTEST_INVALID', 'ack.operator: string 1..256 required');
  }
  if (manifestDigest !== null && manifestDigest !== undefined) assertHex64(manifestDigest, 'ack.manifestDigest');
  if (keyId !== null && keyId !== undefined) assertAddress(keyId, 'ack.keyId');
  if (opId !== null && opId !== undefined) {
    if (typeof opId !== 'string' || !OPID_SHAPE.test(opId)) fail('ATTEST_INVALID', 'ack.opId: attestation opId or null');
  }
  const stamp = at === undefined ? Date.now() : at;
  assertMs(stamp, 'ack.at');
  assertHex64(chainPrev, 'ack.chainPrev');
  return {
    ackId,
    at: stamp,
    bytesSha256,
    chainPrev,
    classification,
    format: RECONCILIATION_FORMAT,
    keyId: keyId === undefined ? null : (keyId === null ? null : keyId.toLowerCase()),
    length,
    manifestDigest: manifestDigest === undefined ? null : manifestDigest,
    offset,
    opId: opId === undefined ? null : opId,
    operator,
    rationale,
    store
  };
}

function amendmentId({ amendsAckId, endorsedRecordSha256, newRationale, newClassification, operator }) {
  if (typeof amendsAckId !== 'string' || !ACKID_SHAPE.test(amendsAckId)) {
    fail('ATTEST_INVALID', 'amendment.amendsAckId: acknowledgment id required');
  }
  assertHex64(endorsedRecordSha256, 'amendment.endorsedRecordSha256');
  if (typeof newRationale !== 'string' || newRationale.length === 0 || newRationale.length > 2000) {
    fail('ATTEST_INVALID', 'amendment.newRationale: string 1..2000 required');
  }
  if (newClassification !== null && newClassification !== undefined
    && !['foreign-debris', 'ambiguous-debris', 'blank-line', 'torn-fragment'].includes(newClassification)) {
    fail('ATTEST_INVALID', 'amendment.newClassification: known classification or null');
  }
  if (typeof operator !== 'string' || operator.length === 0 || operator.length > 256) {
    fail('ATTEST_INVALID', 'amendment.operator: string 1..256 required');
  }
  return `attamd_${sha256Hex(canonicalStringify({
    amendsAckId,
    endorsedRecordSha256,
    newClassification: newClassification === undefined ? null : newClassification,
    newRationale,
    operator,
    purpose: 'reconciliation-amendment'
  }))}`;
}

function buildAmendment({
  amendsAckId, endorsedRecordSha256, newRationale, newClassification, operator, at, chainPrev
}) {
  const id = amendmentId({ amendsAckId, endorsedRecordSha256, newRationale, newClassification, operator });
  const stamp = at === undefined ? Date.now() : at;
  assertMs(stamp, 'amendment.at');
  assertHex64(chainPrev, 'amendment.chainPrev');
  return {
    amendsAckId,
    amendmentId: id,
    at: stamp,
    chainPrev,
    endorsedRecordSha256,
    format: RECONCILIATION_AMENDMENT_FORMAT,
    newClassification: newClassification === undefined ? null : newClassification,
    newRationale,
    operator
  };
}

function buildNote({ refAckId, text, operator, at, chainPrev }) {
  if (refAckId !== null && refAckId !== undefined
    && (typeof refAckId !== 'string' || !ACKID_SHAPE.test(refAckId))) {
    fail('ATTEST_INVALID', 'note.refAckId: acknowledgment id or null');
  }
  if (typeof text !== 'string' || text.length === 0 || text.length > 2000) fail('ATTEST_INVALID', 'note.text: string 1..2000 required');
  if (typeof operator !== 'string' || operator.length === 0 || operator.length > 256) {
    fail('ATTEST_INVALID', 'note.operator: string 1..256 required');
  }
  const stamp = at === undefined ? Date.now() : at;
  assertMs(stamp, 'note.at');
  assertHex64(chainPrev, 'note.chainPrev');
  const noteId = `attnote_${sha256Hex(canonicalStringify({
    operator,
    purpose: 'reconciliation-note',
    refAckId: refAckId === undefined ? null : refAckId,
    text
  }))}`;
  return { at: stamp, chainPrev, format: RECONCILIATION_NOTE_FORMAT, noteId, operator, refAckId: refAckId === undefined ? null : refAckId, text };
}

function assertNoteShape(n) {
  assertExactKeys(n, ['at', 'chainPrev', 'format', 'noteId', 'operator', 'refAckId', 'text'], 'note');
  if (n.format !== RECONCILIATION_NOTE_FORMAT) fail('ATTEST_INVALID', 'note.format');
  assertMs(n.at, 'note.at');
  assertHex64(n.chainPrev, 'note.chainPrev');
  if (typeof n.operator !== 'string' || n.operator.length === 0 || n.operator.length > 256) fail('ATTEST_INVALID', 'note.operator');
  if (typeof n.text !== 'string' || n.text.length === 0 || n.text.length > 2000) fail('ATTEST_INVALID', 'note.text');
  if (n.refAckId !== null && (typeof n.refAckId !== 'string' || !ACKID_SHAPE.test(n.refAckId))) {
    fail('ATTEST_INVALID', 'note.refAckId');
  }
  const expect = `attnote_${sha256Hex(canonicalStringify({ operator: n.operator, purpose: 'reconciliation-note', refAckId: n.refAckId, text: n.text }))}`;
  if (n.noteId !== expect) fail('ATTEST_INVALID', 'note.noteId does not match content fields');
}

function assertAckShape(a) {
  assertExactKeys(a, ['ackId', 'at', 'bytesSha256', 'chainPrev', 'classification', 'format', 'keyId', 'length', 'manifestDigest', 'offset', 'opId', 'operator', 'rationale', 'store'], 'ack');
  if (a.format !== RECONCILIATION_FORMAT) fail('ATTEST_INVALID', 'ack.format');
  const expect = acknowledgmentId({ store: a.store, offset: a.offset, length: a.length, bytesSha256: a.bytesSha256 });
  if (a.ackId !== expect) fail('ATTEST_INVALID', 'ack.ackId does not match identity fields');
  assertEnum(a.classification, ['foreign-debris', 'ambiguous-debris', 'blank-line', 'torn-fragment'], 'ack.classification');
  if (typeof a.rationale !== 'string' || a.rationale.length === 0 || a.rationale.length > 2000) fail('ATTEST_INVALID', 'ack.rationale');
  if (typeof a.operator !== 'string' || a.operator.length === 0 || a.operator.length > 256) fail('ATTEST_INVALID', 'ack.operator');
  assertMs(a.at, 'ack.at');
  assertHex64(a.chainPrev, 'ack.chainPrev');
  if (a.manifestDigest !== null) assertHex64(a.manifestDigest, 'ack.manifestDigest');
  if (a.keyId !== null) assertAddress(a.keyId, 'ack.keyId');
  if (a.opId !== null && (typeof a.opId !== 'string' || !OPID_SHAPE.test(a.opId))) {
    fail('ATTEST_INVALID', 'ack.opId: attestation opId or null');
  }
}

function assertAmendmentShape(a) {
  assertExactKeys(a, ['amendsAckId', 'amendmentId', 'at', 'chainPrev', 'endorsedRecordSha256', 'format', 'newClassification', 'newRationale', 'operator'], 'amendment');
  if (a.format !== RECONCILIATION_AMENDMENT_FORMAT) fail('ATTEST_INVALID', 'amendment.format');
  const expect = amendmentId({
    amendsAckId: a.amendsAckId,
    endorsedRecordSha256: a.endorsedRecordSha256,
    newRationale: a.newRationale,
    newClassification: a.newClassification,
    operator: a.operator
  });
  if (a.amendmentId !== expect) fail('ATTEST_INVALID', 'amendment.amendmentId does not match identity fields');
  assertMs(a.at, 'amendment.at');
  assertHex64(a.chainPrev, 'amendment.chainPrev');
}

// ---------------------------------------------------------------------------
// Store I/O. Prefix-tolerant readers classify but never accept; the
// integrity gate decides. Durable appends sync + re-read + verify.
// ---------------------------------------------------------------------------

const STORE_FILES = {
  attestations: 'attestations.jsonl',
  audit: 'attestation-audit.jsonl',
  journal: 'attestation-reconciliation.jsonl'
};

function storePaths(storeDir) {
  const dir = storeDir || path.join(process.cwd(), 'data');
  return {
    dir,
    attestations: path.join(dir, STORE_FILES.attestations),
    audit: path.join(dir, STORE_FILES.audit),
    journal: path.join(dir, STORE_FILES.journal),
    lock: path.join(dir, '.attestation-ceremony.lock'),
    quarantine: path.join(dir, '.attestation-lock-quarantine')
  };
}

function readStoreFile(file) {
  // Returns every complete line with byte offsets plus the optional
  // unterminated tail. Empty file = valid initialized empty store.
  let raw;
  try {
    raw = fs.readFileSync(file);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      return { file, exists: false, lines: [], malformed: [], blanks: [], tail: null, endsWithNewline: true, size: 0 };
    }
    throw err;
  }
  const lines = [];
  const malformed = [];
  const blanks = [];
  let start = 0;
  const lineIndex = () => lines.length + malformed.length + blanks.length;
  for (let i = 0; i < raw.length; i += 1) {
    if (raw[i] === 10) {
      const bytes = raw.subarray(start, i);
      const text = bytes.toString('utf8');
      const entry = { index: lineIndex(), offset: start, length: bytes.length, sha256: sha256Hex(bytes), text, bytes: Buffer.from(bytes) };
      if (text.trim().length === 0) {
        blanks.push(entry);
      } else {
        let parsed = null;
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = null;
        }
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          lines.push({ ...entry, parsed });
        } else {
          malformed.push(entry);
        }
      }
      start = i + 1;
    }
  }
  let tail = null;
  if (start < raw.length) {
    const bytes = raw.subarray(start);
    tail = { offset: start, length: bytes.length, sha256: sha256Hex(bytes), bytes };
  }
  return { file, exists: true, lines, malformed, blanks, tail, endsWithNewline: start >= raw.length, size: raw.length };
}

function fsyncDir(dir) {
  // Directory-entry durability for new files. POSIX-only primitive;
  // Node cannot fsync directories on Windows — documented limitation
  // (NTFS metadata journaling covers the common case; absence of the
  // file on retry is handled as a fresh store either way).
  if (process.platform === 'win32') return 'skipped-windows';
  const fd = fs.openSync(dir, 'r');
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  return 'synced';
}

function durableAppend(file, line, { fsyncFn } = {}) {
  // Append one complete line, synchronize, then re-read and verify the
  // exact bytes. Returns {offset, length}. Never returns success unless
  // the bytes on disk match. Retries are the caller's job — and must
  // always re-read first (see ceremony recovery).
  if (typeof line !== 'string' || line.length === 0 || line.includes('\n')) {
    fail('ATTEST_INVALID', 'durableAppend: single non-empty line without newline required');
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const existed = fs.existsSync(file);
  const sync = fsyncFn || fs.fsyncSync;
  const payload = Buffer.from(`${line}\n`, 'utf8');
  const fd = fs.openSync(file, 'a');
  let offset;
  try {
    offset = fs.fstatSync(fd).size;
    fs.writeSync(fd, payload, 0, payload.length, null);
    sync(fd);
  } finally {
    fs.closeSync(fd);
  }
  if (!existed) {
    try {
      fsyncDir(path.dirname(file));
    } catch {
      // Best-effort directory durability; file content already synced.
    }
  }
  const check = fs.openSync(file, 'r');
  try {
    const back = Buffer.alloc(payload.length);
    const read = fs.readSync(check, back, 0, payload.length, offset);
    if (read !== payload.length || !back.equals(payload)) {
      fail('ATTEST_PERSIST_FAILED', 'post-write verification mismatch');
    }
  } finally {
    fs.closeSync(check);
  }
  return { offset, length: line.length };
}

function appendDelimiterIfNeeded(file) {
  // Ensures the file ends with \n by pure append (zero existing bytes
  // touched) so a following record starts on a fresh line. Returns true
  // when a delimiter was written. Empty/missing files need none.
  let raw;
  try {
    raw = fs.readFileSync(file);
  } catch (err) {
    if (err && err.code === 'ENOENT') return false;
    throw err;
  }
  if (raw.length === 0 || raw[raw.length - 1] === 10) return false;
  durableAppendRaw(file, Buffer.from([10]));
  return true;
}

function durableAppendRaw(file, payload) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const fd = fs.openSync(file, 'a');
  try {
    fs.writeSync(fd, payload, 0, payload.length, null);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

// ---------------------------------------------------------------------------
// Attestation + audit record shapes, finders, adoption.
// ---------------------------------------------------------------------------

function buildAttestationStoreLine({ attestation, opId, recordedAt }) {
  assertAttestationShape(attestation);
  if (typeof opId !== 'string' || !OPID_SHAPE.test(opId)) fail('ATTEST_INVALID', 'store.opId: attestation opId required');
  const at = recordedAt === undefined ? Date.now() : recordedAt;
  assertMs(at, 'store.recordedAt');
  return { attestation, format: ATTESTATION_STORE_FORMAT, opId, recordedAt: at };
}

function assertAttestationStoreLine(line) {
  assertExactKeys(line, ['attestation', 'format', 'opId', 'recordedAt'], 'attestation store line');
  if (line.format !== ATTESTATION_STORE_FORMAT) fail('ATTEST_INVALID', 'attestation store line format');
  assertAttestationShape(line.attestation);
  if (typeof line.opId !== 'string' || !OPID_SHAPE.test(line.opId)) fail('ATTEST_INVALID', 'attestation store line opId');
  assertMs(line.recordedAt, 'attestation store line recordedAt');
}

function assertLockBrokenShape(v) {
  if (v === null || v === undefined) return null;
  assertExactKeys(v, ['prevAge', 'prevPid', 'quarantined'], 'audit.lockBroken');
  if (!Number.isSafeInteger(v.prevAge) || v.prevAge < 0) fail('ATTEST_INVALID', 'audit.lockBroken.prevAge: integer >= 0 required');
  if (!Number.isSafeInteger(v.prevPid) || v.prevPid < 0) fail('ATTEST_INVALID', 'audit.lockBroken.prevPid: integer >= 0 required');
  if (typeof v.quarantined !== 'string') fail('ATTEST_INVALID', 'audit.lockBroken.quarantined: string required');
  return v;
}

function buildAuditEvent({
  opId, manifestDigest, keyId, investigationId, decision, registryVersion,
  warnings, reconciliationRefs, lockBroken, at
}) {
  if (typeof opId !== 'string' || !OPID_SHAPE.test(opId)) fail('ATTEST_INVALID', 'audit.opId: attestation opId required');
  assertHex64(manifestDigest, 'audit.manifestDigest');
  assertAddress(keyId, 'audit.keyId');
  assertId(investigationId, 'audit.investigationId');
  if (typeof decision !== 'string' || decision.length === 0) fail('ATTEST_INVALID', 'audit.decision required');
  if (!Number.isSafeInteger(registryVersion) || registryVersion < 0) fail('ATTEST_INVALID', 'audit.registryVersion required');
  if (!Array.isArray(warnings)) fail('ATTEST_INVALID', 'audit.warnings: array required');
  if (!Array.isArray(reconciliationRefs)) fail('ATTEST_INVALID', 'audit.reconciliationRefs: array required');
  const stamp = at === undefined ? Date.now() : at;
  assertMs(stamp, 'audit.at');
  const lb = assertLockBrokenShape(lockBroken === undefined ? null : lockBroken);
  return {
    at: stamp,
    decision,
    format: ATTESTATION_AUDIT_FORMAT,
    investigationId,
    keyId: keyId.toLowerCase(),
    lockBroken: lb,
    manifestDigest,
    opId,
    reconciliationRefs: [...reconciliationRefs],
    registryVersion,
    result: 'attested',
    warnings: [...warnings]
  };
}

function assertAuditEventShape(e) {
  assertExactKeys(e, ['at', 'decision', 'format', 'investigationId', 'keyId', 'lockBroken', 'manifestDigest', 'opId', 'reconciliationRefs', 'registryVersion', 'result', 'warnings'], 'audit event');
  if (e.format !== ATTESTATION_AUDIT_FORMAT) fail('ATTEST_INVALID', 'audit event format');
  if (e.result !== 'attested') fail('ATTEST_INVALID', 'audit event result');
  if (typeof e.opId !== 'string' || !OPID_SHAPE.test(e.opId)) fail('ATTEST_INVALID', 'audit event opId');
  assertLockBrokenShape(e.lockBroken);
  assertHex64(e.manifestDigest, 'audit.manifestDigest');
  assertAddress(e.keyId, 'audit.keyId');
  assertMs(e.at, 'audit.at');
}

function shapeInvalidLines(storeRead, store) {
  // Complete JSON-object lines that fail the store's record shape. Our
  // writers only emit builder-validated lines, so these are conclusively
  // not-ours — but unlike foreign tails they sit as complete history and
  // must be explicitly dispositioned, never silently skipped.
  const checks = store === 'attestations' ? [assertAttestationStoreLine]
    : store === 'audit' ? [assertAuditEventShape]
      : [assertAckShape, assertAmendmentShape, assertNoteShape];
  const out = [];
  for (const entry of storeRead.lines) {
    let valid = false;
    for (const check of checks) {
      try {
        check(entry.parsed);
        valid = true;
        break;
      } catch {
        // Try the next shape (journal) or record as invalid.
      }
    }
    if (!valid) out.push(entry);
  }
  return out;
}

function findAttestationMatches(storeRead, manifestDigest, keyId) {
  const out = [];
  for (const line of storeRead.lines) {
    try {
      assertAttestationStoreLine(line.parsed);
    } catch {
      continue;
    }
    const b = line.parsed.attestation.body;
    if (b.manifestDigest === manifestDigest && b.keyId.toLowerCase() === keyId.toLowerCase()) {
      out.push(line);
    }
  }
  return out;
}

function findAuditMatches(storeRead, manifestDigest, keyId) {
  const out = [];
  for (const line of storeRead.lines) {
    try {
      assertAuditEventShape(line.parsed);
    } catch {
      continue;
    }
    if (line.parsed.manifestDigest === manifestDigest && line.parsed.keyId.toLowerCase() === keyId.toLowerCase()) {
      out.push(line);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Journal evaluation: chain + usability + conflicts + amendments.
// An ack is usable iff: complete valid event, unbroken prefix chain
// through it, live original bytes match, ackId uncontested (or
// contest resolved by a valid chained amendment endorsing one copy).
// ---------------------------------------------------------------------------

function evaluateJournal(lines) {
  const entries = normalizeChainLines(lines);
  const chain = verifyJournalChain(entries);
  const byAckId = new Map();
  const amendments = [];
  const notes = [];
  entries.forEach(({ text: line }, index) => {
    const verdict = chain.verdicts[index];
    if (verdict.kind === RECONCILIATION_FORMAT && verdict.usable) {
      let ack = null;
      try {
        const parsed = JSON.parse(line);
        assertAckShape(parsed);
        ack = parsed;
      } catch {
        ack = null;
      }
      if (ack !== null) {
        if (!byAckId.has(ack.ackId)) byAckId.set(ack.ackId, []);
        byAckId.get(ack.ackId).push({ index, ack, line });
      }
    } else if (verdict.kind === RECONCILIATION_AMENDMENT_FORMAT && verdict.usable) {
      try {
        const parsed = JSON.parse(line);
        assertAmendmentShape(parsed);
        amendments.push({ index, amendment: parsed, line });
      } catch {
        // Schema-invalid amendment lines are inert debris for usability.
      }
    } else if (verdict.kind === RECONCILIATION_NOTE_FORMAT && verdict.usable) {
      try {
        assertNoteShape(JSON.parse(line));
        notes.push({ index, line });
      } catch {
        // Schema-invalid note lines are inert debris for usability.
      }
    }
  });
  // Contested IDs: same ackId, non-identical bytes.
  const contested = new Set();
  for (const [id, copies] of byAckId) {
    const first = copies[0].line;
    if (copies.some((c) => c.line !== first)) contested.add(id);
  }
  // Amendments resolve contests by endorsing one record sha256; the
  // latest valid amendment in chain order governs interpretation.
  const endorsed = new Map();
  const sortedAmendments = [...amendments].sort((a, b) => a.index - b.index);
  for (const { amendment } of sortedAmendments) {
    const copies = byAckId.get(amendment.amendsAckId) || [];
    const match = copies.find((c) => sha256Hex(Buffer.from(c.line, 'utf8')) === amendment.endorsedRecordSha256);
    if (match) endorsed.set(amendment.amendsAckId, { amendment, endorsed: match });
  }
  return { chain, byAckId, amendments: sortedAmendments, notes, contested, endorsed };
}

function usableAckFor(journalEval, ackId, { readOriginalBytes }) {
  const copies = journalEval.byAckId.get(ackId) || [];
  if (copies.length === 0) return { usable: false, reason: 'no-acknowledgment' };
  const first = copies[0].line;
  const identical = copies.every((c) => c.line === first);
  if (!identical) {
    if (!journalEval.contested.has(ackId)) return { usable: false, reason: 'conflict' };
    const resolution = journalEval.endorsed.get(ackId);
    if (!resolution) return { usable: false, reason: 'contested-unresolved' };
    return usableAckRecord(resolution.endorsed.ack, readOriginalBytes);
  }
  return usableAckRecord(copies[0].ack, readOriginalBytes);
}

function usableAckRecord(ack, readOriginalBytes) {
  // Live byte re-verification: the acknowledged bytes must still match.
  let current;
  try {
    current = readOriginalBytes(ack.store, ack.offset, ack.length);
  } catch (err) {
    return { usable: false, reason: `original-unreadable: ${err && err.message}` };
  }
  if (current === null) return { usable: false, reason: 'original-changed' };
  if (sha256Hex(current) !== ack.bytesSha256) return { usable: false, reason: 'original-changed' };
  return { usable: true, reason: '', ack };
}

// ---------------------------------------------------------------------------
// Exclusive ceremony lock. One lock covers the store pair (+ journal).
// Holding ⟺ your O_EXCL create succeeded and your token still occupies
// the path (fenced before every append). Fail-fast, no waiting.
// ---------------------------------------------------------------------------

function readLockFile(lockPath) {
  try {
    const raw = fs.readFileSync(lockPath, 'utf8');
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && typeof parsed.token === 'string') {
        return { present: true, parseable: true, holder: parsed, rawLength: raw.length };
      }
      return { present: true, parseable: false, holder: null, rawLength: raw.length };
    } catch {
      return { present: true, parseable: false, holder: null, rawLength: raw.length };
    }
  } catch (err) {
    if (err && err.code === 'ENOENT') return { present: false, parseable: false, holder: null, rawLength: 0 };
    throw err;
  }
}

function processAlive(pid) {
  // Advisory only: EPERM (cannot signal) counts as alive (conservative:
  // unprovable death never authorizes action).
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if (err && err.code === 'ESRCH') return false;
    return true;
  }
}

function acquireCeremonyLock(storeDir, { opId } = {}) {
  const paths = storePaths(storeDir);
  fs.mkdirSync(paths.dir, { recursive: true });
  const token = crypto.randomBytes(16).toString('hex');
  const content = canonicalStringify({
    hostname: os.hostname(),
    opId: opId === undefined ? null : opId,
    pid: process.pid,
    startedAt: Date.now(),
    stores: [paths.attestations, paths.audit, paths.journal],
    token
  });
  let fd;
  try {
    fd = fs.openSync(paths.lock, 'wx', 0o600);
  } catch (err) {
    if (err && (err.code === 'EEXIST' || err.code === 'EACCES' || err.code === 'EPERM')) {
      const info = readLockFile(paths.lock);
      const held = new AttestationError('ATTEST_LOCK_HELD', 'ceremony lock held by another process');
      held.holder = info.holder;
      held.lockPresent = info.present;
      throw held;
    }
    throw err;
  }
  try {
    fs.writeSync(fd, `${content}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fsyncDir(paths.dir);
  } catch {
    // Best-effort: the lock content itself is synced; directory durability
    // narrows (but cannot portably eliminate) the dual-holder window.
  }
  return { path: paths.lock, token, opId: opId === undefined ? null : opId };
}

function assertLockHeld(lock) {
  // Fence: call before every append. Any mismatch aborts without writing.
  if (!lock || typeof lock.path !== 'string' || typeof lock.token !== 'string') {
    fail('ATTEST_LOCK_LOST', 'no lock held');
  }
  const info = readLockFile(lock.path);
  if (!info.present || !info.parseable || info.holder.token !== lock.token) {
    fail('ATTEST_LOCK_LOST', 'lock token mismatch: lock lost during hold');
  }
  return true;
}

function releaseCeremonyLock(lock) {
  // Releases only a lock verifiably ours. Never deletes on mismatch.
  // Returns status (never throws for mismatch; IO errors propagate).
  if (!lock || typeof lock.path !== 'string' || typeof lock.token !== 'string') {
    return { released: false, reason: 'no-lock-held' };
  }
  const info = readLockFile(lock.path);
  if (!info.present) return { released: false, reason: 'lock-absent' };
  if (!info.parseable || info.holder.token !== lock.token) {
    return { released: false, reason: 'token-mismatch-refusing-delete' };
  }
  fs.unlinkSync(lock.path);
  const again = readLockFile(lock.path);
  if (again.present) return { released: false, reason: 'delete-unconfirmed' };
  return { released: true, reason: '' };
}

function executionGrade(manifest) {
  // Receipt-backed: a verified receipt exists (EXECUTED, EFFECTS_DIVERGED,
  // or reverted FAILED with receipt status). Unverified: hash claimed
  // without receipt evidence. None: no transaction hash at all.
  const tx = (manifest && manifest.transaction) || {};
  if (tx.transactionHash === null || tx.transactionHash === undefined) return 'none';
  if (tx.receiptStatus !== null && tx.receiptStatus !== undefined) return 'receipt-backed';
  return 'unverified';
}

function modelEvidenceComplete(manifest) {
  const muse = manifest && manifest.modelCalls && manifest.modelCalls.museSpark;
  const sam = manifest && manifest.modelCalls && manifest.modelCalls.sam;
  const museOk = muse && !['NOT_INVOKED', 'INVOKED'].includes(muse.contribution);
  const samOk = sam && !['NOT_INVOKED', 'MOCK', 'FAILED', 'TIMEOUT'].includes(sam.contribution);
  return { complete: Boolean(museOk && samOk), muse: muse ? muse.contribution : null, sam: sam ? sam.contribution : null };
}

function classifyPackageCase({ manifest, superseded }) {
  // Primary letter by decision/execution state (determines action);
  // evidence completeness rides along as an explicit flag + warning.
  const grade = executionGrade(manifest);
  const decision = manifest.decision || {};
  const resolved = decision.agent || decision.evaluation || null;
  const evidence = modelEvidenceComplete(manifest);
  let letter = 'A';
  const notes = [];
  if (superseded) {
    letter = 'G';
    notes.push('superseded manifest: not the latest for this investigation');
  } else if (grade === 'unverified') {
    letter = 'F';
    notes.push('execution claimed without receipt evidence');
  } else if (resolved === 'BLOCK' || resolved === 'REVIEW') {
    letter = 'E';
    notes.push('blocked or unreleased review: no transaction expected');
  } else if (resolved === 'ALLOW' && grade === 'none') {
    letter = 'C';
    notes.push('pre-execution manifest: re-attestation due after execution');
  } else if (grade === 'receipt-backed') {
    letter = 'D';
  }
  if (!evidence.complete) notes.push(`incomplete model evidence (muse=${evidence.muse}, sam=${evidence.sam})`);
  let action = 'normal';
  if (letter === 'G') action = 'refuse';
  else if (letter === 'F') action = 'extra-confirm';
  return { case: letter, incompleteEvidence: !evidence.complete, action, notes, executionGrade: grade, decision: resolved };
}

function buildCeremonyPreview({ pkg, manifestDigest, keyAddress, keyState, registryVersion, caseInfo, manifestStoreFound, warnings }) {
  const m = pkg.manifest;
  const pp = pkg.publicProjection || {};
  const ms = m.modelCalls.museSpark;
  const sm = m.modelCalls.sam;
  return {
    investigationId: m.investigationId,
    manifestDigest,
    traceId: m.traceId,
    requestId: m.requestId,
    museSpark: {
      status: ms.status,
      contribution: ms.contribution,
      observedModel: ms.observedModel,
      modelVerdict: ms.modelVerdict,
      verdictAccepted: ms.verdictAccepted
    },
    sam: {
      aggregateStatus: sm.aggregateStatus,
      contribution: sm.contribution,
      detectedCount: sm.detectedCount,
      regionsInPrompt: sm.regionsInPrompt,
      refsValidated: sm.refsValidated,
      prompts: sm.prompts.map((p) => ({ index: p.index, prompt: p.prompt, status: p.status, detections: p.detections }))
    },
    decision: { ...m.decision },
    safeguards: Array.isArray(pp.verdictSafeguards) ? pp.verdictSafeguards.map((s) => s.trigger) : [],
    evidence: { digest: m.evidence.digest, publicDigest: m.evidence.publicDigest },
    transaction: { ...m.transaction, grade: caseInfo.executionGrade },
    key: { address: keyAddress, state: keyState },
    registryVersion,
    manifestStore: manifestStoreFound ? 'found' : 'missing',
    case: caseInfo.case,
    action: caseInfo.action,
    incompleteEvidence: caseInfo.incompleteEvidence,
    warnings: [...warnings, ...caseInfo.notes]
  };
}

function attachAttestation(pkg, attestation) {
  // Returns a NEW package object with the attestation section filled.
  // Never mutates inputs. Digest linkage re-verified, not trusted.
  if (!pkg || typeof pkg !== 'object' || !pkg.manifest) fail('ATTEST_INVALID', 'attachAttestation: package with manifest required');
  assertValidInput(attestation, 'attestation');
  assertAttestationShape(attestation);
  const recomputed = sha256Hex(canonicalStringify(pkg.manifest));
  if (recomputed !== attestation.body.manifestDigest) {
    fail('ATTEST_MISMATCH', 'attestation does not bind this manifest');
  }
  return { ...pkg, packageVersion: 'assertara-verify-2', attestation };
}

function breakStaleLock(storeDir, { maxAgeMs, now } = {}) {
  // Atomic stale-claim via rename-quarantine. Only one process can win
  // the rename; losers abort. Never unlinks: the stale lock is moved to
  // quarantine with content intact, then the winner acquires fresh.
  const paths = storePaths(storeDir);
  const at = now === undefined ? Date.now() : now;
  const threshold = maxAgeMs === undefined ? DEFAULT_LOCK_STALE_MS : maxAgeMs;
  const before = readLockFile(paths.lock);
  if (!before.present) return { broken: false, reason: 'lock-absent' };
  if (!before.parseable) {
    fail('ATTEST_LOCK_UNREADABLE', 'lock file present but unparseable: manual inspection required');
  }
  const holder = before.holder;
  const age = typeof holder.startedAt === 'number' ? at - holder.startedAt : null;
  const alive = processAlive(holder.pid);
  const stale = age !== null && age > threshold && alive === false;
  if (!stale) {
    fail('ATTEST_LOCK_LIVE', `lock not demonstrably stale (ageMs=${age}, alive=${alive}): refusing break`);
  }
  fs.mkdirSync(paths.quarantine, { recursive: true });
  const qname = `${holder.startedAt || 'unknown'}-${holder.pid || 'unknown'}-${String(holder.token || 'notoken').slice(0, 8)}.lock`;
  const qpath = path.join(paths.quarantine, qname);
  let beforeBytes;
  try {
    beforeBytes = fs.readFileSync(paths.lock);
  } catch (err) {
    if (err && err.code === 'ENOENT') fail('ATTEST_LOCK_CHANGED', 'lock changed during break: aborting');
    throw err;
  }
  try {
    fs.renameSync(paths.lock, qpath);
  } catch (err) {
    if (err && err.code === 'ENOENT') fail('ATTEST_LOCK_CHANGED', 'lock changed during break: aborting');
    throw err;
  }
  let afterBytes;
  try {
    afterBytes = fs.readFileSync(qpath);
  } catch (err) {
    if (err && err.code === 'ENOENT') fail('ATTEST_LOCK_CHANGED', 'quarantine changed during break: aborting');
    throw err;
  }
  if (!afterBytes.equals(beforeBytes)) {
    fail('ATTEST_LOCK_CHANGED', 'quarantined bytes differ from inspected lock: aborting');
  }
  return { broken: true, reason: '', quarantined: qpath, previous: { pid: holder.pid, hostname: holder.hostname, startedAt: holder.startedAt, ageMs: age, opId: holder.opId || null } };
}

// ---------------------------------------------------------------------------
// Torn-fragment classifier. Answers whether bytes could be a prefix of a
// legitimate store line. Sound by construction (a legitimate interrupted
// write is never FOREIGN — proven by the truncation property test);
// incomplete by design (unprovable bytes stay AMBIGUOUS, the safe side).
// ---------------------------------------------------------------------------

function isIncompleteCharSuffix(tail) {
  if (tail.length === 0 || tail.length > 3) return false;
  const b0 = tail[0];
  let expected = 0;
  if (b0 >= 0xc2 && b0 <= 0xdf) expected = 2;
  else if (b0 >= 0xe0 && b0 <= 0xef) expected = 3;
  else if (b0 >= 0xf0 && b0 <= 0xf4) expected = 4;
  else return false;
  if (tail.length >= expected) return false;
  for (let i = 1; i < tail.length; i += 1) {
    if (tail[i] < 0x80 || tail[i] > 0xbf) return false;
  }
  return true;
}

function splitDecodablePrefix(bytes) {
  // Smallest strip k (0..3) leaving valid UTF-8 with a proper incomplete
  // suffix, or null when no legitimate truncation explains the bytes.
  const fatal = new TextDecoder('utf-8', { fatal: true });
  for (let k = 0; k <= 3; k += 1) {
    const head = bytes.subarray(0, bytes.length - k);
    let text;
    try {
      text = fatal.decode(head);
    } catch {
      continue;
    }
    if (k === 0) return { text, stripped: 0 };
    if (isIncompleteCharSuffix(bytes.subarray(bytes.length - k))) return { text, stripped: k };
  }
  return null;
}

// Schema DSL for legitimate line grammars. Canonical key order is fixed,
// so every legitimate line matches exactly one template walk.
const GS = {
  lit: (s) => ({ t: 'lit', s }),
  digits: () => ({ t: 'digits' }),
  qfree: () => ({ t: 'qfree' }),
  qfixed: (v) => ({ t: 'qfixed', v }),
  qhex: (prefix, n) => ({ t: 'qhex', prefix, n }),
  nul: () => ({ t: 'null' }),
  arr: (item) => ({ t: 'arr', item }),
  obj: (keys) => ({ t: 'obj', keys }),
  or: (...alts) => ({ t: 'or', alts })
};
const HEXCHARS = '0123456789abcdefABCDEF';

function matchNode(node, text, pos) {
  // Returns {status:'ok'|'partial', pos} or null on definite mismatch.
  // Exhaustion mid-token is always 'partial' (legitimate so far).
  const atEnd = (p) => p >= text.length;
  switch (node.t) {
    case 'lit': {
      for (let i = 0; i < node.s.length; i += 1) {
        if (atEnd(pos + i)) return { status: 'partial', pos: text.length };
        if (text[pos + i] !== node.s[i]) return null;
      }
      return { status: 'ok', pos: pos + node.s.length };
    }
    case 'digits': {
      if (atEnd(pos)) return { status: 'partial', pos };
      if (text[pos] < '0' || text[pos] > '9') return null;
      let p = pos;
      const leadingZero = text[p] === '0';
      while (p < text.length && text[p] >= '0' && text[p] <= '9') p += 1;
      if (leadingZero && p - pos > 1) return null; // JSON never emits leading zeros.
      if (p >= text.length) return { status: 'partial', pos: p };
      return { status: 'ok', pos: p };
    }
    case 'qfree': {
      if (atEnd(pos)) return { status: 'partial', pos };
      if (text[pos] !== '"') return null;
      let p = pos + 1;
      while (p < text.length) {
        const c = text[p];
        if (c === '\\') {
          if (p + 1 >= text.length) return { status: 'partial', pos: text.length };
          const e = text[p + 1];
          if (e === 'u') {
            for (let i = 0; i < 4; i += 1) {
              if (p + 2 + i >= text.length) return { status: 'partial', pos: text.length };
              if (!HEXCHARS.includes(text[p + 2 + i])) return null;
            }
            p += 6;
          } else if ('"\\/bfnrt'.includes(e)) {
            p += 2;
          } else {
            return null; // JSON.stringify never emits this escape.
          }
          continue;
        }
        if (c === '"') return { status: 'ok', pos: p + 1 };
        if (c < ' ') return null; // Raw controls never emitted.
        p += 1;
      }
      return { status: 'partial', pos: p };
    }
    case 'qfixed': {
      const open = matchNode(GS.lit('"'), text, pos);
      if (open === null || open.status === 'partial') return open;
      const body = matchNode(GS.lit(node.v), text, open.pos);
      if (body === null || body.status === 'partial') return body;
      return matchNode(GS.lit('"'), text, body.pos);
    }
    case 'qhex': {
      const open = matchNode(GS.lit('"'), text, pos);
      if (open === null || open.status === 'partial') return open;
      const pre = matchNode(GS.lit(node.prefix), text, open.pos);
      if (pre === null || pre.status === 'partial') return pre;
      let p = pre.pos;
      let count = 0;
      while (count < node.n) {
        if (p >= text.length) return { status: 'partial', pos: p };
        if (!HEXCHARS.includes(text[p])) return null;
        p += 1;
        count += 1;
      }
      if (p < text.length && HEXCHARS.includes(text[p])) return null; // Overlong.
      return matchNode(GS.lit('"'), text, p);
    }
    case 'null':
      return matchNode(GS.lit('null'), text, pos);
    case 'arr': {
      const open = matchNode(GS.lit('['), text, pos);
      if (open === null || open.status === 'partial') return open;
      let p = open.pos;
      if (p < text.length && text[p] === ']') return { status: 'ok', pos: p + 1 };
      if (p >= text.length) return { status: 'partial', pos: p };
      for (;;) {
        const item = matchNode(node.item, text, p);
        if (item === null) return null;
        if (item.status === 'partial') return item;
        p = item.pos;
        if (p >= text.length) return { status: 'partial', pos: p };
        if (text[p] === ',') {
          p += 1;
          if (p >= text.length) return { status: 'partial', pos: p };
          continue;
        }
        if (text[p] === ']') return { status: 'ok', pos: p + 1 };
        return null;
      }
    }
    case 'obj': {
      const open = matchNode(GS.lit('{'), text, pos);
      if (open === null || open.status === 'partial') return open;
      let p = open.pos;
      for (let i = 0; i < node.keys.length; i += 1) {
        const [name, schema] = node.keys[i];
        const key = matchNode(GS.lit(`"${name}":`), text, p);
        if (key === null || key.status === 'partial') return key;
        const val = matchNode(schema, text, key.pos);
        if (val === null || val.status === 'partial') return val;
        p = val.pos;
        if (i < node.keys.length - 1) {
          if (p >= text.length) return { status: 'partial', pos: p };
          if (text[p] !== ',') return null;
          p += 1;
        }
      }
      if (p >= text.length) return { status: 'partial', pos: p };
      if (text[p] !== '}') return null;
      return { status: 'ok', pos: p + 1 };
    }
    case 'or': {
      let sawPartial = false;
      for (const alt of node.alts) {
        const r = matchNode(alt, text, pos);
        if (r !== null && r.status === 'ok') return r;
        if (r !== null && r.status === 'partial') sawPartial = true;
      }
      if (sawPartial) return { status: 'partial', pos: text.length };
      return null;
    }
    default:
      fail('ATTEST_INVALID', `grammar: unknown node ${node.t}`);
      return null;
  }
}

const qaddr = () => GS.qhex('0x', 40);
const qhex64 = () => GS.qhex('', 64);
const qopid = () => GS.qhex('attop_', 64);
const qackid = () => GS.qhex('attrec_', 64);
const qamdid = () => GS.qhex('attamd_', 64);
const qnoteid = () => GS.qhex('attnote_', 64);

const SCHEMA_ATTESTATION_BODY = GS.obj([
  ['attestationChainId', GS.digits()],
  ['format', GS.qfixed(ATTESTATION_BODY_FORMAT)],
  ['investigationId', GS.qfree()],
  ['issuedAt', GS.digits()],
  ['keyId', qaddr()],
  ['manifestDigest', qhex64()],
  ['manifestSchemaVersion', GS.qfixed(ATTESTATION_SCHEMA_VERSION)],
  ['purpose', GS.qfixed(ATTESTATION_PURPOSE)],
  ['requestId', GS.or(GS.qfree(), GS.nul())],
  ['traceId', GS.qfree()]
]);

const SCHEMA_ATTESTATION = GS.obj([
  ['algorithm', GS.qfixed(ATTESTATION_ALGORITHM)],
  ['authority', qaddr()],
  ['body', SCHEMA_ATTESTATION_BODY],
  ['format', GS.qfixed(ATTESTATION_FORMAT)],
  ['signature', GS.qhex('0x', 130)]
]);

const SCHEMA_STORE_LINE = GS.obj([
  ['attestation', SCHEMA_ATTESTATION],
  ['format', GS.qfixed(ATTESTATION_STORE_FORMAT)],
  ['opId', qopid()],
  ['recordedAt', GS.digits()]
]);

const SCHEMA_LOCK_BROKEN = GS.obj([
  ['prevAge', GS.digits()],
  ['prevPid', GS.digits()],
  ['quarantined', GS.qfree()]
]);

const SCHEMA_AUDIT_LINE = GS.obj([
  ['at', GS.digits()],
  ['decision', GS.qfree()],
  ['format', GS.qfixed(ATTESTATION_AUDIT_FORMAT)],
  ['investigationId', GS.qfree()],
  ['keyId', qaddr()],
  ['lockBroken', GS.or(SCHEMA_LOCK_BROKEN, GS.nul())],
  ['manifestDigest', qhex64()],
  ['opId', qopid()],
  ['reconciliationRefs', GS.arr(GS.qfree())],
  ['registryVersion', GS.digits()],
  ['result', GS.qfixed('attested')],
  ['warnings', GS.arr(GS.qfree())]
]);

const SCHEMA_ACK_LINE = GS.obj([
  ['ackId', qackid()],
  ['at', GS.digits()],
  ['bytesSha256', qhex64()],
  ['chainPrev', qhex64()],
  ['classification', GS.or(GS.qfixed('foreign-debris'), GS.qfixed('ambiguous-debris'), GS.qfixed('blank-line'), GS.qfixed('torn-fragment'))],
  ['format', GS.qfixed(RECONCILIATION_FORMAT)],
  ['keyId', GS.or(qaddr(), GS.nul())],
  ['length', GS.digits()],
  ['manifestDigest', GS.or(qhex64(), GS.nul())],
  ['offset', GS.digits()],
  ['opId', GS.or(qopid(), GS.nul())],
  ['operator', GS.qfree()],
  ['rationale', GS.qfree()],
  ['store', GS.or(GS.qfixed('attestations'), GS.qfixed('audit'), GS.qfixed('journal'))]
]);

const SCHEMA_AMENDMENT_LINE = GS.obj([
  ['amendmentId', qamdid()],
  ['amendsAckId', qackid()],
  ['at', GS.digits()],
  ['chainPrev', qhex64()],
  ['endorsedRecordSha256', qhex64()],
  ['format', GS.qfixed(RECONCILIATION_AMENDMENT_FORMAT)],
  ['newClassification', GS.or(GS.qfixed('foreign-debris'), GS.qfixed('ambiguous-debris'), GS.qfixed('blank-line'), GS.qfixed('torn-fragment'), GS.nul())],
  ['newRationale', GS.qfree()],
  ['operator', GS.qfree()]
]);

const SCHEMA_NOTE_LINE = GS.obj([
  ['at', GS.digits()],
  ['chainPrev', qhex64()],
  ['format', GS.qfixed(RECONCILIATION_NOTE_FORMAT)],
  ['noteId', qnoteid()],
  ['operator', GS.qfree()],
  ['refAckId', GS.or(qackid(), GS.nul())],
  ['text', GS.qfree()]
]);

const STORE_GRAMMARS = {
  attestations: SCHEMA_STORE_LINE,
  audit: SCHEMA_AUDIT_LINE,
  journal: GS.or(SCHEMA_ACK_LINE, SCHEMA_AMENDMENT_LINE, SCHEMA_NOTE_LINE)
};

function classifyFragment(storeType, fragmentBytes) {
  // Verdicts: FOREIGN (bytes prove non-legitimate origin) or AMBIGUOUS
  // (could be an interrupted legitimate write — reconcile, never assume).
  if (!STORE_GRAMMARS[storeType]) fail('ATTEST_INVALID', `classifyFragment: unknown store ${storeType}`);
  if (!Buffer.isBuffer(fragmentBytes)) fail('ATTEST_INVALID', 'classifyFragment: Buffer required');
  for (let i = 0; i < fragmentBytes.length; i += 1) {
    if (fragmentBytes[i] === 10) fail('ATTEST_INVALID', 'classifyFragment: fragment must not contain newline');
    if (fragmentBytes[i] < 32) return { verdict: 'FOREIGN', reason: 'control-byte' };
  }
  const split = splitDecodablePrefix(fragmentBytes);
  if (split === null) return { verdict: 'FOREIGN', reason: 'invalid-utf8' };
  const walked = matchNode(STORE_GRAMMARS[storeType], split.text, 0);
  if (walked === null) return { verdict: 'FOREIGN', reason: 'not-a-line-prefix' };
  if (walked.status === 'ok' && (walked.pos !== split.text.length || split.stripped > 0)) {
    // Bytes after a complete line with no newline: our writer emits
    // line+\n atomically per record, so this cannot be our output.
    return { verdict: 'FOREIGN', reason: 'bytes-after-complete-line' };
  }
  return { verdict: 'AMBIGUOUS', reason: walked.status === 'ok' ? 'complete-valid-line' : 'legitimate-prefix' };
}

// ---------------------------------------------------------------------------
// Integrity gate + acknowledgment processing. The gate blocks on ANY
// unacknowledged malformed/blank/shape-invalid record or ambiguous tail
// in the attestation/audit stores — and on ANY complete malformed,
// blank, or shape-invalid record in the reconciliation journal itself.
// Journal debris is gate-blocking (fail-closed): ceremonies and journal
// mutations refuse until every debris item has usable acknowledgment
// coverage. Acknowledgments pin the exact original bytes (offset,
// length, SHA-256) and record disposition only — they never promote
// debris into trusted records. A journal chain break blocks new
// ceremonies and journal mutations permanently for that store (reads
// stay available for forensics). Incomplete unterminated crash tails
// are never gated: they repair by pure delimiter append on the next
// journal write and are listed for inspection in the meantime.
// ---------------------------------------------------------------------------

function mergedChainEntries(storeRead) {
  const all = [...storeRead.lines, ...storeRead.malformed, ...storeRead.blanks];
  all.sort((a, b) => a.index - b.index);
  return all.map((e) => ({ bytes: e.bytes, text: e.text }));
}

function originalBytesAt(storeDir, store, offset, length) {
  const paths = storePaths(storeDir);
  const file = store === 'attestations' ? paths.attestations
    : store === 'audit' ? paths.audit
      : store === 'journal' ? paths.journal : null;
  if (file === null) fail('ATTEST_INVALID', `ack.store: unknown ${store}`);
  let raw;
  try {
    raw = fs.readFileSync(file);
  } catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0) return null;
  if (offset + length > raw.length) return null;
  return raw.subarray(offset, offset + length);
}

function gateBlockers({ storeDir, attRead, auditRead, journalRead, journalEval }) {
  const readOriginal = (store, offset, length) => originalBytesAt(storeDir, store, offset, length);
  const blockers = [];
  const notes = [];
  const considerEntry = (store, kind, entry, suggestedClassification) => {
    const ackId = acknowledgmentId({ store, offset: entry.offset, length: entry.length, bytesSha256: entry.sha256 });
    const use = usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
    if (use.usable) {
      notes.push({ store, kind, offset: entry.offset, acknowledged: true, ackId });
    } else {
      blockers.push({
        store, kind, offset: entry.offset, length: entry.length,
        bytesSha256: entry.sha256, ackId, ackState: use.reason,
        suggestedClassification
      });
    }
  };
  const consider = (store, read) => {
    for (const entry of read.malformed) considerEntry(store, 'malformed', entry, 'foreign-debris');
    // Every blank line is unexplained corruption: the writer never
    // emits one (empty file = valid empty store; anything else with a
    // blank line needs acknowledgment). Zero-length included.
    for (const entry of read.blanks) considerEntry(store, 'blank', entry, 'blank-line');
    // Complete JSON that fails the store's record shape: our writers
    // only emit builder-validated lines, so these are conclusively
    // not-ours — dispositioned explicitly, never silently skipped.
    for (const entry of shapeInvalidLines(read, store)) considerEntry(store, 'shape-invalid', entry, 'foreign-debris');
    if (store === 'journal') return; // Journal tails auto-repair; never gated.
    if (read.tail !== null) {
      const verdict = classifyFragment(store, read.tail.bytes);
      if (verdict.verdict === 'FOREIGN') {
        notes.push({ store, kind: 'tail', offset: read.tail.offset, verdict, acknowledged: false, autoProceed: true });
      } else {
        const ackId = acknowledgmentId({ store, offset: read.tail.offset, length: read.tail.length, bytesSha256: read.tail.sha256 });
        const use = usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
        if (use.usable) {
          notes.push({ store, kind: 'tail', offset: read.tail.offset, verdict, acknowledged: true, ackId });
        } else {
          blockers.push({
            store, kind: 'tail', offset: read.tail.offset, length: read.tail.length,
            bytesSha256: read.tail.sha256, ackId, ackState: use.reason, verdict,
            suggestedClassification: 'torn-fragment'
          });
        }
      }
    }
  };
  consider('attestations', attRead);
  consider('audit', auditRead);
  if (journalRead) consider('journal', journalRead);
  return { blockers, notes };
}

function throwPhase(phase, code, message, details) {
  const err = new AttestationError(code, message);
  err.phase = phase;
  err.details = details === undefined ? null : details;
  throw err;
}

function locateDebris(reads, store, offset, length, bytesSha256) {
  // Re-locate the exact debris bytes under the lock. Returns its kind
  // or null when no such bytes exist (stale request — never ack blind).
  const read = store === 'attestations' ? reads.attRead
    : store === 'audit' ? reads.auditRead
      : store === 'journal' ? reads.journalRead : null;
  if (!read) return null;
  const kinds = [
    ['malformed', read.malformed],
    ['blank', read.blanks],
    ['shape-invalid', shapeInvalidLines(read, store)]
  ];
  for (const [kind, entries] of kinds) {
    for (const entry of entries) {
      if (entry.offset === offset && entry.length === length && entry.sha256 === bytesSha256) {
        return kind;
      }
    }
  }
  if (store !== 'journal' && read.tail !== null && read.tail.offset === offset && read.tail.length === length && read.tail.sha256 === bytesSha256) {
    return 'tail';
  }
  return null;
}

function processAcknowledgments({ lock, paths, storeDir, requests, now, opId }) {
  // Records operator acknowledgments for gate blockers. Lock must be held.
  // Re-reads everything under the lock; verifies debris identity,
  // classification honesty, and idempotent reuse before appending.
  const recorded = [];
  const preJournal = evaluateJournal(mergedChainEntries(readStoreFile(paths.journal)));
  if (preJournal.chain.firstBreak !== null) {
    throwPhase('acknowledgment', 'ATTEST_JOURNAL_BROKEN', `journal chain broken at line ${preJournal.chain.firstBreak}: no acknowledgment can complete; inspect read-only and see docs`, { firstBreak: preJournal.chain.firstBreak });
  }
  for (const req of requests) {
    assertValidInput(req, 'acknowledgment request');
    assertEnum(req.store, ['attestations', 'audit', 'journal'], 'ack request.store');
    if (!Number.isSafeInteger(req.offset) || req.offset < 0) fail('ATTEST_INVALID', 'ack request.offset');
    if (!Number.isSafeInteger(req.length) || req.length < 0) fail('ATTEST_INVALID', 'ack request.length');
    assertHex64(req.bytesSha256, 'ack request.bytesSha256');
    assertEnum(req.classification, ['foreign-debris', 'ambiguous-debris', 'blank-line', 'torn-fragment'], 'ack request.classification');
    if (typeof req.rationale !== 'string' || req.rationale.length === 0) fail('ATTEST_INVALID', 'ack request.rationale required');
    if (typeof req.operator !== 'string' || req.operator.length === 0) fail('ATTEST_INVALID', 'ack request.operator required');

    const attRead = readStoreFile(paths.attestations);
    const auditRead = readStoreFile(paths.audit);
    const journalRead = readStoreFile(paths.journal);
    const kind = locateDebris({ attRead, auditRead, journalRead }, req.store, req.offset, req.length, req.bytesSha256);
    if (kind === null) {
      if (req.store === 'journal' && journalRead.tail !== null
        && journalRead.tail.offset === req.offset && journalRead.tail.length === req.length
        && journalRead.tail.sha256 === req.bytesSha256) {
        throwPhase('acknowledgment', 'ATTEST_ACK_UNNEEDED', 'journal tails repair automatically: no acknowledgment needed', null);
      }
      throwPhase('acknowledgment', 'ATTEST_ACK_STALE', 'acknowledged bytes not found: store changed or wrong offset', { request: { store: req.store, offset: req.offset, length: req.length } });
    }
    if (kind === 'blank' && req.classification !== 'blank-line') {
      throwPhase('acknowledgment', 'ATTEST_ACK_MISMATCH', 'blank record must be acknowledged as blank-line', null);
    }
    if ((kind === 'malformed' || kind === 'shape-invalid') && req.classification !== 'foreign-debris') {
      throwPhase('acknowledgment', 'ATTEST_ACK_MISMATCH', 'complete malformed or shape-invalid record must be acknowledged as foreign-debris', null);
    }
    if (kind === 'tail') {
      const read = req.store === 'attestations' ? attRead : auditRead;
      const verdict = classifyFragment(req.store, read.tail.bytes);
      if (verdict.verdict === 'FOREIGN') {
        throwPhase('acknowledgment', 'ATTEST_ACK_UNNEEDED', 'tail is conclusively foreign: no acknowledgment needed', { verdict });
      }
      if (req.classification !== 'torn-fragment' && req.classification !== 'ambiguous-debris') {
        throwPhase('acknowledgment', 'ATTEST_ACK_MISMATCH', 'ambiguous tail must be acknowledged as torn-fragment or ambiguous-debris', null);
      }
    }

    const ackId = acknowledgmentId({ store: req.store, offset: req.offset, length: req.length, bytesSha256: req.bytesSha256 });
    // Journal read + torn-tail delimiter repair (pure append, no rewrite).
    let ackJournalRead = readStoreFile(paths.journal);
    if (ackJournalRead.tail !== null) {
      assertLockHeld(lock);
      appendDelimiterIfNeeded(paths.journal);
      ackJournalRead = readStoreFile(paths.journal);
    }
    let journalEval = evaluateJournal(mergedChainEntries(ackJournalRead));
    const readOriginal = (store, offset, length) => originalBytesAt(storeDir, store, offset, length);
    const existing = usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
    if (existing.usable) {
      const prior = existing.ack;
      const same = prior.classification === req.classification
        && prior.rationale === req.rationale
        && prior.operator === req.operator
        && (prior.manifestDigest || null) === (req.manifestDigest || null)
        && (prior.keyId || null) === (req.keyId ? String(req.keyId).toLowerCase() : null)
        && (prior.opId || null) === (req.opId || opId || null);
      if (!same) {
        throwPhase('acknowledgment', 'ATTEST_ACK_CONFLICT', 'same acknowledgment id with different substantive content: amend instead of re-acknowledging', { ackId });
      }
      recorded.push({ ackId, appended: false });
      continue;
    }
    if (journalEval.contested.has(ackId)) {
      throwPhase('acknowledgment', 'ATTEST_ACK_CONFLICT', 'acknowledgment id is contested: resolve via amendment first', { ackId });
    }
    assertLockHeld(lock);
    const ack = buildAcknowledgment({
      store: req.store,
      offset: req.offset,
      length: req.length,
      bytesSha256: req.bytesSha256,
      classification: req.classification,
      rationale: req.rationale,
      operator: req.operator,
      manifestDigest: req.manifestDigest === undefined ? null : req.manifestDigest,
      keyId: req.keyId === undefined ? null : req.keyId,
      opId: req.opId === undefined ? (opId === undefined ? null : opId) : req.opId,
      at: now,
      chainPrev: journalEval.chain.tipState
    });
    durableAppend(paths.journal, canonicalStringify(ack), {});
    // Post-write verification: the ack must now be usable.
    ackJournalRead = readStoreFile(paths.journal);
    journalEval = evaluateJournal(mergedChainEntries(ackJournalRead));
    const after = usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
    if (!after.usable) {
      throwPhase('acknowledgment', 'ATTEST_PERSIST_FAILED', 'acknowledgment not usable after append', { ackId, reason: after.reason });
    }
    recorded.push({ ackId, appended: true });
  }
  return recorded;
}

// ---------------------------------------------------------------------------
// The ceremony. attestPackage runs the full lifecycle: validate →
// expect-digest → lock → gate → registry/key → continuity → preview →
// (confirm) → adopt-or-sign → persist → audit → verify → unlock.
// Every outcome — success, preview, or refusal — reports the exact
// lifecycle phase reached. attested:true ONLY after verified
// persistence of both the attestation and its audit event.
// ---------------------------------------------------------------------------

function normalizeLockBrokenOpt(v) {
  if (v === null || v === undefined) return null;
  if (!v || typeof v !== 'object') fail('ATTEST_INVALID', 'lockBroken: object or null required');
  const prev = v.previous && typeof v.previous === 'object' ? v.previous : {};
  const prevAge = Number.isSafeInteger(prev.ageMs) && prev.ageMs >= 0 ? prev.ageMs : 0;
  const prevPid = Number.isSafeInteger(prev.pid) && prev.pid >= 0 ? prev.pid : 0;
  const quarantined = typeof v.quarantined === 'string' ? v.quarantined : '';
  return { prevAge, prevPid, quarantined };
}

async function adoptIdentityRecords({ attRead, auditRead, manifestDigest, keyId, manifest }) {
  // Returns {attestation, attestationAdopted, auditAdopted}. Throws
  // ATTEST_CONFLICT on ambiguous history for this identity.
  const attMatches = findAttestationMatches(attRead, manifestDigest, keyId);
  let attestation = null;
  let attestationAdopted = false;
  if (attMatches.length > 0) {
    const validSigs = [];
    for (const m of attMatches) {
      const candidate = m.parsed.attestation;
      let recovered = null;
      try {
        recovered = await recoverAttestationAddress(candidate);
      } catch {
        recovered = null;
      }
      const ok = recovered !== null
        && recovered === candidate.authority.toLowerCase()
        && recovered === candidate.body.keyId.toLowerCase();
      if (!ok) {
        throwPhase('conflict', 'ATTEST_CONFLICT', 'identity has a stored attestation with an invalid signature: manual reconciliation required', { manifestDigest, keyId });
      }
      if (candidate.body.investigationId !== manifest.investigationId
        || candidate.body.traceId !== manifest.traceId
        || candidate.body.requestId !== (manifest.requestId === undefined ? null : manifest.requestId)) {
        throwPhase('conflict', 'ATTEST_CONFLICT', 'stored attestation binds different investigation ids: manual reconciliation required', { manifestDigest, keyId });
      }
      validSigs.push(canonicalStringify(m.parsed));
    }
    const distinct = [...new Set(validSigs)];
    if (distinct.length > 1) {
      throwPhase('conflict', 'ATTEST_CONFLICT', 'identity has multiple distinct valid attestations: manual reconciliation required', { manifestDigest, keyId });
    }
    attestation = attMatches[0].parsed.attestation;
    attestationAdopted = true;
  }
  const auditMatches = findAuditMatches(auditRead, manifestDigest, keyId);
  let auditAdopted = false;
  if (auditMatches.length > 0) {
    const distinct = new Set(auditMatches.map((m) => canonicalStringify(m.parsed)));
    if (distinct.size > 1) {
      throwPhase('conflict', 'ATTEST_CONFLICT', 'identity has multiple distinct audit events: manual reconciliation required', { manifestDigest, keyId });
    }
    auditAdopted = true;
  }
  return { attestation, attestationAdopted, auditAdopted };
}

// ---------------------------------------------------------------------------
// Manifest continuity (M5). Guards the manifest-swap TOCTOU: the exact
// reviewed manifest must still exist, its investigation must still be
// listable, and — after the C1 baseline — the latest manifest must not
// have changed. Unknowns fail closed (a prior `latest.ok === false`
// silently proceeded as "not superseded"; it now aborts). Mid-ceremony
// changes abort UNCONDITIONALLY: override flags are never consulted
// past C1. Finder injection (`o.manifestFinders`) keeps the checkpoints
// deterministic under test.
//
// Residual window (documented honestly): no shared manifest-store lock
// exists, so a manifest could land between the last recheck (C3a/C3b)
// and the store append. The window cannot cause a FALSE attestation —
// the signed bytes remain digest-bound to the reviewed manifest — and
// a supersession inside it is semantically equivalent to attesting
// immediately before a legitimate supersession. saveManifest currently
// has zero production callers, so the window is theoretical.
// ---------------------------------------------------------------------------

function checkManifestContinuity({ manifestDigest, investigationId, manifestStore, finders, checkpoint, baseline }) {
  const byDigest = (finders && finders.byDigest) || findManifestByDigest;
  const byInvestigation = (finders && finders.byInvestigation) || findManifestByInvestigation;
  let storeHit;
  try {
    storeHit = byDigest(manifestDigest, manifestStore);
  } catch (err) {
    throwPhase('continuity', 'ATTEST_STORE_ERROR', `[${checkpoint}] manifest store unreadable: ${err.message}`, { checkpoint });
  }
  if (!storeHit.ok) {
    throwPhase('continuity', 'ATTEST_MANIFEST_UNKNOWN', `[${checkpoint}] exact manifest not found in the persistent manifest store: refusing bare-digest signing`, { checkpoint });
  }
  let latest;
  try {
    latest = byInvestigation(investigationId, manifestStore);
  } catch (err) {
    throwPhase('continuity', 'ATTEST_STORE_ERROR', `[${checkpoint}] manifest store unreadable: ${err.message}`, { checkpoint });
  }
  if (!latest.ok) {
    throwPhase('continuity', 'ATTEST_MANIFEST_UNKNOWN', `[${checkpoint}] investigation has no listable manifest: cannot prove the reviewed manifest is current`, { investigationId, checkpoint });
  }
  const latestDigest = latest.envelope.manifestDigest;
  if (baseline === null || baseline === undefined) {
    return { storeHit, latest, superseded: latestDigest !== manifestDigest };
  }
  if (latestDigest !== baseline.latestDigest) {
    throwPhase('continuity', 'ATTEST_MANIFEST_CHANGED', `[${checkpoint}] manifest store changed mid-ceremony (latest ${baseline.latestDigest.slice(0, 12)}… → ${latestDigest.slice(0, 12)}…): aborting; review the latest manifest instead`, { expected: manifestDigest, baselineLatest: baseline.latestDigest, latest: latestDigest, checkpoint });
  }
  return { storeHit, latest, superseded: latestDigest !== manifestDigest };
}

async function attestPackage(opts) {
  const o = opts && typeof opts === 'object' ? opts : {};
  const now = o.now === undefined ? Date.now() : o.now;
  const storeDir = o.storeDir === undefined ? path.join(process.cwd(), 'data') : o.storeDir;
  const paths = storePaths(storeDir);
  const manifestStore = typeof o.manifestStore === 'string' && o.manifestStore.length > 0
    ? o.manifestStore
    : path.join(paths.dir, 'manifests.jsonl');
  const ctx = { preview: null, caseInfo: null, opId: null, manifestDigest: null, keyId: null };

  const refusal = (phase, code, message, extra) => ({
    attested: false,
    phase,
    code,
    message,
    ...(extra === undefined ? {} : extra),
    lockReleased: 'not-acquired',
    opId: ctx.opId,
    manifestDigest: ctx.manifestDigest,
    keyId: ctx.keyId
  });

  // -- Pre-lock: pure validation (no store reads, no writes). --
  if (!o.pkg || typeof o.pkg !== 'object') return refusal('input-invalid', 'ATTEST_INVALID', 'pkg: verification package required');
  if (typeof o.expectDigest !== 'string' || !HEX64.test(o.expectDigest)) {
    return refusal('input-invalid', 'ATTEST_INVALID', 'expectDigest: full 64-hex manifest digest required');
  }
  if (o.privateKey === undefined) return refusal('input-invalid', 'ATTEST_INVALID_KEY', 'privateKey: ceremony key required via environment');
  let keyId;
  try {
    keyId = deriveAddress(o.privateKey);
  } catch (err) {
    return refusal('input-invalid', err.code || 'ATTEST_INVALID_KEY', `signing key rejected: ${err.message}`);
  }
  ctx.keyId = keyId;
  if (!o.registry || typeof o.registry !== 'object') return refusal('input-invalid', 'ATTEST_INVALID', 'registry: key registry object required');
  if (o.trustedRoot === undefined) return refusal('input-invalid', 'ATTEST_INVALID', 'trustedRoot: independently obtained root address required');
  try {
    assertValidInput(o.pkg, 'package');
  } catch (err) {
    return refusal('package-invalid', 'ATTEST_INVALID', `package structurally invalid: ${err.message}`);
  }
  const verified = verifyPackage(o.pkg);
  if (!verified.ok) {
    return refusal('package-invalid', 'ATTEST_PACKAGE_INVALID', 'verification package failed Phase 2 checks', {
      failedChecks: verified.checks.filter((c) => !c.ok).map((c) => ({ name: c.name, detail: c.detail || '' }))
    });
  }
  const manifest = o.pkg.manifest;
  const manifestDigest = sha256Hex(canonicalStringify(manifest));
  ctx.manifestDigest = manifestDigest;
  if (manifestDigest !== o.expectDigest) {
    return refusal('digest-mismatch', 'ATTEST_DIGEST_MISMATCH', 'recomputed manifest digest does not match --expect-digest', {
      recomputed: manifestDigest
    });
  }
  const opId = attestationOpId(manifestDigest, keyId);
  ctx.opId = opId;

  // -- M2 decision/execution consistency. --
  // Execution-writer invariants (agentController.js): approvals are
  // issued ONLY for ALLOW (immediate) and REVIEW (pending operator
  // countersign); BLOCK/UNCERTAIN never receive approvals, and both
  // recordExecution callers require a complete approval first. A
  // BLOCK/UNCERTAIN package carrying an executed transaction hash is
  // therefore contradictory — verifyPackage checks hash binding but
  // not decision consistency. Refuse fail-closed. (decision.agent is
  // authoritative here, not decision.evaluation: execution approval
  // follows the agent-path decision.)
  const agentDecision = manifest.decision ? manifest.decision.agent : null;
  const txHash = manifest.transaction ? manifest.transaction.transactionHash : null;
  if ((agentDecision === 'BLOCK' || agentDecision === 'UNCERTAIN') && txHash !== null && txHash !== undefined) {
    return refusal('decision-inconsistent', 'ATTEST_DECISION_INCONSISTENT', `${agentDecision} decision with an executed transaction hash is contradictory: BLOCK/UNCERTAIN never receive execution approvals`, { decision: agentDecision, transactionHash: txHash });
  }

  // -- Lock. --
  let lock;
  try {
    lock = acquireCeremonyLock(storeDir, { opId });
  } catch (err) {
    if (err && err.code === 'ATTEST_LOCK_HELD') {
      return {
        ...refusal('lock-held', 'ATTEST_LOCK_HELD', 'another ceremony holds the store lock', { holder: err.holder || null }),
        lockReleased: 'not-acquired'
      };
    }
    return refusal('error', (err && err.code) || 'ATTEST_ERROR', `lock acquisition failed: ${(err && err.message) || err}`);
  }

  let result;
  try {
    result = await runLockedCeremony({ o, now, paths, storeDir, manifestStore, manifest, manifestDigest, keyId, opId, lock, ctx });
  } catch (err) {
    if (err instanceof AttestationError) {
      result = {
        attested: false,
        phase: err.phase || 'error',
        code: err.code,
        message: err.message,
        details: err.details === undefined ? null : err.details,
        opId: ctx.opId,
        manifestDigest: ctx.manifestDigest,
        keyId: ctx.keyId,
        preview: ctx.preview,
        caseInfo: ctx.caseInfo
      };
    } else {
      result = {
        attested: false,
        phase: 'error',
        code: 'ATTEST_ERROR',
        message: `unexpected failure: ${(err && err.message) || err}`,
        details: null,
        opId: ctx.opId,
        manifestDigest: ctx.manifestDigest,
        keyId: ctx.keyId,
        preview: ctx.preview,
        caseInfo: ctx.caseInfo
      };
    }
  }
  let release;
  try {
    release = releaseCeremonyLock(lock);
  } catch (err) {
    release = { released: false, reason: `release-error: ${(err && err.message) || err}` };
  }
  result.lockReleased = release.released;
  result.lockReleaseNote = release.reason || '';
  return result;
}

async function runLockedCeremony({ o, now, paths, storeDir, manifestStore, manifest, manifestDigest, keyId, opId, lock, ctx }) {
  // -- Integrity gate (with optional acknowledgments). --
  let attRead = readStoreFile(paths.attestations);
  let auditRead = readStoreFile(paths.audit);
  let journalRead = readStoreFile(paths.journal);
  let journalEval = evaluateJournal(mergedChainEntries(journalRead));
  if (journalEval.chain.firstBreak !== null) {
    throwPhase('integrity-gate', 'ATTEST_JOURNAL_BROKEN', `journal chain broken at line ${journalEval.chain.firstBreak}: new ceremonies blocked; existing records remain readable; see docs for recovery limits`, { firstBreak: journalEval.chain.firstBreak });
  }
  let acksRecorded = [];
  let gate = gateBlockers({ storeDir, attRead, auditRead, journalRead, journalEval });
  if (gate.blockers.length > 0 && Array.isArray(o.acknowledge) && o.acknowledge.length > 0) {
    acksRecorded = processAcknowledgments({ lock, paths, storeDir, requests: o.acknowledge, now, opId });
    attRead = readStoreFile(paths.attestations);
    auditRead = readStoreFile(paths.audit);
    journalRead = readStoreFile(paths.journal);
    journalEval = evaluateJournal(mergedChainEntries(journalRead));
    gate = gateBlockers({ storeDir, attRead, auditRead, journalRead, journalEval });
  }
  if (gate.blockers.length > 0) {
    if (gate.blockers.some((b) => b.store === 'journal')) {
      throwPhase('integrity-gate', 'ATTEST_JOURNAL_CORRUPT', 'unacknowledged journal corruption: reconcile the journal before signing', { blockers: gate.blockers });
    }
    throwPhase('integrity-gate', 'ATTEST_INTEGRITY_BLOCKED', 'unacknowledged store corruption: reconcile before signing', { blockers: gate.blockers });
  }

  // -- Registry + key authorization. --
  const registryCheck = await verifyRegistry({
    registry: o.registry,
    trustedRoot: o.trustedRoot,
    minVersion: o.minRegistryVersion === undefined ? null : o.minRegistryVersion,
    maxAgeDays: o.maxRegistryAgeDays === undefined ? DEFAULT_MAX_REGISTRY_AGE_DAYS : o.maxRegistryAgeDays,
    allowStale: o.allowStaleRegistry === true,
    now
  });
  if (!registryCheck.ok) {
    throwPhase('registry', 'ATTEST_REGISTRY', `key registry rejected: ${registryCheck.code} ${registryCheck.detail}`, { code: registryCheck.code });
  }
  let trustedAuthorities;
  let denyList;
  let rootAddr;
  try {
    trustedAuthorities = Array.isArray(o.trustedAuthorities) ? o.trustedAuthorities.map((a) => assertAddress(a, 'trustedAuthorities[]')) : [];
    denyList = Array.isArray(o.denyList) ? o.denyList.map((a) => assertAddress(a, 'denyList[]')) : [];
    rootAddr = assertAddress(o.trustedRoot, 'trustedRoot');
  } catch (err) {
    throwPhase('key', 'ATTEST_INVALID', `key authorization inputs invalid: ${err.message}`, null);
  }
  if (!trustedAuthorities.includes(keyId)) {
    throwPhase('key', 'ATTEST_UNTRUSTED_KEY', 'signing key is not in TRUSTED_ATTESTATION_AUTHORITIES', null);
  }
  if (keyId === rootAddr || denyList.includes(keyId)) {
    throwPhase('key', 'ATTEST_DENIED_KEY', 'signing key is deny-listed (root/signer/operator/deployment)', null);
  }
  const entry = registryCheck.keys[keyId] || registryCheck.keys[keyId.toLowerCase()] || null;
  if (entry === null) throwPhase('key', 'ATTEST_UNKNOWN_KEY', 'signing key not in registry', null);
  if (entry.status !== 'ACTIVE') {
    throwPhase('key', 'ATTEST_KEY_NOT_ACTIVE', `signing key is ${entry.status}: ceremony signs with ACTIVE keys only`, { status: entry.status });
  }

  // -- C1: manifest continuity baseline (before preview/classification). --
  // Fail-closed on unknowns; superseded-at-entry flows to the case-G
  // override path below (the ONLY place overrides apply).
  const finders = o.manifestFinders === undefined ? null : o.manifestFinders;
  const c1 = checkManifestContinuity({
    manifestDigest, investigationId: manifest.investigationId, manifestStore,
    finders, checkpoint: 'C1', baseline: null
  });
  const storeHit = c1.storeHit;
  const latest = c1.latest;
  const superseded = c1.superseded;
  const continuityBaseline = { latestDigest: latest.envelope.manifestDigest };
  const recheckContinuity = (checkpoint) => checkManifestContinuity({
    manifestDigest, investigationId: manifest.investigationId, manifestStore,
    finders, checkpoint, baseline: continuityBaseline
  });

  // -- Case classification + preview. --
  const caseInfo = classifyPackageCase({ manifest, superseded });
  ctx.caseInfo = caseInfo;
  const warnings = [];
  if (storeHit.corrupted > 0 || (latest.ok && latest.corrupted > 0)) {
    warnings.push(`manifest store has ${(storeHit.corrupted || 0) + ((latest.ok && latest.corrupted) || 0)} corrupted lines (skipped, not used)`);
  }
  for (const n of gate.notes) {
    if (n.acknowledged) warnings.push(`proceeding with acknowledged ${n.kind} debris in ${n.store} at offset ${n.offset} (${n.ackId})`);
    else if (n.autoProceed) warnings.push(`proceeding past conclusively foreign tail in ${n.store} at offset ${n.offset} (${n.verdict.reason})`);
  }
  const preview = buildCeremonyPreview({
    pkg: o.pkg, manifestDigest, keyAddress: keyId, keyState: entry.status,
    registryVersion: registryCheck.version, caseInfo, manifestStoreFound: true, warnings
  });
  ctx.preview = preview;
  if (caseInfo.case === 'G' && o.allowSuperseded !== true) {
    throwPhase('refused-superseded', 'ATTEST_SUPERSEDED', 'manifest is superseded: refusing without explicit override', { latestDigest: latest.envelope.manifestDigest });
  }
  if (caseInfo.case === 'F' && o.allowUnverifiedExecution !== true) {
    throwPhase('refused-unverified-confirmation', 'ATTEST_UNVERIFIED_EXECUTION', 'execution claimed without receipt evidence: refusing without explicit override', null);
  }
  if (o.confirm !== true) {
    return {
      attested: false, phase: 'preview', code: 'ATTEST_PREVIEW',
      message: 'preview only: re-run with explicit --confirm to sign',
      opId, manifestDigest, keyId, preview, caseInfo, warnings,
      acksRecorded: acksRecorded.map((r) => r.ackId)
    };
  }

  // -- Adopt-or-sign. --
  const adoption = await adoptIdentityRecords({ attRead, auditRead, manifestDigest, keyId, manifest });
  // -- C2: recheck after confirmation/adoption, immediately before
  // signing. Aborts unconditionally on any mid-ceremony change. --
  recheckContinuity('C2');
  let attestation = adoption.attestation;
  const decision = caseInfo.decision;
  if (typeof decision !== 'string' || decision.length === 0) {
    throwPhase('error', 'ATTEST_INVALID', 'manifest has no resolvable decision', null);
  }
  if (!adoption.attestationAdopted) {
    const body = buildAttestationBody({
      manifestDigest,
      investigationId: manifest.investigationId,
      traceId: manifest.traceId,
      requestId: manifest.requestId === undefined ? null : manifest.requestId,
      keyId,
      issuedAt: now
    });
    attestation = await signAttestation({ body, privateKey: o.privateKey });
    assertLockHeld(lock);
    if (readStoreFile(paths.attestations).tail !== null) appendDelimiterIfNeeded(paths.attestations);
    const storeLine = buildAttestationStoreLine({ attestation, opId, recordedAt: now });
    // -- C3a: recheck after signing, immediately before appending the
    // attestation. Aborts unconditionally on any mid-ceremony change. --
    recheckContinuity('C3a');
    assertLockHeld(lock);
    durableAppend(paths.attestations, canonicalStringify(storeLine), {});
    // Post-write verification of OUR record.
    attRead = readStoreFile(paths.attestations);
    const ours = findAttestationMatches(attRead, manifestDigest, keyId);
    if (ours.length === 0) throwPhase('persistence', 'ATTEST_PERSIST_FAILED', 'attestation not found after append', null);
  }
  let auditEvent = null;
  if (!adoption.auditAdopted) {
    auditEvent = buildAuditEvent({
      opId, manifestDigest, keyId,
      investigationId: manifest.investigationId,
      decision,
      registryVersion: registryCheck.version,
      warnings: preview.warnings,
      reconciliationRefs: acksRecorded.map((r) => r.ackId),
      lockBroken: normalizeLockBrokenOpt(o.lockBroken === undefined ? null : o.lockBroken),
      at: now
    });
    assertLockHeld(lock);
    if (readStoreFile(paths.audit).tail !== null) appendDelimiterIfNeeded(paths.audit);
    // -- C3b: recheck immediately before appending the audit record.
    // Aborts unconditionally on any mid-ceremony change. --
    recheckContinuity('C3b');
    assertLockHeld(lock);
    durableAppend(paths.audit, canonicalStringify(auditEvent), {});
    auditRead = readStoreFile(paths.audit);
    const ours = findAuditMatches(auditRead, manifestDigest, keyId);
    if (ours.length === 0) throwPhase('persistence', 'ATTEST_PERSIST_FAILED', 'audit event not found after append', null);
  } else {
    const ours = findAuditMatches(auditRead, manifestDigest, keyId);
    auditEvent = ours.length > 0 ? ours[0].parsed : null;
  }

  // -- Final verification from fresh reads. --
  attRead = readStoreFile(paths.attestations);
  auditRead = readStoreFile(paths.audit);
  const finalAtt = findAttestationMatches(attRead, manifestDigest, keyId);
  const finalAudit = findAuditMatches(auditRead, manifestDigest, keyId);
  if (finalAtt.length === 0 || finalAudit.length === 0) {
    throwPhase('persistence', 'ATTEST_PERSIST_FAILED', 'final verification: attestation or audit record missing', null);
  }
  let recovered = null;
  try {
    recovered = await recoverAttestationAddress(finalAtt[0].parsed.attestation);
  } catch {
    recovered = null;
  }
  if (recovered !== keyId) throwPhase('persistence', 'ATTEST_PERSIST_FAILED', 'final verification: stored signature invalid', null);

  return {
    attested: true, phase: 'completed', code: 'ATTEST_COMPLETED',
    message: 'attestation completed: signature persisted and audit recorded',
    opId, manifestDigest, keyId,
    investigationId: manifest.investigationId,
    registryVersion: registryCheck.version,
    adopted: { attestation: adoption.attestationAdopted, audit: adoption.auditAdopted },
    attestation,
    auditEvent,
    preview, caseInfo,
    warnings: preview.warnings,
    acksRecorded: acksRecorded.map((r) => r.ackId)
  };
}

// ---------------------------------------------------------------------------
// Authoritative locked verification. verifyCompletion is the ONLY reader
// (besides the ceremony itself) that may conclude attested:true: it
// holds the lock across both store reads, so the observed pair is
// atomic. Anything unlocked is observational (see ceremonyStatus).
// ---------------------------------------------------------------------------

async function verifyCompletion({ storeDir, manifestDigest, keyId } = {}) {
  if (typeof manifestDigest !== 'string' || !HEX64.test(manifestDigest)) {
    fail('ATTEST_INVALID', 'verifyCompletion: manifestDigest required');
  }
  const keyFilter = keyId === undefined || keyId === null ? null : assertAddress(keyId, 'verifyCompletion.keyId');
  const paths = storePaths(storeDir);
  let lock;
  try {
    lock = acquireCeremonyLock(paths.dir, { opId: null });
  } catch (err) {
    if (err && err.code === 'ATTEST_LOCK_HELD') {
      return { attested: false, phase: 'lock-held', code: 'ATTEST_LOCK_HELD', message: 'stores busy: retry verification later', holder: err.holder || null, complete: false, identities: [] };
    }
    throw err;
  }
  try {
    const attRead = readStoreFile(paths.attestations);
    const auditRead = readStoreFile(paths.audit);
    const journalRead = readStoreFile(paths.journal);
    const journalEval = evaluateJournal(mergedChainEntries(journalRead));
    const groups = new Map();
    for (const line of attRead.lines) {
      let parsed = null;
      try {
        assertAttestationStoreLine(line.parsed);
        parsed = line.parsed;
      } catch {
        continue;
      }
      const b = parsed.attestation.body;
      if (b.manifestDigest !== manifestDigest) continue;
      if (keyFilter !== null && b.keyId.toLowerCase() !== keyFilter) continue;
      const gk = `${b.manifestDigest}|${b.keyId.toLowerCase()}`;
      if (!groups.has(gk)) groups.set(gk, { manifestDigest: b.manifestDigest, keyId: b.keyId.toLowerCase(), storeLines: [], audits: [] });
      groups.get(gk).storeLines.push(parsed);
    }
    for (const line of auditRead.lines) {
      let parsed = null;
      try {
        assertAuditEventShape(line.parsed);
        parsed = line.parsed;
      } catch {
        continue;
      }
      if (parsed.manifestDigest !== manifestDigest) continue;
      if (keyFilter !== null && parsed.keyId.toLowerCase() !== keyFilter) continue;
      const gk = `${parsed.manifestDigest}|${parsed.keyId.toLowerCase()}`;
      if (!groups.has(gk)) groups.set(gk, { manifestDigest: parsed.manifestDigest, keyId: parsed.keyId.toLowerCase(), storeLines: [], audits: [] });
      groups.get(gk).audits.push(parsed);
    }
    const identities = [];
    for (const g of groups.values()) {
      const sigResults = [];
      for (const s of g.storeLines) {
        let recovered = null;
        try {
          recovered = await recoverAttestationAddress(s.attestation);
        } catch {
          recovered = null;
        }
        sigResults.push(recovered !== null
          && recovered === s.attestation.authority.toLowerCase()
          && recovered === s.attestation.body.keyId.toLowerCase());
      }
      const distinctValid = new Set(g.storeLines.filter((_, i) => sigResults[i]).map((s) => canonicalStringify(s)));
      const attestationValid = distinctValid.size === 1;
      const conflict = distinctValid.size > 1 || (g.storeLines.length > 0 && sigResults.every((r) => !r) && g.storeLines.length > 0 && distinctValid.size === 0);
      const auditPresent = g.audits.length > 0 && new Set(g.audits.map((a) => canonicalStringify(a))).size === 1;
      const auditConflict = new Set(g.audits.map((a) => canonicalStringify(a))).size > 1;
      identities.push({
        manifestDigest: g.manifestDigest,
        keyId: g.keyId,
        opId: attestationOpId(g.manifestDigest, g.keyId),
        attestation: attestationValid ? 'valid' : (g.storeLines.length === 0 ? 'absent' : 'invalid-or-conflicted'),
        audit: auditPresent ? 'present' : (g.audits.length === 0 ? 'absent' : 'conflicted'),
        complete: attestationValid && auditPresent && !conflict && !auditConflict
      });
    }
    const complete = identities.length > 0 && identities.every((i) => i.complete);
    return {
      attested: complete,
      phase: complete ? 'completed' : 'incomplete',
      code: complete ? 'ATTEST_COMPLETED' : 'ATTEST_INCOMPLETE',
      message: complete ? 'verified: attestation and audit both persisted' : 'no complete attestation found for this digest',
      complete,
      identities,
      storeNotes: {
        attestations: { malformed: attRead.malformed.length, blanks: attRead.blanks.length, shapeInvalid: shapeInvalidLines(attRead, 'attestations').length, tail: attRead.tail !== null },
        audit: { malformed: auditRead.malformed.length, blanks: auditRead.blanks.length, shapeInvalid: shapeInvalidLines(auditRead, 'audit').length, tail: auditRead.tail !== null },
        journal: { malformed: journalRead.malformed.length, blanks: journalRead.blanks.length, shapeInvalid: shapeInvalidLines(journalRead, 'journal').length, tail: journalRead.tail !== null, chainBreak: journalEval.chain.firstBreak }
      }
    };
  } finally {
    releaseCeremonyLock(lock);
  }
}

// ---------------------------------------------------------------------------
// Observational unlocked readers. ceremonyStatus and reconcileShow NEVER
// acquire the lock and NEVER conclude attested/complete: the two stores
// are read non-atomically, so an in-flight ceremony can be observed
// between its lifecycle events. Output is always labeled observational.
// ---------------------------------------------------------------------------

function lockObservation(paths) {
  const info = readLockFile(paths.lock);
  if (!info.present) return { present: false, holder: null };
  const h = info.holder || {};
  return {
    present: true,
    parseable: info.parseable,
    holder: info.parseable ? { pid: h.pid ?? null, hostname: h.hostname ?? null, startedAt: h.startedAt ?? null, opId: h.opId ?? null } : null
  };
}

function ceremonyStatus({ storeDir, manifestDigest, investigationId } = {}) {
  const paths = storePaths(storeDir || path.join(process.cwd(), 'data'));
  const digestFilter = manifestDigest === undefined || manifestDigest === null ? null : manifestDigest;
  if (digestFilter !== null && !HEX64.test(digestFilter)) fail('ATTEST_INVALID', 'ceremonyStatus: manifestDigest must be 64-hex');
  const observedAt = Date.now();
  const attRead = readStoreFile(paths.attestations);
  const auditRead = readStoreFile(paths.audit);
  const journalRead = readStoreFile(paths.journal);
  const journalEval = evaluateJournal(mergedChainEntries(journalRead));
  const identities = new Map();
  const observe = (digest, key, kind) => {
    const gk = `${digest}|${String(key).toLowerCase()}`;
    if (!identities.has(gk)) identities.set(gk, { manifestDigest: digest, keyId: String(key).toLowerCase(), observedAttestation: 'absent', observedAudit: 'absent' });
    identities.get(gk)[kind] = 'observed-present';
  };
  for (const line of attRead.lines) {
    try {
      assertAttestationStoreLine(line.parsed);
    } catch {
      continue;
    }
    const b = line.parsed.attestation.body;
    if (digestFilter !== null && b.manifestDigest !== digestFilter) continue;
    observe(b.manifestDigest, b.keyId, 'observedAttestation');
  }
  for (const line of auditRead.lines) {
    try {
      assertAuditEventShape(line.parsed);
    } catch {
      continue;
    }
    if (digestFilter !== null && line.parsed.manifestDigest !== digestFilter) continue;
    if (investigationId !== undefined && investigationId !== null && line.parsed.investigationId !== investigationId) continue;
    observe(line.parsed.manifestDigest, line.parsed.keyId, 'observedAudit');
  }
  const tailInfo = (store, read) => (read.tail === null ? null : {
    store, offset: read.tail.offset, length: read.tail.length, sha256: read.tail.sha256, verdict: classifyFragment(store, read.tail.bytes)
  });
  return {
    observational: true,
    observedAt,
    lock: lockObservation(paths),
    storeSizes: { attestations: attRead.size, audit: auditRead.size, journal: journalRead.size },
    corruptionObserved: {
      attestations: { malformed: attRead.malformed.length, blanks: attRead.blanks.length, shapeInvalid: shapeInvalidLines(attRead, 'attestations').length },
      audit: { malformed: auditRead.malformed.length, blanks: auditRead.blanks.length, shapeInvalid: shapeInvalidLines(auditRead, 'audit').length },
      journal: { malformed: journalRead.malformed.length, blanks: journalRead.blanks.length, shapeInvalid: shapeInvalidLines(journalRead, 'journal').length }
    },
    tailsObserved: [tailInfo('attestations', attRead), tailInfo('audit', auditRead), tailInfo('journal', journalRead)].filter(Boolean),
    journalObserved: {
      events: journalEval.byAckId.size,
      amendments: journalEval.amendments.length,
      notes: journalEval.notes.length,
      contested: [...journalEval.contested],
      chainBreak: journalEval.chain.firstBreak,
      tipUnverified: true
    },
    identitiesObserved: [...identities.values()]
  };
}

function reconcileShow({ storeDir } = {}) {
  // Unlocked observational list of every debris item needing attention,
  // with its acknowledgment coverage. Offsets must be re-verified at
  // act time (the ceremony does this under the lock).
  const paths = storePaths(storeDir || path.join(process.cwd(), 'data'));
  const attRead = readStoreFile(paths.attestations);
  const auditRead = readStoreFile(paths.audit);
  const journalRead = readStoreFile(paths.journal);
  const journalEval = evaluateJournal(mergedChainEntries(journalRead));
  const readOriginal = (store, offset, length) => originalBytesAt(paths.dir, store, offset, length);
  const items = [];
  const collect = (store, read) => {
    for (const entry of [...read.malformed, ...read.blanks, ...shapeInvalidLines(read, store)]) {
      const kind = read.malformed.includes(entry) ? 'malformed' : read.blanks.includes(entry) ? 'blank' : 'shape-invalid';
      const ackId = acknowledgmentId({ store, offset: entry.offset, length: entry.length, bytesSha256: entry.sha256 });
      const use = usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
      items.push({
        store, kind, offset: entry.offset, length: entry.length, bytesSha256: entry.sha256, ackId,
        coverage: use.usable ? 'acknowledged' : use.reason,
        suggestedClassification: kind === 'blank' ? 'blank-line' : 'foreign-debris'
      });
    }
    if (read.tail !== null) {
      const verdict = classifyFragment(store, read.tail.bytes);
      const ackId = acknowledgmentId({ store, offset: read.tail.offset, length: read.tail.length, bytesSha256: read.tail.sha256 });
      const use = verdict.verdict === 'FOREIGN'
        ? { usable: true, reason: 'conclusively-foreign' }
        : usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
      items.push({
        store, kind: 'tail', offset: read.tail.offset, length: read.tail.length, bytesSha256: read.tail.sha256, ackId,
        verdict, coverage: use.usable ? (verdict.verdict === 'FOREIGN' ? 'no-acknowledgment-needed' : 'acknowledged') : use.reason,
        suggestedClassification: 'torn-fragment'
      });
    }
  };
  collect('attestations', attRead);
  collect('audit', auditRead);
  // Journal self-debris is gate-BLOCKING (fail-closed): new ceremonies
  // and journal mutations refuse until every item below has usable
  // acknowledgment coverage. A chain break blocks with no recovery path
  // (the store is preserved for forensics; see ATTEST_JOURNAL_BROKEN).
  const journalDebris = [
    ...journalRead.malformed.map((entry) => ({ entry, kind: 'malformed' })),
    ...journalRead.blanks.map((entry) => ({ entry, kind: 'blank' })),
    ...shapeInvalidLines(journalRead, 'journal').map((entry) => ({ entry, kind: 'shape-invalid' }))
  ].map(({ entry, kind }) => {
    const ackId = acknowledgmentId({ store: 'journal', offset: entry.offset, length: entry.length, bytesSha256: entry.sha256 });
    const use = usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
    return {
      store: 'journal', kind, offset: entry.offset, length: entry.length, bytesSha256: entry.sha256, ackId,
      coverage: use.usable ? 'acknowledged' : use.reason,
      suggestedClassification: kind === 'blank' ? 'blank-line' : 'foreign-debris'
    };
  });
  if (journalRead.tail !== null) {
    journalDebris.push({
      store: 'journal', kind: 'tail', offset: journalRead.tail.offset, length: journalRead.tail.length,
      bytesSha256: journalRead.tail.sha256, verdict: classifyFragment('journal', journalRead.tail.bytes),
      coverage: 'tail-repairs-on-append', suggestedClassification: 'torn-fragment'
    });
  }
  return {
    observational: true, observedAt: Date.now(), lock: lockObservation(paths), items, journalDebris,
    chainBreak: journalEval.chain.firstBreak,
    chainNote: journalEval.chain.firstBreak !== null
      ? `JOURNAL CHAIN BREAK at line ${journalEval.chain.firstBreak}: ceremonies and journal mutations are BLOCKED for this store; records before the break remain readable for forensic inspection`
      : null
  };
}

// ---------------------------------------------------------------------------
// Journal appenders for amendments and notes. Each acquires the ceremony
// lock (journal shares it), repairs a torn tail by pure append, and
// verifies its own write. Idempotency and conflict rules per spec.
// ---------------------------------------------------------------------------

function repairJournalTail(paths, lock) {
  let read = readStoreFile(paths.journal);
  if (read.tail !== null) {
    assertLockHeld(lock);
    appendDelimiterIfNeeded(paths.journal);
    read = readStoreFile(paths.journal);
  }
  return read;
}

function journalCorruptionEntries(journalRead) {
  // Complete journal lines that are not valid records of any kind.
  // (Tails are excluded: unterminated fragments repair, they don't gate.)
  return [
    ...journalRead.malformed.map((entry) => ({ entry, kind: 'malformed' })),
    ...journalRead.blanks.map((entry) => ({ entry, kind: 'blank' })),
    ...shapeInvalidLines(journalRead, 'journal').map((entry) => ({ entry, kind: 'shape-invalid' }))
  ];
}

function parsedAmendmentsFromLines(journalRead) {
  const out = [];
  for (const line of journalRead.lines) {
    try {
      assertAmendmentShape(line.parsed);
      out.push({ line: canonicalStringify(line.parsed), amendment: line.parsed });
    } catch {
      // Not an amendment (or invalid): inert for this scan.
    }
  }
  return out;
}

function appendAmendment({ storeDir, amendsAckId, endorsedRecordSha256, newRationale, newClassification, operator, at, now }) {
  const paths = storePaths(storeDir || path.join(process.cwd(), 'data'));
  const stamp = at === undefined ? (now === undefined ? Date.now() : now) : at;
  const candidateId = amendmentId({ amendsAckId, endorsedRecordSha256, newRationale, newClassification, operator });
  let lock;
  try {
    lock = acquireCeremonyLock(paths.dir, { opId: null });
  } catch (err) {
    if (err && err.code === 'ATTEST_LOCK_HELD') throwPhase('lock-held', 'ATTEST_LOCK_HELD', 'stores busy: retry the amendment later', null);
    throw err;
  }
  try {
    // Freeze rule: no mutation across a broken chain; no NON-recovery
    // mutation while complete corruption is present. An amendment that
    // targets a contested acknowledgment IS recovery, so it alone is
    // permitted (on an unbroken chain). Checked before any repair so
    // refusals never mutate.
    const preRead = readStoreFile(paths.journal);
    const preEval = evaluateJournal(mergedChainEntries(preRead));
    if (preEval.chain.firstBreak !== null) {
      throwPhase('amendment', 'ATTEST_JOURNAL_BROKEN', `journal chain broken at line ${preEval.chain.firstBreak}: amendments blocked; existing records remain readable`, { firstBreak: preEval.chain.firstBreak });
    }
    if (journalCorruptionEntries(preRead).length > 0 && !preEval.contested.has(amendsAckId)) {
      throwPhase('amendment', 'ATTEST_JOURNAL_CORRUPT', 'unacknowledged journal corruption: reconcile the journal before amending (contested-ack amendments excepted)', null);
    }
    const journalRead = repairJournalTail(paths, lock);
    // Exact-duplicate and conflict scan across ALL complete lines.
    for (const { line, amendment } of parsedAmendmentsFromLines(journalRead)) {
      if (amendment.amendmentId !== candidateId) continue;
      const substantiveSame = amendment.endorsedRecordSha256 === endorsedRecordSha256
        && amendment.newRationale === newRationale
        && (amendment.newClassification === null ? null : amendment.newClassification) === (newClassification === undefined || newClassification === null ? null : newClassification)
        && amendment.operator === operator;
      if (substantiveSame) return { appended: false, amendmentId: candidateId, reason: 'idempotent-duplicate' };
      throwPhase('amendment', 'ATTEST_AMEND_CONFLICT', 'same amendment id with different substantive content', { amendmentId: candidateId });
    }
    const journalEval = evaluateJournal(mergedChainEntries(journalRead));
    const copies = journalEval.byAckId.get(amendsAckId) || [];
    if (copies.length === 0) {
      throwPhase('amendment', 'ATTEST_AMEND_DANGLING', 'amended acknowledgment not found in verified journal history', { amendsAckId });
    }
    const endorsed = copies.some((c) => sha256Hex(Buffer.from(c.line, 'utf8')) === endorsedRecordSha256);
    if (!endorsed) {
      throwPhase('amendment', 'ATTEST_AMEND_DANGLING', 'endorsed record digest matches no known copy of the acknowledgment', { amendsAckId });
    }
    assertLockHeld(lock);
    const amendment = buildAmendment({
      amendsAckId, endorsedRecordSha256, newRationale,
      newClassification: newClassification === undefined ? null : newClassification,
      operator, at: stamp, chainPrev: journalEval.chain.tipState
    });
    const lineText = canonicalStringify(amendment);
    durableAppend(paths.journal, lineText, {});
    // Post-write verification: the amendment links correctly.
    const reread = readStoreFile(paths.journal);
    const reeval = evaluateJournal(mergedChainEntries(reread));
    const found = reeval.amendments.some((a) => a.line === lineText);
    if (!found) throwPhase('amendment', 'ATTEST_PERSIST_FAILED', 'amendment not verifiable after append', null);
    return { appended: true, amendmentId: candidateId, amendment };
  } finally {
    releaseCeremonyLock(lock);
  }
}

function appendNote({ storeDir, refAckId, text, operator, at, now }) {
  const paths = storePaths(storeDir || path.join(process.cwd(), 'data'));
  const stamp = at === undefined ? (now === undefined ? Date.now() : now) : at;
  if (refAckId !== null && refAckId !== undefined && (typeof refAckId !== 'string' || !ACKID_SHAPE.test(refAckId))) {
    fail('ATTEST_INVALID', 'note.refAckId: acknowledgment id or null');
  }
  let lock;
  try {
    lock = acquireCeremonyLock(paths.dir, { opId: null });
  } catch (err) {
    if (err && err.code === 'ATTEST_LOCK_HELD') throwPhase('lock-held', 'ATTEST_LOCK_HELD', 'stores busy: retry the note later', null);
    throw err;
  }
  try {
    // Freeze rule: notes are never recovery, so any complete journal
    // corruption or chain break refuses. Checked before any repair so
    // refusals never mutate.
    const preRead = readStoreFile(paths.journal);
    const preEval = evaluateJournal(mergedChainEntries(preRead));
    if (preEval.chain.firstBreak !== null) {
      throwPhase('note', 'ATTEST_JOURNAL_BROKEN', `journal chain broken at line ${preEval.chain.firstBreak}: notes blocked; existing records remain readable`, { firstBreak: preEval.chain.firstBreak });
    }
    if (journalCorruptionEntries(preRead).length > 0) {
      throwPhase('note', 'ATTEST_JOURNAL_CORRUPT', 'unacknowledged journal corruption: reconcile the journal before noting', null);
    }
    const journalRead = repairJournalTail(paths, lock);
    const journalEval = evaluateJournal(mergedChainEntries(journalRead));
    if (refAckId !== null && refAckId !== undefined && (journalEval.byAckId.get(refAckId) || []).length === 0) {
      throwPhase('note', 'ATTEST_NOTE_DANGLING', 'referenced acknowledgment not found in verified journal history', { refAckId });
    }
    const note = buildNote({ refAckId: refAckId === undefined ? null : refAckId, text, operator, at: stamp, chainPrev: journalEval.chain.tipState });
    // Notes are content-addressed: same noteId = same substantive note.
    // A resubmission (new timestamp/position) is idempotent, never a
    // conflict — every substantive field participates in the id.
    for (const line of journalRead.lines) {
      const p = line.parsed;
      if (p && p.format === RECONCILIATION_NOTE_FORMAT && p.noteId === note.noteId) {
        return { appended: false, noteId: note.noteId, reason: 'idempotent-duplicate' };
      }
    }
    assertLockHeld(lock);
    const lineText = canonicalStringify(note);
    durableAppend(paths.journal, lineText, {});
    const reread = readStoreFile(paths.journal);
    const found = reread.lines.some((l) => {
      try {
        return canonicalStringify(l.parsed) === lineText;
      } catch {
        return false;
      }
    });
    if (!found) throwPhase('note', 'ATTEST_PERSIST_FAILED', 'note not verifiable after append', null);
    return { appended: true, noteId: note.noteId, note };
  } finally {
    releaseCeremonyLock(lock);
  }
}

module.exports = {
  // Constants.
  ATTESTATION_BODY_FORMAT,
  ATTESTATION_FORMAT,
  ATTESTATION_STORE_FORMAT,
  ATTESTATION_AUDIT_FORMAT,
  ATTESTATION_ALGORITHM,
  ATTESTATION_PURPOSE,
  ATTESTATION_CHAIN_ID,
  ATTESTATION_SCHEMA_VERSION,
  REGISTRY_FORMAT,
  RECONCILIATION_FORMAT,
  RECONCILIATION_AMENDMENT_FORMAT,
  RECONCILIATION_NOTE_FORMAT,
  assertAddress,
  GENESIS_STATE,
  KEY_STATES,
  DEFAULT_MAX_REGISTRY_AGE_DAYS,
  DEFAULT_LOCK_STALE_MS,
  AttestationError,
  // Keys (generation only — no import path exists by design).
  generateAttestationKey,
  deriveAddress,
  fingerprintOfAddress,
  parseAddressList,
  // Operations.
  attestationOpId,
  // Attestation lifecycle.
  buildAttestationBody,
  assertAttestationBodyShape,
  assertAttestationShape,
  signAttestation,
  recoverAttestationAddress,
  verifyAttestation,
  buildAttestationStoreLine,
  assertAttestationStoreLine,
  buildAuditEvent,
  assertAuditEventShape,
  assertLockBrokenShape,
  findAttestationMatches,
  findAuditMatches,
  attachAttestation,
  // Registry.
  assertRegistryKeyEntry,
  registryUnsignedBytes,
  buildRegistrySkeleton,
  prepareRegistryUpdate,
  signRegistry,
  verifyRegistry,
  // Journal chain.
  chainAdvance,
  verifyJournalChain,
  normalizeChainLines,
  evaluateJournal,
  usableAckFor,
  usableAckRecord,
  acknowledgmentId,
  buildAcknowledgment,
  assertAckShape,
  amendmentId,
  buildAmendment,
  assertAmendmentShape,
  buildNote,
  // Stores + gate.
  storePaths,
  readStoreFile,
  durableAppend,
  appendDelimiterIfNeeded,
  mergedChainEntries,
  originalBytesAt,
  gateBlockers,
  processAcknowledgments,
  checkManifestContinuity,
  // Classifier.
  classifyFragment,
  // Locking.
  readLockFile,
  processAlive,
  acquireCeremonyLock,
  assertLockHeld,
  releaseCeremonyLock,
  breakStaleLock,
  // Ceremony.
  executionGrade,
  modelEvidenceComplete,
  classifyPackageCase,
  buildCeremonyPreview,
  attestPackage,
  verifyCompletion,
  ceremonyStatus,
  reconcileShow,
  appendAmendment,
  appendNote
};
