/**
 * Provenance + attestation HTTP controller (SDK-upgrade milestone).
 *
 * Thin HTTP adapter over the completed Phase 1-3 / Step 4-6 services.
 * It exposes manifest generation, export retrieval, operator-gated
 * ceremony + publication, and read-only judge-style verification to
 * SDK developers. It implements NO cryptography itself: every check
 * runs in the existing services (provenanceManifest,
 * provenanceAttestation, attestationPublisher).
 *
 * Security posture (prototype):
 * - Manifest/export/verify routes: agent API key + ownership scoping.
 * - Ceremony + publish routes: additionally require OPERATOR_SECRET in
 *   the request body (same pattern as REVIEW operator release) AND an
 *   explicit server-side opt-in (ATTESTATION_SERVER_SIGNING /
 *   ATTESTATION_SERVER_PUBLISH). Without both, they answer 503/403.
 * - Server-side ceremony holding ATTESTATION_SIGNING_KEY is a
 *   prototype/demo posture. Production provenance must use the offline
 *   CLI ceremony (src/attestation/attest.js); see docs/attestation.md.
 * - No endpoint accepts, returns, or logs private key material. The
 *   agent never receives the operator secret, so it cannot self-attest.
 */

const fs = require('fs');
const path = require('path');
const { allowOwner, requestKey, safeEqual } = require('../middleware/agentAuth');
const {
  buildManifest, saveManifest, findManifestByDigest, buildVerificationPackage,
  verifyPackage, ManifestError
} = require('../services/provenanceManifest');
const {
  attestPackage, verifyAttestation, verifyRegistry, recoverAttestationAddress,
  parseAddressList, readStoreFile, storePaths, AttestationError
} = require('../services/provenanceAttestation');
const {
  publishAttestation, PublisherError, deriveModelBitmap, deriveCompatBitmap,
  deriveModelMetadata, sameModels, DECISION_MAP, CONTRACT_ABI, CONTRACT_ABI_V2
} = require('../services/attestationPublisher');
const { canonicalStringify, sha256Hex } = require('../utils/canonicalJson');
const { findSubmissionTx } = require('../attestation/judge');

const EXPORT_FORMAT = 'assertara-attestation-export-1';
const HEX64 = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function readProvenanceConfig(env) {
  const e = env || {};
  const str = (v) => (typeof v === 'string' && v.length > 0 ? v : null);
  const chainId = str(e.ATTESTATION_CHAIN_ID);
  const version = str(e.ATTESTATION_CONTRACT_VERSION);
  return {
    manifestStore: str(e.ATTESTATION_MANIFEST_STORE),
    storeDir: str(e.ATTESTATION_STORE_DIR),
    registryFile: str(e.ATTESTATION_REGISTRY_FILE),
    trustedRoot: str(e.TRUSTED_REGISTRY_ROOT),
    trustedAuthoritiesRaw: str(e.TRUSTED_ATTESTATION_AUTHORITIES),
    denyListRaw: str(e.ATTESTATION_DENY_ADDRESSES),
    signingEnabled: e.ATTESTATION_SERVER_SIGNING === 'enabled',
    signingKey: str(e.ATTESTATION_SIGNING_KEY),
    publishEnabled: e.ATTESTATION_SERVER_PUBLISH === 'enabled',
    publisherKey: str(e.PUBLISHER_TX_KEY),
    rpcUrl: str(e.ATTESTATION_RPC_URL),
    contractAddress: str(e.ATTESTATION_CONTRACT_ADDRESS),
    chainId: chainId === null ? null : Number(chainId),
    chainIdRaw: chainId,
    contractVersion: version === null ? 2 : Number(version),
    minRegistryVersion: str(e.ATTESTATION_MIN_REGISTRY_VERSION),
    maxRegistryAgeDays: str(e.ATTESTATION_MAX_REGISTRY_AGE_DAYS)
  };
}

function fail(res, status, code, message) {
  return res.status(status).json({ error: message, code });
}

function manifestErr(res, err, fallback) {
  if (err instanceof ManifestError) {
    const status = err.code === 'MANIFEST_MISMATCH' ? 409 : 422;
    return fail(res, status, err.code, err.message);
  }
  return fail(res, 500, fallback || 'PROVENANCE_INTERNAL', 'Provenance operation failed.');
}

function checkOperator(req, res, operatorSecret) {
  if (!operatorSecret) {
    return fail(res, 503, 'OPERATOR_UNAVAILABLE', 'Operator authorization unavailable: OPERATOR_SECRET is not configured.');
  }
  const presented = req.body && req.body.operatorSecret;
  if (typeof presented !== 'string' || !safeEqual(presented, operatorSecret)) {
    return fail(res, 403, 'OPERATOR_AUTH_FAILED', 'Operator authentication failed.');
  }
  return null;
}

function loadRegistry(registryFile) {
  const raw = fs.readFileSync(registryFile, 'utf8');
  return JSON.parse(raw);
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

function createProvenanceController({ store, operatorSecret, config }) {
  const cfg = config || {};
  // eslint-disable-next-line global-require
  const { findByEvalId } = require('../services/investigationStore');

  function recordAccessible(req, requestRecord) {
    return Boolean(requestRecord) && allowOwner(req, requestRecord.ownerKeyId);
  }

  // Resolve the (request, persisted record) pair for one agent request.
  function resolvePair(requestId) {
    if (!store) return { ok: false, error: 'STORE_UNAVAILABLE' };
    const request = store.get(requestId);
    if (!request) return { ok: false, error: 'UNKNOWN_REQUEST' };
    if (typeof request.evalId !== 'string' || !request.evalId) {
      return { ok: false, error: 'NO_PERSISTED_INVESTIGATION', request };
    }
    const found = findByEvalId(request.evalId);
    if (!found.ok) return { ok: false, error: 'NO_PERSISTED_INVESTIGATION', request };
    return { ok: true, request, record: found.record };
  }

  // Owner check for a stored manifest: follow its requestId back to the
  // agent request. Manifests without a request link are visible only in
  // development contexts (fail closed in production).
  function manifestAccessible(req, manifest) {
    const requestId = manifest && manifest.requestId;
    if (typeof requestId === 'string' && requestId && store) {
      return recordAccessible(req, store.get(requestId));
    }
    return requestKey(req).development === true;
  }

  // Latest ceremony-produced attestation for one manifest digest, by
  // scanning the append-only store (last match wins). Malformed lines
  // are skipped: only structurally valid attestations are returned,
  // and signatures are verified by publisher/judge, never here.
  function findAttestationByDigest(manifestDigest) {
    const paths = storePaths(cfg.storeDir);
    const read = readStoreFile(paths.attestations);
    let found = null;
    for (const entry of read.lines || []) {
      const line = entry && typeof entry.text === 'string' ? entry.text : '';
      if (!line.trim()) continue;
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        continue;
      }
      const att = parsed && parsed.attestation;
      if (!att || !att.body || att.body.manifestDigest !== manifestDigest) continue;
      if (typeof att.signature !== 'string' || typeof att.authority !== 'string') continue;
      found = att;
    }
    return found;
  }

  // POST /api/v1/provenance/manifests { requestId }
  async function handleBuildManifest(req, res) {
    const requestId = req.body && req.body.requestId;
    if (typeof requestId !== 'string' || !requestId) {
      return fail(res, 400, 'REQUEST_ID_REQUIRED', 'requestId is required.');
    }
    const pair = resolvePair(requestId);
    if (!pair.ok) {
      if (pair.error === 'UNKNOWN_REQUEST') return fail(res, 404, 'UNKNOWN_REQUEST', 'Unknown agent request id.');
      if (pair.error === 'STORE_UNAVAILABLE') return fail(res, 503, 'STORE_UNAVAILABLE', 'Agent request store unavailable.');
      return fail(res, 409, 'NO_PERSISTED_INVESTIGATION', 'No persisted model-origin investigation for this request.');
    }
    if (!recordAccessible(req, pair.request)) {
      return fail(res, 404, 'UNKNOWN_REQUEST', 'Unknown agent request id.');
    }
    if (!allowOwner(req, pair.record.ownerKeyId)) {
      return fail(res, 404, 'UNKNOWN_REQUEST', 'Unknown agent request id.');
    }
    let built;
    try {
      built = buildManifest({ record: pair.record, request: pair.request });
    } catch (err) {
      return manifestErr(res, err);
    }
    try {
      saveManifest(built, cfg.manifestStore);
    } catch (err) {
      return manifestErr(res, err, 'MANIFEST_PERSIST_FAILED');
    }
    return res.json({
      manifest: built.manifest,
      envelope: built.envelope,
      manifestDigest: built.manifestDigest
    });
  }

  // GET /api/v1/provenance/manifests/:digest
  async function handleGetManifest(req, res) {
    const digest = String(req.params.digest || '').toLowerCase();
    if (!HEX64.test(digest)) return fail(res, 400, 'DIGEST_INVALID', 'digest: 64 lowercase hex required.');
    let envelope;
    try {
      const found = findManifestByDigest(digest, cfg.manifestStore);
      envelope = found && found.envelope;
    } catch (err) {
      return manifestErr(res, err);
    }
    if (!envelope) return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
    if (!manifestAccessible(req, envelope.manifest)) {
      return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
    }
    return res.json({ manifest: envelope.manifest, envelope, manifestDigest: digest });
  }

  function buildExportForDigest(digest) {
    const found = findManifestByDigest(digest, cfg.manifestStore);
    const envelope = found && found.envelope;
    if (!envelope) return { ok: false, error: 'MANIFEST_UNKNOWN' };
    const manifest = envelope.manifest;
    const requestId = manifest.requestId;
    let request = null;
    let record = null;
    if (typeof requestId === 'string' && requestId && store) {
      const pair = resolvePair(requestId);
      if (pair.ok) {
        request = pair.request;
        record = pair.record;
      }
    }
    if (!record) return { ok: false, error: 'NO_PERSISTED_INVESTIGATION' };
    // Deterministic rebuild: identical bytes to the original build.
    const built = buildManifest({ record, request });
    if (built.manifestDigest !== digest) return { ok: false, error: 'MANIFEST_MISMATCH' };
    const pkg = buildVerificationPackage(built);
    const pv = verifyPackage(pkg);
    if (!pv.ok) return { ok: false, error: 'PACKAGE_INVALID' };
    const attestation = findAttestationByDigest(digest);
    if (!attestation) return { ok: false, error: 'NOT_ATTESTED' };
    if (attestation.body.investigationId !== manifest.investigationId
      || attestation.body.traceId !== manifest.traceId) {
      return { ok: false, error: 'ATTESTATION_MISMATCH' };
    }
    return {
      ok: true,
      manifest,
      exported: {
        format: EXPORT_FORMAT,
        exportedAt: Date.now(),
        manifestDigest: digest,
        package: { ...pkg, packageVersion: 'assertara-verify-2', attestation }
      }
    };
  }

  // GET /api/v1/provenance/exports/:digest
  async function handleGetExport(req, res) {
    const digest = String(req.params.digest || '').toLowerCase();
    if (!HEX64.test(digest)) return fail(res, 400, 'DIGEST_INVALID', 'digest: 64 lowercase hex required.');
    let out;
    try {
      out = buildExportForDigest(digest);
    } catch (err) {
      return manifestErr(res, err);
    }
    if (!out.ok) {
      if (out.error === 'MANIFEST_UNKNOWN') return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
      if (out.error === 'NOT_ATTESTED') return fail(res, 409, 'NOT_ATTESTED', 'Manifest exists but no ceremony attestation was recorded for it.');
      return fail(res, 409, out.error, `Export unavailable: ${out.error}.`);
    }
    if (!manifestAccessible(req, out.manifest)) {
      return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
    }
    return res.json(out.exported);
  }

  function ceremonyAvailable() {
    if (cfg.signingEnabled !== true) return 'server-side ceremony is not enabled (ATTESTATION_SERVER_SIGNING).';
    if (!cfg.signingKey) return 'ATTESTATION_SIGNING_KEY is not configured.';
    if (!cfg.registryFile) return 'ATTESTATION_REGISTRY_FILE is not configured.';
    if (!cfg.trustedRoot) return 'TRUSTED_REGISTRY_ROOT is not configured.';
    if (!cfg.trustedAuthoritiesRaw) return 'TRUSTED_ATTESTATION_AUTHORITIES is not configured.';
    return null;
  }

  // POST /api/v1/attestations
  // { package } or { digest }, expectDigest, confirm, operatorSecret, flags...
  // Without confirm:true this returns the ceremony preview only.
  async function handleCeremony(req, res) {
    const denied = checkOperator(req, res, operatorSecret);
    if (denied) return denied;
    const unavailable = ceremonyAvailable();
    if (unavailable) return fail(res, 503, 'CEREMONY_UNAVAILABLE', `Attestation ceremony unavailable: ${unavailable}`);
    const body = req.body || {};
    const expectDigest = typeof body.expectDigest === 'string' ? body.expectDigest.toLowerCase() : '';
    if (!HEX64.test(expectDigest)) {
      return fail(res, 400, 'EXPECT_DIGEST_REQUIRED', 'expectDigest: 64 lowercase hex required.');
    }
    let pkg = body.package;
    if ((pkg === undefined || pkg === null) && typeof body.digest === 'string') {
      const digest = body.digest.toLowerCase();
      if (!HEX64.test(digest)) return fail(res, 400, 'DIGEST_INVALID', 'digest: 64 lowercase hex required.');
      let out;
      try {
        out = buildExportForDigest(digest);
      } catch (err) {
        return manifestErr(res, err);
      }
      if (!out.ok && out.error === 'NOT_ATTESTED') {
        // Unsigned package path: rebuild the v1 package directly.
        try {
          const found = findManifestByDigest(digest, cfg.manifestStore);
          const envelope = found && found.envelope;
          if (!envelope) return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
          if (!manifestAccessible(req, envelope.manifest)) {
            return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
          }
          const pair = resolvePair(envelope.manifest.requestId);
          if (!pair.ok) return fail(res, 409, 'NO_PERSISTED_INVESTIGATION', 'Cannot rebuild the package for this digest.');
          const built = buildManifest({ record: pair.record, request: pair.request });
          pkg = buildVerificationPackage(built);
        } catch (err) {
          return manifestErr(res, err);
        }
      } else if (!out.ok) {
        if (out.error === 'MANIFEST_UNKNOWN') return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
        return fail(res, 409, out.error, `Package unavailable: ${out.error}.`);
      } else {
        if (!manifestAccessible(req, out.manifest)) {
          return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
        }
        pkg = out.exported.package;
      }
    }
    if (!pkg || typeof pkg !== 'object') {
      return fail(res, 400, 'PACKAGE_REQUIRED', 'package object or digest is required.');
    }
    let registry;
    try {
      registry = loadRegistry(cfg.registryFile);
    } catch (err) {
      return fail(res, 503, 'REGISTRY_UNAVAILABLE', `Key registry unreadable: ${(err && err.message) || err}.`);
    }
    let trustedAuthorities;
    let denyList = [];
    try {
      trustedAuthorities = parseAddressList(cfg.trustedAuthoritiesRaw, 'TRUSTED_ATTESTATION_AUTHORITIES');
      if (cfg.denyListRaw) denyList = parseAddressList(cfg.denyListRaw, 'ATTESTATION_DENY_ADDRESSES');
    } catch (err) {
      return fail(res, 503, 'REGISTRY_UNAVAILABLE', (err && err.message) || 'Trust configuration invalid.');
    }
    if (trustedAuthorities.length === 0) {
      return fail(res, 503, 'REGISTRY_UNAVAILABLE', 'TRUSTED_ATTESTATION_AUTHORITIES is empty.');
    }
    let result;
    try {
      result = await attestPackage({
        pkg,
        registry,
        trustedRoot: cfg.trustedRoot,
        trustedAuthorities,
        denyList,
        privateKey: cfg.signingKey,
        expectDigest,
        confirm: body.confirm === true,
        storeDir: cfg.storeDir,
        manifestStore: cfg.manifestStore,
        allowSuperseded: body.allowSuperseded === true,
        allowUnverifiedExecution: body.allowUnverifiedExecution === true,
        allowStaleRegistry: body.allowStaleRegistry === true,
        minRegistryVersion: body.minRegistryVersion,
        maxRegistryAgeDays: body.maxRegistryAgeDays
      });
    } catch (err) {
      if (err instanceof AttestationError) {
        return fail(res, 422, err.code, err.message);
      }
      return fail(res, 500, 'CEREMONY_FAILED', 'Attestation ceremony failed.');
    }
    return res.json(result);
  }

  function publishAvailable() {
    if (cfg.publishEnabled !== true) return 'server-side publication is not enabled (ATTESTATION_SERVER_PUBLISH).';
    if (!cfg.publisherKey) return 'PUBLISHER_TX_KEY is not configured.';
    if (!cfg.rpcUrl) return 'ATTESTATION_RPC_URL is not configured.';
    if (!cfg.contractAddress) return 'ATTESTATION_CONTRACT_ADDRESS is not configured.';
    if (!Number.isInteger(cfg.chainId)) return 'ATTESTATION_CHAIN_ID is not configured.';
    if (!cfg.registryFile) return 'ATTESTATION_REGISTRY_FILE is not configured.';
    if (!cfg.trustedRoot) return 'TRUSTED_REGISTRY_ROOT is not configured.';
    if (!cfg.trustedAuthoritiesRaw) return 'TRUSTED_ATTESTATION_AUTHORITIES is not configured.';
    if (cfg.contractVersion !== 1 && cfg.contractVersion !== 2) return 'ATTESTATION_CONTRACT_VERSION must be 1 or 2.';
    return null;
  }

  // POST /api/v1/attestations/publish { signedPackage } or { digest }, operatorSecret
  async function handlePublish(req, res) {
    const denied = checkOperator(req, res, operatorSecret);
    if (denied) return denied;
    const unavailable = publishAvailable();
    if (unavailable) return fail(res, 503, 'PUBLISH_UNAVAILABLE', `Attestation publication unavailable: ${unavailable}`);
    const body = req.body || {};
    let signedPackage = body.signedPackage;
    if ((signedPackage === undefined || signedPackage === null) && typeof body.digest === 'string') {
      const digest = body.digest.toLowerCase();
      if (!HEX64.test(digest)) return fail(res, 400, 'DIGEST_INVALID', 'digest: 64 lowercase hex required.');
      let out;
      try {
        out = buildExportForDigest(digest);
      } catch (err) {
        return manifestErr(res, err);
      }
      if (!out.ok) {
        if (out.error === 'MANIFEST_UNKNOWN') return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
        if (out.error === 'NOT_ATTESTED') return fail(res, 409, 'NOT_ATTESTED', 'Manifest has no ceremony attestation; run the ceremony first.');
        return fail(res, 409, out.error, `Signed package unavailable: ${out.error}.`);
      }
      if (!manifestAccessible(req, out.manifest)) {
        return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
      }
      signedPackage = out.exported.package;
    }
    // Accept the portable export envelope or the bare v2 package.
    if (signedPackage && signedPackage.format === EXPORT_FORMAT && signedPackage.package) {
      signedPackage = signedPackage.package;
    }
    if (!signedPackage || typeof signedPackage !== 'object' || !signedPackage.manifest || !signedPackage.attestation) {
      return fail(res, 400, 'SIGNED_PACKAGE_REQUIRED', 'signedPackage (v2 package with attestation) or digest is required.');
    }
    let registry;
    try {
      registry = loadRegistry(cfg.registryFile);
    } catch (err) {
      return fail(res, 503, 'REGISTRY_UNAVAILABLE', `Key registry unreadable: ${(err && err.message) || err}.`);
    }
    let trustedAuthorities;
    let denyList = [];
    try {
      trustedAuthorities = parseAddressList(cfg.trustedAuthoritiesRaw, 'TRUSTED_ATTESTATION_AUTHORITIES');
      if (cfg.denyListRaw) denyList = parseAddressList(cfg.denyListRaw, 'ATTESTATION_DENY_ADDRESSES');
    } catch (err) {
      return fail(res, 503, 'REGISTRY_UNAVAILABLE', (err && err.message) || 'Trust configuration invalid.');
    }
    let result;
    try {
      result = await publishAttestation({
        signedPackage,
        registry,
        trustedRoot: cfg.trustedRoot,
        trustedAuthorities,
        denyList,
        rpcUrl: cfg.rpcUrl,
        publisherKey: cfg.publisherKey,
        chainId: cfg.chainId,
        contractAddress: cfg.contractAddress,
        contractVersion: cfg.contractVersion,
        confirmations: body.confirmations
      });
    } catch (err) {
      if (err instanceof PublisherError) {
        return fail(res, 422, err.code, err.message);
      }
      return fail(res, 500, 'PUBLISH_FAILED', 'Attestation publication failed.');
    }
    return res.json(result);
  }

  // POST /api/v1/attestations/verify — read-only judge flow as data.
  // { exported } or { digest }, optional: registry, trustedRoot,
  // investigation, attester, submitTx, contractVersion, minVersion,
  // maxAgeDays, now. RPC + contract are server-configured (no caller
  // override: this route is a verification engine, not an open proxy).
  // Caller-supplied registry/trustedRoot are honored so a developer
  // can verify against their own trusted root.
  async function handleVerify(req, res) {
    const body = req.body || {};
    if (!cfg.rpcUrl) return fail(res, 503, 'VERIFY_UNAVAILABLE', 'Attestation verification unavailable: ATTESTATION_RPC_URL is not configured.');
    if (!cfg.contractAddress) return fail(res, 503, 'VERIFY_UNAVAILABLE', 'Attestation verification unavailable: ATTESTATION_CONTRACT_ADDRESS is not configured.');
    const contractVersion = body.contractVersion === undefined ? cfg.contractVersion : body.contractVersion;
    if (contractVersion !== 1 && contractVersion !== 2) {
      return fail(res, 400, 'CONTRACT_VERSION_INVALID', 'contractVersion must be 1 or 2.');
    }
    const v2 = contractVersion === 2;
    const checks = [];
    const step = (name, ok, detail) => {
      checks.push({ name, ok: Boolean(ok), detail: detail || '' });
      return Boolean(ok);
    };
    const done = (verdict) => res.json({ verdict, checks, models: modelsInfo });

    let exported = body.exported;
    if ((exported === undefined || exported === null) && typeof body.digest === 'string') {
      const digest = body.digest.toLowerCase();
      if (!HEX64.test(digest)) return fail(res, 400, 'DIGEST_INVALID', 'digest: 64 lowercase hex required.');
      let out;
      try {
        out = buildExportForDigest(digest);
      } catch (err) {
        return manifestErr(res, err);
      }
      if (!out.ok) {
        if (out.error === 'MANIFEST_UNKNOWN') return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
        return fail(res, 409, out.error, `Export unavailable: ${out.error}.`);
      }
      if (!manifestAccessible(req, out.manifest)) {
        return fail(res, 404, 'MANIFEST_UNKNOWN', 'No stored manifest for this digest.');
      }
      exported = out.exported;
    }
    let modelsInfo = [];
    if (!exported || exported.format !== EXPORT_FORMAT || !exported.package || !exported.package.manifest) {
      step('export-shape', false, 'not an attestation export object');
      return done('FAIL');
    }
    step('export-shape', true, exported.format);
    const pkg = exported.package;
    const manifest = pkg.manifest;
    const investigationId = typeof body.investigation === 'string' && body.investigation
      ? body.investigation : manifest.investigationId;
    if (typeof investigationId !== 'string' || !investigationId) {
      step('chain-record', false, 'no investigation id');
      return done('FAIL');
    }
    let attester = typeof body.attester === 'string' && body.attester
      ? body.attester.toLowerCase() : null;
    if (attester !== null && !ADDRESS.test(attester)) {
      return fail(res, 400, 'ATTESTER_INVALID', 'attester must be an address.');
    }
    if (attester === null) {
      try {
        attester = (await recoverAttestationAddress(pkg.attestation)).toLowerCase();
      } catch {
        step('signer-match', false, 'attester unknown and recovery failed');
        return done('FAIL');
      }
    }

    let viem;
    try {
      viem = require('viem');
    } catch {
      return fail(res, 503, 'VERIFY_UNAVAILABLE', 'Chain client unavailable on this server.');
    }
    const { encodeFunctionData, decodeFunctionResult, decodeEventLog, keccak256, toHex, parseAbi } = viem;
    const abi = v2 ? CONTRACT_ABI_V2 : parseAbi(CONTRACT_ABI);
    const eventName = v2 ? 'AttestedWithModels' : 'Attested';
    const contract = cfg.contractAddress;

    // 1. On-chain record.
    let record;
    try {
      const raw = await rpc(cfg.rpcUrl, 'eth_call', [{
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
      return done('FAIL');
    }
    step('chain-record', true, `decision=${record.decision} bitmap=${record.modelBitmap}`);

    // 2+3. Digest binding.
    const recomputed = sha256Hex(canonicalStringify(manifest));
    if (!step('digest-recompute', recomputed === exported.manifestDigest, recomputed)) return done('FAIL');
    if (!step('digest-onchain', `0x${recomputed.toLowerCase()}` === String(record.manifestDigest).toLowerCase(), 'manifest binds the chain record')) {
      return done('FAIL');
    }

    // 4. Package integrity + attestation presence.
    let pv;
    try {
      pv = verifyPackage(pkg);
    } catch (err) {
      step('package', false, `verifyPackage threw (${(err && err.message) || err})`);
      return done('FAIL');
    }
    if (!step('package', pv.ok, pv.ok ? 'verifyPackage ok' : `verifyPackage: ${pv.code}`)) return done('FAIL');
    if (!pkg.attestation || typeof pkg.attestation !== 'object') {
      step('attestation-present', false, 'export carries no attestation object');
      return done('FAIL');
    }
    step('attestation-present', true, '');

    // 5+6. Signature + signer match. Trust inputs: caller-supplied
    // registry/root when given, else the server-configured registry.
    let registry = body.registry;
    let trustedRoot = typeof body.trustedRoot === 'string' ? body.trustedRoot : cfg.trustedRoot;
    if (registry === undefined || registry === null) {
      if (!cfg.registryFile) {
        step('signature', false, 'no registry available (supply one or configure ATTESTATION_REGISTRY_FILE)');
        return done('FAIL');
      }
      try {
        registry = loadRegistry(cfg.registryFile);
      } catch (err) {
        step('signature', false, `registry unreadable (${(err && err.message) || err})`);
        return done('FAIL');
      }
    }
    if (!ADDRESS.test(String(trustedRoot || ''))) {
      step('signature', false, 'no trusted root available (supply one or configure TRUSTED_REGISTRY_ROOT)');
      return done('FAIL');
    }
    const now = body.now === undefined ? Date.now() : body.now;
    let av;
    try {
      av = await verifyAttestation({
        manifest,
        attestation: pkg.attestation,
        trustedAuthorities: [attester],
        keyRegistry: registry,
        trustedRoot,
        maxRegistryAgeDays: body.maxAgeDays,
        now
      });
    } catch (err) {
      step('signature', false, `verifyAttestation threw (${(err && err.message) || err})`);
      return done('FAIL');
    }
    if (!step('signature', av.ok, av.ok ? `verifyAttestation ${av.code}` : `verifyAttestation: ${av.code}`)) return done('FAIL');
    let recovered;
    try {
      recovered = (await recoverAttestationAddress(pkg.attestation)).toLowerCase();
    } catch (err) {
      step('signer-match', false, `recovery failed (${(err && err.message) || err})`);
      return done('FAIL');
    }
    if (!step('signer-match', recovered === attester && recovered === String(record.attester).toLowerCase(), recovered)) {
      return done('FAIL');
    }

    // 7. Registry trust + key status.
    let reg;
    try {
      reg = await verifyRegistry({
        registry,
        trustedRoot,
        minVersion: body.minVersion === undefined
          ? (cfg.minRegistryVersion === null ? undefined : Number(cfg.minRegistryVersion)) : body.minVersion,
        maxAgeDays: body.maxAgeDays === undefined
          ? (cfg.maxRegistryAgeDays === null ? undefined : Number(cfg.maxRegistryAgeDays)) : body.maxAgeDays,
        now
      });
    } catch (err) {
      step('registry', false, `verifyRegistry threw (${(err && err.message) || err})`);
      return done('FAIL');
    }
    if (!step('registry', reg.ok, reg.ok ? 'root signature + freshness ok' : `registry: ${reg.code}`)) return done('FAIL');
    const entry = (reg.keys && (reg.keys[attester] || reg.keys[attester.toLowerCase()])) || null;
    if (!entry) {
      step('key-status', false, 'attester absent from registry');
      return done('FAIL');
    }
    if (!step('key-status', entry.status === 'ACTIVE', `registry status=${entry.status}`)) return done('FAIL');

    // 8. Decision + bitmap + txHash agreement.
    let bitmap;
    try {
      bitmap = v2 ? deriveCompatBitmap(manifest) : deriveModelBitmap(manifest);
    } catch (err) {
      step('bitmap-match', false, `derivation failed (${(err && err.message) || err})`);
      return done('FAIL');
    }
    const agentDecision = manifest.decision ? manifest.decision.agent : null;
    const decisionOk = Object.prototype.hasOwnProperty.call(DECISION_MAP, agentDecision || '')
      && DECISION_MAP[agentDecision] === record.decision;
    if (!step('decision-match', decisionOk, `${String(agentDecision)} vs on-chain ${record.decision}`)) return done('FAIL');
    if (!step('bitmap-match', bitmap === record.modelBitmap, `recomputed=${bitmap} on-chain=${record.modelBitmap}`)) {
      return done('FAIL');
    }
    const manifestTx = manifest.transaction && manifest.transaction.transactionHash != null
      ? String(manifest.transaction.transactionHash).toLowerCase()
      : `0x${'00'.repeat(32)}`;
    if (!step('txhash-match', manifestTx === String(record.txHash).toLowerCase(), manifestTx)) return done('FAIL');

    // 8b. V2 model metadata agreement (derived from the verified
    // manifest, never supplied by the caller).
    let expectedModels = null;
    if (v2) {
      let expected;
      try {
        expected = deriveModelMetadata(manifest);
      } catch (err) {
        step('models-match', false, `derivation failed (${(err && err.message) || err})`);
        return done('FAIL');
      }
      expectedModels = expected;
      modelsInfo = expected.map((m) => ({
        name: m.name, provider: m.provider, modelId: m.modelId,
        status: m.status, contribution: m.contribution
      }));
      if (!step('models-match', sameModels(record.models, expected), `${expected.length} model(s) agree with manifest`)) {
        return done('FAIL');
      }
    }

    // 9. Receipt + event.
    let submitTx = body.submitTx || null;
    if (submitTx === null) {
      const sig = v2
        ? keccak256(toHex('AttestedWithModels(string,bytes32,address,uint8,uint8,bytes32,(string,string,string,string,string,string,string,bytes32,bytes32)[])'))
        : keccak256(toHex('Attested(string,bytes32,address,uint8,uint8,bytes32)'));
      const idTopic = keccak256(toHex(investigationId));
      const found = await findSubmissionTx(
        (method, params) => rpc(cfg.rpcUrl, method, params),
        contract,
        [sig, idTopic, String(record.manifestDigest).toLowerCase(), `0x000000000000000000000000${attester.slice(2)}`]
      );
      if (!found.tx) {
        step('event-found', false, found.error || `no ${eventName} log for this investigation+attester`);
        return done('FAIL');
      }
      step('event-found', true, `submission tx found (scanned ${found.blocks} block(s))`);
      submitTx = found.tx;
    } else {
      step('event-found', true, `using submitTx ${submitTx}`);
    }
    let receipt;
    try {
      receipt = await rpc(cfg.rpcUrl, 'eth_getTransactionReceipt', [submitTx]);
    } catch {
      receipt = null;
    }
    if (!receipt) {
      step('receipt', false, 'receipt unavailable');
      return done('FAIL');
    }
    if (!step('receipt', Number(receipt.status) === 1, `status=${String(receipt.status)} block=${String(receipt.blockNumber)}`)) {
      return done('FAIL');
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
      && (!v2 || sameModels(a.models, expectedModels))
    );
    if (!step('event-match', Boolean(match), match ? `${eventName} log matches the record` : `no matching ${eventName} log in receipt`)) {
      return done('FAIL');
    }

    // 10. No-payment statement.
    if (record.decision !== 0) {
      const zero = String(record.txHash).toLowerCase() === `0x${'00'.repeat(32)}`;
      if (!step('no-payment', zero, record.decision === 1 ? 'BLOCK carries a zero hash: no payment executed or implied' : 'REVIEW carries a zero hash: no payment executed or implied')) {
        return done('FAIL');
      }
    } else if (String(record.txHash).toLowerCase() === `0x${'00'.repeat(32)}`) {
      step('no-payment', true, 'ALLOW with zero hash: pre-execution attestation, no payment claimed');
    } else {
      step('no-payment', true, 'ALLOW with hash: payment claim requires independent explorer/receipt verification (different chain possible)');
    }

    return done('PASS');
  }

  return {
    handleBuildManifest, handleGetManifest, handleGetExport,
    handleCeremony, handlePublish, handleVerify
  };
}

module.exports = { createProvenanceController, readProvenanceConfig };
