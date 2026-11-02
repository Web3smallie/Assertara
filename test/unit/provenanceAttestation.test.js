const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const A = require('../../src/services/provenanceAttestation');
const {
  buildManifest,
  buildVerificationPackage,
  verifyPackage,
  saveManifest
} = require('../../src/services/provenanceManifest');
const { canonicalStringify, sha256Hex } = require('../../src/utils/canonicalJson');

// Phase 3 provenance attestation: signing, registry, ceremony, journal,
// locking, crash recovery, CLIs, and negative security tests N1–N9.
// Fixture-only: ephemeral keys, tmp stores, no network, no chain.

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

const T0 = 1793600000000; // 2026-11-02, inside 2020–2100
const NOW = T0 + 5000;
const hex = (c) => String(c).repeat(64);
const TXHASH = `0x${'ab'.repeat(32)}`;
const REPO = path.join(__dirname, '..', '..');
const TMPROOT = path.join(__dirname, '.tmp-attestation');

function freshTmp(name) {
  const dir = path.join(TMPROOT, `${name}-${process.pid}-${Math.random().toString(16).slice(2)}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function expectAttestCode(fn, code, label) {
  try {
    const r = fn();
    if (r && typeof r.then === 'function') return r.then(
      () => assert.fail(`${label}: expected ${code}`),
      (err) => {
        assert.ok(err instanceof A.AttestationError, `${label}: typed AttestationError`);
        assert.strictEqual(err.code, code, `${label}: code ${code} (got ${err.code}: ${err.message})`);
      }
    );
  } catch (err) {
    assert.ok(err instanceof A.AttestationError, `${label}: typed AttestationError`);
    assert.strictEqual(err.code, code, `${label}: code ${code} (got ${err.code}: ${err.message})`);
    return null;
  }
  assert.fail(`${label}: expected ${code}`);
  return null;
}

function baseRecord() {
  return {
    recordId: 'inv_test_1', id: 'eval_test_1', traceId: 'tr_test_1', requestId: 'agent_test_1',
    recordedAt: T0, receivedAt: T0 - 1000, durationMs: 1000, investigationPath: 'agent', chainId: '31337',
    sender: '0xaaaa', to: '0xbbbb', verdict: 'MATCH', confidence: 0.9, recommendedAction: 'PROCEED',
    policyDecision: { decision: 'ALLOW', reasons: ['within mandate'] }, verdictSafeguards: [],
    txBinding: { receivedTxDigest: hex('a'), evaluatedTxDigest: hex('b'), match: true },
    decodedTransaction: { contract: '0xbbbb', contractName: 'T', functionName: 'transfer', standard: 'ERC20', valueEth: '0.005', isUnlimitedApproval: false },
    ruleFindings: [{ ruleId: 'R1' }],
    museProvenance: {
      status: 'success', provider: 'meta-model-api', endpoint: 'chat/completions',
      requested: 'muse-spark-1.3', served: 'muse-spark-1.3', responseId: 'resp_1',
      invokedAt: T0, completedAt: T0 + 1000, inputDigest: hex('c'), outputDigest: hex('d'),
      latencyMs: 1000, usage: { prompt_tokens: 5, completion_tokens: 6, total_tokens: 11 }
    },
    samProvenance: {
      status: 'success', mode: 'live', configured: 'sam-3.1', observed: null,
      invokedAt: T0, completedAt: T0 + 400, responseId: null, usage: null,
      outputDigest: hex('e'), screenshotDigest: hex('f'), submittedImageDigest: hex('f'),
      detectedCount: 1,
      perPrompt: [{ index: 0, prompt: 'button', status: 'success', invokedAt: T0, completedAt: T0 + 400, responseId: null, inputDigest: hex('1'), outputDigest: hex('2'), detections: 1 }]
    },
    investigation: { verdict: 'MATCH' },
    visualEvidence: { regions: [{ regionId: 'R-1' }] },
    evidencePacking: { truncations: [] },
    referenceValidation: { present: true, ok: true },
    reasoningOrigin: 'model'
  };
}

function baseRequest() {
  return {
    id: 'agent_test_1', traceId: 'tr_test_1', evalId: 'eval_test_1', status: 'EXECUTED',
    decision: 'ALLOW', reasons: ['within mandate'], txDigest: hex('b'), evalVerdict: 'MATCH',
    normalizedTx: { chainId: 31337 },
    execution: { outcome: 'EXECUTED', txHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x10' }
  };
}

function buildPackage(record, request) {
  const built = buildManifest({ record, request: request === undefined ? null : request });
  const pkg = buildVerificationPackage(built);
  const check = verifyPackage(pkg);
  assert.ok(check.ok, `fixture package must verify: ${JSON.stringify(check.checks.filter((c) => !c.ok))}`);
  return { built, pkg, manifestDigest: built.manifestDigest };
}

function activeEntry(reason, at) {
  return { reason, status: 'ACTIVE', statusChangedAt: at, supersededBy: null, validFrom: at };
}

async function signedRegistry(keys, rootKey, version, publishedAt) {
  const skeleton = A.buildRegistrySkeleton({ version, publishedAt });
  for (const [addr, entry] of Object.entries(keys)) skeleton.keys[addr.toLowerCase()] = entry;
  return A.signRegistry({ registry: skeleton, rootPrivateKey: rootKey });
}

async function ceremonyEnv(fx) {
  // fx: {record, request, version?, publishedAt?, keyState?}. Returns
  // everything attestPackage needs, with stores in a fresh tmp dir.
  const day = A.generateAttestationKey();
  const root = A.generateAttestationKey();
  const dir = freshTmp('ceremony');
  const { built, pkg, manifestDigest } = buildPackage(fx.record || baseRecord(), fx.request || baseRequest());
  const manifestStore = path.join(dir, 'manifests.jsonl');
  saveManifest(built, manifestStore);
  const entry = fx.keyState === undefined || fx.keyState === 'ACTIVE'
    ? activeEntry('test key', T0)
    : { reason: 'test transition', status: fx.keyState, statusChangedAt: T0 + 100, supersededBy: null, validFrom: T0 };
  const registry = await signedRegistry({ [day.address]: entry }, root.privateKey, fx.version === undefined ? 0 : fx.version, fx.publishedAt === undefined ? NOW : fx.publishedAt);
  return {
    dir, day, root, built, pkg, manifestDigest, manifestStore, registry,
    baseOpts: {
      pkg, registry, trustedRoot: root.address, trustedAuthorities: [day.address],
      denyList: [], privateKey: day.privateKey, expectDigest: manifestDigest,
      confirm: true, storeDir: dir, manifestStore, now: NOW
    }
  };
}

function runCli(script, args, opts) {
  const o = opts || {};
  const r = spawnSync(process.execPath, [path.join(REPO, script), ...args], {
    cwd: o.cwd || REPO,
    env: { ...process.env, ...(o.env || {}) },
    encoding: 'utf8'
  });
  return { exit: r.status === null ? 1 : r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// Byte-exact journal vectors (V1 clean chain, V2 debris chain).
// Every hash below was cross-verified with the OS-native SHA-256
// (Get-FileHash) over the exact preimage bytes state||line||0x0A.
const V1_L0 = '{"ackId":"attrec_bad41c20ee18fe66e520544622c3cd2616bf066cf6178d872c37fbce61e0f957","at":1793600000000,"bytesSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","chainPrev":"0000000000000000000000000000000000000000000000000000000000000000","classification":"foreign-debris","format":"assertara-reconciliation-1","keyId":null,"length":17,"manifestDigest":null,"offset":0,"opId":null,"operator":"vector","rationale":"vector fixture","store":"attestations"}';
const V1_S0 = '0b86eded998e169744d9d591c01d8fb8ee34e8ae44872a0b35c15b2b79cb61eb';
const V1_L1 = '{"ackId":"attrec_b1829fbb9883eb1097a89e994fc3370879c30492b95a261cb253e77eab3ad518","at":1793600001000,"bytesSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","chainPrev":"0b86eded998e169744d9d591c01d8fb8ee34e8ae44872a0b35c15b2b79cb61eb","classification":"blank-line","format":"assertara-reconciliation-1","keyId":null,"length":9,"manifestDigest":null,"offset":41,"opId":null,"operator":"vector","rationale":"vector fixture 2","store":"audit"}';
const V1_S1 = '02eb48a2fc0501e9297ceff9f942f9e115db854aefb2117129db9bc3a39a1636';
const V2_LF0 = '{"ackId":"attrec_800732b88634e108f7866c56372fae1502e03c29cc56d63c63ad8043c6c433ff","at":1793600000000,"bytesSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","chainPrev":"0000000000000000000000000000000000000000000000000000000000000000","classification":"ambiguous-debris","format":"assertara-reconciliation-1","keyId":null,"length":64,"manifestDigest":null,"offset":7,"opId":null,"operator":"vector","rationale":"vector v2 first","store":"journal"}';
const V2_T0 = '1fc1a0e8970501cd153b4d0f53965fcf0e973c32aacd43400ee4093129866a64';
const V2_DEBRIS = '{"foreign":true,"n":42}';
const V2_T1 = 'aa3ae5e35e23f40e43b4dff839c30ed49f495af295961f66abf2e8c044ce579f';
const V2_LF1 = '{"ackId":"attrec_ebcb9925370e26bc94b9ac27d566aac6860fc934b936416c096222b64809595a","at":1793600002000,"bytesSha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","chainPrev":"aa3ae5e35e23f40e43b4dff839c30ed49f495af295961f66abf2e8c044ce579f","classification":"torn-fragment","format":"assertara-reconciliation-1","keyId":null,"length":3,"manifestDigest":null,"offset":100,"opId":null,"operator":"vector","rationale":"vector v2 second","store":"attestations"}';
const V2_T2 = '25cf75fdfe36f2a13d83974ccc74fe4d51d10abb7407e95bd593f52feaa37a11';
const V2_SKIP = 'ede4a9886f44bb8c1a1902db5ae1c45df2abdff0dab2d581b253c56ef9f0018d';

async function runAttestationTests() {
  console.log('Testing Phase 3 provenance attestation...\n');

  // Test 1: key utilities — generation shape, derivation, fingerprints,
  // address-list parsing. No import path exists (no API takes a key file).
  {
    const k = A.generateAttestationKey();
    assert.ok(/^0x[0-9a-f]{64}$/.test(k.privateKey), 'private key 0x 32-byte hex');
    assert.ok(/^0x[0-9a-f]{40}$/.test(k.address), 'address 0x 20-byte lowercase');
    assert.strictEqual(A.deriveAddress(k.privateKey), k.address, 'derive round-trip');
    const k2 = A.generateAttestationKey();
    assert.notStrictEqual(k.privateKey, k2.privateKey, 'fresh entropy per key');
    assert.strictEqual(A.fingerprintOfAddress(k.address), sha256Hex(k.address), 'fingerprint = sha256(address)');
    assert.strictEqual(A.fingerprintOfAddress(k.address.toUpperCase().replace('0X', '0x')), sha256Hex(k.address), 'fingerprint case-insensitive');
    assert.deepStrictEqual(A.parseAddressList('', 't'), [], 'empty list');
    assert.deepStrictEqual(A.parseAddressList(` ${k.address} ,, ${k2.address} `, 't'), [k.address, k2.address], 'comma list trims');
    await expectAttestCode(() => A.deriveAddress('not-a-key'), 'ATTEST_INVALID_KEY', 'malformed key refused');
    await expectAttestCode(() => A.deriveAddress(`0x${'gg'.repeat(32)}`), 'ATTEST_INVALID_KEY', 'non-hex key refused');
    await expectAttestCode(() => A.parseAddressList('0x123', 't'), 'ATTEST_INVALID', 'bad list entry refused');
    assert.strictEqual(typeof A.importAttestationKey, 'undefined', 'no key-import API exists');
    console.log('✔ Test 1 Passed: key utilities.');
  }

  // Test 2: operation IDs — full 256-bit, deterministic, distinct;
  // correlation only (composite identity stays authoritative elsewhere).
  {
    const day = A.generateAttestationKey();
    const other = A.generateAttestationKey();
    const d1 = hex('a');
    const d2 = hex('b');
    const id1 = A.attestationOpId(d1, day.address);
    assert.ok(/^attop_[0-9a-f]{64}$/.test(id1), 'full 64-hex opId');
    assert.strictEqual(A.attestationOpId(d1, day.address), id1, 'deterministic');
    assert.notStrictEqual(A.attestationOpId(d2, day.address), id1, 'digest-sensitive');
    assert.notStrictEqual(A.attestationOpId(d1, other.address), id1, 'key-sensitive');
    assert.strictEqual(A.attestationOpId(d1, day.address.toUpperCase().replace('0X', '0x')), id1, 'address normalized');
    await expectAttestCode(() => A.attestationOpId('xyz', day.address), 'ATTEST_INVALID', 'bad digest refused');
    console.log('✔ Test 2 Passed: operation IDs.');
  }

  // Test 3: attestation sign/verify round-trip; key mismatch refused.
  {
    const day = A.generateAttestationKey();
    const body = A.buildAttestationBody({
      manifestDigest: hex('a'), investigationId: 'eval_1', traceId: 'tr_1', requestId: 'rq_1', keyId: day.address, issuedAt: NOW
    });
    const att = await A.signAttestation({ body, privateKey: day.privateKey });
    assert.strictEqual(att.authority, day.address, 'authority = signer');
    assert.strictEqual(await A.recoverAttestationAddress(att), day.address, 'recovery round-trip');
    const wrong = A.generateAttestationKey();
    await expectAttestCode(() => A.signAttestation({ body, privateKey: wrong.privateKey }), 'ATTEST_KEY_MISMATCH', 'wrong key refused');
    const tampered = JSON.parse(JSON.stringify(att));
    tampered.body.manifestDigest = hex('b');
    assert.notStrictEqual(await A.recoverAttestationAddress(tampered), day.address, 'tampered body does not recover');
    await expectAttestCode(() => A.buildAttestationBody({ manifestDigest: 'zz', investigationId: 'e', traceId: 't', requestId: null, keyId: day.address, issuedAt: NOW }), 'ATTEST_INVALID', 'bad digest refused');
    console.log('✔ Test 3 Passed: attestation signing round-trip.');
  }

  // Test 4: V1 clean-chain vector, byte-exact (OS cross-verified).
  {
    assert.strictEqual(A.GENESIS_STATE, '00'.repeat(32), 'genesis is exactly 32 zero bytes (64 hex chars)');
    assert.strictEqual(A.GENESIS_STATE.length, 64, 'genesis text length');
    const s0 = A.chainAdvance(A.GENESIS_STATE, V1_L0);
    assert.strictEqual(s0, V1_S0, 'V1 S0 byte-exact');
    assert.ok(V1_L1.includes(`"chainPrev":"${V1_S0}"`), 'V1 L1 commits to S0');
    const s1 = A.chainAdvance(s0, V1_L1);
    assert.strictEqual(s1, V1_S1, 'V1 S1 byte-exact');
    const chain = A.verifyJournalChain([V1_L0, V1_L1]);
    assert.strictEqual(chain.firstBreak, null, 'V1 chain unbroken');
    assert.strictEqual(chain.tipState, V1_S1, 'V1 tip');
    assert.ok(chain.verdicts.every((v) => v.usable), 'V1 all usable');
    console.log('✔ Test 4 Passed: V1 clean-chain vector byte-exact.');
  }

  // Test 5: V2 debris-chain vector + skip-mismatch proof (OS cross-verified).
  {
    const t0 = A.chainAdvance(A.GENESIS_STATE, V2_LF0);
    assert.strictEqual(t0, V2_T0, 'V2 T0 byte-exact');
    const t1 = A.chainAdvance(t0, V2_DEBRIS);
    assert.strictEqual(t1, V2_T1, 'V2 debris state byte-exact');
    assert.ok(V2_LF1.includes(`"chainPrev":"${V2_T1}"`), 'V2 F1 commits to post-debris state');
    const t2 = A.chainAdvance(t1, V2_LF1);
    assert.strictEqual(t2, V2_T2, 'V2 T2 byte-exact');
    const skip = A.chainAdvance(t0, V2_LF1);
    assert.strictEqual(skip, V2_SKIP, 'V2 skip hash byte-exact');
    assert.notStrictEqual(skip, V2_T2, 'skipping debris changes the chain');
    const chain = A.verifyJournalChain([V2_LF0, V2_DEBRIS, V2_LF1]);
    assert.strictEqual(chain.firstBreak, null, 'V2 chain unbroken');
    assert.strictEqual(chain.tipState, V2_T2, 'V2 tip');
    assert.strictEqual(chain.verdicts[1].kind, 'debris', 'middle line classified debris');
    assert.strictEqual(chain.verdicts[1].usable, false, 'debris never usable');
    assert.strictEqual(chain.verdicts[2].usable, true, 'post-debris event usable');
    console.log('✔ Test 5 Passed: V2 debris-chain vector + skip mismatch.');
  }
  // Test 6: chain-break detection — modification, deletion, insertion,
  // reordering each break verifiability of everything after the break.
  {
    const mod = JSON.parse(V1_L1);
    mod.chainPrev = hex('9');
    const tamperedLine = canonicalStringify(mod);
    const c1 = A.verifyJournalChain([V1_L0, tamperedLine]);
    assert.strictEqual(c1.firstBreak, 1, 'modified link breaks at index 1');
    assert.strictEqual(c1.verdicts[1].reason, 'chain-link-break', 'break reason');
    const c2 = A.verifyJournalChain([V1_L1]);
    assert.strictEqual(c2.firstBreak, 0, 'orphan event (deleted predecessor) breaks at 0');
    const c3 = A.verifyJournalChain([V1_L0, V1_L0]);
    assert.strictEqual(c3.firstBreak, 1, 'duplicated line breaks (chainPrev mismatch)');
    const c4 = A.verifyJournalChain([V1_L1, V1_L0]);
    assert.strictEqual(c4.firstBreak, 0, 'reordered lines break at 0');
    const c5 = A.verifyJournalChain([V1_L0, V1_L1, tamperedLine]);
    assert.strictEqual(c5.firstBreak, 2, 'late break detected');
    assert.strictEqual(c5.verdicts[0].usable, true, 'pre-break stays usable');
    console.log('✔ Test 6 Passed: chain-break detection.');
  }

  // Test 7: acknowledgment usability — live byte re-verification.
  {
    const dir = freshTmp('ackuse');
    const paths = A.storePaths(dir);
    fs.writeFileSync(paths.attestations, 'NOT-JSON\n');
    const read = A.readStoreFile(paths.attestations);
    assert.strictEqual(read.malformed.length, 1, 'malformed recorded');
    const debris = read.malformed[0];
    const ackId = A.acknowledgmentId({ store: 'attestations', offset: debris.offset, length: debris.length, bytesSha256: debris.sha256 });
    const ack = A.buildAcknowledgment({
      store: 'attestations', offset: debris.offset, length: debris.length, bytesSha256: debris.sha256,
      classification: 'foreign-debris', rationale: 'test ack', operator: 'tester', at: NOW, chainPrev: A.GENESIS_STATE
    });
    assert.strictEqual(ack.ackId, ackId, 'ack id deterministic');
    const journalEval = A.evaluateJournal([{ bytes: Buffer.from(canonicalStringify(ack), 'utf8'), text: canonicalStringify(ack) }]);
    const readOriginal = (s, o, l) => A.originalBytesAt(dir, s, o, l);
    const use = A.usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
    assert.strictEqual(use.usable, true, 'ack usable while bytes match');
    fs.writeFileSync(paths.attestations, 'CHANGED!!\n');
    const use2 = A.usableAckFor(journalEval, ackId, { readOriginalBytes: readOriginal });
    assert.strictEqual(use2.usable, false, 'byte change invalidates ack');
    assert.strictEqual(use2.reason, 'original-changed', 'reason reported');
    const use3 = A.usableAckFor(journalEval, `attrec_${hex('0')}`, { readOriginalBytes: readOriginal });
    assert.strictEqual(use3.reason, 'no-acknowledgment', 'missing ack reported');
    console.log('✔ Test 7 Passed: acknowledgment usability + live re-verification.');
  }

  // Test 8: contested acks — same id, different substance → unusable
  // until a chained amendment endorses exactly one copy.
  {
    const mkAck = (rationale, chainPrev) => canonicalStringify(A.buildAcknowledgment({
      store: 'audit', offset: 5, length: 12, bytesSha256: hex('c'),
      classification: 'foreign-debris', rationale, operator: 'tester', at: NOW, chainPrev
    }));
    const lineA = mkAck('first rationale', A.GENESIS_STATE);
    const stateA = A.chainAdvance(A.GENESIS_STATE, lineA);
    const lineB = mkAck('second rationale', stateA);
    const journalEval = A.evaluateJournal([lineA, lineB]);
    const ackId = JSON.parse(lineA).ackId;
    assert.strictEqual(JSON.parse(lineB).ackId, ackId, 'same identity, different bytes');
    assert.ok(journalEval.contested.has(ackId), 'id contested');
    const use = A.usableAckFor(journalEval, ackId, { readOriginalBytes: () => Buffer.alloc(0) });
    assert.strictEqual(use.reason, 'contested-unresolved', 'contested without amendment unusable');
    const endorsedSha = sha256Hex(Buffer.from(lineA, 'utf8'));
    const amendState = A.chainAdvance(stateA, lineB);
    const amendment = A.buildAmendment({
      amendsAckId: ackId, endorsedRecordSha256: endorsedSha, newRationale: 'endorse first', newClassification: null,
      operator: 'tester', at: NOW, chainPrev: amendState
    });
    const lineC = canonicalStringify(amendment);
    const journalEval2 = A.evaluateJournal([lineA, lineB, lineC]);
    assert.ok(!journalEval2.contested.has(ackId) || journalEval2.endorsed.has(ackId), 'amendment resolves');
    const use2 = A.usableAckFor(journalEval2, ackId, { readOriginalBytes: () => Buffer.alloc(0) });
    assert.strictEqual(use2.usable, false, 'still unusable: original bytes absent here');
    assert.strictEqual(use2.reason, 'original-changed', 'resolution reached byte check (proves endorsement path)');
    console.log('✔ Test 8 Passed: contested acks + amendment resolution.');
  }

  // Test 9: amendment identity — Case A (exact duplicate), Case B
  // (timestamp-only), Case D (new id); Case C forgery rejected by shape.
  {
    const dir = freshTmp('amend');
    const paths = A.storePaths(dir);
    fs.writeFileSync(paths.attestations, 'DEBRIS-LINE\n');
    const read = A.readStoreFile(paths.attestations);
    const debris = read.malformed[0];
    const lock = A.acquireCeremonyLock(dir, { opId: null });
    let recorded;
    try {
      recorded = A.processAcknowledgments({
        lock, paths, storeDir: dir,
        requests: [{
          store: 'attestations', offset: debris.offset, length: debris.length, bytesSha256: debris.sha256,
          classification: 'foreign-debris', rationale: 'original', operator: 'op1'
        }],
        now: NOW, opId: null
      });
    } finally {
      A.releaseCeremonyLock(lock);
    }
    assert.strictEqual(recorded.length, 1, 'ack recorded');
    assert.strictEqual(recorded[0].appended, true, 'first write appends');
    const ackId = recorded[0].ackId;
    const journalLines = A.readStoreFile(paths.journal).lines.map((l) => canonicalStringify(l.parsed));
    const endorsedSha = sha256Hex(Buffer.from(journalLines[0], 'utf8'));
    const args = { storeDir: dir, amendsAckId: ackId, endorsedRecordSha256: endorsedSha, newRationale: 'refined', newClassification: null, operator: 'op1' };
    const first = A.appendAmendment({ ...args, at: NOW });
    assert.strictEqual(first.appended, true, 'amendment appended');
    const dup = A.appendAmendment({ ...args, at: NOW + 999 });
    assert.strictEqual(dup.appended, false, 'Case B timestamp-only resubmission is idempotent');
    assert.strictEqual(dup.amendmentId, first.amendmentId, 'same id');
    const again = A.appendAmendment({ ...args, at: NOW });
    assert.strictEqual(again.appended, false, 'Case A exact duplicate is idempotent');
    const genuine = A.appendAmendment({ ...args, newRationale: 'further refined', at: NOW + 1000 });
    assert.strictEqual(genuine.appended, true, 'Case D substantive change appends');
    assert.notStrictEqual(genuine.amendmentId, first.amendmentId, 'Case D gets a new id');
    const forged = { ...first.amendment, newRationale: 'forged', amendmentId: first.amendmentId };
    await expectAttestCode(() => A.assertAmendmentShape(forged), 'ATTEST_INVALID', 'Case C forgery (id/content mismatch) rejected');
    await expectAttestCode(() => A.appendAmendment({ ...args, amendsAckId: `attrec_${hex('7')}`, newRationale: 'x', at: NOW }), 'ATTEST_AMEND_DANGLING', 'dangling amends refused');
    await expectAttestCode(() => A.appendAmendment({ ...args, endorsedRecordSha256: hex('8'), newRationale: 'x', at: NOW }), 'ATTEST_AMEND_DANGLING', 'endorsement of unknown bytes refused');
    console.log('✔ Test 9 Passed: amendment idempotency, conflicts, dangling refs.');
  }

  // Test 10: notes — content-addressed, dangling refs refused, duplicates
  // idempotent (timestamp/position differences never conflict).
  {
    const dir = freshTmp('notes');
    const n1 = A.appendNote({ storeDir: dir, refAckId: null, text: 'free note', operator: 'op1', at: NOW });
    assert.strictEqual(n1.appended, true, 'note appended');
    const n2 = A.appendNote({ storeDir: dir, refAckId: null, text: 'free note', operator: 'op1', at: NOW + 5000 });
    assert.strictEqual(n2.appended, false, 'resubmission idempotent');
    assert.strictEqual(n2.noteId, n1.noteId, 'same content id');
    await expectAttestCode(() => A.appendNote({ storeDir: dir, refAckId: `attrec_${hex('7')}`, text: 'x', operator: 'op1', at: NOW }), 'ATTEST_NOTE_DANGLING', 'dangling ref refused');
    console.log('✔ Test 10 Passed: journal notes.');
  }

  // Test 11: classifier soundness property — EVERY truncation of every
  // legitimate line kind is AMBIGUOUS (never FOREIGN). Proves an
  // interrupted legitimate write can never be auto-dismissed.
  {
    const day = A.generateAttestationKey();
    const opId = A.attestationOpId(hex('a'), day.address);
    const body = A.buildAttestationBody({ manifestDigest: hex('a'), investigationId: 'eval_1', traceId: 'tr_1', requestId: 'unicode-✓-test', keyId: day.address, issuedAt: NOW });
    const att = await A.signAttestation({ body, privateKey: day.privateKey });
    const storeLine = canonicalStringify(A.buildAttestationStoreLine({ attestation: att, opId, recordedAt: NOW }));
    const auditLine = canonicalStringify(A.buildAuditEvent({
      opId, manifestDigest: hex('a'), keyId: day.address, investigationId: 'eval_1', decision: 'ALLOW "quoted" \\ escaped ✓',
      registryVersion: 3, warnings: ['w1', 'w"2'], reconciliationRefs: [`attrec_${hex('1')}`],
      lockBroken: { prevAge: 5, prevPid: 123, quarantined: 'q.lock' }, at: NOW
    }));
    const auditNullLock = canonicalStringify(A.buildAuditEvent({
      opId, manifestDigest: hex('a'), keyId: day.address, investigationId: 'eval_1', decision: 'BLOCK',
      registryVersion: 0, warnings: [], reconciliationRefs: [], lockBroken: null, at: NOW
    }));
    const ackLine = canonicalStringify(A.buildAcknowledgment({
      store: 'audit', offset: 0, length: 1, bytesSha256: hex('e'), classification: 'blank-line',
      rationale: 'r ✓', operator: 'op', manifestDigest: hex('f'), keyId: day.address, opId, at: NOW, chainPrev: hex('0')
    }));
    const ackNulls = canonicalStringify(A.buildAcknowledgment({
      store: 'journal', offset: 12, length: 0, bytesSha256: hex('e'), classification: 'torn-fragment',
      rationale: 'r', operator: 'op', manifestDigest: null, keyId: null, opId: null, at: NOW, chainPrev: hex('0')
    }));
    const amdLine = canonicalStringify(A.buildAmendment({
      amendsAckId: `attrec_${hex('1')}`, endorsedRecordSha256: hex('2'), newRationale: 'nr ✓', newClassification: 'blank-line',
      operator: 'op', at: NOW, chainPrev: hex('0')
    }));
    const noteLine = canonicalStringify(A.buildNote({ refAckId: `attrec_${hex('1')}`, text: 'note ✓ "q"', operator: 'op', at: NOW, chainPrev: hex('0') }));
    const cases = [
      ['attestations', storeLine], ['audit', auditLine], ['audit', auditNullLock],
      ['journal', ackLine], ['journal', ackNulls], ['journal', amdLine], ['journal', noteLine],
      ['journal', V1_L0]
      // NOTE: V2_DEBRIS is foreign data by design, not a legitimate
      // line — its full bytes classify FOREIGN (see Test 12).
    ];
    let checked = 0;
    for (const [store, line] of cases) {
      const bytes = Buffer.from(line, 'utf8');
      for (let cut = 1; cut < bytes.length; cut += 1) {
        const frag = bytes.subarray(0, cut);
        const verdict = A.classifyFragment(store, frag);
        assert.strictEqual(verdict.verdict, 'AMBIGUOUS', `${store} truncation @${cut}/${bytes.length} must be AMBIGUOUS (got ${verdict.verdict}:${verdict.reason})`);
        checked += 1;
      }
    }
    assert.ok(checked > 3000, `property swept ${checked} truncations`);
    console.log(`✔ Test 11 Passed: classifier soundness over ${checked} truncations.`);
  }

  // Test 12: classifier foreign verdicts — bytes our writer can never
  // produce are FOREIGN (with the exact reason).
  {
    const foreign = [
      ['attestations', Buffer.from('GARBAGE', 'utf8'), 'not-a-line-prefix'],
      ['attestations', Buffer.from('{"attestation":—,}', 'utf8'), 'not-a-line-prefix'],
      ['audit', Buffer.from('{"at":12x}', 'utf8'), 'not-a-line-prefix'],
      ['audit', Buffer.from('{"at":007}', 'utf8'), 'not-a-line-prefix'],
      ['journal', Buffer.from([0xff, 0xfe, 0x41]), 'invalid-utf8'],
      ['journal', Buffer.from('{"ackId":"nope"', 'utf8'), 'not-a-line-prefix'],
      ['attestations', Buffer.from('{"a":"b\x01c"}', 'utf8'), 'control-byte'],
      ['journal', Buffer.from(V2_DEBRIS, 'utf8'), 'not-a-line-prefix']
    ];
    for (const [store, bytes, reason] of foreign) {
      const v = A.classifyFragment(store, bytes);
      assert.strictEqual(v.verdict, 'FOREIGN', `${store} ${JSON.stringify(bytes.toString('utf8').slice(0, 24))} FOREIGN`);
      assert.strictEqual(v.reason, reason, 'reason exact');
    }
    await expectAttestCode(() => A.classifyFragment('nope', Buffer.from('x')), 'ATTEST_INVALID', 'unknown store refused');
    await expectAttestCode(() => A.classifyFragment('audit', 'not-a-buffer'), 'ATTEST_INVALID', 'non-Buffer refused');
    console.log('✔ Test 12 Passed: classifier foreign verdicts.');
  }

  // Test 13: store I/O — prefix-tolerant reads, empty store valid,
  // durable append verify, delimiter repair by pure append.
  {
    const dir = freshTmp('storeio');
    const paths = A.storePaths(dir);
    const missing = A.readStoreFile(paths.attestations);
    assert.strictEqual(missing.exists, false, 'missing file reported');
    assert.strictEqual(missing.lines.length, 0, 'missing = empty');
    fs.writeFileSync(paths.attestations, '');
    const empty = A.readStoreFile(paths.attestations);
    assert.strictEqual(empty.exists, true, 'empty file exists');
    assert.strictEqual(empty.lines.length, 0, 'empty store valid, zero records');
    const r1 = A.durableAppend(paths.attestations, '{"a":1}', {});
    assert.strictEqual(r1.offset, 0, 'first offset');
    const r2 = A.durableAppend(paths.attestations, '{"a":2}', {});
    assert.strictEqual(r2.offset, 8, 'second offset after 8 bytes');
    const reread = A.readStoreFile(paths.attestations);
    assert.strictEqual(reread.lines.length, 2, 'two lines');
    assert.strictEqual(reread.lines[1].offset, 8, 'offset tracked');
    assert.strictEqual(reread.lines[1].sha256, sha256Hex(Buffer.from('{"a":2}', 'utf8')), 'line sha tracked');
    fs.appendFileSync(paths.attestations, '{"torn": tru');
    const torn = A.readStoreFile(paths.attestations);
    assert.ok(torn.tail !== null && torn.tail.length === 12, 'torn tail captured');
    const before = fs.readFileSync(paths.attestations);
    assert.strictEqual(A.appendDelimiterIfNeeded(paths.attestations), true, 'delimiter written');
    const after = fs.readFileSync(paths.attestations);
    assert.ok(after.subarray(0, before.length).equals(before), 'zero existing bytes touched');
    assert.strictEqual(after[after.length - 1], 10, 'newline appended');
    assert.strictEqual(A.appendDelimiterIfNeeded(paths.attestations), false, 'no-op when terminated');
    await expectAttestCode(() => A.durableAppend(paths.attestations, 'has\nnewline', {}), 'ATTEST_INVALID', 'embedded newline refused');
    console.log('✔ Test 13 Passed: store I/O + delimiter repair.');
  }

  // Test 14: registry lifecycle — monotonic versions, monotonic key
  // states, terminal states never leave, illegal transitions refused.
  {
    const root = A.generateAttestationKey();
    const k1 = A.generateAttestationKey();
    const k2 = A.generateAttestationKey();
    const v0 = await signedRegistry({}, root.privateKey, 0, T0);
    const v0check = await A.verifyRegistry({ registry: v0, trustedRoot: root.address, now: NOW });
    assert.strictEqual(v0check.ok, true, 'v0 verifies');
    const v1unsigned = A.prepareRegistryUpdate(v0, {
      add: { [k1.address]: activeEntry('day key 1', T0 + 10) }, publishedAt: T0 + 10, retire: {}, revoke: {}, version: 1
    });
    const v1 = await A.signRegistry({ registry: v1unsigned, rootPrivateKey: root.privateKey });
    assert.strictEqual((await A.verifyRegistry({ registry: v1, trustedRoot: root.address, now: NOW })).ok, true, 'v1 verifies');
    const v2unsigned = A.prepareRegistryUpdate(v1, {
      add: { [k2.address]: activeEntry('day key 2', T0 + 20) }, publishedAt: T0 + 20,
      retire: { [k1.address]: { reason: 'rotation', status: 'RETIRED', statusChangedAt: T0 + 20, supersededBy: k2.address, validFrom: T0 + 10 } },
      revoke: {}, version: 2
    });
    const v2 = await A.signRegistry({ registry: v2unsigned, rootPrivateKey: root.privateKey });
    assert.strictEqual(v2.keys[k1.address].status, 'RETIRED', 'retired recorded');
    // Illegal transitions.
    await expectAttestCode(() => A.prepareRegistryUpdate(v2, {
      add: { [k1.address]: activeEntry('rehab', T0 + 30) }, publishedAt: T0 + 30, retire: {}, revoke: {}, version: 3
    }), 'ATTEST_INVALID', 're-adding a retired key refused');
    await expectAttestCode(() => A.prepareRegistryUpdate(v2, {
      add: {}, publishedAt: T0 + 30, retire: {}, revoke: { [k2.address]: { reason: 'x', status: 'ACTIVE', statusChangedAt: T0 + 30, supersededBy: null, validFrom: T0 + 20 } }, version: 3
    }), 'ATTEST_INVALID', 'revoke with non-terminal status refused');
    await expectAttestCode(() => A.prepareRegistryUpdate(v2, {
      add: {}, publishedAt: T0 + 30, retire: {}, revoke: {}, version: 5
    }), 'ATTEST_INVALID', 'version skip refused');
    const v3unsigned = A.prepareRegistryUpdate(v2, {
      add: {}, publishedAt: T0 + 30, retire: {},
      revoke: { [k1.address]: { reason: 'lost fob', status: 'COMPROMISED', statusChangedAt: T0 + 30, supersededBy: k2.address, validFrom: T0 + 10 } },
      version: 3
    });
    const v3 = await A.signRegistry({ registry: v3unsigned, rootPrivateKey: root.privateKey });
    await expectAttestCode(() => A.prepareRegistryUpdate(v3, {
      add: {}, publishedAt: T0 + 40, retire: { [k1.address]: { reason: 'back', status: 'RETIRED', statusChangedAt: T0 + 40, supersededBy: null, validFrom: T0 + 10 } },
      revoke: {}, version: 4
    }), 'ATTEST_INVALID', 'compromised key can never be rehabilitated');
    // Registry tamper + trust checks.
    const tampered = JSON.parse(JSON.stringify(v1));
    tampered.keys[k1.address].status = 'REVOKED';
    const tcheck = await A.verifyRegistry({ registry: tampered, trustedRoot: root.address, now: NOW });
    assert.strictEqual(tcheck.ok, false, 'tampered registry rejected');
    const wrongRoot = await A.verifyRegistry({ registry: v1, trustedRoot: k2.address, now: NOW });
    assert.strictEqual(wrongRoot.code, 'registry-invalid', 'wrong root rejected');
    const rollback = await A.verifyRegistry({ registry: v0, trustedRoot: root.address, minVersion: 1, now: NOW });
    assert.strictEqual(rollback.code, 'registry-rollback', 'rollback below minimum rejected');
    const stale = await A.verifyRegistry({ registry: v0, trustedRoot: root.address, maxAgeDays: 1, now: T0 + 2 * 86400000 });
    assert.strictEqual(stale.code, 'stale-registry', 'stale registry rejected');
    const staleOk = await A.verifyRegistry({ registry: v0, trustedRoot: root.address, maxAgeDays: 1, allowStale: true, now: T0 + 2 * 86400000 });
    assert.strictEqual(staleOk.ok, true, 'explicit stale override allowed');
    console.log('✔ Test 14 Passed: registry lifecycle + trust checks.');
  }

  // Test 15: verifyAttestation — every outcome code.
  {
    const day = A.generateAttestationKey();
    const root = A.generateAttestationKey();
    const { pkg, manifestDigest } = buildPackage(baseRecord(), baseRequest());
    const manifest = pkg.manifest;
    const body = A.buildAttestationBody({
      manifestDigest, investigationId: manifest.investigationId, traceId: manifest.traceId,
      requestId: manifest.requestId, keyId: day.address, issuedAt: NOW
    });
    const att = await A.signAttestation({ body, privateKey: day.privateKey });
    const reg = await signedRegistry({ [day.address]: activeEntry('day', T0) }, root.privateKey, 0, NOW);
    const trust = { manifest, attestation: att, trustedAuthorities: [day.address], keyRegistry: reg, trustedRoot: root.address, now: NOW + 1000 };
    assert.strictEqual((await A.verifyAttestation(trust)).code, 'valid', 'happy path valid');
    const badSig = JSON.parse(JSON.stringify(att));
    badSig.signature = `0x${'11'.repeat(65)}`;
    assert.strictEqual((await A.verifyAttestation({ ...trust, attestation: badSig })).code, 'invalid-signature', 'bad signature');
    assert.strictEqual((await A.verifyAttestation({ ...trust, trustedAuthorities: [] })).code, 'unknown-key', 'empty trust list');
    assert.strictEqual((await A.verifyAttestation({ ...trust, trustedAuthorities: [root.address] })).code, 'unknown-key', 'unlisted authority');
    assert.strictEqual((await A.verifyAttestation({ ...trust, keyRegistry: null })).code, 'registry-missing', 'registry required');
    const edited = JSON.parse(JSON.stringify(manifest));
    edited.traceId = 'tr_other';
    assert.strictEqual((await A.verifyAttestation({ ...trust, manifest: edited })).code, 'digest-mismatch', 'edited manifest mismatches digest');
    const wrongAlg = JSON.parse(JSON.stringify(att));
    wrongAlg.algorithm = 'rsa-1';
    assert.strictEqual((await A.verifyAttestation({ ...trust, attestation: wrongAlg })).code, 'unsupported-algorithm', 'unknown algorithm');
    const future = JSON.parse(JSON.stringify(att));
    future.body.issuedAt = NOW + 3600000;
    const futureSig = await A.signAttestation({ body: future.body, privateKey: day.privateKey });
    assert.strictEqual((await A.verifyAttestation({ ...trust, attestation: futureSig })).code, 'context-mismatch', 'future issuedAt');
    // Key states.
    const retiredReg = await signedRegistry(
      { [day.address]: { reason: 'rotated', status: 'RETIRED', statusChangedAt: NOW + 500, supersededBy: null, validFrom: T0 } },
      root.privateKey, 1, NOW
    );
    assert.strictEqual((await A.verifyAttestation({ ...trust, keyRegistry: retiredReg })).code, 'retired-uncorroborated', 'retired needs corroboration');
    const hist = await A.verifyAttestation({ ...trust, keyRegistry: retiredReg, corroboration: { type: 'release', ref: 'v1.2.3' } });
    assert.strictEqual(hist.code, 'trusted-historical', 'retired + corroboration trusted-historical');
    assert.strictEqual(hist.corroboration.assertedBy, 'caller', 'corroboration labeled caller-asserted');
    const revokedReg = await signedRegistry(
      { [day.address]: { reason: 'abuse', status: 'REVOKED', statusChangedAt: NOW + 500, supersededBy: null, validFrom: T0 } },
      root.privateKey, 1, NOW
    );
    assert.strictEqual((await A.verifyAttestation({ ...trust, keyRegistry: revokedReg })).code, 'revoked-key', 'revoked untrusted');
    const overridden = await A.verifyAttestation({ ...trust, keyRegistry: revokedReg, acceptRevoked: true });
    assert.strictEqual(overridden.overridden, true, 'revocation override explicit and labeled');
    assert.strictEqual(overridden.ok, false, 'override still not ok');
    const compReg = await signedRegistry(
      { [day.address]: { reason: 'stolen', status: 'COMPROMISED', statusChangedAt: NOW + 500, supersededBy: null, validFrom: T0 } },
      root.privateKey, 1, NOW
    );
    assert.strictEqual((await A.verifyAttestation({ ...trust, keyRegistry: compReg })).code, 'compromised-key', 'compromised untrusted');
    console.log('✔ Test 15 Passed: verifyAttestation outcome matrix.');
  }

  // Test 16: case classifier + execution grades (unit-level, all letters).
  {
    const mkManifest = (decision, tx, museContribution, samContribution) => ({
      decision, transaction: tx,
      modelCalls: { museSpark: { contribution: museContribution }, sam: { contribution: samContribution } }
    });
    const receiptTx = { transactionHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x1', chainId: 31337 };
    const unverifiedTx = { transactionHash: TXHASH, receiptStatus: null, blockNumber: null, chainId: 31337 };
    const noTx = { transactionHash: null, receiptStatus: null, blockNumber: null, chainId: null };
    assert.strictEqual(A.executionGrade({ transaction: receiptTx }), 'receipt-backed', 'receipt grade');
    assert.strictEqual(A.executionGrade({ transaction: unverifiedTx }), 'unverified', 'unverified grade');
    assert.strictEqual(A.executionGrade({ transaction: noTx }), 'none', 'none grade');
    const full = ['VERDICT_ACCEPTED', 'VALIDATED_AGAINST'];
    assert.strictEqual(A.classifyPackageCase({ manifest: mkManifest({ agent: 'ALLOW' }, receiptTx, ...full), superseded: false }).case, 'D', 'post-execution = D');
    assert.strictEqual(A.classifyPackageCase({ manifest: mkManifest({ agent: 'ALLOW' }, noTx, ...full), superseded: false }).case, 'C', 'pre-execution = C');
    assert.strictEqual(A.classifyPackageCase({ manifest: mkManifest({ agent: 'BLOCK' }, noTx, ...full), superseded: false }).case, 'E', 'block = E');
    assert.strictEqual(A.classifyPackageCase({ manifest: mkManifest({ agent: 'REVIEW' }, noTx, ...full), superseded: false }).case, 'E', 'review = E');
    const f = A.classifyPackageCase({ manifest: mkManifest({ agent: 'ALLOW' }, unverifiedTx, ...full), superseded: false });
    assert.strictEqual(f.case, 'F', 'unverified execution = F');
    assert.strictEqual(f.action, 'extra-confirm', 'F needs extra confirmation');
    const g = A.classifyPackageCase({ manifest: mkManifest({ agent: 'ALLOW' }, receiptTx, ...full), superseded: true });
    assert.strictEqual(g.case, 'G', 'superseded = G');
    assert.strictEqual(g.action, 'refuse', 'G refuses by default');
    const b = A.classifyPackageCase({ manifest: mkManifest({ agent: 'ALLOW' }, receiptTx, 'NOT_INVOKED', 'NOT_INVOKED'), superseded: false });
    assert.strictEqual(b.incompleteEvidence, true, 'incomplete evidence flagged (B condition)');
    assert.ok(b.notes.some((n) => n.includes('incomplete model evidence')), 'B note present');
    const a = A.classifyPackageCase({ manifest: mkManifest({ agent: 'UNCERTAIN' }, noTx, ...full), superseded: false });
    assert.strictEqual(a.case, 'A', 'fallback = A');
    console.log('✔ Test 16 Passed: case classifier + grades.');
  }

  // Test 17: ceremony happy path — preview, confirm, stores, adoption.
  {
    const fx = await ceremonyEnv({});
    const preview = await A.attestPackage({ ...fx.baseOpts, confirm: false });
    assert.strictEqual(preview.attested, false, 'preview never attests');
    assert.strictEqual(preview.phase, 'preview', 'preview phase');
    assert.strictEqual(preview.preview.manifestDigest, fx.manifestDigest, 'preview shows full digest');
    assert.strictEqual(preview.preview.case, 'D', 'preview case');
    assert.strictEqual(preview.lockReleased, true, 'preview releases lock');
    assert.strictEqual(fs.existsSync(A.storePaths(fx.dir).attestations), false, 'preview writes nothing');
    const done = await A.attestPackage(fx.baseOpts);
    assert.strictEqual(done.attested, true, 'confirmed ceremony attests');
    assert.strictEqual(done.phase, 'completed', 'completed phase');
    assert.deepStrictEqual(done.adopted, { attestation: false, audit: false }, 'fresh signing');
    assert.strictEqual(done.lockReleased, true, 'lock released');
    const paths = A.storePaths(fx.dir);
    assert.strictEqual(A.readStoreFile(paths.attestations).lines.length, 1, 'one attestation line');
    assert.strictEqual(A.readStoreFile(paths.audit).lines.length, 1, 'one audit line');
    assert.strictEqual(A.readStoreFile(paths.journal).lines.length, 0, 'journal untouched on clean run');
    const retry = await A.attestPackage(fx.baseOpts);
    assert.strictEqual(retry.attested, true, 'retry attests');
    assert.deepStrictEqual(retry.adopted, { attestation: true, audit: true }, 'retry adopts both');
    assert.strictEqual(retry.attestation.signature, done.attestation.signature, 'same signature adopted (no re-sign)');
    assert.strictEqual(A.readStoreFile(paths.attestations).lines.length, 1, 'no duplicate attestation');
    assert.strictEqual(A.readStoreFile(paths.audit).lines.length, 1, 'no duplicate audit');
    // verifyCompletion authoritatively confirms; status stays observational.
    const v = await A.verifyCompletion({ storeDir: fx.dir, manifestDigest: fx.manifestDigest, keyId: fx.day.address });
    assert.strictEqual(v.attested, true, 'completion verifies');
    assert.strictEqual(v.identities.length, 1, 'one identity');
    const s = A.ceremonyStatus({ storeDir: fx.dir, manifestDigest: fx.manifestDigest });
    assert.strictEqual(s.observational, true, 'status labeled observational');
    assert.strictEqual(s.attested, undefined, 'status never claims attested');
    assert.strictEqual(s.identitiesObserved.length, 1, 'identity observed');
    console.log('✔ Test 17 Passed: ceremony happy path + idempotent retry.');
  }

  // Test 18: ceremony input gates — package, digest, lock, registry, key.
  {
    const fx = await ceremonyEnv({});
    const badPkg = JSON.parse(JSON.stringify(fx.pkg));
    badPkg.publicProjection = { forged: true };
    const r1 = await A.attestPackage({ ...fx.baseOpts, pkg: badPkg });
    assert.strictEqual(r1.phase, 'package-invalid', 'forged package refused');
    assert.ok(r1.failedChecks.length > 0, 'failed checks listed');
    const r2 = await A.attestPackage({ ...fx.baseOpts, expectDigest: hex('9') });
    assert.strictEqual(r2.phase, 'digest-mismatch', 'wrong expect-digest refused');
    const r2b = await A.attestPackage({ ...fx.baseOpts, expectDigest: fx.manifestDigest.slice(0, 32) });
    assert.strictEqual(r2b.phase, 'input-invalid', 'truncated expect-digest refused (full digest required)');
    const r3 = await A.attestPackage({ ...fx.baseOpts, privateKey: 'nope' });
    assert.strictEqual(r3.phase, 'input-invalid', 'bad key refused pre-lock');
    // Lock held.
    const holder = A.acquireCeremonyLock(fx.dir, { opId: null });
    try {
      const r4 = await A.attestPackage(fx.baseOpts);
      assert.strictEqual(r4.phase, 'lock-held', 'concurrent ceremony refused');
      assert.ok(r4.holder && typeof r4.holder.pid === 'number', 'holder info exposed');
    } finally {
      A.releaseCeremonyLock(holder);
    }
    // Registry + key gates.
    const staleFx = await ceremonyEnv({ publishedAt: T0 - 200 * 86400000 });
    const r5 = await A.attestPackage(staleFx.baseOpts);
    assert.strictEqual(r5.phase, 'registry', 'stale registry refused');
    const r5b = await A.attestPackage({ ...staleFx.baseOpts, allowStaleRegistry: true });
    assert.strictEqual(r5b.attested, true, 'explicit stale override proceeds');
    const r6 = await A.attestPackage({ ...fx.baseOpts, minRegistryVersion: 99 });
    assert.strictEqual(r6.phase, 'registry', 'rollback floor enforced');
    const stranger = A.generateAttestationKey();
    const r7 = await A.attestPackage({ ...fx.baseOpts, privateKey: stranger.privateKey, trustedAuthorities: [stranger.address] });
    assert.strictEqual(r7.phase, 'key', 'unregistered key refused');
    const retiredFx = await ceremonyEnv({ keyState: 'RETIRED' });
    const r8 = await A.attestPackage(retiredFx.baseOpts);
    assert.strictEqual(r8.phase, 'key', 'non-ACTIVE key refused');
    const r9 = await A.attestPackage({ ...fx.baseOpts, trustedAuthorities: [stranger.address] });
    assert.strictEqual(r9.phase, 'key', 'unlisted key refused');
    const r10 = await A.attestPackage({ ...fx.baseOpts, denyList: [fx.day.address] });
    assert.strictEqual(r10.phase, 'key', 'deny-listed key refused');
    const r11 = await A.attestPackage({ ...fx.baseOpts, privateKey: fx.root.privateKey, trustedAuthorities: [fx.root.address] });
    assert.strictEqual(r11.phase, 'key', 'root key refused as day key');
    console.log('✔ Test 18 Passed: ceremony input/key/registry gates.');
  }

  // Test 19: ceremony continuity + case actions — superseded, unverified,
  // BLOCK/REVIEW signing, bare-digest refusal.
  {
    const fx = await ceremonyEnv({});
    const unknown = await A.attestPackage({ ...fx.baseOpts, manifestStore: path.join(fx.dir, 'empty.jsonl') });
    assert.strictEqual(unknown.phase, 'continuity', 'manifest absent from store refused (no bare-digest signing)');
    // Superseded: append a second manifest for the same investigation.
    const rec2 = baseRecord();
    rec2.recordedAt = T0 + 50;
    const req2 = baseRequest();
    const built2 = buildManifest({ record: rec2, request: req2 });
    saveManifest(built2, fx.manifestStore);
    const g = await A.attestPackage(fx.baseOpts);
    assert.strictEqual(g.phase, 'refused-superseded', 'superseded refused by default');
    assert.strictEqual(g.preview.case, 'G', 'preview shows G');
    const g2 = await A.attestPackage({ ...fx.baseOpts, allowSuperseded: true });
    assert.strictEqual(g2.attested, true, 'explicit superseded override proceeds');
    // Unverified execution.
    const reqU = baseRequest();
    reqU.execution = { outcome: 'EXECUTED_UNVERIFIED', txHash: TXHASH, receiptStatus: null, blockNumber: null };
    const fxU = await ceremonyEnv({ request: reqU });
    const f = await A.attestPackage(fxU.baseOpts);
    assert.strictEqual(f.phase, 'refused-unverified-confirmation', 'unverified execution refused by default');
    assert.strictEqual(f.preview.case, 'F', 'preview shows F');
    const f2 = await A.attestPackage({ ...fxU.baseOpts, allowUnverifiedExecution: true });
    assert.strictEqual(f2.attested, true, 'explicit unverified override proceeds');
    // BLOCK and unreleased REVIEW sign normally (case E, no transaction).
    const recB = baseRecord();
    recB.policyDecision = { decision: 'BLOCK', reasons: ['outside mandate'] };
    recB.recommendedAction = 'ABORT';
    const reqB = baseRequest();
    reqB.decision = 'BLOCK';
    reqB.status = 'BLOCKED';
    delete reqB.execution;
    const fxB = await ceremonyEnv({ record: recB, request: reqB });
    const b = await A.attestPackage(fxB.baseOpts);
    assert.strictEqual(b.attested, true, 'BLOCK attests (case E)');
    assert.strictEqual(b.preview.case, 'E', 'BLOCK previews as E');
    assert.strictEqual(b.preview.transaction.transactionHash, null, 'no hash attached to BLOCK');
    const recR = baseRecord();
    recR.policyDecision = { decision: 'REVIEW', reasons: ['needs operator'] };
    const reqR = baseRequest();
    reqR.decision = 'REVIEW';
    reqR.status = 'PENDING';
    delete reqR.execution;
    const fxR = await ceremonyEnv({ record: recR, request: reqR });
    const r = await A.attestPackage(fxR.baseOpts);
    assert.strictEqual(r.attested, true, 'unreleased REVIEW attests (case E)');
    assert.strictEqual(r.preview.case, 'E', 'REVIEW previews as E');
    console.log('✔ Test 19 Passed: continuity + case actions.');
  }

  // Test 20: crash recovery — attestation-without-audit completes the
  // audit; conflicts fail closed; original bytes never rewritten.
  {
    const fx = await ceremonyEnv({});
    const paths = A.storePaths(fx.dir);
    // Simulate crash after attestation persistence: valid attestation,
    // no audit event.
    const opId = A.attestationOpId(fx.manifestDigest, fx.day.address);
    const body = A.buildAttestationBody({
      manifestDigest: fx.manifestDigest, investigationId: fx.pkg.manifest.investigationId,
      traceId: fx.pkg.manifest.traceId, requestId: fx.pkg.manifest.requestId, keyId: fx.day.address, issuedAt: NOW
    });
    const att = await A.signAttestation({ body, privateKey: fx.day.privateKey });
    A.durableAppend(paths.attestations, canonicalStringify(A.buildAttestationStoreLine({ attestation: att, opId, recordedAt: NOW })), {});
    const resume = await A.attestPackage(fx.baseOpts);
    assert.strictEqual(resume.attested, true, 'crashed ceremony resumes to completion');
    assert.deepStrictEqual(resume.adopted, { attestation: true, audit: false }, 'attestation adopted, audit fresh');
    assert.strictEqual(resume.attestation.signature, att.signature, 'no conflicting re-signature');
    assert.strictEqual(A.readStoreFile(paths.attestations).lines.length, 1, 'still one attestation');
    assert.strictEqual(A.readStoreFile(paths.audit).lines.length, 1, 'one audit now');
    // Conflicting history fails closed.
    const fx2 = await ceremonyEnv({});
    const p2 = A.storePaths(fx2.dir);
    const op2 = A.attestationOpId(fx2.manifestDigest, fx2.day.address);
    const mkAtt = async (issuedAt) => A.signAttestation({
      body: A.buildAttestationBody({
        manifestDigest: fx2.manifestDigest, investigationId: fx2.pkg.manifest.investigationId,
        traceId: fx2.pkg.manifest.traceId, requestId: fx2.pkg.manifest.requestId, keyId: fx2.day.address, issuedAt
      }),
      privateKey: fx2.day.privateKey
    });
    const a1 = await mkAtt(NOW);
    const a2 = await mkAtt(NOW + 1);
    A.durableAppend(p2.attestations, canonicalStringify(A.buildAttestationStoreLine({ attestation: a1, opId: op2, recordedAt: NOW })), {});
    A.durableAppend(p2.attestations, canonicalStringify(A.buildAttestationStoreLine({ attestation: a2, opId: op2, recordedAt: NOW + 1 })), {});
    const before = fs.readFileSync(p2.attestations);
    const conflict = await A.attestPackage(fx2.baseOpts);
    assert.strictEqual(conflict.phase, 'conflict', 'distinct duplicate attestations fail closed');
    assert.ok(fs.readFileSync(p2.attestations).equals(before), 'conflicting history preserved byte-for-byte');
    assert.strictEqual(conflict.lockReleased, true, 'lock released on conflict');
    console.log('✔ Test 20 Passed: crash recovery + conflict fail-closed.');
  }

  // Test 21: integrity gate via ceremony — malformed, blank, ambiguous
  // tail block; acknowledgments unblock; foreign tails auto-proceed.
  {
    const fx = await ceremonyEnv({});
    const paths = A.storePaths(fx.dir);
    fs.writeFileSync(paths.attestations, 'NOT-JSON-AT ALL\n');
    fs.writeFileSync(paths.audit, '\n');
    const blocked = await A.attestPackage(fx.baseOpts);
    assert.strictEqual(blocked.phase, 'integrity-gate', 'corruption blocks ceremony');
    assert.strictEqual(blocked.details.blockers.length, 2, 'both stores report blockers');
    const acks = blocked.details.blockers.map((b) => ({
      store: b.store, offset: b.offset, length: b.length, bytesSha256: b.bytesSha256,
      classification: b.suggestedClassification, rationale: 'test acknowledgment', operator: 'tester'
    }));
    const unblocked = await A.attestPackage({ ...fx.baseOpts, acknowledge: acks });
    assert.strictEqual(unblocked.attested, true, 'acknowledged corruption unblocks');
    assert.strictEqual(unblocked.acksRecorded.length, 2, 'both acks recorded');
    assert.ok(unblocked.warnings.some((w) => w.includes('acknowledged')), 'ack warning in audit trail');
    // Mislabeling is refused.
    const fx2 = await ceremonyEnv({});
    const p2 = A.storePaths(fx2.dir);
    fs.writeFileSync(p2.attestations, 'BROKEN{\n');
    const b2 = await A.attestPackage(fx2.baseOpts);
    assert.strictEqual(b2.phase, 'integrity-gate', 'mislabel fixture blocks');
    const wrong = [{ ...b2.details.blockers[0], classification: 'blank-line', rationale: 'wrong', operator: 'tester' }];
    delete wrong.ackId;
    delete wrong.ackState;
    delete wrong.suggestedClassification;
    const refused = await A.attestPackage({ ...fx2.baseOpts, acknowledge: wrong });
    assert.strictEqual(refused.phase, 'acknowledgment', 'misclassified ack refused');
    // Foreign tail auto-proceeds with a warning, bytes preserved.
    const fx3 = await ceremonyEnv({});
    const p3 = A.storePaths(fx3.dir);
    fs.writeFileSync(p3.attestations, 'ZZZ-FOREIGN-TAIL');
    const beforeTail = fs.readFileSync(p3.attestations);
    const auto = await A.attestPackage(fx3.baseOpts);
    assert.strictEqual(auto.attested, true, 'foreign tail auto-proceeds');
    assert.ok(auto.warnings.some((w) => w.includes('foreign tail')), 'foreign-tail warning recorded');
    const afterTail = fs.readFileSync(p3.attestations);
    assert.ok(afterTail.subarray(0, beforeTail.length).equals(beforeTail), 'tail bytes preserved');
    console.log('✔ Test 21 Passed: integrity gate + acknowledgment flow.');
  }

  // Test 22: attachAttestation — v2 package linkage, mismatch refusal.
  {
    const fx = await ceremonyEnv({});
    const done = await A.attestPackage(fx.baseOpts);
    assert.strictEqual(done.attested, true, 'setup attests');
    const v2 = A.attachAttestation(fx.pkg, done.attestation);
    assert.strictEqual(v2.packageVersion, 'assertara-verify-2', 'v2 version tag');
    assert.strictEqual(v2.attestation.signature, done.attestation.signature, 'attestation attached');
    assert.strictEqual(fx.pkg.attestation, undefined, 'input package not mutated');
    assert.strictEqual(verifyPackage(v2).ok, true, 'v2 still passes Phase 2 verification');
    const trusted = await A.verifyAttestation({
      manifest: v2.manifest, attestation: v2.attestation, trustedAuthorities: [fx.day.address],
      keyRegistry: fx.registry, trustedRoot: fx.root.address, now: NOW + 1000
    });
    assert.strictEqual(trusted.code, 'valid', 'attached attestation verifies end-to-end');
    const otherRecord = baseRecord();
    otherRecord.recordedAt = T0 + 77;
    otherRecord.receivedAt = T0 - 1000 + 77;
    const otherFx = await ceremonyEnv({ record: otherRecord });
    assert.notStrictEqual(otherFx.manifestDigest, fx.manifestDigest, 'mismatch fixture differs');
    await expectAttestCode(() => A.attachAttestation(otherFx.pkg, done.attestation), 'ATTEST_MISMATCH', 'cross-manifest attach refused');
    console.log('✔ Test 22 Passed: v2 attach + linkage.');
  }

  // Test 23: lock lifecycle — acquire/fence/release, foreign release
  // refused, stale break with quarantine, live break refused.
  {
    const dir = freshTmp('lock');
    const paths = A.storePaths(dir);
    const lock = A.acquireCeremonyLock(dir, { opId: 'attop_note:advisory-only' });
    assert.ok(fs.existsSync(paths.lock), 'lock file created');
    assert.strictEqual(A.assertLockHeld(lock), true, 'fence passes while held');
    await expectAttestCode(() => A.acquireCeremonyLock(dir, {}), 'ATTEST_LOCK_HELD', 'second acquirer fails fast');
    const foreign = { path: paths.lock, token: '0'.repeat(32) };
    assert.strictEqual(A.releaseCeremonyLock(foreign).released, false, 'foreign release refused');
    assert.ok(fs.existsSync(paths.lock), 'lock survives foreign release');
    fs.unlinkSync(paths.lock);
    await expectAttestCode(() => A.assertLockHeld(lock), 'ATTEST_LOCK_LOST', 'fence detects loss');
    assert.strictEqual(A.releaseCeremonyLock(lock).reason, 'lock-absent', 'absent release reported');
    // Stale break: planted old lock for a dead pid.
    const staleContent = canonicalStringify({ hostname: 'test', opId: null, pid: 42424242, startedAt: NOW - 7200000, stores: [], token: 'a'.repeat(32) });
    fs.writeFileSync(paths.lock, `${staleContent}\n`);
    const broke = A.breakStaleLock(dir, { maxAgeMs: 1000, now: NOW });
    assert.strictEqual(broke.broken, true, 'demonstrably stale lock broken');
    assert.ok(!fs.existsSync(paths.lock), 'lock path cleared');
    assert.strictEqual(fs.readFileSync(broke.quarantined, 'utf8'), `${staleContent}\n`, 'quarantine preserves bytes');
    const fresh = A.acquireCeremonyLock(dir, {});
    try {
      await expectAttestCode(() => A.breakStaleLock(dir, { maxAgeMs: 3600000, now: Date.now() }), 'ATTEST_LOCK_LIVE', 'live lock break refused');
    } finally {
      A.releaseCeremonyLock(fresh);
    }
    const absent = A.breakStaleLock(dir, {});
    assert.strictEqual(absent.broken, false, 'absent lock: nothing to break');
    fs.writeFileSync(paths.lock, 'not-json{{{');
    await expectAttestCode(() => A.breakStaleLock(dir, {}), 'ATTEST_LOCK_UNREADABLE', 'unparseable lock needs manual inspection');
    console.log('✔ Test 23 Passed: lock lifecycle + stale break.');
  }

  // Test 24: cross-process contention + kill recovery. A holder process
  // keeps the lock; a contender must fail; after SIGKILL the stale lock
  // breaks via quarantine and the ceremony proceeds with audit linkage.
  {
    const dir = freshTmp('concurrency');
    const holderScript = path.join(dir, 'holder.js');
    fs.writeFileSync(holderScript, [
      "const A = require('REPO/src/services/provenanceAttestation.js');",
      'const lock = A.acquireCeremonyLock(process.argv[2], { opId: null });',
      'setTimeout(() => { A.releaseCeremonyLock(lock); }, 8000);'
    ].join('\n').replace('REPO', REPO.replace(/\\/g, '/')));
    const child = spawn(process.execPath, [holderScript, dir], { cwd: REPO, stdio: 'ignore' });
    try {
      const lockPath = A.storePaths(dir).lock;
      const deadline = Date.now() + 10000;
      while (!fs.existsSync(lockPath) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
      assert.ok(fs.existsSync(lockPath), 'holder acquired the lock');
      await expectAttestCode(() => A.acquireCeremonyLock(dir, {}), 'ATTEST_LOCK_HELD', 'contender fails while held');
      const fx = await ceremonyEnv({});
      const r = await A.attestPackage({ ...fx.baseOpts, storeDir: dir, manifestStore: fx.manifestStore });
      assert.strictEqual(r.phase, 'lock-held', 'ceremony refuses while another holds the lock');
    } finally {
      child.kill();
      await new Promise((resolve) => child.on('exit', resolve));
    }
    await new Promise((r) => setTimeout(r, 200));
    const broke = A.breakStaleLock(dir, { maxAgeMs: 1 });
    assert.strictEqual(broke.broken, true, 'killed holder leaves a breakable stale lock');
    const fx2 = await ceremonyEnv({});
    const done = await A.attestPackage({
      ...fx2.baseOpts,
      storeDir: dir,
      manifestStore: fx2.manifestStore,
      lockBroken: { quarantined: broke.quarantined, previous: { pid: broke.previous.pid, startedAt: broke.previous.startedAt, ageMs: broke.previous.ageMs } }
    });
    assert.strictEqual(done.attested, true, 'ceremony proceeds after stale break');
    assert.strictEqual(done.auditEvent.lockBroken.quarantined, broke.quarantined, 'break recorded in audit event');
    console.log('✔ Test 24 Passed: cross-process contention + kill recovery.');
  }

  // Test 25: reconcile/amend/note core flows + observational guarantees.
  {
    const fx = await ceremonyEnv({});
    const paths = A.storePaths(fx.dir);
    fs.writeFileSync(paths.audit, 'BAD1\n\n');
    const shown = A.reconcileShow({ storeDir: fx.dir });
    assert.strictEqual(shown.observational, true, 'reconcile labeled observational');
    assert.strictEqual(shown.items.length, 2, 'malformed + blank listed');
    assert.ok(shown.items.every((i) => i.suggestedClassification), 'suggestions present');
    const done = await A.attestPackage({
      ...fx.baseOpts,
      acknowledge: shown.items.map((i) => ({
        store: i.store, offset: i.offset, length: i.length, bytesSha256: i.bytesSha256,
        classification: i.suggestedClassification, rationale: 't25', operator: 'tester'
      }))
    });
    assert.strictEqual(done.attested, true, 'shown offsets work at act time');
    const journalLines = A.readStoreFile(paths.journal).lines;
    assert.strictEqual(journalLines.length, 2, 'two acks recorded');
    // Amend the first ack, then confirm usability still holds.
    const firstLine = canonicalStringify(journalLines[0].parsed);
    const am = A.appendAmendment({
      storeDir: fx.dir, amendsAckId: journalLines[0].parsed.ackId,
      endorsedRecordSha256: sha256Hex(Buffer.from(firstLine, 'utf8')),
      newRationale: 'clarified', newClassification: null, operator: 'tester', at: NOW + 10
    });
    assert.strictEqual(am.appended, true, 'amendment appended');
    const note = A.appendNote({ storeDir: fx.dir, refAckId: journalLines[0].parsed.ackId, text: 'context', operator: 'tester', at: NOW + 11 });
    assert.strictEqual(note.appended, true, 'note appended');
    const st = A.ceremonyStatus({ storeDir: fx.dir });
    assert.strictEqual(st.observational, true, 'status observational');
    assert.strictEqual(JSON.stringify(st).includes('attested'), false, 'status text never claims attested');
    assert.strictEqual(st.journalObserved.amendments, 1, 'amendment observed');
    assert.strictEqual(st.journalObserved.notes, 1, 'note observed');
    console.log('✔ Test 25 Passed: reconcile/amend/note flows.');
  }

  // Test 26: keygen CLI — channels, refusals, secret placement.
  {
    const work = freshTmp('keygen');
    const cwd = path.join(work, 'cwd');
    fs.mkdirSync(cwd, { recursive: true });
    const outFile = path.join(work, 'out', 'k.key');
    const r1 = runCli('src/attestation/keygen.js', ['--out', outFile, '--role', 'attestation'], { cwd });
    assert.strictEqual(r1.exit, 0, `keygen --out exits 0: ${r1.stderr}`);
    const key = fs.readFileSync(outFile, 'utf8').trim();
    assert.ok(/^0x[0-9a-f]{64}$/.test(key), 'file holds exactly one key line');
    assert.ok(!r1.stdout.includes(key) && !r1.stderr.includes(key), 'key in file ONLY');
    assert.ok(r1.stdout.includes('address=0x'), 'address on stdout');
    const r2 = runCli('src/attestation/keygen.js', ['--out', outFile], { cwd });
    assert.notStrictEqual(r2.exit, 0, 'overwrite refused');
    const r3 = runCli('src/attestation/keygen.js', ['--out', path.join(cwd, 'inner.key')], { cwd });
    assert.notStrictEqual(r3.exit, 0, 'repo-tree (cwd-inside) write refused');
    assert.ok(!fs.existsSync(path.join(cwd, 'inner.key')), 'no key written on refusal');
    const r4 = runCli('src/attestation/keygen.js', [], { cwd });
    assert.notStrictEqual(r4.exit, 0, 'missing channel refused');
    const r5 = runCli('src/attestation/keygen.js', ['--export', '--role', 'root'], { cwd });
    assert.strictEqual(r5.exit, 0, 'export exits 0');
    const lines = r5.stdout.trim().split('\n');
    assert.strictEqual(lines.length, 1, 'stdout holds ONLY the key line');
    assert.ok(/^0x[0-9a-f]{64}$/.test(lines[0]), 'exported key shape');
    assert.ok(!r5.stderr.includes(lines[0]), 'key never on stderr');
    assert.ok(r5.stderr.includes('address=0x'), 'address on stderr in export mode');
    console.log('✔ Test 26 Passed: keygen CLI.');
  }

  // Test 27: registry CLI — full lifecycle + refusal paths.
  {
    const work = freshTmp('regcli');
    const root = A.generateAttestationKey();
    const day = A.generateAttestationKey();
    const day2 = A.generateAttestationKey();
    const v0 = path.join(work, 'v0.json');
    const v0s = path.join(work, 'v0.signed.json');
    const v1 = path.join(work, 'v1.json');
    const v1s = path.join(work, 'v1.signed.json');
    let r = runCli('src/attestation/registry.js', ['init', '--out', v0, '--key', day.address, '--reason', 'genesis']);
    assert.strictEqual(r.exit, 0, `init: ${r.stderr}`);
    r = runCli('src/attestation/registry.js', ['sign', '--registry', v0, '--out', v0s], { env: { REGISTRY_ROOT_KEY: root.privateKey } });
    assert.strictEqual(r.exit, 0, `sign: ${r.stderr}`);
    assert.ok(!r.stdout.includes(root.privateKey) && !r.stderr.includes(root.privateKey), 'root key never echoed');
    r = runCli('src/attestation/registry.js', ['verify', '--registry', v0s, '--trusted-root', root.address]);
    assert.strictEqual(r.exit, 0, `verify: ${r.stdout}`);
    assert.ok(r.stdout.includes('VALID'), 'valid labeled');
    r = runCli('src/attestation/registry.js', ['add', '--registry', v0s, '--trusted-root', root.address, '--out', v1, '--key', day2.address, '--reason', 'second']);
    assert.strictEqual(r.exit, 0, `add: ${r.stderr}`);
    r = runCli('src/attestation/registry.js', ['sign', '--registry', v1, '--out', v1s], { env: { REGISTRY_ROOT_KEY: root.privateKey } });
    assert.strictEqual(r.exit, 0, `sign v1: ${r.stderr}`);
    // Refusals: mutate from unsigned base, root-as-daykey, missing env.
    r = runCli('src/attestation/registry.js', ['add', '--registry', v1, '--trusted-root', root.address, '--out', path.join(work, 'x.json'), '--key', day.address, '--reason', 'x']);
    assert.notStrictEqual(r.exit, 0, 'mutation from unsigned base refused');
    const evil = path.join(work, 'evil.json');
    runCli('src/attestation/registry.js', ['init', '--out', evil, '--key', root.address, '--reason', 'root as day']);
    r = runCli('src/attestation/registry.js', ['sign', '--registry', evil, '--out', path.join(work, 'evil.s.json')], { env: { REGISTRY_ROOT_KEY: root.privateKey } });
    assert.notStrictEqual(r.exit, 0, 'root doubling as day key refused');
    r = runCli('src/attestation/registry.js', ['sign', '--registry', v0, '--out', path.join(work, 'noenv.json')], { env: { REGISTRY_ROOT_KEY: '' } });
    assert.notStrictEqual(r.exit, 0, 'missing root env refused');
    r = runCli('src/attestation/registry.js', ['verify', '--registry', v0s, '--trusted-root', day.address]);
    assert.notStrictEqual(r.exit, 0, 'wrong root fails verify');
    console.log('✔ Test 27 Passed: registry CLI.');
  }

  // Test 28: attest CLI — ceremony, modes, secret-leak scan, exit codes.
  {
    const fx = await ceremonyEnv({});
    const work = freshTmp('attestcli');
    const pkgFile = path.join(work, 'pkg.json');
    const regFile = path.join(work, 'reg.json');
    fs.writeFileSync(pkgFile, JSON.stringify(fx.pkg));
    fs.writeFileSync(regFile, JSON.stringify(fx.registry));
    const env = {
      ATTESTATION_SIGNING_KEY: fx.day.privateKey,
      TRUSTED_ATTESTATION_AUTHORITIES: fx.day.address,
      TRUSTED_REGISTRY_ROOT: fx.root.address
    };
    const base = ['--package', pkgFile, '--expect-digest', fx.manifestDigest, '--registry', regFile, '--store-dir', work, '--manifest-store', fx.manifestStore];
    let r = runCli('src/attestation/attest.js', base, { env });
    assert.strictEqual(r.exit, 1, 'preview exits 1 (not attested)');
    assert.ok(r.stdout.includes('ATTESTATION PREVIEW'), 'preview printed');
    r = runCli('src/attestation/attest.js', [...base, '--confirm'], { env });
    assert.strictEqual(r.exit, 0, `confirm exits 0: ${r.stdout} ${r.stderr}`);
    assert.ok(r.stdout.includes('attested=true'), 'completion printed');
    for (const f of ['attestations.jsonl', 'attestation-audit.jsonl', 'attestation-reconciliation.jsonl']) {
      const p = path.join(work, f);
      if (fs.existsSync(p)) assert.ok(!fs.readFileSync(p, 'utf8').includes(fx.day.privateKey), `key absent from ${f}`);
    }
    r = runCli('src/attestation/attest.js', ['--verify', '--digest', fx.manifestDigest, '--store-dir', work], { env });
    assert.strictEqual(r.exit, 0, 'verify exits 0');
    assert.ok(r.stdout.includes('attested=true'), 'verify confirms');
    r = runCli('src/attestation/attest.js', ['--status', '--store-dir', work], { env });
    assert.strictEqual(r.exit, 0, 'status exits 0');
    assert.ok(r.stdout.includes('OBSERVATIONAL'), 'status labeled');
    assert.ok(!r.stdout.includes('attested=true'), 'status never claims attested');
    r = runCli('src/attestation/attest.js', ['--reconcile', '--store-dir', work], { env });
    assert.strictEqual(r.exit, 0, 'reconcile exits 0');
    r = runCli('src/attestation/attest.js', [...base, '--confirm'], { env: { ...env, ATTESTATION_SIGNING_KEY: '' } });
    assert.notStrictEqual(r.exit, 0, 'missing key env refused');
    // Full-output secret scan across every captured stream.
    const allOutputs = [];
    for (const args of [base, [...base, '--confirm'], ['--verify', '--digest', fx.manifestDigest, '--store-dir', work]]) {
      const rr = runCli('src/attestation/attest.js', args, { env });
      allOutputs.push(rr.stdout, rr.stderr);
    }
    assert.ok(allOutputs.every((t) => !t.includes(fx.day.privateKey)), 'signing key in NO CLI output');
    console.log('✔ Test 28 Passed: attest CLI + secret-leak scan.');
  }

  // Test 29 (N1/N2/N5): source boundary — no user-secret handling, strict
  // imports, no transaction/wallet/RPC surface in the subsystem.
  {
    const files = [
      'src/services/provenanceAttestation.js',
      'src/attestation/attest.js',
      'src/attestation/keygen.js',
      'src/attestation/registry.js'
    ];
    const forbiddenTokens = [
      'mnemonic', 'seed phrase', 'seedphrase', 'keystore', 'SIGNER_PRIVATE_KEY', 'OPERATOR_SIGNING_KEY',
      'sendTransaction', 'signTransaction', 'createWalletClient', 'createPublicClient', 'walletClient',
      'publicClient', 'eth_sendTransaction', 'eth_signTransaction', 'personal_sign', 'bip39', 'HDKey',
      'fromMnemonic', 'decryptKeystore', 'loadKeystore', 'importKey', 'userPrivateKey', 'userSeed',
      'requestAccounts', 'eth_requestAccounts', 'broadcastTransaction', 'writeContract', 'sendRawTransaction'
    ];
    const stripComments = (src) => {
      let out = '';
      let i = 0;
      let quote = null;
      while (i < src.length) {
        const c = src[i];
        const n = src[i + 1];
        if (quote !== null) {
          out += c;
          if (c === '\\') {
            out += n || '';
            i += 2;
            continue;
          }
          if (c === quote) quote = null;
          i += 1;
          continue;
        }
        if (c === '"' || c === "'" || c === '`') {
          quote = c;
          out += c;
          i += 1;
          continue;
        }
        if (c === '/' && n === '/') {
          while (i < src.length && src[i] !== '\n') i += 1;
          continue;
        }
        if (c === '/' && n === '*') {
          i += 2;
          while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i += 1;
          i += 2;
          continue;
        }
        out += c;
        i += 1;
      }
      return out;
    };
    for (const f of files) {
      const code = stripComments(fs.readFileSync(path.join(REPO, f), 'utf8'));
      for (const tok of forbiddenTokens) {
        assert.ok(!code.includes(tok), `N1: ${f} code must not contain ${tok}`);
      }
    }
    const allow = {
      'src/services/provenanceAttestation.js': new Set(['fs', 'path', 'crypto', 'os', '../utils/canonicalJson', './provenanceManifest', 'viem/accounts', 'viem']),
      'src/attestation/keygen.js': new Set(['fs', 'os', 'path', 'child_process', '../services/provenanceAttestation']),
      'src/attestation/registry.js': new Set(['fs', 'path', '../services/provenanceAttestation']),
      'src/attestation/attest.js': new Set(['fs', 'path', '../services/provenanceAttestation'])
    };
    const forbiddenImportFrag = ['signer', 'wallet', 'agent', 'express', 'http', 'axios', 'fetch', 'ethers', 'web3', 'server', 'config', 'approvals', 'keystore', 'route', 'controller', 'middleware', 'sdk'];
    for (const [f, expected] of Object.entries(allow)) {
      const text = fs.readFileSync(path.join(REPO, f), 'utf8');
      const found = new Set([...text.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]));
      assert.deepStrictEqual(found, expected, `N2: ${f} import boundary exact`);
      for (const target of found) {
        for (const frag of forbiddenImportFrag) assert.ok(!target.toLowerCase().includes(frag), `N2: ${f} must not import ${target}`);
      }
      assert.ok(!/createServer|listen\(|fetch\(|XMLHttpRequest/.test(text), `N5: ${f} has no server/fetch surface`);
    }
    for (const name of Object.keys(A)) {
      assert.ok(!/Transaction|Broadcast|Transfer|send[A-Z]|execute|approve|wallet|rpc|estimate|gas|nonce|swap|bridge/i.test(name), `N5: export ${name} is not transaction-shaped`);
    }
    console.log('✔ Test 29 Passed: N1/N2/N5 source + import + surface boundaries.');
  }

  // Test 30 (N3/N4/N6/N7/N8): key-role separation, protected output,
  // failure atomicity — the remaining negative gates.
  {
    // N3: role separation is structural — deny-list + root checks live
    // on the ceremony path (exercised in Test 18 r10/r11); here assert
    // the registry CLI independently refuses root-as-daykey at rest.
    const root = A.generateAttestationKey();
    const reg = await signedRegistry({}, root.privateKey, 0, NOW);
    assert.ok(!Object.keys(reg.keys).map((k) => k.toLowerCase()).includes(root.address), 'N3: root is not a registry day key');
    // N4: unknown/unregistered/non-ACTIVE keys rejected (ceremony r7/r8
    // in Test 18); verifyAttestation independently agrees.
    const day = A.generateAttestationKey();
    const { pkg } = buildPackage(baseRecord(), baseRequest());
    const v = await A.verifyAttestation({
      manifest: pkg.manifest,
      attestation: await A.signAttestation({
        body: A.buildAttestationBody({
          manifestDigest: sha256Hex(canonicalStringify(pkg.manifest)),
          investigationId: pkg.manifest.investigationId, traceId: pkg.manifest.traceId,
          requestId: pkg.manifest.requestId, keyId: day.address, issuedAt: NOW
        }),
        privateKey: day.privateKey
      }),
      trustedAuthorities: [day.address], keyRegistry: reg, trustedRoot: root.address, now: NOW + 10
    });
    assert.strictEqual(v.code, 'unknown-key', 'N4: unregistered key unknown to verifier');
    // N6: normal-operation secret silence — ceremony result objects
    // never carry key material (CLI streams covered in Tests 26–28).
    const fx = await ceremonyEnv({});
    const done = await A.attestPackage(fx.baseOpts);
    assert.strictEqual(done.attested, true, 'N6 setup attests');
    assert.ok(!JSON.stringify(done).includes(fx.day.privateKey), 'N6: result carries no key material');
    assert.ok(!JSON.stringify(done).includes(fx.root.privateKey), 'N6: result carries no root material');
    // N7: protected output — refusal paths (behavior covered in Test
    // 26); here assert the fallback warning contract exists in source.
    const keygenSrc = fs.readFileSync(path.join(REPO, 'src/attestation/keygen.js'), 'utf8');
    assert.ok(keygenSrc.includes('directory-default permissions'), 'N7: Windows fallback warning present');
    assert.ok(keygenSrc.includes('/inheritance:r'), 'N7: ACL lockdown attempted first');
    assert.ok(keygenSrc.includes('icacls.exe'), 'N7: absolute icacls path (no PATH resolution)');
    // N8: failure atomicity — refused ceremonies leave stores + locks
    // exactly as found.
    const fx8 = await ceremonyEnv({});
    const p8 = A.storePaths(fx8.dir);
    fs.writeFileSync(p8.attestations, 'CORRUPT-BYTES\n');
    const beforeBytes = fs.readFileSync(p8.attestations);
    const refused = await A.attestPackage(fx8.baseOpts);
    assert.strictEqual(refused.phase, 'integrity-gate', 'N8 setup blocks');
    assert.ok(fs.readFileSync(p8.attestations).equals(beforeBytes), 'N8: refused ceremony preserves bytes');
    assert.ok(!fs.existsSync(p8.lock), 'N8: lock released after refusal');
    assert.ok(!fs.existsSync(p8.journal), 'N8: no journal created on refusal without acks');
    console.log('✔ Test 30 Passed: N3/N4/N6/N7/N8 negative gates.');
  }

  // Test 31 (N9): no attestation-signing entrypoint outside the
  // subsystem — no SDK/agent/HTTP exposure. Walks product code.
  // Step 6 extends the importer allowlist to two verify-only
  // consumers (publisher + judge) with a compensating control below:
  // they may verify, never sign or generate keys.
  {
    const roots = ['src', 'agent', 'demo', 'public', 'sdk', 'extension'].map((d) => path.join(REPO, d)).filter((d) => fs.existsSync(d));
    const jsFiles = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.name === 'node_modules' || e.name === '.git') continue;
        const full = path.join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else if (e.isFile() && e.name.endsWith('.js')) jsFiles.push(full);
      }
    };
    roots.forEach(walk);
    assert.ok(jsFiles.length > 50, `N9 walked ${jsFiles.length} product files`);
    const allowedImporters = new Set(['src/attestation/attest.js', 'src/attestation/keygen.js', 'src/attestation/registry.js', 'src/attestation/judge.js', 'src/services/attestationPublisher.js'].map((f) => path.join(REPO, f)));
    for (const f of jsFiles) {
      const text = fs.readFileSync(f, 'utf8');
      if (/require\(\s*['"][^'"]*provenanceAttestation['"]\s*\)/.test(text)) {
        assert.ok(allowedImporters.has(f), `N9: only attestation CLIs may import the core (${path.relative(REPO, f)})`);
      }
    }
    // Compensating control for the two Step 6 verify-only consumers:
    // importing the core for verification is permitted, but neither
    // file may reference or invoke any signing or key-generation
    // entrypoint or any role key. (exportPackage.js needs no core
    // import at all, so it stays outside the allowlist and the loop
    // above enforces that.)
    const noSigningTokens = ['signAttestation', 'attestPackage', 'keygen', 'generateAttestationKey', 'generatePrivateKey', 'ATTESTATION_SIGNING_KEY', 'REGISTRY_ROOT_KEY', 'SIGNER_PRIVATE_KEY', 'OPERATOR_SIGNING_KEY'];
    for (const f of [path.join(REPO, 'src/attestation/judge.js'), path.join(REPO, 'src/services/attestationPublisher.js')]) {
      const text = fs.readFileSync(f, 'utf8');
      for (const tok of noSigningTokens) {
        assert.ok(!text.includes(tok), `N9: Step 6 consumer must not reference ${tok} (${path.relative(REPO, f)})`);
      }
    }
    const httpZones = ['src/server.js', 'src/routes', 'src/controllers', 'src/middleware', 'src/sdk', 'src/signer', 'agent', 'demo', 'public', 'sdk', 'extension'];
    for (const f of jsFiles) {
      const rel = path.relative(REPO, f).replace(/\\/g, '/');
      if (!httpZones.some((z) => rel === z || rel.startsWith(`${z}/`))) continue;
      assert.ok(!/attest/i.test(fs.readFileSync(f, 'utf8')), `N9: no attestation surface in ${rel}`);
    }
    console.log(`✔ Test 31 Passed: N9 no SDK/agent/HTTP signing exposure (${jsFiles.length} files walked).`);
  }

  // Test 32: Phase 2 backward compatibility — old unsigned packages
  // verify untouched; tampering still detected.
  {
    const { pkg } = buildPackage(baseRecord(), baseRequest());
    assert.strictEqual(pkg.packageVersion, 'assertara-verify-1', 'unsigned package keeps v1 tag');
    assert.strictEqual(verifyPackage(pkg).ok, true, 'unsigned package verifies');
    const tampered = JSON.parse(JSON.stringify(pkg));
    tampered.manifest.decision.agent = 'BLOCK';
    assert.strictEqual(verifyPackage(tampered).ok, false, 'tampered unsigned package still fails');
    console.log('✔ Test 32 Passed: Phase 2 backward compatibility.');
  }

  // Test 33 (M1): strict numeric validation — core + CLI. Malformed
  // numerics fail the check; they never disable it.
  {
    const day = A.generateAttestationKey();
    const root = A.generateAttestationKey();
    const reg = await signedRegistry({ [day.address]: activeEntry('m1', T0) }, root.privateKey, 3, NOW);
    const good = { registry: reg, trustedRoot: root.address, now: NOW + 10 };
    for (const bad of ['abc', '', ' ', NaN, Infinity, -Infinity, -1, 1.5, '1.5', '0x10', '3 ']) {
      const r = await A.verifyRegistry({ ...good, minVersion: bad });
      assert.strictEqual(r.ok, false, `core minVersion ${JSON.stringify(bad)} refused`);
      assert.strictEqual(r.code, 'registry-invalid-input', `core minVersion ${JSON.stringify(bad)} code (got ${r.code})`);
    }
    for (const bad of ['abc', '', NaN, Infinity, -Infinity, -1]) {
      const r = await A.verifyRegistry({ ...good, maxAgeDays: bad });
      assert.strictEqual(r.ok, false, `core maxAgeDays ${JSON.stringify(bad)} refused`);
      assert.strictEqual(r.code, 'registry-invalid-input', `core maxAgeDays ${JSON.stringify(bad)} code (got ${r.code})`);
    }
    // Valid boundaries: checks fire rather than bypass.
    let r = await A.verifyRegistry({ ...good, minVersion: 3, maxAgeDays: 365 });
    assert.strictEqual(r.ok, true, 'valid numerics verify');
    r = await A.verifyRegistry({ ...good, minVersion: 0, maxAgeDays: 365 });
    assert.strictEqual(r.ok, true, 'zero minimum verifies');
    r = await A.verifyRegistry({ ...good, minVersion: 4 });
    assert.strictEqual(r.code, 'registry-rollback', 'rollback minimum fires');
    r = await A.verifyRegistry({ ...good, maxAgeDays: 0 });
    assert.strictEqual(r.code, 'stale-registry', 'zero-day age fires staleness (a check, not a bypass)');
    // CLI: registry verify flag parsing.
    const work = freshTmp('m1cli');
    const regFile = path.join(work, 'reg.json');
    fs.writeFileSync(regFile, JSON.stringify(reg));
    for (const bad of ['abc', '', 'Infinity', '-1', '1.5']) {
      const rr = runCli('src/attestation/registry.js', ['verify', '--registry', regFile, '--trusted-root', root.address, '--min-version', bad]);
      assert.notStrictEqual(rr.exit, 0, `cli --min-version ${JSON.stringify(bad)} exits non-zero`);
      assert.ok(rr.stderr.includes('--min-version must be a non-negative integer'), `cli --min-version ${JSON.stringify(bad)} flag error: ${rr.stderr}`);
    }
    for (const bad of ['abc', '', 'Infinity', '-1']) {
      const rr = runCli('src/attestation/registry.js', ['verify', '--registry', regFile, '--trusted-root', root.address, '--max-age-days', bad]);
      assert.notStrictEqual(rr.exit, 0, `cli --max-age-days ${JSON.stringify(bad)} exits non-zero`);
      assert.ok(
        rr.stderr.includes('--max-age-days must be a finite non-negative number') || rr.stderr.includes('--max-age-days requires a non-negative number'),
        `cli --max-age-days ${JSON.stringify(bad)} flag error: ${rr.stderr}`
      );
    }
    r = runCli('src/attestation/registry.js', ['verify', '--registry', regFile, '--trusted-root', root.address, '--min-version', '0', '--max-age-days', '9999']);
    assert.strictEqual(r.exit, 0, `cli valid numerics verify: ${r.stderr}`);
    assert.ok(r.stdout.includes('registry VALID'), 'cli valid output');
    r = runCli('src/attestation/registry.js', ['verify', '--registry', regFile, '--trusted-root', root.address, '--min-version', '99']);
    assert.notStrictEqual(r.exit, 0, 'cli rollback minimum refuses');
    assert.ok(r.stdout.includes('registry-rollback'), 'cli rollback code shown');
    // CLI: show is labeled UNVERIFIED; stdout stays pure JSON.
    r = runCli('src/attestation/registry.js', ['show', '--registry', regFile]);
    assert.strictEqual(r.exit, 0, 'show exits 0');
    assert.ok(r.stderr.includes('UNVERIFIED'), 'show labeled unverified');
    assert.doesNotThrow(() => JSON.parse(r.stdout), 'show stdout stays pure JSON');
    // CLI: attest ceremony flags (needs files + env to reach parsing).
    const fx = await ceremonyEnv({});
    const pkgFile = path.join(work, 'pkg.json');
    const regFile2 = path.join(work, 'reg2.json');
    fs.writeFileSync(pkgFile, JSON.stringify(fx.pkg));
    fs.writeFileSync(regFile2, JSON.stringify(fx.registry));
    const env = {
      ATTESTATION_SIGNING_KEY: fx.day.privateKey,
      TRUSTED_ATTESTATION_AUTHORITIES: fx.day.address,
      TRUSTED_REGISTRY_ROOT: fx.root.address
    };
    const base = ['--package', pkgFile, '--expect-digest', fx.manifestDigest, '--registry', regFile2, '--store-dir', work, '--manifest-store', fx.manifestStore];
    r = runCli('src/attestation/attest.js', [...base, '--min-registry-version', 'abc'], { env });
    assert.notStrictEqual(r.exit, 0, 'attest bad min version refused');
    assert.ok(r.stderr.includes('--min-registry-version must be a non-negative integer'), `attest flag error: ${r.stderr}`);
    r = runCli('src/attestation/attest.js', [...base, '--max-registry-age-days', 'Infinity'], { env });
    assert.notStrictEqual(r.exit, 0, 'attest bad max age refused');
    assert.ok(r.stderr.includes('--max-registry-age-days must be a finite non-negative number'), `attest flag error: ${r.stderr}`);
    r = runCli('src/attestation/attest.js', [...base, '--min-registry-version', '0'], { env });
    assert.ok(!r.stderr.includes('must be a non-negative integer'), 'valid min version proceeds past parsing');
    assert.ok(r.stdout.includes('ATTESTATION PREVIEW'), 'valid min version reaches preview');
    r = runCli('src/attestation/attest.js', ['--break-lock', '--max-age-ms', 'abc', '--store-dir', work], { env });
    assert.notStrictEqual(r.exit, 0, 'bad max-age-ms refused');
    assert.ok(r.stderr.includes('--max-age-ms must be a non-negative integer'), `break-lock flag error: ${r.stderr}`);
    console.log('✔ Test 33 Passed: M1 strict numeric validation (core + CLI).');
  }

  // Test 34 (M2): decision/execution consistency — BLOCK/UNCERTAIN with
  // an executed hash is contradictory (no approval path exists) and is
  // refused; legitimate REVIEW execution still attests.
  {
    const day = A.generateAttestationKey();
    const root = A.generateAttestationKey();
    const reg = await signedRegistry({ [day.address]: activeEntry('m2', T0) }, root.privateKey, 0, NOW);
    for (const decision of ['BLOCK', 'UNCERTAIN']) {
      const rec = baseRecord();
      rec.policyDecision = { decision, reasons: ['m2 fixture'] };
      rec.recommendedAction = 'ABORT';
      const req = baseRequest();
      req.decision = decision;
      req.status = decision === 'BLOCK' ? 'BLOCKED' : 'UNCERTAIN';
      const built = buildManifest({ record: rec, request: req });
      const pkg = buildVerificationPackage(built);
      assert.strictEqual(verifyPackage(pkg).ok, true, `Phase 2 binding passes ${decision}+hash (hole reaches the ceremony)`);
      assert.notStrictEqual(pkg.manifest.transaction.transactionHash, null, `${decision} fixture carries a hash`);
      const dir = freshTmp(`m2-${decision.toLowerCase()}`);
      const manifestStore = path.join(dir, 'manifests.jsonl');
      saveManifest(built, manifestStore);
      const res = await A.attestPackage({
        pkg, registry: reg, trustedRoot: root.address, trustedAuthorities: [day.address],
        denyList: [], privateKey: day.privateKey, expectDigest: built.manifestDigest,
        confirm: true, storeDir: dir, manifestStore, now: NOW
      });
      assert.strictEqual(res.attested, false, `${decision}+hash not attested`);
      assert.strictEqual(res.phase, 'decision-inconsistent', `${decision} refusal phase`);
      assert.strictEqual(res.code, 'ATTEST_DECISION_INCONSISTENT', `${decision} refusal code`);
    }
    // Legitimate: released REVIEW carrying execution attests.
    const recR = baseRecord();
    recR.policyDecision = { decision: 'REVIEW', reasons: ['operator released'] };
    const reqR = baseRequest();
    reqR.decision = 'REVIEW';
    reqR.status = 'EXECUTED';
    const fxR = await ceremonyEnv({ record: recR, request: reqR });
    const rR = await A.attestPackage(fxR.baseOpts);
    assert.strictEqual(rR.attested, true, 'released REVIEW with execution attests');
    console.log('✔ Test 34 Passed: M2 decision/execution consistency.');
  }

  // Test 35 (M4 journal): complete journal corruption fails closed and
  // recovers only through explicit byte-pinned acknowledgment. Original
  // bytes preserved; debris never promoted; prior acks stay usable.
  {
    // 35a: malformed journal line blocks; ack recovers with a linked event.
    const fx = await ceremonyEnv({});
    const paths = A.storePaths(fx.dir);
    fs.writeFileSync(paths.journal, 'JOURNAL-NOT-JSON\n');
    const blocked = await A.attestPackage(fx.baseOpts);
    assert.strictEqual(blocked.phase, 'integrity-gate', 'journal malformed blocks at gate');
    assert.strictEqual(blocked.code, 'ATTEST_JOURNAL_CORRUPT', 'journal corruption code');
    assert.ok(blocked.details.blockers.some((b) => b.store === 'journal' && b.kind === 'malformed'), 'journal blocker listed');
    const show = A.reconcileShow({ storeDir: fx.dir });
    assert.strictEqual(show.journalDebris.length, 1, 'debris shown');
    const jd = show.journalDebris[0];
    assert.strictEqual(jd.kind, 'malformed', 'kind');
    assert.ok(/^attrec_[0-9a-f]{64}$/.test(jd.ackId), 'ack id shown');
    assert.strictEqual(jd.coverage, 'no-acknowledgment', 'uncovered');
    assert.strictEqual(jd.suggestedClassification, 'foreign-debris', 'suggestion');
    assert.strictEqual(jd.offset, 0, 'offset');
    assert.strictEqual(jd.length, Buffer.byteLength('JOURNAL-NOT-JSON'), 'length');
    assert.strictEqual(jd.bytesSha256, sha256Hex(Buffer.from('JOURNAL-NOT-JSON', 'utf8')), 'digest');
    const before = fs.readFileSync(paths.journal);
    const unblocked = await A.attestPackage({
      ...fx.baseOpts,
      acknowledge: [{
        store: 'journal', offset: jd.offset, length: jd.length, bytesSha256: jd.bytesSha256,
        classification: 'foreign-debris', rationale: 'test journal ack', operator: 'tester'
      }]
    });
    assert.strictEqual(unblocked.attested, true, 'journal ack unblocks');
    assert.strictEqual(unblocked.acksRecorded.length, 1, 'one ack recorded');
    const after = fs.readFileSync(paths.journal);
    assert.ok(after.subarray(0, before.length).equals(before), 'original debris bytes preserved');
    const jread = A.readStoreFile(paths.journal);
    const ackLine = jread.lines.find((l) => l.parsed && l.parsed.format === 'assertara-reconciliation-1');
    assert.ok(ackLine, 'ack event present');
    assert.strictEqual(ackLine.parsed.chainPrev, A.chainAdvance(A.GENESIS_STATE, 'JOURNAL-NOT-JSON'), 'ack links the tip above the debris');
    const jeval = A.evaluateJournal(A.mergedChainEntries(jread));
    assert.strictEqual(jeval.chain.firstBreak, null, 'chain unbroken');
    assert.strictEqual(jeval.byAckId.get(jd.ackId).length, 1, 'ack trusted; debris not promoted');
    assert.strictEqual(jeval.amendments.length, 0, 'no phantom amendments');
    assert.strictEqual(jeval.notes.length, 0, 'no phantom notes');
    // 35b: blank + shape-invalid journal lines block and recover alike.
    const fx2 = await ceremonyEnv({});
    const p2 = A.storePaths(fx2.dir);
    fs.writeFileSync(p2.journal, '\n{"not":"an-ack"}\n');
    const b2 = await A.attestPackage(fx2.baseOpts);
    assert.strictEqual(b2.code, 'ATTEST_JOURNAL_CORRUPT', 'blank+shape-invalid block');
    assert.strictEqual(b2.details.blockers.length, 2, 'two blockers');
    assert.deepStrictEqual(b2.details.blockers.map((x) => x.kind).sort(), ['blank', 'shape-invalid'], 'kinds distinguished');
    const show2 = A.reconcileShow({ storeDir: fx2.dir });
    assert.deepStrictEqual(
      Object.fromEntries(show2.journalDebris.map((x) => [x.kind, x.suggestedClassification])),
      { blank: 'blank-line', 'shape-invalid': 'foreign-debris' },
      'suggestions'
    );
    const u2 = await A.attestPackage({
      ...fx2.baseOpts,
      acknowledge: show2.journalDebris.map((x) => ({
        store: 'journal', offset: x.offset, length: x.length, bytesSha256: x.bytesSha256,
        classification: x.suggestedClassification, rationale: 't35b', operator: 'tester'
      }))
    });
    assert.strictEqual(u2.attested, true, 'both acked → attested');
    // 35c: byte pinning — wrong offset/digest is stale, never blind.
    const fx3 = await ceremonyEnv({});
    const p3 = A.storePaths(fx3.dir);
    fs.writeFileSync(p3.journal, 'PIN-ME\n');
    const b3 = await A.attestPackage(fx3.baseOpts);
    const bl = b3.details.blockers[0];
    const stale = await A.attestPackage({
      ...fx3.baseOpts,
      acknowledge: [{ store: 'journal', offset: bl.offset + 1, length: bl.length, bytesSha256: bl.bytesSha256, classification: 'foreign-debris', rationale: 'x', operator: 'tester' }]
    });
    assert.strictEqual(stale.code, 'ATTEST_ACK_STALE', 'wrong offset is stale');
    const stale2 = await A.attestPackage({
      ...fx3.baseOpts,
      acknowledge: [{ store: 'journal', offset: bl.offset, length: bl.length, bytesSha256: hex('9'), classification: 'foreign-debris', rationale: 'x', operator: 'tester' }]
    });
    assert.strictEqual(stale2.code, 'ATTEST_ACK_STALE', 'wrong digest is stale');
    // 35d: changed bytes invalidate coverage (unit-level pin liveness).
    const dirU = freshTmp('journalpin');
    const pU = A.storePaths(dirU);
    fs.writeFileSync(pU.journal, 'JDEBRIS\n');
    const rdU = A.readStoreFile(pU.journal);
    const dbU = rdU.malformed[0];
    const ackU = A.buildAcknowledgment({
      store: 'journal', offset: dbU.offset, length: dbU.length, bytesSha256: dbU.sha256,
      classification: 'foreign-debris', rationale: 'u', operator: 'tester', at: NOW, chainPrev: A.GENESIS_STATE
    });
    const jeU = A.evaluateJournal([canonicalStringify(ackU)]);
    const readU = (s, o, l) => A.originalBytesAt(dirU, s, o, l);
    assert.strictEqual(A.usableAckFor(jeU, ackU.ackId, { readOriginalBytes: readU }).usable, true, 'journal ack usable while bytes match');
    fs.writeFileSync(pU.journal, 'JDEBRIX\n');
    const useU2 = A.usableAckFor(jeU, ackU.ackId, { readOriginalBytes: readU });
    assert.strictEqual(useU2.usable, false, 'journal byte change invalidates');
    assert.strictEqual(useU2.reason, 'original-changed', 'reason');
    // 35e: pre-existing valid acks stay usable after later debris is acked.
    const fx5 = await ceremonyEnv({});
    const p5 = A.storePaths(fx5.dir);
    fs.writeFileSync(p5.attestations, 'ATT-DEBRIS\n');
    const pre = await A.attestPackage(fx5.baseOpts);
    assert.strictEqual(pre.phase, 'integrity-gate', 'att debris blocks first');
    const first = await A.attestPackage({
      ...fx5.baseOpts,
      acknowledge: pre.details.blockers.map((b) => ({
        store: b.store, offset: b.offset, length: b.length, bytesSha256: b.bytesSha256,
        classification: b.suggestedClassification, rationale: 't35e-1', operator: 'tester'
      }))
    });
    assert.strictEqual(first.attested, true, 'first ceremony attests with att ack');
    const attAckId = first.acksRecorded[0];
    fs.appendFileSync(p5.journal, 'LATER-JOURNAL-DEBRIS\n');
    const mid = A.reconcileShow({ storeDir: fx5.dir });
    assert.strictEqual(mid.items.find((i) => i.ackId === attAckId).coverage, 'acknowledged', 'pre-debris ack still covered');
    assert.strictEqual(mid.journalDebris.length, 1, 'new journal debris listed');
    const second = await A.attestPackage(fx5.baseOpts);
    assert.strictEqual(second.code, 'ATTEST_JOURNAL_CORRUPT', 'new journal debris blocks second ceremony');
    assert.ok(second.details.blockers.every((b) => b.store === 'journal'), 'only journal blocks (att still covered)');
    const midJd = mid.journalDebris[0];
    const third = await A.attestPackage({
      ...fx5.baseOpts,
      acknowledge: [{
        store: 'journal', offset: midJd.offset, length: midJd.length, bytesSha256: midJd.bytesSha256,
        classification: 'foreign-debris', rationale: 't35e-2', operator: 'tester'
      }]
    });
    assert.strictEqual(third.attested, true, 'journal ack unblocks');
    assert.strictEqual(third.adopted.attestation, true, 'existing attestation adopted, not duplicated');
    const post = A.reconcileShow({ storeDir: fx5.dir });
    assert.ok(post.items.every((i) => i.coverage === 'acknowledged'), 'all att/audit debris still acknowledged');
    assert.ok(post.journalDebris.every((j) => j.coverage === 'acknowledged'), 'journal debris acknowledged');
    console.log('✔ Test 35 Passed: journal fail-closed + append-only recovery.');
  }

  // Test 36 (M4 journal): mutation freeze, contested-ack recovery,
  // permanent chain breaks, read-only forensics, CLI prints.
  {
    // 36a: notes and ordinary amendments refuse during corruption.
    const fx = await ceremonyEnv({});
    const paths = A.storePaths(fx.dir);
    fs.writeFileSync(paths.journal, 'FROZEN\n');
    await expectAttestCode(() => A.appendNote({ storeDir: fx.dir, refAckId: null, text: 'n', operator: 'tester', at: NOW }), 'ATTEST_JOURNAL_CORRUPT', 'note refused during corruption');
    await expectAttestCode(() => A.appendAmendment({
      storeDir: fx.dir, amendsAckId: `attrec_${hex('3')}`, endorsedRecordSha256: hex('4'),
      newRationale: 'x', newClassification: null, operator: 'tester', at: NOW
    }), 'ATTEST_JOURNAL_CORRUPT', 'ordinary amendment refused during corruption');
    // 36b: contested-ack amendment is recovery — permitted on an unbroken chain.
    const dirC = freshTmp('contestrec');
    const pC = A.storePaths(dirC);
    const mkAck = (rationale, chainPrev) => canonicalStringify(A.buildAcknowledgment({
      store: 'audit', offset: 5, length: 12, bytesSha256: hex('c'),
      classification: 'foreign-debris', rationale, operator: 'tester', at: NOW, chainPrev
    }));
    const lineA = mkAck('first rationale', A.GENESIS_STATE);
    const stateA = A.chainAdvance(A.GENESIS_STATE, lineA);
    const lineB = mkAck('second rationale', stateA);
    fs.writeFileSync(pC.journal, `${lineA}\n${lineB}\nJOURNAL-DEBRIS\n`);
    const ackIdC = JSON.parse(lineA).ackId;
    const rec = A.appendAmendment({
      storeDir: dirC, amendsAckId: ackIdC, endorsedRecordSha256: sha256Hex(Buffer.from(lineA, 'utf8')),
      newRationale: 'endorse first', newClassification: null, operator: 'tester', at: NOW + 1
    });
    assert.strictEqual(rec.appended, true, 'contested-ack amendment permitted during corruption');
    const jeC = A.evaluateJournal(A.mergedChainEntries(A.readStoreFile(pC.journal)));
    assert.ok(jeC.endorsed.has(ackIdC), 'recovery amendment endorses');
    await expectAttestCode(() => A.appendNote({ storeDir: dirC, refAckId: null, text: 'n', operator: 'tester', at: NOW + 2 }), 'ATTEST_JOURNAL_CORRUPT', 'notes still refused');
    // 36c: chain break blocks ceremonies AND mutations; reads survive.
    const fxB = await ceremonyEnv({});
    const pB = A.storePaths(fxB.dir);
    const tampered = JSON.parse(V1_L1);
    tampered.chainPrev = hex('9');
    fs.writeFileSync(pB.journal, `${V1_L0}\n${canonicalStringify(tampered)}\n`);
    const brk = await A.attestPackage(fxB.baseOpts);
    assert.strictEqual(brk.code, 'ATTEST_JOURNAL_BROKEN', 'ceremony blocked on break');
    const brkAck = await A.attestPackage({
      ...fxB.baseOpts,
      acknowledge: [{ store: 'journal', offset: 0, length: 1, bytesSha256: hex('1'), classification: 'foreign-debris', rationale: 'x', operator: 'tester' }]
    });
    assert.strictEqual(brkAck.code, 'ATTEST_JOURNAL_BROKEN', 'acks cannot complete on break');
    await expectAttestCode(() => A.appendNote({ storeDir: fxB.dir, refAckId: null, text: 'n', operator: 'tester', at: NOW }), 'ATTEST_JOURNAL_BROKEN', 'note blocked on break');
    await expectAttestCode(() => A.appendAmendment({
      storeDir: fxB.dir, amendsAckId: JSON.parse(V1_L0).ackId, endorsedRecordSha256: sha256Hex(Buffer.from(V1_L0, 'utf8')),
      newRationale: 'x', newClassification: null, operator: 'tester', at: NOW
    }), 'ATTEST_JOURNAL_BROKEN', 'amendment blocked on break');
    const stB = A.ceremonyStatus({ storeDir: fxB.dir });
    assert.strictEqual(stB.journalObserved.chainBreak, 1, 'status reports break');
    const shB = A.reconcileShow({ storeDir: fxB.dir });
    assert.strictEqual(shB.chainBreak, 1, 'reconcile reports break');
    assert.ok(shB.chainNote.includes('BLOCKED'), 'break note prominent');
    const vB = await A.verifyCompletion({ storeDir: fxB.dir, manifestDigest: fxB.manifestDigest, keyId: fxB.day.address });
    assert.strictEqual(vB.attested, false, 'nothing attested');
    assert.strictEqual(vB.storeNotes.journal.chainBreak, 1, 'verify reports break');
    const jeB = A.evaluateJournal(A.mergedChainEntries(A.readStoreFile(pB.journal)));
    assert.strictEqual(jeB.byAckId.get(JSON.parse(V1_L0).ackId).length, 1, 'pre-break ack retains prefix validity');
    // 36d: read-only paths report non-break corruption without throwing.
    const st = A.ceremonyStatus({ storeDir: fx.dir });
    assert.strictEqual(st.corruptionObserved.journal.malformed, 1, 'status counts journal malformed');
    assert.strictEqual(st.corruptionObserved.journal.shapeInvalid, 0, 'status counts shape-invalid');
    assert.strictEqual(st.corruptionObserved.attestations.shapeInvalid, 0, 'status counts att shape-invalid');
    const sh = A.reconcileShow({ storeDir: fx.dir });
    assert.strictEqual(sh.journalDebris.length, 1, 'reconcile lists journal debris');
    assert.ok(sh.journalDebris[0].ackId && sh.journalDebris[0].coverage && sh.journalDebris[0].suggestedClassification, 'debris fully described');
    const vv = await A.verifyCompletion({ storeDir: fx.dir, manifestDigest: fx.manifestDigest, keyId: fx.day.address });
    assert.strictEqual(vv.storeNotes.journal.malformed, 1, 'verify notes journal corruption');
    // 36e: CLI prints.
    let r = runCli('src/attestation/attest.js', ['--reconcile', '--store-dir', fx.dir]);
    assert.strictEqual(r.exit, 0, 'reconcile exits 0');
    assert.ok(r.stdout.includes('journal BLOCKING malformed'), `blocking label: ${r.stdout}`);
    assert.ok(r.stdout.includes('ack=attrec_') && r.stdout.includes('suggest=foreign-debris'), 'ack + suggestion printed');
    r = runCli('src/attestation/attest.js', ['--reconcile', '--store-dir', fxB.dir]);
    assert.ok(r.stdout.includes('JOURNAL CHAIN BREAK at line 1'), 'break prominent');
    r = runCli('src/attestation/attest.js', ['--status', '--store-dir', fx.dir]);
    assert.ok(r.stdout.includes('journal(m=1,b=0,s=0)'), `status counts: ${r.stdout}`);
    console.log('✔ Test 36 Passed: journal freeze, breaks, forensics, prints.');
  }

  // Test 37 (M5): manifest continuity — C1 baseline plus C2/C3a/C3b
  // rechecks. Unknowns fail closed; mid-ceremony changes abort without
  // consulting overrides; aborts precede the guarded mutation.
  {
    const M = require('../../src/services/provenanceManifest');
    const fx = await ceremonyEnv({});
    const hitD = M.findManifestByDigest(fx.manifestDigest, fx.manifestStore);
    const hitI = M.findManifestByInvestigation(fx.pkg.manifest.investigationId, fx.manifestStore);
    assert.strictEqual(hitD.ok && hitI.ok, true, 'setup hits');
    const newerDigest = hex('9');
    const newerLatest = { ...hitI, envelope: { ...hitI.envelope, manifestDigest: newerDigest } };
    const c1args = { manifestDigest: fx.manifestDigest, investigationId: fx.pkg.manifest.investigationId, manifestStore: fx.manifestStore };
    // Unit: C1 reports superseded without throwing; unknowns throw.
    const c1 = A.checkManifestContinuity({ ...c1args, finders: null, checkpoint: 'C1', baseline: null });
    assert.strictEqual(c1.superseded, false, 'current manifest not superseded');
    await expectAttestCode(() => A.checkManifestContinuity({ ...c1args, finders: { byDigest: () => ({ ok: false }), byInvestigation: () => hitI }, checkpoint: 'C1', baseline: null }), 'ATTEST_MANIFEST_UNKNOWN', 'missing digest aborts');
    await expectAttestCode(() => A.checkManifestContinuity({ ...c1args, finders: { byDigest: () => hitD, byInvestigation: () => ({ ok: false }) }, checkpoint: 'C1', baseline: null }), 'ATTEST_MANIFEST_UNKNOWN', 'missing investigation aborts (fail-closed)');
    await expectAttestCode(() => A.checkManifestContinuity({ ...c1args, finders: { byDigest: () => { throw new Error('disk gone'); }, byInvestigation: () => hitI }, checkpoint: 'C1', baseline: null }), 'ATTEST_STORE_ERROR', 'store error aborts');
    await expectAttestCode(() => A.checkManifestContinuity({ ...c1args, finders: { byDigest: () => hitD, byInvestigation: () => newerLatest }, checkpoint: 'C2', baseline: { latestDigest: fx.manifestDigest } }), 'ATTEST_MANIFEST_CHANGED', 'newer manifest aborts');
    const stable = A.checkManifestContinuity({ ...c1args, finders: { byDigest: () => hitD, byInvestigation: () => hitI }, checkpoint: 'C2', baseline: { latestDigest: fx.manifestDigest } });
    assert.strictEqual(stable.superseded, false, 'stable store passes recheck');
    // Ceremony-level: flip the latest manifest at each checkpoint in turn.
    for (const [flipAt, checkpoint] of [[2, 'C2'], [3, 'C3a'], [4, 'C3b']]) {
      const dir = freshTmp(`m5-${checkpoint.toLowerCase()}`);
      const p = A.storePaths(dir);
      let calls = 0;
      const finders = {
        byDigest: () => hitD,
        byInvestigation: () => { calls += 1; return calls < flipAt ? hitI : newerLatest; }
      };
      const res = await A.attestPackage({ ...fx.baseOpts, storeDir: dir, manifestFinders: finders });
      assert.strictEqual(res.code, 'ATTEST_MANIFEST_CHANGED', `${checkpoint} aborts on change`);
      assert.strictEqual(res.details.checkpoint, checkpoint, 'checkpoint reported');
      assert.strictEqual(res.attested, false, 'not attested');
      if (checkpoint === 'C2' || checkpoint === 'C3a') {
        assert.ok(!fs.existsSync(p.attestations), `${checkpoint} abort precedes attestation persistence`);
      }
      if (checkpoint === 'C3b') {
        assert.strictEqual(A.readStoreFile(p.attestations).lines.length, 1, 'C3b abort lands after attestation, before audit');
        assert.ok(!fs.existsSync(p.audit), 'no audit persisted');
        // Crash-consistent state resumes to completion under a stable store.
        const resume = await A.attestPackage({ ...fx.baseOpts, storeDir: dir, manifestFinders: { byDigest: () => hitD, byInvestigation: () => hitI } });
        assert.strictEqual(resume.attested, true, 'C3b-aborted ceremony resumes');
        assert.deepStrictEqual(resume.adopted, { attestation: true, audit: false }, 'attestation adopted, audit fresh');
      }
    }
    // No override bypasses a detected mid-ceremony change.
    {
      let calls = 0;
      const res = await A.attestPackage({
        ...fx.baseOpts,
        storeDir: freshTmp('m5-override'),
        allowSuperseded: true,
        allowUnverifiedExecution: true,
        manifestFinders: { byDigest: () => hitD, byInvestigation: () => { calls += 1; return calls < 2 ? hitI : newerLatest; } }
      });
      assert.strictEqual(res.code, 'ATTEST_MANIFEST_CHANGED', 'overrides do not bypass mid-ceremony change');
    }
    // Vanishing digest / unlistable investigation mid-ceremony.
    {
      let d = 0;
      const res = await A.attestPackage({
        ...fx.baseOpts,
        storeDir: freshTmp('m5-vanish'),
        manifestFinders: { byDigest: () => (++d < 3 ? hitD : { ok: false }), byInvestigation: () => hitI }
      });
      assert.strictEqual(res.code, 'ATTEST_MANIFEST_UNKNOWN', 'vanished digest aborts mid-ceremony');
      assert.strictEqual(res.details.checkpoint, 'C3a', 'vanish detected at C3a');
    }
    {
      let n = 0;
      const res = await A.attestPackage({
        ...fx.baseOpts,
        storeDir: freshTmp('m5-unlist'),
        manifestFinders: { byDigest: () => hitD, byInvestigation: () => (++n < 2 ? hitI : { ok: false }) }
      });
      assert.strictEqual(res.code, 'ATTEST_MANIFEST_UNKNOWN', 'unlistable investigation aborts');
      assert.strictEqual(res.details.checkpoint, 'C2', 'unlist detected at C2');
    }
    console.log('✔ Test 37 Passed: manifest continuity C1–C3b.');
  }

  // Test 38: cross-protocol signature rejection — a mandate seal
  // signature verifies no attestation, and vice versa, even when both
  // were made by the same key.
  {
    const { sealMandateObject, verifyMandateSeal, SEAL_FORMAT, SEAL_ALGORITHM } = require('../../src/services/mandate');
    const day = A.generateAttestationKey();
    const root = A.generateAttestationKey();
    const { pkg } = buildPackage(baseRecord(), baseRequest());
    const digest = sha256Hex(canonicalStringify(pkg.manifest));
    const body = A.buildAttestationBody({
      manifestDigest: digest, investigationId: pkg.manifest.investigationId,
      traceId: pkg.manifest.traceId, requestId: pkg.manifest.requestId, keyId: day.address, issuedAt: NOW
    });
    const att = await A.signAttestation({ body, privateKey: day.privateKey });
    const reg = await signedRegistry({ [day.address]: activeEntry('xproto', T0) }, root.privateKey, 0, NOW);
    const vArgs = { manifest: pkg.manifest, trustedAuthorities: [day.address], keyRegistry: reg, trustedRoot: root.address, now: NOW + 10 };
    assert.strictEqual((await A.verifyAttestation({ ...vArgs, attestation: att })).ok, true, 'control: genuine attestation verifies');
    const seal = await sealMandateObject({ id: 'm-xproto' }, day.privateKey);
    assert.strictEqual(seal.authority, day.address, 'seal by the same key (strongest replay case)');
    const replayed = { ...att, signature: seal.signature };
    const vA = await A.verifyAttestation({ ...vArgs, attestation: replayed });
    assert.strictEqual(vA.ok, false, 'mandate signature rejected as attestation');
    assert.strictEqual(vA.code, 'invalid-signature', 'recovery mismatch code');
    const vB = await verifyMandateSeal({
      mandate: { id: 'm-xproto', seal: { format: SEAL_FORMAT, authority: day.address, algorithm: SEAL_ALGORITHM, signature: att.signature } },
      authorities: [day.address]
    });
    assert.strictEqual(vB.ok, false, 'attestation signature rejected as mandate seal');
    const ctlSeal = await sealMandateObject({ id: 'm-xproto' }, day.privateKey);
    assert.strictEqual((await verifyMandateSeal({ mandate: { id: 'm-xproto', seal: ctlSeal }, authorities: [day.address] })).ok, true, 'control: genuine seal verifies');
    console.log('✔ Test 38 Passed: cross-protocol signature rejection.');
  }

  // Test 39: low-S enforcement — malleated (high-S) signatures are
  // rejected at ingest for attestations and registry roots; fresh
  // signatures are canonically low-S.
  {
    const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    const day = A.generateAttestationKey();
    const root = A.generateAttestationKey();
    const { pkg } = buildPackage(baseRecord(), baseRequest());
    const digest = sha256Hex(canonicalStringify(pkg.manifest));
    const body = A.buildAttestationBody({
      manifestDigest: digest, investigationId: pkg.manifest.investigationId,
      traceId: pkg.manifest.traceId, requestId: pkg.manifest.requestId, keyId: day.address, issuedAt: NOW
    });
    const att = await A.signAttestation({ body, privateKey: day.privateKey });
    A.assertAttestationShape(att);
    const malleate = (sig) => {
      const r = sig.slice(0, 66);
      const s = BigInt(`0x${sig.slice(66, 130)}`);
      const v = sig.slice(130, 132);
      assert.ok(s <= N / 2n, 'precondition: original is low-S');
      const s2 = (N - s).toString(16).padStart(64, '0');
      assert.ok(BigInt(`0x${s2}`) > N / 2n, 'malleated s is high');
      return `${r}${s2}${v.toLowerCase() === '1b' ? '1c' : '1b'}`;
    };
    const bad = { ...att, signature: malleate(att.signature) };
    await expectAttestCode(() => A.assertAttestationShape(bad), 'ATTEST_INVALID', 'high-S attestation rejected at ingest');
    const reg = await signedRegistry({ [day.address]: activeEntry('lows', T0) }, root.privateKey, 0, NOW);
    const v = await A.verifyAttestation({
      manifest: pkg.manifest, attestation: bad, trustedAuthorities: [day.address],
      keyRegistry: reg, trustedRoot: root.address, now: NOW + 10
    });
    assert.strictEqual(v.ok, false, 'high-S never verifies');
    assert.strictEqual(v.code, 'attestation-invalid', 'rejected before recovery');
    const regBad = JSON.parse(JSON.stringify(reg));
    regBad.rootSignature.signature = malleate(reg.rootSignature.signature);
    const rv = await A.verifyRegistry({ registry: regBad, trustedRoot: root.address, now: NOW + 10 });
    assert.strictEqual(rv.ok, false, 'high-S registry signature rejected');
    assert.strictEqual(rv.code, 'registry-invalid', 'registry code');
    console.log('✔ Test 39 Passed: low-S signature enforcement.');
  }

  // Test 40: lock-break races map to ATTEST_LOCK_CHANGED (controlled
  // abort, stores untouched); the same stale lock breaks cleanly
  // without interference.
  {
    const dir = freshTmp('lockenoent');
    const paths = A.storePaths(dir);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(paths.lock, canonicalStringify({ hostname: 'test', opId: null, pid: 42424242, startedAt: Date.now() - 99999999, stores: [], token: 'tok' }));
    const realRead = fs.readFileSync;
    const realRename = fs.renameSync;
    try {
      let lockReads = 0;
      fs.readFileSync = function (p, ...rest) {
        if (String(p) === paths.lock) {
          lockReads += 1;
          if (lockReads === 2) {
            const e = new Error('simulated disappearance');
            e.code = 'ENOENT';
            throw e;
          }
        }
        return realRead.call(fs, p, ...rest);
      };
      await expectAttestCode(() => A.breakStaleLock(dir, { maxAgeMs: 1000 }), 'ATTEST_LOCK_CHANGED', 'vanishing lock maps to LOCK_CHANGED');
    } finally {
      fs.readFileSync = realRead;
    }
    try {
      fs.renameSync = function (src, dst) {
        if (String(src) === paths.lock) {
          const e = new Error('simulated rename race');
          e.code = 'ENOENT';
          throw e;
        }
        return realRename.call(fs, src, dst);
      };
      await expectAttestCode(() => A.breakStaleLock(dir, { maxAgeMs: 1000 }), 'ATTEST_LOCK_CHANGED', 'rename race maps to LOCK_CHANGED');
    } finally {
      fs.renameSync = realRename;
    }
    assert.ok(fs.existsSync(paths.lock), 'lock untouched after mapped failures');
    const broke = A.breakStaleLock(dir, { maxAgeMs: 1000 });
    assert.strictEqual(broke.broken, true, 'control: stale lock breakable');
    console.log('✔ Test 40 Passed: lock-race controlled mapping.');
  }
}

module.exports = { runAttestationTests };

if (require.main === module) {
  runAttestationTests().then(
    () => {
      fs.rmSync(TMPROOT, { recursive: true, force: true });
      console.log('\nAll Phase 3 attestation tests passed.');
    },
    (err) => {
      console.error(err);
      console.error(`(tmp artifacts preserved under ${TMPROOT})`);
      process.exit(1);
    }
  );
}
