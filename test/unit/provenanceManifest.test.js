const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const {
  ManifestError,
  assertValidInput,
  buildManifest,
  buildVerificationPackage,
  verifyPackage,
  saveManifest,
  findManifestByDigest,
  findManifestByInvestigation
} = require('../../src/services/provenanceManifest');
const { canonicalStringify, sha256Hex } = require('../../src/utils/canonicalJson');

// Phase 2 provenance manifest: strict validation, deterministic
// digests, contribution levels, transaction binding, privacy
// projection, verification package, and content-addressed persistence.
// Fixture-only: no network, no model, no live calls.

const T0 = 1793600000000; // 2026-11-02, inside the 2020–2100 window
const hex = (c) => String(c).repeat(64);
const TXHASH = `0x${'ab'.repeat(32)}`;

function baseRecord() {
  return {
    recordId: 'inv_test_1',
    id: 'eval_test_1',
    traceId: 'tr_test_1',
    requestId: 'agent_test_1',
    recordedAt: T0,
    receivedAt: T0 - 1000,
    durationMs: 1000,
    investigationPath: 'agent',
    chainId: '31337',
    sender: '0xaaaa',
    to: '0xbbbb',
    verdict: 'MATCH',
    confidence: 0.9,
    recommendedAction: 'PROCEED',
    policyDecision: { decision: 'ALLOW', reasons: ['within mandate'] },
    verdictSafeguards: [],
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
    id: 'agent_test_1',
    traceId: 'tr_test_1',
    evalId: 'eval_test_1',
    status: 'EXECUTED',
    decision: 'ALLOW',
    reasons: ['within mandate'],
    txDigest: hex('b'),
    evalVerdict: 'MATCH',
    normalizedTx: { chainId: 31337 },
    execution: { outcome: 'EXECUTED', txHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x10' }
  };
}

function expectCode(fn, code, label) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof ManifestError, `${label}: typed ManifestError`);
    assert.strictEqual(err.code, code, `${label}: code ${code}`);
    return;
  }
  assert.fail(`${label}: expected ${code}`);
}

async function runManifestTests() {
  console.log('Testing Phase 2 provenance manifest...\n');

  // Test 1: strict input validation rejects forbidden types, accepts explicit nulls.
  {
    const bad = [
      ['undefined field', { a: undefined }], ['NaN', { a: NaN }], ['Infinity', { a: Infinity }],
      ['BigInt', { a: 1n }], ['Date', { a: new Date() }], ['Buffer', { a: Buffer.from('x') }],
      ['function', { a: () => 1 }], ['symbol', { a: Symbol('s') }], ['class instance', { a: new (class {})() }]
    ];
    for (const [label, v] of bad) expectCode(() => assertValidInput(v, 't'), 'MANIFEST_INVALID', label);
    const circular = { a: 1 }; circular.self = circular;
    expectCode(() => assertValidInput(circular, 't'), 'MANIFEST_INVALID', 'circular');
    assert.doesNotThrow(() => assertValidInput({ a: null, b: [1, 'x', null], c: { d: 0 } }, 't'), 'explicit nulls pass');
    console.log('✔ Test 1 Passed: strict type validation.');
  }

  // Test 2: field validators (enums, digests, timestamps, ids, sequences).
  {
    expectCode(() => buildManifest({ record: { ...baseRecord(), verdict: 'MAYBE' } }), 'MANIFEST_INVALID', 'bad verdict enum');
    expectCode(() => buildManifest({ record: { ...baseRecord(), museProvenance: { ...baseRecord().museProvenance, status: 'unknown' } } }), 'MANIFEST_INVALID', 'unknown muse status refused');
    const badDigest = baseRecord();
    badDigest.museProvenance = { ...badDigest.museProvenance, outputDigest: 'xyz' };
    expectCode(() => buildManifest({ record: badDigest }), 'MANIFEST_INVALID', 'malformed digest refused');
    const badTime = baseRecord();
    badTime.recordedAt = 999;
    expectCode(() => buildManifest({ record: badTime }), 'MANIFEST_INVALID', 'out-of-range timestamp refused');
    const badIdx = baseRecord();
    badIdx.samProvenance = { ...badIdx.samProvenance, perPrompt: [{ ...badIdx.samProvenance.perPrompt[0], index: 1 }] };
    expectCode(() => buildManifest({ record: badIdx }), 'MANIFEST_INVALID', 'broken prompt index refused');
    const badDet = baseRecord();
    badDet.samProvenance = { ...badDet.samProvenance, perPrompt: [{ ...badDet.samProvenance.perPrompt[0], detections: -1 }] };
    expectCode(() => buildManifest({ record: badDet }), 'MANIFEST_INVALID', 'negative detections refused');
    const missing = baseRecord();
    delete missing.id;
    expectCode(() => buildManifest({ record: missing }), 'MANIFEST_INVALID', 'missing required field refused');
    const legacy = baseRecord();
    delete legacy.museProvenance;
    expectCode(() => buildManifest({ record: legacy }), 'MANIFEST_INVALID', 'pre-Phase-1 record refused');
    console.log('✔ Test 2 Passed: field/enum/digest/timestamp/sequence validation.');
  }

  // Test 3: determinism, sensitivity, envelope exclusion, recomputation.
  {
    const a = buildManifest({ record: baseRecord(), request: baseRequest() });
    const b = buildManifest({ record: baseRecord(), request: baseRequest() });
    assert.strictEqual(a.manifestDigest, b.manifestDigest, 'identical inputs → identical digest');
    assert.strictEqual(canonicalStringify(a.manifest), canonicalStringify(b.manifest), 'identical bytes');
    assert.ok(!('createdAt' in a.manifest) && !('builderVersion' in a.manifest), 'envelope excluded from committed bytes');
    assert.strictEqual(a.envelope.manifestDigest, a.manifestDigest);
    assert.strictEqual(sha256Hex(canonicalStringify(baseRecord())), a.manifest.evidence.digest, 'evidence digest recomputes');
    assert.strictEqual(sha256Hex(canonicalStringify(a.publicProjection)), a.manifest.evidence.publicDigest, 'public digest recomputes');
    assert.strictEqual(sha256Hex(canonicalStringify(a.requestProjection)), a.manifest.request.digest, 'request digest recomputes');
    const flipped = baseRecord();
    flipped.verdict = 'MISMATCH';
    const flippedReq = baseRequest();
    flippedReq.evalVerdict = 'MISMATCH';
    assert.notStrictEqual(buildManifest({ record: flipped, request: flippedReq }).manifestDigest, a.manifestDigest, 'verdict flip changes digest');
    console.log('✔ Test 3 Passed: determinism, sensitivity, recomputation.');
  }

  // Test 4: Muse contribution levels.
  {
    const ok = buildManifest({ record: baseRecord(), request: baseRequest() });
    assert.strictEqual(ok.manifest.modelCalls.museSpark.contribution, 'VERDICT_ACCEPTED');
    assert.strictEqual(ok.manifest.modelCalls.museSpark.modelVerdict, 'MATCH');
    assert.strictEqual(ok.manifest.modelCalls.museSpark.verdictAccepted, true);
    const downgraded = baseRecord();
    downgraded.verdict = 'UNCERTAIN';
    downgraded.verdictSafeguards = [{ trigger: 'BLOCKING_FINDING', from: 'MATCH', to: 'UNCERTAIN' }];
    const dg = buildManifest({ record: downgraded, request: { ...baseRequest(), evalVerdict: 'UNCERTAIN' } });
    assert.strictEqual(dg.manifest.modelCalls.museSpark.contribution, 'OUTPUT_INCLUDED');
    assert.strictEqual(dg.manifest.modelCalls.museSpark.modelVerdict, 'MATCH');
    assert.strictEqual(dg.manifest.modelCalls.museSpark.verdictAccepted, false);
    const failed = baseRecord();
    failed.museProvenance = { ...failed.museProvenance, status: 'timeout', outputDigest: null, responseId: null, served: null, usage: null, latencyMs: null };
    failed.reasoningOrigin = 'heuristic-fallback';
    delete failed.investigation;
    assert.strictEqual(buildManifest({ record: failed }).manifest.modelCalls.museSpark.contribution, 'INVOKED');
    const skipped = baseRecord();
    skipped.museProvenance = { status: 'skipped', provider: null, endpoint: null, requested: null, served: null, responseId: null, invokedAt: null, completedAt: null, inputDigest: null, outputDigest: null, latencyMs: null, usage: null };
    skipped.reasoningOrigin = 'heuristic-fallback';
    delete skipped.investigation;
    assert.strictEqual(buildManifest({ record: skipped }).manifest.modelCalls.museSpark.contribution, 'NOT_INVOKED');
    console.log('✔ Test 4 Passed: Muse contribution levels.');
  }

  // Test 5: SAM contribution levels, prompts, zero-detection, packing linkage.
  {
    const ok = buildManifest({ record: baseRecord(), request: baseRequest() });
    assert.strictEqual(ok.manifest.modelCalls.sam.contribution, 'VALIDATED_AGAINST');
    assert.strictEqual(ok.manifest.modelCalls.sam.prompts.length, 1);
    assert.strictEqual(ok.manifest.modelCalls.sam.regionsInPrompt, 1);
    // Partial: one success + one error.
    const partial = baseRecord();
    partial.samProvenance = {
      ...partial.samProvenance, status: 'partial', completedAt: T0 + 2,
      perPrompt: [
        { index: 0, prompt: 'a', status: 'success', invokedAt: T0, completedAt: T0 + 1, responseId: null, inputDigest: hex('1'), outputDigest: hex('2'), detections: 1 },
        { index: 1, prompt: 'b', status: 'error', invokedAt: T0, completedAt: T0 + 2, responseId: null, inputDigest: hex('3'), outputDigest: null, detections: 0, error: 'boom' }
      ]
    };
    assert.strictEqual(buildManifest({ record: partial }).manifest.modelCalls.sam.contribution, 'PARTIAL');
    // All-timeout → TIMEOUT; mixed failure → FAILED.
    const timeouts = baseRecord();
    timeouts.samProvenance = { ...timeouts.samProvenance, status: 'failed', completedAt: T0 + 1, outputDigest: null, detectedCount: 0, perPrompt: [{ index: 0, prompt: 'a', status: 'timeout', invokedAt: T0, completedAt: T0 + 1, responseId: null, inputDigest: hex('1'), outputDigest: null, detections: 0, timeout: true, error: 'timed out' }] };
    assert.strictEqual(buildManifest({ record: timeouts }).manifest.modelCalls.sam.contribution, 'TIMEOUT');
    // Mock terminal.
    const mock = baseRecord();
    mock.samProvenance = { status: 'mock', mode: 'mock', configured: 'sam-3.1', observed: null, invokedAt: null, completedAt: null, responseId: null, usage: null, outputDigest: null, screenshotDigest: null, submittedImageDigest: null, detectedCount: 0, perPrompt: [] };
    assert.strictEqual(buildManifest({ record: mock }).manifest.modelCalls.sam.contribution, 'MOCK');
    // Skipped terminal.
    const skipped = baseRecord();
    skipped.samProvenance = { status: 'skipped', mode: null, configured: null, observed: null, invokedAt: null, completedAt: null, responseId: null, usage: null, outputDigest: null, screenshotDigest: null, submittedImageDigest: null, detectedCount: 0, perPrompt: [] };
    assert.strictEqual(buildManifest({ record: skipped }).manifest.modelCalls.sam.contribution, 'NOT_INVOKED');
    // Zero-detection success still succeeds with an honest digest.
    const zero = baseRecord();
    zero.samProvenance = { ...zero.samProvenance, completedAt: T0 + 1, detectedCount: 0, outputDigest: sha256Hex('[]'), perPrompt: [{ index: 0, prompt: 'a', status: 'success', invokedAt: T0, completedAt: T0 + 1, responseId: null, inputDigest: hex('1'), outputDigest: sha256Hex('[]'), detections: 0 }] };
    zero.visualEvidence = { regions: [] };
    const zr = buildManifest({ record: zero });
    assert.strictEqual(zr.manifest.modelCalls.sam.contribution, 'VALIDATED_AGAINST');
    assert.strictEqual(zr.manifest.modelCalls.sam.detectedCount, 0);
    // Prompt inclusion counts from packing truncations.
    const withheld = baseRecord();
    withheld.visualEvidence = { regions: [{ regionId: 'R-1' }, { regionId: 'R-2' }, { regionId: 'R-3' }] };
    withheld.evidencePacking = { truncations: [{ section: 'regions', removedChars: 2, reason: 'cap' }] };
    const wr = buildManifest({ record: withheld });
    assert.strictEqual(wr.manifest.modelCalls.sam.regionsInPrompt, 1);
    assert.strictEqual(wr.manifest.modelCalls.sam.regionsWithheld, 2);
    console.log('✔ Test 5 Passed: SAM levels, prompts, zero-detection, packing linkage.');
  }

  // Test 6: transaction binding matrix — never fabricate a hash.
  {
    const executed = buildManifest({ record: baseRecord(), request: baseRequest() });
    assert.strictEqual(executed.manifest.transaction.transactionHash, TXHASH);
    assert.strictEqual(executed.manifest.transaction.executionStatus, 'EXECUTED');
    assert.strictEqual(executed.manifest.transaction.chainId, 31337);
    const reverted = buildManifest({ record: baseRecord(), request: { ...baseRequest(), execution: { outcome: 'FAILED', txHash: TXHASH, receiptStatus: '0x0', blockNumber: '0x11' } } });
    assert.strictEqual(reverted.manifest.transaction.transactionHash, TXHASH, 'reverted tx hash is a chain fact');
    assert.strictEqual(reverted.manifest.transaction.executionStatus, 'FAILED');
    assert.strictEqual(reverted.manifest.transaction.receiptStatus, '0x0');
    const diverged = buildManifest({ record: baseRecord(), request: { ...baseRequest(), execution: { outcome: 'EFFECTS_DIVERGED', txHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x12' } } });
    assert.strictEqual(diverged.manifest.transaction.transactionHash, TXHASH);
    const mismatch = buildManifest({ record: baseRecord(), request: { ...baseRequest(), execution: { outcome: 'MISMATCH', txHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x13' } } });
    assert.strictEqual(mismatch.manifest.transaction.transactionHash, null, 'mismatched hash is not ours');
    assert.strictEqual(mismatch.manifest.transaction.executionStatus, 'MISMATCH');
    const blocked = buildManifest({ record: baseRecord(), request: { ...baseRequest(), decision: 'BLOCK', status: 'DECIDED', execution: null } });
    assert.strictEqual(blocked.manifest.transaction.transactionHash, null);
    assert.strictEqual(blocked.manifest.decision.agent, 'BLOCK');
    const review = buildManifest({ record: baseRecord(), request: { ...baseRequest(), decision: 'REVIEW', status: 'AWAITING_APPROVAL', execution: null } });
    assert.strictEqual(review.manifest.transaction.transactionHash, null);
    const released = buildManifest({ record: baseRecord(), request: { ...baseRequest(), decision: 'REVIEW', execution: { outcome: 'EXECUTED', txHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x14' } } });
    assert.strictEqual(released.manifest.transaction.transactionHash, TXHASH, 'released REVIEW binds its execution');
    const browser = buildManifest({ record: { ...baseRecord(), requestId: null } });
    assert.strictEqual(browser.manifest.transaction.transactionHash, null);
    assert.strictEqual(browser.manifest.request.available, false);
    // Mismatches refuse.
    expectCode(() => buildManifest({ record: baseRecord(), request: { ...baseRequest(), txDigest: hex('9') } }), 'MANIFEST_MISMATCH', 'digest mismatch');
    expectCode(() => buildManifest({ record: baseRecord(), request: { ...baseRequest(), normalizedTx: { chainId: 1 } } }), 'MANIFEST_MISMATCH', 'chain mismatch');
    expectCode(() => buildManifest({ record: baseRecord(), request: { ...baseRequest(), id: 'agent_other' } }), 'MANIFEST_MISMATCH', 'id mismatch');
    expectCode(() => buildManifest({ record: null }), 'MANIFEST_UNAVAILABLE', 'missing record');
    console.log('✔ Test 6 Passed: transaction binding without fabrication.');
  }

  // Test 7: privacy — secrets and raw content never disclosed; tampering detected.
  {
    const dirty = baseRecord();
    dirty.approvalToken = 'tok_SECRET';
    dirty.pageEvidence = { title: 'secret page', url: 'http://x/y?session=1' };
    dirty.investigation = { verdict: 'MATCH', secretNote: 'do not disclose' };
    dirty.decodedTransaction = { ...dirty.decodedTransaction, parameters: { secret: 's' } };
    dirty.agentEvidence = [{ content: 'user said things' }];
    const req = { ...baseRequest(), approval: { token: 'tok_SECRET', pendingToken: 'pend_SECRET' }, purpose: 'user task text', idempotencyKey: 'idem', ownerKeyId: 'owner' };
    const built = buildManifest({ record: dirty, request: req });
    const pkg = buildVerificationPackage(built);
    const disclosed = JSON.stringify({ p: pkg.publicProjection, r: pkg.requestProjection, m: pkg.manifest });
    for (const secret of ['tok_SECRET', 'pend_SECRET', 'secret page', 'session=1', 'do not disclose', 'user said things', 'user task text', 'idem', 'owner']) {
      assert.ok(!disclosed.includes(secret), `must not disclose: ${secret}`);
    }
    assert.ok(verifyPackage(pkg).ok, 'genuine package verifies');
    const tampered = JSON.parse(JSON.stringify(pkg));
    tampered.publicProjection.verdict = 'MISMATCH';
    assert.ok(!verifyPackage(tampered).ok, 'tampered projection detected');
    const swapped = JSON.parse(JSON.stringify(pkg));
    swapped.manifest.decision.agent = 'BLOCK';
    assert.ok(!verifyPackage(swapped).ok, 'tampered manifest detected');
    console.log('✔ Test 7 Passed: privacy projection and tamper detection.');
  }

  // Test 8: persistence — append-only, idempotent, integrity-checked.
  {
    const dir = path.join(__dirname, '..', 'tmp', `manif-${process.pid}`);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'manifests.jsonl');
    try {
      const built = buildManifest({ record: baseRecord(), request: baseRequest() });
      const first = saveManifest(built, file);
      assert.strictEqual(first.duplicate, false);
      const second = saveManifest(built, file);
      assert.strictEqual(second.duplicate, true, 'duplicate build idempotent');
      assert.strictEqual(fs.readFileSync(file, 'utf8').trim().split('\n').length, 1, 'one line stored');
      const found = findManifestByDigest(built.manifestDigest, file);
      assert.strictEqual(found.ok, true);
      assert.strictEqual(found.envelope.manifest.investigationId, 'eval_test_1');
      const byInv = findManifestByInvestigation('eval_test_1', file);
      assert.strictEqual(byInv.ok, true);
      assert.strictEqual(findManifestByInvestigation('eval_nope', file).ok, false);
      fs.appendFileSync(file, 'not json\n', 'utf8');
      const afterCorrupt = findManifestByDigest(built.manifestDigest, file);
      assert.strictEqual(afterCorrupt.ok, true, 'readable entries survive corruption');
      assert.strictEqual(afterCorrupt.corrupted, 1, 'corruption counted');
      fs.appendFileSync(file, `${JSON.stringify({ manifest: { a: 1 }, manifestDigest: hex('9') })}\n`, 'utf8');
      assert.strictEqual(findManifestByDigest(built.manifestDigest, file).corrupted, 2, 'altered manifest detected');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    console.log('✔ Test 8 Passed: content-addressed persistence with integrity checks.');
  }

  // Test 9 (B1): semantic verification rejects invalid-but-consistently-
  // rehashed packages. The attacker model: full package access plus the
  // public canonicalizer, so every digest is recomputed correctly and
  // only the semantic checks can catch the forgery.
  {
    const rehashPackage = (pkg) => {
      pkg.manifest.evidence.publicDigest = sha256Hex(canonicalStringify(pkg.publicProjection));
      if (pkg.requestProjection) pkg.manifest.request.digest = sha256Hex(canonicalStringify(pkg.requestProjection));
      const d = sha256Hex(canonicalStringify(pkg.manifest));
      pkg.envelope.manifestDigest = d;
      pkg.digests.publicDigest = pkg.manifest.evidence.publicDigest;
      pkg.digests.requestProjectionDigest = pkg.manifest.request.digest;
      pkg.digests.manifestDigest = d;
      return pkg;
    };
    const failedChecks = (result) => result.checks.filter((c) => !c.ok).map((c) => c.name);
    const passedChecks = (result) => result.checks.filter((c) => c.ok).map((c) => c.name);
    const genuine = buildVerificationPackage(buildManifest({ record: baseRecord(), request: baseRequest() }));
    const gv = verifyPackage(genuine);
    assert.strictEqual(gv.ok, true, 'genuine package passes all checks');
    for (const name of ['publicDigest', 'requestDigest', 'requestLinkage', 'manifestDigest', 'projectionLinkage', 'manifestSemantics', 'projectionSemantics', 'provenanceConsistency', 'contributionClaims', 'manifestLinkage', 'packageDigests']) {
      assert.ok(passedChecks(gv).includes(name), `genuine package passes ${name}`);
    }
    // 'super-success' with consistent digests must not verify.
    const forged = JSON.parse(JSON.stringify(genuine));
    forged.publicProjection.museProvenance.status = 'super-success';
    forged.manifest.modelCalls.museSpark.status = 'super-success';
    rehashPackage(forged);
    const fv = verifyPackage(forged);
    assert.strictEqual(fv.ok, false, 'forged status rejected');
    assert.ok(failedChecks(fv).includes('manifestSemantics'), 'manifest semantics catches forged status');
    assert.ok(passedChecks(fv).includes('publicDigest') && passedChecks(fv).includes('manifestDigest'), 'digests were consistent: semantics did the work');
    // Contradicted contribution claim with consistent digests.
    const lied = JSON.parse(JSON.stringify(genuine));
    lied.manifest.modelCalls.museSpark.contribution = 'NOT_INVOKED';
    lied.manifest.modelCalls.museSpark.verdictAccepted = false;
    rehashPackage(lied);
    const lv = verifyPackage(lied);
    assert.strictEqual(lv.ok, false, 'contradicted contribution rejected');
    assert.ok(failedChecks(lv).includes('contributionClaims'), 'contribution re-derivation catches the lie');
    // Broken prompt sequence with consistent digests.
    const seq = JSON.parse(JSON.stringify(genuine));
    seq.publicProjection.samProvenance.perPrompt[0].index = 5;
    rehashPackage(seq);
    assert.ok(failedChecks(verifyPackage(seq)).includes('projectionSemantics'), 'projection semantics catches broken sequence');
    // Manifest-side copy diverging from the disclosed projection.
    const copied = JSON.parse(JSON.stringify(genuine));
    copied.manifest.modelCalls.sam.detectedCount = 99;
    rehashPackage(copied);
    const cv = verifyPackage(copied);
    assert.strictEqual(cv.ok, false, 'divergent manifest copy rejected');
    assert.ok(failedChecks(cv).includes('manifestLinkage'), 'linkage catches the divergence');
    assert.ok(passedChecks(cv).includes('manifestDigest'), 'manifest digest was consistent: linkage did the work');
    // Model verdict contradicting the safeguard record.
    const mv = JSON.parse(JSON.stringify(genuine));
    mv.manifest.modelCalls.museSpark.modelVerdict = 'MISMATCH';
    rehashPackage(mv);
    assert.ok(failedChecks(verifyPackage(mv)).includes('contributionClaims'), 'verdict accounting catches the lie');
    // Informational digest block must match committed values.
    const dg = JSON.parse(JSON.stringify(genuine));
    dg.digests.publicDigest = hex('9');
    assert.ok(failedChecks(verifyPackage(dg)).includes('packageDigests'), 'digest block mismatch detected');
    console.log('✔ Test 9 Passed: semantic verifier rejects rehashed forgeries.');
  }

  // Test 10 (B2): builder refuses contradictory provenance combinations.
  {
    const expectInvalid = (mutator, label) => {
      const r = baseRecord();
      mutator(r);
      expectCode(() => buildManifest({ record: r }), 'MANIFEST_INVALID', label);
    };
    // Muse contradictions.
    expectInvalid((r) => { r.museProvenance.completedAt = null; }, 'success muse without completedAt');
    expectInvalid((r) => { r.museProvenance.outputDigest = null; }, 'success muse without outputDigest');
    expectInvalid((r) => { r.reasoningOrigin = 'heuristic-fallback'; }, 'success muse with fallback origin');
    expectInvalid((r) => { r.museProvenance.invokedAt = null; }, 'attempted muse without invokedAt');
    expectInvalid((r) => { r.museProvenance.inputDigest = null; }, 'attempted muse without inputDigest');
    expectInvalid((r) => { r.museProvenance.completedAt = T0 - 1; }, 'muse completedAt precedes invokedAt');
    expectInvalid((r) => {
      r.museProvenance = { ...r.museProvenance, status: 'timeout', responseId: null, served: null, usage: null, latencyMs: null };
      r.reasoningOrigin = 'heuristic-fallback';
      delete r.investigation;
    }, 'timeout muse keeps outputDigest');
    expectInvalid((r) => {
      r.museProvenance = { ...r.museProvenance, status: 'timeout', outputDigest: null, served: null, usage: null, latencyMs: null };
      r.reasoningOrigin = 'heuristic-fallback';
      delete r.investigation;
    }, 'timeout muse keeps responseId');
    expectInvalid((r) => {
      r.museProvenance = { ...r.museProvenance, status: 'timeout', outputDigest: null, responseId: null, served: null, usage: null, latencyMs: null };
      delete r.investigation;
    }, 'timeout muse with model origin');
    expectInvalid((r) => {
      r.museProvenance = { status: 'skipped', provider: null, endpoint: null, requested: null, served: null, responseId: null, invokedAt: null, completedAt: null, inputDigest: hex('c'), outputDigest: null, latencyMs: null, usage: null };
      r.reasoningOrigin = 'heuristic-fallback';
      delete r.investigation;
    }, 'skipped muse with inputDigest artifact');
    expectInvalid((r) => {
      r.museProvenance = { status: 'skipped', provider: null, endpoint: null, requested: null, served: null, responseId: null, invokedAt: null, completedAt: null, inputDigest: null, outputDigest: null, latencyMs: null, usage: null };
      delete r.investigation;
    }, 'skipped muse with model origin');
    // SAM aggregate/per-prompt contradictions.
    expectInvalid((r) => {
      r.samProvenance.perPrompt = [{ index: 0, prompt: 'a', status: 'error', invokedAt: T0, completedAt: T0 + 400, responseId: null, inputDigest: hex('1'), outputDigest: null, detections: 0, error: 'x' }];
    }, 'success aggregate with failed prompt');
    expectInvalid((r) => { r.samProvenance.status = 'partial'; }, 'partial aggregate with all-success prompts');
    expectInvalid((r) => { r.samProvenance = { ...r.samProvenance, status: 'failed', outputDigest: null, detectedCount: 0 }; }, 'failed aggregate with success prompt');
    expectInvalid((r) => { r.samProvenance.perPrompt = []; }, 'success aggregate with empty perPrompt');
    expectInvalid((r) => { r.samProvenance = { status: 'mock', mode: 'mock', configured: 'sam-3.1', observed: null, invokedAt: null, completedAt: null, responseId: null, usage: null, outputDigest: null, screenshotDigest: null, submittedImageDigest: null, detectedCount: 0, perPrompt: [{ index: 0, prompt: 'a', status: 'success', invokedAt: T0, completedAt: T0 + 1, responseId: null, inputDigest: hex('1'), outputDigest: hex('2'), detections: 1 }] }; }, 'mock with per-prompt records');
    expectInvalid((r) => { r.samProvenance = { status: 'mock', mode: 'mock', configured: 'sam-3.1', observed: null, invokedAt: null, completedAt: null, responseId: null, usage: null, outputDigest: hex('e'), screenshotDigest: null, submittedImageDigest: null, detectedCount: 0, perPrompt: [] }; }, 'mock with outputDigest');
    expectInvalid((r) => { r.samProvenance = { status: 'skipped', mode: null, configured: null, observed: null, invokedAt: null, completedAt: null, responseId: null, usage: null, outputDigest: hex('e'), screenshotDigest: null, submittedImageDigest: null, detectedCount: 0, perPrompt: [] }; }, 'skipped sam with outputDigest');
    expectInvalid((r) => { r.samProvenance = { status: 'skipped', mode: null, configured: null, observed: null, invokedAt: null, completedAt: null, responseId: null, usage: null, outputDigest: null, screenshotDigest: null, submittedImageDigest: null, detectedCount: 1, perPrompt: [] }; }, 'skipped sam claiming detections');
    expectInvalid((r) => { r.samProvenance.outputDigest = null; }, 'success sam without outputDigest');
    expectInvalid((r) => { r.samProvenance.submittedImageDigest = null; }, 'success sam without submittedImageDigest');
    expectInvalid((r) => { r.visualEvidence = {}; }, 'sam output without persisted regions array');
    expectInvalid((r) => { r.samProvenance.detectedCount = 2; }, 'detectedCount exceeds per-prompt detections');
    expectInvalid((r) => { r.samProvenance.invokedAt = T0 + 5; }, 'aggregate invokedAt diverges from first prompt');
    expectInvalid((r) => { r.samProvenance.mode = 'mock'; }, 'success aggregate with mock mode');
    expectInvalid((r) => {
      r.samProvenance = { ...r.samProvenance, status: 'failed', completedAt: T0 + 1, outputDigest: null, detectedCount: 0, observed: 'sam-x', perPrompt: [{ index: 0, prompt: 'a', status: 'timeout', invokedAt: T0, completedAt: T0 + 1, responseId: null, inputDigest: hex('1'), outputDigest: null, detections: 0, timeout: true, error: 'timed out' }] };
    }, 'failed sam with observed model');
    // Per-prompt contradictions (mixed two-prompt shape keeps the
    // aggregate rollup honest so the per-prompt rule is what refuses).
    const mixed = () => {
      const r = baseRecord();
      r.samProvenance = {
        ...r.samProvenance, status: 'partial', completedAt: T0 + 2,
        perPrompt: [
          { index: 0, prompt: 'a', status: 'success', invokedAt: T0, completedAt: T0 + 1, responseId: null, inputDigest: hex('1'), outputDigest: hex('2'), detections: 1 },
          { index: 1, prompt: 'b', status: 'error', invokedAt: T0, completedAt: T0 + 2, responseId: null, inputDigest: hex('3'), outputDigest: null, detections: 0, error: 'boom' }
        ]
      };
      return r;
    };
    {
      const r = mixed();
      r.samProvenance.perPrompt[0].completedAt = null;
      expectCode(() => buildManifest({ record: r }), 'MANIFEST_INVALID', 'success prompt without completedAt');
    }
    {
      const r = mixed();
      r.samProvenance.perPrompt[1].outputDigest = hex('9');
      expectCode(() => buildManifest({ record: r }), 'MANIFEST_INVALID', 'error prompt with outputDigest');
    }
    {
      const r = mixed();
      delete r.samProvenance.perPrompt[1].error;
      expectCode(() => buildManifest({ record: r }), 'MANIFEST_INVALID', 'error prompt without error detail');
    }
    {
      const r = mixed();
      r.samProvenance.perPrompt[1].detections = 1;
      expectCode(() => buildManifest({ record: r }), 'MANIFEST_INVALID', 'error prompt claiming detections');
    }
    {
      const r = mixed();
      r.samProvenance.perPrompt[1] = { ...r.samProvenance.perPrompt[1], status: 'timeout', timeout: false };
      expectCode(() => buildManifest({ record: r }), 'MANIFEST_INVALID', 'timeout status without timeout flag');
    }
    {
      const r = mixed();
      r.samProvenance.perPrompt[1] = { index: 1, prompt: 'b', status: 'incomplete', invokedAt: T0, completedAt: T0 + 2, responseId: null, inputDigest: hex('3'), outputDigest: null, detections: 2 };
      expectCode(() => buildManifest({ record: r }), 'MANIFEST_INVALID', 'incomplete status without incomplete flag');
    }
    // Genuine edge shapes must still build: invalid-input failure (null
    // stamps plus per-prompt errors) and incomplete-inclusive partial.
    {
      const r = baseRecord();
      r.samProvenance = {
        status: 'failed', mode: 'live', configured: 'sam-3.1', observed: null,
        invokedAt: null, completedAt: null, responseId: null, usage: null,
        outputDigest: null, screenshotDigest: null, submittedImageDigest: null, detectedCount: 0,
        perPrompt: [
          { index: 0, prompt: 'a', status: 'error', invokedAt: null, completedAt: null, responseId: null, inputDigest: null, outputDigest: null, detections: 0, error: 'invalid screenshot input' },
          { index: 1, prompt: 'b', status: 'error', invokedAt: null, completedAt: null, responseId: null, inputDigest: null, outputDigest: null, detections: 0, error: 'invalid screenshot input' }
        ]
      };
      assert.strictEqual(buildManifest({ record: r }).manifest.modelCalls.sam.contribution, 'FAILED', 'invalid-input failure builds');
    }
    {
      const r = mixed();
      r.samProvenance.perPrompt[1] = { index: 1, prompt: 'b', status: 'incomplete', invokedAt: T0, completedAt: T0 + 2, responseId: null, inputDigest: hex('3'), outputDigest: null, detections: 2, incomplete: true };
      assert.strictEqual(buildManifest({ record: r }).manifest.modelCalls.sam.contribution, 'PARTIAL', 'incomplete-inclusive partial builds');
    }
    console.log('✔ Test 10 Passed: builder refuses contradictory provenance.');
  }

  // Test 11 (B3): VALIDATED_AGAINST requires model reasoning origin.
  // The fallback sets referenceValidation.present vacuously, so a
  // fallback record with SAM success must cap at PROMPT_INCLUDED.
  {
    const fb = baseRecord();
    fb.museProvenance = { ...fb.museProvenance, status: 'timeout', outputDigest: null, responseId: null, served: null, usage: null, latencyMs: null };
    fb.reasoningOrigin = 'heuristic-fallback';
    delete fb.investigation;
    assert.strictEqual(fb.referenceValidation.present, true, 'fallback fixture carries vacuous present flag');
    const built = buildManifest({ record: fb });
    assert.strictEqual(built.manifest.modelCalls.sam.contribution, 'PROMPT_INCLUDED', 'fallback cannot claim VALIDATED_AGAINST');
    assert.strictEqual(built.manifest.modelCalls.museSpark.contribution, 'INVOKED', 'fallback muse level unchanged');
    const genuine = buildManifest({ record: baseRecord() });
    assert.strictEqual(genuine.manifest.modelCalls.sam.contribution, 'VALIDATED_AGAINST', 'model origin still validates');
    assert.strictEqual(genuine.manifest.modelCalls.museSpark.contribution, 'VERDICT_ACCEPTED', 'model muse level unchanged');
    console.log('✔ Test 11 Passed: VALIDATED_AGAINST origin gate.');
  }

  // Test 12 (B4): investigation lookup returns the latest valid
  // manifest, so a post-execution manifest supersedes its pre-execution
  // predecessor. Corruption never wins; idempotent rewrites change nothing.
  {
    const dir = path.join(__dirname, '..', 'tmp', `manif-latest-${process.pid}`);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'manifests.jsonl');
    try {
      const pre = buildManifest({ record: baseRecord(), request: { ...baseRequest(), status: 'DECIDED', execution: null } });
      const post = buildManifest({ record: baseRecord(), request: baseRequest() });
      assert.notStrictEqual(pre.manifestDigest, post.manifestDigest, 'pre/post execution digests differ');
      assert.strictEqual(pre.manifest.transaction.transactionHash, null);
      saveManifest(pre, file);
      saveManifest(post, file);
      const found = findManifestByInvestigation('eval_test_1', file);
      assert.strictEqual(found.ok, true);
      assert.strictEqual(found.envelope.manifestDigest, post.manifestDigest, 'latest manifest wins');
      assert.strictEqual(found.envelope.manifest.transaction.executionStatus, 'EXECUTED');
      assert.strictEqual(found.corrupted, 0);
      fs.appendFileSync(file, 'truncated { bad json\n', 'utf8');
      const afterCorrupt = findManifestByInvestigation('eval_test_1', file);
      assert.strictEqual(afterCorrupt.envelope.manifestDigest, post.manifestDigest, 'corruption does not displace latest');
      assert.strictEqual(afterCorrupt.corrupted, 1, 'corruption counted');
      const dup = saveManifest(pre, file);
      assert.strictEqual(dup.duplicate, true, 'old digest rewrite is idempotent');
      assert.strictEqual(fs.readFileSync(file, 'utf8').trim().split('\n').length, 3, 'no new line written');
      assert.strictEqual(findManifestByInvestigation('eval_test_1', file).envelope.manifestDigest, post.manifestDigest, 'duplicate does not rewind latest');
      assert.strictEqual(findManifestByDigest(pre.manifestDigest, file).envelope.manifestDigest, pre.manifestDigest, 'digest lookup unaffected');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    console.log('✔ Test 12 Passed: latest-manifest retrieval.');
  }

  // Test 13: documented security boundaries — the unsigned-rebuild
  // attack, envelope non-commitment, and cross-process determinism.
  {
    // An attacker holding the public canonicalizer can alter disclosed
    // fields and recompute every public digest into a fully consistent
    // package. This MUST verify today (consistency is all Phase 2 can
    // prove); authorship waits for Phase 3 signatures.
    const genuine = buildVerificationPackage(buildManifest({ record: baseRecord(), request: baseRequest() }));
    const rebuilt = JSON.parse(JSON.stringify(genuine));
    rebuilt.publicProjection.verdict = 'MISMATCH';
    rebuilt.manifest.decision.evalVerdict = 'MISMATCH';
    rebuilt.manifest.modelCalls.museSpark.modelVerdict = 'MISMATCH';
    rebuilt.manifest.evidence.publicDigest = sha256Hex(canonicalStringify(rebuilt.publicProjection));
    rebuilt.digests.publicDigest = rebuilt.manifest.evidence.publicDigest;
    const d = sha256Hex(canonicalStringify(rebuilt.manifest));
    rebuilt.envelope.manifestDigest = d;
    rebuilt.digests.manifestDigest = d;
    assert.strictEqual(verifyPackage(rebuilt).ok, true, 'unsigned rebuild verifies: consistency, not authorship');
    assert.ok(genuine.limitations.some((l) => l.includes('Unsigned manifests prove internal consistency, not authorship')), 'limitation documented in package');
    // Envelope metadata carries no assurance and is uncommitted.
    const env = JSON.parse(JSON.stringify(genuine));
    const before = env.envelope.manifestDigest;
    env.envelope.createdAt = 0;
    env.envelope.builderVersion = 'forged';
    assert.strictEqual(verifyPackage(env).ok, true, 'envelope metadata uncommitted');
    assert.strictEqual(env.envelope.manifestDigest, before, 'committed digest untouched by envelope edits');
    // Cross-process determinism: two fresh node processes build
    // byte-identical digests from the same fixture.
    const dir = path.join(__dirname, '..', 'tmp', `manif-xproc-${process.pid}`);
    fs.mkdirSync(dir, { recursive: true });
    try {
      const fixture = path.join(dir, 'fixture.json');
      fs.writeFileSync(fixture, JSON.stringify({ record: baseRecord(), request: baseRequest() }), 'utf8');
      const modulePath = JSON.stringify(path.join(__dirname, '..', '..', 'src', 'services', 'provenanceManifest'));
      const script = `const fs=require('fs');const pm=require(${modulePath});const f=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));process.stdout.write(pm.buildManifest(f).manifestDigest);`;
      const a = execFileSync(process.execPath, ['-e', script, fixture], { encoding: 'utf8' });
      const b = execFileSync(process.execPath, ['-e', script, fixture], { encoding: 'utf8' });
      const local = buildManifest({ record: baseRecord(), request: baseRequest() }).manifestDigest;
      assert.strictEqual(a, b, 'two processes agree');
      assert.strictEqual(a, local, 'child processes agree with in-process build');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    console.log('✔ Test 13 Passed: unsigned-rebuild boundary, envelope, determinism.');
  }

  console.log('\nAll Phase 2 Manifest Tests Passed Successfully!');
}

runManifestTests().catch((err) => { console.error(err); process.exit(1); });
