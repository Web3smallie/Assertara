const assert = require('assert');
const fs = require('fs');
const path = require('path');
const config = require('../../src/config/env');
const { loadMandate, sealMandateObject } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { createAgentStore } = require('../../src/services/agentStore');
const { createAgentController } = require('../../src/controllers/agentController');
const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
const { compileEvidenceBundle } = require('../../src/services/evidenceService');
const {
  buildManifest, buildVerificationPackage, verifyPackage
} = require('../../src/services/provenanceManifest');
const { canonicalStringify, sha256Hex } = require('../../src/utils/canonicalJson');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Step 5 (Option B) closure: the autonomous agent is transaction-
// oriented, not browser-operated. It has no visual interface for
// Assertara to capture, so agent-path investigations honestly record
// SAM 3.1 as NOT_INVOKED. These tests lock that posture end to end:
// controller rejection -> skipped record provenance -> NOT_INVOKED
// manifest contribution -> bitmap bit 1 clear, plus proof the browser
// SAM path stays live. Fixture-only: no network, no live models.

const ORIGINAL_KEY = config.modelApiKey;
const T0 = 1793600000000;
const hex = (c) => String(c).repeat(64);
const DUMMY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

const OPERATOR_KEY = generatePrivateKey();
const OPERATOR_ADDR = privateKeyToAccount(OPERATOR_KEY).address.toLowerCase();
const SIGNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const APPROVAL_SECRET = 'agent-visual-test-approval-secret-0123456789';
const OPERATOR_SECRET = 'agent-visual-test-operator-secret-0123456789';
const SCREENSHOT_REFUSAL = 'Agent proposals do not carry visual evidence in v1: genuine visual capture is Assertara-operated. Omit screenshot.';

// SAM contribution levels that count as successful contribution for
// Step 4 model-bitmap bit 1. Mirrors docs/autonomous-agent.md; the
// Step 6 publisher owns the executable derivation.
const SAM_SUCCESS_LEVELS = ['SUCCEEDED', 'OUTPUT_INCLUDED', 'PROMPT_INCLUDED', 'VALIDATED_AGAINST'];

function fixtureMandate() {
  return {
    id: 'agent-visual-mandate', version: 1, issuer: 'test-operator',
    notBefore: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [],
    signerAddress: SIGNER, senders: [SIGNER],
    chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:18545', name: 'anvil-test' }],
    recipients: { allow: [RECIPIENT], deny: [] },
    contracts: { allow: [] }, selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [],
    reviewRules: [{ when: 'nativeValueAboveWei', value: '10000000000000000' }]
  };
}

async function makeController() {
  const dir = path.join(__dirname, '..', 'tmp', `agent-visual-${Date.now()}-${Math.floor(Math.random() * 1e6)}`);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'mandate.json');
  fs.writeFileSync(file, JSON.stringify(fixtureMandate()), 'utf8');
  const loaded = loadMandate(file);
  assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
  fs.rmSync(dir, { recursive: true, force: true });
  loaded.mandate.seal = await sealMandateObject(loaded.mandate, OPERATOR_KEY);
  return createAgentController({
    mandate: loaded.mandate,
    mandateError: null,
    mandateAuthorities: [OPERATOR_ADDR],
    approvalSecret: APPROVAL_SECRET,
    operatorSecret: OPERATOR_SECRET,
    approvalTtlMs: 300000,
    requestTtlMs: 900000,
    store: createAgentStore({ ledgerFile: null }),
    spendingLedger: createSpendingLedger({})
  });
}

function mockReqRes(body, params) {
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const req = { body, params: params || {} };
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(payload) { resolve({ status: this.statusCode, body: payload }); }
  };
  return { req, res, done };
}

function evaluate(body) {
  return new Promise((resolve) => {
    const req = { body };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); }
    };
    handleEvaluateTransaction(req, res);
  });
}

// Minimal valid record shell (field names mirror the Phase 2
// fixtures); samProvenance is always overwritten with genuine
// assembler output, never hand-written success.
function baseRecord() {
  return {
    recordId: 'inv_visual_1',
    id: 'eval_visual_1',
    traceId: 'tr_visual_1',
    requestId: 'agent_visual_1',
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
    samProvenance: null, // overwritten per test with genuine assembler output
    investigation: { verdict: 'MATCH' },
    visualEvidence: { regions: [] },
    evidencePacking: { truncations: [] },
    referenceValidation: { present: true, ok: true },
    reasoningOrigin: 'model'
  };
}

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

async function runAgentVisualEvidenceTests() {
  console.log('Testing agent visual-evidence posture (Step 5 closure; fixture-only)...\n');
  config.modelApiKey = 'mock_eval';
  try {
    // Test 1: agent-supplied screenshots refused with the exact message.
    {
      const c = await makeController();
      const { req, res, done } = mockReqRes({
        transaction: { from: SIGNER, to: RECIPIENT, chainId: '0x7a69' },
        screenshot: 'abc'
      });
      await c.handlePropose(req, res);
      const out = await done;
      assert.strictEqual(out.status, 400, 'screenshot-bearing proposal refused');
      assert.ok(
        JSON.stringify(out.body).includes(SCREENSHOT_REFUSAL),
        `exact v1 refusal preserved (got ${JSON.stringify(out.body).slice(0, 200)})`
      );
      console.log('✔ Test 1 Passed: agent-supplied screenshots rejected.');
    }

    // Test 2: agent-path record carries honestly skipped SAM provenance.
    // Uses the exact no-screenshot visualResult default the controller
    // passes when no screenshot is supplied.
    let agentSamProvenance = null;
    {
      const bundle = compileEvidenceBundle({
        visualResult: { regions: [], combinedText: '', detectedCount: 0, visualAvailable: false },
        decodedTx: { from: SIGNER, to: RECIPIENT, valueEth: '0.005' },
        reasoningResult: { origin: 'heuristic-fallback', verdict: 'UNCERTAIN' }
      });
      agentSamProvenance = bundle.samProvenance;
      assert.strictEqual(agentSamProvenance.status, 'skipped', 'no-screenshot record is skipped');
      assert.strictEqual(agentSamProvenance.outputDigest, null, 'no output digest without invocation');
      assert.strictEqual(agentSamProvenance.screenshotDigest, null, 'no screenshot digest without bytes');
      assert.strictEqual(agentSamProvenance.detectedCount, 0, 'no detections without invocation');
      assert.deepStrictEqual(agentSamProvenance.perPrompt, [], 'no prompt records without invocation');
      assert.strictEqual(bundle.visualEvidence.visualAvailable, false, 'visual unavailable flagged');
      console.log('✔ Test 2 Passed: agent-path SAM honestly skipped.');
    }

    // Test 3: manifest derives NOT_INVOKED from the genuine record.
    {
      const record = baseRecord();
      record.samProvenance = agentSamProvenance;
      const built = buildManifest({ record });
      const sam = built.manifest.modelCalls.sam;
      assert.strictEqual(sam.contribution, 'NOT_INVOKED', 'manifest contribution honest');
      assert.ok(!SAM_SUCCESS_LEVELS.includes(sam.contribution), 'no success level: Step 4 bitmap bit 1 must be 0');
      assert.strictEqual(sam.outputDigest, null, 'manifest carries no SAM output digest');
      console.log('✔ Test 3 Passed: manifest records NOT_INVOKED, bitmap bit clear.');
    }

    // Test 4: a tampered SAM-success claim on an agent record fails.
    {
      const record = baseRecord();
      record.samProvenance = agentSamProvenance;
      const genuine = buildVerificationPackage(buildManifest({ record }));
      assert.strictEqual(verifyPackage(genuine).ok, true, 'honest agent package verifies');
      const lied = JSON.parse(JSON.stringify(genuine));
      lied.manifest.modelCalls.sam.contribution = 'OUTPUT_INCLUDED';
      rehashPackage(lied);
      const lv = verifyPackage(lied);
      assert.strictEqual(lv.ok, false, 'false SAM success rejected despite consistent digests');
      assert.ok(
        lv.checks.filter((c) => !c.ok).map((c) => c.name).includes('contributionClaims'),
        'contribution re-derivation catches the lie'
      );
      console.log('✔ Test 4 Passed: false SAM claims rejected.');
    }

    // Test 5: browser SAM path stays live and honestly labeled (mock).
    {
      const res = await evaluate({
        screenshot: DUMMY_PNG,
        pageContext: { title: 'Send demo', url: 'https://demo.local/send' },
        transaction: { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x2386f26fc10000' }
      });
      assert.strictEqual(res.status, 200, 'browser evaluation succeeds');
      assert.strictEqual(res.body.samProvenance.status, 'mock', 'unconfigured provider honestly mocked, intake live');
      assert.strictEqual(res.body.samProvenance.outputDigest, null, 'mock carries no genuine output digest');
      const record = baseRecord();
      record.samProvenance = res.body.samProvenance;
      record.investigationPath = 'browser';
      const sam = buildManifest({ record }).manifest.modelCalls.sam;
      assert.strictEqual(sam.contribution, 'MOCK', 'mock classified MOCK, never success');
      assert.ok(!SAM_SUCCESS_LEVELS.includes(sam.contribution), 'mock sets no success bit');
      console.log('✔ Test 5 Passed: browser SAM intact and honestly labeled.');
    }

    console.log('\nAll agent visual-evidence posture tests passed.');
  } finally {
    config.modelApiKey = ORIGINAL_KEY;
    try { await closeOcrWorker(); } catch {}
  }
}

if (require.main === module) {
  runAgentVisualEvidenceTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentVisualEvidenceTests };
