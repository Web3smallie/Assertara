const assert = require('assert');
const {
  buildManifest, buildVerificationPackage, verifyPackage
} = require('../../src/services/provenanceManifest');
const A = require('../../src/services/provenanceAttestation');
const {
  PublisherError, deriveModelBitmap, publishAttestation, CONTRACT_ABI, ZERO_BYTES32
} = require('../../src/services/attestationPublisher');
const { canonicalStringify, sha256Hex } = require('../../src/utils/canonicalJson');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');

// Step 6 publisher unit tests: bitmap derivation, pre-submit
// verification, key separation, transport-verified submission, and
// secret hygiene. Chain side is an ABI-level fake (real viem
// encode/decode, contract-conformant validation); the real contract
// is proven by forge tests + the Anvil lifecycle e2e.

const T0 = 1793600000000;
const NOW = T0 + 3600000;
const hex = (c) => String(c).repeat(64);
const TXHASH = `0x${'ab'.repeat(32)}`;
const CONTRACT = '0x5fbdb2315678afecb367f032d93f642f64180aa3';
const UNKNOWN_SELECTOR = (() => {
  const { keccak256, toHex } = require('viem');
  return keccak256(toHex('UnknownAttestation()')).slice(2, 10).toLowerCase();
})();

function baseRecord() {
  return {
    recordId: 'inv_pub_1', id: 'eval_pub_1', traceId: 'tr_pub_1',
    requestId: 'agent_pub_1', recordedAt: T0, receivedAt: T0 - 1000,
    durationMs: 1000, investigationPath: 'agent', chainId: '31337',
    sender: '0xaaaa', to: '0xbbbb', verdict: 'MATCH', confidence: 0.9,
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
      status: 'skipped', provider: 'meta-model-api', requested: 'sam-3.1', observed: null,
      invokedAt: null, completedAt: null, attempts: 0, usage: null,
      outputDigest: null, screenshotDigest: null, submittedImageDigest: null,
      detectedCount: 0, perPrompt: []
    },
    investigation: { verdict: 'MATCH' },
    visualEvidence: { regions: [] },
    evidencePacking: { truncations: [] },
    referenceValidation: { present: true, ok: true },
    reasoningOrigin: 'model'
  };
}

function baseRequest() {
  return {
    id: 'agent_pub_1', traceId: 'tr_pub_1', evalId: 'eval_pub_1',
    status: 'EXECUTED', decision: 'ALLOW', reasons: ['within mandate'],
    txDigest: hex('b'), evalVerdict: 'MATCH',
    normalizedTx: { chainId: 31337 },
    execution: { outcome: 'EXECUTED', txHash: TXHASH, receiptStatus: '0x1', blockNumber: '0x10' }
  };
}

function samSuccessProvenance() {
  return {
    status: 'success', provider: 'meta-model-api', requested: 'sam-3.1', observed: 'sam-3.1',
    invokedAt: T0, completedAt: T0 + 500, attempts: 2, responseId: 'sam_resp_1',
    usage: { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7 },
    outputDigest: hex('e'), screenshotDigest: hex('f'), submittedImageDigest: hex('f'),
    perPrompt: [
      { index: 0, status: 'success', invokedAt: T0, completedAt: T0 + 250, responseId: 'sam_resp_1a', inputDigest: hex('1'), outputDigest: hex('2'), detections: 2 },
      { index: 1, status: 'success', invokedAt: T0 + 250, completedAt: T0 + 500, responseId: 'sam_resp_1b', inputDigest: hex('3'), outputDigest: hex('4'), detections: 1 }
    ]
  };
}

function activeEntry(reason, at) {
  return { reason, status: 'ACTIVE', statusChangedAt: at, supersededBy: null, validFrom: at };
}

async function signedRegistry(keys, rootKey, version, publishedAt) {
  const skeleton = A.buildRegistrySkeleton({ version, publishedAt });
  for (const [addr, entry] of Object.entries(keys)) skeleton.keys[addr.toLowerCase()] = entry;
  return A.signRegistry({ registry: skeleton, rootPrivateKey: rootKey });
}

async function signedPackage({ record, request, dayKey, issuedAt }) {
  const built = buildManifest({ record: record || baseRecord(), request: request === undefined ? baseRequest() : request });
  const pkg = buildVerificationPackage(built);
  const digest = sha256Hex(canonicalStringify(built.manifest));
  const dayAddr = privateKeyToAccount(dayKey).address.toLowerCase();
  const body = A.buildAttestationBody({
    manifestDigest: digest,
    investigationId: built.manifest.investigationId,
    traceId: built.manifest.traceId,
    requestId: built.manifest.requestId,
    keyId: dayAddr,
    issuedAt: issuedAt === undefined ? NOW : issuedAt
  });
  const attestation = await A.signAttestation({ body, privateKey: dayKey });
  return { v2: A.attachAttestation(pkg, attestation), digest, dayAddr };
}

// ABI-level fake chain: same validation rules as the contract
// (bitmap<=3, decision<=2, zero-hash rule, idempotent identical,
// conflicting revert). Real viem encode/decode throughout.
function makeFakeChain({ contract, publisherAddr, failures }) {
  const f = failures || {};
  const { encodeFunctionData, decodeFunctionData, encodeFunctionResult, encodeAbiParameters, keccak256, toHex, parseAbi } = require('viem');
  const abi = parseAbi(CONTRACT_ABI);
  const records = new Map();
  const receipts = new Map();
  const calls = { send: 0, call: 0 };
  let block = 100;
  const key = (id, at) => `${id}|${String(at).toLowerCase()}`;
  const transport = {
    address: publisherAddr.toLowerCase(),
    chainId: async () => 31337,
    call: async ({ to, data }) => {
      calls.call += 1;
      const decoded = decodeFunctionData({ abi, data });
      if (decoded.functionName !== 'getAttestation') throw new Error('fake: unknown function');
      const rec = records.get(key(decoded.args[0], decoded.args[1]));
      if (!rec) {
        const err = new Error('execution reverted: unknown record');
        err.data = `0x${UNKNOWN_SELECTOR}`;
        throw err;
      }
      const out = f.readbackMismatch
        ? { ...rec, modelBitmap: (rec.modelBitmap + 1) % 4 }
        : rec;
      return encodeFunctionResult({
        abi, functionName: 'getAttestation',
        result: [out.investigationId, out.manifestDigest, out.modelBitmap, out.decision, out.txHash, out.attester]
      });
    },
    sendTransaction: async ({ to, data }) => {
      calls.send += 1;
      if (f.revertOnSubmit) throw new Error('execution reverted: fake submit rejection');
      const decoded = decodeFunctionData({ abi, data });
      const [id, dg, bm, dec, th, at] = decoded.args;
      if (Number(bm) > 3 || Number(dec) > 2) throw new Error('execution reverted: fake validation');
      if (Number(dec) !== 0 && String(th).toLowerCase() !== ZERO_BYTES32) throw new Error('execution reverted: fake zero-hash rule');
      const k = key(id, at);
      const prev = records.get(k);
      if (prev) {
        const same = prev.manifestDigest.toLowerCase() === String(dg).toLowerCase()
          && prev.modelBitmap === Number(bm) && prev.decision === Number(dec)
          && prev.txHash.toLowerCase() === String(th).toLowerCase();
        if (!same) throw new Error('execution reverted: fake conflict');
      } else {
        records.set(k, { investigationId: id, manifestDigest: String(dg), modelBitmap: Number(bm), decision: Number(dec), txHash: String(th), attester: String(at) });
      }
      const hash = `0x${calls.send.toString(16).padStart(64, 'c')}`;
      const topics = [
        keccak256(toHex('Attested(string,bytes32,address,uint8,uint8,bytes32)')),
        keccak256(toHex(id)),
        String(dg).toLowerCase(),
        `0x000000000000000000000000${String(at).slice(2).toLowerCase()}`
      ];
      const logData = encodeAbiParameters(
        [{ type: 'uint8' }, { type: 'uint8' }, { type: 'bytes32' }],
        [Number(bm), Number(dec), th]
      );
      const logs = f.noEvent ? [] : [{ address: to, topics, data: logData }];
      if (f.eventMismatch && logs.length > 0) logs[0] = { ...logs[0], topics: [logs[0].topics[0], keccak256(toHex('wrong')), logs[0].topics[2], logs[0].topics[3]] };
      block += 1;
      receipts.set(hash, { status: f.receiptStatus0 ? 'reverted' : 'success', blockNumber: BigInt(block), logs });
      return hash;
    },
    getReceipt: async (hash) => {
      if (f.receiptNever) return null;
      return receipts.get(hash) || null;
    },
    getBlockNumber: async () => `0x${(block + (f.confirmationsBump || 0)).toString(16)}`,
    getLogs: async () => []
  };
  return { transport, records, calls };
}

async function expectPublishCode(fn, code, label) {
  try {
    await fn();
  } catch (err) {
    assert.ok(err instanceof PublisherError, `${label}: typed PublisherError (got ${err && err.constructor && err.constructor.name})`);
    assert.strictEqual(err.code, code, `${label}: code ${code} (got ${err.code}: ${err.message})`);
    return err;
  }
  assert.fail(`${label}: expected ${code}`);
}

function leakScan(value, secrets, label) {
  const blob = JSON.stringify(value, (k, v) => (typeof v === 'bigint' ? String(v) : v));
  for (const s of secrets) {
    assert.ok(!blob.includes(s), `${label}: secret material absent from output`);
    assert.ok(!blob.toLowerCase().includes(String(s).toLowerCase()), `${label}: secret material absent (case-insensitive)`);
  }
}

async function runPublisherTests() {
  console.log('Testing Step 6 attestation publisher (fake transport; temp keys)...\n');
  const dayKey = generatePrivateKey();
  const dayAddr = privateKeyToAccount(dayKey).address.toLowerCase();
  const rootKey = generatePrivateKey();
  const rootAddr = privateKeyToAccount(rootKey).address.toLowerCase();
  const pubKey = generatePrivateKey();
  const pubAddr = privateKeyToAccount(pubKey).address.toLowerCase();
  const otherKey = generatePrivateKey();
  const secrets = [dayKey, rootKey, pubKey, otherKey];

  const baseOpts = async (over) => {
    const { v2 } = await signedPackage({ dayKey });
    const registry = await signedRegistry({ [dayAddr]: activeEntry('day key', T0) }, rootKey, 0, NOW);
    return {
      signedPackage: v2, registry, trustedRoot: rootAddr, trustedAuthorities: [dayAddr],
      denyList: [], rpcUrl: 'http://127.0.0.1:9', chainId: 31337, contractAddress: CONTRACT,
      publisherKey: pubKey, now: NOW + 1000, confirmTimeoutMs: 5000, ...(over || {})
    };
  };

  // Test 1: bitmap truth table over contribution levels.
  {
    const museLevels = ['NOT_INVOKED', 'INVOKED', 'SUCCEEDED', 'OUTPUT_INCLUDED', 'VERDICT_ACCEPTED', 'BOGUS'];
    const samLevels = ['NOT_INVOKED', 'INVOKED', 'MOCK', 'FAILED', 'TIMEOUT', 'PARTIAL', 'SUCCEEDED', 'OUTPUT_INCLUDED', 'PROMPT_INCLUDED', 'VALIDATED_AGAINST', 'BOGUS'];
    const museBit = { NOT_INVOKED: 0, INVOKED: 0, SUCCEEDED: 1, OUTPUT_INCLUDED: 1, VERDICT_ACCEPTED: 1, BOGUS: 0 };
    const samBit = {
      NOT_INVOKED: 0, INVOKED: 0, MOCK: 0, FAILED: 0, TIMEOUT: 0, PARTIAL: 0,
      SUCCEEDED: 2, OUTPUT_INCLUDED: 2, PROMPT_INCLUDED: 2, VALIDATED_AGAINST: 2, BOGUS: 0
    };
    let count = 0;
    for (const m of museLevels) {
      for (const s of samLevels) {
        const got = deriveModelBitmap({ modelCalls: { museSpark: { contribution: m }, sam: { contribution: s } } });
        assert.strictEqual(got, museBit[m] | samBit[s], `bitmap(${m},${s})`);
        count += 1;
      }
    }
    assert.strictEqual(count, museLevels.length * samLevels.length, 'full table exercised');
    await expectPublishCode(async () => deriveModelBitmap(null), 'PUBLISH_INVALID_PACKAGE', 'null manifest');
    await expectPublishCode(async () => deriveModelBitmap({}), 'PUBLISH_INVALID_PACKAGE', 'missing modelCalls');
    await expectPublishCode(async () => deriveModelBitmap({ modelCalls: { museSpark: {}, sam: { contribution: 'SUCCEEDED' } } }), 'PUBLISH_INVALID_PACKAGE', 'missing muse contribution');
    console.log('✔ Test 1 Passed: bitmap truth table (PARTIAL/MOCK/INVOKED clear).');
  }

  // Test 2: happy path through the fake chain.
  {
    const opts = await baseOpts();
    const { transport, calls } = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr });
    opts.transport = transport;
    const res = await publishAttestation(opts);
    assert.strictEqual(res.ok, true, 'published');
    assert.strictEqual(res.duplicate, false, 'not a duplicate');
    assert.strictEqual(res.submitted, true, 'submitted');
    assert.ok(/^0x[0-9a-f]{64}$/.test(res.txHash), 'tx hash returned');
    assert.strictEqual(res.modelBitmap, 1, 'bitmap 0b01 (muse success, sam skipped)');
    assert.strictEqual(res.decision, 'ALLOW', 'decision carried');
    assert.strictEqual(res.attester, dayAddr, 'attester carried');
    assert.ok(res.checks.length >= 8 && res.checks.every((c) => c.ok), 'all checks pass');
    assert.strictEqual(calls.send, 1, 'one submission');
    leakScan(res, secrets, 'happy-path result');
    console.log('✔ Test 2 Passed: happy-path publish + verify.');
  }

  // Test 3: invalid/tampered packages refused before any submission.
  {
    const opts = await baseOpts();
    const { transport, calls } = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr });
    opts.transport = transport;
    const tampered = JSON.parse(JSON.stringify(opts.signedPackage));
    tampered.manifest.decision.agent = 'BLOCK';
    await expectPublishCode(async () => publishAttestation({ ...opts, signedPackage: tampered }), 'PUBLISH_INVALID_PACKAGE', 'tampered manifest');
    const noAtt = JSON.parse(JSON.stringify(opts.signedPackage));
    delete noAtt.attestation;
    await expectPublishCode(async () => publishAttestation({ ...opts, signedPackage: noAtt }), 'PUBLISH_INVALID_PACKAGE', 'missing attestation');
    assert.strictEqual(calls.send, 0, 'nothing submitted');
    console.log('✔ Test 3 Passed: invalid packages refused pre-submission.');
  }

  // Test 4: signature + trust failures (wrong/revoked/retired/stale).
  {
    const mk = async (dayK, entry, authorities, regAge) => {
      const { v2 } = await signedPackage({ dayKey: dayK });
      const addr = privateKeyToAccount(dayK).address.toLowerCase();
      const registry = await signedRegistry({ [addr]: entry }, rootKey, 0, regAge === undefined ? NOW : regAge);
      const o = await baseOpts({ signedPackage: v2, registry, trustedAuthorities: authorities });
      o.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr }).transport;
      return o;
    };
    const wrongKey = await mk(otherKey, activeEntry('other', T0), [dayAddr]);
    await expectPublishCode(async () => publishAttestation(wrongKey), 'PUBLISH_KEY_UNTRUSTED', 'wrong key');
    const revoked = await mk(dayKey, { reason: 'r', status: 'REVOKED', statusChangedAt: T0 + 100, supersededBy: null, validFrom: T0 }, [dayAddr]);
    await expectPublishCode(async () => publishAttestation(revoked), 'PUBLISH_KEY_UNTRUSTED', 'revoked key');
    const retired = await mk(dayKey, { reason: 'r', status: 'RETIRED', statusChangedAt: T0 + 100, supersededBy: null, validFrom: T0 }, [dayAddr]);
    await expectPublishCode(async () => publishAttestation(retired), 'PUBLISH_KEY_UNTRUSTED', 'retired key without corroboration');
    const stale = await mk(dayKey, activeEntry('day key', T0), [dayAddr], T0 - 400 * 86400000);
    stale.maxRegistryAgeDays = 30;
    await expectPublishCode(async () => publishAttestation(stale), 'PUBLISH_KEY_UNTRUSTED', 'stale registry');
    const badSig = await baseOpts();
    const tamperedSig = JSON.parse(JSON.stringify(badSig.signedPackage));
    tamperedSig.attestation.signature = `0x${'11'.repeat(65)}`;
    badSig.signedPackage = tamperedSig;
    badSig.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr }).transport;
    await expectPublishCode(async () => publishAttestation(badSig), 'PUBLISH_KEY_UNTRUSTED', 'corrupt signature');
    console.log('✔ Test 4 Passed: signature/trust failures refused.');
  }

  // Test 5: key separation enforced mechanically.
  {
    const mk = async (pKey, deny) => {
      const o = await baseOpts({ publisherKey: pKey, denyList: deny || [] });
      o.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: privateKeyToAccount(pKey).address }).transport;
      return o;
    };
    await expectPublishCode(async () => publishAttestation(await mk(dayKey)), 'PUBLISH_KEY_CONFLICT', 'publisher == attester');
    await expectPublishCode(async () => publishAttestation(await mk(rootKey)), 'PUBLISH_KEY_CONFLICT', 'publisher == root');
    await expectPublishCode(async () => publishAttestation(await mk(pubKey, [pubAddr])), 'PUBLISH_KEY_CONFLICT', 'deny-listed publisher');
    const badShape = await baseOpts({ publisherKey: '0x1234' });
    badShape.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr }).transport;
    await expectPublishCode(async () => publishAttestation(badShape), 'PUBLISH_INVALID_KEY', 'malformed publisher key');
    console.log('✔ Test 5 Passed: key separation refusals.');
  }

  // Test 6: decision + txHash rules (BLOCK/REVIEW/UNCERTAIN).
  {
    const blockReq = baseRequest();
    blockReq.decision = 'BLOCK';
    blockReq.status = 'BLOCKED';
    blockReq.execution = null;
    const recB = baseRecord();
    recB.policyDecision = { decision: 'BLOCK', reasons: ['x'] };
    const { v2: blockPkg } = await signedPackage({ record: recB, request: blockReq, dayKey });
    const oB = await baseOpts({ signedPackage: blockPkg });
    oB.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr }).transport;
    const rB = await publishAttestation(oB);
    assert.strictEqual(rB.decision, 'BLOCK', 'BLOCK publishes with zero hash');

    const execReq = baseRequest();
    execReq.decision = 'BLOCK';
    const recB2 = baseRecord();
    recB2.policyDecision = { decision: 'BLOCK', reasons: ['x'] };
    const { v2: blockHash } = await signedPackage({ record: recB2, request: execReq, dayKey });
    const oBH = await baseOpts({ signedPackage: blockHash });
    oBH.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr }).transport;
    await expectPublishCode(async () => publishAttestation(oBH), 'PUBLISH_TXHASH_FORBIDDEN', 'BLOCK + hash');

    const revReq = baseRequest();
    revReq.decision = 'REVIEW';
    const { v2: revHash } = await signedPackage({ request: revReq, dayKey });
    const oRH = await baseOpts({ signedPackage: revHash });
    oRH.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr }).transport;
    await expectPublishCode(async () => publishAttestation(oRH), 'PUBLISH_TXHASH_FORBIDDEN', 'REVIEW + hash');

    const uncReq = baseRequest();
    uncReq.decision = 'UNCERTAIN';
    uncReq.status = 'UNCERTAIN';
    uncReq.execution = null;
    const { v2: uncPkg } = await signedPackage({ request: uncReq, dayKey });
    const oU = await baseOpts({ signedPackage: uncPkg });
    oU.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr }).transport;
    await expectPublishCode(async () => publishAttestation(oU), 'PUBLISH_DECISION_UNSUPPORTED', 'UNCERTAIN unrepresentable');
    console.log('✔ Test 6 Passed: decision/txHash enforcement.');
  }

  // Test 7: receipt, read-back, and event verification failures.
  {
    const mk = (failures, timeout) => baseOpts().then(async (o) => {
      o.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr, failures }).transport;
      if (timeout !== undefined) o.confirmTimeoutMs = timeout;
      return o;
    });
    await expectPublishCode(async () => publishAttestation(await mk({ receiptStatus0: true })), 'PUBLISH_TX_FAILED', 'failed receipt');
    await expectPublishCode(async () => publishAttestation(await mk({ receiptNever: true }, 60)), 'PUBLISH_RECEIPT_TIMEOUT', 'missing receipt');
    await expectPublishCode(async () => publishAttestation(await mk({ readbackMismatch: true })), 'PUBLISH_READBACK_MISMATCH', 'read-back mismatch');
    await expectPublishCode(async () => publishAttestation(await mk({ noEvent: true })), 'PUBLISH_EVENT_MISMATCH', 'missing event');
    await expectPublishCode(async () => publishAttestation(await mk({ eventMismatch: true })), 'PUBLISH_EVENT_MISMATCH', 'wrong event contents');
    await expectPublishCode(async () => publishAttestation(await mk({ revertOnSubmit: true })), 'PUBLISH_TX_FAILED', 'submit revert');
    console.log('✔ Test 7 Passed: receipt/read-back/event failures.');
  }

  // Test 8: duplicate policy (identical skips, conflicting refuses).
  {
    const o = await baseOpts();
    const chain = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr });
    o.transport = chain.transport;
    const first = await publishAttestation(o);
    assert.strictEqual(first.submitted, true, 'first submits');
    const second = await publishAttestation(o);
    assert.strictEqual(second.duplicate, true, 'identical flagged duplicate');
    assert.strictEqual(second.submitted, false, 'identical skips submission');
    assert.strictEqual(second.txHash, null, 'no new hash on skip');
    assert.strictEqual(chain.calls.send, 1, 'exactly one submission total');

    const recC = baseRecord();
    recC.verdict = 'MISMATCH';
    recC.investigation = { verdict: 'MISMATCH' };
    const reqC = baseRequest();
    reqC.evalVerdict = 'MISMATCH';
    const { v2: v2conflict, digest: dgConflict } = await signedPackage({ record: recC, request: reqC, dayKey });
    const { verifyPackage: vp } = require('../../src/services/provenanceManifest');
    assert.strictEqual(vp(v2conflict).ok, true, 'conflicting package internally valid');
    assert.notStrictEqual(dgConflict, first.manifestDigest, 'conflict package has a different digest');
    const oC = await baseOpts({ signedPackage: v2conflict });
    oC.transport = chain.transport;
    await expectPublishCode(async () => publishAttestation(oC), 'PUBLISH_CONFLICT', 'conflicting duplicate');
    assert.strictEqual(chain.calls.send, 1, 'conflict submits nothing');
    console.log('✔ Test 8 Passed: duplicate idempotency + conflict refusal.');
  }

  // Test 9: confirmations + secret hygiene + N9 self-check.
  {
    const o = await baseOpts({ confirmations: 3 });
    o.transport = makeFakeChain({ contract: CONTRACT, publisherAddr: pubAddr, failures: { confirmationsBump: 5 } }).transport;
    const res = await publishAttestation(o);
    assert.strictEqual(res.ok, true, 'confirmations satisfied');
    assert.ok(res.checks.some((c) => c.name === 'confirmations' && c.ok), 'confirmation check recorded');
    leakScan(res, secrets, 'publish result');

    const fs = require('fs');
    const pubSrc = fs.readFileSync(require('path').join(__dirname, '..', '..', 'src', 'services', 'attestationPublisher.js'), 'utf8');
    assert.ok(/require\(['"]\.\/provenanceAttestation['"]\)/.test(pubSrc), 'N9: publisher core import present (allowlisted)');
    for (const tok of ['signAttestation', 'attestPackage', 'keygen', 'generateAttestationKey', 'generatePrivateKey', 'ATTESTATION_SIGNING_KEY', 'REGISTRY_ROOT_KEY', 'SIGNER_PRIVATE_KEY', 'OPERATOR_SIGNING_KEY']) {
      assert.ok(!pubSrc.includes(tok), `N9: publisher must not reference ${tok}`);
    }
    const judgeSrc = fs.readFileSync(require('path').join(__dirname, '..', '..', 'src', 'attestation', 'judge.js'), 'utf8');
    assert.ok(/require\(['"]\.\.\/services\/provenanceAttestation['"]\)/.test(judgeSrc), 'N9: judge core import present (allowlisted)');
    for (const tok of ['signAttestation', 'attestPackage', 'keygen', 'generateAttestationKey', 'generatePrivateKey', 'ATTESTATION_SIGNING_KEY', 'REGISTRY_ROOT_KEY', 'SIGNER_PRIVATE_KEY', 'OPERATOR_SIGNING_KEY']) {
      assert.ok(!judgeSrc.includes(tok), `N9: judge must not reference ${tok}`);
    }
    const expSrc = fs.readFileSync(require('path').join(__dirname, '..', '..', 'src', 'attestation', 'exportPackage.js'), 'utf8');
    assert.ok(!/provenanceAttestation/.test(expSrc), 'N9: exporter needs no core import');
    assert.strictEqual(UNKNOWN_SELECTOR, 'cac52429', 'UnknownAttestation() selector pinned to contract');
    console.log('✔ Test 9 Passed: confirmations, hygiene, N9 self-check.');
  }

  console.log('\nAll attestation publisher unit tests passed.');
}

if (require.main === module) {
  runPublisherTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runPublisherTests };
