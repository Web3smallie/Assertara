const assert = require('assert');
const {
  issueApproval, verifyApproval, countersignApproval,
  verifyOperatorSignature, safeEqualSecret
} = require('../../src/services/approvals');

// Approval tokens: issuance, HMAC verification, expiry, tamper
// resistance, operator countersigning. Pure crypto, no chain.

const SECRET = 'test-approval-secret-0123456789abcdef';
const OP_SECRET = 'test-operator-secret-0123456789abcdef';
const NOW = 1780000000000;

function baseArgs(overrides) {
  return {
    secret: SECRET,
    requestId: 'agent_test-1',
    txDigest: 'ab'.repeat(32),
    chainId: '0x7a69',
    sender: '0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    mandateId: 'test-mandate',
    mandateVersion: 3,
    policyId: 'assertara-agent-mvp-1',
    requiresOperator: false,
    ttlMs: 300000,
    nowMs: NOW,
    nonce: 'fixed-nonce-001',
    ...(overrides || {})
  };
}

async function runApprovalTests() {
  console.log('Testing approval tokens (issue, verify, countersign)...\n');

  // Test 1: round-trip verifies with normalized fields.
  {
    const token = issueApproval(baseArgs());
    assert.ok(token.startsWith('apv1.'), 'token carries version prefix');
    const v = verifyApproval({ secret: SECRET, token, nowMs: NOW + 1000 });
    assert.strictEqual(v.ok, true, JSON.stringify(v.error || 'ok'));
    assert.strictEqual(v.payload.requestId, 'agent_test-1');
    assert.strictEqual(v.payload.decision, 'ALLOW');
    assert.strictEqual(v.payload.sender, '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266', 'sender normalized');
    assert.strictEqual(v.payload.expiresAt, NOW + 300000);
    console.log('✔ Test 1 Passed: Issue/verify round-trip.');
  }

  // Test 2: tampering any bound field invalidates the token.
  {
    const token = issueApproval(baseArgs());
    const [, body, sig] = token.split('.');
    const tamperedBody = (mut) => {
      const obj = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      mut(obj);
      return `apv1.${Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url')}.${sig}`;
    };
    for (const [label, mut] of [
      ['requestId', (o) => { o.requestId = 'agent_other'; }],
      ['txDigest', (o) => { o.txDigest = 'ff'.repeat(32); }],
      ['chainId', (o) => { o.chainId = '0x1'; }],
      ['sender', (o) => { o.sender = '0x0000000000000000000000000000000000000001'; }],
      ['mandateVersion', (o) => { o.mandateVersion = 99; }],
      ['expiry', (o) => { o.expiresAt = NOW + 99999999; }],
      ['decision', (o) => { o.decision = 'ALLOW'; o.requiresOperator = true; }]
    ]) {
      const v = verifyApproval({ secret: SECRET, token: tamperedBody(mut), nowMs: NOW + 1000 });
      assert.strictEqual(v.ok, false, `${label} tamper must invalidate`);
      assert.ok(/signature invalid/.test(v.error), `${label}: MAC failure named`);
    }
    // Signature bit-flip.
    const badSig = `${'apv1'}.${body}.${sig.slice(0, -1)}${sig.endsWith('0') ? '1' : '0'}`;
    assert.strictEqual(verifyApproval({ secret: SECRET, token: badSig, nowMs: NOW }).ok, false);
    console.log('✔ Test 2 Passed: Field tampering detected.');
  }

  // Test 3: wrong secret, expiry, and malformed tokens rejected.
  {
    const token = issueApproval(baseArgs());
    assert.strictEqual(verifyApproval({ secret: 'wrong-secret-00000000000000000000', token, nowMs: NOW }).ok, false);
    assert.strictEqual(verifyApproval({ secret: '', token, nowMs: NOW }).ok, false);
    const expired = verifyApproval({ secret: SECRET, token, nowMs: NOW + 300001 });
    assert.strictEqual(expired.ok, false);
    assert.ok(/expired/.test(expired.error));
    const future = verifyApproval({ secret: SECRET, token, nowMs: NOW - 1 });
    assert.strictEqual(future.ok, false, 'issued-in-future rejected');
    for (const bad of [null, 42, '', 'apv1.onlyone', 'xx.a.b', 'apv1..sig', 'apv1.!!!notbase64!!!.00']) {
      assert.strictEqual(verifyApproval({ secret: SECRET, token: bad, nowMs: NOW }).ok, false, `malformed rejected: ${bad}`);
    }
    assert.throws(() => issueApproval(baseArgs({ secret: 'short' })), /at least 16/, 'weak secret refused at issue');
    console.log('✔ Test 3 Passed: Expiry and malformed tokens rejected.');
  }

  // Test 4: operator countersigning for REVIEW decisions.
  {
    const pending = issueApproval(baseArgs({ requiresOperator: true, nonce: 'fixed-nonce-002' }));
    assert.strictEqual(verifyApproval({ secret: SECRET, token: pending, nowMs: NOW }).payload.requiresOperator, true);
    const signed = countersignApproval({ secret: SECRET, token: pending, operatorSecret: OP_SECRET, nowMs: NOW });
    assert.strictEqual(signed.ok, true, JSON.stringify(signed.error || 'ok'));
    assert.ok(signed.payload.operatorSig, 'countersignature attached');
    assert.strictEqual(
      verifyOperatorSignature({ operatorSecret: OP_SECRET, nonce: 'fixed-nonce-002', signature: signed.payload.operatorSig }),
      true);
    assert.strictEqual(
      verifyOperatorSignature({ operatorSecret: 'wrong-operator-secret-0000000000', nonce: 'fixed-nonce-002', signature: signed.payload.operatorSig }),
      false, 'wrong operator secret fails');
    assert.strictEqual(
      verifyOperatorSignature({ operatorSecret: OP_SECRET, nonce: 'other-nonce', signature: signed.payload.operatorSig }),
      false, 'countersignature bound to its nonce');
    // Countersigning is part of the approval MAC: stripping requiresOperator breaks it.
    const [, body, sig] = signed.token.split('.');
    const obj = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    obj.requiresOperator = false;
    const stripped = `apv1.${Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url')}.${sig}`;
    assert.strictEqual(verifyApproval({ secret: SECRET, token: stripped, nowMs: NOW }).ok, false);
    // Non-operator approvals reject countersigning.
    const plain = issueApproval(baseArgs({ nonce: 'fixed-nonce-003' }));
    assert.strictEqual(countersignApproval({ secret: SECRET, token: plain, operatorSecret: OP_SECRET, nowMs: NOW }).ok, false);
    console.log('✔ Test 4 Passed: Operator countersigning exact.');
  }

  // Test 5: secret comparison helpers fail closed.
  {
    assert.strictEqual(safeEqualSecret('abc', 'abc'), true);
    assert.strictEqual(safeEqualSecret('abc', 'abd'), false);
    assert.strictEqual(safeEqualSecret('abc', 'abcd'), false, 'length mismatch fails');
    assert.strictEqual(safeEqualSecret('', ''), false, 'empty secrets never compare true');
    assert.strictEqual(safeEqualSecret(null, 'abc'), false);
    console.log('✔ Test 5 Passed: Secret comparison fails closed.');
  }

  // Test 6 (Capability 5 B1): subcall-tree binding rides the HMAC'd body.
  {
    const h = 'ab'.repeat(32);
    const t = issueApproval(baseArgs({ subcallTreeHash: h }));
    const body = JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString('utf8'));
    assert.strictEqual(body.subcallTreeHash, h, 'binding carried in payload');
    const tamperedBody = { ...body, subcallTreeHash: '00'.repeat(32) };
    const tampered = `${t.split('.')[0]}.${Buffer.from(JSON.stringify(tamperedBody)).toString('base64url')}.${t.split('.')[2]}`;
    assert.strictEqual(verifyApproval({ secret: SECRET, token: tampered, nowMs: NOW }).ok, false, 'rebound tree hash breaks the MAC');
    const legacy = issueApproval(baseArgs());
    assert.strictEqual(JSON.parse(Buffer.from(legacy.split('.')[1], 'base64url').toString('utf8')).subcallTreeHash, null, 'absent binding is explicit null');
    console.log('✔ Test 6 Passed: Subcall-tree binding is HMAC-covered.');
  }

  console.log('\nAll Approval Token Tests Passed Successfully!\n');
}

if (require.main === module) {
  runApprovalTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runApprovalTests };
