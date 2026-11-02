const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { encodeFunctionData, parseAbi } = require('viem');
const { loadMandate, evaluateMandate } = require('../../src/services/mandate');
const { createSpendingLedger } = require('../../src/services/spendingLedger');
const { decodeTransactionCalldata } = require('../../src/services/decoderService');

// Mandate engine: operator authorization model, deterministic evaluation,
// fail-closed defaults. No chain, no model.

const SIGNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const SPENDER = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const NOW = Date.parse('2026-06-01T00:00:00Z');

function fixtureMandate(overrides) {
  return {
    id: 'test-mandate',
    version: 3,
    issuer: 'operator-key-1',
    notBefore: '2026-01-01T00:00:00Z',
    expiresAt: '2027-01-01T00:00:00Z',
    revokedVersions: [1],
    signerAddress: SIGNER,
    senders: [SIGNER],
    chains: [{ id: 31337, rpcUrl: 'http://127.0.0.1:18545', name: 'anvil-test' }],
    recipients: { allow: [RECIPIENT], deny: [] },
    contracts: { allow: [] },
    selectors: { allow: [] },
    allowNativeTransfer: true,
    maxNativePerTxWei: '100000000000000000',
    approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [] },
    spendingLimits: [{ windowMs: 86400000, maxNativeWei: '1000000000000000000' }],
    reviewRules: [{ when: 'nativeValueAboveWei', value: '10000000000000000' }],
    ...(overrides || {})
  };
}

function scratchDir(prefix) {
  const base = path.join(__dirname, '..', 'tmp');
  fs.mkdirSync(base, { recursive: true });
  const dir = fs.mkdtempSync(path.join(base, `${prefix}-`));
  return dir;
}

function loadFixture(overrides) {
  const dir = scratchDir('mandate-test');
  try {
    const file = path.join(dir, 'mandate.json');
    fs.writeFileSync(file, JSON.stringify(fixtureMandate(overrides)), 'utf8');
    return loadMandate(file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function nativeTx(overrides) {
  return { from: SIGNER, to: RECIPIENT, data: '0x', value: '0x16345785d8a0000', chainId: '0x7a69', ...(overrides || {}) };
}

function evalWith(mandate, tx, decodedTx, ledger) {
  return evaluateMandate({ mandate, mandateError: null, tx, decodedTx: decodedTx || { functionName: 'unknownFunction' }, nowMs: NOW, ledger: ledger || null });
}

async function runMandateTests() {
  console.log('Testing mandate engine (load, validate, evaluate)...\n');

  // Test 1: valid mandate loads and normalizes.
  {
    const loaded = loadFixture();
    assert.strictEqual(loaded.ok, true, JSON.stringify(loaded.error || 'ok'));
    assert.strictEqual(loaded.mandate.signerAddress, SIGNER.toLowerCase());
    assert.deepStrictEqual(loaded.mandate.chains, [{ id: '0x7a69', rpcUrl: 'http://127.0.0.1:18545', name: 'anvil-test' }]);
    assert.strictEqual(loaded.mandate.policyId, 'assertara-agent-mvp-1');
    console.log('✔ Test 1 Passed: Valid mandate loads and normalizes.');
  }

  // Test 2: invalid mandates rejected, never partially trusted.
  {
    const bad = [
      [{ version: 0 }, 'bad version'],
      [{ notBefore: 'nonsense' }, 'bad dates'],
      [{ expiresAt: '2025-01-01T00:00:00Z' }, 'expiry before start'],
      [{ signerAddress: '0x123' }, 'bad address'],
      [{ senders: [] }, 'empty senders'],
      [{ chains: 'nope' }, 'bad chains'],
      [{ chains: [{ id: 1 }] }, 'chain without rpc'],
      [{ recipients: { allow: ['0x123'] } }, 'bad recipient'],
      [{ maxNativePerTxWei: '-5' }, 'negative limit'],
      [{ maxNativePerTxWei: '1.5' }, 'fractional wei'],
      [{ approvals: { allowUnlimited: 'yes', allowOperatorAll: false, spenderAllowlist: [] } }, 'non-boolean approval flag'],
      [{ spendingLimits: [{ windowMs: -1, maxNativeWei: '1' }] }, 'negative window'],
      [{ reviewRules: [{ when: 'mystery' }] }, 'unknown review rule'],
      [{ reviewRules: [{ when: 'nativeValueAboveWei', value: 'lots' }] }, 'non-numeric review value']
    ];
    for (const [overrides, label] of bad) {
      const loaded = loadFixture(overrides);
      assert.strictEqual(loaded.ok, false, `${label} must be rejected`);
      assert.ok(/invalid mandate/.test(loaded.error), `${label}: explicit error`);
    }
    assert.strictEqual(loadMandate('/nonexistent/mandate.json').ok, false, 'missing file rejected');
    assert.strictEqual(loadMandate(null).ok, false, 'missing path rejected');
    {
      const dir = scratchDir('mandate-empty');
      try {
        const file = path.join(dir, 'mandate.json');
        fs.writeFileSync(file, '{}', 'utf8');
        const empty = loadMandate(file);
        assert.strictEqual(empty.ok, false, 'empty object rejected');
        fs.writeFileSync(file, 'not json{{{', 'utf8');
        assert.strictEqual(loadMandate(file).ok, false, 'unparseable file rejected');
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
    console.log('✔ Test 2 Passed: Invalid mandates rejected.');
  }

  // Test 3: no mandate, expired, revoked.
  {
    const missing = evaluateMandate({ mandate: null, mandateError: 'MANDATE_FILE is not configured', tx: nativeTx(), decodedTx: {}, nowMs: NOW, ledger: null });
    assert.strictEqual(missing.decision, 'UNCERTAIN', 'no mandate can never authorize');
    const expired = loadFixture({ expiresAt: '2026-02-01T00:00:00Z' }).mandate;
    assert.strictEqual(evalWith(expired, nativeTx()).decision, 'BLOCK', 'expired mandate blocks');
    const revoked = loadFixture({ revokedVersions: [3] }).mandate;
    assert.strictEqual(evalWith(revoked, nativeTx()).decision, 'BLOCK', 'revoked version blocks');
    console.log('✔ Test 3 Passed: Missing/expired/revoked mandates fail closed.');
  }

  // Test 4: chain, sender, recipient gating.
  {
    const m = loadFixture().mandate;
    assert.strictEqual(evalWith(m, nativeTx({ chainId: '0x1' })).decision, 'BLOCK', 'foreign chain blocked');
    assert.strictEqual(evalWith(m, nativeTx({ from: RECIPIENT })).decision, 'BLOCK', 'unauthorized sender blocked');
    assert.strictEqual(evalWith(m, nativeTx({ to: SIGNER })).decision, 'BLOCK', 'non-allowlisted recipient blocked');
    const denied = loadFixture({ recipients: { allow: [RECIPIENT, SIGNER], deny: [SIGNER] } }).mandate;
    assert.strictEqual(evalWith(denied, nativeTx({ to: SIGNER })).decision, 'BLOCK', 'explicit deny wins over allow');
    console.log('✔ Test 4 Passed: Chain/sender/recipient gating exact.');
  }

  // Test 5: native value limits and review threshold.
  {
    const m = loadFixture().mandate;
    const ledger = createSpendingLedger({});
    const ok = evalWith(m, nativeTx({ value: '0x2386f26fc10000' }), null, ledger); // 0.01 ETH
    assert.strictEqual(ok.decision, 'ALLOW', 'in-mandate transfer allows');
    assert.ok(ok.checks.every((c) => c.pass), 'all checks pass on ALLOW');
    const overMax = evalWith(m, nativeTx({ value: '0x1c6bf5263400000' }), null, ledger); // ~0.128 ETH
    assert.strictEqual(overMax.decision, 'BLOCK', 'over per-tx maximum blocks');
    const review = evalWith(m, nativeTx({ value: '0x470de4df820000' }), null, ledger); // 0.02 ETH > 0.01 review threshold
    assert.strictEqual(review.decision, 'REVIEW', 'above-threshold value needs operator');
    assert.ok(/operator/i.test(review.reasons.join(' ')), 'review reason names operator');
    console.log('✔ Test 5 Passed: Value limits and review threshold.');
  }

  // Test 6: spending windows enforced from verified executions only.
  {
    const m = loadFixture().mandate;
    const ledger = createSpendingLedger({});
    ledger.record({ chainId: '0x7a69', wei: '995000000000000000', requestId: 'r-old', txHash: '0xaaa', atMs: NOW - 1000 });
    assert.strictEqual(
      evalWith(m, nativeTx({ value: '0x2386f26fc10000' }), null, ledger).decision, 'BLOCK', 'window overflow blocks');
    assert.strictEqual(
      evalWith(m, nativeTx({ value: '0x2386f26fc10000' }), null, createSpendingLedger({})).decision, 'ALLOW', 'empty window allows');
    const noLedger = evalWith(m, nativeTx({ value: '0x2386f26fc10000' }), null, null);
    assert.strictEqual(noLedger.decision, 'UNCERTAIN', 'missing ledger cannot verify limits');
    // Stale entries outside the window do not count.
    const stale = createSpendingLedger({});
    stale.record({ chainId: '0x7a69', wei: '990000000000000000', requestId: 'r-stale', txHash: '0xbbb', atMs: NOW - 90000000 });
    assert.strictEqual(evalWith(m, nativeTx({ value: '0x2386f26fc10000' }), null, stale).decision, 'ALLOW');
    // Ledger persists and reloads (restart must not reset limits silently).
    const dir = scratchDir('ledger-test');
    const file = path.join(dir, 'spending.jsonl');
    const a = createSpendingLedger({ filePath: file });
    a.record({ chainId: '0x7a69', wei: '100', requestId: 'r1', txHash: '0x1', atMs: NOW });
    const b = createSpendingLedger({ filePath: file });
    assert.strictEqual(b.load().loaded, 1);
    assert.strictEqual(b.spentWithin({ chainId: '0x7a69', windowMs: 60000, nowMs: NOW }), '100');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ Test 6 Passed: Spending windows with persisted accounting.');
  }

  // Test 7: contract calls gated by contract + selector + approval structure.
  {
    const ERC20 = parseAbi(['function approve(address spender, uint256 amount) external returns (bool)']);
    const m = loadFixture({
      contracts: { allow: ['0xdAC17F958D2ee523a2206206994597C13D831ec7'] },
      selectors: { allow: ['0x095ea7b3'] },
      recipients: { allow: ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8', '0xdAC17F958D2ee523a2206206994597C13D831ec7'], deny: [] },
      approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [SPENDER] }
    }).mandate;
    const usdt = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
    const approveMax = encodeFunctionData({ abi: ERC20, functionName: 'approve', args: [SPENDER, (1n << 256n) - 1n] });
    const approveSmall = encodeFunctionData({ abi: ERC20, functionName: 'approve', args: [SPENDER, 100n] });
    const approveStranger = encodeFunctionData({ abi: ERC20, functionName: 'approve', args: [RECIPIENT, 100n] });

    const blocked1 = evaluateMandate({ mandate: loadFixture().mandate, tx: { from: SIGNER, to: usdt, data: approveSmall, value: '0x0', chainId: '0x7a69' }, decodedTx: decodeTransactionCalldata({ to: usdt, data: approveSmall, value: '0x0' }), nowMs: NOW, ledger: null });
    assert.strictEqual(blocked1.decision, 'BLOCK', 'non-allowlisted contract blocked');

    const tx = (data) => ({ from: SIGNER, to: usdt, data, value: '0x0', chainId: '0x7a69' });
    const dec = (data) => decodeTransactionCalldata({ to: usdt, data, value: '0x0' });
    assert.strictEqual(evaluateMandate({ mandate: m, tx: tx(approveMax), decodedTx: dec(approveMax), nowMs: NOW, ledger: null }).decision, 'BLOCK', 'unlimited approval blocked');
    assert.strictEqual(evaluateMandate({ mandate: m, tx: tx(approveStranger), decodedTx: dec(approveStranger), nowMs: NOW, ledger: null }).decision, 'BLOCK', 'non-allowlisted spender blocked');
    assert.strictEqual(evaluateMandate({ mandate: m, tx: tx(approveSmall), decodedTx: dec(approveSmall), nowMs: NOW, ledger: null }).decision, 'ALLOW', 'listed spender + limited amount allows');
    const unknownData = '0xdeadbeef00000000000000000000000000000000000000000000000000000000';
    const unknown = evaluateMandate({
      mandate: loadFixture({ contracts: { allow: [usdt] }, selectors: { allow: ['0xdeadbeef'] }, recipients: { allow: [usdt], deny: [] } }).mandate,
      tx: tx(unknownData), decodedTx: dec(unknownData), nowMs: NOW, ledger: null
    });
    assert.strictEqual(unknown.decision, 'UNCERTAIN', 'allowed selector that will not decode cannot authorize');
    console.log('✔ Test 7 Passed: Contract/selector/approval gating.');
  }

  // Test 8: fail-closed defaults — empty allowlists deny everything.
  {
    const m = loadFixture({ recipients: { allow: [], deny: [] } }).mandate;
    assert.strictEqual(evalWith(m, nativeTx()).decision, 'BLOCK', 'empty recipient list denies');
    const m2 = loadFixture({ allowNativeTransfer: false }).mandate;
    assert.strictEqual(evalWith(m2, nativeTx()).decision, 'BLOCK', 'disabled native transfers deny');
    console.log('✔ Test 8 Passed: Empty policy denies by default.');
  }

  // Test 9 (Capability 5 B1): recursive inner-operation authorization.
  {
    const { UNISWAP_V3_ROUTER_ABI, ERC20_ABI } = require('../../src/utils/abiSignatures');
    const { buildSubcallTree, hashSubcallTree } = require('../../src/services/nestedCalls');
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const STRANGER = '0x000000000000000000000000000000000000dEaD';
    const innerApprove = (spender, amount) => encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [spender, amount] });
    const innerTransfer = (to, amount) => encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [to, amount] });
    const batch = (inners) => encodeFunctionData({ abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [inners] });
    const selOf = (data) => data.slice(0, 10).toLowerCase();
    const multiSel = selOf(batch([innerTransfer(RECIPIENT, 1n)]));
    const m = loadFixture({
      contracts: { allow: [ROUTER] },
      selectors: { allow: [multiSel, '0x095ea7b3', '0xa9059cbb'] },
      recipients: { allow: [ROUTER, RECIPIENT], deny: [STRANGER] },
      approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [SPENDER] }
    }).mandate;
    const run = (data) => evaluateMandate({
      mandate: m,
      tx: { from: SIGNER, to: ROUTER, data, value: '0x0', chainId: '0x7a69' },
      decodedTx: decodeTransactionCalldata({ to: ROUTER, data, value: '0x0' }),
      nowMs: NOW, ledger: null
    });
    // Legit batch: allowlisted inner transfer to an allowlisted recipient.
    const good = run(batch([innerTransfer(RECIPIENT, 100n)]));
    assert.strictEqual(good.decision, 'ALLOW', 'authorized batch allows');
    assert.ok(good.checks.some((c) => c.id === 'inner-operations' && c.pass), 'inner pass recorded');
    // Inner approval to a non-allowlisted spender must not execute.
    const evilApprove = run(batch([innerApprove(STRANGER, 100n)]));
    assert.strictEqual(evilApprove.decision, 'BLOCK', 'inner unauthorized spender blocked');
    assert.ok(evilApprove.reasons.join(' ').includes('SC-001'), 'inner provenance in reason');
    assert.ok(evilApprove.checks.some((c) => c.id === 'inner-SC-001-approval-spender' && !c.pass));
    // Inner transfer to a denied recipient.
    const evilXfer = run(batch([innerTransfer(STRANGER, 100n)]));
    assert.strictEqual(evilXfer.decision, 'BLOCK', 'inner denied recipient blocked');
    // Inner unlimited approval where unlimited is prohibited.
    const evilMax = run(batch([innerApprove(SPENDER, (1n << 256n) - 1n)]));
    assert.strictEqual(evilMax.decision, 'BLOCK', 'inner unlimited approval blocked');
    // Inner selector outside the allowlist.
    const m2 = loadFixture({
      contracts: { allow: [ROUTER] }, selectors: { allow: [multiSel] },
      recipients: { allow: [ROUTER, RECIPIENT], deny: [] },
      approvals: { allowUnlimited: false, allowOperatorAll: false, spenderAllowlist: [SPENDER] }
    }).mandate;
    const badSel = evaluateMandate({
      mandate: m2,
      tx: { from: SIGNER, to: ROUTER, data: batch([innerApprove(SPENDER, 100n)]), value: '0x0', chainId: '0x7a69' },
      decodedTx: decodeTransactionCalldata({ to: ROUTER, data: batch([innerApprove(SPENDER, 100n)]), value: '0x0' }),
      nowMs: NOW, ledger: null
    });
    assert.strictEqual(badSel.decision, 'BLOCK', 'inner non-allowlisted selector blocked');
    // Unknown inner operation blocks agent execution (never skipped).
    const unknownData = batch([`0xdeadbeef${'00'.repeat(32)}`]);
    const unknown = run(unknownData);
    assert.strictEqual(unknown.decision, 'BLOCK', 'unknown inner blocks');
    assert.ok(unknown.checks.some((c) => c.id === 'inner-SC-001-interpretable' && !c.pass));
    // Tree hash: deterministic, mutation-sensitive, stable for empty trees.
    const d1 = decodeTransactionCalldata({ to: ROUTER, data: batch([innerTransfer(RECIPIENT, 100n)]), value: '0x0' });
    const d2 = decodeTransactionCalldata({ to: ROUTER, data: batch([innerTransfer(RECIPIENT, 101n)]), value: '0x0' });
    assert.strictEqual(hashSubcallTree(d1), hashSubcallTree(d1), 'hash deterministic');
    assert.notStrictEqual(hashSubcallTree(d1), hashSubcallTree(d2), 'inner mutation changes hash');
    assert.strictEqual(
      hashSubcallTree(decodeTransactionCalldata({ to: RECIPIENT, data: '0x', value: '0x0' })),
      hashSubcallTree({}),
      'empty tree hash stable'
    );
    assert.ok(buildSubcallTree(d1).subcalls.length === 1, 'sanity: one inner decoded');
    // Over-bound batches fail closed instead of sampling a subset.
    const many = { contract: ROUTER, parameters: { calls: [] } };
    for (let i = 0; i < 501; i += 1) {
      many.parameters.calls.push({ functionName: 'transfer', standard: 'ERC20', selector: '0xa9059cbb', args: [RECIPIENT, 1n] });
    }
    const over = evaluateMandate({
      mandate: m,
      tx: { from: SIGNER, to: ROUTER, data: batch([innerTransfer(RECIPIENT, 1n)]), value: '0x0', chainId: '0x7a69' },
      decodedTx: many, nowMs: NOW, ledger: null
    });
    assert.strictEqual(over.decision, 'UNCERTAIN', 'over-bound batch cannot authorize');
    console.log('✔ Test 9 Passed: Recursive inner-operation mandate authorization + tree binding.');
  }

  console.log('\nAll Mandate Engine Tests Passed Successfully!\n');
}

if (require.main === module) {
  runMandateTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runMandateTests };
