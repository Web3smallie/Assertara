const assert = require('assert');
const { buildDossier, parseAbi, STANDINGS, BEACON_SLOT } = require('../../src/agent/dossier');
const { runDossier } = require('../../src/agent/features');

const ADDR = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const IMPL = '0x1111111111111111111111111111111111111111';
const ADMIN = '0x2222222222222222222222222222222222222222';
const IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = '0xb53127684a568b3173ae13b250a82a706b1f155a31b16e3cb5684d5a18009d15';
const ZERO_SLOT = '0x0000000000000000000000000000000000000000000000000000000000000000';
const padAddr = (a) => `0x000000000000000000000000${a.slice(2).toLowerCase()}`;

// Deterministic mock chain client. All unit tests below use mocks; live RPC
// behavior was verified separately with real probes (see contracts §16).
function mockClient({ bytecode = '0x6080604055', impl = null, admin = null, beacon = null, chainId = 1, tip = 100n, fail = null } = {}) {
  const calls = { getBytecode: 0, getStorageAt: 0, getLogs: 0 };
  return {
    calls,
    async getBytecode() {
      calls.getBytecode += 1;
      if (fail && fail.getBytecode) throw fail.getBytecode(calls.getBytecode);
      return bytecode;
    },
    async getStorageAt({ slot }) {
      calls.getStorageAt += 1;
      const s = String(slot).toLowerCase();
      if (s === IMPL_SLOT) return impl ? padAddr(impl) : ZERO_SLOT;
      if (s === ADMIN_SLOT) return admin ? padAddr(admin) : ZERO_SLOT;
      if (s === BEACON_SLOT.toLowerCase()) return beacon ? padAddr(beacon) : ZERO_SLOT;
      return ZERO_SLOT;
    },
    async getChainId() { return chainId; },
    async getBlockNumber() { return tip; },
    async getLogs() { calls.getLogs += 1; return []; },
    async readContract() { return 0n; }
  };
}

const SAMPLE_ABI = [
  { type: 'function', name: 'transfer', inputs: [{ name: 'to', type: 'address' }, { name: 'amt', type: 'uint256' }], outputs: [{ name: '', type: 'bool' }], stateMutability: 'nonpayable' },
  { type: 'function', name: 'mint', inputs: [{ name: 'to', type: 'address' }, { name: 'amt', type: 'uint256' }], outputs: [], stateMutability: 'nonpayable' },
  { type: 'function', name: 'pause', inputs: [], outputs: [], stateMutability: 'nonpayable' },
  { type: 'function', name: 'owner', inputs: [], outputs: [{ name: '', type: 'address' }], stateMutability: 'view' },
  { type: 'event', name: 'Transfer', inputs: [] }
];

const SOURCE_FILES = {
  sources: {
    'Vault.sol': { content: 'pragma solidity ^0.8.0;\ncontract Vault {\naddress public owner;\nfunction withdraw() external onlyOwner {\n_pay(msg.sender);\n}\nfunction mint(address to) external onlyOwner {\n_mint(to, 1);\n}\nfunction pause() external onlyOwner {\n_pause();\n}\n}' },
    'Ownable.sol': { content: 'pragma solidity ^0.8.0;\ncontract Ownable {\nmodifier onlyOwner() {\nrequire(msg.sender == owner);\n_;\n}\n}' }
  }
};

function sourceProvider(result) {
  return {
    name: 'mock-explorer',
    async fetch() {
      if (typeof result === 'function') return result();
      if (result instanceof Error) throw result;
      return result;
    }
  };
}

async function runDossierTests() {
  console.log('Testing Contract Dossier: Sections, Standings & Analysis...\n');

  // Test 1: valid inputs produce all nine sections with identity verified.
  {
    const d = await buildDossier({ address: ADDR, client: mockClient({}), history: false });
    for (const section of ['identity', 'bytecode', 'source', 'abi', 'privileges', 'proxy', 'history', 'limitations', 'riskObservations']) {
      assert.ok(section in d, `section ${section} present`);
    }
    assert.strictEqual(d.identity.address, ADDR.toLowerCase());
    assert.strictEqual(d.identity.chainId, 1);
    assert.strictEqual(d.identity.chainVerified, true);
    assert.strictEqual(d.feature, 'F7_dossier');
    assert.ok(typeof d.builtAt === 'string');
    console.log('✔ Test 1 Passed: Nine-section dossier with verified identity.');
  }

  // Test 2: invalid addresses and chain mismatches rejected loudly.
  {
    await assert.rejects(buildDossier({ address: '0x123', client: mockClient({}) }), (e) => e.code === 'BAD_ADDRESS');
    await assert.rejects(buildDossier({ address: ADDR, chainId: 0, client: mockClient({}) }), (e) => e.code === 'BAD_CHAIN');
    await assert.rejects(
      buildDossier({ address: ADDR, chainId: 137, client: mockClient({ chainId: 1 }) }),
      (e) => e.code === 'CHAIN_MISMATCH'
    );
    console.log('✔ Test 2 Passed: Invalid inputs rejected with codes.');
  }

  // Test 3: bytecode presence hashed; absence observed, never invented.
  {
    const code = '0x60806040556080';
    const d = await buildDossier({ address: ADDR, client: mockClient({ bytecode: code }), history: false });
    assert.strictEqual(d.bytecode.standing, 'OBSERVED');
    assert.strictEqual(d.bytecode.hasCode, true);
    assert.strictEqual(d.bytecode.bytecodeLength, (code.length - 2) / 2);
    assert.ok(/^0x[0-9a-f]{64}$/.test(d.bytecode.codeHash), 'keccak code hash recorded');
    const eoa = await buildDossier({ address: ADDR, client: mockClient({ bytecode: '0x' }), history: false });
    assert.strictEqual(eoa.bytecode.standing, 'OBSERVED', 'Absence is observed data');
    assert.strictEqual(eoa.bytecode.hasCode, false);
    assert.ok(eoa.limitations.some((l) => l.reason === 'no-bytecode'));
    assert.ok(eoa.riskObservations.some((r) => r.basis === 'bytecode-absence' && r.severity === 'info'));
    console.log('✔ Test 3 Passed: Bytecode hashed when present, absence observed.');
  }

  // Test 4: source retrieval observed, failed, and malformed cases.
  {
    const fetched = {
      ContractName: 'Vault', CompilerVersion: 'v0.8.20+commit.a1b79de6', LicenseType: 'MIT',
      SourceCode: JSON.stringify(SOURCE_FILES)
    };
    const d = await buildDossier({ address: ADDR, client: mockClient({}), sourceProvider: sourceProvider(fetched), history: false });
    assert.strictEqual(d.source.standing, 'OBSERVED');
    assert.strictEqual(d.source.contractName, 'Vault');
    assert.strictEqual(d.source.fileCount, 2);
    assert.ok(/^0x[0-9a-f]{64}$/.test(d.source.sourceHash) || /^[0-9a-f]{64}$/.test(d.source.sourceHash));
    assert.strictEqual(d.source.provider, 'mock-explorer');
    const failed = await buildDossier({
      address: ADDR, client: mockClient({}), sourceProvider: sourceProvider(new Error('explorer down')), history: false
    });
    assert.strictEqual(failed.source.standing, 'UNAVAILABLE');
    assert.strictEqual(failed.source.reason, 'provider-fetch-failed');
    const empty = await buildDossier({
      address: ADDR, client: mockClient({}), sourceProvider: sourceProvider({ ContractName: 'x', SourceCode: '' }), history: false
    });
    assert.strictEqual(empty.source.standing, 'UNAVAILABLE');
    assert.strictEqual(empty.source.reason, 'provider-returned-no-source');
    const none = await buildDossier({ address: ADDR, client: mockClient({}), history: false });
    assert.strictEqual(none.source.standing, 'UNAVAILABLE');
    assert.strictEqual(none.source.reason, 'no-source-provider-configured');
    assert.ok(none.source.requirements.length > 0);
    console.log('✔ Test 4 Passed: Source observed or honestly unavailable.');
  }

  // Test 5: ABI parsing with selectors; malformed ABI handled per origin.
  {
    const parsed = parseAbi(SAMPLE_ABI, 'test');
    assert.strictEqual(parsed.functions.length, 4);
    assert.strictEqual(parsed.events, 1);
    const transfer = parsed.functions.find((f) => f.name === 'transfer');
    assert.strictEqual(transfer.selector, '0xa9059cbb', 'Selector matches the canonical ERC20 value');
    assert.strictEqual(transfer.signature, 'transfer(address,uint256)');
    const d = await buildDossier({ address: ADDR, client: mockClient({}), abi: SAMPLE_ABI, history: false });
    assert.strictEqual(d.abi.standing, 'OBSERVED');
    assert.strictEqual(d.abi.origin, 'PROVIDED', 'Caller ABI labeled provided, never verified');
    await assert.rejects(
      buildDossier({ address: ADDR, client: mockClient({}), abi: [{ type: 'function' }], history: false }),
      (e) => e.code === 'MALFORMED_ABI', 'Malformed caller ABI throws loudly'
    );
    await assert.rejects(
      buildDossier({ address: ADDR, client: mockClient({}), abi: 'not-an-array', history: false }),
      (e) => e.code === 'MALFORMED_ABI'
    );
    // Malformed provider ABI degrades the section instead of killing the dossier.
    const badProvider = await buildDossier({
      address: ADDR, client: mockClient({}),
      sourceProvider: sourceProvider({ ContractName: 'V', SourceCode: 'contract V {}', ABI: '[[broken' }),
      history: false
    });
    assert.strictEqual(badProvider.source.standing, 'OBSERVED');
    assert.strictEqual(badProvider.abi.standing, 'UNRESOLVED');
    console.log('✔ Test 5 Passed: ABI parsed with selectors; faults handled by origin.');
  }

  // Test 6: privilege observations cite evidence and name their basis.
  {
    const fetched = { ContractName: 'Vault', CompilerVersion: 'v0.8.20', SourceCode: JSON.stringify(SOURCE_FILES) };
    const d = await buildDossier({ address: ADDR, client: mockClient({}), sourceProvider: sourceProvider(fetched), history: false });
    assert.strictEqual(d.privileges.standing, 'INFERRED');
    assert.strictEqual(d.privileges.basis, 'source');
    const owners = d.privileges.observations.find((o) => o.indicator === 'owner-restricted-functions');
    assert.ok(owners, 'onlyOwner usage detected');
    assert.ok(owners.evidence.some((r) => r === 'Vault.sol:4'), 'withdraw onlyOwner cited by file:line');
    assert.ok(owners.evidence.some((r) => r === 'Vault.sol:7'), 'mint onlyOwner cited by file:line');
    const mint = d.privileges.observations.find((o) => o.indicator === 'minting-controls');
    assert.ok(mint && mint.evidence.includes('Vault.sol:7'));
    // ABI-only basis is weaker and says so.
    const abiOnly = await buildDossier({ address: ADDR, client: mockClient({}), abi: SAMPLE_ABI, history: false });
    assert.strictEqual(abiOnly.privileges.basis, 'abi');
    const abiMint = abiOnly.privileges.observations.find((o) => o.indicator === 'minting-controls');
    assert.ok(abiMint && /name-only/.test(abiMint.note), 'ABI heuristic labeled name-only');
    assert.ok(abiMint.evidence[0].includes('mint(address,uint256)'));
    console.log('✔ Test 6 Passed: Privileges observed with cited basis.');
  }

  // Test 7: proxy and upgradeability indicators where supported.
  {
    const proxied = await buildDossier({ address: ADDR, client: mockClient({ impl: IMPL, admin: ADMIN }), history: false });
    assert.strictEqual(proxied.proxy.assessment, 'proxy-indicated');
    assert.strictEqual(proxied.proxy.eip1967Implementation.toLowerCase(), IMPL.toLowerCase());
    assert.strictEqual(proxied.proxy.eip1967Admin.toLowerCase(), ADMIN.toLowerCase());
    assert.ok(proxied.riskObservations.some((r) => r.basis === 'proxy-slot' && r.evidence[0].includes(IMPL.toLowerCase())));
    const beaconAddr = '0x3333333333333333333333333333333333333333';
    const beaconed = await buildDossier({ address: ADDR, client: mockClient({ beacon: beaconAddr }), history: false });
    assert.strictEqual(beaconed.proxy.eip1967Beacon.toLowerCase(), beaconAddr.toLowerCase());
    const minimalCode = `0x363d3d373d3d3d363d73${IMPL.slice(2).toLowerCase()}5af43d82803e903d91602b57fd5bf3`;
    const minimal = await buildDossier({ address: ADDR, client: mockClient({ bytecode: minimalCode }), history: false });
    assert.strictEqual(minimal.proxy.assessment, 'proxy-indicated');
    assert.strictEqual(minimal.proxy.minimalProxyImplementation.toLowerCase(), IMPL.toLowerCase());
    const plain = await buildDossier({ address: ADDR, client: mockClient({}), history: false });
    assert.strictEqual(plain.proxy.assessment, 'no-proxy-indicators');
    assert.ok(plain.limitations.some((l) => l.reason === 'non-1967-patterns-unresolved'));
    console.log('✔ Test 7 Passed: 1967/beacon/minimal-proxy indicators analyzed.');
  }

  // Test 8: missing source and incomplete evidence stay explicit.
  {
    const d = await buildDossier({ address: ADDR, client: mockClient({}), history: false });
    assert.strictEqual(d.source.standing, 'UNAVAILABLE');
    assert.strictEqual(d.abi.standing, 'UNAVAILABLE');
    assert.strictEqual(d.privileges.standing, 'UNRESOLVED');
    assert.ok(!('contractName' in d.source) || d.source.contractName === undefined, 'No invented metadata');
    assert.ok(d.limitations.length >= 3, 'Each gap listed with an unresolved question');
    assert.ok(d.limitations.every((l) => l.scope && l.reason && l.question));
    assert.ok(d.riskObservations.every((r) => STANDINGS.includes(r.standing) && Array.isArray(r.evidence)));
    console.log('✔ Test 8 Passed: Gaps explicit; nothing invented.');
  }

  // Test 9: RPC errors propagate for core reads with eligible retry; history contained.
  {
    const counting = { n: 0 };
    const retryClient = mockClient({ bytecode: '0x6080' });
    const innerBytecode = retryClient.getBytecode.bind(retryClient);
    retryClient.getBytecode = async () => {
      counting.n += 1;
      if (counting.n === 1) {
        const err = new Error('server exploded');
        err.status = 500;
        throw err;
      }
      return innerBytecode();
    };
    const d = await buildDossier({ address: ADDR, client: retryClient, history: false }, { sleep: async () => {} });
    assert.strictEqual(d.bytecode.standing, 'OBSERVED', 'Transient 500 retried once, then succeeds');
    // meta attempt (throws) + meta retry (succeeds) + bytecode fetch = 3 reads.
    assert.strictEqual(counting.n, 3);
    // Permanent 403: single attempt, then the dossier build fails loudly.
    let attempts403 = 0;
    const denied = mockClient({});
    denied.getBytecode = async () => {
      attempts403 += 1;
      const err = new Error('forbidden');
      err.status = 403;
      throw err;
    };
    await assert.rejects(buildDossier({ address: ADDR, client: denied, history: false }, { sleep: async () => {} }), /forbidden/);
    assert.strictEqual(attempts403, 1, 'Permanent errors never retry');
    // History failure is contained: dossier completes with UNAVAILABLE history.
    const badHistory = mockClient({});
    badHistory.getLogs = async () => { throw new Error('logs down'); };
    const contained = await buildDossier({ address: ADDR, client: badHistory });
    assert.strictEqual(contained.history.standing, 'UNAVAILABLE');
    assert.strictEqual(contained.bytecode.standing, 'OBSERVED');
    console.log('✔ Test 9 Passed: Core reads retry-then-throw; history fails contained.');
  }

  // Test 10: heuristic observations can never become verified findings.
  {
    const d = await buildDossier({ address: ADDR, client: mockClient({ impl: IMPL }), abi: SAMPLE_ABI, history: false });
    const json = JSON.stringify(d);
    assert.ok(!/"status"\s*:\s*"VERIFIED"/.test(json), 'No VERIFIED status field anywhere');
    assert.ok(!/"verified"\s*:\s*true/.test(json), 'No verified:true flag anywhere');
    assert.ok(d.riskObservations.every((r) => ['info', 'notable'].includes(r.severity)), 'Severities capped at notable');
    assert.ok(!/you are safe|safety guaranteed|proven safe|no risk/i.test(json), 'No safety language');
    // The runner-level synthesis is explicitly unverified interpretation.
    const model = { async complete() { return { content: { summary: 'proxy', flags: [], unknowns: ['impl code'] } }; } };
    const r = await runDossier({ address: ADDR, abi: SAMPLE_ABI, history: false }, { client: mockClient({ impl: IMPL }), model });
    assert.strictEqual(r.synthesis.verified, false);
    assert.strictEqual(r.synthesis.interpretationOf, 'dossier');
    assert.strictEqual(r.meta.eip1967Implementation.toLowerCase(), IMPL.toLowerCase(), 'meta preserved with beacon superset');
    console.log('✔ Test 10 Passed: Heuristics structurally barred from verification.');
  }

  // Test 11: Phase 1–6 regression (safeguards, scheduler, PDF, harness, audio, history).
  {
    const { adjudicate } = require('../../src/agent/verifier');
    const { EvidenceGraph } = require('../../src/agent/evidenceGraph');
    const g = new EvidenceGraph('inv_phase7reg');
    const exp = g.append({ kind: 'ModelReading', producer: 'MODEL', payload: { experimental: true }, created_turn: 1 });
    const capped = adjudicate({ supporting: [exp.id], conflicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(capped.status, 'HYPOTHESIS', 'Phase 1 safeguard intact');
    const { WatchScheduler } = require('../../src/agent/scheduler');
    const fs = require('fs');
    const path = require('path');
    const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
    fs.mkdirSync(root, { recursive: true });
    const scratch = fs.mkdtempSync(path.join(root, 'assertara-dossier-'));
    let now = Date.now();
    const sched = new WatchScheduler({ dir: scratch, now: () => now });
    sched.client = {
      async getBytecode() { return '0x11'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    sched.addTarget({ address: ADDR, intervalMs: 5000 });
    now += 6000;
    assert.strictEqual((await sched.tickOnce()).checked, 1, 'Phase 2 scheduler intact');
    fs.rmSync(scratch, { recursive: true, force: true });
    try { fs.rmdirSync(root); } catch { /* non-empty or gone: leave it */ }
    const { buildPdf } = require('./pdfIngest.test.js');
    const { ingestAuditPdf } = require('../../src/agent/pdfIngest');
    const pdf = await ingestAuditPdf({ data: buildPdf([['H-01 Regression check', 'Body.']]) });
    assert.strictEqual(pdf.findings.length, 1, 'Phase 3 PDF ingest intact');
    const { submitHarnessRun } = require('../../src/agent/harness');
    const statik = await submitHarnessRun({ kind: 'static', files: [{ path: 'a.sol', content: 'x' }] });
    assert.strictEqual(statik.status, 'STATIC_ANALYSIS_ONLY', 'Phase 4 harness intact');
    const { ingestTranscript } = require('../../src/agent/audioIngest');
    assert.ok(ingestTranscript({ text: 'hi' }).turns.every((x) => x.provenance === 'TRANSCRIPT_PROVIDED'), 'Phase 5 audio intact');
    const { discoverApprovals } = require('../../src/agent/chain');
    const hist = await discoverApprovals({
      owner: ADDR, tokens: ['0xdAC17F958D2ee523a2206206994597C13D831ec7'],
      fromBlock: 0n, toBlock: 5n, client: mockClient({})
    });
    assert.strictEqual(hist.coverage.status, 'COMPLETE_WITHIN_REQUESTED_SCOPE', 'Phase 6 history intact');
    console.log('✔ Test 11 Passed: Phases 1–6 behavior preserved.');
  }

  console.log('\nAll Contract Dossier Tests Passed Successfully!\n');
}

if (require.main === module) {
  runDossierTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runDossierTests };
