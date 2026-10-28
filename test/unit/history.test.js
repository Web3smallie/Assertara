const assert = require('assert');
const {
  discoverApprovals, fetchApprovals, computeExposure, classifyRpcError,
  APPROVAL_TOPIC, APPROVAL_EVENT, KNOWN_TOKENS, KNOWN_TOKEN_LIST_VERSION
} = require('../../src/agent/chain');
const { runSentinel } = require('../../src/agent/features');

const OWNER = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const TOKEN = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const TOKEN2 = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
const pad = (a) => `0x000000000000000000000000${a.slice(2).toLowerCase()}`;

function makeLog({ token = TOKEN, owner = OWNER, spender = SPENDER, txHash = '0xaaa', blockNumber = 900n, logIndex = 3 } = {}) {
  return {
    address: token,
    topics: [APPROVAL_TOPIC, pad(owner), pad(spender)],
    transactionHash: txHash,
    blockNumber,
    logIndex
  };
}

// Scriptable mock RPC client. All unit tests below are deterministic mocks;
// live provider behavior was verified separately with real RPC probes
// (see contracts §15) and is NOT re-probed by this suite.
function scriptClient({ tip = 1000n, chainId = 1, hasChainId = true, onLogs = async () => [], allowance = async () => 0n } = {}) {
  const calls = { getLogs: [], getBlockNumber: 0, getChainId: 0, readContract: [] };
  const client = {
    calls,
    async getBlockNumber() { calls.getBlockNumber += 1; return tip; },
    async getLogs(args) { calls.getLogs.push(args); return onLogs(args, calls.getLogs.length); },
    async readContract(args) { calls.readContract.push(args); return allowance(args); }
  };
  if (hasChainId) client.getChainId = async () => { calls.getChainId += 1; return chainId; };
  return client;
}

function rpcError({ status = null, code = null, message = 'boom', headers = null } = {}) {
  const err = new Error(message);
  if (status !== null) err.status = status;
  if (code !== null) err.code = code;
  if (headers) err.headers = headers;
  return err;
}

async function runHistoryTests() {
  console.log('Testing Historical Discovery: Chunking, Coverage & Retry Honesty...\n');

  // Test 1: valid bounded query uses event+args filtering and rich records.
  {
    const log = makeLog({});
    const client = scriptClient({ onLogs: async (args) => (args.fromBlock === 0n ? [log] : []) });
    const res = await discoverApprovals({
      owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 99n, chunkBlocks: 40, client
    });
    assert.strictEqual(res.coverage.status, 'COMPLETE_WITHIN_REQUESTED_SCOPE');
    assert.strictEqual(client.calls.getLogs.length, 3, '100 blocks / 40 per chunk = 3 calls');
    for (const args of client.calls.getLogs) {
      assert.strictEqual(args.address, TOKEN);
      assert.strictEqual(args.event, APPROVAL_EVENT, 'Filter must use viem event+args, never raw topics');
      assert.deepStrictEqual(args.args, { owner: OWNER });
      assert.ok(!('topics' in args), 'Raw topics prop must never be sent (viem drops it silently)');
    }
    assert.strictEqual(res.approvals.length, 1);
    assert.deepStrictEqual(
      [res.approvals[0].txHash, res.approvals[0].logIndex, res.approvals[0].chainId, res.approvals[0].source],
      ['0xaaa', '3', 1, 'rpc-logs']
    );
    assert.ok(typeof res.approvals[0].retrievedAt === 'string');
    assert.strictEqual(res.approvals[0].allowance, '0');
    assert.strictEqual(res.coverage.retrievedScope.foreignLogsFiltered, 0);
    assert.strictEqual(res.coverage.provider.chainId, 1);
    console.log('✔ Test 1 Passed: Bounded query filters correctly with rich records.');
  }

  // Test 2: invalid inputs rejected with codes before any network use.
  {
    const client = scriptClient({});
    const bad = [
      [{ owner: '0x123', client }, 'BAD_ADDRESS'],
      [{ owner: OWNER, tokens: ['0x123'], client }, 'BAD_ADDRESS'],
      [{ owner: OWNER, tokens: [], client }, 'BAD_TOKENS'],
      [{ owner: OWNER, chainId: 0, client }, 'BAD_CHAIN'],
      [{ owner: OWNER, chainId: 1.5, client }, 'BAD_CHAIN'],
      [{ owner: OWNER, tokens: [TOKEN], fromBlock: 50n, toBlock: 10n, client }, 'BAD_BLOCK_RANGE'],
      [{ owner: OWNER, tokens: [TOKEN], fromBlock: -1, client }, 'BAD_BLOCK_RANGE'],
      [{ owner: OWNER, tokens: [TOKEN], chunkBlocks: 0, client }, 'BAD_CHUNKING'],
      [{ owner: OWNER, tokens: [TOKEN], maxCalls: 0, client }, 'BAD_LIMITS'],
      [{ owner: OWNER, tokens: [TOKEN], maxLogs: 0, client }, 'BAD_LIMITS']
    ];
    for (const [input, code] of bad) {
      await assert.rejects(discoverApprovals(input), (e) => e.code === code, `expected ${code}`);
    }
    assert.strictEqual(client.calls.getBlockNumber, 0, 'Validation must precede network use');
    const wrongChain = scriptClient({ chainId: 137 });
    await assert.rejects(
      discoverApprovals({ owner: OWNER, tokens: [TOKEN], client: wrongChain }),
      (e) => e.code === 'CHAIN_MISMATCH'
    );
    console.log('✔ Test 2 Passed: Invalid inputs rejected before network use.');
  }

  // Test 3: chunk boundaries are exact and contiguous.
  {
    const client = scriptClient({});
    await discoverApprovals({ owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 99n, chunkBlocks: 30, client });
    const ranges = client.calls.getLogs.map((a) => [a.fromBlock, a.toBlock]);
    assert.deepStrictEqual(ranges, [[0n, 29n], [30n, 59n], [60n, 89n], [90n, 99n]]);
    // Hex and number bounds are accepted and normalized.
    const client2 = scriptClient({ tip: 200n });
    await discoverApprovals({ owner: OWNER, tokens: [TOKEN], fromBlock: 100, toBlock: '0xC8', chunkBlocks: 500, client: client2 });
    assert.deepStrictEqual(client2.calls.getLogs.map((a) => [a.fromBlock, a.toBlock]), [[100n, 200n]]);
    console.log('✔ Test 3 Passed: Chunking splits ranges exactly.');
  }

  // Test 4: duplicates eliminated; foreign logs filtered, never ingested.
  {
    const dup = makeLog({ txHash: '0xdup', logIndex: 1 });
    const sameTxOtherIndex = makeLog({ txHash: '0xdup', logIndex: 2 });
    const foreign = makeLog({ owner: '0x1111111111111111111111111111111111111111', txHash: '0xforeign', logIndex: 0 });
    const wrongToken = makeLog({ token: TOKEN2, txHash: '0xwrong', logIndex: 0 });
    const client = scriptClient({ onLogs: async () => [dup, dup, sameTxOtherIndex, foreign, wrongToken] });
    const res = await discoverApprovals({
      owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 10n, chunkBlocks: 50, client,
      // silence allowance reads: not relevant here
    });
    assert.strictEqual(res.coverage.retrievedScope.eventsKept, 2, 'Dup collapsed; distinct logIndex kept');
    assert.strictEqual(res.coverage.retrievedScope.foreignLogsFiltered, 2, 'Foreign owner + foreign token filtered');
    assert.ok(res.approvals.every((a) => a.txHash === '0xdup'), 'Only owner events ingested');
    console.log('✔ Test 4 Passed: Dedup by txHash:logIndex; foreign logs excluded.');
  }

  // Test 5: transient failures retry exactly once, honoring Retry-After.
  {
    const slept = [];
    const sleep = async (ms) => { slept.push(ms); };
    let attempts = 0;
    const client = scriptClient({
      onLogs: async () => {
        attempts += 1;
        if (attempts === 1) throw rpcError({ status: 429, message: 'too many requests', headers: { 'retry-after': '2' } });
        return [];
      }
    });
    const res = await discoverApprovals({ owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 5n, client, sleep });
    assert.strictEqual(attempts, 2, 'Exactly one retry');
    assert.deepStrictEqual(slept, [2000], 'Retry-After honored');
    assert.strictEqual(res.coverage.status, 'COMPLETE_WITHIN_REQUESTED_SCOPE');
    // 500 without Retry-After falls back to 500ms; persistent failure gaps out.
    const slept2 = [];
    let attempts2 = 0;
    const client2 = scriptClient({
      onLogs: async () => { attempts2 += 1; throw rpcError({ status: 500, message: 'server exploded' }); }
    });
    const res2 = await discoverApprovals({
      owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 5n, client: client2, sleep: async (ms) => { slept2.push(ms); }
    });
    assert.strictEqual(attempts2, 2, 'Persistent 5xx stops after one retry');
    assert.deepStrictEqual(slept2, [500]);
    assert.strictEqual(res2.coverage.status, 'HISTORY_UNAVAILABLE');
    assert.strictEqual(res2.coverage.gaps[0].reason, 'QUERY_FAILED');
    // Retry-After is capped at 10s.
    assert.strictEqual(classifyRpcError(rpcError({ status: 429, headers: { 'retry-after': '99' } })).retryAfterMs, 10000);
    console.log('✔ Test 5 Passed: One retry on transient; backoff policy honored.');
  }

  // Test 6: permanent errors never retry; gaps say QUERY_REJECTED.
  {
    const permanent = [
      rpcError({ status: 403, code: -32602, message: 'Archive requests require a personal token' }),
      rpcError({ code: -32701, message: 'Please specify an address in your request' }),
      rpcError({ status: 400, message: 'invalid params' })
    ];
    for (const err of permanent) {
      let attempts = 0;
      const client = scriptClient({
        onLogs: async () => { attempts += 1; throw err; }
      });
      const res = await discoverApprovals({ owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 5n, client });
      assert.strictEqual(attempts, 1, `No retry for: ${err.message}`);
      assert.strictEqual(res.coverage.gaps[0].reason, 'QUERY_REJECTED');
    }
    assert.strictEqual(classifyRpcError(rpcError({ message: 'weird shape' })).retryable, false, 'Unknown fails closed');
    console.log('✔ Test 6 Passed: Permanent failures single-attempt with QUERY_REJECTED.');
  }

  // Test 7: unsupported scopes fail explicitly; chain check skips cleanly.
  {
    const client = scriptClient({});
    await assert.rejects(
      discoverApprovals({ owner: OWNER, chainId: 137, client }),
      (e) => e.code === 'CHAIN_REGISTRY_UNAVAILABLE'
    );
    // Explicit tokens work on any chain (provider chain verified when possible).
    const alt = scriptClient({ chainId: 137 });
    const res = await discoverApprovals({ owner: OWNER, chainId: 137, tokens: [TOKEN], fromBlock: 0n, toBlock: 5n, client: alt });
    assert.strictEqual(res.coverage.status, 'COMPLETE_WITHIN_REQUESTED_SCOPE');
    // Clients without getChainId proceed (documented skip), still validated otherwise.
    const noChainId = scriptClient({ hasChainId: false });
    const res2 = await discoverApprovals({ owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 5n, client: noChainId });
    assert.strictEqual(res2.coverage.status, 'COMPLETE_WITHIN_REQUESTED_SCOPE');
    console.log('✔ Test 7 Passed: Registry limits explicit; chain check degrades gracefully.');
  }

  // Test 8: partial results report gaps; caps truncate honestly.
  {
    // One of two chunks fails after its retry: PARTIAL with the failed range.
    const client = scriptClient({
      onLogs: async (args) => {
        if (args.fromBlock === 0n) throw rpcError({ status: 500, message: 'shard down' });
        return [makeLog({ blockNumber: 60n })];
      }
    });
    const res = await discoverApprovals({ owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 99n, chunkBlocks: 50, client });
    assert.strictEqual(res.coverage.status, 'PARTIAL_COVERAGE');
    assert.strictEqual(res.coverage.gaps.length, 1);
    assert.deepStrictEqual([res.coverage.gaps[0].fromBlock, res.coverage.gaps[0].toBlock], ['0', '49']);
    assert.strictEqual(res.coverage.gaps[0].reason, 'QUERY_FAILED');
    assert.strictEqual(res.approvals.length, 1, 'Successful chunks still ingested');
    // maxLogs cap truncates with an explicit gap, never silently.
    const many = scriptClient({ onLogs: async () => [makeLog({ txHash: '0x1', logIndex: 1 }), makeLog({ txHash: '0x2', logIndex: 2 })] });
    const capped = await discoverApprovals({ owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 5n, maxLogs: 1, client: many });
    assert.strictEqual(capped.truncated, true);
    assert.strictEqual(capped.coverage.status, 'PARTIAL_COVERAGE');
    assert.ok(capped.coverage.gaps.some((g) => g.reason === 'max-logs-cap'));
    // maxCalls cap leaves the rest as gaps.
    const callCap = await discoverApprovals({
      owner: OWNER, tokens: [TOKEN, TOKEN2], fromBlock: 0n, toBlock: 99n, chunkBlocks: 50, maxCalls: 1, client: scriptClient({})
    });
    assert.strictEqual(callCap.coverage.retrievedScope.callsMade, 1);
    assert.ok(callCap.coverage.gaps.some((g) => g.reason === 'max-calls-cap'));
    console.log('✔ Test 8 Passed: Partial coverage reports exact gaps and caps.');
  }

  // Test 9: sentinel findings link evidence; exposure stays deterministic.
  {
    const big = 2n ** 256n - 1n;
    const client = scriptClient({
      onLogs: async () => [makeLog({ txHash: '0xev1', logIndex: 7, blockNumber: 950n })],
      allowance: async () => big
    });
    const model = { async complete() { return { content: { summary: 'one unlimited', highestRisk: [TOKEN] } }; } };
    const s = await runSentinel({ owner: OWNER, tokens: [TOKEN], fromBlock: 900n, toBlock: 999n }, { client, model });
    assert.strictEqual(s.status, 'OK');
    assert.strictEqual(s.approvals[0].txHash, '0xev1');
    assert.strictEqual(s.approvals[0].logIndex, '7');
    assert.strictEqual(s.exposure.unlimitedCount, 1);
    assert.strictEqual(s.coverage.status, 'COMPLETE_WITHIN_REQUESTED_SCOPE');
    assert.strictEqual(s.narrative.summary, 'one unlimited');
    assert.deepStrictEqual(s.window, { fromBlock: '900', toBlock: '999' });
    // Legacy single-shot path preserved with identical return shape.
    const legacy = await fetchApprovals({ owner: OWNER, client });
    assert.strictEqual(legacy.approvals.length, 1);
    assert.strictEqual(legacy.truncated, false);
    console.log('✔ Test 9 Passed: Findings linked to tx/log evidence; legacy intact.');
  }

  // Test 10: partial history can never imply safety or verification.
  {
    const client = scriptClient({
      onLogs: async (args) => {
        if (args.fromBlock === 0n) throw rpcError({ status: 403, message: 'Archive requests require a personal token' });
        return [];
      }
    });
    const s = await runSentinel({ owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 99n, chunkBlocks: 50 }, { client });
    assert.strictEqual(s.coverage.status, 'PARTIAL_COVERAGE');
    assert.ok(s.completenessNote.includes('PARTIAL coverage'), 'Note must name the partial state');
    assert.ok(s.completenessNote.includes('not evidence of safety'), 'Note must refuse safety claims');
    assert.ok(!/verif/i.test(JSON.stringify({ note: s.completenessNote, status: s.coverage.status })), 'No verification language on partial data');
    const full = await runSentinel({ owner: OWNER, tokens: [TOKEN], fromBlock: 0n, toBlock: 5n }, { client: scriptClient({}) });
    assert.ok(full.completenessNote.includes('Complete within requested scope only'));
    assert.ok(full.completenessNote.includes('Not a claim about other tokens'));
    console.log('✔ Test 10 Passed: Coverage notes refuse unjustified conclusions.');
  }

  // Test 11: Phase 1–5 regression (safeguards, scheduler, PDF, harness, audio).
  {
    const { adjudicate } = require('../../src/agent/verifier');
    const { EvidenceGraph } = require('../../src/agent/evidenceGraph');
    const g = new EvidenceGraph('inv_phase6reg');
    const exp = g.append({ kind: 'ModelReading', producer: 'MODEL', payload: { experimental: true }, created_turn: 1 });
    const capped = adjudicate({ supporting: [exp.id], conflicting: [] }, g, { verdict: 'SUPPORTED', reasons: [] });
    assert.strictEqual(capped.status, 'HYPOTHESIS', 'Phase 1 experimental safeguard intact');
    const { WatchScheduler } = require('../../src/agent/scheduler');
    const fs = require('fs');
    const path = require('path');
    const root = path.join(__dirname, '..', '..', 'data', '.test-tmp');
    fs.mkdirSync(root, { recursive: true });
    const scratch = fs.mkdtempSync(path.join(root, 'assertara-history-'));
    let now = Date.now();
    const sched = new WatchScheduler({ dir: scratch, now: () => now });
    sched.client = {
      async getBytecode() { return '0x11'; },
      async getStorageAt() { return '0x0000000000000000000000000000000000000000000000000000000000000000'; }
    };
    sched.addTarget({ address: OWNER, intervalMs: 5000 });
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
    const t = ingestTranscript({ text: 'hello' });
    assert.ok(t.turns.every((x) => x.provenance === 'TRANSCRIPT_PROVIDED'), 'Phase 5 audio provenance intact');
    assert.deepStrictEqual(KNOWN_TOKENS.length, 6, 'Token registry stable');
    assert.strictEqual(KNOWN_TOKEN_LIST_VERSION, 'mainnet-major-v1');
    assert.ok(computeExposure([]).approvalCount === 0, 'Exposure pure function intact');
    console.log('✔ Test 11 Passed: Phases 1–5 behavior preserved.');
  }

  console.log('\nAll Historical Discovery Tests Passed Successfully!\n');
}

if (require.main === module) {
  runHistoryTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runHistoryTests };
