const assert = require('assert');

// Bounded submission-tx discovery (judge log search): no wide
// fromBlock/toBlock ranges, adaptive shrink on provider range errors,
// clean { error } results instead of throws.

const { findSubmissionTx, LOG_CHUNK_BLOCKS, LOG_MAX_CHUNKS } = require('../../src/attestation/judge');

const TOPICS = ['0xsig', '0xid'];

function fakeRpc({ head, logAt, rangeLimit, failHead }) {
  const calls = [];
  const call = async (method, params) => {
    calls.push({ method, params });
    if (method === 'eth_blockNumber') {
      if (failHead) throw new Error(failHead);
      return `0x${head.toString(16)}`;
    }
    const q = params[0];
    const from = parseInt(q.fromBlock, 16);
    const to = parseInt(q.toBlock, 16);
    if (rangeLimit && (to - from + 1) > rangeLimit) {
      throw new Error('requested range too large');
    }
    if (logAt !== null && logAt !== undefined && from <= logAt && logAt <= to) {
      return [{ transactionHash: `0x${'ab'.repeat(32)}`, blockNumber: `0x${logAt.toString(16)}` }];
    }
    return [];
  };
  return { call, calls };
}

async function runJudgeLogsTests() {
  console.log('Testing judge bounded log search...\n');

  // Test 1: finds a recent log with small bounded ranges only.
  {
    const { call, calls } = fakeRpc({ head: 100000, logAt: 99950 });
    const found = await findSubmissionTx(call, '0xcontract', TOPICS);
    assert.strictEqual(found.tx, `0x${'ab'.repeat(32)}`, 'submission tx returned');
    assert.ok(found.blocks > 0 && found.blocks <= LOG_CHUNK_BLOCKS, 'blocks scanned reported');
    const logCalls = calls.filter((c) => c.method === 'eth_getLogs');
    assert.ok(logCalls.length >= 1, 'at least one log query ran');
    for (const c of logCalls) {
      const span = parseInt(c.params[0].toBlock, 16) - parseInt(c.params[0].fromBlock, 16) + 1;
      assert.ok(span <= LOG_CHUNK_BLOCKS, `range bounded (${span} blocks)`);
    }
    console.log('✔ Test 1 Passed: recent log found with bounded ranges.');
  }

  // Test 2: scans backwards across chunks to an older log.
  {
    const { call, calls } = fakeRpc({ head: 100000, logAt: 100000 - 2 * LOG_CHUNK_BLOCKS - 10 });
    const found = await findSubmissionTx(call, '0xcontract', TOPICS);
    assert.strictEqual(found.tx, `0x${'ab'.repeat(32)}`, 'older log found');
    assert.ok(calls.filter((c) => c.method === 'eth_getLogs').length >= 3, 'multiple chunks scanned');
    console.log('✔ Test 2 Passed: backward chunk scan reaches older logs.');
  }

  // Test 3: strict provider rejects even default chunks; search shrinks and still finds the log.
  {
    const { call, calls } = fakeRpc({ head: 5000, logAt: 4950, rangeLimit: 500 });
    const found = await findSubmissionTx(call, '0xcontract', TOPICS);
    assert.strictEqual(found.tx, `0x${'ab'.repeat(32)}`, 'log found after shrink');
    const logCalls = calls.filter((c) => c.method === 'eth_getLogs');
    assert.ok(logCalls.length >= 2, 'retried with smaller chunks');
    const last = logCalls[logCalls.length - 1];
    const span = parseInt(last.params[0].toBlock, 16) - parseInt(last.params[0].fromBlock, 16) + 1;
    assert.ok(span <= 500, `final range fits provider limit (${span} blocks)`);
    console.log('✔ Test 3 Passed: range errors shrink the chunk instead of failing.');
  }

  // Test 4: log beyond the scan window returns a clean error naming --submit-tx.
  {
    const { call } = fakeRpc({ head: 1000000, logAt: 1 });
    const found = await findSubmissionTx(call, '0xcontract', TOPICS);
    assert.ok(!found.tx, 'no tx claimed');
    assert.ok(found.error.includes('--submit-tx'), 'error directs to --submit-tx');
    console.log('✔ Test 4 Passed: out-of-window log fails cleanly with guidance.');
  }

  // Test 5: provider failures never throw.
  {
    const { call } = fakeRpc({ head: 0, logAt: null, failHead: 'boom' });
    const found = await findSubmissionTx(call, '0xcontract', TOPICS);
    assert.ok(!found.tx && found.error.includes('boom'), 'head failure is a clean error');
    const down = async () => { throw new Error('connection reset'); };
    const found2 = await findSubmissionTx(down, '0xcontract', TOPICS);
    assert.ok(!found2.tx && found2.error.includes('connection reset'), 'rpc failure is a clean error');
    console.log('✔ Test 5 Passed: RPC failures return errors, never throw.');
  }

  // Test 6: scan depth is capped (no unbounded walk on huge chains).
  {
    const { call, calls } = fakeRpc({ head: 70000000, logAt: null });
    const found = await findSubmissionTx(call, '0xcontract', TOPICS);
    assert.ok(!found.tx, 'no false hit');
    assert.ok(calls.filter((c) => c.method === 'eth_getLogs').length <= LOG_MAX_CHUNKS, 'chunk count capped');
    console.log('✔ Test 6 Passed: scan depth capped on huge chains.');
  }

  console.log('\nAll judge log-search tests passed.');
}

if (require.main === module) {
  runJudgeLogsTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runJudgeLogsTests };
