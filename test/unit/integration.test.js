/**
 * Visual Sentry End-to-End Evaluation Pipeline Tests
 * Verifies the 3 Core Hackathon Scenarios:
 * 1. Deceptive Scenario -> MISMATCH
 * 2. Legitimate Scenario -> MATCH
 * 3. Ambiguous Scenario -> UNCERTAIN
 */

const assert = require('assert');
const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
const { closeOcrWorker } = require('../../src/services/ocrService');

// Mock Express req/res helper
function createMockHttp(body) {
  return new Promise((resolve) => {
    const req = { body };
    const res = {
      statusCode: 200,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        resolve({ status: this.statusCode, body: payload });
      }
    };
    handleEvaluateTransaction(req, res);
  });
}

// 1x1 transparent PNG base64
const DUMMY_PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

async function runIntegrationTests() {
  console.log('Running Visual Sentry End-to-End Integration Tests...\n');

  // Scenario 1: Deceptive Phishing Airdrop -> Expects MISMATCH
  console.log('[Scenario 1] Testing Deceptive Phishing Airdrop...');
  const res1 = await createMockHttp({
    screenshot: DUMMY_PNG,
    pageContext: {
      url: 'https://uniswap-airdrop-claim.fake/reward',
      title: 'Claim 1,000 UNI Free Community Airdrop'
    },
    transaction: {
      from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      to: '0xdAC17F958D2ee523a2206206994597C13D831ec7', // USDT
      data: '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      value: '0x0'
    }
  });

  assert.strictEqual(res1.status, 200);
  assert.strictEqual(res1.body.verdict, 'MISMATCH', 'Scenario 1 should yield MISMATCH');
  assert.strictEqual(res1.body.decodedTransaction.isUnlimitedApproval, true);
  assert.ok(res1.body.safetyNotice.includes('A MATCH verdict indicates visual alignment'));
  // Simulation must be attempted for MISMATCH — but only genuine EVM execution
  // may report executed:true (FALLBACK/FAILED must stay honest).
  const sim1 = res1.body.simulation;
  assert.ok(['EXECUTED', 'FALLBACK', 'FAILED'].includes(sim1.status), `Simulation must be attempted for MISMATCH (got ${sim1.status})`);
  assert.strictEqual(sim1.executed, sim1.status === 'EXECUTED', 'Only genuine EVM execution may report executed:true');
  if (sim1.status !== 'EXECUTED') {
    assert.strictEqual(sim1.success, false, 'Non-executed simulation must not report success');
  }
  // Provenance: screenshot supplied (OCR ran), no DOM text supplied.
  const sources1 = res1.body.visualEvidence.textSources;
  assert.deepStrictEqual(sources1.map(s => s.source), ['OCR_TEXT', 'DOM_TEXT']);
  assert.strictEqual(sources1[0].available, true, 'Screenshot was supplied so the OCR lane ran');
  assert.strictEqual(sources1[1].available, false, 'No DOM text was supplied');
  console.log(`✔ Scenario 1 Passed: Verdict = ${res1.body.verdict} | Simulation Honestly Reported (${sim1.status}).`);

  // Scenario 2: Legitimate Swap -> Expects MATCH
  console.log('\n[Scenario 2] Testing Legitimate DEX Swap...');
  const res2 = await createMockHttp({
    screenshot: DUMMY_PNG,
    pageContext: {
      url: 'https://app.uniswap.org/#/swap',
      title: 'Swap 1.0 ETH for 3,450 USDC'
    },
    transaction: {
      from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Uniswap Router
      data: '0x04e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4',
      value: '0xde0b6b3a7640000'
    }
  });

  assert.strictEqual(res2.status, 200);
  assert.strictEqual(res2.body.verdict, 'MATCH', 'Scenario 2 should yield MATCH');
  assert.ok(res2.body.safetyNotice.includes('NOT that the target contract or protocol is secure'));
  assert.strictEqual(res2.body.pageEvidence.title, 'Swap 1.0 ETH for 3,450 USDC', 'Supplied page title must survive the pipeline');
  assert.strictEqual(res2.body.simulation.status, 'NOT_RUN', 'Low-risk MATCH must not claim a simulation');
  console.log(`✔ Scenario 2 Passed: Verdict = ${res2.body.verdict} | Visual and Transaction Aligned.`);

  // Scenario 3: Ambiguous Contract Call -> Expects UNCERTAIN
  console.log('\n[Scenario 3] Testing Ambiguous Proxy Interaction...');
  const res3 = await createMockHttp({
    screenshot: DUMMY_PNG,
    pageContext: {
      url: 'https://dao-voting-portal.eth/vote',
      title: 'Governance Proposal #42'
    },
    transaction: {
      from: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
      to: '0x1234567890123456789012345678901234567890', // Unknown contract
      data: '0x79c65092000000000000000000000000000000000000000000000000000000000000002a',
      value: '0x0'
    }
  });

  assert.strictEqual(res3.status, 200);
  assert.strictEqual(res3.body.verdict, 'UNCERTAIN', 'Scenario 3 should yield UNCERTAIN');
  console.log(`✔ Scenario 3 Passed: Verdict = ${res3.body.verdict} | Ambiguity Gracefully Handled.`);

  console.log('\n======================================================');
  console.log('   All 3 Hackathon Scenarios Passed with 100% Match!  ');
  console.log('======================================================\n');
}

if (require.main === module) {
  runIntegrationTests()
    .then(() => closeOcrWorker())
    .catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runIntegrationTests };
