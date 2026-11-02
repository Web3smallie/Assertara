// Phase 3 (Capability #9): transaction-summary OCR isolation.
// Verifies the deterministic selector that picks the primary transaction-intent
// text from summary-prompt regions, keeping every other outcome explicit.
const assert = require('assert');
const { selectSummaryText } = require('../../src/utils/summary');

const SUM = 'transaction summary';
const DIALOG = 'dialog box';
const OPTS = { summaryPrompts: [SUM] };
const select = (regions) => selectSummaryText(regions, OPTS);

function summaryRegion(regionId, ocr, prompts = [SUM]) {
  return { regionId, prompts, ocr };
}
const TEXT = (text) => ({ text, error: null });
const EMPTY = { text: null, empty: true, error: null };
const FAILED = (message) => ({ text: null, error: { code: 'OCR_FAILED', message } });

async function runSummaryTests() {
  console.log('\n=== Running Transaction-Summary Isolation Tests ===');

  // Test 1: a single usable summary region yields targeted intent text.
  {
    const view = select([
      summaryRegion('R-1', TEXT('Send 1.0 ETH to 0xabc')),
      summaryRegion('R-2', TEXT('Settings | Help | Blog'), ['navigation'])
    ]);
    assert.strictEqual(view.status, 'targeted');
    assert.strictEqual(view.text, 'Send 1.0 ETH to 0xabc');
    assert.deepStrictEqual(view.regionIds, ['R-1']);
    assert.ok(!view.text.includes('Settings'), 'Navigation stays out');
    assert.deepStrictEqual(view.issues, []);
  }
  console.log('✔ Test 1 Passed: Targeted summary text selected.');

  // Test 2: several summary regions are AMBIGUOUS by design — texts join
  // without choosing a candidate; navigation still stays out.
  {
    const view = select([
      summaryRegion('R-1', TEXT('Swap 1.0 ETH')),
      summaryRegion('R-2', TEXT('for 3,450 USDC — Confirm Swap')),
      summaryRegion('R-3', TEXT('Advertisement: earn 10x'), ['banner'])
    ]);
    assert.strictEqual(view.status, 'ambiguous');
    assert.strictEqual(view.text, 'Swap 1.0 ETH\nfor 3,450 USDC — Confirm Swap');
    assert.deepStrictEqual(view.regionIds, ['R-1', 'R-2']);
    assert.ok(!view.text.includes('Advertisement'), 'Ads stay out');
  }
  console.log('✔ Test 2 Passed: Multi-candidate summaries stay ambiguous.');

  // Test 3: mixed multi-prompt region still counts as a summary candidate.
  {
    const view = select([
      summaryRegion('R-1', TEXT('Amount: 1.0 ETH'), [DIALOG, SUM])
    ]);
    assert.strictEqual(view.status, 'targeted');
    assert.deepStrictEqual(view.regionIds, ['R-1']);
  }
  console.log('✔ Test 3 Passed: Multi-prompt regions are candidates.');

  // Test 4: generic detections never impersonate a summary — the caller
  // falls back to the labeled full scan instead.
  {
    const view = select([
      summaryRegion('R-1', TEXT('Swap 1.0 ETH'), []),
      summaryRegion('R-2', TEXT('Approve unlimited USDC'), ['button'])
    ]);
    assert.strictEqual(view.status, 'no-summary-regions');
    assert.strictEqual(view.text, '');
    assert.deepStrictEqual(view.regionIds, []);
  }
  console.log('✔ Test 4 Passed: Generic regions are not summaries.');

  // Test 5: a lone generic region is likewise not a summary.
  {
    const view = select([
      summaryRegion('R-1', TEXT('Confirm: 1.0 ETH'), ['button'])
    ]);
    assert.strictEqual(view.status, 'no-summary-regions');
    assert.strictEqual(view.text, '');
  }
  console.log('✔ Test 5 Passed: Lone generic region is not a summary.');

  // Test 6: failed summary OCR stays distinct from empty OCR.
  {
    const failed = select([
      summaryRegion('R-1', FAILED('worker crashed'))
    ]);
    assert.strictEqual(failed.status, 'ocr-failed');
    assert.strictEqual(failed.text, '');
    assert.deepStrictEqual(failed.issues, [{ regionId: 'R-1', issue: 'ocr-failed:OCR_FAILED' }]);

    const empty = select([
      summaryRegion('R-1', EMPTY)
    ]);
    assert.strictEqual(empty.status, 'ocr-empty');
    assert.strictEqual(empty.text, '');
    assert.deepStrictEqual(empty.issues, [{ regionId: 'R-1', issue: 'ocr-empty' }]);
  }
  console.log('✔ Test 6 Passed: OCR failure distinguished from empty OCR.');

  // Test 7: a surviving summary region joins an ambiguous view while the
  // failed sibling is recorded in issues.
  {
    const view = select([
      summaryRegion('R-1', FAILED('crop rejected')),
      summaryRegion('R-2', TEXT('Send 1.0 ETH'))
    ]);
    assert.strictEqual(view.status, 'ambiguous');
    assert.strictEqual(view.text, 'Send 1.0 ETH');
    assert.deepStrictEqual(view.regionIds, ['R-2']);
    assert.deepStrictEqual(view.issues, [{ regionId: 'R-1', issue: 'ocr-failed:OCR_FAILED' }]);
  }
  console.log('✔ Test 7 Passed: Usable text kept, failure recorded.');

  // Test 8: missing evidence stays missing — non-array input is
  // 'unavailable'; empty or summary-less arrays are 'no-summary-regions'.
  {
    assert.strictEqual(select(undefined).status, 'unavailable');
    assert.strictEqual(select(null).status, 'unavailable');
    const emptyArr = select([]);
    assert.strictEqual(emptyArr.status, 'no-summary-regions');
    assert.strictEqual(emptyArr.text, '');
    const genericBarren = select([
      summaryRegion('R-1', EMPTY, ['button'])
    ]);
    assert.strictEqual(genericBarren.status, 'no-summary-regions');
    assert.strictEqual(genericBarren.text, '');
  }
  console.log('✔ Test 8 Passed: Missing summary evidence stays missing.');

  // Test 9: mixed failed/blank summary candidates are 'ocr-unusable'.
  {
    const view = select([
      summaryRegion('R-1', FAILED('bad crop')),
      summaryRegion('R-2', null)
    ]);
    assert.strictEqual(view.status, 'ocr-unusable');
    assert.strictEqual(view.text, '');
    assert.strictEqual(view.issues.length, 2);
  }
  console.log('✔ Test 9 Passed: Mixed unusable evidence is ocr-unusable.');

  console.log('\nAll Transaction-Summary Isolation Tests Passed Successfully!\n');
}

module.exports = { runSummaryTests };

if (require.main === module) {
  runSummaryTests().catch((err) => {
    console.error(`\nTransaction-Summary Isolation Tests Failed: ${err.message}\n`);
    process.exit(1);
  });
}
