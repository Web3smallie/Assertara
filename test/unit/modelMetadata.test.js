const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Dynamic model-metadata derivation tests (V2 provenance visibility).
// Fixtures use fictional providers/models to prove the derivation is
// genuinely dynamic: no model, provider, or outcome name is hardcoded
// anywhere in the derivation path, the V2 contract, or the V2 tests.

const {
  PublisherError, deriveModelMetadata, deriveCompatBitmap, sameModels
} = require('../../src/services/attestationPublisher');

const ZERO = `0x${'00'.repeat(32)}`;
const hex = (ch) => ch.repeat(64);

function runModelMetadataTests() {
  console.log('Testing dynamic model metadata derivation (no mocks of derivation)...\n');

  // Test 1: genuine-shaped manifest (success + honest skip).
  {
    const manifest = {
      modelCalls: {
        museSpark: {
          provider: 'meta-model-api', endpoint: 'chat/completions',
          configuredModel: 'muse-spark-1.3', observedModel: 'muse-spark-1.3',
          status: 'success', contribution: 'VERDICT_ACCEPTED', modelVerdict: 'MATCH',
          inputDigest: hex('c'), outputDigest: hex('d')
        },
        sam: {
          configuredModel: null, observedModel: null,
          aggregateStatus: 'skipped', contribution: 'NOT_INVOKED',
          inputDigest: null, outputDigest: null
        }
      }
    };
    const models = deriveModelMetadata(manifest);
    assert.strictEqual(models.length, 2, 'two entries');
    assert.deepStrictEqual(models[0], {
      name: 'museSpark', provider: 'meta-model-api', modelId: 'muse-spark-1.3',
      endpoint: 'chat/completions', status: 'success', contribution: 'VERDICT_ACCEPTED',
      verdict: 'MATCH', inputDigest: `0x${hex('c')}`, outputDigest: `0x${hex('d')}`
    });
    assert.deepStrictEqual(models[1], {
      name: 'sam', provider: '', modelId: '', endpoint: '',
      status: 'skipped', contribution: 'NOT_INVOKED', verdict: '',
      inputDigest: ZERO, outputDigest: ZERO
    });
    assert.strictEqual(deriveCompatBitmap(manifest), 1, 'compat bitmap muse-only');
    console.log('✔ Test 1 Passed: genuine-shaped success + honest skip.');
  }

  // Test 2: fictional multi-provider manifest (proves dynamic behavior).
  {
    const manifest = {
      modelCalls: {
        'oracle-9': {
          provider: 'provider-acme', endpoint: 'responses',
          configuredModel: 'oracle-9', observedModel: 'oracle-9-2026',
          status: 'success', contribution: 'OUTPUT_INCLUDED', modelVerdict: 'MATCH',
          inputDigest: hex('1'), outputDigest: hex('2')
        },
        'seer-2': {
          provider: 'provider-beta', endpoint: null,
          configuredModel: 'seer-2', observedModel: null,
          status: 'timeout', contribution: 'TIMEOUT',
          inputDigest: hex('3'), outputDigest: null
        },
        'lens-0': {
          provider: null, configuredModel: null, observedModel: null,
          aggregateStatus: 'failed', contribution: 'FAILED',
          inputDigest: null, outputDigest: null
        }
      }
    };
    const models = deriveModelMetadata(manifest);
    assert.strictEqual(models.length, 3, 'three fictional entries pass through');
    assert.strictEqual(models[0].name, 'oracle-9', 'fictional name preserved');
    assert.strictEqual(models[0].provider, 'provider-acme', 'fictional provider preserved');
    assert.strictEqual(models[0].modelId, 'oracle-9-2026', 'observed preferred over configured');
    assert.strictEqual(models[1].status, 'timeout', 'timeout status honest');
    assert.strictEqual(models[1].contribution, 'TIMEOUT', 'timeout contribution honest');
    assert.strictEqual(models[1].outputDigest, ZERO, 'missing output is zero, not fabricated');
    assert.strictEqual(models[2].status, 'failed', 'aggregateStatus fallback works');
    assert.strictEqual(models[2].provider, '', 'missing provider is empty');
    assert.strictEqual(deriveCompatBitmap(manifest), 0, 'no legacy slots: compat bitmap 0, models[] carries truth');
    console.log('✔ Test 2 Passed: fictional multi-provider passthrough.');
  }

  // Test 3: failure isolation (refuse malformed, never guess).
  {
    const bad = (modelCalls, label) => {
      try {
        deriveModelMetadata({ modelCalls });
      } catch (err) {
        assert.ok(err instanceof PublisherError, `${label}: typed error`);
        assert.strictEqual(err.code, 'PUBLISH_INVALID_PACKAGE', `${label}: code`);
        return;
      }
      assert.fail(`${label}: expected refusal`);
    };
    bad({}, 'empty modelCalls');
    bad({ x: null }, 'null slot');
    bad({ x: { contribution: 'SUCCEEDED' } }, 'missing status');
    bad({ x: { status: 'success' } }, 'missing contribution');
    bad({ x: { status: '', contribution: 'SUCCEEDED' } }, 'empty status');
    bad({ x: { status: 'success', contribution: 'SUCCEEDED', outputDigest: '0xZZZ' } }, 'malformed digest');
    try {
      deriveModelMetadata(null);
      assert.fail('null manifest: expected refusal');
    } catch (err) {
      assert.strictEqual(err.code, 'PUBLISH_INVALID_PACKAGE', 'null manifest code');
    }
    console.log('✔ Test 3 Passed: malformed metadata refused.');
  }

  // Test 4: sameModels comparison semantics.
  {
    const a = [{ name: 'n', provider: 'p', modelId: 'm', endpoint: 'e', status: 'success', contribution: 'SUCCEEDED', verdict: 'MATCH', inputDigest: `0x${hex('a')}`, outputDigest: `0x${hex('b')}` }];
    const b = JSON.parse(JSON.stringify(a));
    assert.strictEqual(sameModels(a, b), true, 'identical matches');
    b[0].outputDigest = `0x${hex('b').toUpperCase()}`;
    assert.strictEqual(sameModels(a, b), true, 'digest case-insensitive');
    b[0].outputDigest = `0x${hex('c')}`;
    assert.strictEqual(sameModels(a, b), false, 'digest change detected');
    assert.strictEqual(sameModels(a, []), false, 'length change detected');
    assert.strictEqual(sameModels(a, [{ ...a[0], status: 'failed' }]), false, 'status change detected');
    const reordered = [a[0], { ...a[0], name: 'z' }];
    assert.strictEqual(sameModels(reordered, [reordered[1], reordered[0]]), false, 'order-sensitive');
    console.log('✔ Test 4 Passed: sameModels semantics.');
  }

  // Test 5: no-hardcoding proof across the V2 path.
  {
    const deriveSrc = deriveModelMetadata.toString();
    assert.ok(!/muse/i.test(deriveSrc), 'deriveModelMetadata: no muse literal');
    assert.ok(!/sam/i.test(deriveSrc), 'deriveModelMetadata: no sam literal');
    assert.ok(!/spark/i.test(deriveSrc), 'deriveModelMetadata: no spark literal');
    const repoRoot = path.join(__dirname, '..', '..');
    const contractSrc = fs.readFileSync(path.join(repoRoot, 'contracts', 'ProvenanceAttestationV2.sol'), 'utf8');
    for (const lit of ['muse-spark', 'museSpark', 'Muse Spark', 'sam-3.1', 'SAM 3.1', "'sam'", '"sam"', 'SAM,']) {
      assert.ok(!contractSrc.includes(lit), `V2 contract must not contain ${lit}`);
    }
    const forgeSrc = fs.readFileSync(path.join(repoRoot, 'test', 'forge', 'ProvenanceAttestationV2.t.sol'), 'utf8');
    assert.ok(forgeSrc.includes('alpha-reasoner'), 'forge fixtures use fictional names');
    for (const lit of ['muse-spark', 'museSpark', 'sam-3.1', 'SAM 3.1']) {
      assert.ok(!forgeSrc.includes(lit), `V2 forge suite must not contain ${lit}`);
    }
    console.log('✔ Test 5 Passed: no model identities hardcoded in V2 path.');
  }

  console.log('\nAll model metadata derivation tests passed.');
}

if (require.main === module) {
  try {
    runModelMetadataTests();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

module.exports = { runModelMetadataTests };
