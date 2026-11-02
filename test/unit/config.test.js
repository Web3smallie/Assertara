const assert = require('assert');
const { parseTimeoutMs, MAX_TIMEOUT_MS } = require('../../src/config/validate');

// Timeout configuration validation. Deterministic: the pure helper is
// tested directly, so results never depend on the local .env contents.
function runConfigTests() {
  console.log('Testing Timeout Configuration Validation...\n');

  // Test 1: missing or empty values use the documented defaults.
  {
    for (const [name, raw] of [['undefined', undefined], ['null', null], ['empty', ''], ['whitespace', '   ']]) {
      assert.strictEqual(parseTimeoutMs(raw, 30000), 30000, `${name} uses the SAM default`);
      assert.strictEqual(parseTimeoutMs(raw, 60000), 60000, `${name} uses the Muse default`);
    }
    console.log('✔ Test 1 Passed: Missing/empty values fall back to defaults.');
  }

  // Test 2: valid positive integers are accepted, including the boundary.
  {
    for (const [raw, want] of [['1', 1], ['30000', 30000], ['60000', 60000], ['  45000  ', 45000], ['2147483647', 2147483647]]) {
      assert.strictEqual(parseTimeoutMs(raw, 30000), want, `${JSON.stringify(raw)} accepted as ${want}`);
    }
    assert.strictEqual(MAX_TIMEOUT_MS, 2147483647, 'Upper bound is setTimeout maximum');
    console.log('✔ Test 2 Passed: Valid positive integers accepted.');
  }

  // Test 3: negative values fall back instead of arming instant timeouts.
  {
    for (const raw of ['-1', '-30000', '-2147483648']) {
      assert.strictEqual(parseTimeoutMs(raw, 30000), 30000, `${raw} rejected`);
    }
    console.log('✔ Test 3 Passed: Negatives fall back to the default.');
  }

  // Test 4: zero falls back.
  {
    assert.strictEqual(parseTimeoutMs('0', 30000), 30000, 'Zero rejected');
    assert.strictEqual(parseTimeoutMs(' 0 ', 60000), 60000, 'Padded zero rejected');
    console.log('✔ Test 4 Passed: Zero falls back to the default.');
  }

  // Test 5: fractional decimals fall back (never truncated to ~1ms).
  {
    for (const raw of ['1.5', '0.5', '30000.9']) {
      assert.strictEqual(parseTimeoutMs(raw, 30000), 30000, `${raw} rejected`);
    }
    console.log('✔ Test 5 Passed: Fractional decimals fall back.');
  }

  // Test 6: non-numeric strings fall back.
  {
    for (const raw of ['abc', '30s', 'NaN', 'null', 'undefined']) {
      assert.strictEqual(parseTimeoutMs(raw, 30000), 30000, `${JSON.stringify(raw)} rejected`);
    }
    console.log('✔ Test 6 Passed: Non-numeric strings fall back.');
  }

  // Test 7: out-of-range values fall back instead of overflowing setTimeout.
  {
    for (const raw of ['2147483648', '99999999999999999999999', 'Infinity', '-Infinity']) {
      assert.strictEqual(parseTimeoutMs(raw, 30000), 30000, `${raw} rejected`);
    }
    console.log('✔ Test 7 Passed: Out-of-range values fall back.');
  }

  // Test 8: non-string programmatic inputs never throw and stay safe.
  // (In-process numeric overrides bypass this parser entirely, so strictness
  // here cannot break the documented override pattern used by services.)
  {
    for (const [name, raw] of [['number', 5000], ['true', true], ['false', false], ['object', {}], ['array', []], ['array-num', [50]]]) {
      assert.strictEqual(parseTimeoutMs(raw, 30000), 30000, `${name} rejected`);
    }
    console.log('✔ Test 8 Passed: Non-string inputs fall back without throwing.');
  }

  // Test 9: the loaded config module always exposes safe numerics,
  // regardless of what the local .env contains (never read here).
  {
    const config = require('../../src/config/env');
    for (const [key, fallback] of [['samTimeoutMs', 30000], ['museTimeoutMs', 60000]]) {
      assert.ok(
        Number.isInteger(config[key]) && config[key] > 0 && config[key] <= MAX_TIMEOUT_MS,
        `${key} must be a safe positive integer (got ${config[key]})`
      );
      assert.notStrictEqual(config[key], undefined, `${key} present (default ${fallback})`);
    }
    console.log('✔ Test 9 Passed: Loaded config exposes safe timeout values.');
  }

  console.log('\nAll Config Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runConfigTests();
}

module.exports = { runConfigTests };
