const assert = require('assert');

// Agent provenance capture: the integration records the manifest
// digest additively and never lets provenance failure change the
// outcome. Fake client only: no network, no chain, no model.

function fakeClient({ decision, buildManifestImpl }) {
  const inv = {
    requestId: 'req_p1', traceId: 'tr_p1', txDigest: 'd'.repeat(64),
    wait: async () => ({ decision, reasons: ['fake'], txDigest: 'd'.repeat(64), status: 'DECIDED' }),
    evidence: async () => ({ findings: [] }),
    execute: async () => ({ txHash: `0x${'ab'.repeat(32)}`, receipt: null }),
    waitForExecution: async () => ({ outcome: 'EXECUTED' })
  };
  return {
    submit: async () => inv,
    waitForOperatorApproval: async () => { throw new Error('not used'); },
    execute: async () => { throw new Error('not used'); },
    buildManifest: buildManifestImpl
  };
}

async function runAgentProvenanceTests() {
  console.log('Testing agent provenance capture...\n');
  const { createAssertaraIntegration } = require('../../agent/integrations/assertara.js');

  // Test 1: success path carries the digest + event.
  {
    const events = [];
    const integration = createAssertaraIntegration({
      client: fakeClient({ decision: 'ALLOW', buildManifestImpl: async () => ({ manifestDigest: 'e'.repeat(64) }) }),
      agentId: 'prov-test'
    });
    const out = await integration.executeAction(
      { from: '0x0', to: '0x1', value: '0x1', data: '0x', chainId: '0x7a69' },
      { onEvent: (event, detail, extra) => events.push({ event, extra }) }
    );
    assert.strictEqual(out.decision, 'ALLOW', 'decision preserved');
    assert.deepStrictEqual(out.provenance, { manifestDigest: 'e'.repeat(64) }, 'digest attached');
    assert.ok(events.some((e) => e.event === 'PROVENANCE_RECORDED' && e.extra.manifestDigest === 'e'.repeat(64)), 'event emitted');
    console.log('✔ Test 1 Passed: digest captured + event emitted.');
  }

  // Test 2: provenance failure never changes the outcome.
  {
    for (const [label, impl] of [
      ['rejecting', async () => { throw new Error('store down'); }],
      ['missing method', undefined],
      ['empty digest', async () => ({})]
    ]) {
      const integration = createAssertaraIntegration({
        client: fakeClient({ decision: 'BLOCK', buildManifestImpl: impl }),
        agentId: 'prov-test'
      });
      const out = await integration.executeAction(
        { from: '0x0', to: '0x1', value: '0x1', data: '0x', chainId: '0x7a69' }, {}
      );
      assert.strictEqual(out.decision, 'BLOCK', `${label}: decision preserved`);
      assert.strictEqual(out.provenance, null, `${label}: provenance null, outcome intact`);
      assert.strictEqual(out.stopped, true, `${label}: stopped flag intact`);
    }
    console.log('✔ Test 2 Passed: capture failure is additive-only.');
  }

  console.log('\nAll agent provenance tests passed.');
}

if (require.main === module) {
  runAgentProvenanceTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runAgentProvenanceTests };
