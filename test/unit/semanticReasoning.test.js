/**
 * Capability 4: Semantic and Contextual Reasoning — unit + mocked
 * integration tests, one section per workstream (B1–B10). Deterministic
 * only: live-model behavior is covered by the gated live batteries.
 */
const assert = require('assert');
const appConfig = require('../../src/config/env');
const { handleEvaluateTransaction, applyVerdictSafeguards } = require('../../src/controllers/evaluateController');
const { packEvidence } = require('../../src/services/evidencePacker');
const { composePolicyDecision } = require('../../src/services/policyDecision');
const { PROMPT_VERSION, SHARED_SEMANTIC_RULES, selectSystemPrompt } = require('../../src/services/reasoningPrompts');
const {
  ERC1967_IMPL_SLOT,
  ERC1967_BEACON_SLOT,
  parseStorageAddress,
  detectMinimalProxy,
  resolveProxy,
  fetchProxyEvidence
} = require('../../src/services/proxyResolution');

const IMPL = '0x1111111111111111111111111111111111111111';
const PROXY = '0x2222222222222222222222222222222222222222';
const BEACON = '0x3333333333333333333333333333333333333333';
const ADMIN = '0x4444444444444444444444444444444444444444';
const WORD_OF = (addr) => `0x${'0'.repeat(24)}${addr.slice(2).toLowerCase()}`;
const ZERO_WORD = `0x${'0'.repeat(64)}`;
const MINIMAL_CODE = `0x363d3d373d3d3d363d73${IMPL.slice(2)}5af43d82803e903d91602b57fd5bf3`;
const GENERIC_CODE = '0x6080604052348015600e57560080fd5b506004361060325760003560e01c8063';

function mockModelFetch(verdict) {
  return async () => ({
    ok: true,
    json: async () => ({
      model: 'mock-m',
      choices: [{ message: { content: JSON.stringify({ verdict, confidence: 0.9, summary: 'canned', discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION' }) } }]
    })
  });
}

function evalRequest(tx) {
  return {
    body: {
      pageContext: { title: 't', url: 'https://w.example' },
      transaction: tx
    }
  };
}

function evalResponseCollector() {
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const res = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(p) { resolve({ status: this.statusCode, body: p }); }
  };
  return { done, res };
}

async function run() {
  // ---- B1.1: storage-word parsing ----
  {
    assert.strictEqual(parseStorageAddress(WORD_OF(IMPL)), IMPL.toLowerCase());
    assert.strictEqual(parseStorageAddress(ZERO_WORD), null, 'zero word is absence, not an address');
    assert.strictEqual(parseStorageAddress(`0x${'1'.repeat(24)}${IMPL.slice(2)}`), null, 'nonzero padding never truncates into an address');
    assert.strictEqual(parseStorageAddress('0x1234'), null);
    assert.strictEqual(parseStorageAddress(null), null);
    assert.strictEqual(parseStorageAddress(123), null);
    console.log('✔ B1.1 Passed: Storage-word address parsing (padding/zero/malformed).');
  }

  // ---- B1.2: EIP-1167 pattern detection ----
  {
    assert.strictEqual(MINIMAL_CODE.length, 92, 'fixture is exactly 45 bytes');
    const hit = detectMinimalProxy(MINIMAL_CODE);
    assert.strictEqual(hit.isMinimalProxy, true);
    assert.strictEqual(hit.implementation, IMPL.toLowerCase());
    assert.strictEqual(detectMinimalProxy(GENERIC_CODE).isMinimalProxy, false);
    assert.strictEqual(detectMinimalProxy('0x').isMinimalProxy, false);
    assert.strictEqual(detectMinimalProxy(null).isMinimalProxy, false);
    // Near-miss: correct prefix but wrong suffix must not match.
    const near = `${MINIMAL_CODE.slice(0, -4)}0000`;
    assert.strictEqual(detectMinimalProxy(near).isMinimalProxy, false);
    console.log('✔ B1.2 Passed: EIP-1167 detection + embedded implementation extraction.');
  }

  // ---- B1.3: resolveProxy across all branches ----
  {
    const codeOf = (map) => async (addr) => {
      if (!Object.prototype.hasOwnProperty.call(map, addr.toLowerCase())) throw new Error('no code fixture');
      return map[addr.toLowerCase()];
    };
    // No code: EOA, not a proxy, no readers touched.
    let touched = false;
    const eoa = await resolveProxy({
      address: PROXY, code: '0x',
      readStorage: async () => { touched = true; throw new Error('must not read'); },
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(eoa.status, 'not-proxy');
    assert.strictEqual(eoa.isProxy, false);
    assert.strictEqual(eoa.downgrade, false);
    assert.strictEqual(touched, false);

    // EIP-1167 with live implementation.
    const mini = await resolveProxy({
      address: PROXY, code: MINIMAL_CODE,
      readStorage: async () => { throw new Error('minimal proxy needs no slot reads'); },
      readCode: codeOf({ [IMPL.toLowerCase()]: GENERIC_CODE }),
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(mini.status, 'resolved');
    assert.strictEqual(mini.kind, 'EIP-1167');
    assert.strictEqual(mini.implementation, IMPL.toLowerCase());
    assert.strictEqual(mini.implementationCode.hasCode, true);
    assert.strictEqual(mini.downgrade, false);

    // EIP-1167 dangling: points at empty account.
    const dangling = await resolveProxy({
      address: PROXY, code: MINIMAL_CODE,
      readStorage: async () => { throw new Error('unneeded'); },
      readCode: codeOf({ [IMPL.toLowerCase()]: '0x' }),
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(dangling.status, 'proxy-unresolved');
    assert.strictEqual(dangling.downgrade, true);
    assert.strictEqual(dangling.hold.source, 'proxy-resolution');

    // ERC-1967 direct, resolved.
    const e1967 = await resolveProxy({
      address: PROXY, code: GENERIC_CODE,
      readStorage: async (a, slot) => {
        assert.strictEqual(a, PROXY.toLowerCase());
        if (slot === ERC1967_IMPL_SLOT) return WORD_OF(IMPL);
        throw new Error(`unexpected slot ${slot}`);
      },
      readCode: codeOf({ [IMPL.toLowerCase()]: GENERIC_CODE }),
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(e1967.status, 'resolved');
    assert.strictEqual(e1967.kind, 'ERC-1967');
    assert.strictEqual(e1967.implementation, IMPL.toLowerCase());
    assert.strictEqual(e1967.downgrade, false);

    // ERC-1967 dangling implementation.
    const e1967dead = await resolveProxy({
      address: PROXY, code: GENERIC_CODE,
      readStorage: async () => WORD_OF(IMPL),
      readCode: codeOf({ [IMPL.toLowerCase()]: '0x' }),
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(e1967dead.status, 'proxy-unresolved');
    assert.strictEqual(e1967dead.downgrade, true);

    // Slot read failure: unknown, never moves a verdict.
    const failed = await resolveProxy({
      address: PROXY, code: GENERIC_CODE,
      readStorage: async () => { throw new Error('rpc down'); },
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(failed.status, 'unknown');
    assert.strictEqual(failed.isProxy, null);
    assert.strictEqual(failed.downgrade, false);
    assert.strictEqual(failed.hold, null);

    // Beacon proxy, implementation readable.
    const beacon = await resolveProxy({
      address: PROXY, code: GENERIC_CODE,
      readStorage: async (a, slot) => {
        if (slot === ERC1967_IMPL_SLOT) return ZERO_WORD;
        if (slot === ERC1967_BEACON_SLOT) return WORD_OF(BEACON);
        throw new Error(`unexpected slot ${slot}`);
      },
      readCode: codeOf({ [IMPL.toLowerCase()]: GENERIC_CODE }),
      callView: async (a, data) => {
        assert.strictEqual(a, BEACON.toLowerCase());
        assert.strictEqual(data, '0x5c60da1b');
        return WORD_OF(IMPL);
      },
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(beacon.status, 'resolved');
    assert.strictEqual(beacon.kind, 'ERC-1967-beacon');
    assert.strictEqual(beacon.beacon, BEACON.toLowerCase());
    assert.strictEqual(beacon.implementation, IMPL.toLowerCase());

    // Beacon proxy, implementation() reverts: unresolved.
    const beaconDark = await resolveProxy({
      address: PROXY, code: GENERIC_CODE,
      readStorage: async (a, slot) => (slot === ERC1967_BEACON_SLOT ? WORD_OF(BEACON) : ZERO_WORD),
      callView: async () => { throw new Error('revert'); },
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(beaconDark.status, 'proxy-unresolved');
    assert.strictEqual(beaconDark.downgrade, true);
    assert.ok(beaconDark.explanation.includes(BEACON.slice(0, 10).toLowerCase()));

    // Empty pointers + admin set: admin alone never classifies.
    const adminOnly = await resolveProxy({
      address: PROXY, code: GENERIC_CODE,
      readStorage: async (a, slot) => ZERO_WORD,
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(adminOnly.status, 'not-proxy');
    assert.strictEqual(adminOnly.isProxy, false);
    assert.strictEqual(adminOnly.downgrade, false);

    const adminSet = await resolveProxy({
      address: PROXY, code: GENERIC_CODE,
      readStorage: async (a, slot) => (slot.endsWith('f5e7f8b3a8') ? WORD_OF(ADMIN) : ZERO_WORD),
      chainId: '1', blockNumber: '0x5'
    });
    assert.strictEqual(adminSet.status, 'not-proxy');
    assert.strictEqual(adminSet.admin, ADMIN.toLowerCase());
    console.log('✔ B1.3 Passed: resolveProxy all branches (resolved/unresolved/unknown/not-proxy/beacon/admin).');
  }

  // ---- B1.4: fetchProxyEvidence transport behavior ----
  {
    const rpc = (routes) => async (url, opts) => {
      const calls = JSON.parse(opts.body);
      const list = (Array.isArray(calls) ? calls : [calls]).map((c) => {
        const key = `${c.method}:${JSON.stringify(c.params)}`;
        if (!Object.prototype.hasOwnProperty.call(routes, key)) {
          return { jsonrpc: '2.0', id: c.id, error: { message: `no fixture for ${c.method}` } };
        }
        return { jsonrpc: '2.0', id: c.id, result: routes[key] };
      });
      return { ok: true, json: async () => list };
    };
    const t = PROXY.toLowerCase();
    const routes = {
      'eth_chainId:[]': '0x1',
      'eth_blockNumber:[]': '0x9',
      [`eth_getCode:${JSON.stringify([t, 'latest'])}`]: GENERIC_CODE,
      [`eth_getStorageAt:${JSON.stringify([t, ERC1967_IMPL_SLOT, 'latest'])}`]: WORD_OF(IMPL),
      [`eth_getCode:${JSON.stringify([IMPL.toLowerCase(), 'latest'])}`]: GENERIC_CODE
    };
    const ok = await fetchProxyEvidence({
      rpcUrl: 'http://rpc.invalid', chainId: '0x1', address: PROXY, fetchImpl: rpc(routes)
    });
    assert.strictEqual(ok.status, 'resolved');
    assert.strictEqual(ok.implementation, IMPL.toLowerCase());
    assert.strictEqual(ok.blockNumber, '0x9');
    assert.strictEqual(ok.chainId, '1');
    assert.ok(ok.targetCodeHash && ok.targetCodeHash.startsWith('0x'));

    // Wrong chain: discarded, no downgrade.
    const wrong = await fetchProxyEvidence({
      rpcUrl: 'http://rpc.invalid', chainId: '0x89', address: PROXY, fetchImpl: rpc(routes)
    });
    assert.strictEqual(wrong.status, 'wrong-chain');
    assert.strictEqual(wrong.downgrade, false);

    // No RPC: unavailable, fetch never called.
    let called = false;
    const unavail = await fetchProxyEvidence({
      rpcUrl: null, chainId: '0x1', address: PROXY, fetchImpl: async () => { called = true; throw new Error('x'); }
    });
    assert.strictEqual(unavail.status, 'unavailable');
    assert.strictEqual(called, false);

    // Transport failure: unknown, never throws.
    const dead = await fetchProxyEvidence({
      rpcUrl: 'http://rpc.invalid', chainId: '0x1', address: PROXY,
      fetchImpl: async () => { throw new Error('connect refused'); }
    });
    assert.strictEqual(dead.status, 'unknown');
    assert.strictEqual(dead.downgrade, false);

    // Programmer misuse still throws.
    await assert.rejects(fetchProxyEvidence({ rpcUrl: 'http://x', address: 'nope' }), TypeError);
    console.log('✔ B1.4 Passed: fetchProxyEvidence chain check, unavailable, failure tolerance.');
  }

  // ---- B1.5: safeguard stage 10 + policy hold ----
  {
    const mkResult = (proxyResolution) => ({
      verdict: 'MATCH', confidence: 0.9, summary: 's', origin: 'model', proxyResolution
    });
    const hit = applyVerdictSafeguards({ ruleFindings: [] }, mkResult({
      status: 'proxy-unresolved', downgrade: true, explanation: 'beacon dark'
    }));
    assert.strictEqual(hit.reasoningResult.verdict, 'UNCERTAIN');
    assert.ok(hit.safeguards.some((s) => s.trigger === 'UNRESOLVED_PROXY_IMPLEMENTATION'));

    // Safe-direction verdicts pass through untouched.
    const safe = applyVerdictSafeguards({ ruleFindings: [] }, {
      verdict: 'MISMATCH', confidence: 0.9, summary: 's', origin: 'model',
      proxyResolution: { status: 'proxy-unresolved', downgrade: true }
    });
    assert.strictEqual(safe.reasoningResult.verdict, 'MISMATCH');
    assert.ok(!safe.safeguards.some((s) => s.trigger === 'UNRESOLVED_PROXY_IMPLEMENTATION'));

    // Resolved/unknown proxies never trigger.
    for (const pr of [
      { status: 'resolved', downgrade: false },
      { status: 'not-proxy', downgrade: false },
      { status: 'unknown', downgrade: false },
      null
    ]) {
      const r = applyVerdictSafeguards({ ruleFindings: [] }, mkResult(pr));
      assert.strictEqual(r.reasoningResult.verdict, 'MATCH', `no downgrade for ${pr && pr.status}`);
    }

    // The hold converts would-be ALLOW into REVIEW.
    const held = composePolicyDecision({
      verdict: 'MATCH', modelVerdict: 'MATCH', modelConfidence: 0.9,
      reasoningOrigin: 'model', ruleFindings: [],
      deterministicHolds: [{ source: 'proxy-resolution', reason: 'beacon dark' }]
    });
    assert.strictEqual(held.decision, 'REVIEW');
    console.log('✔ B1.5 Passed: Stage-10 safeguard (MATCH-only) + policy hold to REVIEW.');
  }

  // ---- B1.6: packing + prompt + registry ----
  {
    assert.strictEqual(PROMPT_VERSION, 'investigate-2.7');
    assert.ok(SHARED_SEMANTIC_RULES.includes('S1. Proxy awareness'));
    const browser = selectSystemPrompt('browser');
    const agent = selectSystemPrompt('agent');
    assert.ok(browser.text.includes('S1. Proxy awareness'));
    assert.ok(agent.text.includes('S1. Proxy awareness'));
    assert.ok(browser.text.includes('proxy, identity, deadlines, history, explicitIntent.'));
    assert.ok(browser.text.includes('A printed [EI-xxx] statement ID is also citable. NEVER invent tokens'));

    const packed = (proxy) => packEvidence({
      visualText: '', pageContext: { title: 't', url: 'https://w.example' },
      decodedTx: { contract: PROXY.toLowerCase(), functionName: 'transfer', standard: 'ERC20', parameters: {}, ruleFindings: [] },
      visualMeta: {},
      extra: { proxy }
    }).sectionTexts.find((s) => s.name === 'tx').text;
    const res = packed({ status: 'resolved', isProxy: true, kind: 'ERC-1967', target: PROXY.toLowerCase(), implementation: IMPL.toLowerCase(), chainId: '1', blockNumber: '0x9', implementationCode: { checked: true, hasCode: true } });
    assert.ok(res.includes('IS a proxy (ERC-1967)') && res.includes(IMPL.toLowerCase().slice(0, 12)));
    const un = packed({ status: 'proxy-unresolved', isProxy: true, kind: 'ERC-1967-beacon', target: PROXY.toLowerCase(), beacon: BEACON.toLowerCase(), explanation: 'beacon dark' });
    assert.ok(un.includes('BUT the implementation could not be established') && un.includes('UNKNOWN'));
    const np = packed({ status: 'not-proxy', isProxy: false, target: PROXY.toLowerCase(), admin: null });
    assert.ok(np.includes('is not a proxy'));
    console.log('✔ B1.6 Passed: Proxy pack block, prompt 2.2 S1 rule, registry token.');
  }

  // ---- B1.7: controller end-to-end (mocked model) ----
  {
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    // Non-empty calldata so the proxy path engages; internal proxy record
    // drives the outcome deterministically (mirrors chainState injection).
    const tx = {
      from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      to: PROXY,
      data: '0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000000000000000064',
      value: '0x0',
      chainId: '0x1'
    };
    try {
      global.fetch = mockModelFetch('MATCH');
      const { done, res } = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest(tx), res, {
        proxyResolution: {
          target: PROXY.toLowerCase(), status: 'proxy-unresolved', isProxy: true,
          kind: 'ERC-1967-beacon', beacon: BEACON.toLowerCase(), implementation: null,
          downgrade: true,
          hold: { source: 'proxy-resolution', reason: 'beacon dark' },
          explanation: 'beacon dark'
        }
      });
      const out = await done;
      assert.strictEqual(out.status, 200);
      assert.strictEqual(out.body.verdict, 'UNCERTAIN', 'unresolved proxy downgrades MATCH');
      assert.ok(out.body.verdictSafeguards.some((s) => s.trigger === 'UNRESOLVED_PROXY_IMPLEMENTATION'));
      assert.strictEqual(out.body.proxyResolution.status, 'proxy-unresolved');
      assert.strictEqual(out.body.policyDecision.decision, 'UNCERTAIN');

      // Resolved proxy: MATCH stands, implementation recorded.
      global.fetch = mockModelFetch('MATCH');
      const second = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest(tx), second.res, {
        proxyResolution: {
          target: PROXY.toLowerCase(), status: 'resolved', isProxy: true,
          kind: 'ERC-1967', implementation: IMPL.toLowerCase(),
          implementationCode: { checked: true, hasCode: true },
          downgrade: false, hold: null, explanation: 'resolved'
        }
      });
      const out2 = await second.done;
      assert.strictEqual(out2.status, 200);
      // Note: approve() to an unknown token fires deterministic findings
      // (ambiguous scope / unverified spender), so policy holds REVIEW;
      // the point is the proxy safeguard does NOT fire.
      assert.ok(!out2.body.verdictSafeguards.some((s) => s.trigger === 'UNRESOLVED_PROXY_IMPLEMENTATION'));
      const packing = JSON.stringify(out2.body.evidencePacking || {});
      assert.ok(out2.body.proxyResolution.implementation === IMPL.toLowerCase(), 'implementation in bundle');
      void packing;
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B1.7 Passed: Controller downgrades unresolved proxy; resolved proxy recorded.');
  }

  // ---- B2.1: privileged functions decode with exact parameters ----
  {
    const { encodeFunctionData } = require('viem');
    const { OWNABLE_ABI, ACCESS_CONTROL_ABI, PAUSABLE_ABI, PROXY_ADMIN_ABI } = require('../../src/utils/abiSignatures');
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const NEW_OWNER = '0x5555555555555555555555555555555555555555';
    const ROLE = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const cases = [
      { abi: OWNABLE_ABI, fn: 'transferOwnership', args: [NEW_OWNER], standard: 'Ownable', params: { newOwner: NEW_OWNER } },
      { abi: OWNABLE_ABI, fn: 'renounceOwnership', args: [], standard: 'Ownable', params: { renounced: true } },
      { abi: ACCESS_CONTROL_ABI, fn: 'grantRole', args: [ROLE, NEW_OWNER], standard: 'AccessControl', params: { role: ROLE, account: NEW_OWNER } },
      { abi: ACCESS_CONTROL_ABI, fn: 'revokeRole', args: [ROLE, NEW_OWNER], standard: 'AccessControl', params: { role: ROLE, account: NEW_OWNER } },
      { abi: ACCESS_CONTROL_ABI, fn: 'renounceRole', args: [ROLE, NEW_OWNER], standard: 'AccessControl', params: { role: ROLE, account: NEW_OWNER } },
      { abi: PAUSABLE_ABI, fn: 'pause', args: [], standard: 'Pausable', params: { paused: true } },
      { abi: PAUSABLE_ABI, fn: 'unpause', args: [], standard: 'Pausable', params: { paused: false } },
      { abi: PROXY_ADMIN_ABI, fn: 'upgradeTo', args: [IMPL], standard: 'ProxyAdmin', params: { newImplementation: IMPL } },
      { abi: PROXY_ADMIN_ABI, fn: 'upgradeToAndCall', args: [IMPL, '0x1234'], standard: 'ProxyAdmin', params: { newImplementation: IMPL, data: '0x1234' } },
      { abi: PROXY_ADMIN_ABI, fn: 'changeAdmin', args: [ADMIN], standard: 'ProxyAdmin', params: { newAdmin: ADMIN } }
    ];
    for (const c of cases) {
      const data = encodeFunctionData({ abi: c.abi, functionName: c.fn, args: c.args });
      const d = decodeTransactionCalldata({ to: PROXY, data, value: '0x0', from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' });
      assert.strictEqual(d.functionName, c.fn, c.fn);
      assert.strictEqual(d.standard, c.standard, c.fn);
      for (const [k, v] of Object.entries(c.params)) {
        const got = typeof d.parameters[k] === 'string' ? d.parameters[k].toLowerCase() : d.parameters[k];
        const want = typeof v === 'string' ? v.toLowerCase() : v;
        assert.deepStrictEqual(got, want, `${c.fn}.${k}`);
      }
    }
    // Same name, different signature: pause(address) must NOT decode as Pausable.
    const fakePause = `0x${'11'.repeat(4)}${'0'.repeat(64)}`;
    const unknown = decodeTransactionCalldata({ to: PROXY, data: fakePause, value: '0x0' });
    assert.strictEqual(unknown.functionName, 'unknownFunction');
    assert.ok(!unknown.ruleFindings.some((f) => f.ruleId === 'CONTRACT_PAUSED'));
    console.log('✔ B2.1 Passed: All 10 privileged functions decode exactly; name-only lookalikes rejected.');
  }

  // ---- B2.2: findings, severity, caller-vs-recipient ----
  {
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const { encodeFunctionData } = require('viem');
    const { PROXY_ADMIN_ABI, OWNABLE_ABI, ACCESS_CONTROL_ABI } = require('../../src/utils/abiSignatures');
    const CALLER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
    const upgrade = decodeTransactionCalldata({
      to: PROXY,
      data: encodeFunctionData({ abi: PROXY_ADMIN_ABI, functionName: 'upgradeToAndCall', args: [IMPL, '0x'] }),
      value: '0x0', from: CALLER
    });
    const up = upgrade.ruleFindings.find((f) => f.ruleId === 'PROXY_UPGRADE');
    assert.ok(up, 'upgrade finding fires');
    assert.strictEqual(up.severity, 'CRITICAL');
    assert.strictEqual(up.metadata.newImplementation, IMPL.toLowerCase());
    assert.strictEqual(up.metadata.caller, CALLER.toLowerCase());
    assert.strictEqual(up.metadata.withCall, true);
    assert.ok(up.description.includes('authorization') && up.description.includes('not verified'));

    const owner = decodeTransactionCalldata({
      to: PROXY,
      data: encodeFunctionData({ abi: OWNABLE_ABI, functionName: 'transferOwnership', args: ['0x5555555555555555555555555555555555555555'] }),
      value: '0x0', from: CALLER
    });
    const ot = owner.ruleFindings.find((f) => f.ruleId === 'OWNERSHIP_TRANSFER');
    assert.ok(ot && ot.severity === 'HIGH');
    assert.strictEqual(ot.metadata.caller, CALLER.toLowerCase());
    assert.strictEqual(ot.metadata.newOwner, '0x5555555555555555555555555555555555555555');

    const role = decodeTransactionCalldata({
      to: PROXY,
      data: encodeFunctionData({ abi: ACCESS_CONTROL_ABI, functionName: 'grantRole', args: [`0x${'0'.repeat(64)}`, CALLER] }),
      value: '0x0'
    });
    const rg = role.ruleFindings.find((f) => f.ruleId === 'ROLE_GRANTED');
    assert.ok(rg && rg.severity === 'HIGH');
    assert.strictEqual(rg.metadata.caller, 'unknown caller', 'missing from is explicit, not invented');

    // Ordinary operations are untouched: no privileged findings.
    const plain = decodeTransactionCalldata({
      to: PROXY,
      data: '0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000000000000000064',
      value: '0x0', from: CALLER
    });
    assert.ok(!plain.ruleFindings.some((f) => /PROXY_UPGRADE|OWNERSHIP|ROLE_|PAUSED/.test(f.ruleId)));
    console.log('✔ B2.2 Passed: Privileged findings fire with severity + caller/recipient split; plain txs clean.');
  }

  // ---- B2.3: policy mapping (REVIEW, never silent, never BLOCK) ----
  {
    const { findingActionFor } = require('../../src/services/policyDecision');
    for (const id of ['PROXY_UPGRADE', 'PROXY_ADMIN_CHANGE', 'OWNERSHIP_TRANSFER', 'OWNERSHIP_RENOUNCED', 'ROLE_GRANTED', 'ROLE_REVOKED', 'ROLE_RENOUNCED', 'CONTRACT_PAUSED', 'CONTRACT_UNPAUSED']) {
      assert.strictEqual(findingActionFor(id), 'REVIEW', id);
    }
    const held = composePolicyDecision({
      verdict: 'MATCH', modelVerdict: 'MATCH', modelConfidence: 0.95,
      reasoningOrigin: 'model',
      ruleFindings: [{ ruleId: 'PROXY_UPGRADE', severity: 'CRITICAL' }]
    });
    assert.strictEqual(held.decision, 'REVIEW');
    assert.ok(held.reasons.some((r) => r.includes('PROXY_UPGRADE')));
    console.log('✔ B2.3 Passed: All 9 privileged findings hold REVIEW through policy.');
  }

  // ---- B2.4: prompt S2 + controller integration ----
  {
    assert.ok(SHARED_SEMANTIC_RULES.includes('S2. Privileged operations'));
    assert.ok(selectSystemPrompt('browser').text.includes('S2. Privileged operations'));
    assert.ok(selectSystemPrompt('agent').text.includes('S2. Privileged operations'));

    const { encodeFunctionData } = require('viem');
    const { PROXY_ADMIN_ABI } = require('../../src/utils/abiSignatures');
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    global.fetch = mockModelFetch('MATCH');
    try {
      const { done, res } = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
        to: PROXY,
        data: encodeFunctionData({ abi: PROXY_ADMIN_ABI, functionName: 'upgradeTo', args: [IMPL] }),
        value: '0x0',
        chainId: '0x1'
      }), res, { proxyResolution: { target: PROXY.toLowerCase(), status: 'not-proxy', isProxy: false, downgrade: false, hold: null, explanation: 'direct' } });
      const out = await done;
      assert.strictEqual(out.status, 200);
      const finding = (out.body.ruleFindings || []).find((f) => f.ruleId === 'PROXY_UPGRADE');
      assert.ok(finding, 'CRITICAL upgrade finding reaches the bundle');
      assert.strictEqual(finding.severity, 'CRITICAL');
      assert.strictEqual(out.body.policyDecision.decision, 'REVIEW', 'MATCH + CRITICAL privileged finding holds');
      assert.ok((out.body.policyDecision.reviewFindings || []).includes('PROXY_UPGRADE'));
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B2.4 Passed: S2 prompt rule + upgrade tx held REVIEW end to end.');
  }

  // ---- B3.1: approval-amount classification boundary ----
  {
    const { classifyApprovalAmount } = require('../../src/utils/valueProtection');
    const T = 2n ** 255n;
    const MAX = (2n ** 256n) - 1n;
    assert.strictEqual(classifyApprovalAmount(0n).kind, 'zero');
    assert.strictEqual(classifyApprovalAmount('1000000').kind, 'ordinary');
    assert.strictEqual(classifyApprovalAmount(T - 1n).kind, 'ordinary', 'one below threshold stays ordinary');
    const at = classifyApprovalAmount(T);
    assert.strictEqual(at.kind, 'unlimited');
    assert.strictEqual(at.threshold, '2^255');
    assert.strictEqual(at.isMaxUint, false);
    const max = classifyApprovalAmount(MAX.toString());
    assert.strictEqual(max.kind, 'unlimited');
    assert.strictEqual(max.isMaxUint, true);
    assert.strictEqual(classifyApprovalAmount('not-a-number').kind, 'unparseable');
    assert.strictEqual(classifyApprovalAmount(-5).kind, 'unparseable');
    assert.strictEqual(classifyApprovalAmount(null).kind, 'unparseable');
    console.log('✔ B3.1 Passed: Approval threshold 2^255 boundary (zero/ordinary/unlimited/unparseable).');
  }

  // ---- B3.2: output-gap math (exact, indicative, insufficient-data) ----
  {
    const { analyzeOutputGap } = require('../../src/utils/valueProtection');
    const QUOTE = (3450n * 10n ** 6n).toString(); // 3,450.0 USDC in base units
    const un = analyzeOutputGap({ amountOutMinimum: '0', quotedOutputWei: QUOTE });
    assert.strictEqual(un.status, 'analyzed');
    assert.strictEqual(un.level, 'unprotected');
    assert.strictEqual(un.gapBps, '10000');
    const over = analyzeOutputGap({ amountOutMinimum: (4000n * 10n ** 6n).toString(), quotedOutputWei: QUOTE });
    assert.strictEqual(over.level, 'minimum-exceeds-quote');
    const part = analyzeOutputGap({ amountOutMinimum: (3400n * 10n ** 6n).toString(), quotedOutputWei: QUOTE });
    assert.strictEqual(part.level, 'partial');
    assert.strictEqual(part.gapBps, '144', 'floored bps: 50/3450*10000 = 144.9…');
    const exact = analyzeOutputGap({ amountOutMinimum: QUOTE, quotedOutputWei: QUOTE });
    assert.strictEqual(exact.level, 'none');
    assert.strictEqual(exact.gapBps, '0');
    assert.strictEqual(analyzeOutputGap({ amountOutMinimum: undefined, quotedOutputWei: QUOTE }).status, 'insufficient-data');
    assert.strictEqual(analyzeOutputGap({ amountOutMinimum: '1', quotedOutputWei: null }).status, 'insufficient-data');
    assert.strictEqual(analyzeOutputGap({ amountOutMinimum: '1', quotedOutputWei: '0' }).status, 'insufficient-data');
    assert.strictEqual(analyzeOutputGap({ amountOutMinimum: '1.5', quotedOutputWei: QUOTE }).status, 'insufficient-data', 'decimals never enter base-unit math');
    console.log('✔ B3.2 Passed: Gap levels, floored bps, decimal rejection, insufficient-data.');
  }

  // ---- B3.3: decoder value-protection rules ----
  {
    const { encodeFunctionData, toFunctionSelector } = require('viem');
    const { UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const SENDER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
    const swap = (minOut) => decodeTransactionCalldata({
      to: ROUTER,
      data: encodeFunctionData({
        abi: UNISWAP_V3_ROUTER_ABI, functionName: 'exactInputSingle',
        args: [{ tokenIn: WETH, tokenOut: USDC, fee: 500, recipient: SENDER, amountIn: 10n ** 18n, amountOutMinimum: minOut, sqrtPriceLimitX96: 0n }]
      }),
      value: `0x${(10n ** 18n).toString(16)}`, from: SENDER
    });
    const zero = swap(0n);
    const zf = zero.ruleFindings.find((f) => f.ruleId === 'ZERO_MINIMUM_OUTPUT');
    assert.ok(zf, 'zero minimum fires');
    assert.strictEqual(zf.severity, 'HIGH');
    const safe = swap(3400n * 10n ** 6n);
    assert.ok(!safe.ruleFindings.some((f) => f.ruleId === 'ZERO_MINIMUM_OUTPUT' || f.ruleId === 'MISSING_OUTPUT_PROTECTION'));
    // Truncated calldata: selector + offset + one field word → minimum absent.
    const sel = toFunctionSelector('exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))');
    const trunc = decodeTransactionCalldata({
      to: ROUTER,
      data: `${sel}${'0'.repeat(63)}20${'0'.repeat(24)}${WETH.slice(2).toLowerCase()}`,
      value: '0x0', from: SENDER
    });
    assert.strictEqual(trunc.functionName, 'exactInputSingle');
    assert.ok(trunc.ruleFindings.some((f) => f.ruleId === 'MISSING_OUTPUT_PROTECTION'), 'absent minimum is a finding, not a pass');
    console.log('✔ B3.3 Passed: ZERO/MISSING minimum findings fire; protected swaps clean.');
  }

  // ---- B3.4: outputProtection comparison field ----
  {
    const { compareIntentToTx } = require('../../src/utils/intentComparison');
    const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const SENDER = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
    const region = (regionId, text) => ({ regionId, genuine: true, synthetic: false, ocr: { text, empty: text.length === 0, error: null } });
    const claim = (type, value, regionIds) => ({ type, value, regionIds, associationIds: [], status: 'supported' });
    const link = (linkId, kind, method, members) => ({ linkId, kind, method, members: members.map(([regionId, role]) => ({ regionId, role })) });
    const decoded = (minOut) => ({
      contract: ROUTER, functionName: 'exactInputSingle', standard: 'UniswapV3Router',
      symbol: null, decimals: null, valueWei: '1000000000000000000',
      parameters: { tokenIn: WETH, tokenOut: USDC, fee: 500, recipient: SENDER, amountIn: '1000000000000000000', amountOutMinimum: minOut },
      tokenMeta: { [WETH]: { symbol: 'WETH', decimals: 18 }, [USDC]: { symbol: 'USDC', decimals: 6 } }
    });
    const quoted = {
      regions: [region('R-001', 'You receive 3,450 USDC')],
      claims: [claim('amount', '3,450 USDC', ['R-001'])],
      associations: { links: [link('L-001', 'action-amount', 'same-region', [['R-001', 'action'], ['R-001', 'amount']])], ambiguities: [] }
    };
    const fieldOf = (res, field) => res.fields.find((f) => f.field === field);

    const unprotected = compareIntentToTx(quoted, decoded('0'));
    assert.strictEqual(fieldOf(unprotected, 'outputProtection').status, 'MISMATCH');
    assert.strictEqual(fieldOf(unprotected, 'outputProtection').gapBps, '10000');
    assert.strictEqual(fieldOf(unprotected, 'swapOutput').status, 'INCONCLUSIVE', 'swapOutput design preserved');

    const over = compareIntentToTx(quoted, decoded((4000n * 10n ** 6n).toString()));
    assert.strictEqual(fieldOf(over, 'outputProtection').status, 'MISMATCH');
    assert.strictEqual(fieldOf(over, 'outputProtection').level, 'minimum-exceeds-quote');

    const partial = compareIntentToTx(quoted, decoded((3400n * 10n ** 6n).toString()));
    assert.strictEqual(fieldOf(partial, 'outputProtection').status, 'INCONCLUSIVE', 'partial gaps stay indicative');
    assert.strictEqual(fieldOf(partial, 'outputProtection').gapBps, '144');

    const noQuote = compareIntentToTx({
      regions: [region('R-001', 'Swap now')],
      claims: [claim('action', 'Swap', ['R-001'])],
      associations: { links: [], ambiguities: [] }
    }, decoded('0'));
    assert.strictEqual(fieldOf(noQuote, 'outputProtection').status, 'INCONCLUSIVE');

    const plain = compareIntentToTx(quoted, {
      contract: USDC, functionName: 'transfer', standard: 'ERC20', symbol: 'USDC', decimals: 6,
      parameters: { recipient: SENDER, amount: '100' }, valueWei: '0'
    });
    assert.strictEqual(fieldOf(plain, 'outputProtection').status, 'INCONCLUSIVE');
    console.log('✔ B3.4 Passed: outputProtection MISMATCH/INCONCLUSIVE with recorded ratios.');
  }

  // ---- B3.5: stage-11 safeguard + policy + S3 + controller (S3-leniency fix) ----
  {
    const { findingActionFor } = require('../../src/services/policyDecision');
    assert.strictEqual(findingActionFor('ZERO_MINIMUM_OUTPUT'), 'REVIEW');
    assert.strictEqual(findingActionFor('MISSING_OUTPUT_PROTECTION'), 'REVIEW');
    assert.ok(SHARED_SEMANTIC_RULES.includes('S3. Value protection'));

    const zeroRes = { verdict: 'MATCH', confidence: 0.9, summary: 's', origin: 'model' };
    const hit = applyVerdictSafeguards({ ruleFindings: [{ ruleId: 'ZERO_MINIMUM_OUTPUT' }] }, zeroRes);
    assert.strictEqual(hit.reasoningResult.verdict, 'UNCERTAIN');
    assert.ok(hit.safeguards.some((s) => s.trigger === 'ZERO_MINIMUM_OUTPUT'));
    const safe = applyVerdictSafeguards({ ruleFindings: [{ ruleId: 'ZERO_MINIMUM_OUTPUT' }] },
      { verdict: 'MISMATCH', confidence: 0.9, summary: 's', origin: 'model' });
    assert.strictEqual(safe.reasoningResult.verdict, 'MISMATCH');
    const clean = applyVerdictSafeguards({ ruleFindings: [] }, { verdict: 'MATCH', confidence: 0.9, summary: 's', origin: 'model' });
    assert.strictEqual(clean.reasoningResult.verdict, 'MATCH');

    // End to end: S3 replay — swap with amountOutMinimum 0 and a mocked
    // model MATCH must come back UNCERTAIN, never an unqualified MATCH.
    const { encodeFunctionData } = require('viem');
    const { UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const SENDER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    global.fetch = mockModelFetch('MATCH');
    try {
      const { done, res } = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: SENDER, to: ROUTER,
        data: encodeFunctionData({
          abi: UNISWAP_V3_ROUTER_ABI, functionName: 'exactInputSingle',
          args: [{ tokenIn: WETH, tokenOut: USDC, fee: 500, recipient: SENDER, amountIn: 10n ** 18n, amountOutMinimum: 0n, sqrtPriceLimitX96: 0n }]
        }),
        value: `0x${(10n ** 18n).toString(16)}`, chainId: '0x1'
      }), res, { proxyResolution: { target: ROUTER.toLowerCase(), status: 'not-proxy', isProxy: false, downgrade: false, hold: null, explanation: 'direct' } });
      const out = await done;
      assert.strictEqual(out.status, 200);
      assert.ok((out.body.ruleFindings || []).some((f) => f.ruleId === 'ZERO_MINIMUM_OUTPUT'));
      assert.ok(out.body.verdictSafeguards.some((s) => s.trigger === 'ZERO_MINIMUM_OUTPUT'));
      assert.strictEqual(out.body.verdict, 'UNCERTAIN', 'no unqualified MATCH over a zero minimum');
      assert.strictEqual(out.body.policyDecision.decision, 'UNCERTAIN');
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B3.5 Passed: Stage 11 + REVIEW mapping + S3 + S3-leniency fix end to end.');
  }

  // ---- B4.1: subcall tree structure (IDs, paths, depth, effects) ----
  {
    const { encodeFunctionData } = require('viem');
    const { ERC20_ABI, UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const { buildSubcallTree } = require('../../src/services/nestedCalls');
    const SPENDER = '0x942c733fa43900388424a1bf7f94d934b3531b23';
    const USER = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const innerApprove = encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [SPENDER, 500n] });
    const innerTransfer = encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [USER, 42n] });
    const nested = encodeFunctionData({ abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [[innerTransfer, '0xdeadbeef']] });
    const outer = encodeFunctionData({ abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [[innerApprove, nested]] });
    const decoded = decodeTransactionCalldata({ to: ROUTER, data: outer, value: '0x0' });
    const tree = buildSubcallTree(decoded);
    assert.strictEqual(tree.hasNested, true);
    assert.strictEqual(tree.subcalls.length, 4);
    assert.strictEqual(tree.maxDepth, 2);
    assert.strictEqual(tree.unknownCount, 1);
    const [sc1, sc2, sc3, sc4] = tree.subcalls;
    assert.deepStrictEqual([sc1.subcallId, sc1.path, sc1.depth, sc1.parentId], ['SC-001', '0', 1, null]);
    assert.deepStrictEqual([sc2.subcallId, sc2.path, sc2.depth, sc2.parentId], ['SC-002', '1', 1, null]);
    assert.strictEqual(sc2.container, true);
    assert.deepStrictEqual([sc3.subcallId, sc3.path, sc3.depth, sc3.parentId], ['SC-003', '1/0', 2, 'SC-002']);
    assert.deepStrictEqual([sc4.subcallId, sc4.path, sc4.depth, sc4.parentId], ['SC-004', '1/1', 2, 'SC-002']);
    assert.strictEqual(sc4.unknown, true);
    assert.strictEqual(sc4.selector, '0xdeadbeef');
    assert.ok(sc1.effect.summary.includes('approve') && sc1.effect.grantsApproval === true);
    assert.ok(sc3.effect.movesAssets === true);
    assert.ok(sc1.target === ROUTER.toLowerCase(), 'inners target the batch contract');
    // Deterministic: rebuilt trees assign identical IDs.
    const again = buildSubcallTree(decoded);
    assert.deepStrictEqual(again.subcalls.map((s) => s.subcallId), ['SC-001', 'SC-002', 'SC-003', 'SC-004']);
    // Non-batch transactions have no tree.
    const plain = decodeTransactionCalldata({ to: USER, data: '0x', value: '0x1' });
    assert.strictEqual(buildSubcallTree(plain).hasNested, false);
    console.log('✔ B4.1 Passed: Stable subcall IDs, paths, parents, depth, effects.');
  }

  // ---- B4.2: inner findings fire with subcall provenance ----
  {
    const { encodeFunctionData } = require('viem');
    const { ERC20_ABI, UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const ATTACKER = '0xdead000000000000000000000000000000000001';
    const USER = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const MAX = (1n << 256n) - 1n;
    const drain = encodeFunctionData({
      abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
      args: [[
        encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [USER, 1n] }),
        encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [ATTACKER, MAX] }),
        '0xdeadbeef'
      ]]
    });
    const decoded = decodeTransactionCalldata({ to: ROUTER, data: drain, value: '0x0', from: USER });
    const ids = decoded.ruleFindings.map((f) => f.ruleId);
    assert.ok(ids.includes('AMBIGUOUS_APPROVAL_SCOPE'), 'hidden max-approve cannot hide behind the batch');
    assert.ok(ids.includes('UNVERIFIED_SPENDER'), 'hidden attacker spender flagged');
    assert.ok(ids.includes('UNKNOWN_INNER_CALL'), 'unknown inner flagged');
    const amb = decoded.ruleFindings.find((f) => f.ruleId === 'AMBIGUOUS_APPROVAL_SCOPE');
    assert.strictEqual(amb.metadata.subcall.subcallId, 'SC-002');
    assert.ok(amb.description.startsWith('[nested SC-002 approve]'));
    const unk = decoded.ruleFindings.find((f) => f.ruleId === 'UNKNOWN_INNER_CALL');
    assert.strictEqual(unk.severity, 'MEDIUM');
    assert.strictEqual(unk.metadata.subcall.subcallId, 'SC-003');
    // Benign batch: ordinary transfer only, no findings smuggled in.
    const benign = encodeFunctionData({
      abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
      args: [[encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [USER, 1n] })]]
    });
    const clean = decodeTransactionCalldata({ to: ROUTER, data: benign, value: '0x0', from: USER });
    assert.deepStrictEqual(clean.ruleFindings, [], 'benign batch stays clean');
    // Depth limit: 6-deep nesting marks the boundary uninterpretable.
    let layer = '0xdeadbeef';
    for (let i = 0; i < 6; i++) {
      layer = encodeFunctionData({ abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall', args: [[layer]] });
    }
    const deep = decodeTransactionCalldata({ to: ROUTER, data: layer, value: '0x0' });
    const dl = deep.ruleFindings.find((f) => f.ruleId === 'UNKNOWN_INNER_CALL' && f.metadata && f.metadata.depthLimited === true);
    assert.ok(dl, 'depth-limited branch flagged as uninterpretable');
    console.log('✔ B4.2 Passed: Hidden approvals/spenders/unknowns flagged; benign batches clean; depth limit honest.');
  }

  // ---- B4.3: stage-12 safeguard + policy + S4 + SC-xxx registry ----
  {
    const { findingActionFor } = require('../../src/services/policyDecision');
    assert.strictEqual(findingActionFor('UNKNOWN_INNER_CALL'), 'REVIEW');
    assert.ok(SHARED_SEMANTIC_RULES.includes('S4. Nested operations'));
    const hit = applyVerdictSafeguards({ ruleFindings: [{ ruleId: 'UNKNOWN_INNER_CALL' }] },
      { verdict: 'MATCH', confidence: 0.9, summary: 's', origin: 'model' });
    assert.strictEqual(hit.reasoningResult.verdict, 'UNCERTAIN');
    assert.ok(hit.safeguards.some((s) => s.trigger === 'UNKNOWN_INNER_CALL'));
    const safe = applyVerdictSafeguards({ ruleFindings: [{ ruleId: 'UNKNOWN_INNER_CALL' }] },
      { verdict: 'MISMATCH', confidence: 0.9, summary: 's', origin: 'model' });
    assert.strictEqual(safe.reasoningResult.verdict, 'MISMATCH');

    const { encodeFunctionData } = require('viem');
    const { ERC20_ABI, UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const { buildEvidenceRegistry, classifyRef } = require('../../src/services/reasoningValidation');
    const { buildSourceTexts } = require('../../src/services/supportValidation');
    const { buildDeterministicEdges } = require('../../src/services/evidenceGraph');
    const { buildSubcallTree } = require('../../src/services/nestedCalls');
    const batch = decodeTransactionCalldata({
      to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
      data: encodeFunctionData({
        abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
        args: [[encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8', 7n] }), '0xdeadbeef']]
      }),
      value: '0x0'
    });
    const reg = buildEvidenceRegistry({ pageContext: { title: 't', url: 'https://w.example' }, decodedTx: batch, visualMeta: {}, extra: {} });
    assert.strictEqual(classifyRef('SC-001', reg), 'ok');
    assert.strictEqual(classifyRef('[SC-002]', reg), 'ok', 'bracketed display form canonicalizes');
    assert.strictEqual(classifyRef('SC-999', reg), 'fabricated');
    const texts = buildSourceTexts({ decodedTx: batch });
    assert.ok(texts.get('SC-001').includes('transfer'), 'subcall text supports quoted spans');
    const edges = buildDeterministicEdges({ subcalls: buildSubcallTree(batch) });
    assert.ok(edges.some((e) => e.type === 'DERIVED_FROM' && e.from === 'tx' && e.to === 'SC-001'));
    assert.ok(edges.some((e) => e.type === 'CONTRADICTS' && e.from === 'SC-002' && e.to === 'tx'));
    console.log('✔ B4.3 Passed: Stage 12 + REVIEW + S4 + SC-xxx registry/texts/graph edges.');
  }

  // ---- B4.4: multicall-aware action comparison ----
  {
    const { compareIntentToTx } = require('../../src/utils/intentComparison');
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const region = (regionId, text) => ({ regionId, genuine: true, synthetic: false, ocr: { text, empty: text.length === 0, error: null } });
    const claim = (type, value, regionIds) => ({ type, value, regionIds, associationIds: [], status: 'supported' });
    const fieldOf = (res, field) => res.fields.find((f) => f.field === field);
    const uiSwap = {
      regions: [region('R-001', 'Swap tokens')],
      claims: [claim('action', 'Swap', ['R-001'])]
    };
    const withInners = (calls) => ({
      contract: ROUTER, functionName: 'multicall', standard: 'UniswapV3Router',
      parameters: { args: [], calls }, valueWei: '0'
    });
    const swapBatch = compareIntentToTx(uiSwap, withInners([
      { functionName: 'exactInputSingle', standard: 'UniswapV3Router' },
      { functionName: 'unknownFunction', standard: 'Unknown' }
    ]));
    assert.strictEqual(fieldOf(swapBatch, 'action').status, 'MATCH', 'verb matches decoded inner');
    assert.ok(fieldOf(swapBatch, 'action').txValue.includes('exactInputSingle'));

    const approveOnly = compareIntentToTx(uiSwap, withInners([{ functionName: 'approve', standard: 'ERC20' }]));
    assert.strictEqual(fieldOf(approveOnly, 'action').status, 'INCONCLUSIVE', 'verb/inner mismatch never MISMATCHes');

    const noCalls = compareIntentToTx(uiSwap, withInners(undefined));
    assert.strictEqual(fieldOf(noCalls, 'action').status, 'INCONCLUSIVE');

    const uiApprove = {
      regions: [region('R-001', 'Approve spending')],
      claims: [claim('action', 'Approve', ['R-001'])]
    };
    const bare = compareIntentToTx(uiApprove, withInners([{ functionName: 'approve', standard: 'ERC20' }]));
    assert.strictEqual(fieldOf(bare, 'action').status, 'INCONCLUSIVE', 'approval verb still needs operation context');
    const scoped = compareIntentToTx({
      regions: [region('R-001', 'Approve Unlimited spending')],
      claims: [claim('action', 'Approve', ['R-001']), claim('approval', 'Unlimited spending', ['R-001'])]
    }, withInners([{ functionName: 'approve', standard: 'ERC20' }]));
    assert.strictEqual(fieldOf(scoped, 'action').status, 'MATCH', 'approval verb + scope + inner approve');
    console.log('✔ B4.4 Passed: Multicall action MATCH/INCONCLUSIVE with approval-context gate.');
  }

  // ---- B4.5: controller end to end (hidden drain batch held) ----
  {
    const { encodeFunctionData } = require('viem');
    const { ERC20_ABI, UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const ATTACKER = '0xdead000000000000000000000000000000000001';
    const USER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
    const ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
    const MAX = (1n << 256n) - 1n;
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    global.fetch = mockModelFetch('MATCH');
    try {
      const { done, res } = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: USER, to: ROUTER,
        data: encodeFunctionData({
          abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
          args: [[
            encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [USER, 1n] }),
            encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [ATTACKER, MAX] }),
            '0xdeadbeef'
          ]]
        }),
        value: '0x0', chainId: '0x1'
      }), res, { proxyResolution: { target: ROUTER.toLowerCase(), status: 'not-proxy', isProxy: false, downgrade: false, hold: null, explanation: 'direct' } });
      const out = await done;
      assert.strictEqual(out.status, 200);
      const ids = (out.body.ruleFindings || []).map((f) => f.ruleId);
      assert.ok(ids.includes('AMBIGUOUS_APPROVAL_SCOPE') && ids.includes('UNKNOWN_INNER_CALL'));
      assert.ok(out.body.verdictSafeguards.some((s) => s.trigger === 'UNKNOWN_INNER_CALL'));
      assert.strictEqual(out.body.verdict, 'UNCERTAIN', 'MATCH over hidden drain batch must not stand');
      assert.strictEqual(out.body.policyDecision.decision, 'UNCERTAIN');
      assert.strictEqual(out.body.subcalls.hasNested, true, 'subcall tree persisted in bundle');
      assert.strictEqual(out.body.subcalls.subcalls.length, 3);
      assert.ok(out.body.evidenceGraph.edges.some((e) => e.to === 'SC-001' && e.type === 'DERIVED_FROM'), 'subcall edges in graph');
      // The nested block reaches the model prompt (packing audit keeps
      // accounting only, so pack the same decoded batch directly).
      const { decodeTransactionCalldata } = require('../../src/services/decoderService');
      const packedBatch = decodeTransactionCalldata({
        to: ROUTER,
        data: encodeFunctionData({
          abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
          args: [[
            encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [USER, 1n] }),
            encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [ATTACKER, MAX] })
          ]]
        }),
        value: '0x0'
      });
      const txText = packEvidence({
        visualText: '', pageContext: { title: 't', url: 'https://w.example' },
        decodedTx: packedBatch, visualMeta: {}, extra: {}
      }).sectionTexts.find((s) => s.name === 'tx').text;
      assert.ok(txText.includes('Nested Calls') && txText.includes('[SC-002]'), 'nested block reaches the model prompt');
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B4.5 Passed: Hidden-drain batch downgraded, persisted, packed, graphed.');
  }

  // ---- B4.6: inner parameter citation (live fix: CS5 param:spender) ----
  {
    const { encodeFunctionData } = require('viem');
    const { ERC20_ABI, UNISWAP_V3_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const { buildEvidenceRegistry, classifyRef } = require('../../src/services/reasoningValidation');
    const batch = decodeTransactionCalldata({
      to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
      data: encodeFunctionData({
        abi: UNISWAP_V3_ROUTER_ABI, functionName: 'multicall',
        args: [[encodeFunctionData({
          abi: ERC20_ABI, functionName: 'approve',
          args: ['0xdead000000000000000000000000000000000001', (1n << 256n) - 1n]
        })]]
      }),
      value: '0x0'
    });
    const reg = buildEvidenceRegistry({ pageContext: {}, decodedTx: batch, visualMeta: {}, extra: {} });
    assert.strictEqual(classifyRef('param:spender', reg), 'ok', 'inner approve spender citable');
    assert.strictEqual(classifyRef('param:amount', reg), 'ok', 'inner approve amount citable');
    assert.strictEqual(classifyRef('param:noSuchParam', reg), 'fabricated', 'unknown names still fabricated');
    const plain = decodeTransactionCalldata({
      to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      data: encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8', 1n] }),
      value: '0x0'
    });
    const regPlain = buildEvidenceRegistry({ pageContext: {}, decodedTx: plain, visualMeta: {}, extra: {} });
    assert.strictEqual(classifyRef('param:spender', regPlain), 'fabricated', 'no blanket pass without an inner approve');
    assert.strictEqual(classifyRef('param:recipient', regPlain), 'ok', 'top-level names still resolve');
    console.log('✔ B4.6 Passed: Inner subcall parameters citable; unknown names still fabricated.');
  }

  // ---- B5.1: chain-scoped static decode ----
  {
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
    const approveData = '0x095ea7b3000000000000000000000000942c733fa43900388424a1bf7f94d934b3531b23000000000000000000000000000000000000000000000000000000000000064';
    const onMainnet = decodeTransactionCalldata({ to: USDT, data: approveData, value: '0x0', chainId: '0x1' });
    assert.strictEqual(onMainnet.contractName, 'Tether USD');
    assert.strictEqual(onMainnet.symbol, 'USDT');
    assert.strictEqual(onMainnet.decimals, 6);
    assert.strictEqual(onMainnet.chainId, '1');
    assert.strictEqual(onMainnet.standardAmbiguous, false);
    // Same address on Polygon: an unrelated contract, never Tether.
    const onPolygon = decodeTransactionCalldata({ to: USDT, data: approveData, value: '0x0', chainId: '137' });
    assert.strictEqual(onPolygon.contractName, 'Unknown Contract');
    assert.strictEqual(onPolygon.symbol, null);
    assert.strictEqual(onPolygon.decimals, null);
    assert.strictEqual(onPolygon.chainId, '137');
    assert.strictEqual(onPolygon.standardAmbiguous, true, 'approve on unidentified contract is ambiguous');
    // Legacy unscoped callers keep working (chainId recorded as null).
    const legacy = decodeTransactionCalldata({ to: USDT, data: approveData, value: '0x0' });
    assert.strictEqual(legacy.contractName, 'Tether USD');
    assert.strictEqual(legacy.chainId, null);
    const badChain = decodeTransactionCalldata({ to: USDT, data: approveData, value: '0x0', chainId: 'zzz' });
    assert.strictEqual(badChain.contractName, 'Tether USD', 'unparseable chain falls back to legacy');
    console.log('✔ B5.1 Passed: Static labels chain-scoped; legacy unscoped callers preserved.');
  }

  // ---- B5.2: scoped spender allowlist + swap-leg metadata ----
  {
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const { resolveStaticTokenMeta } = require('../../src/services/intentComparisonAdapter');
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const ROUTER_V2 = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
    const approveTo = (spender) => `0x095ea7b3000000000000000000000000${spender.slice(2).toLowerCase()}0000000000000000000000000000000000000000000000000000000000000064`;
    const mainnet = decodeTransactionCalldata({ to: USDC, data: approveTo(ROUTER_V2), value: '0x0', chainId: 1 });
    assert.ok(!mainnet.ruleFindings.some((f) => f.ruleId === 'UNVERIFIED_SPENDER'), 'mainnet router verified on mainnet');
    const l2 = decodeTransactionCalldata({ to: USDC, data: approveTo(ROUTER_V2), value: '0x0', chainId: '0xa' });
    assert.ok(l2.ruleFindings.some((f) => f.ruleId === 'UNVERIFIED_SPENDER'), 'mainnet router address unverified on Optimism');
    assert.deepStrictEqual(resolveStaticTokenMeta(USDC, '1'), { symbol: 'USDC', decimals: 6 });
    assert.strictEqual(resolveStaticTokenMeta(USDC, '137'), null, 'mainnet decimals never calibrate L2 amounts');
    assert.deepStrictEqual(resolveStaticTokenMeta(USDC, undefined), { symbol: 'USDC', decimals: 6 }, 'legacy unscoped metadata preserved');
    console.log('✔ B5.2 Passed: Router allowlist + leg metadata chain-scoped.');
  }

  // ---- B5.3: verification-status ladder ----
  {
    const { resolveContractIdentity } = require('../../src/services/contractIdentity');
    const T = '0xdead000000000000000000000000000000000001';
    const okState = (hasCode, codeHash) => ({
      status: 'ok', states: { target: { address: T.toLowerCase(), status: 'ok', balanceWei: '0', nonce: '0', hasCode, codeHash } }
    });
    const noProxy = { status: 'not-proxy', isProxy: false, targetCodeHash: null };
    // Source verification wins over everything.
    const sv = resolveContractIdentity({
      address: T, chainId: '1', decodedTx: { functionName: 'transfer', standard: 'ERC20' },
      chainState: okState(true, '0xabc'), proxyResolution: noProxy,
      sourceVerification: { status: 'full', source: 'sourcify-v2' }
    });
    assert.strictEqual(sv.status, 'source-verified');
    // Bytecode match beats proxy/label tiers.
    const HASH = `0x${'ab'.repeat(32)}`;
    const bm = resolveContractIdentity({
      address: T, chainId: '1', decodedTx: { functionName: 'transfer', standard: 'ERC20' },
      chainState: okState(true, HASH), proxyResolution: noProxy,
      bytecodeRefs: { ok: true, refs: { 1: { [T.toLowerCase()]: HASH } }, skipped: [] },
      sourceVerification: { status: 'none' }
    });
    assert.strictEqual(bm.status, 'bytecode-matched');
    assert.strictEqual(bm.bytecodeMatch.role, 'target');
    // Resolved proxy beats labels.
    const IMPL = '0x1111111111111111111111111111111111111111';
    const px = resolveContractIdentity({
      address: T, chainId: '1', decodedTx: { functionName: 'transfer', standard: 'ERC20' },
      chainState: okState(true, '0xdef'), proxyResolution: {
        status: 'resolved', isProxy: true, kind: 'ERC-1967', implementation: IMPL,
        implementationCode: { checked: true, hasCode: true, codeHash: `0x${'cd'.repeat(32)}` }
      },
      sourceVerification: { status: 'none' }
    });
    assert.strictEqual(px.status, 'proxy-implementation-resolved');
    // Static label (display only) with cross-chain note.
    const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
    const sl = resolveContractIdentity({
      address: USDT, chainId: '0x1', decodedTx: { functionName: 'transfer', standard: 'ERC20' },
      chainState: { status: 'unavailable' }, proxyResolution: { status: 'unavailable', isProxy: null },
      sourceVerification: { status: 'unavailable' }
    });
    assert.strictEqual(sl.status, 'static-label');
    assert.ok(sl.staticLabel.label.includes('Tether'));
    // Code present, nothing else.
    const cu = resolveContractIdentity({
      address: T, chainId: '1', decodedTx: { functionName: 'transfer', standard: 'ERC20' },
      chainState: okState(true, '0x123'), proxyResolution: noProxy,
      sourceVerification: { status: 'none' }
    });
    assert.strictEqual(cu.status, 'code-present-unverified');
    // Confirmed EOA.
    const eoa = resolveContractIdentity({
      address: T, chainId: '1', decodedTx: { functionName: 'nativeTransfer', standard: 'Native' },
      chainState: okState(false, null), proxyResolution: { status: 'skipped-native-transfer', isProxy: false },
      sourceVerification: { status: 'skipped' }
    });
    assert.strictEqual(eoa.status, 'unknown');
    // No reads at all: unavailable, distinct from unknown.
    const un = resolveContractIdentity({
      address: T, chainId: '1', decodedTx: { functionName: 'transfer', standard: 'ERC20' },
      chainState: { status: 'unavailable' }, proxyResolution: { status: 'unavailable', isProxy: null },
      sourceVerification: { status: 'unavailable' }
    });
    assert.strictEqual(un.status, 'verification-unavailable');
    // Partial sourcify never counts as verification.
    const part = resolveContractIdentity({
      address: T, chainId: '1', decodedTx: { functionName: 'transfer', standard: 'ERC20' },
      chainState: okState(true, '0x123'), proxyResolution: noProxy,
      sourceVerification: { status: 'partial', source: 'sourcify-v2' }
    });
    assert.strictEqual(part.status, 'code-present-unverified');
    console.log('✔ B5.3 Passed: Identity ladder ordered honestly (source > bytecode > proxy > label > code > unknown/unavailable).');
  }

  // ---- B5.4: directory lookups + bytecode refs (injected transport) ----
  {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const { lookupSelectorSignature, lookupSourceVerification, loadBytecodeRefs } = require('../../src/services/contractIdentity');
    const fourByte = async () => ({
      ok: true, status: 200, json: async () => ({
        count: 2,
        results: [
          { id: 999, text_signature: 'evilSpam(uint256)', hex_signature: '0xdeadbeef' },
          { id: 12, text_signature: 'claimReward(uint256)', hex_signature: '0xdeadbeef' }
        ]
      })
    });
    const sig = await lookupSelectorSignature('0xdeadbeef', { fetchImpl: fourByte });
    assert.strictEqual(sig.status, 'found');
    assert.strictEqual(sig.textSignature, 'claimReward(uint256)', 'earliest submission wins as the hint');
    assert.strictEqual(sig.count, 2);
    assert.strictEqual((await lookupSelectorSignature('0xdeadbeef', { fetchImpl: fourByte, enabled: false })).status, 'disabled');
    assert.strictEqual((await lookupSelectorSignature('nope', { fetchImpl: fourByte })).status, 'invalid-selector');
    const empty = await lookupSelectorSignature('0xdeadbeef', { fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ count: 0, results: [] }) }) });
    assert.strictEqual(empty.status, 'not-found');
    const down = await lookupSelectorSignature('0xdeadbeef', { fetchImpl: async () => { throw new Error('dns'); } });
    assert.strictEqual(down.status, 'unavailable');

    const full = await lookupSourceVerification('0xdAC17F958D2ee523a2206206994597C13D831ec7', '0x1', {
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ match: 'match', verifiedAt: '2024-01-01', matchId: '7' }) })
    });
    assert.strictEqual(full.status, 'full');
    const none = await lookupSourceVerification('0xdead000000000000000000000000000000000001', 1, {
      fetchImpl: async () => ({ ok: false, status: 404, json: async () => ({}) })
    });
    assert.strictEqual(none.status, 'none', 'sourcify 404 means unverified');
    const partial = await lookupSourceVerification('0xdead000000000000000000000000000000000001', 1, {
      fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ match: 'partial' }) })
    });
    assert.strictEqual(partial.status, 'partial');
    assert.strictEqual((await lookupSourceVerification('0xdead000000000000000000000000000000000001', 1, { fetchImpl: fourByte, enabled: false })).status, 'disabled');

    const dir = fs.mkdtempSync(path.join('test', 'tmp', 'cap4-b5-'));
    try {
      const good = path.join(dir, 'refs.json');
      fs.writeFileSync(good, JSON.stringify({ 1: { '0xdead000000000000000000000000000000000001': `0x${'ab'.repeat(32)}` }, junk: 'xx' }), 'utf8');
      const loaded = loadBytecodeRefs(good);
      assert.strictEqual(loaded.ok, true);
      assert.ok(loaded.refs['1']['0xdead000000000000000000000000000000000001']);
      assert.strictEqual(loadBytecodeRefs(null).refs && Object.keys(loadBytecodeRefs(null).refs).length, 0);
      assert.strictEqual(loadBytecodeRefs(path.join(dir, 'missing.json')).ok, false);
      fs.writeFileSync(path.join(dir, 'bad.json'), '{oops', 'utf8');
      assert.strictEqual(loadBytecodeRefs(path.join(dir, 'bad.json')).ok, false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    console.log('✔ B5.4 Passed: 4byte/Sourcify/refs lookups with explicit failure states.');
  }

  // ---- B5.5: S5 prompt + identity pack block + registry token ----
  {
    assert.ok(SHARED_SEMANTIC_RULES.includes('S5. Contract identity'));
    assert.ok(selectSystemPrompt('browser').text.includes('S5. Contract identity'));
    assert.ok(selectSystemPrompt('agent').text.includes('identity section'));
    const { buildEvidenceRegistry, classifyRef } = require('../../src/services/reasoningValidation');
    const reg = buildEvidenceRegistry({ pageContext: {}, decodedTx: { parameters: {} }, visualMeta: {}, extra: {} });
    assert.strictEqual(classifyRef('identity', reg), 'ok');
    const text = packEvidence({
      visualText: '', pageContext: { title: 't', url: 'https://w.example' },
      decodedTx: { contract: '0xdead000000000000000000000000000000000001', functionName: 'transfer', standard: 'ERC20', parameters: {}, ruleFindings: [] },
      visualMeta: {},
      extra: {
        contractIdentity: {
          target: '0xdead000000000000000000000000000000000001', chainId: '137', status: 'code-present-unverified',
          explanation: 'Contract code is present but nothing identifies it.',
          staticLabel: null, staticLabelOtherChains: ['1'],
          code: { present: true, codeHash: `0x${'12'.repeat(32)}`, source: 'chain-state' },
          proxy: { isProxy: false }, bytecodeMatch: null,
          selectorSignature: null, sourceVerification: { status: 'none' }
        }
      }
    }).sectionTexts.find((s) => s.name === 'tx').text;
    assert.ok(text.includes('Contract Identity') && text.includes('code-present-unverified'));
    assert.ok(text.includes('label-known-on-other-chains=[1]'), 'cross-chain label collision disclosed');
    console.log('✔ B5.5 Passed: S5 rule, identity pack block, registry token.');
  }

  // ---- B5.6: controller end to end (wrong-chain label + unknown selector) ----
  {
    const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    global.fetch = mockModelFetch('MATCH');
    try {
      // USDT address on chain 137: no borrowed mainnet identity.
      const first = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', to: USDT,
        data: '0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000000000000000064',
        value: '0x0', chainId: '0x89'
      }), first.res, {
        chainState: { status: 'unavailable' },
        proxyResolution: { target: USDT.toLowerCase(), status: 'unavailable', isProxy: null, explanation: 'no rpc' }
      });
      const out = await first.done;
      assert.strictEqual(out.status, 200);
      assert.strictEqual(out.body.decodedTransaction.contractName, 'Unknown Contract');
      assert.strictEqual(out.body.contractIdentity.status, 'verification-unavailable');
      assert.ok((out.body.contractIdentity.staticLabelOtherChains || []).includes('1'), 'mainnet-only label disclosed as other-chain');

      // Unknown selector with live code: 4byte-shaped stub yields
      // not-found, sourcify-shaped stub yields none — deterministic.
      const second = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
        to: '0x1234567890123456789012345678901234567890',
        data: '0xdeadbeef', value: '0x0', chainId: '0x1'
      }), second.res, {
        chainState: {
          status: 'ok', rpcChainId: '1', chainVerified: true, blockNumber: '0x1',
          states: { target: { address: '0x1234567890123456789012345678901234567890', status: 'ok', balanceWei: '0', nonce: '1', hasCode: true, codeHash: `0x${'99'.repeat(32)}` } }
        },
        proxyResolution: { target: '0x1234567890123456789012345678901234567890', status: 'not-proxy', isProxy: false, explanation: 'direct' }
      });
      const out2 = await second.done;
      assert.strictEqual(out2.status, 200);
      assert.strictEqual(out2.body.contractIdentity.status, 'code-present-unverified');
      assert.strictEqual(out2.body.contractIdentity.selectorSignature.status, 'not-found');
      assert.strictEqual(out2.body.contractIdentity.sourceVerification.status, 'none');
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B5.6 Passed: Wrong-chain labels rejected; unknown-selector identity assembled.');
  }

  // ---- B6.1: deadline-bearing functions decode ----
  {
    const { encodeFunctionData } = require('viem');
    const { ERC20_ABI, PERMIT2_ABI, UNISWAP_V2_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const { decodeTransactionCalldata } = require('../../src/services/decoderService');
    const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const V2 = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
    const USER = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const v2 = decodeTransactionCalldata({
      to: V2,
      data: encodeFunctionData({
        abi: UNISWAP_V2_ROUTER_ABI, functionName: 'swapExactTokensForTokens',
        args: [1000n, 900n, [WETH, USDC], USER, 1893456000n]
      }),
      value: '0x0', chainId: '1'
    });
    assert.strictEqual(v2.functionName, 'swapExactTokensForTokens');
    assert.strictEqual(v2.standard, 'UniswapV2Router');
    assert.strictEqual(v2.parameters.deadline, '1893456000');
    assert.strictEqual(v2.parameters.amountOutMin, '900');
    assert.deepStrictEqual(v2.parameters.path.map((p) => p.toLowerCase()), [WETH.toLowerCase(), USDC.toLowerCase()]);

    const eip2612 = decodeTransactionCalldata({
      to: USDC,
      data: encodeFunctionData({
        abi: ERC20_ABI, functionName: 'permit',
        args: [USER, V2, 500n, 1893456000n, 27, `0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`]
      }),
      value: '0x0', chainId: '1'
    });
    assert.strictEqual(eip2612.functionName, 'permit');
    assert.strictEqual(eip2612.standard, 'ERC20');
    assert.strictEqual(eip2612.parameters.deadline, '1893456000');
    assert.ok(!eip2612.ruleFindings.some((f) => f.ruleId === 'PERMIT2_OFFCHAIN_APPROVAL'), 'EIP-2612 never misattributed to Permit2');

    const p2 = decodeTransactionCalldata({
      to: '0x000000000022d473030f116ddee9f6b43ac78ba3',
      data: encodeFunctionData({
        abi: PERMIT2_ABI, functionName: 'permit',
        args: [USER, { token: USDC, amount: 100n, expiration: 1893456000, nonce: 7 }, '0x1234']
      }),
      value: '0x0', chainId: '1'
    });
    assert.strictEqual(String(p2.parameters.expiration), '1893456000', 'uint48 expiration (viem number)');
    assert.ok(p2.ruleFindings.some((f) => f.ruleId === 'PERMIT2_OFFCHAIN_APPROVAL'), 'Permit2 permit still fires its rule');
    console.log('✔ B6.1 Passed: V2 swaps, EIP-2612 permit, Permit2 expirations decode.');
  }

  // ---- B6.2: deadline analysis branches ----
  {
    const { analyzeDeadlines } = require('../../src/services/deadlineAnalysis');
    const BLOCK = '1700000000';
    const v2 = (deadline) => ({
      functionName: 'swapExactTokensForTokens', standard: 'UniswapV2Router',
      parameters: { deadline }
    });
    const expired = analyzeDeadlines({ decodedTx: v2('1699999000'), blockTimestamp: BLOCK, blockNumber: '0x9', chainId: '1' });
    assert.strictEqual(expired.states[0].outcome, 'expired');
    assert.ok(expired.findings.some((f) => f.ruleId === 'EXPIRED_OPERATION'));
    assert.strictEqual(expired.downgrade, true);
    assert.strictEqual(expired.hold.source, 'deadline-analysis');

    // Grace boundary: exactly 300s past is tolerated (near-expiry, no
    // finding), 301s is expired.
    const edge = analyzeDeadlines({ decodedTx: v2(String(1700000000 - 300)), blockTimestamp: BLOCK });
    assert.strictEqual(edge.states[0].outcome, 'near-expiry');
    assert.strictEqual(edge.findings.length, 0);
    const past = analyzeDeadlines({ decodedTx: v2(String(1700000000 - 301)), blockTimestamp: BLOCK });
    assert.strictEqual(past.states[0].outcome, 'expired');

    const near = analyzeDeadlines({ decodedTx: v2(String(1700000000 + 600)), blockTimestamp: BLOCK });
    assert.strictEqual(near.states[0].outcome, 'near-expiry');
    assert.strictEqual(near.findings.length, 0, 'near-expiry is informational only');

    const valid = analyzeDeadlines({ decodedTx: v2('1893456000'), blockTimestamp: BLOCK });
    assert.strictEqual(valid.states[0].outcome, 'valid');

    const missing = analyzeDeadlines({ decodedTx: v2(undefined), blockTimestamp: BLOCK });
    assert.strictEqual(missing.states[0].outcome, 'missing');
    assert.ok(missing.findings.some((f) => f.ruleId === 'MISSING_DEADLINE'));

    const noClock = analyzeDeadlines({ decodedTx: v2('1893456000'), blockTimestamp: null });
    assert.strictEqual(noClock.states[0].outcome, 'unassessable');
    assert.strictEqual(noClock.findings.length, 0, 'no clock means no finding');
    assert.strictEqual(noClock.downgrade, false);

    const v3 = analyzeDeadlines({
      decodedTx: { functionName: 'exactInputSingle', standard: 'UniswapV3Router', parameters: { amountOutMinimum: '1' } },
      blockTimestamp: BLOCK
    });
    assert.strictEqual(v3.states[0].outcome, 'not-applicable', 'V3 absence is by design');
    assert.strictEqual(v3.checks.length, 0);

    // Nested expired inner carries subcall provenance.
    const inner = analyzeDeadlines({
      decodedTx: { functionName: 'multicall', standard: 'UniswapV3Router', parameters: {} },
      subcalls: [{
        subcallId: 'SC-002', path: '1', functionName: 'swapExactTokensForTokens',
        standard: 'UniswapV2Router', container: false, unknown: false, depthLimited: false,
        parameters: { deadline: '1600000000' }
      }],
      blockTimestamp: BLOCK
    });
    const innerFinding = inner.findings.find((f) => f.ruleId === 'EXPIRED_OPERATION');
    assert.ok(innerFinding && innerFinding.description.startsWith('[nested SC-002'));
    assert.strictEqual(innerFinding.metadata.subcall.subcallId, 'SC-002');
    assert.ok(inner.checks.some((c) => c.checkId === 'DEADLINE_VALID_INNER'));
    console.log('✔ B6.2 Passed: Expired/valid/near/missing/unassessable/N-A + grace boundary + inners.');
  }

  // ---- B6.3: block timestamps in chain state (mocked transport) ----
  {
    const { fetchChainState } = require('../../src/services/chainStateService');
    const addr = `0xab${'0'.repeat(36)}01`;
    const rpcOk = async (url, opts) => {
      const calls = JSON.parse(opts.body);
      return {
        ok: true,
        json: async () => calls.map((c) => {
          let result = null;
          if (c.method === 'eth_chainId') result = '0x1';
          if (c.method === 'eth_blockNumber') result = '0x9';
          if (c.method === 'eth_getBalance') result = '0x1';
          if (c.method === 'eth_getTransactionCount') result = '0x2';
          if (c.method === 'eth_getCode') result = '0x6000';
          if (c.method === 'eth_getBlockByNumber') result = { number: '0x9', timestamp: '0x6553f100' };
          return { jsonrpc: '2.0', id: c.id, result };
        })
      };
    };
    const ok = await fetchChainState({
      rpcUrl: 'http://127.0.0.1:9', chainId: '0x1',
      addresses: [{ role: 'target', address: addr }], fetchImpl: rpcOk
    });
    assert.strictEqual(ok.status, 'ok');
    assert.strictEqual(ok.block.status, 'ok');
    assert.strictEqual(ok.block.timestamp, String(0x6553f100));
    // Block-header failure degrades the block, never the chain state.
    const rpcNoBlock = async (url, opts) => {
      const calls = JSON.parse(opts.body);
      return {
        ok: true,
        json: async () => calls.map((c) => (c.method === 'eth_getBlockByNumber'
          ? { jsonrpc: '2.0', id: c.id, error: { message: 'no header' } }
          : { jsonrpc: '2.0', id: c.id, result: c.method === 'eth_chainId' ? '0x1' : (c.method === 'eth_blockNumber' ? '0x9' : (c.method === 'eth_getCode' ? '0x6000' : '0x1')) }))
      };
    };
    const degraded = await fetchChainState({
      rpcUrl: 'http://127.0.0.1:9', chainId: '0x1',
      addresses: [{ role: 'target', address: addr }], fetchImpl: rpcNoBlock
    });
    assert.strictEqual(degraded.status, 'ok');
    assert.strictEqual(degraded.block.status, 'unavailable');
    assert.strictEqual(degraded.states.target.hasCode, true);
    console.log('✔ B6.3 Passed: Block timestamps fetched; header failure degrades honestly.');
  }

  // ---- B6.4: stage-13 safeguard + policy + S6 + pack + registry ----
  {
    const { findingActionFor } = require('../../src/services/policyDecision');
    assert.strictEqual(findingActionFor('EXPIRED_OPERATION'), 'REVIEW');
    assert.strictEqual(findingActionFor('MISSING_DEADLINE'), 'REVIEW');
    assert.ok(SHARED_SEMANTIC_RULES.includes('S6. Deadlines and expiry'));
    const hit = applyVerdictSafeguards({ ruleFindings: [{ ruleId: 'EXPIRED_OPERATION' }] },
      { verdict: 'MATCH', confidence: 0.9, summary: 's', origin: 'model' });
    assert.strictEqual(hit.reasoningResult.verdict, 'UNCERTAIN');
    assert.ok(hit.safeguards.some((s) => s.trigger === 'EXPIRED_OPERATION'));
    const clean = applyVerdictSafeguards({ ruleFindings: [] }, { verdict: 'MATCH', confidence: 0.9, summary: 's', origin: 'model' });
    assert.strictEqual(clean.reasoningResult.verdict, 'MATCH');
    const { buildEvidenceRegistry, classifyRef } = require('../../src/services/reasoningValidation');
    const reg = buildEvidenceRegistry({ pageContext: {}, decodedTx: { parameters: {} }, visualMeta: {}, extra: {} });
    assert.strictEqual(classifyRef('deadlines', reg), 'ok');
    const text = packEvidence({
      visualText: '', pageContext: { title: 't', url: 'https://w.example' },
      decodedTx: { contract: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', functionName: 'swapExactTokensForTokens', standard: 'UniswapV2Router', parameters: {}, ruleFindings: [] },
      visualMeta: {},
      extra: {
        deadlines: {
          blockTime: '1700000000', blockNumber: '0x9',
          states: [{ label: 'top-level call', functionName: 'swapExactTokensForTokens', field: 'deadline', outcome: 'expired', deadline: '1600000000', blockTime: '1700000000' }]
        }
      }
    }).sectionTexts.find((s) => s.name === 'tx').text;
    assert.ok(text.includes('Deadline Analysis') && text.includes('expired'));
    console.log('✔ B6.4 Passed: Stage 13 + REVIEW + S6 + deadline pack block + token.');
  }

  // ---- B6.5: controller end to end (expired swap held; valid permit clean) ----
  {
    const { encodeFunctionData } = require('viem');
    const { ERC20_ABI, UNISWAP_V2_ROUTER_ABI } = require('../../src/utils/abiSignatures');
    const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const V2 = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
    const USER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
    const chainAt = (ts) => ({
      status: 'ok', rpcChainId: '1', chainVerified: true, blockNumber: '0x9',
      block: { status: 'ok', number: '0x9', timestamp: ts, timestampHex: `0x${BigInt(ts).toString(16)}` },
      states: {}
    });
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    global.fetch = mockModelFetch('MATCH');
    try {
      const first = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: USER, to: V2,
        data: encodeFunctionData({
          abi: UNISWAP_V2_ROUTER_ABI, functionName: 'swapExactTokensForTokens',
          args: [1000n, 900n, [WETH, USDC], USER, 1600000000n]
        }),
        value: '0x0', chainId: '0x1'
      }), first.res, {
        chainState: chainAt('1700000000'),
        proxyResolution: { target: V2.toLowerCase(), status: 'not-proxy', isProxy: false, explanation: 'direct' }
      });
      const out = await first.done;
      assert.strictEqual(out.status, 200);
      assert.ok((out.body.ruleFindings || []).some((f) => f.ruleId === 'EXPIRED_OPERATION'));
      assert.ok(out.body.verdictSafeguards.some((s) => s.trigger === 'EXPIRED_OPERATION'));
      assert.strictEqual(out.body.verdict, 'UNCERTAIN', 'MATCH over an expired swap must not stand');
      assert.strictEqual(out.body.deadlineAnalysis.states[0].outcome, 'expired');

      const second = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: USER, to: USDC,
        data: encodeFunctionData({
          abi: ERC20_ABI, functionName: 'permit',
          args: [USER, V2, 500n, 1893456000n, 27, `0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`]
        }),
        value: '0x0', chainId: '0x1'
      }), second.res, {
        chainState: chainAt('1700000000'),
        proxyResolution: { target: USDC.toLowerCase(), status: 'not-proxy', isProxy: false, explanation: 'direct' }
      });
      const out2 = await second.done;
      assert.strictEqual(out2.status, 200);
      assert.ok(!(out2.body.ruleFindings || []).some((f) => f.ruleId === 'EXPIRED_OPERATION' || f.ruleId === 'MISSING_DEADLINE'));
      assert.strictEqual(out2.body.deadlineAnalysis.states[0].outcome, 'valid');
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B6.5 Passed: Expired swap downgraded; valid permit unaffected.');
  }

  // ---- B7.1: all eight claim targets verify + contradict ----
  {
    const { verifySemanticClaims } = require('../../src/services/semanticClaims');
    const USER = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
    const OTHER = '0x00000000000000000000000000000000000000aa';
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const run = (statement, decodedTx, extra = {}) => verifySemanticClaims({
      reasoningResult: { investigation: { conclusions: [{ statement, supportingRefs: ['tx'] }] } },
      decodedTx, chainId: '1', ...extra
    }).claims;
    const first = (arr) => arr[0].result;

    // 1. Counterparty.
    const txT = { contract: USDC, functionName: 'transfer', standard: 'ERC20', parameters: { recipient: USER, amount: '100000000' } };
    assert.strictEqual(first(run(`The recipient ${USER} matches the decoded transfer.`, txT)), 'VERIFIED');
    assert.strictEqual(first(run(`The recipient ${OTHER} matches the decoded transfer.`, txT)), 'CONTRADICTED');
    assert.strictEqual(first(run(`The recipient is not ${OTHER} here.`, txT)), 'INCONCLUSIVE');

    // 2. Amount (100.0 USDC, 6 decimals).
    assert.strictEqual(first(run('The transaction transfers 100 USDC to the recipient.', txT)), 'VERIFIED');
    assert.strictEqual(first(run('The transaction transfers 999 USDC to the recipient.', txT)), 'CONTRADICTED');

    // 3. Unlimited approval.
    const MAX = ((1n << 256n) - 1n).toString();
    const txA = { contract: USDC, functionName: 'approve', standard: 'ERC20', parameters: { spender: USER, amount: MAX } };
    assert.strictEqual(first(run('This grants an unlimited approval to the spender.', txA)), 'VERIFIED');
    const txA2 = { contract: USDC, functionName: 'approve', standard: 'ERC20', parameters: { spender: USER, amount: '100' } };
    assert.strictEqual(first(run('This grants an unlimited approval to the spender.', txA2)), 'CONTRADICTED');
    assert.strictEqual(first(run('This is not an unlimited approval.', txA2)), 'VERIFIED');
    assert.strictEqual(first(run('This grants an unlimited approval.', txT)), 'NOT_APPLICABLE');

    // 4. Minimum output (3,400.0 USDC).
    const txS = {
      contract: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', functionName: 'exactInputSingle', standard: 'UniswapV3Router',
      parameters: { tokenOut: USDC, amountOutMinimum: (3400n * 10n ** 6n).toString() }
    };
    assert.strictEqual(first(run('The enforced minimum is 3,400 USDC per amountOutMinimum.', txS)), 'VERIFIED');
    assert.strictEqual(first(run('The enforced minimum is 3,000 USDC per amountOutMinimum.', txS)), 'CONTRADICTED');
    assert.strictEqual(first(run('The enforced minimum is 3,400 USDC.', txT)), 'NOT_APPLICABLE');

    // 5. Function name + selector.
    assert.strictEqual(first(run('The transaction calls transfer on the token.', txT)), 'VERIFIED');
    assert.strictEqual(first(run('The transaction calls approve on the token.', txT)), 'CONTRADICTED');
    const txU = { contract: OTHER, functionName: 'unknownFunction', standard: 'Unknown', parameters: { selector: '0xdeadbeef' } };
    assert.strictEqual(first(run('The calldata selector 0xdeadbeef is unrecognized.', txU)), 'VERIFIED');
    assert.strictEqual(first(run('The calldata selector 0x12345678 is unrecognized.', txU)), 'CONTRADICTED');

    // 6. Identity assertions.
    assert.strictEqual(first(run('The target is a verified contract with matching bytecode.', txT, { contractIdentity: { status: 'bytecode-matched' } })), 'VERIFIED');
    assert.strictEqual(first(run('The target is a verified contract with matching bytecode.', txT, { contractIdentity: { status: 'code-present-unverified' } })), 'CONTRADICTED');
    assert.strictEqual(first(run('The target is an unknown contract.', txT, { contractIdentity: { status: 'unknown' } })), 'VERIFIED');
    assert.strictEqual(first(run('The target is a proxy for the implementation.', txT, { proxyResolution: { isProxy: true } })), 'VERIFIED');
    assert.strictEqual(first(run('The target is a proxy for the implementation.', txT, { proxyResolution: { isProxy: false } })), 'CONTRADICTED');
    assert.strictEqual(first(run('The target is a proxy for the implementation.', txT, { proxyResolution: { isProxy: null } })), 'INCONCLUSIVE');

    // 7. Deadlines.
    assert.strictEqual(first(run('The deadline 1234567890 applies here.', txT)), 'NOT_APPLICABLE');
    const txP = { contract: USDC, functionName: 'permit', standard: 'ERC20', parameters: { deadline: '1893456000' } };
    assert.strictEqual(first(run('The permit deadline 1893456000 is far in the future.', txP)), 'VERIFIED');
    assert.strictEqual(first(run('The permit deadline 1700000000 is far in the future.', txP)), 'CONTRADICTED');
    assert.strictEqual(first(run('The operation has expired and will revert.', txP, { deadlineAnalysis: { states: [{ label: 'top-level call', outcome: 'expired' }] } })), 'VERIFIED');
    assert.strictEqual(first(run('The operation has expired and will revert.', txP, { deadlineAnalysis: { states: [{ label: 'top-level call', outcome: 'valid' }] } })), 'CONTRADICTED');

    // 8. Implementation address (selected by target: the counterparty
    // checker also evaluates the framed address).
    const IMPL = '0x1111111111111111111111111111111111111111';
    const implOf = (arr) => arr.find((c) => c.target === 'implementation').result;
    assert.strictEqual(implOf(run(`The proxy implementation ${IMPL} holds the logic.`, txT, { proxyResolution: { isProxy: true, implementation: IMPL } })), 'VERIFIED');
    assert.strictEqual(implOf(run(`The proxy implementation ${OTHER} holds the logic.`, txT, { proxyResolution: { isProxy: true, implementation: IMPL } })), 'CONTRADICTED');
    assert.strictEqual(implOf(run(`The proxy implementation ${IMPL} holds the logic.`, txT, { proxyResolution: { isProxy: true, implementation: null } })), 'INCONCLUSIVE');
    console.log('✔ B7.1 Passed: Eight claim targets verify, contradict, abstain, or N/A correctly.');
  }

  // ---- B7.2: summary downgrade/hold + claim cap ----
  {
    const { verifySemanticClaims, MAX_CLAIMS } = require('../../src/services/semanticClaims');
    const txT = { contract: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', functionName: 'transfer', standard: 'ERC20', parameters: { recipient: '0x70997970c51812dc3a010c7d01b50e0d17dc79c8', amount: '100' } };
    const bad = verifySemanticClaims({
      reasoningResult: { investigation: { conclusions: [{ statement: 'The transaction calls approve on the token.', supportingRefs: ['tx'] }] } },
      decodedTx: txT, chainId: '1'
    });
    assert.strictEqual(bad.summary.CONTRADICTED, 1);
    assert.strictEqual(bad.summary.downgrade, true);
    assert.strictEqual(bad.summary.hold.source, 'semantic-claims');
    const good = verifySemanticClaims({
      reasoningResult: { investigation: { conclusions: [{ statement: 'The transaction calls transfer on the token.', supportingRefs: ['tx'] }] } },
      decodedTx: txT, chainId: '1'
    });
    assert.strictEqual(good.summary.VERIFIED, 1);
    assert.strictEqual(good.summary.downgrade, false);
    assert.strictEqual(good.summary.hold, null);
    // Cap: conclusions + discrepancies overflow still terminates bounded.
    const mkMany = (n) => Array.from({ length: n }, (_, i) => ({ statement: `The transaction calls nope${i} on the token. The recipient 0x00000000000000000000000000000000000000${String(i).padStart(2, '0')} is set.`, supportingRefs: ['tx'] }));
    const many = verifySemanticClaims({
      reasoningResult: { investigation: { conclusions: mkMany(12), discrepancies: mkMany(12) } },
      decodedTx: txT, chainId: '1'
    });
    assert.strictEqual(many.claims.length, MAX_CLAIMS);
    assert.strictEqual(many.summary.truncated, true);
    console.log('✔ B7.2 Passed: Contradiction downgrades + holds; clean passes; output capped.');
  }

  // ---- B7.3: stage-14 safeguard + S7 prompt ----
  {
    assert.ok(SHARED_SEMANTIC_RULES.includes('S7. Checkable claims'));
    const hit = applyVerdictSafeguards({ ruleFindings: [] }, {
      verdict: 'MATCH', confidence: 0.9, summary: 's', origin: 'model',
      semanticClaims: { claims: [{ claimId: 'CLM-001', target: 'amount', result: 'CONTRADICTED' }], summary: { downgrade: true } }
    });
    assert.strictEqual(hit.reasoningResult.verdict, 'UNCERTAIN');
    assert.ok(hit.safeguards.some((s) => s.trigger === 'CONTRADICTED_SEMANTIC_CLAIM'));
    const clean = applyVerdictSafeguards({ ruleFindings: [] }, {
      verdict: 'MATCH', confidence: 0.9, summary: 's', origin: 'model',
      semanticClaims: { claims: [], summary: { downgrade: false } }
    });
    assert.strictEqual(clean.reasoningResult.verdict, 'MATCH');
    console.log('✔ B7.3 Passed: Stage 14 downgrades contradicted MATCH; clean stands; S7 present.');
  }

  // ---- B7.4: controller end to end (lying model held) ----
  {
    const USER = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
    const LIAR = '0x00000000000000000000000000000000000000aa';
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const investigation = {
      objective: 'check transfer', evidenceInventory: [], sourceAssessments: [],
      intentInterpretation: { statement: 'send', basisRefs: ['tx'], kind: 'inferred' },
      executionAnalysis: { statement: 'transfer', basisRefs: ['tx'] },
      parameterAnalysis: { statement: 'params', basisRefs: ['tx'] },
      discrepancies: [], contradictions: [], competingExplanations: [], suspiciousBehaviours: [],
      missingEvidence: [], uncertainty: { level: 'low', explanation: 'sure' },
      conclusions: [{ statement: `The recipient ${LIAR} matches the decoded transfer exactly.`, supportingRefs: ['tx'], contradictingRefs: [] }],
      recommendations: [], furtherInvestigation: []
    };
    const lyingFetch = async () => ({
      ok: true,
      json: async () => ({
        model: 'mock-m',
        choices: [{ message: { content: JSON.stringify({ verdict: 'MATCH', confidence: 0.95, summary: 'lies', discrepancyDetails: {}, recommendedAction: 'PROCEED_WITH_CAUTION', investigation }) } }]
      })
    });
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    global.fetch = lyingFetch;
    try {
      const { done, res } = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', to: USDC,
        data: `0xa9059cbb000000000000000000000000${USER.slice(2).toLowerCase()}0000000000000000000000000000000000000000000000000000000000000064`,
        value: '0x0', chainId: '0x1'
      }), res, {
        proxyResolution: { target: USDC.toLowerCase(), status: 'not-proxy', isProxy: false, explanation: 'direct' }
      });
      const out = await done;
      assert.strictEqual(out.status, 200);
      const bad = (out.body.semanticClaims.claims || []).find((c) => c.result === 'CONTRADICTED');
      assert.ok(bad && bad.target === 'counterparty', 'false recipient claim caught');
      assert.ok(out.body.verdictSafeguards.some((s) => s.trigger === 'CONTRADICTED_SEMANTIC_CLAIM'));
      assert.strictEqual(out.body.verdict, 'UNCERTAIN', 'MATCH on false claims must not stand');
      assert.strictEqual(out.body.policyDecision.decision, 'UNCERTAIN');
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B7.4 Passed: False model claim downgraded end to end.');
  }

  // ---- B7.5: live-precision regressions (false CONTRADICTEDs) ----
  {
    const { verifySemanticClaims } = require('../../src/services/semanticClaims');
    const USER = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
    const PROXY = '0x2222222222222222222222222222222222222222';
    const IMPL = '0x1111111111111111111111111111111111111111';
    const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const run = (statement, decodedTx, extra = {}) => verifySemanticClaims({
      reasoningResult: { investigation: { conclusions: [{ statement, supportingRefs: ['tx'] }] } },
      decodedTx, chainId: '1', ...extra
    }).claims;
    const byTarget = (arr, t) => arr.filter((c) => c.target === t).map((c) => c.result);

    // 1. Negation scope: "not" in an earlier clause must not flip a
    // later unlimited assertion (live record inv_mvv6yj0w).
    const txA = { contract: USDC, functionName: 'approve', parameters: { spender: USER, amount: ((1n << 256n) - 1n).toString() } };
    assert.deepStrictEqual(
      byTarget(run('Payload does not match benign purpose: unlimited approve enables fund movement contrary to no-movement claim.', txA), 'unlimited'),
      ['VERIFIED'], 'distant-clause "not"/"no" does not negate');
    assert.deepStrictEqual(
      byTarget(run('This is not an unlimited approval.', { contract: USDC, functionName: 'approve', parameters: { spender: USER, amount: '100' } }), 'unlimited'),
      ['VERIFIED'], 'adjacent "not" still negates (pinned)');

    // 2. Full digit runs + raw equality: "minimum 1000000" names the
    // decoded minimum exactly (live record inv_mvv63yc4).
    const txS = {
      contract: '0x7a250d5630b4cf539739df2c5dacb4c659f2488d', functionName: 'swapExactTokensForTokens',
      parameters: { amountIn: '1000000000000000000', amountOutMin: '1000000', path: ['0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', USDC] }
    };
    assert.deepStrictEqual(
      byTarget(run('Execution swaps 1000000000000000000 WETH for minimum 1000000 to self.', txS), 'min-output'),
      ['VERIFIED'], 'verbatim decoded integer verifies despite amountIn prefix');
    assert.deepStrictEqual(
      byTarget(run('The enforced minimum is 3,400 USDC per amountOutMinimum.', {
        contract: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', functionName: 'exactInputSingle',
        parameters: { tokenOut: USDC, amountOutMinimum: (3400n * 10n ** 6n).toString() }
      }), 'min-output'),
      ['VERIFIED'], 'display conversion still works (pinned)');

    // 3. Target/impl mentions are not recipient claims (live record
    // inv_mvv5gka0): proxy target abstains, impl reframing verifies.
    const txT = { contract: PROXY, functionName: 'transfer', parameters: { recipient: USER, amount: '1000' } };
    const cp = run(`Claimed router vs actual target unknown proxy ${PROXY} to unverified impl ${IMPL}: identity unverified.`, txT,
      { proxyResolution: { isProxy: true, implementation: IMPL } });
    const cpByAddr = {};
    for (const c of cp.filter((x) => x.target === 'counterparty')) cpByAddr[c.parsed.address] = c.result;
    assert.strictEqual(cpByAddr[PROXY.toLowerCase()], 'INCONCLUSIVE', 'target mention abstains');
    assert.strictEqual(cpByAddr[IMPL.toLowerCase()], 'VERIFIED', 'impl mention reframed and verified');
    assert.ok(!Object.values(cpByAddr).includes('CONTRADICTED'), 'no false contradiction');
    console.log('✔ B7.5 Passed: Live-precision regressions (negation scope, digit runs, target/impl framing).');
  }

  // ---- B8.1: sender event logs (injected transport) ----
  {
    const { fetchSenderEvents, APPROVAL_TOPIC, TRANSFER_TOPIC, APPROVAL_FOR_ALL_TOPIC } = require('../../src/services/transactionHistory');
    const SENDER = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
    const TOKEN = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const pad = (a) => `0x${'0'.repeat(24)}${a.slice(2).toLowerCase()}`;
    const approval = {
      address: TOKEN, blockNumber: '0x8', logIndex: '0x1', transactionHash: '0xaaa',
      topics: [APPROVAL_TOPIC, pad('0x1111111111111111111111111111111111111111'), pad(SENDER)],
      data: `0x${(500n).toString(16).padStart(64, '0')}`
    };
    const transfer = {
      address: TOKEN, blockNumber: '0x9', logIndex: '0x0', transactionHash: '0xbbb',
      topics: [TRANSFER_TOPIC, pad(SENDER), pad('0x2222222222222222222222222222222222222222')],
      data: `0x${(7n).toString(16).padStart(64, '0')}`
    };
    const nft = {
      address: TOKEN, blockNumber: '0x9', logIndex: '0x2', transactionHash: '0xccc',
      topics: [TRANSFER_TOPIC, pad(SENDER), pad('0x2222222222222222222222222222222222222222'), `0x${(42n).toString(16).padStart(64, '0')}`],
      data: '0x'
    };
    const opAll = {
      address: TOKEN, blockNumber: '0x7', logIndex: '0x0', transactionHash: '0xddd',
      topics: [APPROVAL_FOR_ALL_TOPIC, pad(SENDER), pad('0x3333333333333333333333333333333333333333')],
      data: `0x${(1n).toString(16).padStart(64, '0')}`
    };
    const byTopics = {};
    byTopics[JSON.stringify([APPROVAL_TOPIC, null, pad(SENDER)])] = [approval, approval]; // duplicate across queries
    byTopics[JSON.stringify([TRANSFER_TOPIC, pad(SENDER)])] = [transfer, nft];
    byTopics[JSON.stringify([APPROVAL_FOR_ALL_TOPIC, pad(SENDER)])] = [opAll];
    const fake = async (url, opts) => {
      const calls = JSON.parse(opts.body);
      return {
        ok: true,
        json: async () => calls.map((c) => {
          assert.strictEqual(c.method, 'eth_getLogs');
          assert.strictEqual(c.params[0].fromBlock, '0x0');
          assert.strictEqual(c.params[0].toBlock, '0x9');
          return { jsonrpc: '2.0', id: c.id, result: byTopics[JSON.stringify(c.params[0].topics)] || [] };
        })
      };
    };
    const got = await fetchSenderEvents({ rpcUrl: 'http://rpc.invalid', sender: SENDER, fromBlock: '0x0', toBlock: '0x9', fetchImpl: fake });
    assert.strictEqual(got.status, 'ok');
    assert.strictEqual(got.events.length, 4, 'duplicate log deduped');
    assert.deepStrictEqual(got.events.map((e) => e.event), ['ApprovalForAll', 'Approval', 'Transfer', 'Transfer'], 'ordered by block then logIndex');
    assert.strictEqual(got.events[1].amount, '500');
    assert.strictEqual(got.events[1].spender, SENDER.toLowerCase());
    assert.strictEqual(got.events[3].tokenId, '42', 'NFT transfer carries tokenId, not amount');
    assert.strictEqual(got.events[0].approved, true);
    assert.strictEqual((await fetchSenderEvents({ rpcUrl: null, sender: SENDER })).status, 'unavailable');
    assert.strictEqual((await fetchSenderEvents({ rpcUrl: 'http://x', sender: 'nope' })).status, 'no-sender');
    const dead = await fetchSenderEvents({ rpcUrl: 'http://x', sender: SENDER, fromBlock: '0x0', toBlock: '0x9', fetchImpl: async () => { throw new Error('down'); } });
    assert.strictEqual(dead.status, 'unavailable');
    console.log('✔ B8.1 Passed: Event-log fetch, parse, dedupe, order, failure states.');
  }

  // ---- B8.2: prior-investigation tail reads ----
  {
    const fs = require('fs');
    const path = require('path');
    const { readPriorInvestigations } = require('../../src/services/transactionHistory');
    const SENDER = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
    const file = path.join('test', 'tmp', `cap4-b8-priors-${Date.now()}.jsonl`);
    try {
      const lines = [
        JSON.stringify({ recordId: 'r1', recordedAt: 100, sender: SENDER, chainId: '1', verdict: 'MATCH', decodedTransaction: { contract: '0xaaa', functionName: 'transfer' } }),
        JSON.stringify({ recordId: 'r2', recordedAt: 300, sender: SENDER, chainId: '1', verdict: 'BLOCK', decodedTransaction: { contract: '0xbbb', functionName: 'approve' } }),
        JSON.stringify({ recordId: 'r3', recordedAt: 200, sender: '0x0000000000000000000000000000000000000001', chainId: '1', verdict: 'MATCH' }),
        JSON.stringify({ recordId: 'r4', recordedAt: 400, sender: SENDER, chainId: '137', verdict: 'MATCH' }),
        '{corrupt',
        '',
        JSON.stringify({ recordId: 'r5', recordedAt: 250, verdict: 'MATCH' })
      ];
      fs.writeFileSync(file, `${lines.join('\n')}\n`, 'utf8');
      const got = readPriorInvestigations({ file, sender: SENDER, chainId: '1', limit: 8 });
      assert.strictEqual(got.status, 'ok');
      assert.deepStrictEqual(got.priors.map((p) => p.recordId), ['r2', 'r1'], 'same-sender same-chain newest-first');
      assert.strictEqual(got.skipped, 1, 'corrupt line counted');
      const capped = readPriorInvestigations({ file, sender: SENDER, chainId: '1', limit: 1 });
      assert.deepStrictEqual(capped.priors.map((p) => p.recordId), ['r2']);
      assert.strictEqual(readPriorInvestigations({ file: path.join('test', 'tmp', 'nope-missing.jsonl'), sender: SENDER }).status, 'empty');
      assert.strictEqual(readPriorInvestigations({ file: null, sender: SENDER }).status, 'unavailable');
    } finally {
      try { fs.unlinkSync(file); } catch { /* scratch cleanup */ }
    }
    console.log('✔ B8.2 Passed: Prior lookup filters, orders, bounds, counts corruption.');
  }

  // ---- B8.3: sequence context + relationships + approval finding ----
  {
    const { buildSequenceContext } = require('../../src/services/transactionHistory');
    const SENDER = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
    const OWNER = '0x1111111111111111111111111111111111111111';
    const TOKEN = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
    const approvalEvent = {
      token: TOKEN, blockNumber: '0x8', logIndex: '0x0', txHash: '0xaaa',
      event: 'Approval', owner: OWNER.toLowerCase(), spender: SENDER.toLowerCase(), amount: '500', nft: false
    };
    const decodedTx = {
      contract: TOKEN, functionName: 'transferFrom', standard: 'ERC20',
      parameters: { sender: OWNER, recipient: SENDER, amount: '100' }
    };
    const seq = buildSequenceContext({
      decodedTx, sender: SENDER, chainId: '1',
      senderEvents: { status: 'ok', events: [approvalEvent], truncated: 0 },
      priors: { status: 'ok', priors: [{ recordId: 'r9', recordedAt: 50, verdict: 'MATCH', decodedTransaction: { contract: TOKEN, functionName: 'transferFrom' } }], skipped: 0 },
      admittedPriors: [{ evidenceId: 'X-001', content: 'agent says prior swap succeeded' }],
      maxEntries: 8
    });
    assert.deepStrictEqual(seq.entries.map((e) => e.historyId), ['H-001', 'H-002', 'H-003'], 'stable H-xxx IDs');
    assert.strictEqual(seq.entries[2].trust, 'UNTRUSTED', 'agent priors never laundered');
    const rel = seq.relationships.find((r) => r.type === 'APPROVAL_THEN_SPEND');
    assert.ok(rel && rel.entryIds.includes('H-001'), 'enabling approval linked');
    assert.ok(seq.relationships.some((r) => r.type === 'REPEATED_INTERACTION'), 'repeat detected');
    const f = seq.findings.find((x) => x.ruleId === 'APPROVAL_THEN_SPEND');
    assert.ok(f, 'informational approval finding emitted');
    assert.strictEqual(f.severity, 'LOW');
    assert.strictEqual(f.metadata.historyId, 'H-001');
    // No enabling approval: observed absence, never a flag.
    const bare = buildSequenceContext({
      decodedTx, sender: SENDER, chainId: '1',
      senderEvents: { status: 'ok', events: [], truncated: 0 },
      priors: { status: 'empty', priors: [] }, admittedPriors: [], maxEntries: 8
    });
    assert.strictEqual(bare.findings.length, 0);
    assert.strictEqual(bare.relationships.length, 0);
    // Entry cap truncates with counts.
    const many = buildSequenceContext({
      decodedTx, sender: SENDER, chainId: '1',
      senderEvents: { status: 'ok', events: [approvalEvent, approvalEvent, approvalEvent], truncated: 0 },
      priors: { status: 'ok', priors: [] }, admittedPriors: [], maxEntries: 2
    });
    assert.strictEqual(many.entries.length, 2);
    assert.strictEqual(many.truncated, 1);
    console.log('✔ B8.3 Passed: APPROVAL_THEN_SPEND + repeats + UNTRUSTED priors + caps.');
  }

  // ---- B8.4: S8 prompt + pack block + registry + controller ----
  {
    assert.ok(SHARED_SEMANTIC_RULES.includes('S8. Sequence context'));
    const { buildEvidenceRegistry, classifyRef } = require('../../src/services/reasoningValidation');
    const reg = buildEvidenceRegistry({ pageContext: {}, decodedTx: { parameters: {} }, visualMeta: {}, extra: {} });
    assert.strictEqual(classifyRef('history', reg), 'ok');
    const history = {
      entries: [
        { historyId: 'H-001', kind: 'chain-event', provenance: 'chain-logs', summary: 'Approval on 0xtoken: amount=500 @0x8' },
        { historyId: 'H-002', kind: 'agent-prior', provenance: 'agent-submitted', trust: 'UNTRUSTED', summary: 'agent prior [X-001]: ...' }
      ],
      entryCount: 2, truncated: 0,
      relationships: [{ type: 'APPROVAL_THEN_SPEND', entryIds: ['H-001'], explanation: 'enabling approval' }],
      findings: [], sources: {}
    };
    const text = packEvidence({
      visualText: '', pageContext: { title: 't', url: 'https://w.example' },
      decodedTx: { contract: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', functionName: 'transferFrom', standard: 'ERC20', parameters: {}, ruleFindings: [] },
      visualMeta: {}, extra: { history }
    }).sectionTexts.find((s) => s.name === 'tx').text;
    assert.ok(text.includes('Transaction History') && text.includes('[H-001]') && text.includes('APPROVAL_THEN_SPEND'));
    assert.ok(text.includes('[UNTRUSTED]'), 'agent prior trust preserved in prompt');

    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-key';
    const realFetch = global.fetch;
    global.fetch = mockModelFetch('MATCH');
    try {
      const { done, res } = evalResponseCollector();
      await handleEvaluateTransaction(evalRequest({
        from: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
        to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
        data: '0x23b872dd000000000000000000000000111111111111111111111111111111111111111100000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000000000000000064',
        value: '0x0', chainId: '0x1'
      }), res, {
        proxyResolution: { target: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', status: 'not-proxy', isProxy: false, explanation: 'direct' },
        sequenceHistory: {
          entries: history.entries, entryCount: 2, truncated: 0, relationships: history.relationships,
          findings: [{ ruleId: 'APPROVAL_THEN_SPEND', severity: 'LOW', description: 'spend via prior approval', triggered: true, metadata: { historyId: 'H-001' } }],
          sources: {}
        }
      });
      const out = await done;
      assert.strictEqual(out.status, 200);
      assert.ok((out.body.ruleFindings || []).some((f) => f.ruleId === 'APPROVAL_THEN_SPEND'), 'sequence finding reaches bundle');
      assert.strictEqual(out.body.sequenceHistory.entryCount, 2);
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ B8.4 Passed: S8 + history pack + token + injected history end to end.');
  }

  // ---- B9.1: investigation-record classification (8 classes) ----
  {
    const { classifyInvestigationRecord } = require('../../src/services/investigationStore');
    const full = { conclusions: [{ statement: 'rich genuine conclusion with cited evidence' }] };
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'model', modelId: 'muse-spark-1.3', summary: 'Real prose summary.', investigation: full }), 'genuine-complete');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'model', modelId: 'muse-spark-1.3', investigation: null }), 'null-investigation');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'model', modelId: 'muse-spark-1.3', summary: 'x', investigation: { conclusions: [] } }), 'empty-conclusions');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'heuristic', investigation: full }), 'non-model');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'mock', summary: 'canned', investigation: full }), 'test-fixture', 'canned flag wins over origin');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'model', modelId: 'mock-serving-model', summary: 'canned [x]', investigation: full }), 'test-fixture');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'model', modelId: 'mock-m', summary: 'plausible prose', investigation: full }), 'mock-model', 'mock serving id caught even with plausible text');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'model', modelId: null, summary: 'plausible prose', investigation: full }), 'unverified-model-id', 'no serving id, no genuine claim');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'model', summary: 's [truncated mock]', investigation: full }), 'test-fixture');
    assert.strictEqual(classifyInvestigationRecord(null), 'corrupt');
    assert.strictEqual(classifyInvestigationRecord('nope'), 'corrupt');
    assert.strictEqual(classifyInvestigationRecord({ reasoningOrigin: 'model', modelId: 'spark-x', summary: 'x', investigation: 'flat' }), 'test-fixture');
    console.log('✔ B9.1 Passed: Record classifier separates genuine, mock, canned, null, and unverifiable.');
  }

  // ---- B9.2: quarantine dry-run / apply / idempotency / preservation ----
  {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const { quarantineInvestigations } = require('../../src/services/investigationStore');
    const dir = fs.mkdtempSync(path.join('test', 'tmp', 'cap4-b9q-'));
    const file = path.join(dir, 'inv.jsonl');
    const qfile = path.join(dir, 'q.jsonl');
    const full = { conclusions: [{ statement: 'genuine live reasoning' }] };
    const rows = [
      { recordId: 'g1', reasoningOrigin: 'model', modelId: 'muse-spark-1.3', summary: 'Live prose.', investigation: full },
      { recordId: 'n1', reasoningOrigin: 'model', modelId: 'muse-spark-1.3', investigation: null },
      { recordId: 'f1', reasoningOrigin: 'mock', summary: 'canned', investigation: full },
      'NOT-JSON{{{',
      { recordId: 'h1', reasoningOrigin: 'heuristic', summary: 'fallback', investigation: full }
    ];
    fs.writeFileSync(file, `${rows.map((r) => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n')}\n`, 'utf8');
    const dry = quarantineInvestigations({ file, quarantineFile: qfile });
    assert.strictEqual(dry.ok, true);
    assert.strictEqual(dry.total, 4, 'corrupt line skipped, not counted');
    assert.strictEqual(dry.counts['genuine-complete'], 1);
    assert.strictEqual(dry.counts['null-investigation'], 1);
    assert.strictEqual(dry.counts['test-fixture'], 1);
    assert.strictEqual(dry.counts['non-model'], 1);
    assert.strictEqual(dry.counts.corrupt, 1);
    assert.strictEqual(dry.moved, 3);
    assert.strictEqual(dry.applied, false);
    assert.strictEqual(fs.existsSync(qfile), false, 'dry run moves nothing');
    const applied = quarantineInvestigations({ file, quarantineFile: qfile, apply: true });
    assert.strictEqual(applied.applied, true);
    assert.strictEqual(applied.moved, 3);
    const kept = fs.readFileSync(file, 'utf8').trim().split('\n');
    assert.strictEqual(kept.length, 1);
    assert.strictEqual(JSON.parse(kept[0]).recordId, 'g1');
    const moved = fs.readFileSync(qfile, 'utf8').trim().split('\n');
    assert.strictEqual(moved.length, 3, 'nothing deleted: every moved record preserved with reason');
    const reasons = moved.map((l) => JSON.parse(l).reason).sort();
    assert.deepStrictEqual(reasons, ['non-model', 'null-investigation', 'test-fixture']);
    assert.ok(moved.every((l) => typeof JSON.parse(l).quarantinedAt === 'number'));
    const again = quarantineInvestigations({ file, quarantineFile: qfile, apply: true });
    assert.strictEqual(again.moved, 0, 'idempotent: second run moves nothing');
    assert.strictEqual(fs.readFileSync(qfile, 'utf8').trim().split('\n').length, 3, 'no duplicate quarantine appends');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ B9.2 Passed: Quarantine dry-run counts, apply preserves with reasons, idempotent.');
  }

  // ---- B9.3: genuine-only review selection ----
  {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const { persistInvestigation, listInvestigations } = require('../../src/services/investigationStore');
    const dir = fs.mkdtempSync(path.join('test', 'tmp', 'cap4-b9s-'));
    const file = path.join(dir, 'inv.jsonl');
    const full = { conclusions: [{ statement: 'genuine live reasoning' }] };
    persistInvestigation({ verdict: 'MATCH', reasoningOrigin: 'model', modelId: 'muse-spark-1.3', summary: 'Live prose.', investigation: full }, file);
    persistInvestigation({ verdict: 'MATCH', reasoningOrigin: 'mock', summary: 'canned', investigation: full }, file);
    persistInvestigation({ verdict: 'UNCERTAIN', reasoningOrigin: 'model', modelId: 'muse-spark-1.3', investigation: null }, file);
    const all = listInvestigations({ file, limit: 50 });
    assert.strictEqual(all.items.length, 3);
    const genuine = listInvestigations({ file, limit: 50, genuineOnly: true });
    assert.strictEqual(genuine.items.length, 1, 'review selection sees genuine live only');
    assert.strictEqual(genuine.items[0].reasoningOrigin, 'model');
    fs.rmSync(dir, { recursive: true, force: true });
    console.log('✔ B9.3 Passed: genuineOnly filter restricts qualitative review to genuine live records.');
  }

  // ---- B9.4: deterministic suite needs no API keys; external lookups fail safe ----
  {
    const savedFour = process.env.FOURBYTE_API_KEY;
    const savedSour = process.env.SOURCIFY_API_KEY;
    const savedSpark = process.env.MUSE_SPARK_API_KEY;
    delete process.env.FOURBYTE_API_KEY;
    delete process.env.SOURCIFY_API_KEY;
    delete process.env.MUSE_SPARK_API_KEY;
    try {
      const ident = require('../../src/services/contractIdentity');
      const r4 = await ident.lookupSelectorSignature('0xa9059cbb', { fetchImpl: async () => { throw new Error('no network in unit test'); } });
      assert.strictEqual(r4.status, 'unavailable', 'unreachable 4byte is unavailable, never a hint');
      const rs = await ident.lookupSourceVerification('0x' + '1'.repeat(40), 1, { fetchImpl: async () => { throw new Error('no network in unit test'); } });
      assert.strictEqual(rs.status, 'unavailable', 'unreachable Sourcify is unavailable, never a match');
      const id = await ident.resolveContractIdentity({ address: `0x${'2'.repeat(40)}`, chainId: 1 });
      assert.ok(id && id.verificationStatus !== 'source-verified' && id.verificationStatus !== 'bytecode-matched',
        `offline identity stays honest (got ${id && id.verificationStatus})`);
    } finally {
      if (savedFour !== undefined) process.env.FOURBYTE_API_KEY = savedFour;
      if (savedSour !== undefined) process.env.SOURCIFY_API_KEY = savedSour;
      if (savedSpark !== undefined) process.env.MUSE_SPARK_API_KEY = savedSpark;
    }
    console.log('✔ B9.4 Passed: No-key/offline external lookups fail safe; deterministic suite key-independent.');
  }

  // ---- B10.1: action-element triples (container + links + verb check) ----
  {
    const { buildActionElements } = require('../../src/utils/visualRoles');
    const R = (regionId, text, box) => ({ regionId, boundingBox: box, ocr: { text, empty: false, error: null } });
    const dialog = { x: 0, y: 0, width: 800, height: 600 };
    const regions = [
      R('R-001', 'Confirm transaction', dialog),
      R('R-002', 'Swap', { x: 300, y: 400, width: 200, height: 60 }),
      R('R-003', '1 ETH', { x: 300, y: 300, width: 200, height: 40 }),
      R('R-004', '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', { x: 300, y: 200, width: 200, height: 40 })
    ];
    const links = [{
      linkId: 'L-001', kind: 'action-context', method: 'shared-container',
      members: [
        { regionId: 'R-002', role: 'action', text: 'Swap' },
        { regionId: 'R-003', role: 'amount', text: '1 ETH' },
        { regionId: 'R-004', role: 'recipient', text: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' }
      ]
    }];
    const els = buildActionElements({ regions, associations: { links }, decodedTx: { functionName: 'exactInputSingle' } });
    assert.strictEqual(els.elements.length, 1);
    const el = els.elements[0];
    assert.strictEqual(el.elementId, 'AE-001');
    assert.strictEqual(el.container.regionId, 'R-001', 'smallest observed container attributed');
    assert.ok(el.linkedRoles.includes('amount') && el.linkedRoles.includes('recipient'));
    assert.strictEqual(el.verbConsistent, true, "'Swap' over exactInputSingle is consistent");

    const misleading = buildActionElements({ regions, associations: { links }, decodedTx: { functionName: 'approve' } });
    assert.strictEqual(misleading.elements[0].verbConsistent, false, "'Swap' over approve is a verb mismatch");
    assert.ok(misleading.elements[0].consistencyNote.includes('approve'));

    const batch = buildActionElements({ regions, associations: { links }, decodedTx: { functionName: 'multicall' } });
    assert.strictEqual(batch.elements[0].verbConsistent, null, 'batch wrapper is unassessable, never forced');
    assert.ok(batch.elements[0].consistencyNote.includes('batch'));

    const lone = buildActionElements({
      regions: [R('R-009', 'Send', { x: 10, y: 10, width: 100, height: 40 })],
      associations: { links: [] }, decodedTx: { functionName: 'transfer' }
    });
    assert.strictEqual(lone.elements[0].container, null, 'no container invented when none observed');
    assert.strictEqual(lone.elements[0].verbConsistent, true);

    const none = buildActionElements({
      regions: [R('R-010', 'Balance 5 ETH', { x: 0, y: 0, width: 100, height: 40 })],
      associations: { links: [] }, decodedTx: { functionName: 'transfer' }
    });
    assert.strictEqual(none.elements.length, 0, 'no action text, no elements');
    console.log('✔ B10.1 Passed: Action triples with container attribution + honest verb consistency.');
  }

  // ---- B10.2: finding-element naming (strict, bounded) ----
  {
    const { findNamedElements } = require('../../src/utils/visualRoles');
    const SPENDER = '0xABCD1234ABCD1234ABCD1234ABCD1234ABCD1234';
    const tx = { functionName: 'approve', parameters: { spender: SPENDER, amount: '1000000000000000000' } };
    const appr = [{ ruleId: 'INFINITE_APPROVAL', severity: 'HIGH' }];
    const full = findNamedElements(`Setting approval for ${SPENDER} now`, { decodedTx: tx, findings: appr });
    assert.ok(full.some((e) => e.kind === 'address'), 'full decoded counterparty named');
    const frag = findNamedElements('Setting approval for 0xABCD1234ABCD to move funds', { decodedTx: tx, findings: appr });
    assert.ok(frag.some((e) => e.kind === 'address-fragment' && e.resolvesTo === SPENDER.toLowerCase()), 'long fragment resolves to decoded address');
    const short = findNamedElements('Setting approval for 0xAB12 to move funds', { decodedTx: tx, findings: appr });
    assert.ok(!short.some((e) => e.kind === 'address-fragment'), 'short fragments never resolve (noise guard)');
    const stranger = findNamedElements('Send to 0x9999999999999999999999999999999999999999 now', { decodedTx: tx, findings: appr });
    assert.ok(!stranger.some((e) => e.kind === 'address'), 'undecoded address is not a finding element');
    const digits = findNamedElements('Amount 1000000000000000000 wei approved', { decodedTx: tx, findings: appr });
    assert.ok(digits.some((e) => e.kind === 'amount-digits'), 'exact decoded digit run named');
    const tiny = findNamedElements('Amount 100 wei approved', { decodedTx: tx, findings: appr });
    assert.ok(!tiny.some((e) => e.kind === 'amount-digits'), 'short digit runs never match amounts');
    const limit = findNamedElements('Grants the operator max access to your balance', { decodedTx: tx, findings: appr });
    assert.ok(limit.some((e) => e.kind === 'limit-word'), 'limit word names the approval element');
    const noFinding = findNamedElements('Grants the operator max access to your balance', { decodedTx: tx, findings: [] });
    assert.ok(!noFinding.some((e) => e.kind === 'limit-word'), 'limit word needs a standing approval finding');
    assert.deepStrictEqual(findNamedElements('', { decodedTx: tx, findings: appr }), []);
    assert.deepStrictEqual(findNamedElements(null, { decodedTx: tx, findings: appr }), []);
    console.log('✔ B10.2 Passed: Element naming is strict (addresses, fragments, digits, limit words).');
  }

  // ---- B10.3: model-role cross-check (keyword-free verify, strict refute) ----
  {
    const { crossCheckVisualRoles } = require('../../src/utils/visualRoles');
    const SPENDER = '0xABCD1234ABCD1234ABCD1234ABCD1234ABCD1234';
    const tx = { functionName: 'approve', parameters: { spender: SPENDER, amount: '1000000000000000000' } };
    const findings = [{ ruleId: 'INFINITE_APPROVAL', severity: 'HIGH' }];
    // Paraphrased disclosure with NO fixed-warning-keyword: verifies via
    // the finding's own elements (address fragment + limit word).
    const paraphrase = 'Setting approval for 0xABCD1234ABCD to move funds up to max';
    assert.ok(!/\b(warning|warn|risk|risky|caution|careful|danger|suspicious|alert|phishing|scam)\b/i.test(paraphrase),
      'fixture truly keyword-free');
    const res = crossCheckVisualRoles({
      grounding: {
        status: 'evaluated',
        claims: [
          { index: 0, type: 'warning', value: 'Disclosure of broad token access', status: 'supported', regionIds: ['R-001'], observed: [{ text: paraphrase }] },
          { index: 1, type: 'amount', value: 'Send 5 ETH to 0x9999999999999999999999999999999999999999', status: 'supported', regionIds: ['R-002'], observed: [{ text: 'Send 1 ETH' }] },
          { index: 2, type: 'warning', value: 'Be careful', status: 'supported', regionIds: ['R-003'], observed: [{ text: 'Be careful out there' }] },
          { index: 3, type: 'warning', value: 'Something', status: 'unsupported', regionIds: ['R-004'], observed: [] }
        ]
      },
      ruleFindings: findings, decodedTx: tx
    });
    const byIdx = (i) => res.checks.find((c) => c.claimIndex === i);
    assert.strictEqual(byIdx(0).result, 'VERIFIED', 'keyword-free paraphrase verifies via named elements');
    assert.ok(byIdx(0).namedElements.includes('address-fragment') && byIdx(0).namedElements.includes('limit-word'));
    assert.strictEqual(byIdx(1).result, 'REFUTED', 'phantom address/digits refute');
    assert.strictEqual(byIdx(2).result, 'INCONCLUSIVE', 'generic wording is unverified, not contradicted');
    assert.strictEqual(byIdx(3).result, 'INCONCLUSIVE', 'unobserved claims stay inconclusive');
    assert.strictEqual(res.summary.downgrade, true, 'one refutation arms the safeguard');
    const clean = crossCheckVisualRoles({ grounding: { status: 'not-evaluated', claims: [] }, ruleFindings: [], decodedTx: {} });
    assert.strictEqual(clean.summary.downgrade, false, 'agent path (no claims) never arms');
    console.log('✔ B10.3 Passed: Roles verify keyword-free, refute strictly, abstain otherwise.');
  }

  // ---- B10.4: warning disclosure specificity (§9 tier, verdict pinned) ----
  {
    const { compareIntentToTx } = require('../../src/utils/intentComparison');
    const SPENDER = '0xABCD1234ABCD1234ABCD1234ABCD1234ABCD1234';
    const region = (regionId, text) => ({ regionId, genuine: true, synthetic: false, ocr: { text, empty: text.length === 0, error: null } });
    const claim = (type, value, regionIds) => ({ type, value, regionIds, associationIds: [], status: 'supported' });
    const fieldOf = (res, field) => res.fields.find((f) => f.field === field);
    const facts = {
      contract: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', functionName: 'approve',
      parameters: { spender: SPENDER, amount: (1n << 256n) - 1n },
      ruleFindings: [{ ruleId: 'INFINITE_APPROVAL', severity: 'HIGH' }]
    };
    const specificText = `Warning: grants ${SPENDER} unlimited access to move your tokens`;
    const specific = compareIntentToTx(
      { regions: [region('R-001', specificText)], claims: [claim('warning', specificText, ['R-001'])] },
      facts
    );
    const sField = fieldOf(specific, 'warning');
    assert.strictEqual(sField.status, 'MATCH', 'class naming still MATCHes (pinned)');
    assert.strictEqual(sField.specificity, 'specific', 'address + limit word = specific disclosure');
    assert.ok(sField.namedElements.includes('address') && sField.namedElements.includes('limit-word'));

    const genericText = 'Warning: this transaction is risky, proceed with caution';
    const generic = compareIntentToTx(
      { regions: [region('R-001', genericText)], claims: [claim('warning', genericText, ['R-001'])] },
      { ...facts, ruleFindings: [{ ruleId: 'UNVERIFIED_SPENDER', severity: 'HIGH' }] }
    );
    const gField = fieldOf(generic, 'warning');
    assert.strictEqual(gField.status, 'MATCH', 'generic class wording still MATCHes (pinned)');
    assert.strictEqual(gField.specificity, 'generic', 'no concrete element = generic disclosure');
    console.log('✔ B10.4 Passed: Disclosure specificity tiers without moving pinned verdicts.');
  }

  // ---- B10.5: pack + prompt + registry + graph + stage 15 ----
  {
    const { selectSystemPrompt } = require('../../src/services/reasoningPrompts');
    const { buildEvidenceRegistry, classifyRef } = require('../../src/services/reasoningValidation');
    const { buildDeterministicEdges } = require('../../src/services/evidenceGraph');
    assert.ok(selectSystemPrompt('browser').text.includes('S9.'), 'S9 visual-roles rule in browser prompt');
    assert.ok(selectSystemPrompt('agent').text.includes('S9.'), 'S9 visual-roles rule in agent prompt');

    const elements = [{
      elementId: 'AE-001', actionRegionId: 'R-002', actionText: 'Swap', verb: 'swap',
      container: { regionId: 'R-001', areaRatio: 40 }, linkedAmounts: ['1 ETH'], linkedRecipients: [],
      decodedFunction: 'approve', verbConsistent: false, consistencyNote: "display verb 'swap' names swap but the transaction is approve"
    }];
    const pageText = packEvidence({
      visualText: '', pageContext: { title: 't', url: 'https://w.example' },
      decodedTx: { contract: '0x1', functionName: 'approve', parameters: {}, ruleFindings: [] },
      visualMeta: {}, extra: { visualElements: { elements, capped: false } }
    }).sectionTexts.find((s) => s.name === 'page').text;
    assert.ok(pageText.includes('[AE-001]') && pageText.includes('VERB MISMATCH'), 'action block reaches the model prompt');

    const reg = buildEvidenceRegistry({ pageContext: {}, decodedTx: {}, visualMeta: {}, extra: { visualElements: { elements } } });
    assert.strictEqual(classifyRef('AE-001', reg), 'ok', 'printed AE id resolves');
    assert.strictEqual(classifyRef('visualRoles', reg), 'ok', 'visualRoles section resolves');
    const bare = buildEvidenceRegistry({ pageContext: {}, decodedTx: {}, visualMeta: {}, extra: {} });
    assert.strictEqual(classifyRef('AE-001', bare), 'fabricated', 'unprinted AE id stays fabricated');

    const edges = buildDeterministicEdges({ actionElements: { elements } });
    assert.ok(edges.some((e) => e.type === 'ASSOCIATED_WITH' && e.from === 'AE-001' && e.to === 'R-001'), 'element-container edge');
    assert.ok(edges.some((e) => e.type === 'CONTRADICTS' && e.from === 'AE-001' && e.to === 'tx'), 'verb-mismatch contradiction edge');

    const bad = applyVerdictSafeguards({ ruleFindings: [] }, {
      verdict: 'MATCH', confidence: 0.9, summary: 's',
      visualRoleChecks: { checks: [{ claimIndex: 0, claimType: 'amount', result: 'REFUTED' }], summary: { downgrade: true } }
    });
    assert.strictEqual(bad.reasoningResult.verdict, 'UNCERTAIN', 'stage 15 downgrades refuted roles');
    assert.ok(bad.safeguards.some((s) => s.trigger === 'REFUTED_VISUAL_ROLE'));
    const good = applyVerdictSafeguards({ ruleFindings: [] }, {
      verdict: 'MATCH', confidence: 0.9, summary: 's',
      visualRoleChecks: { checks: [], summary: { checked: 0, VERIFIED: 0, REFUTED: 0, INCONCLUSIVE: 0, downgrade: false } }
    });
    assert.strictEqual(good.reasoningResult.verdict, 'MATCH', 'clean roles stand');
    console.log('✔ B10.5 Passed: S9 + AE pack/registry/graph + stage-15 safeguard end to end.');
  }

  console.log('\nAll Capability-4 B1–B10 Tests Passed Successfully!\n');
}

run().catch((err) => { console.error(err); process.exit(1); });
