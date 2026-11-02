const assert = require('assert');
const appConfig = require('../../src/config/env');
const { handleEvaluateTransaction } = require('../../src/controllers/evaluateController');
const { evaluateSemanticDiscrepancy, fallbackHeuristicReasoner, validateModelResult } = require('../../src/services/reasonerService');
const {
  PROMPT_VERSION, INVESTIGATION_TYPES, METHODOLOGY_STAGES, SCHEMA_SPEC,
  buildSystemPrompt, selectSystemPrompt
} = require('../../src/services/reasoningPrompts');
const { buildEvidenceRegistry, classifyRef, validateInvestigation } = require('../../src/services/reasoningValidation');
const { composePolicyDecision } = require('../../src/services/policyDecision');

// Capability 2 unit suite. Model TRANSPORT is mocked throughout (clearly
// labeled); live reasoning behavior is covered by test/live/sparkBehavior.

function validInvestigation(overrides = {}) {
  return {
    objective: 'obj',
    evidenceInventory: [{ key: 'tx', tier: 'VERIFIED', available: true }],
    sourceAssessments: [{ source: 'decoder', reliability: 'high', note: 'n' }],
    intentInterpretation: { statement: 'i', basisRefs: ['dom'], kind: 'inferred' },
    executionAnalysis: { statement: 'e', basisRefs: ['tx'] },
    parameterAnalysis: { statement: 'p', basisRefs: ['params'] },
    discrepancies: [],
    contradictions: [],
    competingExplanations: [{ explanation: 'alt', plausibility: 'possible', supportingRefs: ['tx'], contradictingRefs: [] }],
    suspiciousBehaviours: [],
    missingEvidence: [],
    uncertainty: { level: 'low', explanation: 'u' },
    conclusions: [{ statement: 'c', supportingRefs: ['tx'], contradictingRefs: [] }],
    recommendations: [{ action: 'a', rationale: 'r', basisRefs: ['tx'] }],
    furtherInvestigation: [],
    ...overrides
  };
}

function cannedModel(overrides = {}) {
  return {
    verdict: 'MATCH', confidence: 0.9, summary: 'canned',
    discrepancyDetails: { visualIntent: 'v', actualExecution: 'e', criticalMismatch: false },
    recommendedAction: 'PROCEED_WITH_CAUTION',
    investigation: validInvestigation(),
    ...overrides
  };
}

async function runController(body, internal, modelJson) {
  const origKey = appConfig.modelApiKey;
  appConfig.modelApiKey = 'test-live-key';
  const realFetch = global.fetch;
  let captured = null;
  global.fetch = async (url, opts) => {
    captured = JSON.parse(opts.body);
    return { ok: true, json: async () => ({ model: 'mock-serving-model', usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 }, choices: [{ message: { content: JSON.stringify(modelJson) } }] }) };
  };
  try {
    let resolve;
    const done = new Promise((r) => { resolve = r; });
    const req = { body };
    const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(p) { resolve({ status: this.statusCode, body: p }); } };
    await handleEvaluateTransaction(req, res, internal);
    const out = await done;
    return { out, captured };
  } finally {
    global.fetch = realFetch;
    appConfig.modelApiKey = origKey;
  }
}

const CLEAN_TX = {
  pageContext: { title: 't', url: 'https://w.example' },
  transaction: { from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', data: '0x', value: '0x1', chainId: '0x7a69' }
};

async function runReasoningArchitectureTests() {
  console.log('Testing reasoning architecture (prompts + validation + consumption)...\n');

  // 1-3: versioned prompt selection + methodology + schema coverage.
  assert.strictEqual(PROMPT_VERSION, 'investigate-2.7');
  assert.deepStrictEqual([...INVESTIGATION_TYPES].sort(), ['agent', 'browser']);
  assert.strictEqual(selectSystemPrompt().investigationType, 'browser');
  assert.strictEqual(selectSystemPrompt('agent').investigationType, 'agent');
  assert.throws(() => selectSystemPrompt('sms'), TypeError);
  const browser = buildSystemPrompt('browser').text;
  const agent = buildSystemPrompt('agent').text;
  assert.ok(browser.includes('Visual Sentry') && browser.includes('B1.') && !browser.includes('A1.'), 'browser prompt carries B-rules');
  assert.ok(agent.includes('Agent Investigator') && agent.includes('A1.') && agent.includes('NEVER visual evidence'), 'agent prompt carries A-rules');
  for (const t of ['[VERIFIED]', '[DETERMINISTIC]', '[RETRIEVED]', '[OBSERVED]', '[UNTRUSTED]', '[SYNTHETIC]', '[HINT]']) {
    assert.ok(browser.includes(t) && agent.includes(t), `shared tier rule ${t} in both prompts`);
  }
  assert.ok(browser.includes('ADVISORY RULE') && agent.includes('ADVISORY RULE'), 'advisory rule shared by both prompts');
  assert.ok(browser.includes('NEVER recommend PROCEED_WITH_CAUTION while findings stand'), 'advisory rule pins hold advice');
  assert.strictEqual(METHODOLOGY_STAGES.length, 15, 'fifteen methodology stages');
  for (const s of METHODOLOGY_STAGES) {
    assert.ok(browser.includes(`${s.id}:`) && agent.includes(`${s.id}:`), `stage instructed: ${s.id}`);
    assert.ok(s.field.startsWith('investigation.'), `stage maps to output: ${s.id}`);
  }
  for (const f of ['evidenceInventory', 'sourceAssessments', 'intentInterpretation', 'executionAnalysis', 'parameterAnalysis', 'discrepancies', 'contradictions', 'competingExplanations', 'suspiciousBehaviours', 'missingEvidence', 'uncertainty', 'conclusions', 'recommendations', 'furtherInvestigation']) {
    assert.ok(SCHEMA_SPEC.includes(f), `schema captures: ${f}`);
  }
  console.log('✔ Tests 1-3 Passed: Versioned browser/agent prompts, 15 stages, full schema.');

  // 4-6: registry + ref classification + investigation validation.
  const reg = buildEvidenceRegistry({
    decodedTx: { ruleFindings: [{ ruleId: 'R1' }], parameters: { spender: '0x1' } },
    visualMeta: { regionTexts: [{ regionId: 'R-001' }, { regionId: 'R-FALLBACK', synthetic: true }] }
  });
  assert.deepStrictEqual(reg.regions, ['R-001']);
  assert.deepStrictEqual(reg.findings, ['R1']);
  assert.ok(reg.sections.includes('chain') && reg.params.includes('spender'));
  assert.strictEqual(classifyRef('R-001', reg), 'ok');
  assert.strictEqual(classifyRef('R1', reg), 'ok');
  assert.strictEqual(classifyRef('chain', reg), 'ok');
  assert.strictEqual(classifyRef('param:spender', reg), 'ok');
  assert.strictEqual(classifyRef('R-FALLBACK', reg), 'synthetic');
  assert.strictEqual(classifyRef('R-999', reg), 'fabricated');
  assert.strictEqual(classifyRef('param:nope', reg), 'fabricated');
  assert.strictEqual(classifyRef(42, reg), 'malformed');
  assert.strictEqual(classifyRef('pageTitle', reg), 'ok', 'closed alias map canonicalizes');
  assert.strictEqual(classifyRef('txDecoding', reg), 'ok');
  assert.strictEqual(classifyRef('securityRules', reg), 'ok');
  assert.strictEqual(classifyRef('findings', reg), 'ok', 'findings section key registered');
  const aliased = validateInvestigation(validInvestigation({ conclusions: [{ statement: 'c', supportingRefs: ['pageTitle'], contradictingRefs: [] }] }), reg);
  assert.strictEqual(aliased.ok, true);
  assert.deepStrictEqual(aliased.normalized, [{ where: 'conclusions[0].supportingRefs[0]', from: 'pageTitle', to: 'title' }], 'normalization recorded');
  const good = validateInvestigation(validInvestigation(), reg);
  assert.strictEqual(good.ok, true, JSON.stringify(good));
  const fab = validateInvestigation(validInvestigation({ conclusions: [{ statement: 'c', supportingRefs: ['R-999'], contradictingRefs: [] }] }), reg);
  assert.strictEqual(fab.ok, false);
  assert.strictEqual(fab.fabricated.length, 1);
  const unsup = validateInvestigation(validInvestigation({ conclusions: [{ statement: 'c', supportingRefs: [], contradictingRefs: [] }] }), reg);
  assert.strictEqual(unsup.ok, true, 'missing citations flag, not fabrication');
  assert.deepStrictEqual(unsup.unsupportedConclusions, [0]);
  const bad = validateInvestigation({ objective: 42 }, reg);
  assert.strictEqual(bad.ok, false);
  assert.ok(bad.shapeErrors.length > 3, 'shape errors enumerated');
  console.log('✔ Tests 4-6 Passed: Registry, ref classification, grounding validation.');

  // 7: reasoner outbound carries versioned prompt + token bound (MOCKED transport).
  {
    const origKey = appConfig.modelApiKey;
    appConfig.modelApiKey = 'test-live-key';
    const realFetch = global.fetch;
    let captured = null;
    global.fetch = async (url, opts) => {
      captured = JSON.parse(opts.body);
      return { ok: true, json: async () => ({ model: 'serving-x', usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 }, choices: [{ message: { content: JSON.stringify(cannedModel()) } }] }) };
    };
    try {
      const res = await evaluateSemanticDiscrepancy('', { title: 't', url: 'u' }, { contract: 'c', functionName: 'f', parameters: {}, ruleFindings: [] }, {}, {}, { investigationType: 'agent' });
      assert.ok(captured.messages[0].content.includes('Agent Investigator'), 'agent system prompt sent');
      assert.strictEqual(captured.temperature, 0);
      assert.strictEqual(captured.max_tokens, 24000);
      assert.strictEqual(res.origin, 'model');
      assert.strictEqual(res.modelId, 'serving-x', 'serving model recorded');
      assert.ok(Number.isInteger(res.latencyMs), 'latency recorded');
      assert.deepStrictEqual(res.usage, { promptTokens: 1, completionTokens: 2, totalTokens: 3 });
      assert.strictEqual(res.promptVersion, 'investigate-2.7');
      assert.strictEqual(res.investigationType, 'agent');
      assert.ok(res.contextEstimate.estInputTokens > 0 && res.contextEstimate.maxOutputTokens === 24000);
      assert.strictEqual(res.referenceValidation.ok, true);
    } finally {
      global.fetch = realFetch;
      appConfig.modelApiKey = origKey;
    }
    console.log('✔ Test 7 Passed: Outbound versioned/bounded; observability recorded.');
  }

  // 8: discrepancyDetails now preserved in the bundle (MOCKED transport).
  {
    const { out } = await runController(CLEAN_TX, undefined, cannedModel({
      discrepancyDetails: { visualIntent: 'v-intent', actualExecution: 'x-exec', criticalMismatch: false }
    }));
    assert.strictEqual(out.status, 200);
    assert.deepStrictEqual(out.body.discrepancyDetails, { visualIntent: 'v-intent', actualExecution: 'x-exec', criticalMismatch: false });
    assert.ok(out.body.investigation && out.body.investigation.objective === 'obj', 'investigation preserved');
    assert.strictEqual(out.body.promptVersion, 'investigate-2.7');
    assert.strictEqual(out.body.modelId, 'mock-serving-model');
    console.log('✔ Test 8 Passed: discrepancyDetails + investigation preserved end to end.');
  }

  // 9-11: recommendation/criticalMismatch consumption is escalation-only (MOCKED).
  {
    const blocked = await runController(CLEAN_TX, undefined, cannedModel({ recommendedAction: 'BLOCK_TRANSACTION' }));
    assert.strictEqual(blocked.out.body.policyDecision.decision, 'REVIEW', 'model BLOCK escalates clean MATCH');
    const verify = await runController(CLEAN_TX, undefined, cannedModel({ recommendedAction: 'VERIFY_RECIPIENT' }));
    assert.strictEqual(verify.out.body.policyDecision.decision, 'REVIEW', 'model VERIFY escalates clean MATCH');
    assert.ok(blocked.out.body.policyDecision.reasons.join(' ').includes('advisory escalation'), 'escalation reason recorded');
    const crit = await runController(CLEAN_TX, undefined, cannedModel({
      discrepancyDetails: { visualIntent: 'v', actualExecution: 'e', criticalMismatch: true }
    }));
    assert.strictEqual(crit.out.body.policyDecision.decision, 'REVIEW', 'criticalMismatch escalates');
    // Model can never demote a deterministic BLOCK.
    const dec = composePolicyDecision({ verdict: 'MATCH', reasoningOrigin: 'model', ruleFindings: [{ ruleId: 'ZERO_ADDRESS_SPENDER' }], safeguards: [], advisoryEscalations: [] });
    assert.strictEqual(dec.decision, 'BLOCK');
    const demote = composePolicyDecision({ verdict: 'MISMATCH', reasoningOrigin: 'model', ruleFindings: [], safeguards: [], advisoryEscalations: [] });
    assert.strictEqual(demote.decision, 'REVIEW', 'MISMATCH stays REVIEW regardless of advisories');
    console.log('✔ Tests 9-11 Passed: Escalation-only consumption; BLOCK/MISMATCH unaffected.');
  }

  // 12-13: fabricated refs downgrade MATCH; unresolved contradictions escalate (MOCKED).
  {
    const fabMatch = await runController(CLEAN_TX, undefined, cannedModel({
      investigation: validInvestigation({ conclusions: [{ statement: 'c', supportingRefs: ['R-999'], contradictingRefs: [] }] })
    }));
    assert.strictEqual(fabMatch.out.body.verdict, 'UNCERTAIN', 'fabricated refs downgrade MATCH');
    assert.ok(fabMatch.out.body.verdictSafeguards.some((s) => s.trigger === 'FABRICATED_EVIDENCE_REFERENCE'), 'safeguard recorded');
    const contra = await runController(CLEAN_TX, undefined, cannedModel({
      investigation: validInvestigation({ contradictions: [{ statement: 's', sources: ['dom', 'tx'], resolved: false }] })
    }));
    assert.strictEqual(contra.out.body.verdict, 'MATCH', 'verdict untouched by escalation');
    assert.strictEqual(contra.out.body.policyDecision.decision, 'REVIEW', 'unresolved contradiction escalates');
    console.log('✔ Tests 12-13 Passed: Fabrication downgrades; contradictions escalate.');
  }

  // 14-15: fallback emits valid investigation; legacy validation compat.
  {
    const fb = fallbackHeuristicReasoner('swap it', { title: 'Swap', url: 'https://uniswap.org', visibleText: 'swap' }, { functionName: 'exactInputSingle', contractName: 'Router', parameters: {}, ruleFindings: [] });
    assert.strictEqual(fb.origin, 'heuristic-fallback');
    const v = validateInvestigation(fb.investigation, buildEvidenceRegistry({ decodedTx: { ruleFindings: [], parameters: {} }, visualMeta: {} }));
    assert.strictEqual(v.ok, true, JSON.stringify(v));
    assert.strictEqual(validateModelResult({ verdict: 'MATCH', confidence: 0.5, summary: 's', discrepancyDetails: {}, recommendedAction: 'X' }).ok, true, 'legacy shape still valid');
    assert.strictEqual(validateModelResult({ verdict: 'MATCH', confidence: 0.5, summary: 's', discrepancyDetails: {}, recommendedAction: 'X', investigation: [] }).ok, false, 'non-object investigation rejected');
    console.log('✔ Tests 14-15 Passed: Fallback schema-valid; legacy validation intact.');
  }

  // 16: agent path selects the agent prompt (MOCKED transport).
  {
    const { captured, out } = await runController(CLEAN_TX, { investigationType: 'agent' }, cannedModel());
    assert.ok(captured.messages[0].content.includes('Agent Investigator'), 'agent system prompt on agent path');
    assert.strictEqual(out.body.investigationType, 'agent');
    const plain = await runController(CLEAN_TX, undefined, cannedModel());
    assert.ok(plain.captured.messages[0].content.includes('Visual Sentry'), 'browser prompt by default');
    console.log('✔ Test 16 Passed: Per-path prompt selection with safe default.');
  }

  console.log('\nAll Reasoning Architecture Tests Passed Successfully!\n');
}

if (require.main === module) {
  runReasoningArchitectureTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runReasoningArchitectureTests };
