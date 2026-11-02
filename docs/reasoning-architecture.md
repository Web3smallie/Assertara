# Investigative Reasoning Architecture (Capability 2)

Muse Spark acts as a structured investigation engine, not a verdict
oracle. Every investigation follows a 15-stage methodology, produces a
versioned structured report, and is deterministically checked for
evidence grounding before anything downstream may use it.

## Prompts (`src/services/reasoningPrompts.js`)

- `PROMPT_VERSION` (`investigate-2.1`), exported and recorded on every
  result and bundle.
- Shared principles: 7-tier trust rules, a findings advisory rule, the
  15-stage methodology, and the output schema.
- `BROWSER_INSTRUCTIONS`: dApp presentation-layer investigation with
  prioritized verdict rules (B1–B10, earlier wins ties).
- `AGENT_INSTRUCTIONS`: agent-proposal investigation. Objective,
  reported intention, proposed action, payload, and verified evidence
  are five different things; purpose is UNTRUSTED always, never visual
  evidence, never authorization.
- `selectSystemPrompt(type)` chooses per investigation type
  (`browser` default; unknown types throw). The planner prompt
  (`demo/agent.js`) remains a separate responsibility.

## Methodology (15 stages, each with HOW + output field)

Objective → inventory → source assessment → intent → execution →
parameters → correlation → discrepancies → contradictions →
competing explanations → suspicion → missing evidence →
uncertainty → conclusions → next steps. Stage IDs and field mappings
are exported as `METHODOLOGY_STAGES` and pinned by unit tests.

## Schema v2 (legacy fields preserved, `investigation` added)

Top level keeps `verdict`, `confidence`, `summary`,
`discrepancyDetails`, `recommendedAction`, `visualClaims`.
`investigation` carries objective, evidenceInventory,
sourceAssessments, intent/execution/parameter analyses,
discrepancies, contradictions, competingExplanations,
suspiciousBehaviours, missingEvidence, uncertainty, conclusions,
recommendations, furtherInvestigation. Evidence refs use an exact
vocabulary: printed `[R-xxx]` IDs, printed rule IDs, `param:<name>`,
or section tokens (title, url, dom, ocr, findings, params, chain,
freshness, labels, association, summarySelection, sam, tx, visual,
page).

## Grounding validation (`src/services/reasoningValidation.js`)

`buildEvidenceRegistry` collects exactly what was supplied;
`validateInvestigation` shape-checks the report and classifies every
reference: ok, synthetic (fallback cited), malformed, or fabricated.
A closed, recorded alias map (`pageTitle`→`title`, …) absorbs
unambiguous model paraphrase; anything else unknown is fabricated.
Fabricated refs on a MATCH verdict trigger the
`FABRICATED_EVIDENCE_REFERENCE` safeguard (downgrade to UNCERTAIN).
Conclusions without citations are flagged as unsupported.

## Consumption (escalation-only)

`discrepancyDetails` and `investigation` are stored in the bundle
(the Capability 1 audit's discard is fixed). The model can hold a
clean MATCH for review — `BLOCK_TRANSACTION` / `VERIFY_RECIPIENT`
advice, `criticalMismatch`, unresolved contradictions, unsupported
conclusions — but it can never permit: escalations only convert
would-be ALLOW into REVIEW inside `composePolicyDecision`.
Confidence is provenance, never authority.

## Observability

Every result records `promptVersion`, `investigationType`,
serving `modelId`, `latencyMs`, token `usage` (when provided), and
a `contextEstimate` (input chars/tokens, output cap). Output is
bounded by `MUSE_MAX_TOKENS` (default 24000 — sized for a reasoning
model whose hidden chain-of-thought precedes content; too small a
cap yields `finish_reason=length` with empty content).

## Fallback

`fallbackHeuristicReasoner` emits the same schema with an honest,
limited investigation (origin `heuristic-fallback`, low reliability
self-assessment). Policy never ALLOWs non-model origins.

## Tests

- `test/unit/reasoningArchitecture.test.js` (mocked transport):
  versioning, per-path selection, methodology/schema coverage,
  registry + aliases, grounding validation, preservation,
  escalation-only semantics, fabrication downgrade, fallback shape.
- `test/live/sparkBehavior.test.js` (gated, live): 7 genuine
  reasoning scenarios — alignment, phishing, unknown selector,
  disclosed approval, contradiction, agent honest, agent bait —
  asserting verdicts, methodology compliance, and zero fabricated
  references on `origin=model` responses.
