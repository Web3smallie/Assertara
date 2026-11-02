# Multi-Evidence Reasoning (Capability 3)

Correlation, cross-examination, and validation across independent
evidence sources — on top of Capability 1 (assembly) and Capability 2
(reasoning architecture), which are preserved unchanged in behavior.

## B1 — Investigation persistence + rubric

`src/services/investigationStore.js`: append-only JSONL record store
(`INVESTIGATIONS_FILE`, default `data/investigations.jsonl`). Every
model-origin evaluation persists its full bundle plus reasoning
extras. Screenshots redact to hashes, credential-like keys drop,
oversized strings truncate with hashes. Writes are best-effort and
never break evaluation. `src/scripts/reviewInvestigation.js`
(`list|get|review [--file …]`) reads records back.

`src/services/reasoningRubric.js`: 12-criterion grader (0–2 each,
STRONG ≥ 20). Eleven criteria are deterministic structural checks;
facts-vs-inference is labeled heuristic. The rubric never feeds
authorization, and model confidence never raises a score.

## B2 — Simulation integration

`src/services/simulationEvidence.js`: deterministic triggers
(unlimited approval, HIGH/CRITICAL findings, unknown function) run
`forge` BEFORE reasoning; results pack into the prompt with honest
status lines (only executed/success/escalationDetected are
measured). Post-reasoning sims are preserved for MISMATCH verdicts.
`reconcileSimulation` downgrades MATCH only on measured
contradiction (revert, unexpected allowance) — safeguard stage 7.
FAILED/FALLBACK/NOT_RUN never move anything.

## B3 — Deterministic chain verification

`src/services/chainVerification.js`: five pure checks (chain
identity, balance sufficiency, nonce consistency, code/call
consistency, freshness corroboration) with pass/fail/inconclusive/
unavailable outcomes, evidence refs, and explanations. Failures
downgrade MATCH (safeguard stage 8) and hold for REVIEW
(`deterministicHolds`). Nothing here hard-BLOCKs: measurement-based
checks hold rather than prohibit. Results pack into the prompt and
are citable by check ID.

## B4 — Support validation + reconciliation

`src/services/supportValidation.js`: quoted-span entailment against
cited sources (fail), plus needs-review flags for semantic support,
page-only foundations, shared-source citations, support/counter
overlap, and absolute language. `src/services/reconciliation.js`:
precedence across model contradictions, deterministic comparison,
grounding, chain, and sim (deterministic beats model; resolutions
that contradict surviving evidence are overridden and escalated;
safe-direction model verdicts trusted). Reconciliation downgrades
feed safeguard stage 9.

## B5 — Findings-to-presentation comparison

`intentComparison.js` warning field promoted past inconclusive-only:
accurate risk naming MATCHes, safety claims and approval denials
against standing findings MISMATCH, agent-purpose disclosure and
omission are adjudicated (purpose is fully observed), browser
absence stays inconclusive (OCR gaps). Contradictions dominate
accurate warnings on the same page.

## B6 — Agent evidence submission

`src/services/agentEvidence.js`: typed envelopes (10 types),
server-assigned X-ids, forced UNTRUSTED, trust-smuggling rejection,
timestamp sanity, size caps, control-char stripping. Admitted items
pack under an explicit data-only framing with rejections disclosed;
X-ids are citable and support-checked. Region-less
`agentCorroboration` comparison field matches named addresses
against decoded counterparties (appended only when evidence
exists). Intake stays agent-agnostic (fixed schema, no demo
concepts).

## B7 — Graph, calldata, prompt 2.1

`src/services/evidenceGraph.js`: 8 typed edge kinds. Deterministic
edges build pre-reasoning (associations, chain checks, sim,
summary derivation) and print with E-ids for citation; model edges
validate against the registry and merge post-reasoning with
rejections recorded. CORROBORATES requires independent roots.
Raw calldata packs (capped, labeled untrusted data) for unknown /
ambiguous decodes only. Prompt `investigate-2.1` adds C1–C8
correlation rules, the extended ref vocabulary, and the optional
`evidenceRelationships` schema array.

## Verification

- `test/unit/multiEvidence.test.js`: per-workstream unit + mocked
  integration (admission, checks, validators, reconciliation,
  comparisons, graph, packing, end-to-end controller paths).
- `test/live/multiEvidenceLive{A,B,C,D}.test.js` (gated): 14 live
  multi-source scenarios; ME6/ME7 use labeled mocked sim records
  (forge cannot genuinely execute here), all reasoning live.
- `test/tmp/cap3-digest.js` (scratch): per-record rubric digest for
  the 10-investigation qualitative review program.

## Verification results (2026-10-30, muse-spark-1.3)

- Unit: 34/34 suites green (`npm run test:unit`), incl. B1–B7
  multi-evidence suite with bracket-ID canonicalization tests.
- Live batteries: A 4/4, B 4/4, C 3/3, D 3/3 — all 14
  multi-source scenarios green with genuine model reasoning
  (`origin=model`); ME6/ME7 sim records are labeled mocks, all
  reasoning live. One transient `fetch failed` in a chained run
  failed closed to heuristic UNCERTAIN and passed 7/7 on retry.
- Qualitative review: 13 persisted live investigations graded
  against the 12-criterion rubric — 11 STRONG (20–22/24),
  2 ADEQUATE (19/24); zero unsupported conclusions, zero
  fabricated refs, zero support failures across all records.
- Regression: 5/5 Anvil agent scenarios + 4/4 live chain-state
  tests green with real receipts; `demo:agent` 4/4 with live
  planner + live investigation; pre-existing live suites
  (museLive, sparkBehavior 7/7) green.
- Known limits: forge cannot genuinely execute in this env
  (ME6/ME7 sim labeled mocked); `EVIDENCE_CHAIN_RPC_URL` unset
  by default so browser path reports chain state unavailable
  until configured.
