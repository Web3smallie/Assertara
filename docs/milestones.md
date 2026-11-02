# Assertara milestone record

Dated closure entries for completed milestones. Each entry names the
approved scope, the files changed, the verification evidence, and the
accepted limitations. No entry authorizes further work.

## Stage 1 — Muse Spark Live Activity Inspector (2026-11-01)

Status: VERIFIED, APPROVED, CLOSED — SUBSEQUENTLY REVERTED (2026-11-01).

Reversion note: at the operator's request, the Stage 1 terminal
lifecycle display was fully rolled back after acceptance testing. The
`finishReason` / `contextEstimate` span extras, the `demo/sparkLifecycle.js`
renderer, its `demo/agentDriven.js` wiring, and `test/unit/sparkLifecycle.test.js`
were removed, and the original INVESTIGATION_PROGRESS polling output was
restored. This record is preserved for history; Stage 1 is not an active
implementation.

Scope: replace the repetitive `stage=muse-spark model=running` terminal
polls with a single genuine model-request lifecycle. Non-streaming Chat
Completions integration unchanged; no streaming, no Responses API, no new
model calls, no pipeline/authorization changes.

Files changed (6):

- `src/services/reasonerService.js` — span extras only: `finishReason`
  (where the provider returned one) and `contextEstimate` on all seven
  `muse-spark` terminal paths.
- `demo/sparkLifecycle.js` (new) — harness lifecycle renderer: once-only
  milestones from reporter events plus one trace snapshot per
  investigation; honest `not reported` / `FAILED` / `NOT INVOKED` states.
- `demo/agentDriven.js` — wiring only (printer, snapshot fetch, drain).
- `test/unit/sparkLifecycle.test.js` (new) — 8 lifecycle/display tests.
- `test/unit/reasoner.test.js` — Test 15 (span-field recording).
- `package.json` — new suite registered in `test` and `test:unit`.

Verification (all observed, exit 0):

- Focused: `sparkLifecycle.test.js` 8/8, `reasoner.test.js` 15/15.
- Full `npm run test:unit`: green.
- Full `npm run test:e2e` (real Anvil + signer, mock model): green,
  including Demo A (ALLOW → executed → verified) and Demo B
  (BLOCK → nothing signed → chain untouched).
- Live `node demo/agentDriven.js both`: full 7-milestone lifecycle on
  both demos with genuine `finish_reason=stop`, token usage, and
  timings; Demo A EXECUTED, Demo B BLOCKED without retry.
- Closure audit passed all eight Stage 1 requirements; no regressions.

Accepted limitations:

- Non-streaming in-flight visibility remains at MODEL PROCESSING —
  RUNNING.
- Completion details appear after DECIDED.
- REQUEST STARTED uses harness-observed time; subsequent timestamps use
  server span clocks.
