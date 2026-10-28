# Assertara Agent Contracts

Authoritative interface, schema, timeout, retry, limit, and error reference
for `src/agent/`. This document describes what the code does today; code and
tests are the source of truth — update all three together.

Section numbers are stable: removed sections are listed in §10 rather than
renumbered, so code citations (`contracts §13`, `§20`, `§21`, `§27`) keep
working.

## 1. Modules

| Module | Responsibility |
|---|---|
| `evidenceGraph.js` | Append-only store, stable IDs, edges, ref validation, export |
| `toolRegistry.js` | Typed validated tools for the core investigator + harness lane |
| `sparkAdapter.js` | Muse Spark Responses client (schemas, effort, threading, ledger, errors) |
| `orchestrator.js` | Bounded investigation loop (dispatch, budgets, dedup, termination) |
| `verifier.js` | Deterministic gates + fresh-review adjudication |
| `reports.js` | Typed investigation / replay / translator builders |
| `features.js` | 8-area map + feature runners + experimental gate |
| `harness.js` | F15 execution interface: validation, workspaces, detection, adjudication, evidence (no production executor ships) |
| `localize.js` | F12 segment localization: verified languages + protected-value tripwires |
| `replay.js` | F13 hash-chained event records + atomic persistence + pure historical replay |
| `readiness.js` | Capability inventory + validated readiness checks |
| `modelDriver.js` | Live `nextTurn()` driver: Spark-backed F1/F2 loops, strict turn schema, redacted prompts |

## 2. Model client interfaces

Two interfaces; runners declare which they need and throw loudly without it:

- `complete({ system, input, schema, schemaName, effort, previousResponseId, maxOutputTokens, timeoutMs })` → `{ content, usage, estimatedCostUsd, responseId }`. `content` is parsed JSON; malformed JSON is a typed non-retryable `invalid_response` error.
- `nextTurn({ system, effort, responseId, graph, ledger })` → `{ actions: [{ tool, args }], usage?, estimatedCostUsd?, responseId?, notes?, stop?, stopReason? }`.

Real implementation: `SparkAdapter`. Tests use scripted stubs.

## 3. Spark API surface used

- `POST {base}/responses` with `{ model, input, reasoning: { effort }, text: { format: { type: 'json_schema', name, schema, strict: true } }, tools?, previous_response_id?, max_output_tokens?, prompt_cache_key? }`.
- `POST {base}/responses/input_tokens` preflight (exact count + validation, no generation).
- Defaults: model `muse-spark-1.3`, `prompt_cache_key: 'assertara-investigate'`, timeout 120000ms.
- Normalized result: `{ id, status, text, toolCalls: [{ callId, name, argsRaw }], reasoningItems, usage, estimatedCostUsd, cachedTokens }`.
- Cost uses documented standard-tier rates ($1.25/$0.15/$4.25 per MTok) applied ONLY when `usage` is present; otherwise `null` — never invented.

## 4. Tool contract

- Call shape: `runTool(name, args)` → result object, or throws `Error`. Unknown names throw `unknown tool`.
- Validation (two layers, same rules): the orchestrator runs presence + per-tool `validate()` format checks pre-execution and records failures as invalid actions (never executed, never counted as execution failures, never retried); `runTool` re-validates defensively and throws before any execution for direct callers.
- Orchestrator additionally: unknown/invalid actions recorded as failed actions (never executed); duplicates by `(tool, sha256(args))` suppressed and counted in `ledger.deduped`.
- Registered tools (9): `decode_tx`, `compare_fields`, `allowance_analysis`, `segment_concept`, `crop_region`, `ocr_region`, `simulate_tx`, `check_consistency`, `sandbox_exec`.

## 5. Evidence requirements

- Node: `{ id (E-###, app-minted), kind, producer: USER|TOOL|MODEL, tool_ref?, input_hashes[], payload, created_turn }`.
- Edges: `SUPPORTS | CONTRADICTS | REFINES | SUPERSEDES | DERIVED_FROM`, both endpoints must exist.
- Findings cite `supporting[]`/`contradicting[]` IDs; `validateRefs` must pass before adjudication.
- Experimental evidence is marked `kind: 'Experimental'` or `payload.experimental === true` and can never support `VERIFIED` (verifier gate).

## 6. Timeouts

| Layer | Default | Notes |
|---|---|---|
| Adapter request/preflight | 120000ms | Per-attempt; overridable per call |
| Orchestrator tool execution | 30000ms (`budget.toolTimeoutMs`) | Timed-out tools recorded as failures, loop continues |
| Simulator `forge` spawn | 8000ms | Existing service behavior; timeout → `FAILED` |
| Extension backend POST | 120000ms | Existing extension behavior |

## 7. Retry rules

- Retry **once** (max 2 attempts): HTTP 429, HTTP 5xx, timeouts.
- Backoff: honor server `Retry-After`, capped at 10s; otherwise 500ms fixed.
- **Never retried:** 4xx (incl. 400 validation, 401 auth), malformed JSON responses, tool validation failures, unknown tools, deterministic tool errors, model-client `complete()` JSON errors.
- Orchestrator performs no retries of its own: one attempt per validated action; failures become `ToolFailure` evidence and the loop continues or terminates honestly.

## 8. Resource limits

- Orchestrator budget defaults: `maxTurns 8`, `maxToolCalls 24`, `maxUsd 2.00`, `maxIdleTurns 2`. Exhaustion → `INCOMPLETE` with `stopReason`; never a forced verdict.
- Input caps: client visible text 8000 chars (controller), screenshot payloads bounded by Express 25mb JSON limit.

## 9. Error behavior

- `SparkApiError { status, type, code, message, retryable, retryAfterMs }`. Types: `rate_limit_error`, `server_error`, `invalid_request_error`, `authentication_error` (from server), `invalid_response`, `timeout`, `configuration_error` (missing/placeholder key — fails before any network call).
- Tool errors: thrown `Error` with `toolName: reason` messages; orchestrator catches per-action.
- Feature runners: return `{ status: 'OK'|'PARTIAL'|'FAILED'|'GATED'|'EXPERIMENTAL'|'UNAVAILABLE'|'REJECTED', ... }`; programmer errors (missing model/inputs) throw.
- Verifier statuses: `VERIFIED | LIKELY | HYPOTHESIS | REJECTED | INCONCLUSIVE | INCOMPLETE` (meanings in `verifier.js` `STATUSES`). Eight gates (all must pass): has-support (non-empty `supporting[]`), ids-resolve, no-unresolved-contradictions (Finding-node edges), execution-truth (genuine: EXECUTED/passed/VULNERABILITY_REPRODUCED/PATCH_VERIFIED), model-cannot-verify, no-experimental-support, no-failed-support (failed/unavailable/mock ToolResults reject), contradictions-resolved (`contradicting[]` needs a superseding record or REFINES/SUPERSEDES edge). Experimental-support and contradiction failures alone cap at HYPOTHESIS; every other failure rejects.
- Simulation statuses: `EXECUTED | FALLBACK | FAILED | NOT_RUN` — only `EXECUTED` may claim EVM execution.
- Secrets: API keys travel only in the `Authorization` header; never in bodies, errors, logs, or reports.

## 10. Removed lanes (cleanup ledger)

The following workflows were removed from the product along with their
modules, tools, feature runners, readiness checks, and test suites.
Unknown feature ids and tool names now throw loudly instead of resolving.
Git history preserves the deleted code; do not re-add these sections here.

- Former §10 — Night Watch scheduler (`scheduler.js`, F14, `schedule_monitor`).
- Former §12 — Audit-PDF ingestion (`pdfIngest.js`, F10 ledger/assess lanes, `pdf_extract`).
- Former §14 — Audio ingestion (`audioIngest.js`, F8 lanes, `transcribe_audio`).
- Former §15 — Chain-history discovery (`chain.js`, F6 sentinel, `contract_meta`, `chain_history`).
- Former §16 — Contract dossiers (`dossier.js`, F7 runner).
- Former §17 — Finding Q&A (`askAbout.js`, F9 runner).
- Former §18 — Audit assessment (`auditAssess.js`, F10 assess lane).
- Former §19 — Video ingestion (`videoIngest.js`, F11 lane, `video_analysis`).
- Static repository review (`runRepoReview`, former F15 default lane).

Retained neighbors: the F15 harness execute lane, `sandbox_exec`, the
verifier vocabulary (which still names removed status strings as
non-genuine evidence), and F12 localization (kept for Phase 2).

## 11. Tests proving these contracts

`test/unit/agent.test.js`: graph (T1), tools+validation (T2), adapter requests/errors/timeouts (T3), preflight/complete (T4), loop semantics (T5–T6), verifier (T7), reports (T8), feature map (T9), translator/triage/localize (T10–T12), core+replay (T13), advanced+gate (T19), tool catalog (T20), retry-once (T22), non-retryable (T23), experimental gate (T24). Numbers T14–T18/T21 were retired with their lanes.
`test/unit/harness.test.js`: capability detection (T1), unavailable honesty (T2), request validation (T3), timeout handling (T4), truncation+errors (T5), cleanup (T6), completion-vs-reproduction (T7), no-verified-without-proof (T8), patch verification (T9), safeguard regression (T10).
`test/unit/localize.test.js`: successful localization (T1), unsupported languages (T2), missing/failing models (T3), malformed output (T4), value preservation (T5), evidence refs (T6), status preservation (T7), warning/uncertainty (T8), altered-value detection (T9), injection inertness (T10), strict-schema shape (T11), retained-lane regression (T12).
`test/unit/replay.test.js`: ordered recording (T1), schema validation (T2), redaction (T3), chain verification (T4), tamper detection (T5), persistence/recovery (T6), full replay (T7), missing evidence (T8), recorded-vs-derived (T9), no-external-services (T10), resource limits (T11), retained-lane regression (T12), mixed-outcome pairing (T13).
`test/unit/readiness.test.js`: inventory completeness (T1), five-status classification (T2), missing deps/failed probes (T3), live-vs-mock separation (T4), experimental gate (T5), failed-support gate (T6), harness genuine set (T7), no success-shaped failures (T8), record validation (T9), registry consistency (T10), static-vs-reproduction + criterion honesty (T11), retained-lane regression (T12).
`test/unit/hardening.test.js`: adversarial simulator inputs (T1), legit inputs + charset safety (T2), reasoner provenance paths (T3), bundle/display provenance (T4), contradiction semantics (T5), capping composition (T6), strict-schema capture ×4 (T7), malformed outputs contained (T8), no-model honesty (T9), cross-feature spot-checks (T10), simulate_tx validation (T11), retained-lane regression (T12).
`test/unit/modelDriver.test.js` (deterministic, injected doubles): successful F1 (T1), malformed output (T2), unavailable model (T3), transport failure (T4), tool failure + failed-support (T5), iteration limit (T6), drops + caps (T7), prompt redaction (T8), continuity + strict schema (T9), F2 live path (T10), live-without-key (T11), regression (T12). `test/unit/modelDriver.live.test.js` is NOT in the suite: explicit live smoke (self-skips without a key).
`test/unit/legacyRunners.live.test.js` is NOT in the suite: explicit live verification of the retained runners F4/F5/F2/F12 (self-skips without a key).

## 13. Harness contract (`harness.js`, `sandbox_exec` tool, F15 execute lane)

- Interface: `submitHarnessRun({ kind: static|execute|reproduce|verify-patch, files, entry?, criterion?, poc?, suite?, timeoutMs?, maxLogChars? }, { executor?, workspaceRoot?, capabilities? })`. Validation throws coded `HarnessError`s before any staging. `static` returns `STATIC_ANALYSIS_ONLY` (no detection, no workspace). Without an executor, execute-kind requests return `EXECUTION_UNAVAILABLE` with live detection evidence + requirements; nothing runs on the host, ever.
- Run statuses: `EXECUTION_FAILED` (errored before criterion evaluation), `EXECUTION_TIMED_OUT` (wall clock exceeded; abort requested; never a finding), `EXECUTION_COMPLETED` (finished, no criterion satisfied — completion ≠ reproduction), `VULNERABILITY_REPRODUCED` (finished + explicit criterion met), `NOT_REPRODUCED` (finished + criterion evaluated + not met; not proof of safety), `PATCH_VERIFIED` (verify-patch: PoC no longer reproduces AND regression suite passes; carries `{passed:true, logs}` testEvidence for downstream consumers).
- Vocabulary mapping (no conflicts): harness `EXECUTION_*` describes the run; simulator `EXECUTED/FALLBACK/FAILED/NOT_RUN` describes EVM simulation attempts. Static findings, hypotheses, timeouts, and unavailable execution can never produce `PATCH_VERIFIED`.
- Evidence per run: `runId`, `requestHash`/`filesHash` (sha256), argv `command`, `exitCode`/`signal`, bounded logs with explicit truncation markers, `criterion` + `criterionMet`, environment metadata (executor name, required constraints). Per-run workspace under `data/.harness-runs/` (configurable), removed in `finally` after success, failure, and timeout. Command policy: argv exec only (never a shell), tool allowlist `forge|node|python3`, arg count/length/NUL checks.
- Detection: `detectCapabilities()` probes `docker` (binary + daemon) and `podman` (binary + daemon) with 5s timeouts; reports `{available, version?, error?}` + `canExecuteIsolated`. WSL is deliberately excluded: it provides no containment and is not an acceptable substitute. Verified 2026-10-27 on this machine: Docker absent, Podman absent, WSL feature not installed → `canExecuteIsolated: false`.
- Docker/Podman adapter contract (SHIPPED Phase 18 as `src/agent/sandbox.js`; authoritative spec now §27): verify runtime+daemon+image identity BEFORE any run; run `docker|podman run --rm --pull never --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --memory 512m --cpus 1.0 --pids-limit 128 --stop-timeout 5 --name <per-run> -v <workspace>:/work --workdir /work --entrypoint <tool> <pinned-image> <args...>` with runner-side timeout kill (`kill` + `rm -f`); mount ONLY the per-run workspace (never the project root, home, `.env`, Git/SSH credentials, or the runtime socket); pass no secrets via env/args; return `{exitCode, signal?, stdout, stderr}`. Deviations from the pre-Phase-18 sketch are documented and justified in §27. Live-container verification is still pending (no runtime here): the flags are proven by injected-double argv assertions (sandbox T5), not by a real daemon run.

## 20. Localization contract (`localize.js`, F12 runner)

- Interface: `localizeAssessment({ assessment: {segments:[{id, text, tone?}], protected?}, targetLang }, { model? })`. Segments capped (20 × 4000 chars); tones ∈ fact/warning/uncertainty/guidance. `targetLang` normalizes to a lowercase base code (`es-ES` → `es`) and MUST be in `SUPPORTED_LANGUAGES` (currently es/fr/de, each admitted only after a live probe passes every tripwire) — else `UNSUPPORTED_LANGUAGE` with the supported list; nothing translated.
- Model I/O (`LOCALIZE_SCHEMA`, Meta strict shape): model returns `{segments:[{id, text}]}` for the same id set; protected fields are NEVER model output — canonicals are reattached verbatim by the application, so field alteration is structurally impossible. Missing model/failing model → `LOCALIZATION_UNAVAILABLE`; malformed output → `FAILED`; original always preserved alongside.
- Tripwires (deterministic, fail-closed): (1) embedded protected values reappear verbatim — 0x addresses, 64-hex hashes, E-##/F-##/SRC:/REPORT: refs exactly; digit-runs modulo separators (3,450 → 3450 allowed); any drop → FAILED naming the value. (2) No NEW absolute-safety language (English lexicon: verified, guaranteed, proven/proved safe, 100% safe, risk-free, no risk, completely/absolutely safe, confirmed secure) — new presence → FAILED. Limitation: target-language equivalents (verificado/vérifié/…) are NOT scanned, to avoid false positives on legitimate words (e.g. French “Vérifiez” = “check”); statuses stay safe because enums are reattached, never translated. (3) Shortening floor (localized ≥40% of canonical chars, ≥50% when canonical carries uncertainty markers) catches dropped warnings; calibrated for alphabetic scripts only (CJK unsupported).
- Numbers are never reformatted by the service: canonical values ride alongside as `protectedValues[{value, kind, present, display}]` with `display` = canonical (unambiguous by construction). Tone/uncertainty preservation is enforced via tripwires 2–3 plus prompt rules, not semantic proof — documented ceiling.
- `runLocalize` adapts findings (claim/summary/description/warning/uncertaintyNote/recommendedAction/remediation → segments; PROTECTED_FIELDS → protected) and returns the localized finding object with canonical protected fields + original. Verified live 2026-10-27 via SparkAdapter: es/fr/de probes all OK — address/refs/digits preserved, warnings and uncertainty faithfully rendered. Unit tests use stub models (labeled mocks).

## 21. Replay contract (`replay.js`, F13 runner)

- `Recorder({investigationId, runId, featureId?, versions?, model?, now?, mode?})` appends ordered events across 9 types (investigation.started/stopped, model.turn, tool.called/result/rejected, evidence.appended, assessment.recorded, capability.unavailable), each classified observed/interpreted/assessed. Events carry seq + ISO ts + actor + redacted data + evidenceRefs + versions + optional chain context + `prevHash`/`hash` over a canonical subset. Caps: 1000 events, 64KB/event, 4MB/recording; BigInt → tagged strings, Buffer → hashes (screenshots never embedded), circular/too-deep values rejected.
- Redaction: narrow sensitive-key set (api keys, secrets, private keys, passwords, mnemonics, tokens-as-credentials, cookies, dotenv) + known credential value patterns (sk-*, Bearer/Basic, ghp_, PRIVATE KEY blocks). `token` alone is NOT sensitive (ERC-20 evidence preserved); `authorization` redacts string credentials only (EIP-7702 authorization tuples are objects and survive). Redacted JSON paths are listed on each event.
- Integrity: sha256 chain over canonical JSON. Detects in-place edits (EVENT_MODIFIED), deletion/reorder (CHAIN_LINK_BROKEN), truncation/extension (HEAD_MISMATCH) — GIVEN an independently held head hash. Explicit non-guarantee: a writer with full storage control can rewrite the whole file; the chain proves consistency, not authorship. Persistence `replay-<runId>.json` (runId filename-validated, no traversal), atomic tmp+rename writes, validated reads (NOT_FOUND/MALFORMED/UNSUPPORTED_VERSION/BAD codes, never throw-on-corrupt).
- `recordFromRun({record, graph, assessments?})` derives mode=derived recordings from finished orchestrator runs: redacted inputs + inputsHash, per-turn model.turn/tool.called/tool.result (args survive as hashes only — v1 records don't store them), evidence.appended for non-ToolResult nodes, cumulative ledger at stopped. Executed-but-failed actions pair with their own error-only ToolResult as tool.result(ok:false); pure validation rejections stay tool.rejected; ok actions never inherit a failure node's evidence id (Phase 15 pairing fix). Timestamps are recording times (v1 doesn't timestamp turns); budgets and per-turn usage labeled not-recorded. Re-execution is NOT implemented and has no code path.
- `replayRecording(recording, {evidence?})` is synchronous and dependency-free: validates schema + chain, resolves evidenceRefs against a supplied graph export (missing → PARTIAL + gaps; none supplied → unchecked + limit note), and returns timeline items as `{recorded (verbatim), view (deterministic-summary), evidence[]}`. FAILED on any integrity break with the offending seq. No network/model/tx is reachable from replay.
- F13 runner: `{record, graph}` → legacy bundle (unchanged); `{build:true, record, graph}` → recording; `{recording, evidence?}` → historical replay.

## 22. Experimental audit + readiness contract (`readiness.js`)

- Inventory (`CAPABILITIES`, 8 entries): f3.runners TEST_ONLY (gate live, zero runners) · core.local READY (graph/record/replay, live local) · exec.harness UNAVAILABLE (no daemon, no verified image) · media.ocr READY (installed; recognition live-verified on synthetic frames) · sim.forge PARTIAL (forge 1.7.1 present, forge-std absent → FALLBACK by direct run) · model.spark READY (probe PASSED live 2026-10-27; F12 lane verified) · model.sam PARTIAL (probe PASSED live on 1px fixture; real-UI discrimination unproven) · web.intel UNAVAILABLE (no tool ships — documented gap).
- Readiness records: `{capability, name, status ∈ READY|PARTIAL|UNAVAILABLE|TEST_ONLY|FAILED_CHECK, checked[], succeeded[], failed[], unknown[], dependencies[{name,state}], executedWith ∈ live|fixture|mock|model|probe, evidence{}, checkedAt}`. Invariants enforced by `validateReadinessRecord`: READY tolerates no failure/unknown; UNAVAILABLE claims no success; PARTIAL needs a success plus a gap; FAILED_CHECK names a failure; TEST_ONLY explains why; evidence is secret-scanned (recorded keys/credentials throw SECRET_LEAK).
- Execution labeling: injected doubles → `mock`; deterministic fixtures → `fixture`; real local runs → `live`; config/binary/file inspection → `probe`. The unit suite never touches the network. A throwing check synthesizes FAILED_CHECK (loud, labeled) — probes are never silently converted to PARTIAL/READY. Daemon presence without a verified image stays UNAVAILABLE by construction.
- Verdict boundaries: `gateNoFailedSupport` rejects findings citing failed/unavailable/mock ToolResults (UNAVAILABLE, EXECUTION_*, TRANSCRIPTION_* incl. BACKEND_ERROR, VIDEO_PROCESSING_UNAVAILABLE, simulator FAILED, error-only payloads, mode:mock). `gateExecutionTruth` recognizes harness VULNERABILITY_REPRODUCED/PATCH_VERIFIED as genuine; EXECUTION_COMPLETED, NOT_REPRODUCED, STATIC_ANALYSIS_ONLY, FALLBACK remain non-genuine. No tool exposes adjudication (models cannot reach VERIFIED by tool call).

## 23. Hardening contract (simulator validation, reasoner provenance, contradictions, schemas)

- Simulator inputs (`validateSimulationInputs`, simulatorService): `to` required 0x address; `from` optional 0x address; `data` 0x hex bytes ≤128KB (missing → `0x` native transfer); decoded `spender`/`operator` re-validated (parsed, never trusted). Allowlist charset (not escaping) makes interpolation into `address constant` / `hex"..."` contexts structurally safe — validated values cannot contain quotes, semicolons, newlines, or comments. Violations return structured `FAILED` + `SIM_VALIDATION` before any file write; FALLBACK never substitutes for validation. Threat model: a malicious `from`/`to`/`data` previously reached generated Solidity (compile failure contained it; no `--ffi` anywhere so host execution was unreachable). Residual: validation is syntactic (shape), not semantic — an attacker can still request simulation of ARBITRARY VALID transactions (that is the feature); `forge` itself runs un-sandboxed on app-generated sources (pre-existing; sources contain only validated values + fixed template).
- Reasoner provenance: heuristic outputs carry `origin:'heuristic-fallback'`, live model outputs `origin:'model'`; bundles expose `reasoningOrigin` (`unknown` when absent, never invented); extension renders it via `reasoningOriginLabel` (popup note + overlay Analysis row). Fallback verdicts are unverified interpretations: the agent adjudication path never consumes HTTP reasoner output (structural separation), and the label prevents downstream misreading. Deterministic fallback behavior unchanged.
- Contradictions (`gateContradictionsResolved`, 7th gate): each `contradicting[]` entry must be graph-resolved — a superseding node (`node.supersedes === id`) or a REFINES/SUPERSEDES edge from the finding's Finding node. Reviewer SUPPORT alone no longer discharges listed contradictions. Unresolved-only failures cap at HYPOTHESIS (same capping set as experimental); malformed refs (unknown ids) reject via ids-resolve. Limitation: resolution is structural (a superseding record exists), not semantic proof the counter-reading was correctly addressed.
- Schemas: all 4 retained `features.js` model schemas (translator incl. nested quoted with full required, triage, advanced review, localize) are strict-compatible. Capture tests drive every runner with stub models and recursively assert the shape. Per-runner LIVE calls remain individually unverified except where §26 says otherwise.

## 24. Live model driver contract (`modelDriver.js`, F1/F2 `live:true`)

- `createModelDriver({adapter?, allowTools?, maxActionsPerTurn=4, maxSummaryChars=6000, systemExtra?})` returns a `nextTurn()` modelClient: no parallel orchestration — the orchestrator still validates, executes, budgets, dedups, and terminates. Default adapter (`defaultAdapter()`) reads `config.modelApiKey` (existing config; `.env` never written). `{ live: true }` on `runCoreInvestigation`/`runAdvanced` builds the driver (F2 also defaults its reviewer to the same config-backed adapter); an injected modelClient always wins.
- Turn schema `investigation_turn` (strict): `{actions:[{tool, argsJson}], stop, stopReason, notes}`. `argsJson` is a JSON-encoded args object because strict json_schema forbids additionalProperties:true on inline args; the driver parses it and the orchestrator re-validates tool/args/dedup before anything executes or mutates evidence. Unknown tools, oversized args (>16KB), and unparsable/non-object args are dropped with reasons appended to the turn notes (visible in the record).
- Prompt = goal + effort + ledger + redacted caller inputs + bounded redacted evidence summary (100 nodes, 300-char payload previews) + available-tool catalog + investigation rules. Redaction is two-layer (structured pre-stringify + inline `sk-`/`Bearer` sweep, incl. the goal string); scrub counts are reported in the prompt, not hidden. F2 reviewer inputs are redacted the same way.
- Error semantics: unavailable key / transport failure (incl. 429-after-retry, timeout) THROW coded errors → run INCOMPLETE with the message (nothing fabricated, failures counted). Malformed turn content or zero valid actions → STOP turn with a `model-error:` stopReason → run COMPLETES with the reason. Usage/estimatedCost/responseId thread into the ledger; `previous_response_id` chains turns server-side.
- Bounds: orchestrator maxTurns/maxToolCalls/maxIdleTurns/maxUsd all apply unchanged; driver adds the per-turn action cap. The model cannot sign/submit (no such tool exists), bypass gates (no tool reaches them), or run host commands (no such tool exists).
- Eighth gate `gateHasSupport`: findings citing zero supporting evidence REJECT even on reviewer SUPPORTED (verification requires evidence, not agreement).
- Adapter repair (`extractBalancedJson`, live-verified): schema-constrained calls that return prose-prefixed JSON have the first balanced object extracted (`repaired:true`). Refusals/truncation/transport now throw their own typed errors (see §25 taxonomy), not `invalid_response`. Live F1 smoke 2026-10-27: 3 turns, 4 tool results, bounded stop; live F2 smoke: reviewer ran, empty-support hypothesis REJECTED.

## 25. Bounded correction contract (modelDriver one-attempt correction)

- Eligibility (only these trigger ONE correction per turn): `invalid_response` throws from `complete()` (completed response, no parseable JSON — category `no-parseable-json`); parsed content failing turn-shape validation (`bad-turn-shape: <rule>`); zero valid actions where every drop is format-class (malformed entries, unparseable/non-object/oversized argsJson — `bad-args-format: ...`). Unknown-tool drops, empty-actions-continue, refusals, truncation, transport, auth, and 429/5xx NEVER trigger correction.
- Failure taxonomy (typed `SparkApiError.type`, never message-guessed): `refusal` (structural refusal item/block; text never echoed), `truncated_response` (status incomplete + reason), `invalid_response` (completed, no balanced JSON), `transport_error` (fetch failures, invalid HTTP bodies; non-retryable — retry policy unchanged: 429/5xx/timeout only), `timeout`/`rate_limit_error`/`server_error` (retry-once, as before), `configuration_error`, `invalid_request_error`. Every content-level throw carries `.attempt = {responseId, usage, estimatedCostUsd}` so failed attempts keep provenance.
- Mechanism: linear single follow-up (no recursion, no loop) reusing system/schema/effort, chained via the failed attempt's response id; prompt = fixed template + failure category + schema constraints (never raw output, no caller data). The fix is validated from scratch by the identical pipeline (shape → actions → allowlist → caps); anything failing stops with `model-error:` and zero execution. Acceptance is marked `corrected:true` + `[corrected after 1 malformed attempt (...)]` notes; the original is never presented as valid.
- Budgets/observability: correction stays inside the same turn (turn/action caps apply to the corrected output); worst case per turn is 2 model requests × adapter retry-once. Usage/cost merge only when BOTH attempts report, else null/unknown (never zero); first-attempt id, category, and chain preserved on the turn. Spending-cap limitation: maxUsd binds corrected turns only when usage is reported on both attempts; failed-attempt usage on NON-corrected throws (refusal/transport/etc.) is still lost at the orchestrator boundary (pre-existing).
`test/unit/modelDriver.test.js` T14–T27: no correction on valid (T14), one correction + from-scratch acceptance (T15), failed correction safe (T16), corrected-action filtering (T17), refusal/transport/auth/provider/truncation rethrow (T18–22), merged/unknown usage + chaining (T23), caps (T24), no VERIFIED from failure (T25), clean-run parity (T26), adapter taxonomy (T27).

## 26. Retained-runner live verification

- The 4 retained model paths are covered live via `test/unit/legacyRunners.live.test.js` (explicit script, NOT in `npm test`; self-skips without a key). Each runs individually with small fixtures through its real `model.complete()` path; usage/cost captured per call; artifacts secret-scanned. Historical note: the script formerly covered 8 paths; the removed-lane sections (F6/F7/F8/F9/F15-static) were deleted with their modules, and an F12 live check was added.
- Reference results from the pre-cleanup run (2026-10-27): F4 translator OK (quotes verified, issues=0) · F5 triage RED on unlimited approval (deterministic screen + model reasons, escalate=true) · F2 reviewer ran, empty-support hypothesis REJECTED (gateHasSupport holds live). F12 es/fr/de probes passed separately (see §20). Total live spend across the verification runs: under $0.10; per-runner usage/cost printed by the script (unknown represented as unknown).
- Failure handling (inspect-verified + stub-tested, not force-triggered live): all retained runners let typed adapter errors propagate (no catch-and-fabricate anywhere on these paths); malformed stub outputs are contained per hardening T8; bounded correction exists ONLY on the driver path and was deliberately not added to runners (no nested loops).
- Remaining risks: live-model output variance means single-run results are compatibility evidence, not correctness proof; per-runner live behavior on adversarial/malformed real-world inputs is untested.

## 27. Sandbox executor contract (`sandbox.js`, F15 execute lane, Phase 18)

- Enablement is OPERATOR configuration only: `submitHarnessRun(input, { sandbox: { enabled, runtime?, image, expectedDigest?, limits?, spawnFn? }, workspaceRoot? })`. Routing order: injected `deps.executor` (tests) → sandbox iff `enabled === true` (strict; truthy non-`true` stays disabled) → none → `EXECUTION_UNAVAILABLE`. The `sandbox_exec` tool never passes `sandbox`, so model calls cannot enable execution (sandbox T15). There is no host executor and no host fallback: every host process the adapter spawns is the `docker`/`podman` CLI with an argv array (sandbox T11; source guard pins `child_process` imports to `spawn` only, no `execSync`, no `shell:true`).
- Verification (`verifySandbox`, no untrusted execution): normalize runtime (`docker|podman|auto`) → validate image ref (registry grammar, ≤300 chars) → validate `expectedDigest` (`sha256:<64hex>`) and absolute `workspaceRoot` → probe each candidate runtime (`--version`, then `info`) → `image inspect` for Id + RepoDigests → digest match (image Id or RepoDigest suffix). Outcomes: `{ok:true, executor, runtime, version, image, imageId, digestVerified, limits}` or `{ok:false, stage: runtime|daemon|image, error, attempts?, requirements[]}`. Missing infrastructure NEVER throws; invalid operator config throws `SANDBOX_CONFIG`, which the harness maps to `EXECUTION_UNAVAILABLE` (stage `config`), never to a run (sandbox T1–T4, T6).
- Run argv (Docker/Podman-compatible; `buildRunArgv` self-checks every mandatory flag and throws `SANDBOX_INTERNAL` if one is missing): `--rm --pull never --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --memory 512m --cpus 1.0 --pids-limit 128 --stop-timeout 5 --name assertara-<wsbase>-<pid>-<seq> -v <workspace>:/work --workdir /work --entrypoint <tool> <image> <args...>`. The entry is the harness-validated `{tool, args}` re-validated here (shape + NUL checks); its first token becomes `--entrypoint` (overriding any image ENTRYPOINT such as `/bin/sh -c`, which would otherwise swallow arguments) and the remaining args trail the image, unmodified; no shell exists on this path (T17). `workspaceDir` must be absolute, NUL-free, strictly inside `workspaceRoot`, with a safe basename — escapes are rejected before any runtime call (T7–T8).
- Deviations from the pre-Phase-18 §13 sketch (explicit, reasoned): (a) NO `--user <nonroot>`: a fixed UID breaks bind-mount writes for images without that user and behaves unpredictably on Docker Desktop/Windows bind mounts; root-in-container is instead contained by `--cap-drop ALL` + `no-new-privileges` + read-only rootfs + no network (residual risk recorded below). (b) Single RW workspace mount instead of `:ro` + `:rw` scratch split: `forge test` writes `cache/`+`out/` relative to the project and cannot redirect all writes to a scratch dir; isolation is preserved because the mount holds ONLY harness-staged files (never repo, home, `.env`, credentials, or socket). (c) Additions over the sketch: `--pull never` (no silent image fetch, ever), `--stop-timeout 5`, tmpfs `noexec,nosuid`, per-run `--name` for reliable kill.
- Lifecycle: per-run container name; `abort()` issues `<runtime> kill <name>` + `rm -f` (idle abort is a `{aborted:false}` no-op); `run()` always `rm -f`s in `finally`; the harness owns the wall-clock timeout and calls `abort()` on expiry, so timed-out containers are killed, not orphaned (T9, T14). Stdout/stderr are captured at 1MiB/stream with explicit truncation markers; the harness truncates further to `maxLogChars` (T13). Cleanup of the host workspace stays in the harness `finally` (proven after success, failure, and timeout: T10, T13, T14).
- Labeling: sandboxed records carry `environment: {executor: 'sandbox:<runtime>', mode: 'sandboxed', sandbox: {runtime, version, image, imageId, digestVerified, limits}}`; scripted doubles carry `mode: 'test-double'`; static/unavailable lanes carry no execution mode. Failed verification yields `EXECUTION_UNAVAILABLE` with a `sandbox: {ok:false, stage, error}` block + `requirements`, never success-shaped fields (`run`/`testEvidence` absent: T16). Reproduction vs patch-verification adjudication is unchanged (`VULNERABILITY_REPRODUCED` needs the criterion; `PATCH_VERIFIED` needs blocked-PoC + green suite; T12).
- Image strategy: NO image is approved yet — `exec.harness` stays `UNAVAILABLE` (`verified sandbox image: unconfigured`). Approval requires an operator to (1) obtain a published Foundry-capable image out-of-band (no pulls are ever issued by the adapter), (2) record its `repo@sha256:<digest>` + local `image inspect` Id, (3) set `sandbox.image` + `sandbox.expectedDigest` in operator config, (4) run the live daemon checklist (contracts enablement note: runtime present, daemon reachable, image present, digest match, one `--network none` smoke run, cleanup observed). `forge-std` as a dependency must arrive INSIDE the approved image or as harness-staged files — never via network fetch at run time, never via broad host mounts.
- Unit vs live evidence: T1–T16 prove validation, verification stages, argv restrictions, kill/cleanup, routing, labeling, and adjudication through injected `spawnFn` doubles + source guards + ONE real negative (`verifySandbox` with the real spawner on this runtime-less machine fails closed at stage `runtime`: T16). NO real container has ever been started by this adapter: daemon behavior, flag acceptance on real Docker/Podman versions, Windows bind-mount translation, and actual containment are UNVERIFIED and must be proven by a live daemon run before any `READY` claim.
- Residual risks: containers are process isolation, not a perfect boundary (kernel escapes out of scope; host/runtime patching is an operator duty); no `--user` (see above); Windows bind-mount path translation is operator-verified, not tested here; resource limits depend on runtime/cgroup support (`--memory/--cpus/--pids-limit` may degrade on some Podman/Windows setups — a live smoke run must confirm enforcement); digest verification trusts the local image store + daemon (a compromised daemon is outside this boundary).
`test/unit/sandbox.test.js`: missing runtime (T1), daemon-down (T2), missing image (T3), digest mismatch/match (T4), restriction argv (T5), config rejection (T6), workspace escapes (T7), bad commands (T8), abort/kill (T9), explicit-enable routing (T10), runtime-CLI-only proof (T11), repro/patch boundaries (T12), truncation/failures (T13), timeout kill (T14), static+tool isolation (T15), entrypoint override, no shell (T17), unavailable honesty + live negative (T16).
