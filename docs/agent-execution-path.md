# Assertara Agent Execution Path Map

Traced from the actual production code (not diagrams). Every stage below
names its source file and function. Telemetry component ids in brackets
are the live spans shown in the command centre (`/command/`).

## 0. Entry: agent proposal API

`POST /api/v1/agent/propose` → `src/controllers/agentController.js`
`handlePropose` [agent-receiver]

1. Service/store availability gates (503 fail-closed).
2. Mandate seal verification (`verifyMandateSeal`): authority + version.
3. Proposal validation (`validateProposal`): objective, tx fields, evidence
   envelope shapes. Malformed → 400, no investigation.
4. Transaction normalization + canonical digest (`digestTx`).
   Unrepresentable → 400. The digest binds everything downstream.
5. Request record created (`agent-requests.json` + ledger event RECEIVED).

## 1. Investigation (in-process, same request)

`runInvestigation` → `handleEvaluateTransaction` (`src/controllers/evaluateController.js`)

| # | Stage | Code | Telemetry |
|---|-------|------|-----------|
| 1.1 | Mandate-RPC chain state (target+sender, exact chain) | agentController → `fetchChainState` | chainstate |
| 1.2 | Agent evidence admission (typed, forced UNTRUSTED) | `admitAgentEvidence` | agent-evidence |
| 1.3 | Deterministic EVM decode + security rules | `decodeTransactionCalldata` | decoder |
| 1.4 | Screenshot: SAM 3.1 regions (genuine only) | `segmentUiRegions` | sam (SKIPPED: agent path) |
| 1.5 | OCR over genuine regions / full-scan fallback | `extractUiTexts` | ocr (SKIPPED: agent path) |
| 1.6 | Region↔OCR join + association + action elements | `associateRegions`, B10 | visual-association (SKIPPED: agent path) |
| 1.7 | Chain state (injected from 1.1 on agent path) | `fetchChainState` | chainstate |
| 1.8 | Freshness (agent: current-by-construction) | `evaluateFreshness` | freshness |
| 1.9 | Counterparty HINT labels | `resolveCounterparties` | counterparty-labels |
| 1.10 | Pre-reasoning simulation (triggered only) | `runSimulationEvidence` | simulation-pre |
| 1.11 | Chain verification (balance/nonce/code/freshness) | `verifyChainEvidence` | chain-verification |
| 1.12 | Proxy detection + implementation resolution | `fetchProxyEvidence` | proxy-resolution |
| 1.13 | Chain-scoped contract identity (4byte+Sourcify concurrent) | `resolveContractIdentity` | contract-identity |
| 1.14 | Nested-call tree + unknown-inner status | `buildSubcallTree` | subcalls |
| 1.15 | Deterministic evidence-graph edges | `buildDeterministicEdges` | evidence-graph |
| 1.16 | Economic-effect reconstruction (EF-xxx) | `reconstructEffects` | effects |
| 1.17 | Batch composition (approve→spend, fan-out…) | `analyzeBatchComposition` | composition |
| 1.18 | Bridge terms (Across V3 / CCTP V1 only) | `analyzeBridge` | bridge |
| 1.19 | Approval necessity + duration | `analyzeApprovalNecessity` | approval-necessity |
| 1.20 | Deadline / expiry interpretation | `analyzeDeadlines` | deadlines |
| 1.21 | Bounded transaction-history context | `buildSequenceContext` | history |
| 1.22 | Verbatim explicit-intent quotes [EI-xxx] | `extractExplicitIntent` | explicit-intent |
| 1.23 | Evidence packing (bounded, prioritized) | `packEvidence` | evidence-packer |
| 1.24 | Prompt selection (investigate-2.7, browser/agent) | `selectSystemPrompt` | prompt-select |
| 1.25 | **Muse Spark investigation (ONE call, no prod retry)** | `evaluateSemanticDiscrepancy` | muse-spark |
| 1.26 | Schema validation of model output | `validateModelResult` | reasoning-validation |
| 1.27 | Reference grounding / fabrication check | `validateInvestigation` | reference-validation |
| 1.28 | Requested-vs-actual comparison (incl. effect:*) | `buildIntentComparison` | comparison |
| 1.29 | Quote entailment + conclusion support | `validateSupport` | support-validation |
| 1.30 | Mechanism reconciliation (precedence rules) | `reconcileMechanisms` | reconciliation |
| 1.31 | Falsifiable semantic-claim checks | `verifySemanticClaims` | semantic-claims |
| 1.32 | Visual-role cross-check | `crossCheckVisualRoles` | visual-role-check |
| 1.33 | Model edge admission (grounded only) | `validateModelEdges` | evidence-graph |
| 1.34 | 16 ordered verdict safeguards (MATCH-only) | `applyVerdictSafeguards` | safeguards |
| 1.35 | Post-reasoning simulation (MISMATCH only) | `runSimulationEvidence` | simulation-post |
| 1.36 | Policy decision (ALLOW/BLOCK/REVIEW/UNCERTAIN) | `composePolicyDecision` | policy-decision |
| 1.37 | Evidence bundle compilation | `compileEvidenceBundle` | evidence-bundle |
| 1.38 | Investigation persistence (model-origin only) | `persistInvestigation` | persistence |

## 2. Authorization (agent controller resumes)

| Stage | Code | Telemetry |
|-------|------|-----------|
| Recursive mandate evaluation (B1: every inner op) | `evaluateMandate` | mandate-eval |
| Decision combination (investigation × mandate) | `combineDecisions` | (in mandate-eval span window) |
| Subcall-tree hash binding | `hashSubcallTree` | subcall-bind |
| Authorization-time effect reconstruction | `reconstructEffects` | effects |
| Approval issuance (ALLOW) / pending (REVIEW) | `issueApproval` | approval-issue |
| Request record → DECIDED + ledger event | agent store | (in approval span window) |
| Structured response + `traceId` | `handlePropose` | agent-response |

BLOCK/UNCERTAIN issue no approval. REVIEW issues operator-gated
pending approval. The agent learns nothing secret beyond its own token.

## 3. Signing (separate process + trust boundary)

`src/signer/server.js` `POST /sign` → `signerService.execute`:

1. Approval HMAC verification (request, digest, mandate version,
   expiry, single-use, subcall binding).
2. Chain/sender/type restrictions (local Anvil only in this phase).
3. Replay-consumption persistence BEFORE broadcast (fail-closed on
   rollback/deletion/ambiguity).
4. Broadcast → `waitForTransactionReceipt` → balance-delta check.
5. Callback to policy app (`/api/v1/internal/signer-callback`,
   HMAC-guarded) → `recordExecution`.
6. Telemetry: the signer exposes outcomes only
   (`ok/txHash/receipt/verification`, refusal strings). Its internal
   check sequence is deliberately NOT live-instrumented — the trust
   boundary stays closed. Client-measured round-trip appears in the
   runner/UI, labeled as such.

## 4. Execution recording (policy app callback)

`recordExecution` (`agentController.js`):

1. Receipt re-fetch from chain RPC + field equality vs approved tx
   → MISMATCH/pending/unavailable handling [receipt-verify].
2. B7 log reconciliation vs decision-time authorized effects →
   EXECUTED / EXECUTED_UNVERIFIED / EFFECTS_DIVERGED [effect-verify].
   Reverted → FAILED (effect-verify SKIPPED: no logs to reconcile).
3. Spending-ledger append (idempotent), status update, ledger event.

## 5. Agent reads the result

`GET /api/v1/agent/requests/:id` → decision, reasons, mandate checks,
investigation summary (verdict/origin/findings/safeguards), execution,
receipt. REVIEW → `POST .../authorize` (operator secret, never in the
browser UI) → approval → sign → callback → recorded.

## Concurrency in the pipeline

Real overlaps (shown accurately by span timestamps, never staged):
- Selector-signature + Sourcify lookups inside contract identity.
- Chain events + priors fetch inside history assembly.
Everything else on the request path is sequential.
