# Assertara Autonomous Agent Execution System

End-to-end path: agent proposal → investigation → mandate + policy checks →
execution decision → controlled signer → Anvil execution → receipt
verification → evidence record.

The browser extension is out of scope for this phase. Nothing here changes
browser hooks, bridges, popups, or screenshots.

## 1. Architecture and trust boundaries

Three mutually distrusting parties plus one trusted operator:

| Party | Trust | Secrets held |
|---|---|---|
| AI agent | Untrusted. Proposes transactions only. Its intent labels are claims checked against decoded facts, never believed. | None. |
| Policy service (`src/server.js` + `src/controllers/agentController.js`) | Trusted to investigate and decide. Holds approval-issuing power but never sees the signing key. | `APPROVAL_SECRET`, `OPERATOR_SECRET` (verifier). |
| Controlled signer (`src/signer/server.js`, separate OS process) | Trusted to verify and sign. Trusts nothing except approval HMACs, exact transaction bytes, its own mandate copy, and chain RPC reads. | `APPROVAL_SECRET` (verifier), `OPERATOR_SECRET` (verifier), `SIGNER_PRIVATE_KEY`. |
| Operator | Trusted out-of-band. Authors the mandate file, holds `OPERATOR_SECRET`, authorises REVIEW decisions. | `OPERATOR_SECRET` (presenter). |

Key separations enforced in code, not just naming:

- The signing key exists only in the signer process closure
  (`src/signer/signerService.js`). It is never returned, logged, or
  transmitted. `/health` exposes the address only.
- The policy service cannot sign: it issues HMAC approval tokens but holds
  no key. The signer cannot approve: it verifies tokens but issues none.
- Muse Spark (`src/services/reasonerService.js`) assists investigation and
  explanation. Its verdict feeds the policy composer; it cannot authorise
  execution and cannot override a BLOCK.
- Agent-supplied JSON is never treated as a mandate. The mandate loads from
  the operator-owned `MANDATE_FILE` at startup (`src/server.js`,
  `src/signer/server.js`). There is no endpoint that changes it.

## 2. Agent interface and request schema

Base: policy service. All agent routes fail closed with 503 when
`APPROVAL_SECRET` is unconfigured.

- `POST /api/v1/agent/propose`
  - Request: `{ agentId?, intent?: { purpose?: string<=2000 }, transaction: {...} }`.
  - `transaction.from` (valid address), `transaction.to` (valid address,
    contract creation refused), `transaction.chainId` (numeric quantity)
    are required. `value`/`data`/`nonce`/`gas`/`gasPrice`/`maxFeePerGas`/
    `maxPriorityFeePerGas`/`type` validated as quantities/hex when present.
  - `screenshot` in a proposal is rejected (400): genuine visual capture is
    Assertara-operated, and code-only proposals carry none. Visual analysis
    for agent requests is recorded as `NOT_APPLICABLE`, distinct from
    unavailable evidence a required check needs (which yields UNCERTAIN).
  - Behaviour: assigns `requestId` (`agent_<uuid>`), preserves the exact
    normalized payload, computes `txDigest`, runs investigation, evaluates
    the mandate, composes the decision, and issues an approval token only
    for ALLOW (or a pending token for REVIEW).
  - Response: `{ requestId, decision, reasons, txDigest,
    mandate: {id, version}, policyId, approval|null,
    operatorAuthorizationRequired, operatorAvailable, investigation:
    {evalId, verdict, reasoningOrigin, ruleFindings, safeguardTriggers},
    mandateChecks, visual, createdAt }`.
- `GET /api/v1/agent/requests/:id` — status, decision, reasons, approval
  token (only when complete), approval expiry, operator state, execution
  record (`execution: null` means NOT_RUN), visual marker.
- `POST /api/v1/agent/requests/:id/authorize` — operator release for REVIEW
  (`{ operatorSecret }`). Wrong secret → 403. Re-mints the token if it
  lapsed; idempotent while a live countersigned token exists.
- `POST /api/v1/agent/requests/:id/receipts` — report `{ txHash }` after
  signing; the record is verified from chain RPC, never trusted from the
  reporter. 409 when no complete approval exists or a different execution
  is already recorded; idempotent for the same hash.
- `POST /api/v1/internal/signer-callback` — signer delivery notification,
  HMAC-authenticated (`signer-delivery:nonce:txHash`).
- `GET /api/v1/agent/mandate` — mandate id/version/issuer/validity/chains
  only. No recipients, spenders, limits, or secrets.

## 3. Investigation pipeline

`handlePropose` reuses the Phase-1 pipeline in-process
(`src/controllers/evaluateController.js`): deterministic EVM decoding →
transaction-digest binding → Muse Spark semantic reasoning → deterministic
intent comparison → five ordered verdict safeguards → visual-confidence cap
→ Foundry simulation for suspicious transactions → policy composition →
evidence bundle. Agent purpose text enters as untrusted page context
(`[agent-asserted]`, `agent:proposal`).

A `MATCH` verdict means only that investigated intent and transaction
evidence satisfy the comparison logic. It does not establish
authorisation. Authorisation comes from the mandate plus the composed
decision below.

## 4. Mandate authorisation model

File: operator-owned JSON at `MANDATE_FILE`, loaded and strictly validated
at startup by `loadMandate` (`src/services/mandate.js`), and sealed by
the operator key (`assertara-mandate-seal-1`, §10). Missing keys
default to most restrictive; an absent, invalid, or unverified mandate
fails closed (every proposal becomes UNCERTAIN).

Enforced constraints (`evaluateMandate`, all BigInt integer-safe, no price
conversion anywhere):

1. Liveness: `notBefore <= now < expiresAt`, else BLOCK. Version in
   `revokedVersions` → BLOCK.
2. Chain: proposal chain must be listed with an http(s) `rpcUrl`, else
   BLOCK.
3. Sender: must equal a listed sender AND the mandate `signerAddress`,
   else BLOCK.
4. Recipient: deny-list hit → BLOCK; allow-list miss → BLOCK.
5. Native transfers: `allowNativeTransfer` false → BLOCK;
   `value > maxNativePerTxWei` → BLOCK; spending windows checked against
   the verified-native-only ledger (ledger unavailable/unreadable →
   UNCERTAIN; window breach → BLOCK).
6. Contract calls: target must be in `contracts.allow`; selector
   (`data[0:10]`) must be in `selectors.allow`; calldata must decode to a
   known function or the result is UNCERTAIN.
7. Approvals (`approve`/`setApprovalForAll`/`permit`/`permitTransferFrom`):
   unlimited allowance BLOCKed unless `approvals.allowUnlimited`;
   `setApprovalForAll(true)` BLOCKed unless `approvals.allowOperatorAll`;
   spender/operator must be in `approvals.spenderAllowlist`.
8. Review rules: `nativeValueAboveWei` and `selector` matches → REVIEW.
9. Policy version: `assertara-agent-mvp-1`, pinned in approvals and
   re-checked by the signer against its own mandate copy.

Spending accounting covers verified native transfers only (receipt
status `0x1`). ERC-20 amounts are not totaled (no token metadata is
fetched); approvals are structurally restricted instead. Any corrupt
spending-ledger line fails the whole load so limits can never silently
undercount.

## 5. Execution decisions

`combineDecisions` (agent controller) composes the investigation decision
with the mandate decision: BLOCK > UNCERTAIN > REVIEW > ALLOW. Both sides
must be clean for ALLOW.

- ALLOW: within the active mandate, all mandatory checks passed, no
  further authorisation required. Proceeds automatically through the
  controlled path. No human per-transaction approval.
- BLOCK: mandatory prohibition violated. Refused. Muse Spark cannot
  override.
- REVIEW: mandate or policy requires operator authorisation. Held until
  `.../authorize` releases it.
- UNCERTAIN: a required check, evidence source, or verification step is
  unavailable or inconclusive. Never executed through the controlled path.

## 6. Controlled signer

Process: `node src/signer/server.js` (env: `APPROVAL_SECRET`,
`MANDATE_FILE`, `SIGNER_PRIVATE_KEY` required; `OPERATOR_SECRET` required
to honour operator-authorized approvals). Endpoints: `GET /health`,
`POST /sign`.

`verify()` (stateless, no chain I/O) independently checks: request id
match, approval HMAC/expiry/decision, mandate id+version match against its
own copy, mandate liveness, operator countersignature when required,
recomputed `digestTx(transaction)` equality with the approved digest,
permitted chain, chain-approval consistency, sender equals the signer key
and the approval sender, and a well-formed recipient.

`execute()` serializes the critical section (sign lock), rechecks
single-use, persists consumption BEFORE broadcast (a crash burns the
approval but can never allow a replay), signs and broadcasts the exact
approved fields verbatim (absent nonce/gas/fees filled deterministically;
legacy and EIP-1559 only), waits up to 60s for the receipt, verifies
receipt status plus the native recipient balance delta, and best-effort
notifies the policy callback.

The signer refuses missing, malformed, mismatched, expired, revoked,
replayed, or unauthorised requests. Any change to a security-relevant
transaction field changes the digest and invalidates the authorisation.

## 7. Bypass, replay, mutation, and fail-open prevention

- No alternate signing route inside the execution boundary: the demo agent
  holds no key; the only key lives in the signer process.
- Fail-closed triggers (all refuse execution): investigation failure,
  incomplete mandatory check, mandate verification failure, digest
  mismatch, expired/revoked mandate, missing operator authorisation,
  signer unavailability, malformed or replayed request.
- Replay: single-use nonces persisted before broadcast; reused approval →
  `approval already consumed`.
- Mutation: digest recomputed at the signer over the exact bytes; +1 wei
  or any field change → `transaction does not match the approved digest`,
  consuming nothing.
- Forgery: approvals are HMAC-SHA256 under a server-side secret with
  constant-time verification; the agent never sees any secret.
- Execution records: verified from mandate-chain RPC
  (`eth_getTransactionReceipt` + `eth_getTransactionByHash`), comparing
  from/to/value. Outcomes: `EXECUTED` (status `0x1`), `FAILED`,
  `MISMATCH`. Malformed proposals are `REJECTED`; requests that never run
  keep `execution: null` (NOT_RUN). Nothing simulated or mocked is
  labelled as executed; simulation absence is `NOT_RUN`.
- Single broadcast path: `sendTransaction` exists only in
  `src/signer/signerService.js`, reachable only via approval-gated
  `POST /sign`. The evaluation API issues no approvals; agent responses
  carry no key material; smuggled mandate/operator/approval fields are
  ignored. Coverage: `test/unit/enforcement.test.js`.
- Dev-chain restriction: the signer boots only when every mandate chain
  is 31337 over a loopback RPC URL; mainnet, public testnets,
  non-loopback RPC, and empty chain lists refuse startup. Enforcement
  lives in the signer, not in policy text.
- Bypass precision: the demonstrator agent holds no key and can submit
  only through the controlled interface. An external wallet Assertara
  does not control is outside the boundary by definition — refusal of
  the controlled path cannot stop it, and no claim here says otherwise.

## 8. Execution and verification

Local development uses Anvil (`chainId 31337`) and a development key
derived from Anvil's documented default mnemonic at test time — never
hardcoded, never a real wallet or real funds. The e2e suite
(`test/e2e/agentFlow.test.js`) boots real Anvil, a real policy app, and a
real signer process; the ONLY mock is the model transport (canned
MATCH/UNCERTAIN verdicts, labelled MOCK in code and logs). Every security
property — mandate enforcement, digest binding, single-use, operator
gating, broadcast, receipt verification — runs against genuine components
and a live chain.

Scenarios: A (permitted action executes, real receipt recorded), B
(prohibited action blocked, signer refuses, chain untouched), C (mutated
payload refused, original still executes, replay refused), D
(inconclusive investigation held, no execution), E (REVIEW held until
operator authorises, then executes; receipt reporting idempotent).

Run: `npm run test:e2e` (requires Anvil on PATH and localhost listen;
sandboxed shells block this — run unsandboxed). Unit suites:
`npm run test:unit`. Full chain: `npm test`.

## 9. Persistence and restart recovery

Durable file-based stores (no database dependency; matches the existing
JSONL-ledger stack):

- Policy request store (`AGENT_SNAPSHOT_FILE`, default
  `data/agent-requests.json`): requests, digests, decisions, policy
  versions, approvals, tx hashes, verified receipts, outcomes, and the
  last-seen mandate version. Written atomically (tmp file + rename).
  The append-only audit JSONL remains best-effort explanation.
- Signer replay store: HMAC-chained append-only consumption log (every
  line carries a monotonic seq + MAC over the previous MAC) plus a
  separate integrity anchor (`SIGNER_ANCHOR_FILE`, default next to the
  log) recording the last trusted tip. A small continuity state file
  records the last-boot mandate id/version for rollback detection.
- Spending ledger: append-only JSONL of verified native spends, replayed
  at boot; any corrupt line fails the whole load.

Failure behaviour: a corrupt snapshot, a missing snapshot with a
non-empty audit trail, or a corrupt signer log/state refuses to serve
(agent endpoints 503; signer refuses startup) — never a silent clean
slate. Deletion or rollback of the consumed log alone is detected via
the anchor and refuses startup; only an operator recovery ceremony can
re-trust state, and only forward (re-anchoring down is refused even by
the recovery tool). Same-mandate-id version rollback across restart is
rejected on both services; rotation to a new mandate id is allowed.
Receipt recording is serialized per request and idempotent; spending
dedupes by request/tx; a consumed approval can never become reusable;
EXECUTED is reported only from a verified status-`0x1` receipt.
Interrupted executions (approved, nothing recorded) restart as explicit
NOT_RUN and must reconcile against chain RPC before any claim. Restart
coverage: `test/unit/persistence.test.js` (8 scenarios) and
`test/unit/replay.test.js` (10 scenarios).

## 10. Mandate seals and operator recovery ceremonies

Mandate seal (`assertara-mandate-seal-1`): EIP-191 personal-sign
(secp256k1 via viem) over the canonical mandate body
(`assertara-mandate-body-1`: explicit field order over the exact
normalized enforcement values, so no component can interpret the sealed
bytes differently). Seal block: `{format, authority, algorithm,
signature}` embedded top-level in the mandate file. Both services verify
format, algorithm, authority membership, and the signature; either of
them rejects unsigned, tampered, foreign-authority, or malformed seals,
and both refuse to authorize without configured authority lists
(`TRUSTED_MANDATE_AUTHORITIES`, `SIGNER_TRUSTED_MANDATE_AUTHORITIES`).
Expiry and revocation ride inside the sealed bytes and stay enforced by
the existing liveness checks. Coverage: `test/unit/mandateSeal.test.js`.

Key custody: the operator sealing key exists only for the ceremony
(`OPERATOR_SIGNING_KEY=... npm run seal-mandate -- <file>`, which backs
up `<file>.bak` and re-seals in place). It never lives on the policy
server, signer, agent, or browser. Authority addresses enter each
service out-of-band via env config; adding or rotating an authority is
an operator config change plus restart on both services. No
hardware-backed key security is claimed for the demonstrator.

Migration: unsealed legacy mandates are rejected with an explicit
"not sealed" error wherever authorities are configured — never silently
trusted. Migrate by sealing the existing file with the ceremony above;
verify with `test/unit/mandateSeal.test.js` semantics (seal verifies,
enforcement unchanged). Pre-chain consumed logs migrate with
`node src/signer/recover.js --import-legacy --confirm` (adopts existing
consumptions forward into chained format; migrate only a log trusted
complete, or rotate credentials instead).

Recovery procedure (replay continuity): if the signer refuses startup,
run `node src/signer/recover.js --status` to inspect log vs anchor.
Re-anchor (`--reanchor --confirm`, needs `OPERATOR_SECRET`) only after
confirming no unexpired consumed approval exists — wait out
`APPROVAL_TTL_MS`, or rotate `APPROVAL_SECRET` and bump the mandate
version to void everything. Every recovery is audit-logged next to the
anchor. If the log is behind its anchor (records lost), the tool
refuses: restore the log from backup or rotate credentials; there is no
safe way to forget consumptions.

Trust assumptions: the chained log + anchor defeat crashes, partial
writes, operator error, silent loss, and attackers who can delete,
corrupt, or restore individual files but cannot forge HMACs (they lack
`APPROVAL_SECRET`) or mandate seals (they lack the operator key).
Residual: an attacker who rewrites every local file AND holds the
secrets, or who deletes both log and anchor (indistinguishable from
first boot), is outside the mechanism — contained operationally by
short approval TTLs and mandate rotation, stated here instead of
claimed away.

## 11. Live Muse Spark validation record (2026-10-29)

- Endpoint `https://api.meta.ai/v1/chat/completions`, requested model
  `muse-spark-1.3`; provider-returned model id verified as exactly
  `muse-spark-1.3` (HTTP 200, ~10-26s for minimal calls).
- Full production reasoner path (`evaluateSemanticDiscrepancy` + schema
  validator) returned genuine model verdicts twice: MATCH/0.85 in
  ~26s and ~18s, `origin=model`, schema valid.
- One full-prompt call exceeded the 60s default timeout and degraded
  honestly to `heuristic-fallback` with `timeout:true` (operator-gated
  REVIEW downstream, never auto-ALLOW). Live latency is high-variance;
  the gated live test allows 180s for its single call.
- Committed live test: `test/live/museLive.test.js` (`npm run test:live`),
  gated on `LIVE_MODEL_TESTS=1` plus a real key; it skips with exit 0 and
  zero network calls otherwise, and is NOT part of `npm test`.
- Deterministic model-authority invariants stay covered without network:
  BLOCK dominates MATCH (`policyDecision` T1), mandate supremacy over
  MATCH (`agent` T3), missing mandate/ledger → UNCERTAIN (`agent` T7,
  `mandate` T6), malformed output and bad confidence → honest fallback
  (`reasoner` T6/T13/T14), timeout → flagged fallback (`reasoner` T8/T9),
  confidence 1.0 cannot override (`policyDecision` T9).

## 12. Remaining trust assumptions and limitations

- The operator's mandate file, secrets, and machine are trusted. A
  compromised `APPROVAL_SECRET` forges approvals; a compromised
  `OPERATOR_SECRET` releases REVIEW decisions; a compromised
  `SIGNER_PRIVATE_KEY` signs arbitrarily. Secret rotation is manual
  (restart both processes with new values).
- The mandate file is read at startup; mid-run edits require a restart of
  the policy service AND the signer to take effect consistently.
- Request records persist in the atomic snapshot (§9); only transient
  investigation scratch stays in memory. A policy-service restart
  restores decisions, approvals, and execution records.
- Deleting or rolling back the consumed log alone is detected by the
  replay anchor and refuses startup (§9–§10). The remaining residual is
  total local rewrite (every file plus the secrets) or deletion of both
  log and anchor at once (first-boot ambiguity) — contained by short
  approval TTLs and mandate rotation, not claimed away.
- Spending limits cover native value only, not ERC-20 value.
- Chain RPC endpoints named in the mandate are trusted for receipt truth.
- Protection holds within the stated execution boundary: an agent with an
  independent external wallet or key outside Assertara's control is not
  constrained by it. This document claims nothing beyond the controlled
  path.
- Mandate authorization is cryptographic (§10). The demonstrator uses a
  software operator sealing key with no hardware backing; production
  should move sealing to an HSM or equivalent and add multi-authority
  quorum if required.
- Fork simulation is not implemented (`forge test`, no `--fork-url`).
- The e2e suite needs Anvil plus localhost networking and cannot pass in
  a sandbox that denies either.

## 13. The `agent/` subsystem (autonomous agent milestone)

Everything above describes Assertara's side (investigate, decide,
approve, sign). The `agent/` directory is the other side: a genuine
autonomous agent that lives in this repo but is architecturally
independent of Assertara's internals.

- Structure: `agent/runtime/` (lifecycle + task journal),
  `agent/planner/` (live model planning, v2 multi-action),
  `agent/reasoning/` (conservative action selection),
  `agent/transaction-builder/` (exact tx assembly),
  `agent/integrations/` (sole SDK touchpoint),
  `agent/reporting/` (genuine stage log).
- Boundary (mechanically enforced by
  `test/unit/agentBoundary.test.js`): `agent/` imports only `sdk/`,
  the shared digest helper, and Node builtins; only
  `agent/integrations/assertara.js` imports the SDK. The agent holds
  no signing key, no approval/operator secrets — only an inference
  API key, which authorizes nothing.
- Workflow per action: plan → build exact tx → SDK submit →
  genuine progress → published decision → ALLOW executes via the
  controlled signer (REVIEW waits out-of-band); BLOCK/UNCERTAIN ends
  the task with no resubmission or reroute; unclean executions halt
  further actions.
- Demonstrations (`node demo/agentDriven.js [a|b|both]`, live model):
  Demo A pays an authorized contributor 0.005 ETH (ALLOW →
  EXECUTED, receipt verified); Demo B attempts an off-mandate
  payment (BLOCK, nothing signed, chain untouched). Both share
  requestId/traceId/txHash with the Command Centre views.
- Planner reasoning and Assertara findings are recorded separately
  and never conflated: the former is the agent's own words about
  what to do; only the latter bears on authorization.

## 14. Visual Evidence Posture — Step 5: CLOSED, NOT APPLICABLE

The current autonomous agent is transaction-oriented, not
browser-operated: it maps task text to exact Ethereum transactions
(`agent/planner/` → `agent/transaction-builder/` → SDK submit) and
interacts with no website, page, or visual interface. There is no
browser, Playwright/Puppeteer/CDP, or page automation anywhere in the
agent runtime or its dependencies. Consequently there is nothing for
Assertara to screenshot-capture on the agent's behalf, and SAM 3.1
cannot genuinely be invoked in the current agent workflow.

Enforced posture (locked by `test/unit/agentVisualEvidence.test.js`):

- Agent-supplied screenshots remain rejected: proposals carrying a
  `screenshot` field fail closed with the v1 message
  (`src/controllers/agentController.js` validation). Agent bytes can
  never become trusted visual evidence.
- Agent-path records carry `samProvenance.status === 'skipped'`
  (null digests, zero detections, empty prompt history) whenever no
  genuine visual evidence exists — the assembler default when no
  screenshot is supplied, never a success claim.
- Phase 2 manifests derive `sam.contribution === 'NOT_INVOKED'`
  from such records, and `verifyPackage` re-derivation rejects any
  package that claims SAM success on them.
- Step 4 model-bitmap bit 1 (SAM 3.1) is set only for actual
  successful contribution levels (`SUCCEEDED`, `OUTPUT_INCLUDED`,
  `PROMPT_INCLUDED`, `VALIDATED_AGAINST`) — never for configured,
  invoked-only, skipped, mock, or failed states. Agent-path
  manifests therefore always leave bit 1 clear. The Step 6
  publisher owns the executable derivation of this rule.
- Browser-based SAM functionality is unaffected: screenshot-bearing
  browser evaluations still run segmentation + OCR, with
  unconfigured-provider output honestly classified `MOCK` (never
  genuine success) and live output flowing through the normal
  contribution levels.

A browser actuator — an Assertara-owned controlled browser the agent
drives, with Assertara-operated CDP capture bound to requestId and
transaction digest — remains a possible future capability. It does
not exist in this codebase and must not be described as present.
Step 5 is therefore closed as not applicable to the current
transaction-agent architecture, not as completed integration.
