# Assertara Agent API Contract (v1)

External integration contract for autonomous agents. This document pins
request/response shapes, lifecycle, auth, errors, and polling semantics
for the agent API and the controlled signer. Capability 1–5 behavior,
mandate/policy logic, and the signer are unchanged by this contract —
it exposes them, it does not modify them.

Base URLs (deployment-specific):

- Policy service: `http://HOST:PORT` (agent + observations APIs)
- Controlled signer: separate process and secret set (`/health`, `/sign`)

All JSON. Timestamps are ISO-8601 (`createdAt`) or epoch ms where noted.

## 1. Authentication and isolation

- Agent endpoints (`/api/v1/agent/*`) and investigation observations
  require `Authorization: Bearer <keyId>:<secret>` when the service is
  started with `AGENT_API_KEYS` / `AGENT_API_KEYS_FILE` (production).
- Keys identify integrations for rate-limiting, audit, and ownership
  scope. **Keys never authorize transactions.** Decisions come only
  from mandate + policy + signer verification.
- Ownership: every request is stamped with its submitting key. Status,
  receipts, evidence, trace, and stream reads are owner-scoped; foreign
  or unknown ids both answer `404` (ids are not oracle-able).
- Without keys the agent API is open ONLY with explicit
  `AGENT_AUTH_MODE=development` (local work, loud warning); otherwise
  it answers `503`.
- Operator release (`.../authorize`) authenticates ONLY by
  `OPERATOR_SECRET` and is never part of the agent SDK surface.
- The signer callback authenticates by HMAC and is signer→policy only.

## 2. Submission

### `POST /api/v1/agent/investigations` — async submit (primary)

Request: `{ agentId?, intent?: { purpose?: string<=2000 }, transaction: {...}, evidence?: [...] }`.

- `transaction.from/to` valid addresses (`to` required; contract
  creation refused), `chainId` numeric quantity required,
  `value/data/nonce/gas/fees/type` validated when present.
- `evidence` (optional): ≤50 typed envelopes, ≤256 KiB total.
- `screenshot` in a proposal is rejected (`400`).
- `Idempotency-Key` header (optional, `1-128` chars
  `[A-Za-z0-9._~:-]`): same key + same proposal (digest + purpose)
  replays the stored record instead of spending a second
  investigation; same key + different proposal is `409`.

Responses:

- `202 { requestId, traceId, txDigest, status: "INVESTIGATING", replayed: false }`
- `200` + full status record + `replayed: true` for a terminal
  idempotent replay (header `Idempotent-Replayed: true`).
- `409 { error, requestId }` when the key already has a run in flight
  (poll that requestId); `409` without `requestId` on key reuse with
  a different proposal.
- `429 { error, retryAfterMs }` when investigation capacity is full.
- `400/401/503` per §7.

### `POST /api/v1/agent/propose` — sync submit (backward compatible)

Same request contract. Holds the connection and answers `200` with
the full decision record (same shape as before this milestone).
Prefer `investigations` when progress visibility matters.

## 3. Lifecycle and status

### `GET /api/v1/agent/requests/:id`

Status values: `RECEIVED → INVESTIGATING → DECIDED → APPROVED →`
`EXECUTED | EXECUTED_UNVERIFIED | EXECUTION_DIVERGED | FAILED |
EXECUTION_MISMATCH`; `REJECTED` for malformed transactions.

Response (terminal records keep their exact existing fields):

```json
{
  "requestId": "agent_…", "status": "APPROVED", "decision": "ALLOW",
  "reasons": ["…"], "txDigest": "…", "traceId": "tr_…",
  "investigation": { "evalId": "eval_…", "verdict": "MATCH", "reasoningOrigin": "model", "ruleFindings": [], "safeguardTriggers": [] },
  "mandate": { "id": "…", "version": 1 },
  "approvalToken": "apv1.…",
  "approvalExpiresAt": 1767225900000,
  "operatorAuthorizationRequired": false, "operatorAuthorized": false,
  "execution": null, "visual": { "status": "NOT_APPLICABLE" },
  "createdAt": "…", "updatedAt": "…"
}
```

While running (`decision: null`, `status: RECEIVED|INVESTIGATING`)
the response additionally carries genuine progress:

```json
{ "stage": "muse-spark", "progress": { "spansCompleted": 24, "spansTotal": 25, "traceStatus": "RUNNING",
  "museSpark": { "state": "running", "ms": null, "summary": null, "usage": null, "servingModelId": "muse-spark-1.3", "attempts": 1, "timeouts": 0 } } }
```

`stage` is the currently executing component (or `finalizing`);
`museSpark.state` is `pending|running|completed|failed|skipped`.
When the trace has expired from the bounded ring, `stage` is
`"unknown"` with `progress: null` — the API reports ignorance, it
never invents activity. Terminal records carry no `stage`/`progress`.

Interrupted runs (restart, TTL expiry) fail closed to `UNCERTAIN`
with an explicit re-propose reason; they never resume and never ALLOW.

### `GET /api/v1/agent/requests/:id/evidence`

Stable SDK envelope for decided requests (`409` while running):

`{ v: 1, requestId, decision, reasons, txDigest, traceId, evalId,
investigation: { evalId, verdict, reasoningOrigin, ruleFindings,
safeguardTriggers }, mandateChecks: [{ id, pass, detail }] }`.

## 4. Decisions

- The executable states are `ALLOW` with a complete `approvalToken`,
  and `REVIEW` AFTER out-of-band operator release (usable
  `approvalToken` present). Nothing else executes, ever.
  Clients must re-read status immediately before signing (mandates
  rotate, approvals expire) and must verify the local transaction
  digest equals the record `txDigest`.
- `BLOCK` and `UNCERTAIN` never execute. `REVIEW` without a usable
  token never executes.
- `REVIEW` releases ONLY through `POST .../authorize` with the
  operator secret (out-of-band; see §1). The agent polls until
  `approvalToken` appears.

## 5. Execution and receipts

### Signer `POST /sign` — `{ requestId, transaction, approval }`

The signer independently verifies: approval HMAC/expiry/decision,
mandate id+version against its own copy, mandate liveness, operator
countersignature when required, recomputed digest equality,
subcall-tree binding, chain, sender-is-signer-key, and single-use
(persisted BEFORE broadcast). Refusals answer `403` (or `400` for
malformed input, `502` for chain errors). Success:
`{ ok: true, txHash, receipt, verification }`.

### `POST /api/v1/agent/requests/:id/receipts` — `{ txHash }`

Fallback path (normally the signer callback records execution).
The server re-reads the chain and compares from/to/value; outcomes:
`EXECUTED` (status `0x1` + effects matched), `EXECUTED_UNVERIFIED`,
`EFFECTS_DIVERGED`, `FAILED` (reverted), `MISMATCH` (fields differ).
Only `EXECUTED` is a clean result. `404` means receipt-not-found-yet
(retry after inclusion); `409` means a different execution is already
recorded or no complete approval exists.

## 6. Observations (read-only, auth + owner-scoped)

- `GET /api/v1/observations/traces` — own traces only.
- `GET /api/v1/observations/traces/:id` — span snapshot (also served
  mid-run: this is the polling visibility path).
- `GET /api/v1/observations/traces/:id/stream` — SSE: replayed
  history, then live `span-start` / `span-finish` / `trace-finish`
  events, then `stream-end`. Genuine recorded events only.
- `GET /api/v1/observations/investigations/by-eval/:evalId` — full
  model-origin bundle (404 otherwise).
- `GET /api/v1/observations/scenarios` — static demo scenario
  definitions (open, no investigation data).

Snapshots carry no secrets (tokens/keys redacted at record time).

## 7. Errors, timeouts, polling

| HTTP | Meaning | Client action |
|---|---|---|
| 200 | Sync decision / replay / read | consume |
| 202 | Investigation accepted | poll status / stream trace |
| 400 | Malformed proposal/key/evidence | fix the request |
| 401 | Missing/invalid API key | check credentials |
| 403 | Operator auth failed / signer refused | do not retry blindly |
| 404 | Unknown id (or foreign owner) / receipt pending | check id / retry receipts later |
| 409 | Key reuse / run in flight / state conflict | poll `requestId` / fix key |
| 410 | Request expired | re-propose |
| 429 | Capacity full | wait `retryAfterMs`, retry same key |
| 502 | Chain RPC unavailable | retry later |
| 503 | Service unconfigured / store down | operator issue |

Recommended client bounds: submit 30s, sync propose 180s, status
2s interval with 180s decision ceiling, sign 90s, execution wait
90s, operator wait 120s. SSE reconnects with backoff; status polling
is always a valid substitute (traces are progress-only — the record
is the decision source of truth).

## 8. Enforcement boundary (normative)

- Every transaction sent through the guarded SDK is investigated;
  only ALLOW (or operator-released REVIEW) with a complete approval
  reaches the signer.
- Separately held external wallets and direct RPC signing paths are
  OUTSIDE the enforcement boundary. No claim in this contract states
  otherwise.
- API keys identify integrations; they never authorize transactions.
- Investigation progress shows genuine recorded activity only; model
  reasoning content is never streamed or fabricated — structured
  results publish on the terminal record.
