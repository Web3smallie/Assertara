# Evidence Assembly (Phase B)

How Assertara collects, validates, organises, and delivers evidence to
Muse Spark for investigation. Phase B closed the audit gaps: collected
evidence that never reached the model, unlabeled trust levels, unbounded
prompt growth, missing chain state, no freshness tracking, and static-only
counterparty identity.

## Pipeline

```
collect → validate → pack (budget) → reason → bundle → decide
```

1. **Collect** — `evaluateController.handleEvaluateTransaction` gathers:
   decoded transaction + findings, SAM regions, OCR text, page context,
   chain state (`chainStateService.fetchChainState`), freshness
   (`evidenceFreshness.evaluateFreshness`), counterparty labels
   (`counterpartyLabels.resolveCounterparties`), association info,
   summary/sam selection statuses.
2. **Validate** — each source records an explicit status
   (`ok` / `empty` / `unavailable` / `failed` / `stale` / `wrong-chain` /
   `partial`); malformed input is coerced or fails closed, never throws
   the pipeline.
3. **Pack** — `evidencePacker.packEvidence` builds the model prompt:
   every line carries a provenance tier tag, sections have char budgets,
   overflow is prioritised and recorded (see below).
4. **Reason** — `reasonerService` sends the pack to Muse Spark (or the
   deterministic fallback) and returns `evidencePacking { sent }` on
   every result path.
5. **Bundle** — `evidenceService.compileEvidenceBundle` persists the
   pack audit, chain state, freshness, and labels alongside the verdict.
6. **Decide** — policy consumes verdict + deterministic findings only.
   Labels, chain state, and freshness are advisory; they never move a
   decision (locked by `test/unit/evidenceAssembly.test.js` Test 10).

## Provenance tiers (prompt tags)

| Tag | Meaning | Examples |
|---|---|---|
| `[VERIFIED]` | Independently retrieved at investigation time | chain-state reads |
| `[DETERMINISTIC]` | Assertara decoder/rules output | decoded params, findings, ambiguity flags |
| `[RETRIEVED]` | Operator-configured data | counterparty labels (display hint only) |
| `[OBSERVED]` | Sensor output, may be wrong | SAM regions + confidence, OCR text |
| `[UNTRUSTED]` | Agent/user-supplied claims | page title/URL/text, intent |
| `[SYNTHETIC]` | Fallback-generated, not evidence | no-screenshot notices |
| `[HINT]` | Advisory context for the model | freshness, association, truncation notes |

Agent claims can never be promoted: tags are assigned by the packer from
the source, and hostile text (e.g. injected instructions) is passed
through as inspectable content, never executed (Test 11).

## Size management

`packEvidence` enforces per-section and total character budgets
(`DEFAULT_BUDGETS` in `src/services/evidencePacker.js`). On overflow,
lower-priority content is dropped first (DOM text → OCR → regions →
parameters), **finding ruleIds and severities are never dropped**
(descriptions compact first), and every omission is recorded twice:
an inline marker in the prompt (`[TRUNCATED …]`) and an entry in the
`withheld` accounting array persisted in the bundle. Oversized
title/URL/parameter JSON are capped at fixed lengths.

## Chain state

`fetchChainState({ rpcUrl, chainId, addresses, timeoutMs })` reads
`eth_chainId` (aborts with `wrong-chain` on mismatch — state from the
wrong chain is discarded, never mixed), then balance/nonce/code per
address at `latest`, recording block number + codehash (keccak256 of
returned code). Statuses: `ok`, `unavailable` (no endpoint / no valid
addresses), `timeout` (explicit race + abort), `rpc-error`,
`wrong-chain`. Browser path uses `EVIDENCE_CHAIN_RPC_URL`; the agent
path uses the mandate's chain RPC so state always matches the
investigated chain. Server-side only — never accepted from HTTP bodies.

## Freshness

`evaluateFreshness({ capturedAt, maxAgeMs })` → `fresh` / `stale` /
`unknown` (no timestamp) / `invalid` (unparseable or >2 min future
skew). Advisory only: stale evidence is labeled, never blocks
evaluation. Default window `SCREENSHOT_MAX_AGE_MS` (5 min).

## Counterparty labels

Static known-contract map merged with an operator JSON file
(`COUNTERPARTY_LABELS_FILE`, default `data/labels.json`):
`{ "<address>": "<display name>" }`. Malformed file fails closed
(static map still applies). Labels are display hints: they appear in
the prompt (`[RETRIEVED]`) and bundle, but never enter mandate,
policy, or decoder comparison.

## Configuration

See `.env.example` (Evidence Assembly section):
`EVIDENCE_CHAIN_RPC_URL`, `EVIDENCE_CHAIN_TIMEOUT_MS`,
`SCREENSHOT_MAX_AGE_MS`, `COUNTERPARTY_LABELS_FILE`.

## Tests

- `test/unit/evidenceAssembly.test.js` (12 tests): packing tiers,
  legacy-line preservation, overflow priority, region/OCR states,
  malformed input, chain statuses (mocked RPC), freshness, labels,
  prompt + bundle delivery (captured mock transport), label
  advisory-only + forgery rejection, conflict/injection labeling,
  stale + fallback audit.
- `test/e2e/evidenceLive.test.js` (4 tests, real Anvil, NO mocks):
  genuine balances/nonces, code presence + codehash, wrong-chain,
  dead-RPC fail-closed.
- `test/live/museLive.test.js` (gated, real API): baseline pack and
  findings-bearing Phase-B pack reach the live model and validate.
