# Command Centre: Start and Test Guide

Live investigation observability for Assertara's autonomous-agent
integration: real component telemetry, real model activity, real
timings. Anvil only — never mainnet, never real value.

## Prerequisites

- Node 20+, Foundry `anvil` on PATH (or `~/.foundry/bin`).
- `.env` with `MODEL_API_KEY` for live-model runs. Without it (or with
  `--mock-model`), investigations take the labeled heuristic path.

## 1. Start the stack

```powershell
node demo/command-stack.js
```

Default ports: app 3001, signer 3002, Anvil 8545. Override with
`--app-port`, `--signer-port`, `--anvil-port`. Add `--mock-model` for
the heuristic path (investigations hold UNCERTAIN; mandate BLOCKs
still fire for real).

The script prints the exact browser URL, including the signer address
the UI needs for execution:

```text
http://127.0.0.1:3001/command/?signer=http%3A%2F%2F127.0.0.1%3A3002
```

Open that URL in your browser. The stack boots a fresh mandate,
fresh ledgers, and fresh keys on every start (temp dir; nothing
persists between runs except `data/` investigation records).

## 2. Run a scenario in the UI

1. Click any scenario button (fixed proposal, no planner).
2. Watch components, models, timeline, and performance update live
   from the SSE event stream.
3. Read the decision + reasons. ALLOW shows **Sign & execute** (calls
   the controlled signer, then receipt + B7 verification append to the
   same trace). REVIEW stays HELD — release needs the operator
   secret, which never enters the browser.
4. Inspect tabs: objective/tx, decoded, effects, findings, validation,
   model investigation, full redacted record.

Statuses are honest: SKIPPED names a reason; catalog components never
invoked on a path appear under "Not invoked on this path" — never as
activity.

## 3. Run the scripted suite (repeatable, 10 scenarios)

```powershell
node demo/agent-scenarios.js --release
```

`--release` authorizes REVIEW decisions with the boot operator secret
and labels it OPERATOR STAND-IN. Without it, REVIEW scenarios stop at
HELD. `--mock-model` runs the deterministic-only pass. `--only <id>`
runs one scenario. Results (decisions, findings, timings, full trace
snapshots) land in `demo/tmp/agent-scenarios-<ts>.json`.

## 4. Run benchmarks

```powershell
node demo/agent-scenarios.js --bench legitimate-transfer --n 5
node demo/agent-scenarios.js --bench legitimate-transfer --n 20 --mock-model
```

Reports avg/P50/P95/min/max for propose latency and model latency,
plus cold-vs-warm splits and success/timeout/failure rates.

## 5. Regression suites (unchanged)

```powershell
npm run test:unit   # 43 suites, deterministic, no network spend
npm run test:e2e    # real Anvil + signer, mock model transport
npm run test:live   # 9 batteries, genuine Muse Spark (spends API budget)
```

## Reference mandate (command stack)

Chain 31337 only. Recipients allow: contributor, router, unknown-probe,
USDC-label; deny: stranger. Contracts allow: router, unknown-probe,
USDC-label. Selectors: multicall, approve, transfer, 0xdeadbeef probe.
Native ≤ 0.1 ETH/tx, REVIEW above 0.01 ETH, unlimited approvals banned,
approval spenders allowlisted to the contributor.

## Boundaries (by design, not bugs)

- The planner model (demo agent) runs out-of-process; UI/scenario
  proposals are fixed transactions, labeled as such.
- Signer internals are not live-instrumented; only outcomes and
  browser/script-measured round-trips are shown.
- Time-to-first-token is unavailable (non-streaming provider API).
- Production makes exactly one model attempt per investigation; the
  UI/scripts never silently retry.
- Telemetry is read-only and in-memory (25-trace ring); it cannot
  influence any authorization decision.
