# Assertara SDK Integration Guide

How an independently developed agent integrates Assertara, end to
end. For the pinned wire contract see
[api-contract.md](./api-contract.md).

## 1. What you run

- The Assertara **policy service** (investigates, decides, issues
  approvals) with an operator-owned mandate.
- The **controlled signer** (separate process, holds the only signing
  key, verifies every approval independently).
- Your agent, using this SDK. Your agent holds NO signing key and NO
  Assertara secrets — only its API key (`keyId:secret`), which
  identifies the integration and authorizes nothing.

## 2. Minimal integration (three calls)

```js
const { AssertaraClient, createGuardedWallet } = require('assertara-sdk');

const client = new AssertaraClient({ policyBase, signerBase, apiKey });
await client.connect();
const wallet = createGuardedWallet({ client, account, chainId });

const { txHash, execution } = await wallet.sendTransaction(
  { to, value: 5000n },
  { purpose: 'What this payment is for, in plain language' }
);
```

`sendTransaction` submits the exact bytes for investigation, waits
for the published decision, and continues only as the decision
allows (§4). Prefer it over manual submit/wait/execute wiring: the
guarded flow cannot skip a step.

## 3. Manual control (when you need it)

```js
const inv = await client.submit({ transaction: tx, purpose });
// inv.requestId / inv.traceId available immediately (202).
inv.stream((event) => console.log(event.type, event.component)); // genuine live spans
const decided = await inv.wait(); // terminal record
if (decided.decision === 'ALLOW') {
  const { txHash } = await inv.execute(tx); // re-reads fresh status + digest
  const execution = await inv.waitForExecution();
}
const evidence = await inv.evidence(); // reasons, findings, mandate checks
```

Rules the SDK enforces for you:

- `execute()` re-reads status at call time and recomputes the local
  digest. Stale decisions and mutated bytes throw before any signer
  contact (`NOT_EXECUTABLE`, `DIGEST_MISMATCH`, `EXPIRED`).
- `BLOCK` / `UNCERTAIN` / unreleased `REVIEW` throw `NOT_EXECUTABLE`.
  There is no override flag, by design.
- `REVIEW` releases only via the operator endpoint with
  `OPERATOR_SECRET`, which your agent never sees. Use
  `waitForOperatorApproval()` to await the release.

## 4. Framework adapters

The core accepts plain `{ to, value, data, chainId }` objects.
Adapters map framework call shapes without adding dependencies:

- `wrapViemWallet({ wallet, chain, encode? })` →
  `sendTransaction({ account?, to, value?, data?, chain? })`,
  `writeContract({ address, data?, ... })`. Contract writes need
  pre-encoded `data` or a caller-supplied `encode()` (e.g. pass
  viem's `encodeFunctionData` through — the SDK will not import
  viem itself).
- `wrapEthersSigner({ wallet, address? })` →
  `sendTransaction({ to, value?, data?, gasLimit?, ... })`
  (`gasLimit` maps to `gas`), `getAddress()`.

Values accept `bigint`, safe integers, hex/decimal strings, and
`BigNumber`-likes with exact decimal rendering.

## 5. Errors

All failures are `AssertaraError` with a stable `code`: `VALIDATION`,
`AUTH`, `NOT_FOUND`, `CONFLICT`, `EXPIRED`, `RATE_LIMITED`,
`UPSTREAM`, `UNAVAILABLE`, `TIMEOUT`, `NOT_EXECUTABLE`,
`DIGEST_MISMATCH`, `SERVER`. Branch on `code`, show `message` to
operators. `429` carries `detail.retryAfterMs`; `409` in-flight
replays carry `detail.requestId` for polling.

## 6. Timeouts and retries

Defaults: submit 30s, sync propose 180s, status 15s, sign 90s,
decision wait 180s (2s polls), execution wait 90s, operator wait
120s. Retries are safe: the SDK auto-generates an `Idempotency-Key`
per call (override to dedupe your own retries — same key + same
proposal replays the stored record instead of re-investigating).

## 7. Visibility

- Live: `streamProgress(traceId)` (SSE span events) and the
  `stage`/`progress` fields on running status records, including
  `museSpark.state` (`pending|running|completed|failed|skipped`)
  with genuine timing/token data when published.
- Published: `getStatus`, `getEvidence`, trace snapshots, and the
  full model-origin bundle via observations by-eval.
- Never confuse the two: live events describe activity; only the
  terminal record carries the decision, findings, and usage.

## 8. Enforcement boundary

- Inside: everything submitted through this SDK — investigated,
  decided, and executed only via the controlled signer on a fresh
  ALLOW with a complete approval.
- Outside: separately held external wallets and direct RPC signing
  paths. Assertara cannot intercept what never reaches it; integrate
  by routing ALL agent sends through the guarded wallet.
- The SDK surface provably contains no private-key handling, local
  signing, broadcast, raw-send, force, or override capability
  (`test/unit/guardedWallet.test.js` Test 8 audits every export).
