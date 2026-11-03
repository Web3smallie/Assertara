# Assertara SDK

Client library for the Assertara network: submit blockchain transactions for AI investigation, receive authorization decisions, execute only through a guarded signer, and produce cryptographic provenance attestations.

One flow, one package:

```
propose → investigate → decide → execute → manifest → attest → publish → verify
```

Zero dependencies. Node 20+. CommonJS (`require`). Agent-agnostic core with thin viem/ethers call-shape adapters (duck-typed — no framework imports).

## Requirements

- Node.js 20 or later.
- A reachable Assertara policy service (`policyBase`, e.g. `http://127.0.0.1:3001`).
- A reachable controlled signer (`signerBase`) — required only for execution.
- An API key (`keyId:secret`) identifying your integration. It identifies you; it authorizes nothing.
- The operator credential — required only for `requestAttestation` and `publishAttestation`, passed per call, never stored. Never give it to an agent.

## Install

```sh
npm install assertara
```

```js
const { AssertaraClient, createGuardedWallet } = require('assertara');
```

## Quickstart

```js
const { AssertaraClient, createGuardedWallet } = require('assertara');

const client = new AssertaraClient({
  policyBase: 'http://127.0.0.1:3001',
  signerBase: 'http://127.0.0.1:3002',
  apiKey: 'my-integration:SECRET',
});

await client.connect(); // fails fast on wrong network / no mandate / bad key

const wallet = createGuardedWallet({
  client,
  account: '0xYOUR_SENDING_ADDRESS', // must be the mandate-authorized sender
  chainId: 31337,
});

// Investigated → decided → (only ALLOW, or operator-released REVIEW)
// signed by the controlled signer → executed → receipt-verified.
const result = await wallet.sendTransaction(
  { to: '0xRECIPIENT', value: 5000n },
  {
    purpose: 'Pay contributor for milestone 3',
    onProgress: ({ stage, progress }) => console.log('stage:', stage),
  }
);

console.log(result.txHash, result.execution.outcome); // EXECUTED on the clean path
```

With viem or ethers call shapes (no new dependencies):

```js
const { wrapViemWallet, wrapEthersSigner } = require('assertara');
const viemLike = wrapViemWallet({ wallet, chain: { id: 31337 } });
await viemLike.sendTransaction({ to, value: 100n });
const ethersLike = wrapEthersSigner({ wallet });
await ethersLike.sendTransaction({ to, value: '1000', gasLimit: 21000 });
```

## Workflow and API

### 1. Submit and investigate

```js
const inv = await client.submit({ transaction, purpose, agentId });
// or client.propose(...) for the synchronous variant
const decided = await inv.wait(); // terminal record with decision
console.log(decided.decision); // ALLOW | BLOCK | REVIEW | UNCERTAIN
```

Client methods: `connect()`, `submit()`, `propose()`, `getStatus(requestId)`, `waitForDecision(requestId, opts)`, `waitForDecisionLive(requestId, opts)`, `getEvidence(requestId)`, `getTrace(traceId)`, `streamProgress(traceId, onEvent)`, `getMandateInfo()`, `waitForOperatorApproval(requestId, opts)`, `reportReceipt(requestId, txHash)`.

`Investigation` handle conveniences: `status()`, `wait()`, `evidence()`, `trace()`, `stream()`, `execute()`, `waitForExecution()`.

### 2. Decide — handle all four outcomes

| Decision | Meaning | SDK behavior |
|---|---|---|
| `ALLOW` | Within mandate, checks passed | Executes via the controlled signer, verifies the receipt |
| `BLOCK` | Mandatory prohibition violated | Throws `NOT_EXECUTABLE`. Nothing signs. Chain untouched. |
| `UNCERTAIN` | A required check is inconclusive | Same as BLOCK. Never treat as approval. |
| `REVIEW` | Operator must release | Waits for out-of-band operator release, then executes |

Execution outcomes: only `EXECUTED` is clean (use `isCleanExecution()` to branch). `EFFECTS_DIVERGED`, `EXECUTED_UNVERIFIED`, `FAILED`, and `MISMATCH` are returned verbatim, never relabeled.

### 3. Execute (guarded)

```js
const signed = await inv.execute(transaction, { status: decided });
const execution = await inv.waitForExecution();
```

`execute()` re-verifies decision, approval token, expiry, and exact-byte digest match before contacting the signer, which independently re-verifies everything. The SDK signs nothing itself.

### 4. Provenance — manifest, attestation, publication, verification

Works after any decision (BLOCK and REVIEW carry provenance too, with no payment implied):

```js
// Deterministic manifest for the decided request (idempotent).
const { manifestDigest } = await client.buildManifest(inv.requestId);
const stored = await client.getManifest(manifestDigest);

// Portable signed-export envelope (needs a ceremony first).
// The SDK recomputes the digest locally before returning.
const exported = await client.getExportPackage(manifestDigest);

// Operator ceremony: preview, then sign (credential per call, never stored).
const operatorSecret = process.env.OPERATOR_SECRET;
await client.requestAttestation({ digest: manifestDigest, expectDigest: manifestDigest, operatorSecret });
await client.requestAttestation({ digest: manifestDigest, expectDigest: manifestDigest, confirm: true, operatorSecret });

// Operator publication to the attestation contract.
const pub = await client.publishAttestation({ digest: manifestDigest, operatorSecret });
console.log(pub.txHash);

// Read-only verification (judge flow as data).
const { verdict, checks, models } = await client.verifyAttestation({ digest: manifestDigest });
console.log(verdict); // PASS or FAIL
console.log(models); // derived server-side from the verified manifest
```

`Investigation` conveniences: `inv.manifest()`, `inv.exportPackage([digest])`, `inv.verifyAttestation(opts)`.

## Configuration and authentication

```js
new AssertaraClient({
  policyBase: 'http://127.0.0.1:3001', // required
  signerBase: 'http://127.0.0.1:3002', // required for execute()
  apiKey: 'keyId:secret', // integration identity; authorizes nothing
  timeouts: { submit: 30000, propose: 180000, status: 15000 }, // overrides; see DEFAULT_TIMEOUTS
  fetchImpl: customFetch, // optional transport injection (tests, proxies)
});
```

- API keys identify integrations for rate-limiting, audit, and ownership scoping. Each key sees only its own requests and evidence. Keys never authorize transactions.
- The operator credential authorizes REVIEW release, attestation ceremony, and publication. It is supplied per call by a human operator workflow and is never retained by the client, never logged, and must never be given to an agent.
- Errors are typed `AssertaraError` with stable `code` values (`CODES.VALIDATION`, `CODES.AUTH`, `CODES.NOT_FOUND`, `CODES.CONFLICT`, `CODES.NOT_EXECUTABLE`, `CODES.DIGEST_MISMATCH`, …). Branch on codes, not message text.

## Visibility: live vs published

- `onProgress` and `streamProgress()` deliver **genuine live events** (component spans, model invocation state). When the trace ring has expired, progress honestly reports `unknown`.
- Decisions, findings, evidence, and token usage are **published results** on the terminal record. The SDK never fabricates reasoning streams or telemetry.

## Security boundaries — what this SDK does NOT do

- Holds **no private keys** and performs **no signing**. Execution signatures come only from the controlled signer process.
- Cannot broadcast, raw-send, force, or override anything (locked by test).
- Cannot authorize: BLOCK and UNCERTAIN never execute; REVIEW executes only after genuine out-of-band operator release; ALLOW requires a fresh, complete policy-issued approval for the exact investigated bytes.
- Cannot self-attest: ceremony and publication require the per-call operator credential, which agents must never receive.
- Cannot fabricate model provenance: `models` output is derived server-side from the verified manifest and displayed verbatim.
- A **separately held external wallet or direct RPC path is outside the enforcement boundary.** Route all agent sends through the guarded wallet.
- `verifyAttestation()` is a convenience call that trusts the serving backend + RPC. Fully independent verification remains the judge CLI (`src/attestation/judge.js` in the Assertara repo) plus public chain data — no Assertara server or key required.

## Links

- Assertara repository: https://github.com/Web3smallie/Assertara
- npm package: https://www.npmjs.com/package/assertara
- In-repo docs: `docs/sdk.md` (integration guide), `docs/api-contract.md` (endpoint contract), `docs/attestation.md` (provenance runbook)
