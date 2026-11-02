# Assertara Agent SDK

Investigate-then-execute for autonomous agents. Zero dependencies,
Node 20+. Agent-agnostic core with thin viem/ethers call-shape
adapters (duck-typed — no framework imports).

## Install (in-repo)

```js
const { AssertaraClient, createGuardedWallet } = require('./sdk');
```

## Quickstart

```js
const { AssertaraClient, createGuardedWallet } = require('./sdk');

const client = new AssertaraClient({
  policyBase: 'http://127.0.0.1:3001', // Assertara policy service
  signerBase: 'http://127.0.0.1:3002', // controlled signer (separate process)
  apiKey: 'my-integration:SECRET', // keyId:secret (identifies you; authorizes nothing)
});

await client.connect(); // fails fast on wrong network / no mandate / bad key

const wallet = createGuardedWallet({
  client,
  account: '0xYOUR_SENDING_ADDRESS', // must be the mandate-authorized sender
  chainId: 31337,
});

// Every send below is automatically: investigated → decided → (only ALLOW,
// or operator-released REVIEW) signed by the controlled signer → executed → receipt-verified.
const result = await wallet.sendTransaction(
  { to: '0xRECIPIENT', value: 5000n }, // bigint/number/hex all accepted
  {
    purpose: 'Pay contributor for milestone 3', // plain-language intent (checked, never trusted)
    onProgress: ({ stage, progress }) => console.log('stage:', stage, progress.museSpark.state),
  }
);

console.log(result.txHash, result.execution.outcome); // EXECUTED on the clean path
```

With viem or ethers call shapes (no new dependencies):

```js
const { wrapViemWallet } = require('./sdk');
const viemLike = wrapViemWallet({ wallet, chain: { id: 31337 } });
await viemLike.sendTransaction({ to, value: 100n });
await viemLike.writeContract({ address, data: '0x…' }); // pre-encoded, or pass { encode }
```

```js
const { wrapEthersSigner } = require('./sdk');
const ethersLike = wrapEthersSigner({ wallet });
await ethersLike.sendTransaction({ to, value: '1000', gasLimit: 21000 });
```

## Decisions (you must handle all four)

| Decision | Meaning | What happens |
|---|---|---|
| `ALLOW` | Within mandate, checks passed | SDK signs via the controlled signer and verifies the receipt |
| `BLOCK` | Mandatory prohibition violated | `sendTransaction` throws `NOT_EXECUTABLE`. Nothing signs. Chain untouched. |
| `UNCERTAIN` | A required check is inconclusive | Same as BLOCK: throws, nothing signs. Never treat as approval. |
| `REVIEW` | Operator must release | SDK waits (`operatorTimeoutMs`, default 120s) for an out-of-band operator release, then executes. Your agent never handles the operator secret. |

Execution outcomes: only `EXECUTED` is clean. `EFFECTS_DIVERGED`,
`EXECUTED_UNVERIFIED`, `FAILED`, and `MISMATCH` are returned verbatim
(use `isCleanExecution()` to branch) — the SDK never relabels them.

## Visibility: live vs published

- `onProgress` and `streamProgress()` deliver **genuine live events**
  (component spans starting/finishing, model invocation state). When
  the trace ring has expired, progress honestly reports `unknown`.
- Decisions, findings, evidence, and token usage are **published
  results**, available on the terminal record (`getStatus`,
  `getEvidence`). The SDK never fabricates reasoning streams.

## Enforcement boundary (read this)

- Everything sent **through this SDK** is investigated; only a fresh
  ALLOW with a complete policy-issued approval reaches the signer,
  and the signer re-verifies it all independently.
- The SDK holds **no private keys**, cannot sign, cannot broadcast,
  and has no force/override/raw-send path (locked by test).
- A **separately held external wallet or direct RPC path is outside
  the enforcement boundary.** Assertara cannot constrain a key it
  does not control. Route all agent sends through the guarded wallet
  to stay inside the boundary.

Full contract: [docs/api-contract.md](../docs/api-contract.md).
Integration guide: [docs/sdk.md](../docs/sdk.md).
