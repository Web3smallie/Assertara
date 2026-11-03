# Assertara

Assertara investigates a proposed autonomous-agent blockchain transaction with AI models before it runs. It returns a decision (`ALLOW`, `BLOCK`, `REVIEW` or `UNCERTAIN`), lets only approved transactions reach a controlled signer, and records a signed, tamper-evident provenance attestation of the investigation on Arc Testnet. Anyone can read that attestation, including exactly which models ran and what each concluded, straight from the chain.

```
propose -> investigate -> decide -> execute -> manifest -> attest -> publish -> verify
```

- SDK on npm: [`assertara`](https://www.npmjs.com/package/assertara) (v0.1.0, zero dependencies, Node 20+)
- Onchain proof: see [Onchain proof on Arc Testnet](#onchain-proof-on-arc-testnet)

## Why it exists

Autonomous agents can sign and send transactions faster than a human can review them. Assertara puts an investigation and a policy decision between the agent and the signer:

- The agent holds no signing key. Only a separate controlled signer can sign, and it independently re-verifies every approval.
- `BLOCK` and `UNCERTAIN` decisions never reach the signer. `REVIEW` waits for an operator to release it.
- Every investigation produces a deterministic manifest. An operator signs that manifest's digest and publishes the result onchain, so a third party can later check which models were used and what they concluded without trusting Assertara's servers.

## What is in this repository

| Path | What it is |
|---|---|
| `src/` | Policy service: transaction decoding, evidence assembly, rules, model reasoning, mandate and approvals |
| `src/signer/` | Controlled signer, a separate process that holds the only transaction-signing key |
| `src/attestation/` | Manifest signing ceremony, key registry, export package and judge verifier |
| `src/services/attestationPublisher.js` | Publishes a signed attestation to the onchain contract and re-verifies it |
| `sdk/` | The agent SDK (published as `assertara` on npm) |
| `contracts/` | Provenance attestation contract source |
| `demo/` | Live autonomous-agent demos and the Command Centre stack |
| `extension/` | Chrome (MV3) pre-sign gate for dApp wallet requests |
| `docs/` | Detailed design and operator documentation |

## Decisions

| Decision | Meaning | What happens |
|---|---|---|
| `ALLOW` | Within the mandate and checks passed | Executed through the controlled signer and receipt-verified |
| `BLOCK` | A mandatory prohibition was violated | Nothing is signed |
| `UNCERTAIN` | A required check was inconclusive | Treated like `BLOCK`. Never treated as approval |
| `REVIEW` | An operator must release it | Held until an out-of-band operator release |

## Install the SDK

```sh
npm install assertara
```

```js
const { AssertaraClient, createGuardedWallet } = require('assertara');

const client = new AssertaraClient({
  policyBase: 'http://127.0.0.1:3001',
  signerBase: 'http://127.0.0.1:3002',
  apiKey: 'my-integration:SECRET',
});
await client.connect();

const wallet = createGuardedWallet({ client, account: '0xYOUR_SENDING_ADDRESS', chainId: 31337 });
const result = await wallet.sendTransaction(
  { to: '0xRECIPIENT', value: 5000n },
  { purpose: 'Pay contributor for milestone 3' }
);
console.log(result.txHash, result.execution.outcome);
```

The SDK also exposes the provenance steps: `buildManifest`, `getExportPackage`, `requestAttestation`, `publishAttestation` and `verifyAttestation`. See [sdk/README.md](sdk/README.md) and [docs/sdk.md](docs/sdk.md).

## Onchain proof on Arc Testnet

| Item | Value |
|---|---|
| Network | Arc Testnet, chain ID `5042002` |
| RPC | `https://rpc.testnet.arc.io` |
| Explorer | `https://explorer.testnet.arc.io` |
| Contract | `ProvenanceAttestationV2` at [`0xaa216f7679d1701e8f5121cada4d45aa524c8e30`](https://explorer.testnet.arc.io/address/0xaa216f7679d1701e8f5121cada4d45aa524c8e30) |
| Deployment tx | [`0x75daef28171d0ecdae4ca770b9c18692d03ac1d74d31502e15716bec6a4ea265`](https://explorer.testnet.arc.io/tx/0x75daef28171d0ecdae4ca770b9c18692d03ac1d74d31502e15716bec6a4ea265) (block 70,408,075) |
| Verified source | [Sourcify (exact match)](https://sourcify.dev/server/v2/contract/5042002/0xaa216f7679d1701e8f5121cada4d45aa524c8e30), the Explorer Contract tab, and [`contracts/ProvenanceAttestationV2.sol`](contracts/ProvenanceAttestationV2.sol) in this repo |

### Reproduce the build

The deployed contract was compiled with solc `0.8.20`, `evm_version` shanghai, optimizer disabled, and metadata `bytecodeHash` ipfs. The repo source matches that exact file (SHA-256 `ffdde13a…8043fc`). Rebuild it with the dedicated Foundry profile (`[profile.v2]` in `foundry.toml`; the default profile is untouched):

```sh
FOUNDRY_PROFILE=v2 forge build
FOUNDRY_PROFILE=v2 forge inspect ProvenanceAttestationV2 deployedBytecode
cast code 0xaa216f7679d1701e8f5121cada4d45aa524c8e30 --rpc-url https://rpc.testnet.arc.io
```

(PowerShell: `$env:FOUNDRY_PROFILE='v2'` before each `forge` command.) The rebuilt bytecode is identical to the on-chain code except for the trailing metadata hash, which embeds the local compile path and always differs outside the original build machine. Runtime logic matches exactly.

### Published attestations

| Investigation ID | Publication tx | Block |
|---|---|---|
| `eval_d50e44a8` | [`0x5b9ef706...6613`](https://explorer.testnet.arc.io/tx/0x5b9ef7067513931f091d98b937f3aec7af2143ef1cc77b7244f1ecc4d51e6613) | 70,408,702 |
| `eval_6a67bc85` | [`0xfedfd310...79a1`](https://explorer.testnet.arc.io/tx/0xfedfd3101887c748ff348e8deed05dc11cb042f27a5de383b7ee8066543d79a1) | 70,482,011 |
| `eval_dabc63a9` | [`0xf98bc230...8213`](https://explorer.testnet.arc.io/tx/0xf98bc230a4e1fb032b7ed1266f47748b0850c1042e9ff3791ed556ee7aee8213) | 70,490,682 |
| `eval_d82eee8f` | [`0x2c3708a8...c480`](https://explorer.testnet.arc.io/tx/0x2c3708a8cc45b5dd980e7bdf6283925221ea39810dab3680cc3eb30563c6b480) | 70,491,353 |
| `eval_a5c400c4` (most recent at time of writing) | [`0xb209131b...e80`](https://explorer.testnet.arc.io/tx/0xb209131b3158fbc18ca1d70a325922ef6cdcb7438ebedb5fdb67e99cdae1ce80) | 70,513,712 |

Attester for all of these: `0xCde3BBdc21020D220cD592472daDaFBC033eD322`. More attestations are published over time. The contract page's **Logs** tab on the Explorer lists every one.

### Verify it yourself

You do not need Assertara's CLI, servers or frontend.

**On the Explorer**
1. Open the [contract page](https://explorer.testnet.arc.io/address/0xaa216f7679d1701e8f5121cada4d45aa524c8e30), then **Contract**, then **Read contract**.
2. Expand `getAttestation` and enter, typed by hand with no surrounding spaces:
   - `investigationId`: `eval_d82eee8f`
   - `attester`: `0xCde3BBdc21020D220cD592472daDaFBC033eD322`
3. Click **Read**.
4. To see the decoded event, open the publication tx above and choose **Logs**. The `AttestedWithModels` event lists the models.

**From the command line** (reads straight from the chain with [Foundry](https://getfoundry.sh)'s `cast`)
```sh
cast call 0xaa216f7679d1701e8f5121cada4d45aa524c8e30 \
  "getAttestation(string,address)" \
  "eval_d82eee8f" 0xCde3BBdc21020D220cD592472daDaFBC033eD322 \
  --rpc-url https://rpc.testnet.arc.io
```

### What `getAttestation` returns for `eval_d82eee8f`

| Field | Value |
|---|---|
| manifestDigest | `0xff1203cd6ae93b3150a8c322dad20df5e5f6fd749b0790fd8967474a178af0e3` |
| modelBitmap | `1` (only the first model slot was invoked) |
| decision | `0` |
| txHash | `0x8469388d9706849b80d982ad4015f6fd10f26231b4ca322c6f2c4eb8ce784f5d` (the investigated action, executed on the local demo chain, so it is not on Arc Testnet) |
| attester | `0xCde3BBdc21020D220cD592472daDaFBC033eD322` |

| Model slot | Provider | Model ID | Endpoint | Status | Contribution | Verdict |
|---|---|---|---|---|---|---|
| `museSpark` | `meta-model-api` | `muse-spark-1.3` | `chat/completions` | `success` | `VERDICT_ACCEPTED` | `MATCH` |
| `sam` | none | none | none | `skipped` | `NOT_INVOKED` | none |

- `museSpark` input digest `0x507b521858642f607aaf90f8aa2d0436626998722019ba1fee08335a58fa0b99`, output digest `0x4722205f2692d76eaafb06ff17047e88458bec655bdfeb0f662dc16f22ea7021`.
- `sam` has all-zero digests because it was not called.

### Reading the result

- `modelBitmap = 1` and `sam: skipped / NOT_INVOKED` mean only `museSpark` ran. The unused slot is recorded honestly, not hidden.
- Model names, providers, IDs, statuses and verdicts come from the signed investigation manifest. The contract hardcodes none of them, so other providers and models can be recorded the same way.
- Each attestation holds two different transaction hashes: the publication tx (writes the attestation to the contract) and the recorded `txHash` (the action that was investigated).
- `investigationId` is an indexed string in the event, so the Explorer's Logs view shows its hash. The readable ID is in the transaction input and in `getAttestation`.
- The Explorer's "Indexed?" column only says whether an event field is a log topic. It is not a verdict.
- The Arc Testnet Explorer indexes in the background and can lag behind the chain head. RPC reads and Sourcify always reflect the chain directly.

## What an attestation proves, and what it does not

It proves that the identified Assertara attestation key signed this exact manifest digest, and that the digest is recorded onchain for that investigation.

It does not prove that a model provider actually executed a model (there are no provider receipts), that the investigation records are true, that any payment succeeded, or that the policy decision was correct. Check any transaction hash yourself. Details: [docs/attestation.md](docs/attestation.md).

## Key separation

| Role | Purpose | Must never |
|---|---|---|
| User wallet keys | The user's own funds | Be requested, stored or accessed by Assertara |
| Transaction-signing key (`SIGNER_PRIVATE_KEY`) | Controlled execution | Sign attestations |
| Attestation key (`ATTESTATION_SIGNING_KEY`) | Sign provenance manifests | Authorize or broadcast transactions |
| Registry root (`REGISTRY_ROOT_KEY`) | Sign key-registry updates | Be used as a day-to-day attestation key |
| Publisher key (`PUBLISHER_TX_KEY`) | Pay gas for `attest(...)` | Create attestation signatures |

No key may serve two roles. The publisher refuses to submit if its address equals the attester, registry root or any deny-listed address.

## Run it locally

Requirements: Node.js 20+, [Foundry](https://getfoundry.sh) `anvil` on your PATH, and a Meta model API key for live-model runs.

```sh
npm install
cp .env.example .env     # then fill in your own values
npm start                # policy service on http://localhost:3001
npm run start:signer     # controlled signer
```

Never commit `.env`, and never place ceremony keys in it. See [docs/attestation.md](docs/attestation.md) for the key-handling rules.

### Demos

```sh
npm run demo:agent                  # four live scenarios: allow, block, operator release, uncertain
node demo/agentDriven.js both       # Demo A (allow, executed, attested) and Demo B (blocked)
node demo/command-stack.js          # Command Centre UI at http://127.0.0.1:3001/command/
```

The demos run against a local Anvil chain with a real signer. Planner and investigation calls use the live model API. See [demo/README.md](demo/README.md) and [docs/command-centre.md](docs/command-centre.md).

### Tests

```sh
npm test            # core suite
npm run test:unit   # full unit suite
npm run test:e2e    # end-to-end suite (local Anvil and signer)
npm run test:live   # live-model tests (needs MODEL_API_KEY)
```

## Chrome extension

An advisory pre-sign gate that holds supported dApp wallet requests, evaluates them with the local backend, and forwards them only after you choose Continue. It never signs, submits or alters a request. See [extension/README.md](extension/README.md).

## Environment variables

Copy `.env.example` and fill in your own values. Names only, never commit values.

| Variable | Purpose |
|---|---|
| `MODEL_API_KEY` | Model API key for live investigations |
| `META_API_BASE_URL`, `SAM_MODEL`, `MUSE_MODEL` | Model endpoint and model names |
| `MANDATE_FILE`, `TRUSTED_MANDATE_AUTHORITIES` | Operator mandate and who may sign it |
| `APPROVAL_SECRET`, `OPERATOR_SECRET` | Approval token and operator release secrets |
| `SIGNER_PRIVATE_KEY`, `SIGNER_PORT` | Controlled signer key and port |
| `EVIDENCE_CHAIN_RPC_URL` | RPC used to gather onchain evidence |
| `ATTESTATION_SIGNING_KEY`, `TRUSTED_ATTESTATION_AUTHORITIES`, `TRUSTED_REGISTRY_ROOT`, `ATTESTATION_DENY_ADDRESSES` | Attestation ceremony (load at ceremony time only) |

The full list with comments is in `.env.example`.

## Documentation

- [docs/sdk.md](docs/sdk.md): integrating an agent
- [docs/api-contract.md](docs/api-contract.md): wire contract
- [docs/attestation.md](docs/attestation.md): signing, registry, publication and judge verification
- [docs/autonomous-agent.md](docs/autonomous-agent.md): the agent execution path
- [docs/reasoning-architecture.md](docs/reasoning-architecture.md) and [docs/evidence-assembly.md](docs/evidence-assembly.md): how investigations work

