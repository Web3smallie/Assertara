# Assertara Performance Audit — Investigation Pipeline

Date: 2026-10-31. Status: measurement only — no optimizations implemented, no security logic changed.

Targets (for reference): security decision < 8s; complete local agent workflow < 12s.

## 1. Method

- 30 genuine live Muse Spark runs: 6 scenarios × 5 repeats, sequential, fresh stack per scenario
  (`demo/agent-scenarios.js --bench <id> --n 5`). Serving model `muse-spark-1.3` throughout.
- 6 full runs (`--only <id>`) with complete trace snapshots for evidence sizes and execution timing.
- 1 mock bench (legitimate-transfer × 5) isolating the deterministic pipeline (no model spend).
- Raw data: `demo/tmp/agent-scenarios-1793482905316.json` … `…549441.json` (13 files, bench + full + mock).
- Timing source: backend trace spans (server-recorded, ms resolution) + bench `proposeMs` (client-measured).
  P95 on n=5 is indicative only, reported as observed max-of-sample alongside.

## 2. Measured baseline (live model)

| Scenario | Decision | Origin (5 runs) | Propose avg | P50 | P95≈max | Model avg | Model share |
|---|---|---|---|---|---|---|---|
| legitimate-transfer | ALLOW | 5× model | 43.2s | 48.9s | 53.8s | 43.1s | 99.8% |
| unauthorized-recipient | BLOCK | 5× model | 36.5s | 35.1s | 46.3s | 36.4s | 99.7% |
| unlimited-approval | BLOCK | 3× model, 2× timeout→fallback | 60.3s | 60.3s | 62.9s | 57.9s¹ | 95.7% |
| hidden-multicall-approval | BLOCK | 5× model | 40.8s | 40.0s | 48.7s | 38.7s | 94.9% |
| unknown-contract | UNCERTAIN | 4× model, 1× timeout→fallback | 56.0s | 56.9s | 63.0s | 50.9s¹ | 93.8% |
| misleading-description | REVIEW | 5× model | 46.6s | 46.6s | 57.6s | 44.4s | 95.4% |
| legitimate-transfer (mock) | UNCERTAIN | 5× heuristic | 71ms | 32ms | 231ms | — | 0% |

¹ Model avg over model-origin runs only (n=3 and n=4); fallback runs add the 60s timeout, not inference.

- Cold (run 1) vs warm (runs 2–5), live: 48.5s vs 46.9s — no meaningful difference (~3%).
- Execution (local Anvil, ALLOW path): sign round-trip 225ms (browser-measured), receipt poll 6ms.
  Chain confirmation on real networks is out of Assertara's control and excluded from the 8s target.
- Errors: 3 of 36 live runs hit the 60s model timeout and took the labeled heuristic-fallback path
  (decisions stayed safe: BLOCK/UNCERTAIN). Retries: 0 (production makes exactly 1 attempt by design).
  No HTTP errors observed.

## 3. Stage-by-stage breakdown (27 model-origin runs)

Median per component; everything except the model is sub-10ms at median:

| Stage group | Components (median) | Notes |
|---|---|---|
| Model inference | muse-spark 45.6s (p95 59.2s) | 94–99.8% of every investigation |
| Evidence & input | chainstate 8ms, decoder 1ms, packer 1ms, rest 0ms | prompt build ≈ 1ms |
| Transaction analysis | all ≤1ms median | sim/identity outliers below |
| AI plumbing | prompt-select 0ms, reasoning-validation 0–1ms, reference-validation 1ms | — |
| Verification | all ≤1ms median | safeguards 0–3ms |
| Authorization | mandate-eval 0–4ms, subcall-bind 0–1ms, policy-decision 0–1ms, approval-issue 0–1ms | — |
| Completion | persistence 3ms, receipt-verify 7ms, agent-response 0ms | — |

Deterministic outliers (the only non-model costs ≥100ms in 30 runs):

| Component | Observed cost | Trigger | Root cause |
|---|---|---|---|
| simulation-post | 1.8–3.3s (13 runs) | MISMATCH verdict or fallback path | `forge test` subprocess: compiles + runs a synthesized test contract per investigation (8s timeout) |
| simulation-pre | 1.7–2.1s (5/5 unknown-contract) | pre-reasoning trigger fired | same `forge test` subprocess |
| contract-identity | 1.0–1.4s (5/5 unknown-contract) | unknown selector/contract | sequential external lookups: 4byte.directory (2.5s timeout) + Sourcify verification check |

Sum of deterministic medians per investigation: ≈ 32ms. Worst deterministic total observed: 3.2s
(unknown-contract: sim-pre + identity + sim-post).

## 4. Token and prompt analysis

- Input tokens: 5,078–6,282 (narrow). System prompt is 18,407 chars (~4.6k tokens: 15 methodology
  stages, 14 semantic rules, full schema); packed evidence 4,162–6,673 chars, 0 truncations.
  Evidence is NOT oversized; the static system prompt dominates input.
- Output tokens: 5,537–11,170 (wide). Latency tracks OUTPUT length, not input:
  e.g. 5,624 out → 29.3s vs 9,807 out → 53.7s on the same scenario.
- Marginal rate ≈ 170 output-tokens/s is too fast for pure autoregressive decode, implying large
  hidden reasoning effort (muse-spark-1.3 is a reasoning model). The provider reports no reasoning
  token count (`total == prompt + completion` in all runs), so hidden reasoning is currently
  unmeasurable — a measurement gap, not an implementation cost.
- Request config: temperature 0, `json_object`, max_tokens 24000 (outputs ≤ 11.2k, no truncation
  observed), 60s timeout, non-streaming (TTFT unavailable).

## 5. Bottlenecks, ranked

1. **Model generation (output + hidden reasoning): 30–60s, ~97% of latency.** Root cause: a
   reasoning model producing 5.5–11k structured tokens (16-field investigation object) plus hidden
   reasoning, over a 18k-char system prompt, via a non-streaming API. Variance comes from output
   length, which grows with case complexity.
2. **60s timeout cliff.** Root cause: fixed 60s abort; complex cases (unlimited-approval,
   unknown-contract) hit it, then STILL pay full deterministic + fallback cost. 3/36 runs (8%).
3. **Foundry simulations: ~2s each, up to 2 per investigation.** Root cause: cold `forge test`
   compile+run per trigger. Only on MISMATCH/fallback/triggered paths.
4. **External identity lookups: ~1–1.4s.** Root cause: sequential 4byte + Sourcify calls on unknown
   contracts. Network-bound, unrelated to reasoning.
5. **Everything else combined: ≈ 30ms.** No bottleneck; implementation overhead is negligible.

Answer to Phase 1.6: **Muse Spark itself is the primary bottleneck.** The implementation contributes
~0.03s typically and ≤3.3s on simulation/lookup paths — significant only relative to an 8s target
once the model cost is addressed, not today.

## 6. Duplicated / avoidable work found (code-verified, not yet changed)

- Model runs BEFORE the mandate gate: unauthorized-recipient burns a 35s model call, then the
  mandate BLOCKs anyway. The model verdict adds context but cannot change the outcome.
- Effects reconstructed twice (pre-reasoning + authorization-time binding); subcall tree built and
  hashed separately. Each instance is ~0–4ms — hygiene only, no measurable gain.
- Evidence-graph edges built pre- and post-reasoning (both ~0–1ms) — negligible.
- Independent IO runs sequentially: chainstate → identity → proxy → simulation-pre are awaited in
  order though mutually independent. Parallelizing saves ~1–3s only on sim/lookup paths.
- No repeated network calls to the model (exactly 1 attempt), no oversized prompts, no redundant RPC.

## 7. Safe optimization opportunities (ESTIMATES — pre-registration, not results)

Ordered by expected impact. None may weaken Capabilities 1–5; each needs a quality gate before
acceptance (see risks).

1. **Mandate pre-gate (deterministic BLOCK before the model call).** Skip inference when the mandate
   already fails (recipient/contract/selector/value/spender violations are all pre-computable).
   *Estimate: mandate-blocked cases 35–60s → ~0.2s.* Risk: investigation record loses model
   reasoning on those paths (observability loss, zero authorization impact — the model cannot
   override a mandate BLOCK today either). Mitigation: keep full-model mode available per-flag for
   audit sampling.
2. **Shrink the model's output burden.** Fewer/smaller output fields (e.g. collapse the 15-field
   methodology output, shorten verbatim-quote requirements) and/or a reasoning-effort control if
   the provider offers one. *Estimate: proportional to output+reasoning reduction; 30–50% is
   plausible but unverified.* Risk: DIRECT quality risk — output richness is the investigation.
   Requires A/B grading against the current qualitative bar (genuine-complete records) before any
   acceptance. Do not cap max_tokens blindly: truncation yields fallback, which is slower, not faster.
3. **Fail-fast model timeout with deterministic cover.** Lower the 60s abort once (1) lands, since
   remaining model calls are genuinely ambiguous cases. *Estimate: caps worst case; no median gain.*
   Risk: more fallbacks if set aggressively; fallback quality must stay UNCERTAIN-or-REVIEW (holds
   today).
4. **Parallelize independent deterministic IO** (chainstate, identity, proxy, sim-pre).
   *Estimate: –1 to –3s on sim/lookup paths only (~15% of runs); ~0% median gain.* Risk: near zero
   (read-only, independent); keep span attribution per component.
5. **Simulation cost.** Reuse a warm forge project / precompiled std, or skip sim-post when
   pre-reasoning simulation already contradicts. *Estimate: –1 to –2s on MISMATCH paths.* Risk: low
   if triggers unchanged; any trigger change needs security review.
6. **Identity lookup budget.** Race 4byte+Sourcify with tighter per-call timeouts, or cache by
   (chain, address) with short TTL. *Estimate: –0.5 to –1s on unknown-contract paths.* Risk: low;
   labels are HINTS by contract, never identity proof — caching must carry provenance + TTL.
7. **NOT recommended:** prompt trimming (input doesn't drive latency), output max_tokens cuts
   without schema redesign (causes truncation fallbacks), model substitution (changes the security
   product), streaming partial verdicts (provider doesn't support it; partial JSON isn't a verdict).

Reaching <8s requires (1) for blocked paths plus a large reduction in model generation cost (2)
for the remainder — there is no 5× gain available in the deterministic pipeline (32ms typical).

## 8. Risks and security implications (cross-cutting)

- Any change touching verdict→decision mapping, mandate evaluation, safeguards, or evidence
  requirements is a security change, not a performance change: it needs adversarial review + the
  full unit/e2e/live suites, not just a latency check.
- Output reduction risks silent quality decay: conclusions/discrepancies/uncertainty fields feed
  safeguards and human review. Gate on graded output comparison, not only verdict agreement.
- Timeout/fallback changes must preserve fail-closed behavior (fallback held at UNCERTAIN/REVIEW
  in all 3 observed timeouts — this property must be re-verified after any change).
- Caching (identity, simulation artifacts) must never cross trust boundaries: cached HINTS stay
  hints; cached chain-state needs freshness bounds; never cache model verdicts across different
  transactions.

## 9. Reproduction

```powershell
node demo/agent-scenarios.js --bench <scenario-id> --n 5        # live, spends API budget
node demo/agent-scenarios.js --bench <id> --n 5 --mock-model    # deterministic only
node demo/agent-scenarios.js --only <id>                        # full snapshot + evidence sizes
node test/tmp/perf-analyze.js demo/tmp/agent-scenarios-*.json   # aggregation (scratch)
```

No source files were modified for this audit. No frontend changes. No Capability 6–12 work started.
Awaiting approval before implementing any optimization.
