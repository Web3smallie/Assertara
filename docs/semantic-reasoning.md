# Semantic and Contextual Reasoning (Capability 4)

Understanding what a transaction MEANS, what it can DO, and where its
apparent meaning differs from its real consequences — on top of
Capabilities 1–3, which are preserved unchanged in behavior. Deeper
model reasoning AND independent deterministic verification; the model
never overrides safeguards, mandates, or signer restrictions.

Prompt `investigate-2.2` adds semantic rules S1–S9 to the 15-stage
methodology. Safeguard stages 10–15 downgrade MATCH to UNCERTAIN.

## B1 — Proxy detection + resolution (`src/services/proxyResolution.js`)

ERC-1967 implementation/beacon slots, EIP-1167 minimal proxies, admin
reads. Outcomes: resolved / proxy-unresolved / not-proxy / unknown /
unavailable. Only a CONFIRMED proxy with failed resolution downgrades
(stage 10); unknown/unavailable never moves the verdict.

## B2 — Privileged operations (`src/rules/privilegedOperation.js`)

Ten signature-exact functions (ownership, upgrade, admin, roles,
pause). Findings name caller vs privilege recipient; authorization is
explicitly unverified. CRITICAL findings hold REVIEW (never BLOCK).

## B3 — Value protection (`src/utils/valueProtection.js`, `src/rules/valueProtection.js`)

2^255 documented unlimited threshold (BigInt, base units only);
zero-minimum and missing-protection findings; indicative quote-vs-floor
gap ratios (floored bps). Zero/missing floor downgrades MATCH (stage
11) — the S3-leniency guard.

## B4 — Nested calls (`src/services/nestedCalls.js`)

Stable SC-xxx subcall tree (depth ≤ 5) reaching packer, model, rules,
comparison, graph, and bundle. Same rules run on inners with subcall
provenance; unknown inners downgrade MATCH (stage 12).

## B5 — Contract identity (`src/services/contractIdentity.js`)

Chain-scoped ladder: source-verified > bytecode-matched >
proxy-implementation-resolved > static-label (HINT) > code-present >
unknown/unavailable. Sourcify v2 full-match only; 4byte earliest +
collisions; operator bytecode refs. No-key/offline fails safe.

## B6 — Deadlines (`src/services/deadlineAnalysis.js`)

V2 swaps, EIP-2612, Permit2; block-timestamp provenance; 300 s grace,
900 s near-expiry info. Expired/missing-deadline downgrades MATCH
(stage 13). No clock = unassessable, never assumed.

## B7 — Semantic-claim verification (`src/services/semanticClaims.js`)

Eight falsifiable targets (recipient, amount, unlimited, min-output,
function, identity, deadline, implementation) → VERIFIED /
CONTRADICTED / INCONCLUSIVE / NOT_APPLICABLE. Contradictions
downgrade MATCH (stage 14). Live review hardened three precision
bugs: token-window negation scope, full digit-run parsing with
raw-equality-first, target/impl mention reframing.

## B8 — History (`src/services/transactionHistory.js`)

Bounded window (2000 blocks / 8 priors), sender-keyed local priors +
chain logs + UNTRUSTED agent priors. APPROVAL_THEN_SPEND and
REPEATED_INTERACTION relationships. Absence proves nothing.

## B9 — Corpus + regression (`src/services/investigationStore.js`)

Eight-class record classifier; `reviewInvestigation.js audit
[--apply]` quarantines non-genuine records with reasons (nothing
deleted, idempotent); `list --genuine-only` restricts qualitative
review to complete model-origin investigations. Initial corpus:
1,415 records → 4 genuine kept, 1,411 quarantined. After full
regression (unit mocks + live runs appended 508): 512 → 8 genuine
kept (4 original + 4 new live), 504 quarantined, 1,915 preserved.
Note: unit suites persist mock-origin records to the default file;
re-run `audit --apply` after unit runs to keep the review corpus
clean (one command; the quarantine is the designed remedy).

## B10 — Visual roles (`src/utils/visualRoles.js`)

AE-xxx action elements (action text + observed container + linked
amounts/recipients + verb-vs-function consistency); finding-element
naming (addresses, fragments, exact digits, limit words) powering
keyword-free warning verification and the §9 specificity tier
(specific/generic, verdict-pinned); post-model role cross-check with
strict REFUTED → stage 15 downgrade.

## Verification

- Unit: 46/46 Cap4 blocks + full `test:unit` green.
- Live: 13 genuine Muse Spark scenarios (`test/live/semanticLiveA|B`),
  all green; 10-investigation qualitative review against the semantic
  rubric (9 scored 19–20/20, 1 scored 17/20, all STRONG, zero
  fabricated refs).
- Regression: `test:e2e` 5/5 + live-evidence 4/4, `demo:agent` green,
  full `test:live` 8/8 files green (museLive 2/2, sparkBehavior 7/7,
  ME-A 4/4, ME-B 4/4, ME-C 3/3, ME-D 3/3, semantic-A 7/7,
  semantic-B 6/6).
- Verification-phase fixes: B7.5 (negation scope, digit runs,
  target/impl framing), B4.6 (inner params citable in registry),
  ME-C fixture given a genuine 3,450-USDC minimum (its zero minimum
  with a fixed quote was never all-agreeing), OCR-worker cleanup in
  screenshot batteries.
- Known limits: no RPC by default (chain reads unavailable);
  proxy/chain/identity/history live reads injected in batteries;
  model value-leniency (MATCH over major gaps) persists and is caught
  by stages 11/13/14, not cured; unit runs re-pollute the default
  corpus file (remedy: `audit --apply`).
