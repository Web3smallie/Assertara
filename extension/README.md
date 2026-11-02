# Assertara Chrome Extension (MV3)

Advisory pre-sign gate for EVM wallet requests. Assertara intercepts
supported dApp-to-provider calls in the page, HOLDS them without contacting
the wallet, evaluates transactions with the local backend
(`POST http://localhost:3001/api/v1/evaluate`), and releases each request
only after your explicit CONTINUE TO WALLET / CANCEL decision.

It never signs, approves, rejects-in-wallet, submits, or alters requests,
never handles API keys (those stay on the backend), and never touches
wallet recovery material.

## How it works

1. Start the backend first (from the repo root): `npm start`.
   Confirm `http://localhost:3001/health` responds.
2. Load the extension (Load unpacked, select `extension/`), then browse to a
   dApp over HTTPS (or `http://localhost/*` for local development).
3. The page gate wraps the wallet provider. It cannot see inside the wallet
   itself — it holds the dApp-to-provider calls the page already makes.
4. When you trigger a supported request, the wallet confirmation does NOT
   open yet. Assertara automatically evaluates it and an on-page gate card
   appears by itself — first a loading state, then the assessment (or the
   failure/unsupported reason). No toolbar-icon click is needed. The tab
   badge counts held requests.
5. Choose CONTINUE TO WALLET to forward the original unchanged request
   exactly once — the wallet then opens its normal confirmation, where you
   decide again — or CANCEL REQUEST to reject it locally (wallet never
   contacted). Cancel works even while evaluation is still running.
   Decide in the on-page card or via the toolbar popup; closing
   the popup never forwards anything.
6. Nothing is ever automatic: not after MATCH, not after MISMATCH, not
   after errors or timeouts. Every release needs your explicit choice.

## What is genuinely supported

- **Providers:** any EIP-1193 provider exposing `window.ethereum.request()`
  (single or `providers[]` multi-wallet) and EIP-6963 announced providers.
- **Evaluated:** `eth_sendTransaction` and `eth_signTransaction` with a
  recipient address. Chain ID is shown when the provider reports it.
- **Held but not evaluated:** `personal_sign`, `eth_sign`, and
  `eth_signTypedData*` message signatures. The backend evaluates
  transactions, not messages, so these show an explicit unsupported
  gate card and still require your Continue/Cancel choice — they are
  never silently forwarded while the gate is active.
- **Not observed:** legacy `provider.send` / `provider.sendAsync` call
  shapes. dApps using only those are reported as unobservable when
  detected through no other path.
- **Read-only calls pass through:** `eth_call`, `eth_chainId`,
  `eth_getBalance`, account/chain queries, and any unknown method are
  never held or evaluated.

## Supported environments and request paths

- **Browser:** Chromium with Manifest V3 content scripts in both `MAIN`
  and `ISOLATED` worlds (`minimum_chrome_version 111`). Chrome branded
  builds ignore `--load-extension` in some environments; use Load
  unpacked with Developer mode, or a Chromium build that honors the
  flag, for automated loading.
- **Pages:** top frames of `https://*/*` plus `http://localhost/*` and
  `http://127.0.0.1/*` for local dApp development. Iframes are not
  instrumented (`all_frames: false`); a dApp that issues wallet calls
  from a cross-origin iframe is not intercepted and is not reported
  as protected.
- **Wallets:** any wallet whose dApp-facing calls flow through a page
  `request()` provider (`window.ethereum`, `providers[]`, or EIP-6963
  announcements). Provider objects injected after page load are picked
  up by bounded polling plus `eip6963:requestProvider` solicitation.
- **Held request path:** dApp `provider.request({method, params})` →
  held in the page → validated bridge relay → service-worker gate →
  backend investigation → on-page card + popup → exactly-once forward
  or local 4001 cancel. Closing the popup, navigating, closing the
  tab, worker restarts, and the 10-minute decision timeout (enforced
  in the page, backed by worker sweep) can only cancel or abandon —
  never forward.
- **Not a protected path:** wallet-to-wallet-extension channels the
  page never sees, legacy `send`/`sendAsync` shapes, non-HTTPS pages
  (except localhost), restricted pages, and overflow beyond 20 held
  requests per tab (explicit bypass note, fails open).

## Permissions

| Permission | Why it is needed |
|---|---|
| Page observer (`https://*/*`, `http://localhost/*`, `http://127.0.0.1/*`, MAIN world, `document_start`) | The only browser-supported way to observe pending provider requests pre-sign. Runs only the provider observer; collects page title/URL/visible text (4000 chars, never input values) at request time. |
| `activeTab` | Read the current tab's URL/title after you click the icon; screenshot and overlay injection only after that click. No background access. |
| `scripting` | Inject the overlay into the active tab on demand. |
| `http://localhost:3001/*` (host) | Talk to the local Assertara backend only. No other hosts. |

There is deliberately no `<all_urls>` host permission, no `tabs` bulk
access, no cookie/history access, and no remote code.

## Honest limitations

- **Gate holds the dApp call, not the wallet.** Holding works because the
  dApp calls through the wrapped provider. A wallet talking to its own
  extension through non-page channels cannot be held; such requests are
  reported as bypassed, never claimed as protected.
- **Decision timeout.** Awaiting requests expire after 10 minutes as
  local cancellations (wallet never contacted), enforced by a page-side
  timer with a worker-side sweep as backup. Navigating away or
  closing the tab abandons held requests the same way.
- **Service-worker restarts.** In-flight evaluations are marked failed
  after a restart (the backend result can no longer arrive); held
  requests stay held and decidable.
- **Overflow bypass.** More than 20 held requests on one tab fails open
  for the excess (dApp keeps working) with an explicit popup note.
- **Overlay needs one click.** The post-assessment overlay injection
  requires host access the extension does not take; clicking the toolbar
  icon grants `activeTab`, after which **Show on page** works.
- **Screenshot is opportunistic.** Without the icon click there is no
  capture grant, so auto-flow evaluations usually run on page context
  only and say so explicitly.
- **Message signing is out of scope** for evaluation (see above).
- **Restricted pages.** `chrome://`, the web store, and similar pages
  forbid content scripts; the popup reports them as unobservable.
- **Fixed backend URL.** The MVP targets `http://localhost:3001` (the
  backend default). If `PORT` is changed server-side, update the
  extension constants.

## Manual verification checklist

- [ ] `chrome://extensions` shows Assertara 1.0.0 with no manifest errors or warnings.
- [ ] Popup on a dApp tab: protection "Watching", backend "Backend online".
- [ ] Trigger a test transaction (test account, never real funds): wallet
      confirmation stays CLOSED; gate card appears by itself with a loading
      state (no icon click), then the assessment; CANCEL keeps the wallet
      silent; CONTINUE opens the wallet prompt once.
- [ ] CANCEL while the card still shows the loading state: wallet stays
      silent, card closes, late backend result never surfaces.
- [ ] Leave a held request undecided past 10 minutes: dApp call rejects
      locally, wallet stays silent, card closes.
- [ ] `MISMATCH` (red) visually distinct from `MATCH` (blue `=` badge) and
      `UNCERTAIN` (amber); result shows verdict, summary, confidence,
      contract, function, safeguards, cap, action.
- [ ] "Show on page" renders the overlay with verdict, facts, findings,
      simulation status, action, disclaimer, close button.
- [ ] Trigger `personal_sign`: gate card reports message signing held but
      unevaluable (no fabricated verdict); explicit Continue/Cancel required.
- [ ] Stop the backend → assessment fails with a clear error stating the
      request was NOT blocked or verified (no hang, no fake result).
- [ ] DevTools → Network: extension requests go to `localhost:3001` only
      and carry no `Authorization` header or API key.
- [ ] dApp works identically with the extension enabled vs disabled apart
      from Assertara's own UI (forwarding is transparent).
