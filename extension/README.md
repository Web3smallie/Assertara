# Assertara Chrome Extension (MV3 MVP)

On-page advisory for EVM wallet transactions. The extension collects page
context, sends it with a user-supplied transaction to the local Assertara
backend (`POST http://localhost:3001/api/v1/evaluate`), and renders the
backend's own evidence bundle (`MATCH` / `MISMATCH` / `UNCERTAIN`).

It never signs, submits, approves, blocks, or alters transactions, and never
handles API keys — those stay on the backend.

## Load unpacked (developer mode)

1. Start the backend first (from the repo root): `npm start`.
   Confirm `http://localhost:3001/health` responds.
2. Open `chrome://extensions`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the `extension/` directory in this repo.
5. Pin Assertara to the toolbar (puzzle icon → pin).

No extra options or manual permission grants are needed for the basic flow.

## Permissions (minimal)

| Permission | Why it is needed |
|---|---|
| `activeTab` | Read the current tab's URL/title and capture its visible screenshot, only after you click Inspect. No background access. |
| `scripting` | Inject the context collector and advisory overlay into the active tab on demand. |
| `http://localhost:3001/*` (host) | Talk to the local Assertara backend only. No other hosts. |

There is deliberately no `<all_urls>`, no `tabs` bulk access, no cookie/history access, and no remote code.

## Try it (three demo scenarios)

1. With the backend running, open a fixture page, e.g.
   `http://localhost:3001/demo/phishing-airdrop/`.
2. Click the Assertara toolbar icon. The popup shows the page and backend status.
3. Click a **Demo** button to load that scenario's real transaction, then
   **Inspect Transaction**. Demos are repository fixtures evaluated for real —
   nothing is mocked.
4. Read the verdict, summary, facts, and recommended action.
5. Click **Show on page** for the on-page advisory overlay (close with ✕).

For a live dApp instead of a demo: paste the `to` address (and calldata/value
when your wallet shows them) into the form, keeping the dApp visible, then
inspect. The form is labeled **manual entry** — always verify fields against
your wallet. The extension cannot read your wallet and does not claim otherwise.

## Manual verification checklist

- [ ] `chrome://extensions` shows Assertara 1.0.0 with no manifest errors or warnings.
- [ ] Popup opens, shows the current page domain/URL/title.
- [ ] Backend badge reads "Backend online" while `npm start` runs.
- [ ] Demo airdrop → `MISMATCH` (red), visually distinct from `MATCH` (green).
- [ ] Demo swap → `MATCH`; demo unknown contract → `UNCERTAIN` (amber).
- [ ] Popup result shows verdict, summary, confidence, contract, function, action.
- [ ] "Show on page" renders the overlay: verdict, explanation, decoded facts,
      rule findings, simulation status, recommended action, disclaimer, close button.
- [ ] Overlay close button removes it; page keeps working.
- [ ] Stop the backend → popup shows "Backend offline" and inspection fails with
      a clear error (no hang, no fake result).
- [ ] DevTools → Network: extension requests go to `localhost:3001` only and
      carry no `Authorization` header or API key.

## Known limitations

- **Transaction capture is manual.** The extension cannot reliably intercept
  wallet provider calls without invasive hooks, so the user pastes or confirms
  transaction details. Manually supplied data is labeled as such.
- **Screenshot association.** The screenshot shows the visible page at inspect
  time; it alone cannot prove which transaction a wallet will execute.
- **Simulation.** The backend simulates selected suspicious transactions where
  supported; otherwise the overlay states that simulation was not performed.
- **Restricted pages.** `chrome://`, the web store, and similar pages forbid
  content injection and screenshots; inspection falls back to tab metadata.
- **Fixed backend URL.** The MVP targets `http://localhost:3001` (the backend
  default). If `PORT` is changed server-side, update the extension constants.
