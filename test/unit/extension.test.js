const assert = require('assert');
const fs = require('fs');
const path = require('path');

const EXT_DIR = path.resolve(__dirname, '../../extension');

function readExtFile(relativePath) {
  return fs.readFileSync(path.join(EXT_DIR, relativePath), 'utf8');
}

function listExtFiles(dir = EXT_DIR) {
  let out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out = out.concat(listExtFiles(full));
    else out.push(full);
  }
  return out;
}

function runExtensionTests() {
  console.log('Testing Assertara Extension Manifest, Permissions & Helpers...\n');

  // Test 1: Manifest V3, Assertara branding, minimal permissions.
  const manifest = JSON.parse(readExtFile('manifest.json'));
  assert.strictEqual(manifest.manifest_version, 3, 'Must be Manifest V3');
  assert.strictEqual(manifest.name, 'Assertara', 'Product name must be Assertara');
  assert.ok(!(manifest.name || '').toLowerCase().includes('visual sentry'), 'Must not be renamed');
  const permissions = manifest.permissions || [];
  assert.ok(permissions.includes('activeTab'), 'Needs activeTab for user-gated capture');
  assert.ok(permissions.includes('scripting'), 'Needs scripting for on-demand injection');
  for (const p of permissions) {
    assert.ok(['activeTab', 'scripting'].includes(p), `Permission not minimal: ${p}`);
  }
  const hosts = manifest.host_permissions || [];
  assert.ok(hosts.length > 0, 'Must declare a backend host permission');
  for (const h of hosts) {
    assert.ok(!h.includes('*://*/') && h !== '<all_urls>', `Host permission too broad: ${h}`);
    assert.ok(h.includes('localhost'), `Host permission must be localhost-only: ${h}`);
  }
  // Exactly two declared content scripts: the MAIN-world gate observer and
  // the ISOLATED bridge, on the narrowest dApp-capable matches.
  const cs = manifest.content_scripts || [];
  assert.strictEqual(cs.length, 2, 'MAIN gate + ISOLATED bridge content scripts');
  const MATCHES = ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'];
  const main = cs.find((e) => e.world === 'MAIN');
  const iso = cs.find((e) => e.world === 'ISOLATED');
  assert.ok(main && iso, 'Must declare one MAIN and one ISOLATED entry');
  for (const entry of [main, iso]) {
    assert.deepStrictEqual(entry.matches, MATCHES);
    assert.strictEqual(entry.run_at, 'document_start');
    assert.ok((entry.js || []).includes('shared/gate.js'), 'Both worlds must load the gate protocol');
  }
  assert.ok(main.js.includes('content/provider.js'), 'MAIN entry must be the gate observer');
  assert.deepStrictEqual(iso.js, ['shared/gate.js', 'shared/format.js', 'content/bridge.js'], 'ISOLATED entry must be gate+format+bridge');
  for (const f of ['content/provider.js', 'content/bridge.js', 'shared/gate.js']) {
    assert.ok(fs.existsSync(path.join(EXT_DIR, f)), `Gate file must exist: ${f}`);
  }
  assert.ok(fs.existsSync(path.join(EXT_DIR, manifest.background.service_worker)), 'Service worker file must exist');
  assert.ok(fs.existsSync(path.join(EXT_DIR, manifest.action.default_popup)), 'Popup file must exist');
  console.log('✔ Test 1 Passed: Manifest is MV3, Assertara-branded, least-privilege.');

  // Test 2: No secrets, no remote code, localhost-only network in extension code.
  const codeFiles = listExtFiles().filter((f) => /\.(js|html|json)$/.test(f));
  assert.ok(codeFiles.length > 0, 'Extension must contain code files');
  for (const file of codeFiles) {
    const content = fs.readFileSync(file, 'utf8');
    const rel = path.relative(EXT_DIR, file);
    assert.ok(!/MODEL_API_KEY\s*=\s*['"][^'"]+['"]/.test(content), `${rel} must not embed an API key`);
    assert.ok(!/api[_-]?key\s*[:=]\s*['"][A-Za-z0-9_\-]{8,}['"]/i.test(content), `${rel} must not embed a key value`);
    assert.ok(!/Authorization['"]?\s*:\s*['"]?Bearer\s+\w/.test(content), `${rel} must not send bearer tokens`);
    assert.ok(!/<script[^>]+src\s*=\s*['"]https?:\/\//i.test(content), `${rel} must not load remote scripts`);
    assert.ok(!/fetch\(\s*['"]https:\/\/(?!localhost)/.test(content), `${rel} must not fetch non-localhost hosts`);
  }
  const popupHtml = readExtFile('popup/popup.html');
  for (const match of popupHtml.matchAll(/<script[^>]+src\s*=\s*['"]([^'"]+)['"]/gi)) {
    assert.ok(!/^https?:\/\//i.test(match[1]), `Popup script must be local: ${match[1]}`);
    assert.ok(fs.existsSync(path.join(EXT_DIR, 'popup', match[1])), `Popup script must exist: ${match[1]}`);
  }
  console.log('✔ Test 2 Passed: No embedded secrets or remote code; localhost-only network.');

  // Test 3: Shared pure helpers behave (loaded directly from the extension dir).
  require('../../extension/shared/format.js');
  const F = globalThis.AssertaraFormat;
  assert.strictEqual(F.verdictClass('MATCH'), 'match');
  assert.strictEqual(F.verdictClass('MISMATCH'), 'mismatch');
  assert.strictEqual(F.verdictClass('UNCERTAIN'), 'uncertain');
  assert.strictEqual(F.verdictClass('bogus'), 'uncertain', 'Unknown verdicts fall back to uncertain styling');
  assert.strictEqual(F.verdictLabel('match'), 'MATCH');
  assert.strictEqual(F.escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
  assert.strictEqual(F.shortAddress('0xdAC17F958D2ee523a2206206994597C13D831ec7'), '0xdAC1…1ec7');
  assert.strictEqual(F.isValidAddress('0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45'), true);
  assert.strictEqual(F.isValidAddress('0x123'), false);
  assert.strictEqual(F.isValidAddress(''), false);
  assert.strictEqual(F.formatConfidence(0.95), '95%');
  assert.ok(F.simulationStatus(null).startsWith('Not performed'), 'Missing simulation must say so');
  assert.ok(F.simulationStatus({ status: 'NOT_RUN', executed: false }).startsWith('Not performed'), 'NOT_RUN must not look successful');
  assert.ok(F.simulationStatus({ status: 'EXECUTED', executed: true, success: true, mode: 'foundry-anvil', assetDeltas: [] }).startsWith('Executed successfully'), 'Genuine execution must say so');
  const failedExec = F.simulationStatus({ status: 'EXECUTED', executed: true, success: false, error: 'revert' });
  assert.ok(failedExec.includes('FAILED') && failedExec.includes('revert'), 'Failed execution must show the real error');
  const fallback = F.simulationStatus({ status: 'FALLBACK', executed: false, success: false, reason: 'No EVM simulation ran.', fallbackAnalysis: [] });
  assert.ok(fallback.startsWith('Not executed'), 'Fallback must never claim execution');
  const failed = F.simulationStatus({ status: 'FAILED', executed: false, error: 'timed out' });
  assert.ok(failed.includes('Attempted but failed') && failed.includes('timed out'), 'FAILED must show the error');
  // Safeguard + cap display (UI gap fix): exact trigger/reason text, honest
  // empty/missing states, original-vs-final confidence preserved.
  const one = F.safeguardText([{ trigger: 'UNKNOWN_FUNCTION', from: 'MATCH', to: 'UNCERTAIN', reason: 'Function 0xdead could not be decoded.' }]);
  assert.strictEqual(one, '1 safeguard triggered: UNKNOWN_FUNCTION: Function 0xdead could not be decoded.');
  const two = F.safeguardText([
    { trigger: 'INVALID_VERDICT', reason: 'Bad verdict.' },
    { trigger: 'UNKNOWN_FUNCTION', reason: 'Unknown fn.' }
  ]);
  assert.ok(two.startsWith('2 safeguards triggered:') && two.includes('INVALID_VERDICT') && two.includes('UNKNOWN_FUNCTION'));
  assert.strictEqual(F.safeguardText([]), 'None triggered.', 'Empty list must not warn');
  assert.strictEqual(F.safeguardText(null), 'Safeguard information unavailable.');
  assert.strictEqual(F.safeguardText(undefined), 'Safeguard information unavailable.', 'Missing field is unknown, not none');
  assert.strictEqual(F.safeguardText('oops'), 'Safeguard information unavailable.');
  assert.ok(F.safeguardText([{ trigger: 'X' }]).includes('no reason recorded'), 'Missing reason labeled, trigger kept');
  assert.ok(F.safeguardText([null, 42]).includes('Unrecognized safeguard record'), 'Malformed entries contained');
  assert.ok(F.safeguardText({ trigger: 'UNKNOWN_FUNCTION', reason: 'r' }).startsWith('1 safeguard triggered:'), 'Legacy single object supported');
  const capped = F.confidenceCapText({ trigger: 'ZERO_USABLE_OCR_TEXT', previousConfidence: 0.9, cap: 0.65, reason: 'Screenshot supplied but no usable OCR text.' });
  assert.ok(capped.includes('65%') && capped.includes('90%'), 'Capped and original values both shown');
  assert.ok(capped.includes('Screenshot supplied but no usable OCR text.'), 'Cap reason shown');
  assert.strictEqual(F.confidenceCapText(null), 'No confidence cap applied.');
  assert.strictEqual(F.confidenceCapText(undefined), 'No confidence cap applied.');
  assert.strictEqual(F.confidenceCapText('65%'), 'Confidence-cap information unavailable.');
  assert.strictEqual(F.confidenceCapText({}), 'Confidence-cap information unavailable.', 'Cap object without a cap value is unknown');
  assert.strictEqual(F.confidenceCapText({ cap: NaN }), 'Confidence-cap information unavailable.');
  const noPrev = F.confidenceCapText({ trigger: 'T', cap: 0.65 });
  assert.ok(noPrev.includes('65%') && !noPrev.includes('was'), 'Missing previous value omitted, not invented');
  console.log('✔ Test 3 Passed: Shared format helpers behave correctly.');

  // Test 4: Popup and overlay render the backend's actual evidence fields.
  const popupJs = readExtFile('popup/popup.js');
  for (const field of ['verdict', 'summary', 'confidence', 'decodedTransaction', 'recommendedAction', 'ruleFindings', 'verdictSafeguards', 'confidenceCap']) {
    assert.ok(popupJs.includes(field) || readExtFile('content/overlay.js').includes(field),
      `Extension UI must render evidence field: ${field}`);
  }
  // Safeguard/cap wiring (UI gap fix): both surfaces must call the shared
  // formatters and the popup must provide the target elements.
  for (const fn of ['F.safeguardText(', 'F.confidenceCapText(']) {
    assert.ok(popupJs.includes(fn), `Popup must call shared formatter: ${fn}`);
    assert.ok(readExtFile('content/overlay.js').includes(fn), `Overlay must call shared formatter: ${fn}`);
  }
  for (const id of ['resultSafeguards', 'resultCap']) {
    assert.ok(readExtFile('popup/popup.html').includes(`id="${id}"`), `Popup markup must include #${id}`);
  }
  const overlayJs = readExtFile('content/overlay.js');
  assert.ok(overlayJs.includes('attachShadow'), 'Overlay must scope styles via shadow DOM');
  assert.ok(overlayJs.includes('safetyNotice'), 'Overlay must show the backend disclaimer');
  assert.ok(overlayJs.includes('textSources'), 'Overlay must render text-source provenance');
  assert.ok(!/MATCH\s*(means|implies).*safe/i.test(overlayJs + popupJs), 'UI must never claim MATCH means safe');
  const swJs = readExtFile('service-worker.js');
  assert.ok(swJs.includes('visibleText'), 'Service worker must forward collected DOM text to the backend');
  console.log('✔ Test 4 Passed: UI renders real evidence fields with honest safety wording.');

  // Test 5: Pre-sign gate — demo UI gone, holding gate wired, never signs.
  const html = readExtFile('popup/popup.html');
  for (const gone of ['demo-btn', 'Demo:', 'txTo', 'txData', 'inspectBtn', 'txSourceNote', 'formSection', 'requestSection']) {
    assert.ok(!html.includes(gone), `Popup markup must not contain demo/form remnant: ${gone}`);
  }
  for (const id of ['protectionStatus', 'pendingList', 'refreshBtn', 'verdictBadge', 'resultSection', 'backBtn']) {
    assert.ok(html.includes(`id="${id}"`), `Popup markup must include #${id}`);
  }
  for (const gone of ['DEMO_TRANSACTIONS', 'fillDemo', 'ASSERTARA_INSPECT', 'readTransactionForm', 'ASSERTARA_SIGNING_REQUEST']) {
    assert.ok(!popupJs.includes(gone), `Popup logic must not contain demo remnant: ${gone}`);
  }
  assert.ok(popupJs.includes('ASSERTARA_GET_TAB_STATE'), 'Popup must load per-tab gate state');
  assert.ok(popupJs.includes('ASSERTARA_DECIDE'), 'Popup must deliver working decisions');
  assert.ok(popupJs.includes('Continue to wallet') && popupJs.includes('Cancel request'), 'Popup must show explicit decision actions');
  for (const msg of ['ASSERTARA_GATED_REQUEST', 'ASSERTARA_DECIDE', 'ASSERTARA_TAB_OBSERVED', 'ASSERTARA_GET_TAB_STATE', 'ASSERTARA_GATE_DECISION', 'ASSERTARA_GATE_EXPIRED']) {
    assert.ok(swJs.includes(msg), `Service worker must handle ${msg}`);
  }
  assert.ok(!swJs.includes('ASSERTARA_INSPECT'), 'Manual-inspect handler must be removed');
  assert.ok(!swJs.includes('.request('), 'Service worker must never invoke wallet RPC');
  assert.ok(!swJs.includes('sendRawTransaction'), 'Service worker must never send transactions');
  assert.ok(swJs.includes('shared/gate.js'), 'Service worker must load the shared gate protocol');
  const providerJs = readExtFile('content/provider.js');
  for (const need of ['Gate.TX_METHODS', 'eip6963:announceProvider', '__assertaraGated', 'INTERCEPTED', 'pending.set', 'postMessage']) {
    assert.ok(providerJs.includes(need), `Gate observer must include: ${need}`);
  }
  assert.ok(!providerJs.includes('chrome.'), 'MAIN-world gate must not touch chrome.* (bridge only)');
  const bridgeJs = readExtFile('content/bridge.js');
  for (const need of ['ASSERTARA_GATE_UPDATE', 'ASSERTARA_GATE_DECISION', 'ASSERTARA_GATE_EXPIRED', 'CONTINUE TO WALLET', 'CANCEL REQUEST', 'sender.id !== chrome.runtime.id', 'validateMainMessage', 'Evaluating with the local backend']) {
    assert.ok(bridgeJs.includes(need), `Bridge must include: ${need}`);
  }
  const gateJs = readExtFile('shared/gate.js');
  for (const need of ['AWAITING_USER_DECISION', 'FORWARDED_TO_WALLET', 'USER_CANCELLED', 'createGateStore', 'validateIsoMessage', 'cancellationError']) {
    assert.ok(gateJs.includes(need), `Shared gate protocol must include: ${need}`);
  }
  for (const f of [providerJs, bridgeJs, gateJs, swJs, popupJs]) {
    assert.ok(!/seed|mnemonic|private_?key/i.test(f), 'Extension code must never reference seed phrases or private keys');
  }
  assert.ok(!fs.existsSync(path.join(EXT_DIR, 'content/context.js')), 'Obsolete on-demand context collector must be removed');
  console.log('✔ Test 5 Passed: Demo UI removed; pre-sign gate wired; wallet-safe.');

  console.log('\nAll Extension Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runExtensionTests();
}

module.exports = { runExtensionTests };
