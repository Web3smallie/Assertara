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
  assert.ok(!manifest.content_scripts, 'Must not auto-inject into every page');
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
  console.log('✔ Test 3 Passed: Shared format helpers behave correctly.');

  // Test 4: Popup and overlay render the backend's actual evidence fields.
  const popupJs = readExtFile('popup/popup.js');
  for (const field of ['verdict', 'summary', 'confidence', 'decodedTransaction', 'recommendedAction', 'ruleFindings']) {
    assert.ok(popupJs.includes(field) || readExtFile('content/overlay.js').includes(field),
      `Extension UI must render evidence field: ${field}`);
  }
  const overlayJs = readExtFile('content/overlay.js');
  assert.ok(overlayJs.includes('attachShadow'), 'Overlay must scope styles via shadow DOM');
  assert.ok(overlayJs.includes('safetyNotice'), 'Overlay must show the backend disclaimer');
  assert.ok(overlayJs.includes('textSources'), 'Overlay must render text-source provenance');
  assert.ok(!/MATCH\s*(means|implies).*safe/i.test(overlayJs + popupJs), 'UI must never claim MATCH means safe');
  const swJs = readExtFile('service-worker.js');
  assert.ok(swJs.includes('visibleText'), 'Service worker must forward collected DOM text to the backend');
  console.log('✔ Test 4 Passed: UI renders real evidence fields with honest safety wording.');

  console.log('\nAll Extension Unit Tests Passed Successfully!\n');
}

if (require.main === module) {
  runExtensionTests();
}

module.exports = { runExtensionTests };
