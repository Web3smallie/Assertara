const assert = require('assert');
const fs = require('fs');
const path = require('path');

// SDK packaging + provenance-method tests: the published package is
// self-contained (no requires escaping sdk/), the vendored helpers
// stay behavior-identical to their sources, and the six provenance
// methods hit the right endpoints with client-side digest checks.
// Mocked transport only: no network, no chain, no model.

const ROOT = path.join(__dirname, '..', '..');
const SDK = path.join(ROOT, 'sdk');
const builtinModules = require('module').builtinModules;

function jsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    if (entry.isDirectory()) out.push(...jsFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

function requiresOf(file) {
  const src = fs.readFileSync(file, 'utf8');
  const stripped = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
  const found = [];
  const re = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
  let m;
  while ((m = re.exec(stripped)) !== null) found.push(m[1]);
  return found;
}

function jsonResponse(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function mockFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    const method = (opts && opts.method) || 'GET';
    const u = String(url);
    const base = 'http://policy:1';
    const pth = u.startsWith(base) ? u.slice(base.length) : u;
    const key = `${method} ${pth}`;
    calls.push({ method, path: pth, headers: (opts && opts.headers) || {}, body: opts && opts.body ? JSON.parse(opts.body) : undefined });
    const handler = routes[key] || routes[pth];
    if (!handler) throw new Error(`unexpected fetch ${key}`);
    const out = typeof handler === 'function' ? await handler(u, opts, calls) : handler;
    if (out && typeof out.ok === 'boolean' && typeof out.json === 'function') return out;
    return jsonResponse(200, out);
  };
  return { fetchImpl, calls };
}

function makeExport({ digest, manifest, attestation } = {}) {
  const { canonicalStringify, sha256Hex } = require('../../sdk/internal/canonicalJson');
  const man = manifest || { investigationId: 'eval_1', traceId: 'tr_1', requestId: 'req_1' };
  const recomputed = digest || sha256Hex(canonicalStringify(man));
  return {
    format: 'assertara-attestation-export-1',
    exportedAt: 1793600000000,
    manifestDigest: recomputed,
    package: {
      manifest: man,
      attestation: attestation === undefined ? { body: { manifestDigest: recomputed }, signature: '0x00', authority: '0xabc' } : attestation
    }
  };
}

async function runSdkPackageTests() {
  console.log('Testing SDK packaging + provenance methods...\n');
  const { AssertaraClient } = require('../../sdk/client');
  const { Investigation } = require('../../sdk/investigation');
  const { AssertaraError, CODES } = require('../../sdk/errors');

  // Test 1: self-containment — no sdk require escapes sdk/; bare
  // requires are node builtins only.
  {
    const files = jsFiles(SDK);
    assert.ok(files.length >= 8, `sdk/ holds the runtime files (saw ${files.length})`);
    const builtins = new Set(builtinModules.map((m) => m.replace(/^node:/, '')));
    for (const file of files) {
      for (const target of requiresOf(file)) {
        if (target.startsWith('.')) {
          const resolved = path.normalize(path.join(path.dirname(file), target));
          const rel = path.relative(SDK, resolved);
          assert.ok(rel && !rel.startsWith('..') && !path.isAbsolute(rel),
            `${path.relative(ROOT, file)} escapes sdk/ via ${target}`);
          const withJs = resolved.endsWith('.js') ? resolved : `${resolved}.js`;
          assert.ok(fs.existsSync(resolved) || fs.existsSync(withJs) || fs.existsSync(path.join(resolved, 'index.js')),
            `${path.relative(ROOT, file)} requires missing ${target}`);
        } else {
          assert.ok(builtins.has(target.split('/')[0].replace(/^node:/, '')),
            `${path.relative(ROOT, file)} requires non-builtin ${target}`);
        }
      }
    }
    console.log(`✔ Test 1 Passed: ${files.length} sdk file(s) self-contained (builtins only).`);
  }

  // Test 2: vendored helpers stay behavior-identical to their sources.
  {
    const sdkDigest = require('../../sdk/internal/txDigest');
    const extDigest = require('../../extension/shared/txDigest');
    assert.deepStrictEqual(Object.keys(sdkDigest).sort(), Object.keys(extDigest).sort(), 'txDigest export parity');
    const tx = { from: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', value: '0x1000', data: '0x', chainId: '0x7a69' };
    assert.strictEqual(sdkDigest.digestTx(tx), extDigest.digestTx(tx), 'digestTx parity');
    const sdkCanon = require('../../sdk/internal/canonicalJson');
    const srcCanon = require('../../src/utils/canonicalJson');
    assert.deepStrictEqual(Object.keys(sdkCanon).sort(), Object.keys(srcCanon).sort(), 'canonicalJson export parity');
    const fixture = { b: [3, 1, { z: null, a: 'x' }], a: 1 };
    assert.strictEqual(sdkCanon.canonicalStringify(fixture), srcCanon.canonicalStringify(fixture), 'canonical bytes parity');
    assert.strictEqual(sdkCanon.sha256Hex('abc'), srcCanon.sha256Hex('abc'), 'sha256 parity');
    console.log('✔ Test 2 Passed: vendored txDigest + canonicalJson match their sources.');
  }

  // Test 3: package manifest is valid and covers every runtime file.
  {
    const manifest = JSON.parse(fs.readFileSync(path.join(SDK, 'package.json'), 'utf8'));
    assert.strictEqual(manifest.name, 'assertara', 'package name');
    assert.ok(/^\d+\.\d+\.\d+/.test(manifest.version), 'semver version');
    assert.strictEqual(manifest.main, 'index.js', 'main entry');
    assert.ok(!manifest.dependencies || Object.keys(manifest.dependencies).length === 0, 'zero runtime dependencies');
    assert.ok(manifest.engines && manifest.engines.node, 'engines.node declared');
    const listed = new Set(manifest.files || []);
    for (const f of ['index.js', 'client.js', 'investigation.js', 'guardedWallet.js', 'errors.js', 'digest.js', 'sse.js', 'internal/', 'README.md']) {
      assert.ok(listed.has(f), `files[] lists ${f}`);
      assert.ok(fs.existsSync(path.join(SDK, f)), `${f} exists`);
    }
    const top = require('../../sdk/index');
    for (const k of ['AssertaraClient', 'Investigation', 'createGuardedWallet', 'wrapViemWallet', 'wrapEthersSigner', 'AssertaraError', 'CODES', 'TxDigest']) {
      assert.ok(top[k] !== undefined, `index exports ${k}`);
    }
    console.log('✔ Test 3 Passed: sdk/package.json valid; public surface intact.');
  }

  // Test 4: buildManifest/getManifest endpoints + bodies.
  {
    const { fetchImpl, calls } = mockFetch({
      'POST /api/v1/provenance/manifests': { manifest: { id: 1 }, manifestDigest: 'd1' },
      'GET /api/v1/provenance/manifests/d1': { manifest: { id: 1 }, manifestDigest: 'd1' }
    });
    const client = new AssertaraClient({ policyBase: 'http://policy:1', fetchImpl });
    const built = await client.buildManifest('req_1');
    assert.strictEqual(built.manifestDigest, 'd1', 'buildManifest returns digest');
    assert.deepStrictEqual(calls[0].body, { requestId: 'req_1' }, 'buildManifest body');
    const got = await client.getManifest('d1');
    assert.strictEqual(got.manifestDigest, 'd1', 'getManifest returns manifest');
    assert.strictEqual(calls[1].method, 'GET', 'getManifest is GET');
    await assert.rejects(client.buildManifest(''), /requestId/, 'buildManifest requires requestId');
    await assert.rejects(client.getManifest(''), /digest/, 'getManifest requires digest');
    console.log('✔ Test 4 Passed: buildManifest/getManifest endpoints.');
  }

  // Test 5: getExportPackage re-verifies the digest locally.
  {
    const good = makeExport({});
    const { fetchImpl } = mockFetch({ 'GET /api/v1/provenance/exports/any': good });
    const client = new AssertaraClient({ policyBase: 'http://policy:1', fetchImpl });
    const back = await client.getExportPackage('any');
    assert.strictEqual(back.manifestDigest, good.manifestDigest, 'valid export passes');
    const tampered = JSON.parse(JSON.stringify(good));
    tampered.package.manifest.investigationId = 'eval_evil';
    const t1 = mockFetch({ 'GET /api/v1/provenance/exports/any': tampered });
    const c1 = new AssertaraClient({ policyBase: 'http://policy:1', fetchImpl: t1.fetchImpl });
    await assert.rejects(c1.getExportPackage('any'), (e) => e instanceof AssertaraError && e.code === CODES.DIGEST_MISMATCH, 'tampered manifest refused');
    const noAtt = JSON.parse(JSON.stringify(good));
    delete noAtt.package.attestation;
    const t2 = mockFetch({ 'GET /api/v1/provenance/exports/any': noAtt });
    const c2 = new AssertaraClient({ policyBase: 'http://policy:1', fetchImpl: t2.fetchImpl });
    await assert.rejects(c2.getExportPackage('any'), (e) => e instanceof AssertaraError && e.code === CODES.DIGEST_MISMATCH, 'missing attestation refused');
    const wrongShape = { format: 'nope' };
    const t3 = mockFetch({ 'GET /api/v1/provenance/exports/any': wrongShape });
    const c3 = new AssertaraClient({ policyBase: 'http://policy:1', fetchImpl: t3.fetchImpl });
    await assert.rejects(c3.getExportPackage('any'), (e) => e instanceof AssertaraError && e.code === CODES.DIGEST_MISMATCH, 'wrong shape refused');
    console.log('✔ Test 5 Passed: getExportPackage digest binding enforced.');
  }

  // Test 6: operator methods — endpoints, credential forwarding, no retention.
  {
    const { fetchImpl, calls } = mockFetch({
      'POST /api/v1/attestations': { attested: false, preview: { case: 'D' } },
      'POST /api/v1/attestations/publish': { ok: true, txHash: '0xabc' }
    });
    const client = new AssertaraClient({ policyBase: 'http://policy:1', fetchImpl });
    await client.requestAttestation({ digest: 'd1', expectDigest: 'd1', confirm: true, operatorSecret: 'opaque-op' });
    assert.strictEqual(calls[0].body.operatorSecret, 'opaque-op', 'credential forwarded once');
    assert.strictEqual(calls[0].body.confirm, true, 'confirm forwarded');
    assert.strictEqual(calls[0].body.expectDigest, 'd1', 'expectDigest forwarded');
    await client.publishAttestation({ digest: 'd1', operatorSecret: 'opaque-op', confirmations: 2 });
    assert.strictEqual(calls[1].path, '/api/v1/attestations/publish', 'publish path');
    assert.strictEqual(calls[1].body.confirmations, 2, 'confirmations forwarded');
    assert.ok(!('operatorSecret' in client), 'operator credential not retained');
    for (const k of Object.keys(client)) {
      assert.ok(!/secret|private|mnemonic/i.test(k), `no secret-ish client field ${k}`);
      assert.notStrictEqual(client[k], 'opaque-op', `client field ${k} holds no credential`);
    }
    await assert.rejects(client.requestAttestation({ digest: 'd', expectDigest: 'd' }), /operator credential/, 'credential required');
    await assert.rejects(client.requestAttestation({ digest: 'd', operatorSecret: 'x' }), /expectDigest/, 'expectDigest required');
    await assert.rejects(client.publishAttestation({ digest: 'd' }), /operator credential/, 'publish credential required');
    console.log('✔ Test 6 Passed: operator methods forward once, retain nothing.');
  }

  // Test 7: verifyAttestation endpoint + Investigation conveniences.
  {
    const { fetchImpl, calls } = mockFetch({
      'POST /api/v1/attestations/verify': { verdict: 'PASS', checks: [], models: [{ name: 'm' }] },
      'POST /api/v1/provenance/manifests': { manifestDigest: 'd9' },
      'GET /api/v1/provenance/exports/d9': makeExport({})
    });
    const client = new AssertaraClient({ policyBase: 'http://policy:1', fetchImpl });
    const v = await client.verifyAttestation({ digest: 'd9', contractVersion: 2 });
    assert.strictEqual(v.verdict, 'PASS', 'verdict passes through');
    assert.strictEqual(calls[0].body.contractVersion, 2, 'options pass through');
    const inv = new Investigation(client, { requestId: 'req_7', traceId: 'tr_7' });
    const m = await inv.manifest();
    assert.strictEqual(m.manifestDigest, 'd9', 'inv.manifest resolves digest');
    assert.deepStrictEqual(calls[1].body, { requestId: 'req_7' }, 'inv.manifest uses bound requestId');
    const ex = await inv.exportPackage();
    assert.strictEqual(ex.format, 'assertara-attestation-export-1', 'inv.exportPackage resolves + verifies');
    const v2 = await inv.verifyAttestation({});
    assert.strictEqual(v2.verdict, 'PASS', 'inv.verifyAttestation resolves digest');
    console.log('✔ Test 7 Passed: verifyAttestation + Investigation conveniences.');
  }

  console.log('\nAll SDK packaging tests passed.');
}

if (require.main === module) {
  runSdkPackageTests().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { runSdkPackageTests };
