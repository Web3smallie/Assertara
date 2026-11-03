const assert = require('assert');
const fs = require('fs');
const path = require('path');
const builtinModules = require('module').builtinModules;

// Architectural independence, mechanically enforced:
// - agent/ imports ONLY: relative requires within agent/, the public
//   SDK (the installed `assertara` package, resolved in-repo via the
//   root self-reference export), the shared digest helper, and Node
//   builtins. The legacy relative sdk/ path remains tolerated during
//   migration but new code must use the bare specifier.
// - ONLY agent/integrations/assertara.js may import the SDK.
// - NOTHING under agent/ may import src/, demo/, test/, public/,
//   extension/ (except extension/shared/txDigest.js), or npm packages.
// - NOTHING under src/ or sdk/ may import agent/ (no reverse coupling).

const ROOT = path.join(__dirname, '..', '..');
const AGENT_DIR = path.join(ROOT, 'agent');

function jsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...jsFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

function requiresOf(file) {
  const src = fs.readFileSync(file, 'utf8');
  // Strip comments so documented examples cannot trip the scanner.
  const stripped = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
  const found = [];
  const re = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
  let m;
  while ((m = re.exec(stripped)) !== null) found.push(m[1]);
  return found;
}

function runAgentBoundaryTests() {
  console.log('Testing agent/ architectural boundary...\n');
  const files = jsFiles(AGENT_DIR);
  assert.ok(files.length > 0, 'agent/ subsystem exists');
  const builtins = new Set(builtinModules.map((m) => m.replace(/^node:/, '')));

  // Test 1: every agent require() is within the allowed set.
  for (const file of files) {
    const rel = path.relative(ROOT, file);
    for (const target of requiresOf(file)) {
      if (target.startsWith('.')) {
        const resolved = path.normalize(path.join(path.dirname(file), target));
        const relTarget = path.relative(ROOT, resolved);
        const insideAgent = relTarget === 'agent' || relTarget.startsWith(`agent${path.sep}`);
        const isSdk = relTarget === 'sdk' || relTarget.startsWith(`sdk${path.sep}`);
        const isDigest = relTarget === path.join('extension', 'shared', 'txDigest.js')
          || relTarget === path.join('extension', 'shared', 'txDigest');
        assert.ok(
          insideAgent || isSdk || isDigest,
          `${rel} requires forbidden relative target ${target} (-> ${relTarget})`
        );
        if (isSdk) {
          assert.strictEqual(
            rel, path.join('agent', 'integrations', 'assertara.js'),
            `only agent/integrations/assertara.js may import the SDK (violated by ${rel})`
          );
        }
      } else if (target.startsWith('/') || /^[A-Za-z]:[\\/]/.test(target)) {
        assert.fail(`${rel} requires absolute path ${target}`);
      } else {
        const base = target.split('/')[0].replace(/^node:/, '');
        if (target === 'assertara') {
          assert.strictEqual(
            rel, path.join('agent', 'integrations', 'assertara.js'),
            `only agent/integrations/assertara.js may import the SDK package (violated by ${rel})`
          );
          continue;
        }
        assert.ok(builtins.has(base), `${rel} requires non-builtin package ${target}`);
      }
    }
  }
  console.log(`✔ Test 1 Passed: ${files.length} agent file(s) import only agent/, sdk/ (via integrations), digest, builtins.`);

  // Test 2: no reverse coupling from src/ or sdk/ into agent/.
  for (const dir of ['src', 'sdk']) {
    for (const file of jsFiles(path.join(ROOT, dir))) {
      for (const target of requiresOf(file)) {
        assert.ok(
          !/(^|\/)agent(\/|$)/.test(target.replace(/\\/g, '/')) || target.includes('agentAuth') || target.includes('agentStore') || target.includes('agentEvidence') || target.includes('agentConfig') || target.includes('agentController'),
          `${path.relative(ROOT, file)} reverse-imports the agent subsystem via ${target}`
        );
      }
    }
  }
  console.log('✔ Test 2 Passed: src/ and sdk/ never import agent/ (Assertara-side agent* modules exempted by name).');

  console.log('\nAll agent boundary tests passed.');
}

if (require.main === module) {
  runAgentBoundaryTests();
}

module.exports = { runAgentBoundaryTests };
