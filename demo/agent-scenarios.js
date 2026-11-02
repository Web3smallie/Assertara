/**
 * Scripted adversarial agent scenarios + performance benchmarks.
 *
 * Drives the 10 Part-4 scenarios through a real stack (Anvil + policy
 * app + separate signer process) and records decisions, findings,
 * timings, and trace snapshots. Also runs repeat benchmarks with
 * avg/P50/P95/min/max and cold-vs-warm splits.
 *
 * Run:
 *   node demo/agent-scenarios.js [--mock-model] [--release] [--bench <id> --n 5] [--only <id>]
 *   --mock-model: heuristic path (labeled MOCK); default is LIVE model.
 *   --release:    authorize REVIEW decisions with the boot operator
 *                 secret (labeled OPERATOR STAND-IN; production: human).
 *   --bench:      repeat one scenario N times for latency stats.
 *   --only:       run a single scenario id.
 *
 * Results: demo/tmp/agent-scenarios-<ts>.json (full) + console report.
 * Anvil only. Never mainnet, never real value.
 */

const fs = require('fs');
const path = require('path');
const { bootStack } = require('./command-stack');
const { buildScenarios, LOCAL_ADDRS } = require('./scenarios');

async function post(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function get(url) {
  const res = await fetch(url);
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function waitForExecution(policyBase, requestId, timeoutMs) {
  const start = Date.now();
  for (;;) {
    const { json } = await get(`${policyBase}/api/v1/agent/requests/${requestId}`);
    if (json && json.execution) return json;
    if (Date.now() - start > timeoutMs) return json;
    await new Promise((r) => setTimeout(r, 1000));
  }
}

function summarizeTrace(snap) {
  if (!snap || !Array.isArray(snap.spans)) return { spans: 0, byComponent: {}, model: null, durationMs: null };
  const byComponent = {};
  let model = null;
  for (const s of snap.spans) {
    (byComponent[s.component] = byComponent[s.component] || []).push({ status: s.status, ms: s.durationMs });
    if (s.component === 'muse-spark') model = { status: s.status, ms: s.durationMs, extra: s.extra || null, summary: s.summary || s.error || '' };
  }
  return { spans: snap.spans.length, byComponent, model, durationMs: snap.durationMs, traceStatus: snap.status };
}

async function runOne(policyBase, signerBase, scenario, { release, operatorSecret }) {
  const rec = { id: scenario.id, name: scenario.name, objective: scenario.objective, transaction: scenario.transaction };
  const t0 = Date.now();
  const { status, json } = await post(`${policyBase}/api/v1/agent/propose`, {
    agentId: 'scenario-runner', intent: { purpose: scenario.objective }, transaction: scenario.transaction
  });
  rec.proposeMs = Date.now() - t0;
  rec.httpStatus = status;
  if (status !== 200) {
    rec.error = json.error || `http ${status}`;
    return rec;
  }
  rec.requestId = json.requestId;
  rec.traceId = json.traceId || null;
  rec.decision = json.decision;
  rec.reasons = json.reasons;
  rec.investigation = json.investigation;
  rec.mandateChecks = json.mandateChecks;
  let approval = json.approval || null;

  if (json.decision === 'REVIEW' && release) {
    const auth = await post(`${policyBase}/api/v1/agent/requests/${json.requestId}/authorize`, { operatorSecret });
    rec.released = auth.status === 200 && auth.json.authorized === true;
    rec.releaseNote = 'OPERATOR STAND-IN: script countersigned with the boot operator secret (production: human operator).';
    if (rec.released) approval = auth.json.approval;
  }

  if (approval && (json.decision === 'ALLOW' || rec.released)) {
    const t1 = Date.now();
    const signed = await post(`${signerBase}/sign`, { requestId: json.requestId, transaction: scenario.transaction, approval });
    rec.signMs = Date.now() - t1;
    rec.signOk = signed.status === 200 && signed.json.ok === true;
    rec.signError = rec.signOk ? null : (signed.json.error || `http ${signed.status}`);
    rec.txHash = rec.signOk ? signed.json.txHash : null;
    if (rec.signOk) {
      const t2 = Date.now();
      const st = await waitForExecution(policyBase, json.requestId, 30000);
      rec.receiptMs = Date.now() - t2;
      rec.execution = st.execution || null;
      rec.finalStatus = st;
    }
  } else {
    const st = await get(`${policyBase}/api/v1/agent/requests/${json.requestId}`);
    rec.finalStatus = st.json;
  }

  if (rec.traceId) {
    const snap = await get(`${policyBase}/api/v1/observations/traces/${rec.traceId}`);
    rec.trace = snap.status === 200 ? summarizeTrace(snap.json) : { error: `trace ${snap.status}` };
    rec.traceFull = snap.status === 200 ? snap.json : null;
  }
  if (rec.finalStatus && rec.finalStatus.investigation && rec.finalStatus.investigation.evalId) {
    const found = await get(`${policyBase}/api/v1/observations/investigations/by-eval/${rec.finalStatus.investigation.evalId}`);
    rec.bundleAvailable = found.status === 200;
    if (found.status === 200) {
      const b = found.json.record;
      rec.bundle = {
        verdict: b.verdict, confidence: b.confidence, modelId: b.modelId,
        promptVersion: b.promptVersion, latencyMs: b.latencyMs, usage: b.usage,
        ruleFindings: (b.ruleFindings || []).map((f) => f.ruleId),
        safeguards: (b.verdictSafeguards || []).map((s) => s.trigger)
      };
    }
  }
  rec.totalMs = Date.now() - t0;
  return rec;
}

function stats(arr) {
  const xs = arr.filter((n) => Number.isFinite(n)).sort((a, b) => a - b);
  if (xs.length === 0) return { n: 0 };
  const q = (p) => xs[Math.min(xs.length - 1, Math.floor(p * xs.length))];
  return {
    n: xs.length,
    avg: Math.round(xs.reduce((a, b) => a + b, 0) / xs.length),
    p50: q(0.5), p95: q(0.95), min: xs[0], max: xs[xs.length - 1]
  };
}

async function main() {
  const args = process.argv.slice(2);
  const mockModel = args.includes('--mock-model');
  const release = args.includes('--release');
  const onlyIx = args.indexOf('--only');
  const only = onlyIx !== -1 ? args[onlyIx + 1] : null;
  const benchIx = args.indexOf('--bench');
  const benchId = benchIx !== -1 ? args[benchIx + 1] : null;
  const nIx = args.indexOf('--n');
  const benchN = nIx !== -1 ? Math.max(1, Math.min(50, Number(args[nIx + 1]) || 5)) : 5;

  const stack = await bootStack({ mockModel });
  console.log(`stack up: app=${stack.policyBase} signer=${stack.signerBase} model=${mockModel ? 'MOCK (heuristic, labeled)' : 'LIVE'}`);
  const out = { startedAt: new Date().toISOString(), mockModel, release, results: [] };
  try {
    const scenarios = buildScenarios(LOCAL_ADDRS).filter((s) => !only || s.id === only);
    if (only && scenarios.length === 0) throw new Error(`unknown scenario: ${only}`);

    if (benchId) {
      const s = buildScenarios(LOCAL_ADDRS).find((x) => x.id === benchId);
      if (!s) throw new Error(`unknown scenario: ${benchId}`);
      console.log(`\nbenchmark: ${s.name} x${benchN} (${mockModel ? 'MOCK' : 'LIVE'} model)`);
      const runs = [];
      for (let i = 0; i < benchN; i += 1) {
        const rec = await runOne(stack.policyBase, stack.signerBase, s, { release: false });
        rec.traceFull = undefined;
        runs.push(rec);
        const modelMs = rec.trace && rec.trace.model ? rec.trace.model.ms : null;
        console.log(`  run ${i + 1}: propose=${rec.proposeMs}ms model=${modelMs === null ? 'n/a' : `${modelMs}ms`} decision=${rec.decision} origin=${rec.investigation ? rec.investigation.reasoningOrigin : '?'}`);
      }
      const propose = stats(runs.map((r) => r.proposeMs));
      const model = stats(runs.map((r) => (r.trace && r.trace.model && r.trace.model.status === 'COMPLETED' && Number.isFinite(r.trace.model.ms) ? r.trace.model.ms : NaN)).filter(Number.isFinite));
      out.benchmark = {
        scenario: benchId, runs,
        proposeMs: propose, modelMs: model,
        cold: runs.length > 0 ? { proposeMs: runs[0].proposeMs } : null,
        warm: runs.length > 1 ? stats(runs.slice(1).map((r) => r.proposeMs)) : null,
        successRate: runs.filter((r) => r.httpStatus === 200).length / runs.length,
        timeouts: 0, failures: runs.filter((r) => r.httpStatus !== 200).length,
        note: 'time-to-first-token unavailable (non-streaming provider API); modelMs is total inference latency per call.'
      };
      console.log(`\npropose latency: avg=${propose.avg} p50=${propose.p50} p95=${propose.p95} min=${propose.min} max=${propose.max} (n=${propose.n})`);
      console.log(`model latency:   ${model.n ? `avg=${model.avg} p50=${model.p50} p95=${model.p95} min=${model.min} max=${model.max} (n=${model.n})` : 'no model calls (mock path)'}`);
    } else {
      for (const s of scenarios) {
        console.log(`\n[${s.id}] ${s.name}`);
        const rec = await runOne(stack.policyBase, stack.signerBase, s, { release, operatorSecret: stack.operatorSecret });
        out.results.push(rec);
        console.log(`  decision=${rec.decision} verdict=${rec.investigation ? rec.investigation.verdict : '?'} origin=${rec.investigation ? rec.investigation.reasoningOrigin : '?'}`);
        console.log(`  propose=${rec.proposeMs}ms${rec.signMs !== undefined ? ` sign=${rec.signMs}ms` : ''}${rec.receiptMs !== undefined ? ` receipt=${rec.receiptMs}ms` : ''} total=${rec.totalMs}ms`);
        if (rec.execution) console.log(`  execution=${rec.execution.outcome} tx=${rec.execution.txHash} status=${rec.execution.receiptStatus}`);
        if (rec.signError) console.log(`  sign refused: ${rec.signError}`);
        if (rec.error) console.log(`  ERROR: ${rec.error}`);
      }
    }
  } finally {
    stack.kill();
  }
  out.finishedAt = new Date().toISOString();
  const dir = path.join(__dirname, 'tmp');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `agent-scenarios-${Date.now()}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 1), 'utf8');
  console.log(`\nresults: ${file}`);
}

if (require.main === module) {
  main().catch((err) => { console.error(`scenario run failed: ${err.message}`); process.exit(1); });
}

module.exports = { runOne };
