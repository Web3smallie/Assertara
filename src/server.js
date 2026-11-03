/**
 * Assertara Visual Sentry - Backend Service Entrypoint
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const config = require('./config/env');
const { handleEvaluateTransaction } = require('./controllers/evaluateController');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json({ limit: '25mb' })); // Support base64 viewport screenshots
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Health Check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Assertara Visual Sentry',
    version: '1.0.0',
    models: {
      sam: config.samModel,
      muse: config.museModel
    },
    metaApiBaseUrl: config.metaApiBaseUrl,
    nodeEnv: config.nodeEnv
  });
});

// Primary Evaluation Endpoint
app.post('/api/v1/evaluate', handleEvaluateTransaction);

// Autonomous agent execution system (separate trust path from the
// browser evaluation endpoint; all optional — the server starts and
// serves /api/v1/evaluate with none of this configured).
const { readAgentConfig } = require('./config/agentConfig');
const { loadMandate } = require('./services/mandate');
const { createSpendingLedger } = require('./services/spendingLedger');
const { createAgentStore } = require('./services/agentStore');
const { createAgentController } = require('./controllers/agentController');

const agentConfig = readAgentConfig(process.env);
const agentStore = createAgentStore({ ledgerFile: agentConfig.ledgerFile, snapshotFile: agentConfig.snapshotFile });
const agentStoreLoad = agentStore.load();
if (!agentStoreLoad.ok) {
  console.warn(`[Agent] request store unavailable (${agentStoreLoad.error}); agent endpoints will answer 503.`);
}
const { checkMandateContinuity } = require('./services/mandate');
let agentMandate = agentConfig.mandateFile ? loadMandate(agentConfig.mandateFile) : { ok: false, error: 'MANDATE_FILE is not configured' };
if (!agentMandate.ok) {
  console.warn(`[Agent] mandate unavailable (${agentMandate.error}); agent proposals will be UNCERTAIN.`);
} else if (agentStoreLoad.ok) {
  const continuity = checkMandateContinuity({ last: agentStore.getLastMandate(), current: agentMandate.mandate });
  if (!continuity.ok) {
    console.warn(`[Agent] mandate rejected (${continuity.error}); agent proposals will be UNCERTAIN.`);
    agentMandate = { ok: false, error: continuity.error };
  } else {
    agentStore.setLastMandate({ id: agentMandate.mandate.id, version: agentMandate.mandate.version });
  }
}
const agentSpending = createSpendingLedger({ filePath: agentConfig.spendingLedgerFile });
const agentSpendingLoad = agentSpending.load();
if (!agentSpendingLoad.ok) {
  console.warn(`[Agent] spending ledger unavailable (${agentSpendingLoad.error}); proposals with spending limits will be UNCERTAIN.`);
}
const { createCapacityGuard } = require('./middleware/rateLimit');
const agentCapacity = createCapacityGuard({
  maxTotal: agentConfig.maxConcurrentInvestigations,
  maxPerKey: agentConfig.maxInflightPerKey
});
const agentController = createAgentController({
  mandate: agentMandate.ok ? agentMandate.mandate : null,
  mandateError: agentMandate.ok ? null : agentMandate.error,
  mandateAuthorities: agentConfig.mandateAuthorities,
  approvalSecret: agentConfig.approvalSecret,
  operatorSecret: agentConfig.operatorSecret,
  approvalTtlMs: agentConfig.approvalTtlMs,
  requestTtlMs: agentConfig.requestTtlMs,
  store: agentStore,
  spendingLedger: agentSpendingLoad.ok ? agentSpending : null,
  capacity: agentCapacity
});
// Startup recovery: background investigations do not survive a restart;
// undecided records fail closed to UNCERTAIN (re-propose), never resume.
if (agentStoreLoad.ok) {
  const recovered = agentController.recoverInterrupted();
  if (recovered.recovered > 0) {
    console.warn(`[Agent] fail-closed ${recovered.recovered} interrupted investigation(s) to UNCERTAIN.`);
  }
}

// Agent API authentication (SDK/API milestone): keys identify external
// integrations; without keys the API is open ONLY in explicit
// AGENT_AUTH_MODE=development, otherwise it answers 503. The browser
// evaluation path (/api/v1/evaluate) and health checks are unaffected.
const { requireAgentKey, allowOwner, requestKey } = require('./middleware/agentAuth');
const agentApiAuth = requireAgentKey(agentConfig, { scope: 'agent API' });
if (agentConfig.agentApiKeysError) {
  console.warn(`[Agent] ${agentConfig.agentApiKeysError}.`);
}
if (agentConfig.agentApiKeys) {
  console.warn('[Agent] agent API authentication: PRODUCTION (API keys enforced).');
} else if (agentConfig.agentAuthMode === 'development') {
  console.warn('[Agent] agent API authentication: DEVELOPMENT MODE — agent endpoints are open without keys. Never use with real mandates or keys.');
} else {
  console.warn('[Agent] agent API disabled: no AGENT_API_KEYS and AGENT_AUTH_MODE is not development.');
}

app.post('/api/v1/agent/propose', agentApiAuth, (req, res) => agentController.handlePropose(req, res));
app.post('/api/v1/agent/investigations', agentApiAuth, (req, res) => agentController.handleInvestigate(req, res));
app.get('/api/v1/agent/requests/:id', agentApiAuth, (req, res) => agentController.handleStatus(req, res));
app.get('/api/v1/agent/requests/:id/evidence', agentApiAuth, (req, res) => agentController.handleEvidence(req, res));
app.post('/api/v1/agent/requests/:id/authorize', agentApiAuth, (req, res) => agentController.handleAuthorize(req, res));
app.post('/api/v1/agent/requests/:id/receipts', agentApiAuth, (req, res) => agentController.handleReceipt(req, res));
app.post('/api/v1/internal/signer-callback', (req, res) => agentController.handleSignerCallback(req, res));
app.get('/api/v1/agent/mandate', agentApiAuth, (req, res) => agentController.handleMandateInfo(req, res));
// Agent task trigger for the browser workspace. The runner is injected
// by the hosting process (demo command-stack); without one these answer
// 503. src/ never imports the agent subsystem (boundary preserved).
const agentTasks = require('./agentTasks');
app.post('/api/v1/agent/tasks', agentApiAuth, (req, res) => agentTasks.handleCreateTask(req, res));
app.get('/api/v1/agent/tasks/:id', agentApiAuth, (req, res) => agentTasks.handleGetTask(req, res));

// Provenance + attestation API (SDK upgrade): thin HTTP adapter over
// the Phase 1-3 / Step 4-6 services. Manifest/export/verify are
// agent-key authed and ownership-scoped; ceremony + publish
// additionally require OPERATOR_SECRET plus explicit server-side
// opt-in flags (prototype posture — production provenance must use
// the offline CLI ceremony; see docs/attestation.md).
const { createProvenanceController, readProvenanceConfig } = require('./controllers/provenanceController');
const provenanceController = createProvenanceController({
  store: agentStoreLoad.ok ? agentStore : null,
  operatorSecret: agentConfig.operatorSecret,
  config: readProvenanceConfig(process.env)
});
app.post('/api/v1/provenance/manifests', agentApiAuth, (req, res) => provenanceController.handleBuildManifest(req, res));
app.get('/api/v1/provenance/manifests/:digest', agentApiAuth, (req, res) => provenanceController.handleGetManifest(req, res));
app.get('/api/v1/provenance/exports/:digest', agentApiAuth, (req, res) => provenanceController.handleGetExport(req, res));
app.post('/api/v1/attestations', agentApiAuth, (req, res) => provenanceController.handleCeremony(req, res));
app.post('/api/v1/attestations/publish', agentApiAuth, (req, res) => provenanceController.handlePublish(req, res));
app.post('/api/v1/attestations/verify', agentApiAuth, (req, res) => provenanceController.handleVerify(req, res));

// Serve test fixtures and demo dApp mock pages
app.use('/demo', express.static(path.resolve(__dirname, '../test/fixtures')));

// Live investigation observability (read-only). Streams real execution
// telemetry for the command centre UI. These endpoints can only read
// recorded spans — they cannot influence any authorization decision,
// and snapshots carry no secrets (see investigationTelemetry).
const telemetry = require('./services/investigationTelemetry');
app.use('/command', express.static(path.resolve(__dirname, '../public/command')));
app.get('/api/v1/observations/traces', agentApiAuth, (req, res) => {
  // Owner-scoped: each integration lists only traces linked to its own
  // requests. Unlinked traces are dev-visible only.
  const visible = telemetry.listTraces().filter((t) => {
    if (!t.requestId) return requestKey(req).development;
    if (!agentStoreLoad.ok) return false;
    return agentController.recordAccessible(req, agentStore.get(t.requestId));
  });
  res.json({ traces: visible });
});
app.get('/api/v1/observations/traces/:id', agentApiAuth, (req, res) => {
  const trace = telemetry.getTrace(req.params.id);
  if (!trace || !agentController.traceAccessible(req, trace)) {
    return res.status(404).json({ error: 'Unknown trace id.' });
  }
  res.json(telemetry.snapshot(trace));
});
app.get('/api/v1/observations/scenarios', (req, res) => {
  // eslint-disable-next-line global-require
  const { buildScenarios, LOCAL_ADDRS } = require('../demo/scenarios');
  res.json({ scenarios: buildScenarios(LOCAL_ADDRS) });
});
app.get('/api/v1/observations/investigations/by-eval/:evalId', agentApiAuth, (req, res) => {
  // eslint-disable-next-line global-require
  const { findByEvalId } = require('./services/investigationStore');
  const found = findByEvalId(req.params.evalId);
  // Owner-scoped via the persisted ownerKeyId (dev records with no
  // owner stay dev-visible only).
  if (!found.ok || !allowOwner(req, found.record && found.record.ownerKeyId)) {
    return res.status(404).json({ error: 'No persisted investigation for this evaluation (model-origin records only).' });
  }
  res.json({ record: found.record });
});
app.get('/api/v1/observations/traces/:id/stream', agentApiAuth, (req, res) => {
  const trace = telemetry.getTrace(req.params.id);
  if (!trace || !agentController.traceAccessible(req, trace)) {
    return res.status(404).json({ error: 'Unknown trace id.' });
  }
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });
  const send = (event) => {
    try { res.write(`data: ${JSON.stringify(event)}\n\n`); } catch { /* client gone */ }
  };
  for (const e of trace.events) send(e);
  if (trace.status !== 'RUNNING') {
    send({ type: 'stream-end', traceId: trace.id, status: trace.status });
    return res.end();
  }
  const off = telemetry.subscribe(trace.id, send);
  const heartbeat = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { /* client gone */ }
  }, 15000);
  req.on('close', () => { clearInterval(heartbeat); off(); });
});

// Start listening
if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`====================================================`);
    console.log(`  Assertara Visual Sentry Server running on :${config.port} `);
    console.log(`  Health Check: http://localhost:${config.port}/health        `);
    console.log(`  Evaluation:   http://localhost:${config.port}/api/v1/evaluate`);
    console.log(`====================================================`);
  });
}

module.exports = app;
