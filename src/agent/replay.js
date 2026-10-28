/**
 * Assertara Replay — hash-chained investigation event records + deterministic
 * replay (F13, Investigation Replay Theater). Internal interface only: no
 * routes, no UI, no network, no model calls, no transactions — ever.
 *
 * What this module IS: an ordered, timestamped, hash-chained event log with
 * sensitive-value redaction, atomic persistence, and a pure historical replay
 * that distinguishes recorded outputs from deterministic summaries.
 *
 * What it is NOT: a trust anchor. The hash chain detects modification,
 * deletion, and reordering GIVEN an independently held head hash (pinned in
 * a report, log, or second copy). It does not stop an attacker with full
 * storage control from rewriting the entire file — that limitation is
 * documented in contracts §21, not hidden.
 *
 * Re-execution is NOT implemented: there is no mode that reruns tools, RPC,
 * models, or transactions. Replay reads history; it never acts.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { TOOL_VERSIONS } = require('./reports');

const RECORDING_VERSION = 1;
const MAX_EVENTS = 1000;
const MAX_EVENT_BYTES = 64 * 1024;
const MAX_RECORDING_BYTES = 4 * 1024 * 1024;
const MAX_DEPTH = 50;
const MAX_PATH_CHARS = 200;

const EVENT_TYPES = [
  'investigation.started',
  'model.turn',
  'tool.called',
  'tool.result',
  'tool.rejected',
  'evidence.appended',
  'assessment.recorded',
  'capability.unavailable',
  'investigation.stopped'
];

// Observed = the application saw it happen. Interpreted = a model turn's
// proposal/notes. Assessed = a verdict assigned downstream of evidence.
const EVENT_CLASS = {
  'investigation.started': 'observed',
  'model.turn': 'interpreted',
  'tool.called': 'observed',
  'tool.result': 'observed',
  'tool.rejected': 'observed',
  'evidence.appended': 'observed',
  'assessment.recorded': 'assessed',
  'capability.unavailable': 'observed',
  'investigation.stopped': 'observed'
};

const ACTORS = ['app', 'model', 'tool', 'user'];

const TOOL_NAME_VERSIONS = {
  decode_tx: TOOL_VERSIONS.decoder,
  compare_fields: 'agent:toolRegistry-compare-v1',
  allowance_analysis: 'agent:toolRegistry-allowance-v1',
  segment_concept: TOOL_VERSIONS.sam,
  crop_region: 'agent:imageUtils-crop-v1',
  ocr_region: TOOL_VERSIONS.ocr,
  simulate_tx: TOOL_VERSIONS.simulator,
  sandbox_exec: 'agent:harness-v1'
};

const REPLAY_NOTE = 'Historical replay: recorded outputs only. Nothing was re-executed; '
  + 'no network, model, or transaction activity occurred. Timeline summaries are '
  + 'deterministic views of recorded data, not new interpretations.';

// Key names (normalized: lowercased, non-alphanumerics stripped) whose values
// are secrets. Deliberately narrow: `token` alone is NOT here (ERC-20 token
// addresses/symbols are legitimate evidence), and `authorization` redacts only
// string values (EIP-7702 authorization tuples are objects and are kept).
const SENSITIVE_KEYS = new Set([
  'apikey', 'xapikey', 'authkey', 'secret', 'clientsecret', 'apisecret',
  'privatekey', 'privkey', 'password', 'passwd', 'mnemonic', 'seedphrase',
  'seed', 'credentials', 'accesstoken', 'refreshtoken', 'idtoken', 'bearer',
  'cookie', 'setcookie', 'envfile', 'dotenv', 'privatekeyhex'
]);

const SECRET_VALUE_PATTERNS = [
  /^sk-[A-Za-z0-9]{8,}/,
  /^Bearer\s+\S+/,
  /^Basic\s+\S+/,
  /^ghp_[A-Za-z0-9]+/,
  /^xox[bpas]-[A-Za-z0-9-]+/,
  /BEGIN .*PRIVATE KEY/
];

const REDACTED = '[REDACTED]';

function replayError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function normalizeKey(k) {
  return String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function looksSecretString(s) {
  return SECRET_VALUE_PATTERNS.some((re) => re.test(s));
}

/**
 * Deep-convert to JSON-native values. BigInt → tagged string (decoded tx
 * params carry BigInts); Buffer → hash + length (never embed raw bytes —
 * screenshots must not bloat recordings); circular → throw (never silently
 * drop structure that integrity is supposed to cover).
 */
function toJsonSafe(value, depth = 0, seen = new Set()) {
  if (depth > MAX_DEPTH) throw replayError('VALUE_TOO_DEEP', `value exceeds max depth ${MAX_DEPTH}`);
  if (value === null || value === undefined) return null;
  if (typeof value === 'bigint') return { __bigint: value.toString() };
  if (typeof value === 'number' && !Number.isFinite(value)) return null;
  if (Buffer.isBuffer(value)) {
    return { __bytes: sha256Hex(value.toString('base64')), length: value.length };
  }
  if (typeof value !== 'object') return value;
  if (seen.has(value)) throw replayError('VALUE_CIRCULAR', 'event data must not be circular');
  seen.add(value);
  let out;
  if (Array.isArray(value)) {
    out = value.map((v) => toJsonSafe(v, depth + 1, seen));
  } else {
    out = {};
    for (const k of Object.keys(value)) out[k] = toJsonSafe(value[k], depth + 1, seen);
  }
  seen.delete(value);
  return out;
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeys(value[k]);
    return out;
  }
  return value;
}

function stableStringify(value) {
  return JSON.stringify(sortKeys(toJsonSafe(value)));
}

/**
 * Redact secrets by key name + known value patterns. Returns
 * { value, redacted: [jsonPaths] }. Legitimate tx evidence (addresses,
 * amounts, token ids, auth tuples) passes through untouched.
 */
function redactSensitive(value, basePath = '$', found = [], seen = new Set()) {
  if (typeof value === 'string') {
    if (looksSecretString(value)) {
      if (found.length < 500) found.push(basePath);
      return { value: REDACTED, redacted: found };
    }
    return { value, redacted: found };
  }
  if (!value || typeof value !== 'object') return { value, redacted: found };
  // Cycle-safe: redaction runs before canonicalization, so it must refuse
  // circular input itself instead of recursing forever.
  if (seen.has(value)) throw replayError('VALUE_CIRCULAR', 'event data must not be circular');
  seen.add(value);
  let out;
  if (Array.isArray(value)) {
    out = value.map((v, i) => redactSensitive(v, `${basePath}[${i}]`, found, seen).value);
  } else {
    out = {};
    for (const k of Object.keys(value)) {
      const p = `${basePath}.${k}`;
      const v = value[k];
      // `authorization` redacts string credentials only; on-chain
      // authorization tuples (objects/arrays) are evidence, not secrets.
      if (SENSITIVE_KEYS.has(normalizeKey(k)) && (normalizeKey(k) !== 'authorization' || typeof v === 'string')) {
        if (found.length < 500) found.push(p);
        out[k] = REDACTED;
      } else {
        out[k] = redactSensitive(v, p, found, seen).value;
      }
    }
  }
  seen.delete(value);
  return { value: out, redacted: found };
}

function sanitizeVersions(versions) {
  const out = {};
  if (!versions || typeof versions !== 'object') return out;
  for (const k of Object.keys(versions).slice(0, 20)) {
    if (typeof versions[k] === 'string') out[String(k).slice(0, 40)] = versions[k].slice(0, 200);
  }
  return out;
}

const CHAIN_KEYS = ['chainId', 'block', 'blockNumber', 'blockHash', 'provider', 'txHash'];

function sanitizeChain(chain) {
  if (!chain || typeof chain !== 'object') return null;
  const out = {};
  for (const k of CHAIN_KEYS) {
    const v = chain[k];
    if (typeof v === 'bigint') out[k] = v.toString();
    else if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
    else if (typeof v === 'string' && v.length > 0) out[k] = v.slice(0, MAX_PATH_CHARS);
  }
  return Object.keys(out).length > 0 ? out : null;
}

/** Pull chain/block/provider context one level deep; rpcUrl → hostname only. */
function extractChainContext(payload) {
  const scopes = [];
  if (payload && typeof payload === 'object') {
    scopes.push(payload);
    if (payload.result && typeof payload.result === 'object') scopes.push(payload.result);
  }
  const found = {};
  for (const scope of scopes) {
    for (const k of CHAIN_KEYS) {
      if (found[k] === undefined && scope[k] !== undefined && scope[k] !== null) found[k] = scope[k];
    }
    if (found.provider === undefined && typeof scope.rpcUrl === 'string') {
      try { found.provider = new URL(scope.rpcUrl).hostname; }
      catch { /* unparseable URL: omit, never record raw (may embed keys) */ }
    }
  }
  return sanitizeChain(found);
}

// ---------- Recorder ----------

function checkId(name, value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PATH_CHARS) {
    throw replayError('BAD_ID', `${name} must be a 1-${MAX_PATH_CHARS} char string`);
  }
}

function hashPayloadOf(event) {
  return {
    seq: event.seq, ts: event.ts, type: event.type, class: event.class,
    actor: event.actor, data: event.data, evidenceRefs: event.evidenceRefs,
    versions: event.versions, chain: event.chain || null,
    redacted: event.redacted, prevHash: event.prevHash
  };
}

class Recorder {
  constructor({ investigationId, runId, featureId = null, versions = {}, model = null, now = null, mode = 'live' } = {}) {
    checkId('investigationId', investigationId);
    checkId('runId', runId);
    this.investigationId = investigationId;
    this.runId = runId;
    this.featureId = typeof featureId === 'string' ? featureId.slice(0, 120) : null;
    this.versions = {
      orchestrator: TOOL_VERSIONS.orchestrator,
      ...(typeof model === 'string' ? { model: model.slice(0, 200) } : {}),
      ...sanitizeVersions(versions)
    };
    this.now = typeof now === 'function' ? now : () => Date.now();
    this.mode = mode === 'derived' ? 'derived' : 'live';
    this.events = [];
    this.head = 'GENESIS';
  }

  append(type, { actor = 'app', data = {}, evidenceRefs = [], versions = {}, chain = null } = {}) {
    if (!EVENT_TYPES.includes(type)) throw replayError('UNKNOWN_EVENT_TYPE', `unknown event type: ${String(type).slice(0, 120)}`);
    if (!ACTORS.includes(actor)) throw replayError('BAD_ACTOR', `actor must be one of ${ACTORS.join(',')}`);
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw replayError('BAD_EVENT_DATA', 'event data must be an object');
    }
    if (!Array.isArray(evidenceRefs) || evidenceRefs.some((r) => typeof r !== 'string')) {
      throw replayError('BAD_EVIDENCE_REFS', 'evidenceRefs must be an array of strings');
    }
    if (this.events.length >= MAX_EVENTS) {
      throw replayError('TOO_MANY_EVENTS', `event cap ${MAX_EVENTS} reached`);
    }
    const { value: clean, redacted } = redactSensitive(data);
    const event = {
      seq: this.events.length + 1,
      ts: new Date(this.now()).toISOString(),
      type,
      class: EVENT_CLASS[type],
      actor,
      data: toJsonSafe(clean),
      evidenceRefs: evidenceRefs.slice(0, 200),
      versions: { ...this.versions, ...sanitizeVersions(versions) },
      redacted: redacted.slice(0, MAX_PATH_CHARS),
      redactedCount: redacted.length,
      prevHash: this.head
    };
    const cleanChain = sanitizeChain(chain);
    if (cleanChain) event.chain = cleanChain;
    const bytes = Buffer.byteLength(JSON.stringify(event), 'utf8');
    if (bytes > MAX_EVENT_BYTES) {
      throw replayError('EVENT_TOO_LARGE', `event exceeds ${MAX_EVENT_BYTES} bytes`);
    }
    event.hash = sha256Hex(stableStringify(hashPayloadOf(event)));
    this.head = event.hash;
    this.events.push(event);
    return event;
  }

  export() {
    return {
      type: 'ReplayRecording',
      version: RECORDING_VERSION,
      investigationId: this.investigationId,
      runId: this.runId,
      featureId: this.featureId,
      mode: this.mode,
      recordedAt: new Date(this.now()).toISOString(),
      eventCount: this.events.length,
      events: this.events.map((e) => ({ ...e })),
      head: this.head
    };
  }
}

// ---------- Validation ----------

function invalid(code, error, extra = {}) {
  return { ok: false, code, error, ...extra };
}

function validRecording(rec) {
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return invalid('MALFORMED_RECORDING', 'recording must be an object');
  if (rec.type !== 'ReplayRecording') return invalid('MALFORMED_RECORDING', 'missing type=ReplayRecording');
  if (rec.version !== RECORDING_VERSION) {
    return invalid('UNSUPPORTED_VERSION', `recording version ${rec.version} unsupported (want ${RECORDING_VERSION})`);
  }
  if (typeof rec.investigationId !== 'string' || typeof rec.runId !== 'string') {
    return invalid('MALFORMED_RECORDING', 'investigationId and runId must be strings');
  }
  if (!Array.isArray(rec.events) || rec.events.length === 0) {
    return invalid('MALFORMED_RECORDING', 'events must be a non-empty array');
  }
  if (rec.eventCount !== rec.events.length) {
    return invalid('MALFORMED_RECORDING', `eventCount ${rec.eventCount} != events length ${rec.events.length}`);
  }
  // Byte cap before chain work so oversized forgeries fail fast and loud.
  let totalBytes = 0;
  try {
    totalBytes = Buffer.byteLength(JSON.stringify(rec), 'utf8');
  } catch {
    return invalid('MALFORMED_RECORDING', 'recording is not JSON-serializable');
  }
  if (totalBytes > MAX_RECORDING_BYTES) {
    return invalid('RECORDING_TOO_LARGE', `recording exceeds ${MAX_RECORDING_BYTES} bytes`);
  }
  let prev = 'GENESIS';
  for (let i = 0; i < rec.events.length; i += 1) {
    const e = rec.events[i];
    const where = `event index ${i}`;
    if (!e || typeof e !== 'object') return invalid('MALFORMED_RECORDING', `${where}: must be an object`, { seq: null });
    if (e.seq !== i + 1) return invalid('MALFORMED_RECORDING', `${where}: seq must be ${i + 1}`, { seq: e.seq ?? null });
    if (!EVENT_TYPES.includes(e.type)) return invalid('MALFORMED_RECORDING', `${where}: unknown type`, { seq: e.seq });
    if (e.class !== EVENT_CLASS[e.type]) return invalid('MALFORMED_RECORDING', `${where}: class mismatch`, { seq: e.seq });
    if (!ACTORS.includes(e.actor)) return invalid('MALFORMED_RECORDING', `${where}: bad actor`, { seq: e.seq });
    if (!e.data || typeof e.data !== 'object' || Array.isArray(e.data)) {
      return invalid('MALFORMED_RECORDING', `${where}: data must be an object`, { seq: e.seq });
    }
    if (!Array.isArray(e.evidenceRefs) || !Array.isArray(e.redacted)) {
      return invalid('MALFORMED_RECORDING', `${where}: evidenceRefs/redacted must be arrays`, { seq: e.seq });
    }
    if (typeof e.ts !== 'string' || Number.isNaN(Date.parse(e.ts))) {
      return invalid('MALFORMED_RECORDING', `${where}: ts must be an ISO timestamp`, { seq: e.seq });
    }
    if (typeof e.hash !== 'string' || typeof e.prevHash !== 'string') {
      return invalid('MALFORMED_RECORDING', `${where}: hash/prevHash must be strings`, { seq: e.seq });
    }
    // Link check first: distinguishes deletion/reorder (broken link) from
    // in-place edits (intact link, wrong hash).
    if (e.prevHash !== prev) {
      return invalid('CHAIN_LINK_BROKEN', `event ${e.seq}: prevHash does not match event ${e.seq - 1} (deleted or reordered events?)`, { seq: e.seq });
    }
    let recomputed;
    try {
      recomputed = sha256Hex(stableStringify(hashPayloadOf(e)));
    } catch (err) {
      return invalid('MALFORMED_RECORDING', `event ${e.seq}: unhashable (${err.message})`, { seq: e.seq });
    }
    if (recomputed !== e.hash) {
      return invalid('EVENT_MODIFIED', `event ${e.seq}: hash mismatch (modified after recording?)`, { seq: e.seq });
    }
    prev = e.hash;
  }
  if (rec.head !== prev) {
    return invalid('HEAD_MISMATCH', 'envelope head does not match the last event hash (truncated or extended history?)');
  }
  return { ok: true, bytes: totalBytes };
}

// ---------- Persistence (atomic writes, validated reads) ----------

function safeRecordingName(runId) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$/.test(String(runId || ''))) {
    throw replayError('BAD_RUN_ID', 'runId is not filename-safe (allowed: A–Z a–z 0–9 _ . -)');
  }
  return `replay-${runId}.json`;
}

let saveCounter = 0;

function saveRecording(dir, recording) {
  if (!dir || typeof dir !== 'string') throw replayError('BAD_DIR', 'a state directory string is required');
  const check = validRecording(recording);
  if (!check.ok) throw replayError(check.code, `refusing to persist invalid recording: ${check.error}`);
  const name = safeRecordingName(recording.runId);
  const root = path.resolve(dir);
  fs.mkdirSync(root, { recursive: true });
  const dest = path.join(root, name);
  if (!dest.startsWith(`${root}${path.sep}`)) throw replayError('BAD_DIR', 'recording path escaped the state directory');
  saveCounter += 1;
  const tmp = path.join(root, `.${name}.tmp-${process.pid}-${saveCounter}`);
  fs.writeFileSync(tmp, JSON.stringify(recording, null, 2), 'utf8');
  fs.renameSync(tmp, dest);
  return { path: dest };
}

function loadRecording(filePath) {
  if (!filePath || typeof filePath !== 'string') return invalid('BAD_PATH', 'a file path string is required');
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return invalid('NOT_FOUND', `no recording at ${filePath}`);
    return invalid('READ_FAILED', `cannot read recording: ${err.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return invalid('MALFORMED_RECORDING', 'recording file is not valid JSON (truncated or corrupt?)');
  }
  const check = validRecording(parsed);
  if (!check.ok) return check;
  return { ok: true, recording: parsed, bytes: check.bytes };
}

// ---------- Convert a finished orchestrator run into a recording ----------

function payloadKeys(payload) {
  if (!payload || typeof payload !== 'object') return [];
  return Object.keys(payload).slice(0, 20);
}

function summarizeActionError(tool, error) {
  return { tool: tool || null, error: String(error || 'rejected').slice(0, 500) };
}

/**
 * Derive an ordered recording from a finished orchestrator record + evidence
 * graph (instance or export). Post-hoc by construction: the envelope is
 * marked mode=derived and event timestamps are recording times, because
 * orchestrator v1 does not timestamp turns. Anything the record does not
 * contain (per-turn usage, budgets, original tool args) is labeled
 * not-recorded — never reconstructed.
 */
function recordFromRun({ record, graph, assessments = [], model = null, now = null } = {}) {
  if (!record || typeof record !== 'object') throw replayError('BAD_RECORD', 'recordFromRun requires an orchestrator record');
  if (!record.id || !Array.isArray(record.turns)) throw replayError('BAD_RECORD', 'record needs id + turns[]');
  const exported = !graph ? null
    : (typeof graph.export === 'function' ? graph.export() : graph);
  if (!exported || !Array.isArray(exported.nodes)) throw replayError('BAD_RECORD', 'recordFromRun requires an evidence graph (instance or export)');
  if (!Array.isArray(assessments)) throw replayError('BAD_RECORD', 'assessments must be an array');

  const recorder = new Recorder({
    investigationId: record.id,
    runId: `${record.id}-r1`,
    featureId: record.featureId || record.feature || null,
    model,
    now: typeof now === 'function' ? now : null,
    mode: 'derived'
  });

  const inputs = record.inputs && typeof record.inputs === 'object' ? record.inputs : {};
  const { value: redactedInputs, redacted: inputRedactions } = redactSensitive(toJsonSafe(inputs));
  recorder.append('investigation.started', {
    actor: 'app',
    data: {
      featureId: record.featureId || record.feature || 'unknown',
      inputsHash: sha256Hex(stableStringify(inputs)),
      inputs: redactedInputs,
      inputRedactions,
      budgetNote: 'orchestrator v1 does not persist budgets on the record; limits are not recorded'
    }
  });

  const toolResultsByTurn = new Map();
  for (const node of exported.nodes) {
    if (node.kind !== 'ToolResult') continue;
    const list = toolResultsByTurn.get(node.created_turn) || [];
    list.push(node);
    toolResultsByTurn.set(node.created_turn, list);
  }

  for (const turn of record.turns) {
    const index = Number.isInteger(turn.index) ? turn.index : 0;
    recorder.append('model.turn', {
      actor: 'model',
      data: {
        turn: index,
        effort: turn.effort || null,
        notes: typeof turn.notes === 'string' ? turn.notes.slice(0, 2000) : null,
        stop: turn.stop === true,
        actionCount: Array.isArray(turn.actions) ? turn.actions.length : 0,
        usageNote: 'per-turn usage not recorded by orchestrator v1; see cumulative ledger at investigation.stopped'
      }
    });
    const queue = [...(toolResultsByTurn.get(index) || [])];
    // Error-only ToolResults (executed but failed, e.g. timeouts) pair with
    // ok:false actions; success ToolResults pair with ok:true actions. Never
    // cross-pair: an ok action must not inherit a failure node's evidence id.
    const isErrorNode = (n) => Boolean(n && n.payload && n.payload.error !== undefined && n.payload.result === undefined);
    for (const action of turn.actions || []) {
      const tool = (action && action.tool) || null;
      if (!action || action.ok !== true) {
        const errNode = tool ? queue.find((n) => n.tool_ref === tool && isErrorNode(n)) || null : null;
        if (errNode) {
          queue.splice(queue.indexOf(errNode), 1);
          const argsHash = Array.isArray(errNode.input_hashes) && errNode.input_hashes.length > 0 ? errNode.input_hashes[0] : 'not-recorded';
          recorder.append('tool.called', {
            actor: 'app',
            data: { turn: index, tool, argsHash, argsNote: 'original args are not stored on the v1 record; only the input hash survives' },
            versions: TOOL_NAME_VERSIONS[tool] ? { tool: TOOL_NAME_VERSIONS[tool] } : {}
          });
          recorder.append('tool.result', {
            actor: 'tool',
            data: { turn: index, tool, ok: false, evidenceId: errNode.id, error: String(errNode.payload.error).slice(0, 500) },
            evidenceRefs: [errNode.id],
            versions: TOOL_NAME_VERSIONS[tool] ? { tool: TOOL_NAME_VERSIONS[tool] } : {},
            chain: extractChainContext(errNode.payload)
          });
          continue;
        }
        recorder.append('tool.rejected', { actor: 'app', data: { turn: index, ...summarizeActionError(tool, action && action.error) } });
        if (tool && /UNAVAILABLE/.test(String((action && action.error) || ''))) {
          recorder.append('capability.unavailable', {
            actor: 'app',
            data: { name: tool, detail: String(action.error).slice(0, 500), turn: index }
          });
        }
        continue;
      }
      const node = queue.find((n) => n.tool_ref === tool && !isErrorNode(n))
        || queue.find((n) => !isErrorNode(n))
        || queue[0] || null;
      if (node) queue.splice(queue.indexOf(node), 1);
      const argsHash = node && Array.isArray(node.input_hashes) && node.input_hashes.length > 0
        ? node.input_hashes[0]
        : 'not-recorded';
      recorder.append('tool.called', {
        actor: 'app',
        data: {
          turn: index, tool,
          argsHash,
          argsNote: 'original args are not stored on the v1 record; only the input hash survives'
        },
        versions: TOOL_NAME_VERSIONS[tool] ? { tool: TOOL_NAME_VERSIONS[tool] } : {}
      });
      if (!node) {
        recorder.append('tool.result', {
          actor: 'tool',
          data: { turn: index, tool, ok: true, outputNote: 'no matching ToolResult node; history incomplete' }
        });
        continue;
      }
      recorder.append('tool.result', {
        actor: 'tool',
        data: {
          turn: index, tool, ok: true,
          evidenceId: node.id,
          outputHash: sha256Hex(stableStringify(node.payload)),
          outputKeys: payloadKeys(node.payload && node.payload.result !== undefined ? node.payload.result : node.payload)
        },
        evidenceRefs: [node.id],
        versions: TOOL_NAME_VERSIONS[tool] ? { tool: TOOL_NAME_VERSIONS[tool] } : {},
        chain: extractChainContext(node.payload)
      });
    }
  }

  for (const node of exported.nodes) {
    if (node.kind === 'ToolResult') continue; // referenced by its tool.result
    recorder.append('evidence.appended', {
      actor: node.producer === 'MODEL' ? 'model' : node.producer === 'USER' ? 'user' : 'app',
      data: {
        evidenceId: node.id,
        kind: node.kind,
        producer: node.producer,
        toolRef: node.tool_ref || null,
        createdTurn: node.created_turn,
        payloadHash: sha256Hex(stableStringify(node.payload)),
        payloadKeys: payloadKeys(node.payload)
      },
      evidenceRefs: [node.id]
    });
  }

  for (const a of assessments) {
    if (!a || typeof a !== 'object') throw replayError('BAD_RECORD', 'each assessment must be an object');
    const refs = [...(a.supporting || []), ...(a.contradicting || [])].filter((r) => typeof r === 'string');
    recorder.append('assessment.recorded', {
      actor: 'app',
      data: {
        findingId: a.findingId || a.id || null,
        verdict: a.verdict || null,
        status: a.status || null,
        supporting: (a.supporting || []).filter((r) => typeof r === 'string'),
        contradicting: (a.contradicting || []).filter((r) => typeof r === 'string')
      },
      evidenceRefs: refs
    });
  }

  recorder.append('investigation.stopped', {
    actor: 'app',
    data: {
      status: record.status || 'UNKNOWN',
      stopReason: typeof record.stopReason === 'string' ? record.stopReason.slice(0, 2000) : null,
      ledger: toJsonSafe(record.ledger || {})
    }
  });

  return recorder.export();
}

// ---------- Deterministic replay (pure: no I/O, network, model, or tx) ----------

function short(value, n = 160) {
  const s = value === null || value === undefined ? '' : String(value);
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function hash8(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value) ? value.slice(0, 8) : short(value, 24);
}

function summarizeEvent(event) {
  const d = event.data || {};
  switch (event.type) {
    case 'investigation.started':
      return `Investigation started: ${short(d.featureId)} (inputs sha ${hash8(d.inputsHash)}, ${(d.inputRedactions || []).length} redacted fields)`;
    case 'model.turn':
      return `Model turn ${d.turn} [${short(d.effort)}]: ${short(d.notes) || 'no notes'} → ${d.stop ? 'stop' : 'continue'} (${d.actionCount} actions)`;
    case 'tool.called':
      return `Tool called: ${short(d.tool)} (args sha ${hash8(d.argsHash)})`;
    case 'tool.result':
      if (d.ok === true && d.evidenceId) return `Tool result: ${short(d.tool)} ok → ${short(d.evidenceId)} (output sha ${hash8(d.outputHash)})`;
      if (d.ok === true) return `Tool result: ${short(d.tool)} ok (${short(d.outputNote) || 'no evidence ref'})`;
      return `Tool result: ${short(d.tool)} FAILED: ${short(d.error)}`;
    case 'tool.rejected':
      return `Tool rejected: ${short(d.tool)}: ${short(d.error)}`;
    case 'evidence.appended':
      return `Evidence ${short(d.evidenceId)} [${short(d.kind)}/${short(d.producer)}]`;
    case 'assessment.recorded':
      return `Assessment${d.findingId ? ` ${short(d.findingId)}` : ''}: ${short(d.verdict)} (${short(d.status)})`;
    case 'capability.unavailable':
      return `Unavailable: ${short(d.name)}: ${short(d.detail)}`;
    case 'investigation.stopped':
      return `Investigation ${short(d.status)}: ${short(d.stopReason)}`;
    default:
      return `${event.type} (seq ${event.seq})`;
  }
}

/**
 * Replay a recording as pure history. `evidence` is an optional evidence
 * graph export ({nodes:[{id}]}) used to resolve evidenceRefs — refs that do
 * not resolve are reported as gaps, never invented. Synchronous and
 * dependency-free by construction: there is no code path here that can touch
 * the network, a model, or a transaction.
 */
function replayRecording(recording, { evidence = null } = {}) {
  const check = validRecording(recording);
  if (!check.ok) {
    return {
      status: 'FAILED', mode: 'historical',
      investigationId: recording && recording.investigationId || null,
      runId: recording && recording.runId || null,
      integrity: { verified: false, code: check.code, error: check.error, seq: check.seq ?? null },
      evidence: { checked: false, resolved: 0, missing: [] },
      gaps: [{ kind: 'integrity-failure', code: check.code, error: check.error }],
      limits: [],
      timeline: [],
      note: REPLAY_NOTE
    };
  }
  const known = evidence && Array.isArray(evidence.nodes) ? new Set(evidence.nodes.map((n) => n.id)) : null;
  const gaps = [];
  const limits = [];
  let resolved = 0;
  const missing = [];
  const timeline = recording.events.map((e) => {
    const refs = (e.evidenceRefs || []).map((ref) => {
      let status = 'unchecked';
      if (known) {
        status = known.has(ref) ? 'resolved' : 'missing';
        if (status === 'resolved') resolved += 1;
        else {
          missing.push(ref);
          gaps.push({ kind: 'missing-evidence', ref, seq: e.seq, type: e.type });
        }
      }
      return { ref, status };
    });
    return {
      seq: e.seq, ts: e.ts, type: e.type, class: e.class, actor: e.actor,
      recorded: e.data,
      view: summarizeEvent(e),
      viewOrigin: 'deterministic-summary',
      evidence: refs,
      redactedCount: e.redactedCount || 0,
      chain: e.chain || null,
      versions: e.versions || {}
    };
  });
  if (!known) {
    limits.push('no evidence graph supplied: evidenceRefs left unchecked (pass { evidence } to resolve)');
  }
  if (recording.mode === 'derived') {
    limits.push('derived recording: event times are recording times; orchestrator v1 does not timestamp turns, budgets, or per-turn usage');
  }
  return {
    status: missing.length > 0 ? 'PARTIAL' : 'OK',
    mode: 'historical',
    investigationId: recording.investigationId,
    runId: recording.runId,
    featureId: recording.featureId || null,
    integrity: { verified: true, checkedEvents: recording.events.length, head: recording.head, bytes: check.bytes },
    evidence: { checked: known !== null, resolved, missing: [...new Set(missing)] },
    gaps,
    limits,
    timeline,
    note: REPLAY_NOTE
  };
}

module.exports = {
  RECORDING_VERSION, MAX_EVENTS, MAX_EVENT_BYTES, MAX_RECORDING_BYTES,
  EVENT_TYPES, EVENT_CLASS, ACTORS, REPLAY_NOTE,
  Recorder, redactSensitive, stableStringify, validRecording,
  saveRecording, loadRecording, recordFromRun, replayRecording
};

