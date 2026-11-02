/**
 * Agent request store + audit ledger (agent execution system).
 *
 * Security-relevant request state persists across restarts in an atomic
 * JSON snapshot (tmp-file + rename, so a crash leaves the previous
 * complete snapshot or nothing new — never a half-written file). The
 * append-only JSONL audit trail is best-effort explanation; the snapshot
 * is authoritative for state.
 *
 * Fail-closed rules:
 * - A corrupt or structurally invalid snapshot refuses to load: the store
 *   enters failed mode and every agent endpoint answers 503. It never
 *   serves an empty store as if nothing had happened.
 * - A missing snapshot alongside a non-empty audit trail also refuses:
 *   that combination means state was deleted or lost, not a first boot.
 * - Both absent is a first boot: a fresh store id is minted and the
 *   initial snapshot is written immediately (a write failure here fails
 *   the load just as loudly).
 * - Any persistent persist failure during operation marks the store
 *   failed and rolls the in-memory change back, so memory can never run
 *   ahead of disk. Transient filesystem locks get bounded retries first.
 * - Request ids are unique; duplicates are rejected, never overwritten.
 *
 * Without a snapshotFile the store is memory-only (unit tests, ephemeral
 * use). Memory-only mode still enforces uniqueness but makes no
 * durability claim.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function isAuditNonEmpty(ledgerFile) {
  try {
    if (!ledgerFile) return false;
    if (!fs.existsSync(ledgerFile)) return false;
    return fs.statSync(ledgerFile).size > 0;
  } catch {
    return false;
  }
}

function validRecord(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) return false;
  if (typeof r.id !== 'string' || !r.id) return false;
  if (!Number.isSafeInteger(r.createdAt)) return false;
  if (!r.normalizedTx || typeof r.normalizedTx !== 'object' || Array.isArray(r.normalizedTx)) return false;
  if (r.txDigest !== null && r.txDigest !== undefined && typeof r.txDigest !== 'string') return false;
  return true;
}

function createAgentStore({ ledgerFile, snapshotFile } = {}) {
  const requests = new Map();
  // Idempotency-Key -> requestId. Rebuilt from records on load (the
  // record is the durable source; this map is a lookup index only), so
  // replays survive restarts without a second durable structure.
  const idempotencyIndex = new Map();
  let failed = null;
  let meta = { storeId: null, lastMandate: null };

  function appendEvent(event) {
    if (!ledgerFile) return;
    try {
      fs.mkdirSync(path.dirname(ledgerFile), { recursive: true });
      fs.appendFileSync(ledgerFile, `${JSON.stringify({ ts: Date.now(), ...event })}\n`, 'utf8');
    } catch {
      /* audit logging must never break request handling */
    }
  }

  function snapshotBody() {
    return {
      format: 'assertara-agent-requests-1',
      storeId: meta.storeId,
      savedAt: Date.now(),
      lastMandate: meta.lastMandate,
      requests: [...requests.values()]
    };
  }

  // Atomic durable write. Throws on persistent failure; callers roll
  // back and fail closed. Transient filesystem locks (a scanner holding
  // the rename target on Windows) get bounded retries first: a single
  // EPERM flake must not wedge the whole agent API into failed mode.
  // Serialization stays outside the retry — poison content fails
  // immediately, exactly as before.
  function persist() {
    if (!snapshotFile) return;
    const body = JSON.stringify(snapshotBody());
    fs.mkdirSync(path.dirname(snapshotFile), { recursive: true });
    const tmp = `${snapshotFile}.tmp`;
    let lastErr = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        fs.writeFileSync(tmp, body, 'utf8');
        fs.renameSync(tmp, snapshotFile);
        return;
      } catch (err) {
        lastErr = err;
        try { fs.rmSync(tmp, { force: true }); } catch { /* best-effort cleanup */ }
        if (attempt < 2) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25 * (attempt + 1));
      }
    }
    throw lastErr;
  }

  function fail(reason) {
    failed = reason;
  }

  function load() {
    requests.clear();
    idempotencyIndex.clear();
    failed = null;
    meta = { storeId: null, lastMandate: null };
    try {
      if (!snapshotFile) return { ok: true, loaded: 0, mode: 'memory' };
      if (!fs.existsSync(snapshotFile)) {
        if (isAuditNonEmpty(ledgerFile)) {
          fail('request snapshot is missing but the audit trail is non-empty; refusing to assume a clean slate');
          return { ok: false, error: failed };
        }
        meta.storeId = crypto.randomUUID();
        persist(); // prove the snapshot path is writable before serving
        return { ok: true, loaded: 0, mode: 'first-boot' };
      }
      let parsed;
      try {
        parsed = JSON.parse(fs.readFileSync(snapshotFile, 'utf8'));
      } catch {
        fail('request snapshot is corrupt (unparseable JSON)');
        return { ok: false, error: failed };
      }
      if (!parsed || parsed.format !== 'assertara-agent-requests-1'
        || typeof parsed.storeId !== 'string' || !parsed.storeId
        || !Array.isArray(parsed.requests)) {
        fail('request snapshot has an unrecognized or invalid structure');
        return { ok: false, error: failed };
      }
      const seen = new Set();
      for (const r of parsed.requests) {
        if (!validRecord(r) || seen.has(r.id)) {
          fail('request snapshot contains an invalid or duplicate record');
          return { ok: false, error: failed };
        }
        seen.add(r.id);
        requests.set(r.id, r);
        if (typeof r.idempotencyKey === 'string' && r.idempotencyKey && !idempotencyIndex.has(r.idempotencyKey)) {
          idempotencyIndex.set(r.idempotencyKey, r.id);
        }
      }
      meta = {
        storeId: parsed.storeId,
        lastMandate: parsed.lastMandate && typeof parsed.lastMandate === 'object'
          && typeof parsed.lastMandate.id === 'string'
          && Number.isSafeInteger(parsed.lastMandate.version)
          ? { id: parsed.lastMandate.id, version: parsed.lastMandate.version }
          : null
      };
      return { ok: true, loaded: requests.size, mode: 'restored' };
    } catch (err) {
      fail(`request store load failed: ${err && err.message ? err.message : String(err)}`);
      return { ok: false, error: failed };
    }
  }

  return {
    load,
    available: () => failed === null,
    unavailableReason: () => failed,
    create(record) {
      if (failed) return null;
      if (!record || requests.has(record.id)) return null;
      requests.set(record.id, record);
      const keyIndexed = typeof record.idempotencyKey === 'string' && record.idempotencyKey
        && !idempotencyIndex.has(record.idempotencyKey);
      if (keyIndexed) idempotencyIndex.set(record.idempotencyKey, record.id);
      try {
        persist();
      } catch {
        requests.delete(record.id);
        if (keyIndexed) idempotencyIndex.delete(record.idempotencyKey);
        fail('request snapshot write failed during create');
        return null;
      }
      appendEvent({ event: 'PROPOSED', requestId: record.id, txDigest: record.txDigest || null });
      return record;
    },
    get(id) {
      if (failed) return null;
      return requests.get(id) || null;
    },
    findByIdempotencyKey(key) {
      if (failed) return null;
      if (typeof key !== 'string' || !key) return null;
      const id = idempotencyIndex.get(key);
      return id ? (requests.get(id) || null) : null;
    },
    update(id, patch) {
      if (failed) return null;
      const record = requests.get(id);
      if (!record) return null;
      const before = { ...record };
      Object.assign(record, patch, { updatedAt: Date.now() });
      try {
        persist();
      } catch {
        requests.set(id, before);
        fail('request snapshot write failed during update');
        return null;
      }
      return record;
    },
    getLastMandate() {
      return meta.lastMandate ? { ...meta.lastMandate } : null;
    },
    setLastMandate(entry) {
      if (failed) return false;
      const before = meta.lastMandate;
      meta.lastMandate = entry ? { id: entry.id, version: entry.version } : null;
      try {
        persist();
      } catch {
        meta.lastMandate = before;
        fail('request snapshot write failed during mandate record');
        return false;
      }
      return true;
    },
    appendEvent,
    size: () => requests.size,
    // Snapshot copy for maintenance sweeps (interrupted-investigation
    // recovery). Mutations still go through create/update only.
    all() {
      if (failed) return null;
      return [...requests.values()];
    }
  };
}

module.exports = { createAgentStore };
