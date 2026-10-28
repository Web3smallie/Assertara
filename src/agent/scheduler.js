/**
 * Assertara Night Watch scheduler — in-process recurring watch checks.
 *
 * LIMITS (by design): this scheduler only runs while the application process
 * is alive. It is not 24/7 monitoring without a deployment that keeps the
 * process up (service manager / container restart policy). It never claims
 * otherwise: every status surface reports whether the loop is running.
 *
 * Design: single JSON state file with atomic writes, an exclusive lock file
 * with stale-lock recovery, sequential per-target checks (concurrency bound
 * of 1), per-target error backoff, missed-run catch-up of exactly one check,
 * and alerts only on new observed changes (hash-deduped). No secrets are
 * ever written to state — targets hold public addresses plus public snapshots.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { runWatchCheck } = require('./features');
const { isAddress } = require('./toolRegistry');

const STATE_VERSION = 1;
const STATE_FILE = 'nightwatch.json';
const LOCK_FILE = '.nightwatch.lock';
const MIN_INTERVAL_MS = 5000;
const MAX_INTERVAL_MS = 7 * 24 * 3600 * 1000;
const DEFAULT_INTERVAL_MS = 3600 * 1000;
const DEFAULT_TICK_MS = 15000;
const DEFAULT_STALENESS_MS = 120000;
const DEFAULT_MAX_BACKOFF_MS = 3600 * 1000;
const DEFAULT_MAX_ALERTS = 200;

function randomToken() {
  return crypto.randomBytes(8).toString('hex');
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function isValidInterval(ms) {
  return Number.isFinite(ms) && ms >= MIN_INTERVAL_MS && ms <= MAX_INTERVAL_MS;
}

function sanitizeTarget(raw, id) {
  if (!raw || typeof raw !== 'object') return null;
  if (!isAddress(raw.address)) return null;
  if (!isValidInterval(raw.intervalMs)) return null;
  return {
    id,
    address: raw.address,
    label: typeof raw.label === 'string' ? raw.label.slice(0, 120) : '',
    intervalMs: raw.intervalMs,
    paused: raw.paused === true,
    baseline: raw.baseline && typeof raw.baseline === 'object' ? raw.baseline : null,
    lastCheck: Number.isFinite(raw.lastCheck) ? raw.lastCheck : null,
    nextDue: Number.isFinite(raw.nextDue) ? raw.nextDue : null,
    consecutiveFailures: Number.isInteger(raw.consecutiveFailures) && raw.consecutiveFailures >= 0 ? raw.consecutiveFailures : 0,
    lastAlertHash: typeof raw.lastAlertHash === 'string' ? raw.lastAlertHash : null,
    lastError: typeof raw.lastError === 'string' ? raw.lastError.slice(0, 500) : null
  };
}

class WatchScheduler {
  /**
   * @param {object} opts { dir, tickMs, stalenessMs, maxBackoffMs, maxAlerts,
   *   now?: () => ms, client?: chain client for checks }
   */
  constructor(opts = {}) {
    if (!opts.dir || typeof opts.dir !== 'string') throw new Error('scheduler requires a state directory');
    this.dir = opts.dir;
    this.statePath = path.join(this.dir, STATE_FILE);
    this.lockPath = path.join(this.dir, LOCK_FILE);
    this.tickMs = opts.tickMs || DEFAULT_TICK_MS;
    this.stalenessMs = opts.stalenessMs || DEFAULT_STALENESS_MS;
    this.maxBackoffMs = opts.maxBackoffMs || DEFAULT_MAX_BACKOFF_MS;
    this.maxAlerts = opts.maxAlerts || DEFAULT_MAX_ALERTS;
    this.now = typeof opts.now === 'function' ? opts.now : () => Date.now();
    this.client = opts.client;
    this.timer = null;
    this.lockToken = null;
    this.ticking = false;
  }

  get running() {
    return this.timer !== null;
  }

  // ---------- locking ----------

  readLock() {
    try {
      const raw = fs.readFileSync(this.lockPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed.token !== 'string' || !Number.isFinite(parsed.at)) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  acquireLock() {
    fs.mkdirSync(this.dir, { recursive: true });
    const token = randomToken();
    const payload = JSON.stringify({ token, pid: process.pid, at: this.now() });
    try {
      fs.writeFileSync(this.lockPath, payload, { flag: 'wx' });
      this.lockToken = token;
      return true;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
    // Lock exists: fresh (another live instance) or stale (crashed holder)?
    const existing = this.readLock();
    if (existing && this.now() - existing.at < this.stalenessMs) {
      throw new Error('another scheduler instance holds the lock');
    }
    try {
      fs.unlinkSync(this.lockPath);
    } catch {}
    fs.writeFileSync(this.lockPath, payload, { flag: 'wx' });
    this.lockToken = token;
    return true;
  }

  releaseLock() {
    if (!this.lockToken) return;
    try {
      const existing = this.readLock();
      if (existing && existing.token === this.lockToken) fs.unlinkSync(this.lockPath);
    } catch {}
    this.lockToken = null;
  }

  // ---------- state ----------

  freshState() {
    return { version: STATE_VERSION, targets: {}, alerts: [], meta: {} };
  }

  loadState() {
    let raw;
    try {
      raw = fs.readFileSync(this.statePath, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return { state: this.freshState(), recovered: false };
      throw err;
    }
    return this.parseState(raw);
  }

  parseState(raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return this.quarantine('unparseable JSON');
    }
    if (!parsed || parsed.version !== STATE_VERSION || !parsed.targets || typeof parsed.targets !== 'object') {
      return this.quarantine('schema mismatch');
    }
    const targets = {};
    let dropped = 0;
    for (const [id, entry] of Object.entries(parsed.targets)) {
      // Target ids are internal (w_*); keys are never used as paths.
      if (!/^w_[0-9a-f]+$/.test(id)) {
        dropped += 1;
        continue;
      }
      const clean = sanitizeTarget(entry, id);
      if (clean) targets[id] = clean;
      else dropped += 1;
    }
    const alerts = Array.isArray(parsed.alerts) ? parsed.alerts.filter((a) => a && typeof a === 'object').slice(-this.maxAlerts) : [];
    return { state: { version: STATE_VERSION, targets, alerts, meta: {} }, recovered: false, droppedEntries: dropped };
  }

  quarantine(reason) {
    const name = `nightwatch.corrupt-${Date.now()}.json`;
    try {
      fs.renameSync(this.statePath, path.join(this.dir, name));
    } catch {}
    const state = this.freshState();
    state.meta.recoveredFrom = name;
    state.meta.recoveryReason = reason;
    return { state, recovered: true, quarantine: name, reason };
  }

  saveState(state) {
    fs.mkdirSync(this.dir, { recursive: true });
    const tmp = path.join(this.dir, `.nightwatch.json.tmp-${process.pid}`);
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
    fs.renameSync(tmp, this.statePath); // atomic on the same directory
  }

  // ---------- targets ----------

  addTarget({ address, label, intervalMs }) {
    if (!isAddress(address)) throw new Error('target address must be a 0x address');
    const interval = intervalMs === undefined ? DEFAULT_INTERVAL_MS : intervalMs;
    if (!isValidInterval(interval)) {
      throw new Error(`interval must be between ${MIN_INTERVAL_MS}ms and ${MAX_INTERVAL_MS}ms`);
    }
    const { state } = this.loadState();
    const id = `w_${randomToken()}`;
    const now = this.now();
    state.targets[id] = {
      id, address, label: typeof label === 'string' ? label.slice(0, 120) : '',
      intervalMs: interval, paused: false, baseline: null,
      lastCheck: null, nextDue: now + interval,
      consecutiveFailures: 0, lastAlertHash: null, lastError: null
    };
    this.saveState(state);
    return { ...state.targets[id] };
  }

  updateTarget(id, patch) {
    const { state } = this.loadState();
    const target = state.targets[id];
    if (!target) throw new Error(`unknown target: ${id}`);
    if (patch.intervalMs !== undefined) {
      if (!isValidInterval(patch.intervalMs)) throw new Error(`interval must be between ${MIN_INTERVAL_MS}ms and ${MAX_INTERVAL_MS}ms`);
      target.intervalMs = patch.intervalMs;
    }
    if (patch.paused !== undefined) target.paused = patch.paused === true;
    if (patch.label !== undefined) target.label = String(patch.label).slice(0, 120);
    this.saveState(state);
    return { ...target };
  }

  pauseTarget(id) {
    return this.updateTarget(id, { paused: true });
  }

  resumeTarget(id) {
    const target = this.updateTarget(id, { paused: false });
    // Resume restarts the schedule from now rather than firing a stale backlog.
    const { state } = this.loadState();
    state.targets[id].nextDue = this.now() + state.targets[id].intervalMs;
    this.saveState(state);
    return { ...state.targets[id] };
  }

  removeTarget(id) {
    const { state } = this.loadState();
    if (!state.targets[id]) throw new Error(`unknown target: ${id}`);
    delete state.targets[id];
    this.saveState(state);
    return true;
  }

  listTargets() {
    const { state } = this.loadState();
    return Object.values(state.targets).map((t) => ({ ...t }));
  }

  getAlerts({ targetId, limit } = {}) {
    const { state } = this.loadState();
    let alerts = state.alerts;
    if (targetId) alerts = alerts.filter((a) => a.targetId === targetId);
    return alerts.slice(-(limit || 50)).map((a) => ({ ...a }));
  }

  // ---------- running ----------

  async start() {
    if (this.timer) throw new Error('scheduler already started');
    this.acquireLock();
    // Catch up immediately (one check per due target), then on interval.
    await this.tickOnce();
    this.timer = setInterval(() => {
      this.tickOnce().catch(() => {});
    }, this.tickMs);
    return true;
  }

  async stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.releaseLock();
    return true;
  }

  async tickOnce() {
    if (this.ticking) return { skipped: true, reason: 'tick already in progress' };
    const owned = Boolean(this.lockToken);
    if (!owned) this.acquireLock();
    this.ticking = true;
    try {
      return await this.tick();
    } finally {
      this.ticking = false;
      if (!owned) this.releaseLock();
    }
  }

  async tick() {
    const now = this.now();
    const loaded = this.loadState();
    const state = loaded.state;
    const summary = {
      checked: 0, alerted: 0, failed: 0, skipped: 0,
      recovered: loaded.recovered === true,
      droppedEntries: loaded.droppedEntries || 0
    };
    const due = Object.values(state.targets)
      .filter((t) => !t.paused && Number.isFinite(t.nextDue) && t.nextDue <= now)
      .sort((a, b) => a.nextDue - b.nextDue);
    // Sequential execution: concurrency bound of 1; one target's failure
    // never stops the others.
    for (const target of due) {
      try {
        const res = await runWatchCheck(
          { watch: { address: target.address, label: target.label }, baseline: target.baseline },
          this.client ? { client: this.client } : {}
        );
        if (!target.baseline) {
          target.baseline = res.baselineEstablished;
        } else if (res.changed) {
          const hash = sha256Hex(JSON.stringify(res.changes));
          if (hash !== target.lastAlertHash) {
            state.alerts.push({ id: `a_${randomToken()}`, targetId: target.id, at: now, changes: res.changes });
            if (state.alerts.length > this.maxAlerts) state.alerts.splice(0, state.alerts.length - this.maxAlerts);
            target.lastAlertHash = hash;
            summary.alerted += 1;
          }
          target.baseline = res.current;
        }
        target.lastCheck = now;
        target.consecutiveFailures = 0;
        target.lastError = null;
        // Missed-run recovery: exactly one check, schedule restarts from now.
        target.nextDue = now + target.intervalMs;
        summary.checked += 1;
      } catch (err) {
        target.consecutiveFailures += 1;
        target.lastError = String((err && err.message) || err).slice(0, 500);
        const backoff = Math.min(target.intervalMs * 2 ** Math.min(target.consecutiveFailures, 10), this.maxBackoffMs);
        target.nextDue = now + backoff;
        summary.failed += 1;
      }
    }
    this.saveState(state);
    return summary;
  }
}

module.exports = {
  WatchScheduler,
  MIN_INTERVAL_MS, MAX_INTERVAL_MS, DEFAULT_INTERVAL_MS, DEFAULT_TICK_MS,
  DEFAULT_STALENESS_MS, DEFAULT_MAX_BACKOFF_MS, DEFAULT_MAX_ALERTS
};
