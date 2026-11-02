/**
 * Assertara pre-sign gate: shared protocol constants, message validation,
 * and the race-safe pending-request state machine.
 *
 * Used by the service worker (via importScripts) and by unit tests in Node.
 * Pure: no chrome.*, window, or document access. Time is injectable for
 * deterministic expiry tests.
 *
 * Protocol (page MAIN world <-> isolated bridge, via window.postMessage):
 *   MAIN -> ISO: HELLO, INTERCEPTED, BYPASSED, GATE_EXPIRED, TX_MUTATED
 *   ISO  -> MAIN: BRIDGE_READY, ACK, DECISION
 * Every page message carries __assertara === 'gate-v1' and is validated
 * before use. Page scripts can observe these messages but cannot forge a
 * continuation: the DECISION that releases a held request is only ever
 * emitted by the isolated bridge after the service worker accepts an
 * explicit UI decision for that exact requestId.
 *
 * Payload binding (Phase 2): INTERCEPTED carries the full transaction
 * snapshot plus its SHA-256 digest (txDigest); DECISION carries the
 * approved digest (approvedDigest) bound at approval time. The page
 * re-snapshots the live arguments at release and refuses to forward
 * unless all three digests agree; TX_MUTATED reports a refusal.
 */
(function () {
  const root = typeof globalThis !== 'undefined' ? globalThis : {};

  const PROTOCOL = 'gate-v1';

  // Gated (held) methods. Tx methods are evaluated; message methods are
  // held and shown as unsupported/unverified, never auto-forwarded silently.
  const TX_METHODS = ['eth_sendTransaction', 'eth_signTransaction'];
  const MSG_METHODS = [
    'personal_sign',
    'eth_sign',
    'eth_signTypedData',
    'eth_signTypedData_v1',
    'eth_signTypedData_v3',
    'eth_signTypedData_v4'
  ];

  const STATES = {
    DETECTED: 'DETECTED',
    EVALUATING: 'EVALUATING',
    AWAITING_USER_DECISION: 'AWAITING_USER_DECISION',
    FORWARDED_TO_WALLET: 'FORWARDED_TO_WALLET',
    USER_CANCELLED: 'USER_CANCELLED',
    UNSUPPORTED: 'UNSUPPORTED',
    EVALUATION_FAILED: 'EVALUATION_FAILED',
    EXPIRED: 'EXPIRED'
  };
  const TERMINAL = {
    FORWARDED_TO_WALLET: true,
    USER_CANCELLED: true,
    EXPIRED: true
  };

  const LIMITS = {
    REQUEST_ID_RE: /^[A-Za-z0-9_-]{1,128}$/,
    DIGEST_RE: /^[0-9a-f]{64}$/,
    METHOD_MAX: 64,
    SHORT_STRING_MAX: 4096,
    TX_FIELD_MAX: 65536,
    TX_MAX_KEYS: 256,
    TX_MAX_DEPTH: 4,
    TX_MAX_ITEMS: 256,
    TEXT_MAX: 4096,
    MAX_PENDING_PER_TAB: 20,
    DECISION_TIMEOUT_MS: 600000,
    ACK_TIMEOUT_MS: 1000,
    ACK_RETRIES: 3
  };

  function isTerminal(status) {
    return TERMINAL[status] === true;
  }

  function boundedString(value, max) {
    return typeof value === 'string' && value.length <= max ? value : null;
  }

  function validRequestId(value) {
    return typeof value === 'string' && LIMITS.REQUEST_ID_RE.test(value) ? value : null;
  }

  // Deep-copy one tx value with bounds. Returns { kept, value }: kept
  // false drops the whole FIELD (never silently altered). Field-level
  // atomicity keeps digest comparison honest: a dropped field changes the
  // worker copy, so the recomputed digest mismatches and evaluation fails
  // closed instead of assessing different bytes than the page snapshotted.
  function cleanTxValue(value, depth) {
    if (value === null) return { kept: true, value: null };
    const t = typeof value;
    if (t === 'string') {
      return value.length <= LIMITS.TX_FIELD_MAX
        ? { kept: true, value }
        : { kept: false };
    }
    if (t === 'number') return Number.isFinite(value) ? { kept: true, value } : { kept: true, value: null };
    if (t === 'boolean') return { kept: true, value };
    if (depth >= LIMITS.TX_MAX_DEPTH || t !== 'object') return { kept: false };
    if (Array.isArray(value)) {
      if (value.length > LIMITS.TX_MAX_ITEMS) return { kept: false };
      const out = [];
      for (const item of value) {
        const r = cleanTxValue(item, depth + 1);
        if (!r.kept) return { kept: false };
        out.push(r.value === undefined ? null : r.value);
      }
      return { kept: true, value: out };
    }
    const keys = Object.keys(value);
    if (keys.length > LIMITS.TX_MAX_KEYS) return { kept: false };
    const out = {};
    for (const k of keys) {
      if (typeof k !== 'string' || k.length > 256) return { kept: false };
      const v = value[k];
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
      const r = cleanTxValue(v, depth + 1);
      if (!r.kept) return { kept: false };
      out[k] = r.value;
    }
    return { kept: true, value: out };
  }

  // Preserve the full snapshot (all fields incl. extras) field-atomically.
  // Known EVM fields keep their exact values; oversized/unrepresentable
  // fields are dropped whole, which the digest check detects downstream.
  function cleanTxSnapshot(tx) {
    const out = {};
    if (!tx || typeof tx !== 'object' || Array.isArray(tx)) return out;
    const keys = Object.keys(tx);
    const capped = keys.slice(0, LIMITS.TX_MAX_KEYS);
    for (const key of capped) {
      if (typeof key !== 'string' || key.length === 0 || key.length > 256) continue;
      const r = cleanTxValue(tx[key], 1);
      if (r.kept && r.value !== undefined) out[key] = r.value;
    }
    return out;
  }

  function validDigest(value) {
    return typeof value === 'string' && LIMITS.DIGEST_RE.test(value) ? value : null;
  }

  /**
   * Validate a MAIN->ISO bridge message. Returns a sanitized copy or null.
   * Types: HELLO {requestId? no} | INTERCEPTED {requestId, method, kind,
   * tx?, txDigest?, chainId, wallet, pageContext} | TX_MUTATED {requestId}.
   */
  function validateMainMessage(data) {
    if (!data || typeof data !== 'object') return null;
    if (data.__assertara !== PROTOCOL || data.direction !== 'main-to-iso') return null;
    if (data.type === 'HELLO') return { type: 'HELLO' };
    if (data.type === 'BYPASSED') {
      const requestId = validRequestId(data.requestId);
      const method = boundedString(data.method, LIMITS.METHOD_MAX);
      if (!requestId || !method) return null;
      return { type: 'BYPASSED', requestId, method };
    }
    if (data.type === 'GATE_EXPIRED') {
      const requestId = validRequestId(data.requestId);
      if (!requestId) return null;
      return { type: 'GATE_EXPIRED', requestId };
    }
    if (data.type === 'TX_MUTATED') {
      const requestId = validRequestId(data.requestId);
      if (!requestId) return null;
      return { type: 'TX_MUTATED', requestId };
    }
    if (data.type !== 'INTERCEPTED') return null;
    const requestId = validRequestId(data.requestId);
    const method = boundedString(data.method, LIMITS.METHOD_MAX);
    if (!requestId || !method) return null;
    const kind = data.kind === 'tx' || data.kind === 'message' ? data.kind : null;
    if (!kind) return null;
    const clean = { type: 'INTERCEPTED', requestId, method, kind, tx: {}, txDigest: null, chainId: null, wallet: null, pageContext: { url: '', title: '', visibleText: '' } };
    if (kind === 'tx' && data.tx && typeof data.tx === 'object') {
      clean.tx = cleanTxSnapshot(data.tx);
      clean.txDigest = validDigest(data.txDigest);
    }
    const chainId = boundedString(data.chainId, LIMITS.SHORT_STRING_MAX);
    if (chainId) clean.chainId = chainId;
    if (data.wallet && typeof data.wallet === 'object') {
      const wallet = { source: boundedString(data.wallet.source, 128) || 'unknown' };
      const name = boundedString(data.wallet.name, 128);
      const rdns = boundedString(data.wallet.rdns, 128);
      if (name) wallet.name = name;
      if (rdns) wallet.rdns = rdns;
      clean.wallet = wallet;
    }
    if (data.pageContext && typeof data.pageContext === 'object') {
      clean.pageContext = {
        url: boundedString(data.pageContext.url, LIMITS.TX_FIELD_MAX) || '',
        title: boundedString(data.pageContext.title, LIMITS.SHORT_STRING_MAX) || '',
        visibleText: boundedString(data.pageContext.visibleText, LIMITS.TEXT_MAX) || ''
      };
    }
    return clean;
  }

  /**
   * Validate an ISO->MAIN bridge message (called in the MAIN world before
   * touching any pending request). Types: BRIDGE_READY | ACK {requestId} |
   * DECISION {requestId, decision, approvedDigest?}.
   */
  function validateIsoMessage(data) {
    if (!data || typeof data !== 'object') return null;
    if (data.__assertara !== PROTOCOL || data.direction !== 'iso-to-main') return null;
    if (data.type === 'BRIDGE_READY') return { type: 'BRIDGE_READY' };
    const requestId = validRequestId(data.requestId);
    if (!requestId) return null;
    if (data.type === 'ACK') return { type: 'ACK', requestId };
    if (data.type === 'DECISION' && (data.decision === 'continue' || data.decision === 'cancel')) {
      const reason = boundedString(data.reason, 64);
      return { type: 'DECISION', requestId, decision: data.decision, reason, approvedDigest: validDigest(data.approvedDigest) };
    }
    return null;
  }

  /** EIP-1193-style user-rejection error. Distinct messages keep Assertara
   *  cancellation separate from wallet rejection while staying dApp-safe. */
  function cancellationError(reason) {
    const err = new Error(reason === 'expired'
      ? 'Assertara: request expired before a decision was made; nothing was forwarded to the wallet.'
      : reason === 'mutation-detected'
        ? 'Assertara: transaction changed after evaluation; the approval no longer applies and nothing was forwarded to the wallet.'
        : 'Assertara: user cancelled the request before wallet review; nothing was forwarded to the wallet.');
    err.code = 4001;
    return err;
  }

  function makeRequestId() {
    try {
      const c = root.crypto;
      if (c && typeof c.randomUUID === 'function') return c.randomUUID().replace(/-/g, '');
      if (c && typeof c.getRandomValues === 'function') {
        const bytes = new Uint8Array(16);
        c.getRandomValues(bytes);
        return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
      }
    } catch {
      /* fall through to Math.random */
    }
    let out = '';
    const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    for (let i = 0; i < 32; i += 1) {
      out += alphabet[Math.floor(Math.random() * alphabet.length)];
    }
    return out;
  }

  /**
   * Race-safe pending-request store. Single-threaded check-and-set: decide()
   * and applyAssessment() only act on exact expected states, so double
   * decisions, stale backend results, and post-terminal updates are dropped.
   */
  function createGateStore(options) {
    const now = (options && typeof options.now === 'function') ? options.now : () => Date.now();
    const decisionTimeoutMs = (options && options.decisionTimeoutMs) || LIMITS.DECISION_TIMEOUT_MS;
    const maxPerTab = (options && options.maxPerTab) || LIMITS.MAX_PENDING_PER_TAB;
    const requests = new Map(); // requestId -> record

    function tabPendingCount(tabId) {
      let n = 0;
      for (const r of requests.values()) {
        if (r.tabId === tabId && !isTerminal(r.status)) n += 1;
      }
      return n;
    }

    // Returns {record, duplicate:true} when the id already exists: the
    // caller must NOT re-evaluate. Returns {rejected:'tab-full'} when the
    // tab already holds the maximum pending requests.
    function register(msg, tabId, pageUrl) {
      const existing = requests.get(msg.requestId);
      if (existing) return { record: existing, duplicate: true };
      if (tabPendingCount(tabId) >= maxPerTab) return { record: null, rejected: 'tab-full' };
      const record = {
        requestId: msg.requestId,
        tabId,
        pageUrl: typeof pageUrl === 'string' ? pageUrl : '',
        method: msg.method,
        kind: msg.kind,
        tx: msg.kind === 'tx' ? { ...msg.tx } : null,
        // Page-claimed digest of the intercepted snapshot. The worker
        // recomputes over its own copy before evaluating; a mismatch
        // fails closed (see service worker), so a forged claim buys
        // nothing. Null means unbound (message kind or legacy page).
        txDigest: msg.kind === 'tx' && typeof msg.txDigest === 'string' ? msg.txDigest : null,
        // Digest bound to the approval at decide() time. The page
        // re-verifies this against the live arguments at release.
        approvedDigest: null,
        chainId: msg.chainId || null,
        wallet: msg.wallet || null,
        pageContext: { ...msg.pageContext },
        status: STATES.DETECTED,
        assessment: null,
        decidedAt: null,
        createdAt: now(),
        updatedAt: now()
      };
      requests.set(msg.requestId, record);
      return { record, duplicate: false };
    }

    function get(requestId) {
      return requests.get(requestId) || null;
    }

    function setStatus(record, status) {
      record.status = status;
      record.updatedAt = now();
    }

    // First valid decision wins. Cancel is safe from any non-terminal
    // state (it never forwards, so cancelling mid-evaluation is allowed);
    // continue requires an assessment-ready state. Late backend results
    // for a cancelled record are dropped by applyAssessment/applyEvalFailure.
    // An accepted continue binds the approval to the record's digest at
    // this instant; the page re-verifies it against the live arguments
    // before forwarding. Returns {accepted:true} or {accepted:false, reason}.
    function decide(requestId, decision) {
      const record = requests.get(requestId);
      if (!record) return { accepted: false, reason: 'unknown-request' };
      if (isTerminal(record.status)) return { accepted: false, reason: 'already-decided' };
      if (decision !== 'continue' && decision !== 'cancel') return { accepted: false, reason: 'bad-decision' };
      if (decision === 'continue'
        && record.status !== STATES.AWAITING_USER_DECISION
        && record.status !== STATES.EVALUATION_FAILED
        && record.status !== STATES.UNSUPPORTED) {
        return { accepted: false, reason: 'not-awaiting-decision' };
      }
      record.decidedAt = now();
      if (decision === 'continue') record.approvedDigest = record.txDigest || null;
      setStatus(record, decision === 'continue' ? STATES.FORWARDED_TO_WALLET : STATES.USER_CANCELLED);
      return { accepted: true };
    }

    // Applies a backend outcome only if the record is still EVALUATING.
    // Returns true when applied, false when stale (navigation/terminal/etc).
    function applyAssessment(requestId, assessment) {
      const record = requests.get(requestId);
      if (!record || record.status !== STATES.EVALUATING) return false;
      record.assessment = assessment;
      setStatus(record, STATES.AWAITING_USER_DECISION);
      return true;
    }

    function applyEvalFailure(requestId, errorMessage) {
      const record = requests.get(requestId);
      if (!record || record.status !== STATES.EVALUATING) return false;
      record.assessment = { ok: false, error: errorMessage };
      setStatus(record, STATES.EVALUATION_FAILED);
      return true;
    }

    // Expire awaiting requests past the decision timeout. Returns expired ids.
    function sweepExpired() {
      const expired = [];
      const t = now();
      for (const record of requests.values()) {
        if (isTerminal(record.status)) continue;
        if (record.status !== STATES.AWAITING_USER_DECISION
          && record.status !== STATES.EVALUATION_FAILED
          && record.status !== STATES.UNSUPPORTED) continue;
        if (t - record.updatedAt >= decisionTimeoutMs) {
          setStatus(record, STATES.EXPIRED);
          expired.push(record.requestId);
        }
      }
      return expired;
    }

    // Navigation/tab-close: non-terminal requests for the tab can never
    // resolve (page context is gone). Returns affected ids.
    function invalidateTab(tabId, status) {
      const affected = [];
      for (const record of requests.values()) {
        if (record.tabId !== tabId || isTerminal(record.status)) continue;
        setStatus(record, status || STATES.EXPIRED);
        affected.push(record.requestId);
      }
      return affected;
    }

    function tabRequests(tabId) {
      const out = [];
      for (const record of requests.values()) {
        if (record.tabId === tabId) out.push(record);
      }
      out.sort((a, b) => b.createdAt - a.createdAt);
      return out;
    }

    function pendingCount(tabId) {
      return tabPendingCount(tabId);
    }

    // Drop terminal records older than maxAgeMs. Returns removed count.
    function pruneTerminal(maxAgeMs) {
      const t = now();
      let removed = 0;
      for (const [id, record] of requests) {
        if (isTerminal(record.status) && t - record.updatedAt >= maxAgeMs) {
          requests.delete(id);
          removed += 1;
        }
      }
      return removed;
    }

    return {
      register, get, decide, applyAssessment, applyEvalFailure,
      sweepExpired, invalidateTab, tabRequests, pendingCount,
      pruneTerminal, setStatus,
      size: () => requests.size
    };
  }

  root.AssertaraGate = {
    PROTOCOL,
    TX_METHODS,
    MSG_METHODS,
    STATES,
    LIMITS,
    isTerminal,
    validateMainMessage,
    validateIsoMessage,
    cancellationError,
    makeRequestId,
    createGateStore
  };
})();
