/**
 * Assertara transaction canonicalization + digest (Phase 2: payload binding).
 *
 * Shared by the page observer (MAIN world), the service worker (via
 * importScripts), and Node unit tests / backend (via require). Pure:
 * no chrome.*, window, or document access.
 *
 * Design notes:
 * - Canonical form: JSON string with fixed top-level field order, every
 *   known field always present (null when absent), quantities as minimal
 *   lowercase hex, addresses/data lowercased, unknown extra fields merged
 *   under sorted keys. Byte-exact for everything except well-defined
 *   semantic equivalences (hex case, leading zeros, decimal-vs-hex
 *   quantities, key order). Absent and explicit-null encode identically
 *   (both "not supplied"); absent is NEVER treated as a verified value —
 *   it is simply part of the bound bytes.
 * - Hash: SHA-256 over the UTF-8 canonical bytes, hex-encoded (64 chars,
 *   matching the screenshot-sha256 convention). The implementation below
 *   is the standard FIPS 180-4 algorithm; the backend hashes the same
 *   canonical bytes with Node's crypto, and the regression suite
 *   cross-checks this implementation against Node crypto, WebCrypto, and
 *   NIST vectors. A vendored synchronous implementation is used (instead
 *   of crypto.subtle) because the page release path must verify
 *   synchronously and must not depend on page-reachable globals.
 * - snapshotTx deep-clones params with JSON transport semantics so the
 *   page snapshot, the worker copy (structured clone), and the backend
 *   copy (JSON) all digest identically.
 * - Any function here returns null (never throws, never invents) when
 *   its input cannot be faithfully represented. Callers treat null as
 *   "integrity unverifiable" and fail closed.
 */
(function () {
  const root = typeof globalThis !== 'undefined' ? globalThis : {};
  // Captured at load (document_start runs before page scripts): the page
  // must not be able to subvert the digest by replacing globals later.
  const TE = typeof TextEncoder !== 'undefined' ? TextEncoder : null;

  const DIGEST_RE = /^[0-9a-f]{64}$/;
  const TX_QUANTITY_FIELDS = ['type', 'chainId', 'nonce', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'value'];
  const TX_ADDRESS_FIELDS = ['to', 'from'];
  const TX_DATA_FIELDS = ['data'];
  const TX_ORDER = ['type', 'chainId', 'nonce', 'to', 'from', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'value', 'data', 'accessList'];
  const KNOWN_SET = {};
  for (const k of TX_ORDER) KNOWN_SET[k] = true;

  const MAX_DEPTH = 8;
  const MAX_KEYS = 512;
  const MAX_ITEMS = 1024;
  const MAX_CANONICAL_BYTES = 8 * 1024 * 1024;

  // --- SHA-256 (FIPS 180-4) over a Uint8Array, hex output. ---

  const SHA_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256Bytes(bytes) {
    let h0 = 0x6a09e667; let h1 = 0xbb67ae85; let h2 = 0x3c6ef372; let h3 = 0xa54ff53a;
    let h4 = 0x510e527f; let h5 = 0x9b05688c; let h6 = 0x1f83d9ab; let h7 = 0x5be0cd19;
    const bitLenHi = Math.floor(bytes.length / 0x20000000);
    const bitLenLo = (bytes.length << 3) >>> 0;
    const paddedLen = ((((bytes.length + 8) >> 6) + 1) << 6);
    const padded = new Uint8Array(paddedLen);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 8, bitLenHi);
    view.setUint32(paddedLen - 4, bitLenLo);
    const w = new Uint32Array(64);
    for (let off = 0; off < paddedLen; off += 64) {
      for (let i = 0; i < 16; i += 1) w[i] = view.getUint32(off + i * 4);
      for (let i = 16; i < 64; i += 1) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let a = h0; let b = h1; let c = h2; let d = h3;
      let e = h4; let f = h5; let g = h6; let h = h7;
      for (let i = 0; i < 64; i += 1) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const t1 = (h + S1 + ch + SHA_K[i] + w[i]) | 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    const out = [h0, h1, h2, h3, h4, h5, h6, h7];
    let hex = '';
    for (const v of out) hex += (v >>> 0).toString(16).padStart(8, '0');
    return hex;
  }

  function sha256Hex(input) {
    if (typeof input !== 'string' || TE === null) return null;
    let bytes;
    try {
      bytes = new TE().encode(input);
    } catch {
      return null;
    }
    try {
      return sha256Bytes(bytes);
    } catch {
      return null;
    }
  }

  // --- Canonicalization ---

  function normalizeQuantity(value) {
    try {
      // Bigint is NOT JSON-transportable: it cannot reach the worker copy
      // and backend copy faithfully, so it fails closed instead of being
      // silently dropped or retagged.
      if (typeof value === 'bigint') return { raw: true, value: null, hardFail: true };
      if (typeof value === 'number') {
        if (!Number.isSafeInteger(value) || value < 0) return { raw: true, value: null };
        return { raw: false, value: `0x${value.toString(16)}` };
      }
      if (typeof value === 'string') {
        const s = value.trim();
        if (/^0[xX][0-9a-fA-F]+$/.test(s)) return { raw: false, value: `0x${BigInt(s).toString(16)}` };
        if (/^[0-9]+$/.test(s)) return { raw: false, value: `0x${BigInt(s).toString(16)}` };
      }
    } catch {
      /* fall through to raw */
    }
    return { raw: true, value: null };
  }

  function normalizeAddress(value) {
    if (typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
    return null; // caller falls back to raw encoding
  }

  function normalizeData(value) {
    if (typeof value === 'string' && /^0[xX][0-9a-fA-F]*$/.test(value)) return `0x${value.slice(2).toLowerCase()}`;
    return null; // caller falls back to raw encoding
  }

  // Stable JSON-compatible encoding. Returns { ok, json } — ok:false on
  // caps breach (fail closed). Mirrors JSON transport semantics:
  // undefined/function/symbol dropped in objects (null in arrays),
  // NaN/Infinity -> null, bigint tagged (JSON would throw).
  function stableEncode(value, depth, state) {
    if (state.keys > MAX_KEYS || state.items > MAX_ITEMS) return { ok: false };
    if (value === null || value === undefined) return { ok: true, json: 'null' };
    const t = typeof value;
    if (t === 'boolean') return { ok: true, json: value ? 'true' : 'false' };
    if (t === 'number') {
      if (!Number.isFinite(value)) return { ok: true, json: 'null' };
      return { ok: true, json: JSON.stringify(value) };
    }
    if (t === 'bigint') return { ok: false };
    if (t === 'string') return { ok: true, json: JSON.stringify(value) };
    if (t !== 'object') return { ok: true, json: 'null' };
    if (depth > MAX_DEPTH) return { ok: false };
    if (Array.isArray(value)) {
      if (value.length > MAX_ITEMS) return { ok: false };
      const parts = [];
      for (const item of value) {
        state.items += 1;
        if (item === undefined || typeof item === 'function' || typeof item === 'symbol') {
          parts.push('null');
          continue;
        }
        const r = stableEncode(item, depth + 1, state);
        if (!r.ok) return r;
        parts.push(r.json);
      }
      return { ok: true, json: `[${parts.join(',')}]` };
    }
    const keys = Object.keys(value).sort();
    if (keys.length > MAX_KEYS) return { ok: false };
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
      state.keys += 1;
      const r = stableEncode(v, depth + 1, state);
      if (!r.ok) return r;
      parts.push(`${JSON.stringify(k)}:${r.json}`);
    }
    return { ok: true, json: `{${parts.join(',')}}` };
  }

  function encodeField(value, normalize) {
    if (value === null || value === undefined) return { ok: true, json: 'null' };
    const norm = normalize(value);
    if (typeof norm === 'string') return { ok: true, json: JSON.stringify(norm) };
    return stableEncode(value, 1, { keys: 0, items: 0 });
  }

  function encodeQuantityField(value) {
    if (value === null || value === undefined) return { ok: true, json: 'null' };
    const norm = normalizeQuantity(value);
    if (!norm.raw) return { ok: true, json: JSON.stringify(norm.value) };
    if (norm.hardFail) return { ok: false };
    return stableEncode(value, 1, { keys: 0, items: 0 });
  }

  function encodeAccessList(value) {
    if (value === null || value === undefined) return { ok: true, json: 'null' };
    if (!Array.isArray(value)) return stableEncode(value, 1, { keys: 0, items: 0 });
    if (value.length > MAX_ITEMS) return { ok: false };
    const parts = [];
    for (const entry of value) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        const r = stableEncode(entry, 2, { keys: 0, items: 0 });
        if (!r.ok) return r;
        parts.push(r.json);
        continue;
      }
      const addr = normalizeAddress(entry.address);
      const addrJson = addr !== null ? JSON.stringify(addr) : stableEncode(entry.address, 2, { keys: 0, items: 0 }).json;
      if (addr === null && addrJson === undefined) return { ok: false };
      let keysJson = 'null';
      if (Array.isArray(entry.storageKeys)) {
        if (entry.storageKeys.length > MAX_ITEMS) return { ok: false };
        const kp = [];
        for (const k of entry.storageKeys) {
          const nk = normalizeData(k);
          if (nk !== null) { kp.push(JSON.stringify(nk)); continue; }
          const r = stableEncode(k, 3, { keys: 0, items: 0 });
          if (!r.ok) return r;
          kp.push(r.json);
        }
        keysJson = `[${kp.join(',')}]`;
      } else if (entry.storageKeys !== null && entry.storageKeys !== undefined) {
        const r = stableEncode(entry.storageKeys, 2, { keys: 0, items: 0 });
        if (!r.ok) return r;
        keysJson = r.json;
      }
      parts.push(`{"address":${addrJson},"storageKeys":${keysJson}}`);
    }
    return { ok: true, json: `[${parts.join(',')}]` };
  }

  /**
   * Canonical transaction string, or null when the input cannot be
   * faithfully represented. Fixed field order; known fields always
   * emitted (null when absent); extras merged under sorted keys.
   */
  function canonicalizeTx(tx) {
    try {
      if (!tx || typeof tx !== 'object' || Array.isArray(tx)) return null;
      const fields = [];
      const state = { keys: 0, items: 0 };
      for (const key of TX_ORDER) {
        const present = Object.prototype.hasOwnProperty.call(tx, key) ? tx[key] : null;
        let r;
        if (key === 'accessList') r = encodeAccessList(present);
        else if (TX_QUANTITY_FIELDS.indexOf(key) !== -1) r = encodeQuantityField(present);
        else if (TX_ADDRESS_FIELDS.indexOf(key) !== -1) r = encodeField(present, normalizeAddress);
        else r = encodeField(present, normalizeData);
        if (!r.ok) return null;
        fields.push(`${JSON.stringify(key)}:${r.json}`);
      }
      const extras = Object.keys(tx).filter((k) => !KNOWN_SET[k]).sort();
      for (const k of extras) {
        const v = tx[k];
        if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
        state.keys += 1;
        const r = stableEncode(v, 1, state);
        if (!r.ok) return null;
        fields.push(`${JSON.stringify(k)}:${r.json}`);
      }
      const canonical = `{${fields.join(',')}}`;
      if (canonical.length > MAX_CANONICAL_BYTES) return null;
      return canonical;
    } catch {
      return null;
    }
  }

  /**
   * Deep snapshot with JSON transport semantics (what structured-clone
   * and JSON hops preserve), deeply frozen. Returns null when the input
   * cannot be faithfully snapshotted (circular, over caps).
   */
  function snapshotTx(params) {
    const seen = new Set();
    const state = { keys: 0, items: 0, depth: 0 };
    let failed = false;
    function clone(value, depth) {
      if (value === null) return null;
      const t = typeof value;
      if (t === 'boolean') return value;
      if (t === 'number') return Number.isFinite(value) ? value : null;
      if (t === 'string') return value;
      // Bigint cannot cross the JSON transport hop, so a tx containing
      // one cannot be faithfully bound: fail the whole snapshot.
      if (t === 'bigint') { failed = true; return undefined; }
      if (t === 'undefined' || t === 'function' || t === 'symbol') return undefined;
      if (t !== 'object') return undefined;
      // Circular, too deep, or too large: the snapshot cannot be faithful,
      // so fail the whole snapshot instead of silently dropping structure.
      if (depth > MAX_DEPTH || seen.has(value)) { failed = true; return undefined; }
      seen.add(value);
      if (Array.isArray(value)) {
        if (value.length > MAX_ITEMS) { failed = true; seen.delete(value); return undefined; }
        const out = [];
        for (const item of value) {
          state.items += 1;
          const c = clone(item, depth + 1);
          out.push(c === undefined ? null : c);
        }
        seen.delete(value);
        return out;
      }
      const keys = Object.keys(value);
      if (keys.length > MAX_KEYS) { failed = true; seen.delete(value); return undefined; }
      const out = {};
      for (const k of keys) {
        state.keys += 1;
        const c = clone(value[k], depth + 1);
        if (c !== undefined) out[k] = c;
      }
      seen.delete(value);
      return out;
    }
    function freezeDeep(value) {
      if (!value || typeof value !== 'object' || Object.isFrozen(value)) return;
      Object.freeze(value);
      for (const k of Object.keys(value)) freezeDeep(value[k]);
    }
    try {
      if (!params || typeof params !== 'object' || Array.isArray(params)) return null;
      const out = clone(params, 0);
      if (failed || !out || typeof out !== 'object' || Array.isArray(out)) return null;
      freezeDeep(out);
      return out;
    } catch {
      return null;
    }
  }

  /**
   * SHA-256 hex digest of the canonical transaction, or null when the
   * transaction cannot be faithfully canonicalized or hashed.
   */
  function digestTx(tx) {
    const canonical = canonicalizeTx(tx);
    if (canonical === null) return null;
    const hex = sha256Hex(canonical);
    return typeof hex === 'string' && DIGEST_RE.test(hex) ? hex : null;
  }

  function isValidDigest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
  }

  function digestsEqual(a, b) {
    return isValidDigest(a) && isValidDigest(b) && a === b;
  }

  const api = {
    DIGEST_RE,
    TX_ORDER,
    canonicalizeTx,
    snapshotTx,
    sha256Hex,
    digestTx,
    isValidDigest,
    digestsEqual
  };

  root.AssertaraTxDigest = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})();
