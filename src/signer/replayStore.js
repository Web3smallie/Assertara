/**
 * Replay store: durable, tamper-evident approval-consumption ledger.
 *
 * Every consumed approval appends one line carrying a monotonic sequence
 * number and an HMAC chained to the previous line. A separate anchor file
 * records the last trusted (seq, mac) tip. Boot re-verifies the whole
 * chain and reconciles it against the anchor:
 *
 * - log tip == anchor tip              → boot (steady state)
 * - log ahead, anchor tip is a prefix  → adopt log tip, boot (crash
 *   between log append and anchor update; the HMAC-valid log line was
 *   verifiably written by us, so catching up is safe)
 * - anchor ahead of log                → REFUSE (log truncation or loss
 *   would forget consumptions; operator recovery required)
 * - anchor missing, log non-empty      → REFUSE (never silently re-trust
 *   consumptions; operator recovery required)
 * - anchor/log corrupt or MAC-invalid  → REFUSE
 * - both absent/empty                  → initialize fresh anchor, boot
 *
 * Consumption is appended BEFORE broadcast and the anchor is re-stamped
 * synchronously in the same call, so at most one consumes and a crash
 * can burn an approval but never resurrect one.
 *
 * Trust assumptions (honest): the HMAC key is APPROVAL_SECRET, already
 * trusted server-side. This defeats crashes, partial writes, operator
 * error, silent file loss, and any attacker who can corrupt, delete, or
 * restore individual files but cannot forge HMACs. It does NOT defeat an
 * attacker who can arbitrarily rewrite every local file AND knows the
 * secret, nor one who deletes everything and reboots fresh (that is
 * indistinguishable from first boot). Against total local rewrite the
 * remaining mitigations are short approval TTLs, mandate rotation to
 * void old approvals, and the out-of-band recovery rule below.
 *
 * Recovery rule: re-anchor only after confirming no unexpired consumed
 * approval exists (wait out APPROVAL_TTL_MS, or rotate APPROVAL_SECRET
 * and bump the mandate version to void everything), then run the
 * operator recovery CLI (src/signer/recover.js), which verifies the log
 * chain before re-trusting its tip.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const LOG_LINE_RE = /^[^\n]*$/;

function hmacHex(secret, message) {
  return crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');
}

function lineMac(secret, { seq, prevMac, nonce, requestId, txHash }) {
  return hmacHex(secret, `assertara-consumed-v1:${seq}:${prevMac}:${nonce}:${requestId}:${txHash}`);
}

function anchorMac(secret, { tipSeq, tipMac }) {
  return hmacHex(secret, `assertara-replay-anchor-v1:${tipSeq}:${tipMac}`);
}

function atomicWriteJson(filePath, obj) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(`${filePath}.tmp`, JSON.stringify(obj), 'utf8');
  fs.renameSync(`${filePath}.tmp`, filePath);
}

// Parse + verify the full log chain. Returns { entries, tipSeq, tipMac }.
// Throws on any structural violation, MAC failure, or sequence gap.
function readChainedLog(consumedFile, secret) {
  const entries = [];
  if (!consumedFile || !fs.existsSync(consumedFile)) return { entries, tipSeq: 0, tipMac: 'GENESIS' };
  const raw = fs.readFileSync(consumedFile, 'utf8');
  let prevMac = 'GENESIS';
  let seq = 0;
  const seen = new Set();
  for (const line of raw.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    if (!LOG_LINE_RE.test(s)) throw new Error(`consumed log line ${seq + 1} is malformed`);
    let e;
    try {
      e = JSON.parse(s);
    } catch {
      throw new Error(`consumed log line ${seq + 1} is not JSON`);
    }
    seq += 1;
    if (!e || e.seq !== seq || typeof e.nonce !== 'string' || !e.nonce
      || typeof e.mac !== 'string' || !e.mac) {
      throw new Error(`consumed log line ${seq} is malformed or out of sequence (legacy format? see recover --import-legacy)`);
    }
    if (seen.has(e.nonce)) throw new Error(`consumed log repeats nonce at line ${seq}`);
    const expect = lineMac(secret, {
      seq, prevMac, nonce: e.nonce,
      requestId: e.requestId || '', txHash: e.txHash || ''
    });
    let ok = false;
    try {
      ok = crypto.timingSafeEqual(Buffer.from(e.mac, 'hex'), Buffer.from(expect, 'hex'));
    } catch {
      ok = false;
    }
    if (!ok) throw new Error(`consumed log line ${seq} fails integrity check`);
    seen.add(e.nonce);
    entries.push(e);
    prevMac = e.mac;
  }
  return { entries, tipSeq: seq, tipMac: prevMac };
}

function readAnchor(anchorFile, secret) {
  if (!anchorFile || !fs.existsSync(anchorFile)) return null;
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(anchorFile, 'utf8'));
  } catch {
    throw new Error('replay anchor is corrupt (unparseable JSON)');
  }
  if (!parsed || parsed.format !== 'assertara-replay-anchor-1'
    || !Number.isSafeInteger(parsed.tipSeq) || parsed.tipSeq < 0
    || typeof parsed.tipMac !== 'string' || !parsed.tipMac
    || typeof parsed.mac !== 'string' || !parsed.mac) {
    throw new Error('replay anchor is corrupt or unrecognized');
  }
  const expect = anchorMac(secret, { tipSeq: parsed.tipSeq, tipMac: parsed.tipMac });
  let ok = false;
  try {
    ok = crypto.timingSafeEqual(Buffer.from(parsed.mac, 'hex'), Buffer.from(expect, 'hex'));
  } catch {
    ok = false;
  }
  if (!ok) throw new Error('replay anchor fails integrity check');
  return parsed;
}

function writeAnchor(anchorFile, secret, { tipSeq, tipMac, mandateId, mandateVersion }) {
  atomicWriteJson(anchorFile, {
    format: 'assertara-replay-anchor-1',
    tipSeq, tipMac,
    mandateId: mandateId || null,
    mandateVersion: Number.isSafeInteger(mandateVersion) ? mandateVersion : null,
    updatedAt: Date.now(),
    mac: anchorMac(secret, { tipSeq, tipMac })
  });
}

/**
 * Open (or initialize) the replay store. Throws when continuity cannot be
 * established — the caller must refuse signing.
 */
function openReplayStore({ approvalSecret, consumedFile, anchorFile, mandate }) {
  if (!approvalSecret || typeof approvalSecret !== 'string' || approvalSecret.length < 16) {
    throw new Error('replay store requires APPROVAL_SECRET of at least 16 characters');
  }
  const anchor = anchorFile || (consumedFile ? `${consumedFile.replace(/\.jsonl$/, '')}-replay-anchor.json` : null);

  // Memory-only mode (no consumed file): no durability claim.
  if (!consumedFile) {
    const mem = new Set();
    return {
      mode: 'memory',
      has: (nonce) => mem.has(nonce),
      size: () => mem.size,
      tip: () => ({ tipSeq: mem.size, tipMac: null }),
      consume: ({ nonce, requestId, txHash }) => {
        if (!nonce || typeof nonce !== 'string') throw new Error('cannot record approval consumption: nonce missing');
        mem.add(nonce);
      }
    };
  }

  let log;
  try {
    log = readChainedLog(consumedFile, approvalSecret);
  } catch (err) {
    throw new Error(`signer refusing to start: ${err.message}`);
  }
  let anchored;
  try {
    anchored = readAnchor(anchor, approvalSecret);
  } catch (err) {
    throw new Error(`signer refusing to start: ${err.message}`);
  }

  const consumed = new Set(log.entries.map((e) => e.nonce));

  if (!anchored && log.tipSeq === 0) {
    writeAnchor(anchor, approvalSecret, {
      tipSeq: 0, tipMac: 'GENESIS',
      mandateId: mandate && mandate.id, mandateVersion: mandate && mandate.version
    });
  } else if (!anchored && log.tipSeq > 0) {
    throw new Error(`signer refusing to start: replay anchor is missing while ${log.tipSeq} consumption(s) exist; operator recovery required (never auto re-trusting)`);
  } else if (anchored.tipSeq > log.tipSeq) {
    throw new Error(`signer refusing to start: replay log is behind its anchor (log tip ${log.tipSeq}, anchor tip ${anchored.tipSeq}); consumption records were lost or truncated — operator recovery required`);
  } else if (log.tipSeq > anchored.tipSeq) {
    // Crash between log append and anchor update: adopt only if the
    // anchor tip is a verified prefix of the log.
    const prefix = log.tipSeq === 0 ? 'GENESIS'
      : (log.entries[anchored.tipSeq - 1] ? log.entries[anchored.tipSeq - 1].mac : null);
    const prefixSeqOk = anchored.tipSeq === 0 ? anchored.tipMac === 'GENESIS' : prefix === anchored.tipMac;
    if (!prefixSeqOk) {
      throw new Error('signer refusing to start: replay log diverged from its anchor; operator recovery required');
    }
    writeAnchor(anchor, approvalSecret, {
      tipSeq: log.tipSeq, tipMac: log.tipMac,
      mandateId: mandate && mandate.id, mandateVersion: mandate && mandate.version
    });
  } else if (anchored.tipMac !== log.tipMac) {
    throw new Error('signer refusing to start: replay log tip does not match its anchor; operator recovery required');
  }

  return {
    mode: 'durable',
    anchorFile: anchor,
    has: (nonce) => consumed.has(nonce),
    size: () => consumed.size,
    tip: () => {
      const current = readAnchor(anchor, approvalSecret);
      return { tipSeq: current.tipSeq, tipMac: current.tipMac };
    },
    consume: ({ nonce, requestId, txHash }) => {
      if (!nonce || typeof nonce !== 'string') throw new Error('cannot record approval consumption: nonce missing');
      // Re-read the tip under the caller's lock so concurrent processes
      // cannot fork the sequence (single signer process owns the file;
      // this is defense in depth, not a distributed lock).
      const fresh = readChainedLog(consumedFile, approvalSecret);
      const seq = fresh.tipSeq + 1;
      const mac = lineMac(approvalSecret, {
        seq, prevMac: fresh.tipMac, nonce,
        requestId: requestId || '', txHash: txHash || ''
      });
      const line = { seq, nonce, requestId: requestId || null, txHash: txHash || null, at: Date.now(), mac };
      try {
        fs.mkdirSync(path.dirname(consumedFile), { recursive: true });
        fs.appendFileSync(consumedFile, `${JSON.stringify(line)}\n`, 'utf8');
        writeAnchor(anchor, approvalSecret, {
          tipSeq: seq, tipMac: mac,
          mandateId: mandate && mandate.id, mandateVersion: mandate && mandate.version
        });
      } catch (err) {
        throw new Error(`cannot record approval consumption: ${err.message}`);
      }
      consumed.add(nonce);
      return { seq, mac };
    }
  };
}

module.exports = { openReplayStore, readChainedLog, readAnchor, writeAnchor, lineMac, anchorMac };
