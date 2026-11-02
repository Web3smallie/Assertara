/**
 * Signer replay-recovery CLI (operator tool, not agent-facing).
 *
 * When the signer refuses startup over replay continuity (missing anchor,
 * anchor/log mismatch, truncation), signing stays refused until an
 * operator verifies out-of-band that no unexpired consumed approval
 * exists — wait out APPROVAL_TTL_MS, or rotate APPROVAL_SECRET and bump
 * the mandate version to void everything — and then runs:
 *
 *   APPROVAL_SECRET=... OPERATOR_SECRET=... node src/signer/recover.js --reanchor --confirm
 *
 *   --status                  read-only continuity report (needs APPROVAL_SECRET)
 *   --reanchor --confirm      verify the log chain, re-anchor to its tip (needs both secrets)
 *   --import-legacy --confirm migrate a pre-chain nonce log to chained format (needs both secrets)
 *
 * Paths from SIGNER_CONSUMED_FILE / SIGNER_ANCHOR_FILE (same defaults as
 * the signer). Every mutation appends to recovery-audit.jsonl next to the
 * anchor; a failed audit write aborts the recovery. Secrets travel only
 * in env vars and are never printed.
 */

const fs = require('fs');
const path = require('path');
const { readChainedLog, readAnchor, writeAnchor, lineMac } = require('./replayStore');
const { safeEqualSecret } = require('../services/approvals');

function resolveAnchor(consumedFile, anchorFile) {
  if (anchorFile) return anchorFile;
  if (!consumedFile) throw new Error('no consumed log configured; nothing to recover');
  return `${consumedFile.replace(/\.jsonl$/, '')}-replay-anchor.json`;
}

function audit(anchorFile, entry) {
  const file = path.join(path.dirname(anchorFile), 'recovery-audit.jsonl');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${JSON.stringify({ at: Date.now(), ...entry })}\n`, 'utf8');
}

function checkOperator(presented, expected) {
  if (!expected) throw new Error('OPERATOR_SECRET is not configured; recovery requires operator presence');
  if (!safeEqualSecret(presented || '', expected)) throw new Error('operator authentication failed');
}

function getStatus({ approvalSecret, consumedFile, anchorFile }) {
  const anchor = anchorFile || (consumedFile ? `${consumedFile.replace(/\.jsonl$/, '')}-replay-anchor.json` : null);
  const report = { consumedFile: consumedFile || null, anchorFile: anchor, log: null, anchorState: null, verdict: 'REFUSED', reason: '' };
  try {
    const log = readChainedLog(consumedFile, approvalSecret);
    report.log = { tipSeq: log.tipSeq, tipMac: log.tipMac.slice(0, 16), entries: log.entries.length };
  } catch (err) {
    report.log = { error: err.message };
    report.reason = `log unverifiable: ${err.message}`;
    return report;
  }
  try {
    const a = readAnchor(anchor, approvalSecret);
    report.anchorState = a ? { tipSeq: a.tipSeq, tipMac: String(a.tipMac).slice(0, 16) } : null;
  } catch (err) {
    report.anchorState = { error: err.message };
    report.reason = `anchor unverifiable: ${err.message}`;
    return report;
  }
  const { tipSeq } = report.log;
  const anchored = report.anchorState;
  if (!anchored && tipSeq === 0) {
    report.verdict = 'BOOTABLE';
    report.reason = 'fresh state: no consumptions, no anchor';
  } else if (!anchored) {
    report.reason = `anchor missing with ${tipSeq} consumption(s): re-anchor only after voiding unexpired approvals`;
  } else if (anchored.tipSeq > tipSeq) {
    report.reason = `log behind anchor (log ${tipSeq}, anchor ${anchored.tipSeq}): consumption records lost — restore the log or rotate credentials, never re-anchor down`;
  } else {
    report.verdict = 'BOOTABLE';
    report.reason = tipSeq === anchored.tipSeq ? 'log matches anchor' : 'log ahead of anchor: crash catch-up will apply at boot';
  }
  return report;
}

function reanchor({ approvalSecret, operatorSecret, expectedOperatorSecret, consumedFile, anchorFile, mandate }) {
  checkOperator(operatorSecret, expectedOperatorSecret);
  const anchor = resolveAnchor(consumedFile, anchorFile);
  const log = readChainedLog(consumedFile, approvalSecret); // throws unless the full chain verifies
  const anchored = readAnchor(anchor, approvalSecret); // throws unless valid or absent
  if (anchored && anchored.tipSeq > log.tipSeq) {
    throw new Error(`refusing to re-anchor down (anchor ${anchored.tipSeq} > log ${log.tipSeq}): consumption records are missing; restore the log or rotate credentials`);
  }
  writeAnchor(anchor, approvalSecret, {
    tipSeq: log.tipSeq, tipMac: log.tipMac,
    mandateId: mandate && mandate.id, mandateVersion: mandate && mandate.version
  });
  audit(anchor, { action: 'reanchor', tipSeq: log.tipSeq, tipMac: log.tipMac });
  return { tipSeq: log.tipSeq, tipMac: log.tipMac };
}

// One-way migration for pre-chain logs ({nonce, requestId, ...} lines with
// no seq/mac). Adopting extra consumptions only ever refuses (fail-closed
// direction); it cannot resurrect anything. Deletions from the legacy log
// are undetectable by construction — migrate only a log you trust to be
// complete, or rotate credentials instead.
function importLegacy({ approvalSecret, operatorSecret, expectedOperatorSecret, consumedFile, anchorFile, mandate }) {
  checkOperator(operatorSecret, expectedOperatorSecret);
  if (!consumedFile || !fs.existsSync(consumedFile)) throw new Error('no legacy log to import');
  const anchor = resolveAnchor(consumedFile, anchorFile);
  const nonces = [];
  const seen = new Set();
  for (const line of fs.readFileSync(consumedFile, 'utf8').split('\n')) {
    const s = line.trim();
    if (!s) continue;
    let e;
    try {
      e = JSON.parse(s);
    } catch {
      throw new Error('legacy log contains an unparseable line; refusing import');
    }
    if (e.seq !== undefined || e.mac !== undefined) throw new Error('log is already in chained format; import not needed');
    if (!e || typeof e.nonce !== 'string' || !e.nonce || seen.has(e.nonce)) {
      throw new Error('legacy log contains an invalid or duplicate nonce; refusing import');
    }
    seen.add(e.nonce);
    nonces.push({ nonce: e.nonce, requestId: e.requestId || null, txHash: e.txHash || null, at: e.at || Date.now() });
  }
  fs.copyFileSync(consumedFile, `${consumedFile}.bak`);
  let prevMac = 'GENESIS';
  const out = nonces.map((n, i) => {
    const seq = i + 1;
    const mac = lineMac(approvalSecret, { seq, prevMac, nonce: n.nonce, requestId: n.requestId || '', txHash: n.txHash || '' });
    prevMac = mac;
    return { seq, nonce: n.nonce, requestId: n.requestId, txHash: n.txHash, at: n.at, mac };
  });
  fs.writeFileSync(consumedFile, out.map((l) => JSON.stringify(l)).join('\n') + (out.length ? '\n' : ''), 'utf8');
  const tipMac = out.length ? out[out.length - 1].mac : 'GENESIS';
  writeAnchor(anchor, approvalSecret, {
    tipSeq: out.length, tipMac,
    mandateId: mandate && mandate.id, mandateVersion: mandate && mandate.version
  });
  audit(anchor, { action: 'import-legacy', tipSeq: out.length, tipMac });
  return { imported: out.length, tipSeq: out.length, tipMac };
}

function printUsage() {
  console.log('Usage:');
  console.log('  node src/signer/recover.js --status');
  console.log('  OPERATOR_SECRET=... node src/signer/recover.js --reanchor --confirm');
  console.log('  OPERATOR_SECRET=... node src/signer/recover.js --import-legacy --confirm');
  console.log('Env: APPROVAL_SECRET (always), OPERATOR_SECRET (mutations),');
  console.log('     SIGNER_CONSUMED_FILE, SIGNER_ANCHOR_FILE, MANDATE_FILE (optional, for stamping).');
}

if (require.main === module) {
  const args = new Set(process.argv.slice(2));
  const { readSignerConfig } = require('./signerConfig');
  const cfg = readSignerConfig(process.env);
  const approvalSecret = cfg.approvalSecret;
  if (!approvalSecret) {
    console.error('APPROVAL_SECRET is not configured.');
    process.exit(1);
  }
  let mandate = null;
  if (cfg.mandateFile) {
    try {
      const { loadMandate } = require('../services/mandate');
      const loaded = loadMandate(cfg.mandateFile);
      if (loaded.ok) mandate = loaded.mandate;
    } catch { /* stamping is informational; recovery does not depend on it */ }
  }
  const base = { approvalSecret, consumedFile: cfg.consumedFile, anchorFile: cfg.anchorFile, mandate };
  try {
    if (args.has('--status')) {
      console.log(JSON.stringify(getStatus(base), null, 2));
    } else if (args.has('--reanchor') && args.has('--confirm')) {
      const out = reanchor({ ...base, operatorSecret: process.env.OPERATOR_SECRET, expectedOperatorSecret: cfg.operatorSecret });
      console.log(JSON.stringify({ reanchored: true, ...out }));
    } else if (args.has('--import-legacy') && args.has('--confirm')) {
      const out = importLegacy({ ...base, operatorSecret: process.env.OPERATOR_SECRET, expectedOperatorSecret: cfg.operatorSecret });
      console.log(JSON.stringify({ imported: true, ...out }));
    } else {
      printUsage();
      process.exit(2);
    }
  } catch (err) {
    console.error(`recovery failed: ${err.message}`);
    process.exit(1);
  }
}

module.exports = { getStatus, reanchor, importLegacy };
