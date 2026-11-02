/**
 * Native-value spending ledger (agent execution system).
 *
 * Counts VERIFIED native transfers (receipt status 1) per chain over
 * rolling windows. Entries persist as JSONL so a restart replays them
 * instead of resetting limits. ERC-20 amounts are deliberately NOT
 * totaled here: allowance value needs token decimals we do not fetch,
 * so approvals are structurally restricted by the mandate instead.
 */

const fs = require('fs');
const path = require('path');

function createSpendingLedger({ filePath } = {}) {
  let entries = []; // { ts, chainId, wei, requestId, txHash }

  function load() {
    entries = [];
    if (!filePath) return { ok: true, loaded: 0 };
    try {
      if (!fs.existsSync(filePath)) return { ok: true, loaded: 0 };
      const lines = fs.readFileSync(filePath, 'utf8').split('\n');
      let corrupt = 0;
      for (const line of lines) {
        const s = line.trim();
        if (!s) continue;
        try {
          const e = JSON.parse(s);
          if (e && Number.isSafeInteger(e.ts) && typeof e.chainId === 'string'
            && typeof e.wei === 'string' && /^[0-9]+$/.test(e.wei)) {
            entries.push({ ts: e.ts, chainId: e.chainId, wei: e.wei, requestId: e.requestId || null, txHash: e.txHash || null });
          } else {
            corrupt += 1;
          }
        } catch {
          corrupt += 1;
        }
      }
      // Any corrupt line fails the whole load: silently skipping entries
      // would undercount spending (fail open on limits). The caller must
      // treat limits as unverifiable until an operator repairs the file.
      if (corrupt > 0) {
        entries = [];
        return { ok: false, error: `spending ledger has ${corrupt} corrupt line(s)` };
      }
      return { ok: true, loaded: entries.length };
    } catch (err) {
      return { ok: false, error: err && err.message ? err.message : String(err) };
    }
  }

  function append(entry) {
    if (!filePath) return;
    try {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.appendFileSync(filePath, `${JSON.stringify(entry)}\n`, 'utf8');
    } catch {
      /* persistence is best-effort; memory still counts this run */
    }
  }

  return {
    load,
    record({ chainId, wei, requestId, txHash, atMs }) {
      // Dedupe: the same verified execution must never be counted twice,
      // even if two receipt paths race to record it.
      if (requestId || txHash) {
        const dup = entries.find((e) => (requestId && e.requestId === requestId) || (txHash && e.txHash === txHash));
        if (dup) return dup;
      }
      const entry = {
        ts: Number.isSafeInteger(atMs) ? atMs : Date.now(),
        chainId: String(chainId),
        wei: BigInt(wei).toString(),
        requestId: requestId || null,
        txHash: txHash || null
      };
      entries.push(entry);
      append(entry);
      return entry;
    },
    spentWithin({ chainId, windowMs, nowMs }) {
      const cutoff = nowMs - windowMs;
      let total = 0n;
      for (const e of entries) {
        if (e.chainId === String(chainId) && e.ts > cutoff && e.ts <= nowMs) total += BigInt(e.wei);
      }
      return total.toString();
    },
    prune({ nowMs, keepMs }) {
      const cutoff = nowMs - keepMs;
      const before = entries.length;
      entries = entries.filter((e) => e.ts > cutoff);
      return before - entries.length;
    },
    count: () => entries.length
  };
}

module.exports = { createSpendingLedger };
