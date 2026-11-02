/**
 * Agent-service configuration (agent execution system).
 *
 * Separate from src/config/env.js on purpose: agent secrets and mandate
 * wiring must never leak into the browser-evaluation path, and the
 * extension backend must keep working with none of this configured.
 * All values come from process.env; missing secrets disable (never
 * degrade) the endpoints that need them. Values are never logged.
 */

const KEY_ID_RE = /^[A-Za-z0-9._~-]{1,64}$/;

// Agent API keys identify external integrations (rate-limit + audit +
// ownership scope). They NEVER authorize transactions: decisions still
// come only from mandate + policy + signer. Accepted from AGENT_API_KEYS
// (`keyId:secret` CSV) and/or AGENT_API_KEYS_FILE (JSON object
// {keyId: secret}); both sources merge, file wins on duplicate ids.
// Returns { keys: Map|null, error } — invalid entries are dropped with a
// counted error, never partially trusted.
function readAgentApiKeys(env) {
  const e = env || process.env;
  const keys = new Map();
  let dropped = 0;
  const take = (id, secret) => {
    if (typeof id !== 'string' || !KEY_ID_RE.test(id)) { dropped += 1; return; }
    if (typeof secret !== 'string' || secret.length < 16) { dropped += 1; return; }
    keys.set(id, secret);
  };
  const csv = typeof e.AGENT_API_KEYS === 'string' ? e.AGENT_API_KEYS : '';
  for (const entry of csv.split(',').map((s) => s.trim()).filter(Boolean)) {
    const sep = entry.indexOf(':');
    if (sep <= 0) { dropped += 1; continue; }
    take(entry.slice(0, sep), entry.slice(sep + 1));
  }
  const file = typeof e.AGENT_API_KEYS_FILE === 'string' && e.AGENT_API_KEYS_FILE.length > 0
    ? e.AGENT_API_KEYS_FILE : null;
  if (file) {
    try {
      const parsed = JSON.parse(require('fs').readFileSync(file, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        dropped += 1;
      } else {
        for (const [id, secret] of Object.entries(parsed)) take(id, secret);
      }
    } catch {
      dropped += 1;
    }
  }
  return { keys: keys.size > 0 ? keys : null, error: dropped > 0 ? `${dropped} agent API key entr(y/ies) invalid and ignored` : null };
}

function readAgentConfig(env) {
  const e = env || process.env;
  const ttl = Number.parseInt(e.APPROVAL_TTL_MS, 10);
  const reqTtl = Number.parseInt(e.REQUEST_TTL_MS, 10);
  const maxInflight = Number.parseInt(e.MAX_CONCURRENT_INVESTIGATIONS, 10);
  const maxPerKey = Number.parseInt(e.AGENT_MAX_INFLIGHT_PER_KEY, 10);
  const rawAuthorities = typeof e.TRUSTED_MANDATE_AUTHORITIES === 'string' ? e.TRUSTED_MANDATE_AUTHORITIES : '';
  const authorityEntries = rawAuthorities.split(',').map((s) => s.trim()).filter(Boolean);
  const authoritiesValid = authorityEntries.length > 0 && authorityEntries.every((a) => /^0x[0-9a-fA-F]{40}$/.test(a));
  const apiKeys = readAgentApiKeys(e);
  return {
    agentApiKeys: apiKeys.keys,
    agentApiKeysError: apiKeys.error,
    // Explicit development mode ONLY: 'development' opens the agent API
    // without keys (local work, loud warning). Anything else without
    // configured keys disables the agent API (503) instead of serving
    // it openly by accident.
    agentAuthMode: e.AGENT_AUTH_MODE === 'development' ? 'development' : 'production',
    maxConcurrentInvestigations: Number.isSafeInteger(maxInflight)
      ? Math.min(64, Math.max(1, maxInflight)) : 8,
    maxInflightPerKey: Number.isSafeInteger(maxPerKey)
      ? Math.min(16, Math.max(1, maxPerKey)) : 2,
    mandateFile: typeof e.MANDATE_FILE === 'string' && e.MANDATE_FILE.length > 0 ? e.MANDATE_FILE : null,
    mandateAuthorities: authoritiesValid ? authorityEntries.map((a) => a.toLowerCase()) : null,
    approvalSecret: typeof e.APPROVAL_SECRET === 'string' && e.APPROVAL_SECRET.length > 0 ? e.APPROVAL_SECRET : null,
    operatorSecret: typeof e.OPERATOR_SECRET === 'string' && e.OPERATOR_SECRET.length > 0 ? e.OPERATOR_SECRET : null,
    approvalTtlMs: Number.isSafeInteger(ttl) && ttl > 0 ? ttl : 300000,
    requestTtlMs: Number.isSafeInteger(reqTtl) && reqTtl > 0 ? reqTtl : 900000,
    ledgerFile: typeof e.AGENT_LEDGER_FILE === 'string' && e.AGENT_LEDGER_FILE.length > 0
      ? e.AGENT_LEDGER_FILE
      : 'data/agent-ledger.jsonl',
    snapshotFile: typeof e.AGENT_SNAPSHOT_FILE === 'string' && e.AGENT_SNAPSHOT_FILE.length > 0
      ? e.AGENT_SNAPSHOT_FILE
      : 'data/agent-requests.json',
    spendingLedgerFile: typeof e.SPENDING_LEDGER_FILE === 'string' && e.SPENDING_LEDGER_FILE.length > 0
      ? e.SPENDING_LEDGER_FILE
      : 'data/agent-spending.jsonl'
  };
}

module.exports = { readAgentConfig };
