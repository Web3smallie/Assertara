/**
 * Agent API authentication (SDK/API milestone).
 *
 * Agent API keys identify external integrations for rate-limiting, audit,
 * and ownership scoping. They NEVER authorize transactions: investigation
 * decisions still come only from mandate + policy + signer, and the
 * operator secret / approval HMAC paths are untouched by this module.
 *
 * Mode rule (fail closed):
 * - Keys configured (AGENT_API_KEYS / AGENT_API_KEYS_FILE) -> production
 *   enforcement: every agent/observations request needs a valid Bearer key.
 * - Else AGENT_AUTH_MODE=development -> open access with a loud boot
 *   warning (local work, demos, test harnesses).
 * - Else -> the agent API is disabled (503) instead of being served
 *   openly by accident.
 *
 * On success attaches req.agentKey = { keyId: string|null, development }.
 * Direct controller callers (unit tests) pass no req.agentKey and are
 * treated as legacy/dev: ownership checks allow, isolation documented
 * as an HTTP-layer property.
 */

const crypto = require('crypto');

function safeEqual(a, b) {
  try {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length === 0 || b.length === 0) return false;
    const ab = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

// Resolve the effective mode once at boot. Returns
// { enforced: bool, disabled: bool, keys: Map|null }.
function resolveAuthMode(agentConfig) {
  const keys = agentConfig && agentConfig.agentApiKeys instanceof Map && agentConfig.agentApiKeys.size > 0
    ? agentConfig.agentApiKeys : null;
  if (keys) return { enforced: true, disabled: false, keys };
  if (agentConfig && agentConfig.agentAuthMode === 'development') {
    return { enforced: false, disabled: false, keys: null };
  }
  return { enforced: false, disabled: true, keys: null };
}

function bearerKeyId(req, keys) {
  const header = req && req.headers && typeof req.headers.authorization === 'string'
    ? req.headers.authorization : '';
  const m = /^Bearer (.+)$/.exec(header.trim());
  if (!m) return null;
  const presented = m[1];
  // keyId lookup is non-secret; only the secret comparison is
  // constant-time. Format: "<keyId>:<secret>" inside the Bearer token
  // so one header carries both without a second field.
  const sep = presented.indexOf(':');
  if (sep <= 0) return null;
  const id = presented.slice(0, sep);
  const secret = presented.slice(sep + 1);
  const expected = keys.get(id);
  if (typeof expected !== 'string') return null;
  return safeEqual(secret, expected) ? id : null;
}

// Express middleware factory. failClosedMessage names the endpoint group.
function requireAgentKey(agentConfig, { scope } = {}) {
  const mode = resolveAuthMode(agentConfig);
  if (mode.disabled) {
    return (req, res, next) => res.status(503).json({
      error: `Agent API unavailable: production authentication is not configured${scope ? ` (${scope})` : ''}. ` +
        'Set AGENT_API_KEYS (production) or AGENT_AUTH_MODE=development (local work only).'
    });
  }
  if (!mode.enforced) {
    return (req, res, next) => {
      req.agentKey = { keyId: null, development: true };
      return next();
    };
  }
  const keys = mode.keys;
  return (req, res, next) => {
    const id = bearerKeyId(req, keys);
    if (!id) {
      return res.status(401).json({ error: 'Agent authentication required: valid Bearer <keyId>:<secret>.' });
    }
    req.agentKey = { keyId: id, development: false };
    return next();
  };
}

// Ownership helpers shared by controllers and observation routes.
// allowOwner returns true when req may access a record/trace owned by
// ownerKeyId (null owner = pre-isolation/dev record: visible in dev
// contexts only, never to a foreign production key).
function requestKey(req) {
  if (req && req.agentKey && typeof req.agentKey === 'object') return req.agentKey;
  return { keyId: null, development: true };
}

function allowOwner(req, ownerKeyId) {
  const k = requestKey(req);
  if (k.development) return true;
  if (typeof ownerKeyId !== 'string' || !ownerKeyId) return false;
  return ownerKeyId === k.keyId;
}

module.exports = { resolveAuthMode, requireAgentKey, requestKey, allowOwner, safeEqual };
