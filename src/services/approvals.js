/**
 * Approval tokens (agent execution system).
 *
 * An approval is a capability the policy service issues and the signer
 * verifies. Format: `apv1.<base64url-json>.<hex-hmac-sha256>`, where the
 * HMAC key is APPROVAL_SECRET (server-side only, never given to agents).
 * Verification is constant-time on the MAC. Tokens bind: request id,
 * exact transaction digest, chain, sender, decision, mandate id+version,
 * policy id, operator requirement, expiry, and a single-use nonce.
 *
 * Operator authorization for REVIEW decisions is a second HMAC
 * (OPERATOR_SECRET over `operator-approval:<nonce>`), verified by the
 * signer when the approval requires it. The operator never sees the
 * approval secret and the agent never sees either secret.
 */

const crypto = require('crypto');

const TOKEN_PREFIX = 'apv1';

function b64uEncode(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function b64uDecode(s) {
  return JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
}

function hmacHex(secret, message) {
  return crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');
}

function safeEqualHex(a, b) {
  try {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const ab = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ab.length !== bb.length || ab.length === 0) return false;
    return crypto.timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}

function safeEqualSecret(a, b) {
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

/**
 * Issue an approval token. Only decision ALLOW tokens authorize signing;
 * requiresOperator marks tokens that additionally need countersigning.
 */
function issueApproval({ secret, requestId, txDigest, chainId, sender, mandateId, mandateVersion, policyId, requiresOperator, ttlMs, nowMs, nonce, subcallTreeHash }) {
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new Error('approval secret must be a non-empty string of at least 16 characters');
  }
  const now = Number.isSafeInteger(nowMs) ? nowMs : Date.now();
  const ttl = Number.isSafeInteger(ttlMs) && ttlMs > 0 ? ttlMs : 300000;
  const body = {
    v: 1,
    requestId,
    txDigest,
    chainId,
    sender: typeof sender === 'string' ? sender.toLowerCase() : sender,
    decision: 'ALLOW',
    mandateId,
    mandateVersion,
    policyId,
    requiresOperator: Boolean(requiresOperator),
    operatorSig: null,
    // Capability 5 B1: canonical hash of the authorized subcall tree.
    // HMAC-covered like every other field; the signer recomputes it
    // from the presented transaction and refuses on mismatch, so any
    // mutation between mandate evaluation and signing is detected at
    // inner-operation granularity.
    subcallTreeHash: typeof subcallTreeHash === 'string' ? subcallTreeHash : null,
    issuedAt: now,
    expiresAt: now + ttl,
    nonce: nonce || crypto.randomBytes(16).toString('hex')
  };
  const encoded = b64uEncode(body);
  return `${TOKEN_PREFIX}.${encoded}.${hmacHex(secret, `${TOKEN_PREFIX}.${encoded}`)}`;
}

/**
 * Verify structure, MAC, expiry, and decision. Returns
 * { ok:true, payload } or { ok:false, error }. Single-use and mandate
 * freshness are enforced by the caller (signer), not here.
 */
function verifyApproval({ secret, token, nowMs }) {
  if (!secret || typeof secret !== 'string' || secret.length === 0) return { ok: false, error: 'approval secret not configured' };
  if (typeof token !== 'string') return { ok: false, error: 'approval token must be a string' };
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX || !parts[1] || !parts[2]) {
    return { ok: false, error: 'malformed approval token' };
  }
  if (!safeEqualHex(parts[2], hmacHex(secret, `${parts[0]}.${parts[1]}`))) {
    return { ok: false, error: 'approval signature invalid' };
  }
  let body;
  try {
    body = b64uDecode(parts[1]);
  } catch {
    return { ok: false, error: 'approval payload undecodable' };
  }
  const now = Number.isSafeInteger(nowMs) ? nowMs : Date.now();
  if (!body || body.v !== 1) return { ok: false, error: 'unsupported approval version' };
  if (body.decision !== 'ALLOW') return { ok: false, error: 'approval does not authorize execution' };
  if (!Number.isSafeInteger(body.issuedAt) || !Number.isSafeInteger(body.expiresAt)) {
    return { ok: false, error: 'approval has invalid timestamps' };
  }
  if (body.issuedAt > now) return { ok: false, error: 'approval issued in the future' };
  if (body.expiresAt <= now) return { ok: false, error: 'approval expired' };
  if (typeof body.requestId !== 'string' || !body.requestId) return { ok: false, error: 'approval missing request id' };
  if (typeof body.txDigest !== 'string' || !body.txDigest) return { ok: false, error: 'approval missing transaction digest' };
  if (typeof body.nonce !== 'string' || !body.nonce) return { ok: false, error: 'approval missing nonce' };
  return { ok: true, payload: body };
}

function operatorSignature({ operatorSecret, nonce }) {
  if (!operatorSecret || typeof operatorSecret !== 'string' || operatorSecret.length === 0) {
    throw new Error('operator secret not configured');
  }
  return hmacHex(operatorSecret, `operator-approval:${nonce}`);
}

/**
 * Attach an operator countersignature to a pending approval that
 * requires it. Returns a NEW token (the unsigned one stays invalid
 * for signing); the approval HMAC is recomputed by the issuer.
 */
function countersignApproval({ secret, token, operatorSecret, nowMs }) {
  const verified = verifyApproval({ secret, token, nowMs });
  if (!verified.ok) return verified;
  if (!verified.payload.requiresOperator) return { ok: false, error: 'approval does not require operator authorization' };
  let sig;
  try {
    sig = operatorSignature({ operatorSecret, nonce: verified.payload.nonce });
  } catch (err) {
    return { ok: false, error: err.message };
  }
  const body = { ...verified.payload, operatorSig: sig };
  const encoded = b64uEncode(body);
  return { ok: true, token: `${TOKEN_PREFIX}.${encoded}.${hmacHex(secret, `${TOKEN_PREFIX}.${encoded}`)}`, payload: body };
}

function verifyOperatorSignature({ operatorSecret, nonce, signature }) {
  if (!operatorSecret || typeof operatorSecret !== 'string' || operatorSecret.length === 0) return false;
  if (typeof signature !== 'string' || !signature) return false;
  return safeEqualHex(signature, hmacHex(operatorSecret, `operator-approval:${nonce}`));
}

module.exports = {
  TOKEN_PREFIX,
  issueApproval,
  verifyApproval,
  countersignApproval,
  operatorSignature,
  verifyOperatorSignature,
  safeEqualHex,
  safeEqualSecret
};
