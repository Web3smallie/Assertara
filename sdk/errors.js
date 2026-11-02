/**
 * Assertara SDK typed errors (agent-agnostic, zero dependencies).
 *
 * Every SDK failure surfaces as an AssertaraError with a stable `code`
 * so agents can branch on meaning, not message text. Server HTTP
 * statuses map 1:1; decision guards and integrity failures have their
 * own codes that never overlap with transport errors.
 */

class AssertaraError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'AssertaraError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

const CODES = {
  VALIDATION: 'VALIDATION', // 400: caller-shaped request rejected
  AUTH: 'AUTH', // 401/403: missing/invalid key, operator auth, signer refusal
  NOT_FOUND: 'NOT_FOUND', // 404: unknown id (also foreign-owner reads)
  CONFLICT: 'CONFLICT', // 409: key reuse, running investigation, state conflict
  EXPIRED: 'EXPIRED', // 410 or locally detected approval/request expiry
  RATE_LIMITED: 'RATE_LIMITED', // 429: capacity exhausted
  UPSTREAM: 'UPSTREAM', // 502: chain RPC / signer chain errors
  UNAVAILABLE: 'UNAVAILABLE', // 503: service unconfigured / store down
  TIMEOUT: 'TIMEOUT', // client-side timeout waiting on the network or a wait
  NOT_EXECUTABLE: 'NOT_EXECUTABLE', // decision guard: BLOCK/UNCERTAIN/REVIEW-pending
  DIGEST_MISMATCH: 'DIGEST_MISMATCH', // local bytes differ from the investigated digest
  SERVER: 'SERVER' // 500 or unrecognized failure
};

function fromHttp(status, body, fallback) {
  const message = (body && typeof body.error === 'string' && body.error)
    || fallback || `Request failed with status ${status}.`;
  const detail = body && typeof body === 'object' ? { ...body } : undefined;
  if (detail && typeof detail.error === 'string') delete detail.error;
  switch (status) {
    case 400: return new AssertaraError(CODES.VALIDATION, message, detail);
    case 401:
    case 403: return new AssertaraError(CODES.AUTH, message, detail);
    case 404: return new AssertaraError(CODES.NOT_FOUND, message, detail);
    case 409: return new AssertaraError(CODES.CONFLICT, message, detail);
    case 410: return new AssertaraError(CODES.EXPIRED, message, detail);
    case 429: return new AssertaraError(CODES.RATE_LIMITED, message, detail);
    case 502: return new AssertaraError(CODES.UPSTREAM, message, detail);
    case 503: return new AssertaraError(CODES.UNAVAILABLE, message, detail);
    default: return new AssertaraError(CODES.SERVER, message, detail);
  }
}

function timeout(message) {
  return new AssertaraError(CODES.TIMEOUT, message || 'Timed out waiting for Assertara.');
}

function notExecutable(decision, reasons) {
  const why = Array.isArray(reasons) && reasons.length > 0 ? `: ${reasons.slice(0, 3).join('; ')}` : '.';
  return new AssertaraError(
    CODES.NOT_EXECUTABLE,
    `Decision ${decision || 'unknown'} does not authorize execution${why}`,
    { decision: decision || null, reasons: Array.isArray(reasons) ? reasons : [] }
  );
}

function digestMismatch() {
  return new AssertaraError(
    CODES.DIGEST_MISMATCH,
    'Local transaction bytes differ from the investigated digest; refusing to execute.'
  );
}

module.exports = { AssertaraError, CODES, fromHttp, timeout, notExecutable, digestMismatch };
