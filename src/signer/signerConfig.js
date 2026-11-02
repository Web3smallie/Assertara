/**
 * Signer process configuration. Read ONLY by the signer process: the
 * signing key must never be visible to the policy service, agents, or
 * models. All values from process.env; the server refuses to start
 * without the mandatory ones.
 */

function parseAuthorityList(value) {
  if (typeof value !== 'string' || value.trim().length === 0) return { ok: false, error: 'not configured' };
  const entries = value.split(',').map((s) => s.trim()).filter(Boolean);
  if (entries.length === 0) return { ok: false, error: 'not configured' };
  for (const a of entries) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(a)) return { ok: false, error: `invalid authority address: ${a.slice(0, 18)}` };
  }
  return { ok: true, authorities: entries.map((a) => a.toLowerCase()) };
}

function readSignerConfig(env) {
  const e = env || process.env;
  const port = Number.parseInt(e.SIGNER_PORT, 10);
  const authorities = parseAuthorityList(e.SIGNER_TRUSTED_MANDATE_AUTHORITIES);
  return {
    port: Number.isSafeInteger(port) && port > 0 ? port : 3002,
    mandateAuthorities: authorities.ok ? authorities.authorities : null,
    mandateAuthoritiesError: authorities.ok ? null : authorities.error,
    approvalSecret: typeof e.APPROVAL_SECRET === 'string' && e.APPROVAL_SECRET.length > 0 ? e.APPROVAL_SECRET : null,
    operatorSecret: typeof e.OPERATOR_SECRET === 'string' && e.OPERATOR_SECRET.length > 0 ? e.OPERATOR_SECRET : null,
    mandateFile: typeof e.MANDATE_FILE === 'string' && e.MANDATE_FILE.length > 0 ? e.MANDATE_FILE : null,
    privateKey: typeof e.SIGNER_PRIVATE_KEY === 'string' && e.SIGNER_PRIVATE_KEY.length > 0 ? e.SIGNER_PRIVATE_KEY : null,
    consumedFile: typeof e.SIGNER_CONSUMED_FILE === 'string' && e.SIGNER_CONSUMED_FILE.length > 0
      ? e.SIGNER_CONSUMED_FILE
      : 'data/signer-consumed.jsonl',
    stateFile: typeof e.SIGNER_STATE_FILE === 'string' && e.SIGNER_STATE_FILE.length > 0
      ? e.SIGNER_STATE_FILE
      : null,
    anchorFile: typeof e.SIGNER_ANCHOR_FILE === 'string' && e.SIGNER_ANCHOR_FILE.length > 0
      ? e.SIGNER_ANCHOR_FILE
      : null,
    policyCallbackUrl: typeof e.POLICY_CALLBACK_URL === 'string' && e.POLICY_CALLBACK_URL.length > 0
      ? e.POLICY_CALLBACK_URL
      : null
  };
}

module.exports = { readSignerConfig, parseAuthorityList };
