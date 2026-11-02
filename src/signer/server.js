/**
 * Controlled signer process (agent execution system).
 *
 * Runs as its own OS process with its own secret set. Exposes exactly:
 *   GET  /health — liveness + public identity (address, chains, mandate)
 *   POST /sign   — verify approval + exact payload, sign, broadcast, receipt
 * Nothing here ever returns, logs, or transmits the signing key.
 *
 * Required env: APPROVAL_SECRET, MANDATE_FILE, SIGNER_PRIVATE_KEY.
 * OPERATOR_SECRET is required only to honor operator-authorized
 * approvals (without it, requiresOperator approvals are refused).
 */

const express = require('express');
const cors = require('cors');
const { readSignerConfig } = require('./signerConfig');
const { loadMandate } = require('../services/mandate');
const { createSigner } = require('./signerService');

async function buildSignerApp(deps) {
  const cfg = (deps && deps.config) || readSignerConfig(process.env);
  if (!cfg.approvalSecret) throw new Error('signer refusing to start: APPROVAL_SECRET is not configured');
  if (!cfg.mandateFile) throw new Error('signer refusing to start: MANDATE_FILE is not configured');
  if (!cfg.privateKey) throw new Error('signer refusing to start: SIGNER_PRIVATE_KEY is not configured');
  if (!cfg.mandateAuthorities) throw new Error(`signer refusing to start: SIGNER_TRUSTED_MANDATE_AUTHORITIES ${cfg.mandateAuthoritiesError || 'is not configured'}`);
  const loaded = loadMandate(cfg.mandateFile);
  if (!loaded.ok) throw new Error(`signer refusing to start: ${loaded.error}`);

  // Continuity state lives next to the consumed-nonce log unless placed
  // explicitly, so test and production signer instances stay isolated.
  const stateFile = (deps && deps.stateFile !== undefined) ? deps.stateFile
    : cfg.stateFile || `${cfg.consumedFile.replace(/\.jsonl$/, '')}-state.json`;
  const signer = await createSigner({
    approvalSecret: cfg.approvalSecret,
    operatorSecret: cfg.operatorSecret,
    mandate: loaded.mandate,
    mandateAuthorities: cfg.mandateAuthorities,
    privateKey: cfg.privateKey,
    consumedFile: (deps && deps.consumedFile !== undefined) ? deps.consumedFile : cfg.consumedFile,
    anchorFile: (deps && deps.anchorFile !== undefined) ? deps.anchorFile : cfg.anchorFile,
    stateFile,
    policyCallbackUrl: (deps && deps.policyCallbackUrl !== undefined) ? deps.policyCallbackUrl : cfg.policyCallbackUrl,
    clients: deps && deps.clients ? deps.clients : undefined
  });

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  app.get('/health', (req, res) => {
    res.json({
      ok: true, service: 'Assertara controlled signer', version: '1.0.0',
      address: signer.address,
      mandateId: signer.mandateId,
      mandateVersion: signer.mandateVersion,
      sealAuthority: signer.sealAuthority,
      chainIds: signer.chainIds,
      operatorVerification: Boolean(cfg.operatorSecret),
      consumedApprovals: signer.consumedCount()
    });
  });

  app.post('/sign', async (req, res) => {
    try {
      const { requestId, transaction, approval } = (req.body && typeof req.body === 'object') ? req.body : {};
      const out = await signer.execute({ requestId, transaction, approval });
      if (!out.ok) {
        const status = out.code === 'BAD_REQUEST' ? 400 : out.code === 'CHAIN_ERROR' ? 502 : 403;
        return res.status(status).json({ ok: false, error: out.error });
      }
      return res.status(200).json({ ok: true, txHash: out.txHash, receipt: out.receipt || null, verification: out.verification || null });
    } catch (err) {
      return res.status(500).json({ ok: false, error: `Signer failure: ${err && err.message ? err.message : String(err)}` });
    }
  });

  return { app, signer, config: cfg };
}

if (require.main === module) {
  buildSignerApp().then((built) => {
    built.app.listen(built.config.port, () => {
      console.log(`Assertara controlled signer on :${built.config.port} (address ${built.signer.address}, mandate ${built.signer.mandateId} v${built.signer.mandateVersion})`);
    });
  }).catch((err) => {
    console.error(`[Signer] ${err.message}`);
    process.exit(1);
  });
}

module.exports = { buildSignerApp };
