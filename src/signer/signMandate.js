/**
 * Mandate sealing CLI (operator ceremony, not agent-facing).
 *
 * Embeds a cryptographic seal in a mandate file so the policy service
 * and the signer can verify authorship instead of trusting file
 * provenance:
 *
 *   OPERATOR_SIGNING_KEY=0x... node src/signer/signMandate.js <mandateFile>
 *
 * The file is structurally validated first, then sealed over its exact
 * normalized bytes; the previous version is preserved as <file>.bak.
 * Re-running after any permission change produces a fresh seal (old
 * seals never transfer: any byte change breaks verification).
 *
 * The operator key travels only in OPERATOR_SIGNING_KEY and is never
 * printed, logged, or written. The matching authority address must be
 * configured out-of-band as TRUSTED_MANDATE_AUTHORITIES (policy) and
 * SIGNER_TRUSTED_MANDATE_AUTHORITIES (signer).
 */

const fs = require('fs');
const { loadMandate, sealMandateObject } = require('../services/mandate');

async function sealMandateFile(filePath, operatorPrivateKey) {
  if (!filePath || typeof filePath !== 'string') throw new Error('mandate file path is required');
  const loaded = loadMandate(filePath);
  if (!loaded.ok) throw new Error(loaded.error);
  const seal = await sealMandateObject(loaded.mandate, operatorPrivateKey);
  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  raw.seal = seal;
  fs.copyFileSync(filePath, `${filePath}.bak`);
  fs.writeFileSync(filePath, `${JSON.stringify(raw, null, 2)}\n`, 'utf8');
  return { authority: seal.authority, backup: `${filePath}.bak` };
}

if (require.main === module) {
  const file = process.argv[2];
  if (!file || process.argv.includes('--help') || process.argv.includes('-h')) {
    console.log('Usage: OPERATOR_SIGNING_KEY=0x... node src/signer/signMandate.js <mandateFile>');
    process.exit(file ? 0 : 2);
  }
  sealMandateFile(file, process.env.OPERATOR_SIGNING_KEY).then((out) => {
    console.log(JSON.stringify({ sealed: true, authority: out.authority, backup: out.backup }));
  }).catch((err) => {
    console.error(`seal failed: ${err.message}`);
    process.exit(1);
  });
}

module.exports = { sealMandateFile };
