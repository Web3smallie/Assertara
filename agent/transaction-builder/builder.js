/**
 * Transaction builder: validated plan action -> exact submission bytes.
 *
 * Assembles the canonical transaction object the agent intends to
 * execute. Normalization and validation of chain semantics happen in
 * the SDK's guarded path (the authority); this module only stamps
 * the agent's sender/chain defaults and previews the shared digest
 * for reporting. It never signs, never broadcasts, never authorizes.
 */

const { digestTx } = require('../../extension/shared/txDigest');

function buildTransaction(action, { from, chainId } = {}) {
  if (!action || typeof action !== 'object') throw new Error('buildTransaction requires a validated action.');
  if (!from) throw new Error('buildTransaction requires the agent sending address.');
  if (chainId === undefined || chainId === null) throw new Error('buildTransaction requires a chain id.');
  const tx = {
    from,
    to: action.to,
    value: action.value,
    data: action.data === undefined || action.data === null || action.data === '' ? '0x' : action.data,
    chainId
  };
  let preview = null;
  try {
    preview = digestTx(tx);
  } catch {
    preview = null;
  }
  return { transaction: tx, digestPreview: preview };
}

module.exports = { buildTransaction };
