const { KNOWN_ROUTERS } = require('../utils/abiSignatures');

function evaluateUnverifiedSpender(decodedTx) {
  const spender = (decodedTx.parameters?.spender || decodedTx.parameters?.operator || '').toLowerCase();
  if (!spender) return null;

  if (spender === '0x0000000000000000000000000000000000000000') {
    return {
      ruleId: 'ZERO_ADDRESS_SPENDER',
      severity: 'CRITICAL',
      description: 'Transaction attempts to grant approval to the zero address (0x0).',
      triggered: true
    };
  }

  const isKnownRouter = Boolean(KNOWN_ROUTERS[spender]);
  if (!isKnownRouter) {
    return {
      ruleId: 'UNVERIFIED_SPENDER',
      severity: 'MEDIUM',
      description: `Spender address (${spender}) is not a verified canonical DEX router or protocol contract.`,
      triggered: true,
      metadata: { spender }
    };
  }

  return null;
}

module.exports = { evaluateUnverifiedSpender };
