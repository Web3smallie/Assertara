const { KNOWN_ROUTERS, matchKnownEntry } = require('../utils/abiSignatures');

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

  // Capability 4 B5: router allowlist is chain-scoped. Without chain
  // context the legacy unscoped match applies; with it, a mainnet
  // router address on another chain is unverified.
  const isKnownRouter = Boolean(matchKnownEntry(KNOWN_ROUTERS, spender, decodedTx.chainId));
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
