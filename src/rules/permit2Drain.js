function evaluatePermit2Drain(decodedTx) {
  // Capability 4 B6: scoped to the Permit2 standard. EIP-2612 `permit`
  // shares the function name but is a different protocol — bare-name
  // matching would misattribute it.
  if (decodedTx.standard !== 'Permit2') return null;
  if (decodedTx.functionName === 'permit' || decodedTx.functionName === 'permitTransferFrom') {
    return {
      ruleId: 'PERMIT2_OFFCHAIN_APPROVAL',
      severity: 'HIGH',
      description: 'Transaction executes or verifies a Permit2 off-chain signature that can authorize batch token drains without individual on-chain approvals.',
      triggered: true
    };
  }

  return null;
}

module.exports = { evaluatePermit2Drain };
