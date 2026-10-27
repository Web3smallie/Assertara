function evaluatePermit2Drain(decodedTx) {
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
