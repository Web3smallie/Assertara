const { INFINITE_THRESHOLD, MAX_UINT256 } = require('../utils/abiSignatures');

function evaluateInfiniteApproval(decodedTx) {
  if (decodedTx.functionName === 'approve' || decodedTx.functionName === 'increaseAllowance') {
    const amount = decodedTx.parameters?.amount;
    if (typeof amount === 'bigint' && amount >= INFINITE_THRESHOLD) {
      return {
        ruleId: 'INFINITE_APPROVAL',
        severity: 'HIGH',
        description: 'Transaction approves maximum/unconstrained token allowance (uint256.max), exposing the entire token balance to the spender.',
        triggered: true,
        metadata: {
          amountFormatted: 'UNLIMITED (2^256 - 1)',
          isMaxUint: amount === MAX_UINT256
        }
      };
    }
  }

  if (decodedTx.functionName === 'setApprovalForAll') {
    const approved = decodedTx.parameters?.approved;
    if (approved === true) {
      return {
        ruleId: 'NFT_SET_APPROVAL_FOR_ALL',
        severity: 'HIGH',
        description: 'Transaction grants the operator unrestricted permission to transfer ALL NFTs in this collection belonging to the account.',
        triggered: true
      };
    }
  }

  return null;
}

module.exports = { evaluateInfiniteApproval };
