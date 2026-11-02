const { INFINITE_THRESHOLD, MAX_UINT256 } = require('../utils/abiSignatures');

function evaluateInfiniteApproval(decodedTx) {
  if (decodedTx.functionName === 'approve' || decodedTx.functionName === 'increaseAllowance') {
    const amount = decodedTx.parameters?.amount;
    if (typeof amount === 'bigint' && amount >= INFINITE_THRESHOLD) {
      // Ambiguous standard (approve on an unidentified contract): the
      // max-value argument could be an unlimited ERC-20 allowance or an
      // ERC-721 token id. Alert honestly without asserting either standard.
      // (increaseAllowance never collides, so this arm only fires for approve.)
      if (decodedTx.standardAmbiguous === true) {
        return {
          ruleId: 'AMBIGUOUS_APPROVAL_SCOPE',
          severity: 'MEDIUM',
          description: 'Approve with a max-value argument on an unidentified contract: could be an unlimited ERC-20 allowance or an ERC-721 approval. Standard cannot be determined from calldata alone.',
          triggered: true,
          metadata: {
            amountFormatted: 'MAX-VALUE ARGUMENT (unidentified standard)',
            standardCandidates: Array.isArray(decodedTx.standardCandidates) && decodedTx.standardCandidates.length > 0
              ? [...decodedTx.standardCandidates]
              : ['ERC20', 'ERC721']
          }
        };
      }
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
