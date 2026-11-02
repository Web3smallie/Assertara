const { isAddress } = require('viem');

/**
 * Swap-recipient risk (exactInputSingle only).
 *
 * Compares the decoded swap `recipient` against the validated transaction
 * sender (`from`). A differing recipient is NOT labeled malicious: pay-to-
 * other flows are legitimate. It is flagged MEDIUM so the discrepancy must
 * be resolved before any confident MATCH, and so the model cannot silently
 * ignore it (the finding is surfaced in the reasoner prompt and bundle).
 *
 * No finding is produced when comparison is impossible: other methods,
 * missing/invalid sender, or missing/invalid recipient. Absence of a
 * finding therefore means "no assessed difference", never "verified same".
 */
function evaluateSwapRecipient(decodedTx) {
  if (!decodedTx || decodedTx.functionName !== 'exactInputSingle') return null;
  const sender = decodedTx.sender;
  const recipient = decodedTx.parameters && decodedTx.parameters.recipient;
  if (typeof sender !== 'string' || !isAddress(sender)) return null;
  if (typeof recipient !== 'string' || !isAddress(recipient)) return null;
  if (sender.toLowerCase() === recipient.toLowerCase()) return null;
  return {
    ruleId: 'SWAP_RECIPIENT_DIFFERS_FROM_SENDER',
    severity: 'MEDIUM',
    description: 'Swap output recipient differs from the transaction sender. Pay-to-other flows can be legitimate, but the recipient must be verified before trusting this transaction.',
    triggered: true,
    metadata: { sender, recipient }
  };
}

module.exports = { evaluateSwapRecipient };
