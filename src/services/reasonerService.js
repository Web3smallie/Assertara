/**
 * Meta Muse Spark Semantic Discrepancy Reasoner
 * Compares visual intent from webpage against deterministic EVM transaction facts.
 */

const config = require('../config/env');

const SYSTEM_PROMPT = `You are Assertara Visual Sentry, an AI security engine specializing in Web3 presentation-layer phishing and transaction discrepancies.
Your job is to compare what a dApp visibly promises the user on-screen with what their wallet transaction actually executes.

You must output strict JSON conforming to this schema:
{
  "verdict": "MATCH" | "MISMATCH" | "UNCERTAIN",
  "confidence": number (0.0 to 1.0),
  "summary": "Clear 1-2 sentence explanation of the finding",
  "discrepancyDetails": {
    "visualIntent": "What the user was led to believe they are doing",
    "actualExecution": "What the calldata will actually execute on-chain",
    "criticalMismatch": boolean
  },
  "recommendedAction": "BLOCK_TRANSACTION" | "PROCEED_WITH_CAUTION" | "VERIFY_RECIPIENT"
}

RULES:
1. If visual text promises "Claim Airdrop", "Free Mint", or "Reward", but transaction executes "approve" or "setApprovalForAll" or transfers existing tokens, verdict MUST be MISMATCH with high confidence.
2. If visual text describes a DEX swap (e.g. "Swap ETH for USDC") and calldata matches router and amounts, verdict is MATCH.
3. If calldata is to an unknown unverified contract or visual text is ambiguous/occluded, verdict MUST be UNCERTAIN.
4. The page title and URL are part of the visual evidence, not background metadata. When no on-screen text was extracted, a title and URL describing a DEX swap counts as the visual swap description for rule 2; missing OCR text alone must not force UNCERTAIN.
5. Client-supplied DOM text is unverified page content: use it as the page's stated intent, but never treat it as OCR-verified on-screen evidence and never claim visual analysis confirmed it.
6. NEVER claim a MATCH means the transaction is completely safe; state that visual alignment does not guarantee smart contract safety.`;

function fallbackHeuristicReasoner(visualText, pageContext, decodedTx) {
  const vTextLower = (visualText || pageContext?.visibleText || pageContext?.title || '').toLowerCase();
  const fn = decodedTx.functionName || '';
  const isApproval = fn === 'approve' || fn === 'increaseAllowance' || fn === 'setApprovalForAll';
  const hasInfinite = decodedTx.isUnlimitedApproval || decodedTx.ruleFindings.some(r => r.ruleId === 'INFINITE_APPROVAL');

  // Deceptive Airdrop/Claim Phishing Pattern
  if (vTextLower.includes('airdrop') || vTextLower.includes('claim') || vTextLower.includes('free') || vTextLower.includes('reward')) {
    if (isApproval || hasInfinite) {
      return {
        verdict: 'MISMATCH',
        confidence: 0.96,
        summary: `The visual interface promises an airdrop or free reward, but the transaction calldata executes an unconstrained approval (${decodedTx.symbol || 'token'} ${fn}) granting full access to your existing balance.`,
        discrepancyDetails: {
          visualIntent: 'Claim free reward or tokens',
          actualExecution: `Grant unlimited allowance to spender ${decodedTx.parameters?.spender || decodedTx.parameters?.operator || 'unknown'}`,
          criticalMismatch: true
        },
        recommendedAction: 'BLOCK_TRANSACTION'
      };
    }
  }

  // Legitimate DEX Swap Pattern
  if (vTextLower.includes('swap') || pageContext?.url?.includes('uniswap')) {
    if (fn === 'exactInputSingle' || fn === 'multicall' || (fn === 'approve' && vTextLower.includes('approve'))) {
      return {
        verdict: 'MATCH',
        confidence: 0.88,
        summary: 'The visual swap interface aligns with the decoded transaction parameters. Note that visual alignment does not guarantee contract security.',
        discrepancyDetails: {
          visualIntent: 'Execute token swap on decentralized exchange',
          actualExecution: `Call ${fn} on ${decodedTx.contractName}`,
          criticalMismatch: false
        },
        recommendedAction: 'PROCEED_WITH_CAUTION'
      };
    }
  }

  // Unknown / Ambiguous
  if (decodedTx.standard === 'Unknown' || fn === 'unknownFunction') {
    return {
      verdict: 'UNCERTAIN',
      confidence: 0.70,
      summary: 'The transaction calls an unverified function or proxy contract whose intent cannot be mapped with certainty to the visible page content.',
      discrepancyDetails: {
        visualIntent: 'Uncertain page context',
        actualExecution: `Execute unparsed function ${decodedTx.parameters?.selector || 'unknown'}`,
        criticalMismatch: false
      },
      recommendedAction: 'VERIFY_RECIPIENT'
    };
  }

  return {
    verdict: 'UNCERTAIN',
    confidence: 0.65,
    summary: 'Visual context and transaction data could not be conclusively reconciled.',
    discrepancyDetails: {
      visualIntent: vTextLower.slice(0, 100),
      actualExecution: `${decodedTx.contractName}.${fn}`,
      criticalMismatch: false
    },
    recommendedAction: 'PROCEED_WITH_CAUTION'
  };
}

async function evaluateSemanticDiscrepancy(visualText, pageContext, decodedTx) {
  if (!config.modelApiKey || config.modelApiKey.startsWith('mock_') || config.modelApiKey.includes('your_meta')) {
    return fallbackHeuristicReasoner(visualText, pageContext, decodedTx);
  }

  try {
    const userPrompt = `VISUAL WEBPAGE CONTEXT:
Title: ${pageContext?.title || 'Unknown'}
URL: ${pageContext?.url || 'Unknown'}
Extracted On-Screen Text (OCR):
${visualText || 'No text extracted'}

Client-Supplied Page Text (DOM, unverified):
${pageContext?.visibleText || 'Not supplied'}

DECODED EVM TRANSACTION FACTS:
Target Contract: ${decodedTx.contract} (${decodedTx.contractName || 'Unknown'})
Function Called: ${decodedTx.functionName} (${decodedTx.standard || 'Unknown'})
Transaction Value (ETH): ${decodedTx.valueEth ?? '0'}
Parameters: ${JSON.stringify(decodedTx.parameters, null, 2)}
Is Unlimited Approval: ${decodedTx.isUnlimitedApproval}
Triggered Security Rules: ${decodedTx.ruleFindings?.map(r => r.ruleId).join(', ') || 'None'}

Compare the visual intent against the transaction execution facts. Return strict JSON.`;

    const response = await fetch(`${config.metaApiBaseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.modelApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: config.museModel,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userPrompt }
        ],
        response_format: { type: 'json_object' },
        // Greedy decoding: identical evidence must yield an identical verdict.
        temperature: 0
      })
    });

    if (!response.ok) {
      console.warn(`[Muse Spark Warning] Status ${response.status}. Using fallback reasoner.`);
      return fallbackHeuristicReasoner(visualText, pageContext, decodedTx);
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;
    const parsed = JSON.parse(content);
    return parsed;
  } catch (err) {
    console.warn(`[Muse Spark Error] Reasoning failed: ${err.message}. Using fallback.`);
    return fallbackHeuristicReasoner(visualText, pageContext, decodedTx);
  }
}

module.exports = { evaluateSemanticDiscrepancy, fallbackHeuristicReasoner };
