/**
 * Evidence Bundle Compiler & Serializer
 */

const crypto = require('crypto');

const MANDATORY_SAFETY_NOTICE = 'A MATCH verdict indicates visual alignment with transaction calldata, NOT that the target contract or protocol is secure or bug-free.';

function compileEvidenceBundle({
  visualResult,
  decodedTx,
  reasoningResult,
  simulationResult,
  pageContext = {},
  screenshotProvided = false
}) {
  const evalId = `eval_${crypto.randomBytes(4).toString('hex')}`;
  const timestamp = new Date().toISOString();

  const primaryRegion = visualResult?.regions?.[0] || {
    boundingBox: { x: 0, y: 0, width: 800, height: 600 }
  };

  const ocrText = visualResult.combinedText || '';
  const domText = pageContext.visibleText || '';

  return {
    id: evalId,
    timestamp,
    verdict: reasoningResult.verdict || 'UNCERTAIN',
    confidence: reasoningResult.confidence || 0.5,
    summary: reasoningResult.summary || 'Transaction analysis complete.',
    recommendedAction: reasoningResult.recommendedAction || null,
    safetyNotice: MANDATORY_SAFETY_NOTICE,
    pageEvidence: {
      title: pageContext.title || null,
      url: pageContext.url || null
    },
    visualEvidence: {
      boundingBox: primaryRegion.boundingBox,
      extractedText: ocrText || 'No text extracted',
      actionElement: visualResult.regions?.find(r => r.label.includes('button'))?.label || 'Action Button',
      textSources: [
        { source: 'OCR_TEXT', available: Boolean(screenshotProvided), text: ocrText },
        { source: 'DOM_TEXT', available: domText.length > 0, text: domText }
      ]
    },
    decodedTransaction: {
      contract: decodedTx.contract,
      contractName: decodedTx.contractName,
      functionName: decodedTx.functionName,
      parameters: decodedTx.parameters,
      isUnlimitedApproval: decodedTx.isUnlimitedApproval
    },
    ruleFindings: decodedTx.ruleFindings || [],
    simulation: simulationResult || {
      status: 'NOT_RUN',
      executed: false,
      success: false,
      reason: 'No simulation required for low-risk verdict.'
    }
  };
}

module.exports = { compileEvidenceBundle, MANDATORY_SAFETY_NOTICE };
