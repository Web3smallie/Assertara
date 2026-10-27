/**
 * Visual Sentry Evaluation Controller
 * Orchestrates SAM 3.1 perception, OCR, EVM calldata decoding, Muse Spark reasoning, and Anvil simulation.
 */

const { segmentUiRegions } = require('../services/samService');
const { extractUiTexts } = require('../services/ocrService');
const { decodeTransactionCalldata } = require('../services/decoderService');
const { evaluateSemanticDiscrepancy } = require('../services/reasonerService');
const { simulateTransactionWithFoundry } = require('../services/simulatorService');
const { compileEvidenceBundle } = require('../services/evidenceService');

const MAX_CLIENT_TEXT_CHARS = 8000;
const PAGE_CONTEXT_FIELDS = ['title', 'url', 'visibleText'];

/**
 * Merge the canonical `pageContext` object with the legacy/client-facing
 * `page` object into one internal representation. `pageContext` wins on
 * overlapping fields; valid fields present only in `page` are preserved.
 * Empty strings are treated as absent. Throws on malformed context.
 */
function normalizePageContext(pageContext, page) {
  for (const [name, obj] of [['pageContext', pageContext], ['page', page]]) {
    if (obj === undefined || obj === null) continue;
    if (typeof obj !== 'object' || Array.isArray(obj)) {
      throw new Error(`${name} must be an object with optional title, url, visibleText.`);
    }
  }
  const merged = {};
  for (const source of [page, pageContext]) {
    if (!source) continue;
    for (const key of PAGE_CONTEXT_FIELDS) {
      const value = source[key];
      if (value === undefined || value === null) continue;
      if (typeof value !== 'string') {
        throw new Error(`page context field "${key}" must be a string.`);
      }
      const trimmed = value.trim();
      if (!trimmed) continue;
      merged[key] = key === 'visibleText' ? trimmed.slice(0, MAX_CLIENT_TEXT_CHARS) : trimmed;
    }
  }
  return merged;
}

async function handleEvaluateTransaction(req, res) {
  try {
    const { screenshot, pageContext, page, transaction } = req.body || {};

    if (!transaction || !transaction.to) {
      return res.status(400).json({
        error: 'Invalid request: transaction object with "to" address is required.'
      });
    }

    let normalizedPageContext;
    try {
      normalizedPageContext = normalizePageContext(pageContext, page);
    } catch (err) {
      return res.status(400).json({
        error: `Invalid request: ${err.message}`
      });
    }

    // Step 1: Deterministic EVM calldata decoding
    const decodedTx = decodeTransactionCalldata({
      to: transaction.to,
      data: transaction.data || '0x',
      value: transaction.value || '0x0'
    });

    // Step 2: Meta SAM 3.1 Region Segmentation (if screenshot provided)
    let visualResult = { regions: [], combinedText: '' };
    if (screenshot) {
      const samResult = await segmentUiRegions(screenshot);
      const regions = samResult.regions || [];

      // Step 3: OCR on segmented regions
      const ocrResult = await extractUiTexts(screenshot, regions);
      visualResult = {
        regions,
        combinedText: ocrResult.combinedText,
        regionTexts: ocrResult.regionTexts
      };
    }

    // Step 4: Meta Muse Spark Semantic Discrepancy Reasoning
    const reasoningResult = await evaluateSemanticDiscrepancy(
      visualResult.combinedText,
      normalizedPageContext,
      decodedTx
    );

    // Step 5: Foundry / Anvil simulation for suspicious / mismatch transactions
    let simulationResult = null;
    const shouldSimulate = reasoningResult.verdict === 'MISMATCH' || 
                           decodedTx.isUnlimitedApproval ||
                           decodedTx.ruleFindings.some(r => r.severity === 'HIGH' || r.severity === 'CRITICAL');

    if (shouldSimulate) {
      simulationResult = await simulateTransactionWithFoundry({
        from: transaction.from,
        to: transaction.to,
        data: transaction.data,
        decodedTx
      });
    }

    // Step 6: Evidence compilation
    const evidenceBundle = compileEvidenceBundle({
      visualResult,
      decodedTx,
      reasoningResult,
      simulationResult,
      pageContext: normalizedPageContext,
      screenshotProvided: Boolean(screenshot)
    });

    return res.status(200).json(evidenceBundle);
  } catch (err) {
    console.error('[Evaluation Error]', err);
    return res.status(500).json({
      error: 'Internal evaluation error',
      message: err.message,
      verdict: 'UNCERTAIN',
      summary: 'Evaluation failed due to an internal server error. Proceed with extreme caution.'
    });
  }
}

module.exports = { handleEvaluateTransaction, normalizePageContext };
