/**
 * OCR Text Extraction Service
 * Runs on cropped visual regions identified by SAM 3.1.
 */

const { createWorker } = require('tesseract.js');
const { cropImageRegion } = require('../utils/imageUtils');

let workerInstance = null;

async function getOcrWorker() {
  if (!workerInstance) {
    try {
      workerInstance = await createWorker('eng');
    } catch (err) {
      console.warn(`[OCR Warning] Tesseract worker initialization failed: ${err.message}`);
    }
  }
  return workerInstance;
}

/**
 * Extracts visible text from a specific cropped region of an image
 * @param {string} screenshotBase64 
 * @param {{x: number, y: number, width: number, height: number}} boundingBox 
 * @returns {Promise<string>}
 */
async function extractTextFromRegion(screenshotBase64, boundingBox) {
  try {
    const croppedBuffer = await cropImageRegion(screenshotBase64, boundingBox);
    const worker = await getOcrWorker();
    
    if (!worker) {
      return '';
    }

    const { data: { text } } = await worker.recognize(croppedBuffer);
    return (text || '').trim();
  } catch (err) {
    console.warn(`[OCR Error] Failed to extract text from region: ${err.message}`);
    return '';
  }
}

/**
 * Extracts text from multiple segmented regions and combines them into an intent document
 * @param {string} screenshotBase64 
 * @param {Array<{label: string, boundingBox: object}>} regions 
 * @returns {Promise<{combinedText: string, regionTexts: Array}>}
 */
async function extractUiTexts(screenshotBase64, regions = []) {
  const regionTexts = [];

  for (const region of regions) {
    const text = await extractTextFromRegion(screenshotBase64, region.boundingBox);
    if (text) {
      regionTexts.push({
        label: region.label,
        boundingBox: region.boundingBox,
        text
      });
    }
  }

  const combinedText = regionTexts.map(r => `[${r.label.toUpperCase()}]: ${r.text}`).join('\n');
  return { combinedText, regionTexts };
}

/**
 * Shuts down the shared Tesseract worker. Intended for scripts and test
 * runners so the node process can exit; never call per-request in production.
 */
async function closeOcrWorker() {
  if (workerInstance) {
    try {
      await workerInstance.terminate();
    } catch {}
    workerInstance = null;
  }
}

module.exports = {
  extractTextFromRegion,
  extractUiTexts,
  closeOcrWorker
};
