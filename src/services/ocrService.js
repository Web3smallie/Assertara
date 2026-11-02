/**
 * OCR Text Extraction Service
 * Runs on cropped visual regions identified by SAM 3.1.
 *
 * Phase 2 contract: every region keeps its identity (regionId, label,
 * geometry, genuine/synthetic status) and its OCR outcome. Failures are
 * recorded as `ocrError` on the region — never collapsed into a silent
 * empty string. A successful read of blank pixels yields text '' with
 * empty:true and ocrError:null, which is distinct from a failure.
 */

const { createWorker } = require('tesseract.js');
const { cropImageRegion, prepareOcrCrop } = require('../utils/imageUtils');

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
 * Extracts visible text from a specific cropped region of an image.
 * THROWS a coded error on crop/OCR failure (callers record per-region
 * errors and continue). Success returns trimmed text, possibly ''.
 * @param {string} screenshotBase64
 * @param {{x: number, y: number, width: number, height: number}} boundingBox
 * @param {{recognize?: (buffer: Buffer) => Promise<{data:{text:string}}>}} deps
 *   Optional injected recognizer (tests); defaults to the shared worker.
 * @returns {Promise<string>}
 */
async function extractTextFromRegion(screenshotBase64, boundingBox, deps = {}) {
  const croppedBuffer = await cropImageRegion(screenshotBase64, boundingBox);
  const ocrInput = await prepareOcrCrop(croppedBuffer);
  const recognize = deps.recognize
    || (async (buffer) => {
      const worker = await getOcrWorker();
      if (!worker) {
        const err = new Error('OCR worker unavailable');
        err.code = 'OCR_WORKER_UNAVAILABLE';
        throw err;
      }
      return worker.recognize(buffer);
    });
  let out;
  try {
    out = await recognize(ocrInput);
  } catch (err) {
    const wrapped = new Error(`OCR recognition failed: ${String(err && err.message || err).slice(0, 300)}`);
    wrapped.code = (err && err.code) || 'OCR_FAILED';
    throw wrapped;
  }
  return ((out && out.data && out.data.text) || '').trim();
}

/**
 * Extracts text from segmented regions, preserving per-region identity and
 * failures. One region's failure never blocks the remaining regions.
 * @param {string} screenshotBase64
 * @param {Array<{regionId?, label, boundingBox, genuine?, synthetic?, confidence?, prompts?}>} regions
 * @param {{recognize?: Function}} deps Optional injected recognizer (tests).
 * @returns {Promise<{combinedText: string, regionTexts: Array}>}
 *   regionTexts entries: { regionId, label, boundingBox, genuine, synthetic,
 *   confidence, prompts, text|null, empty, ocrError|null }.
 */
async function extractUiTexts(screenshotBase64, regions = [], deps = {}) {
  const regionTexts = [];

  for (const region of regions || []) {
    const record = {
      regionId: region.regionId || null,
      label: region.label,
      boundingBox: region.boundingBox,
      genuine: region.genuine !== false,
      synthetic: region.synthetic === true,
      confidence: region.confidence === undefined ? null : region.confidence,
      prompts: region.prompts || undefined,
      text: null,
      empty: false,
      ocrError: null
    };
    try {
      const text = await extractTextFromRegion(screenshotBase64, region.boundingBox, deps);
      record.text = text;
      record.empty = text.length === 0;
    } catch (err) {
      record.ocrError = {
        code: (err && err.code) || 'OCR_FAILED',
        message: String(err && err.message || err).slice(0, 300)
      };
    }
    regionTexts.push(record);
  }

  const withText = regionTexts.filter((r) => r.text);
  const combinedText = withText.map((r) => `[${String(r.label).toUpperCase()}]: ${r.text}`).join('\n');
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
