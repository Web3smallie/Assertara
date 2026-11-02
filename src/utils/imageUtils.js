const sharp = require('sharp');
const crypto = require('crypto');

function imageError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

/**
 * Strips data URI prefix (e.g. "data:image/png;base64,") and returns raw Buffer.
 * Non-string input throws a coded BAD_IMAGE error (never a raw TypeError) so
 * callers record a diagnosable failure: screenshotMeta converts it to an
 * honest { error } object and per-region OCR records it as ocrError.
 */
function base64ToBuffer(base64String) {
  if (typeof base64String !== 'string') {
    throw imageError('BAD_IMAGE', `screenshot input must be a base64 string or Buffer, got ${base64String === null ? 'null' : Array.isArray(base64String) ? 'array' : typeof base64String}`);
  }
  const cleanBase64 = base64String.replace(/^data:image\/\w+;base64,/, '');
  return Buffer.from(cleanBase64, 'base64');
}

/**
 * Source-image identity for evidence provenance: sha256 + pixel dimensions.
 * Never throws: failures return { error: { code, message } } so callers can
 * record them with machine-readable provenance (same shape as per-region
 * ocrError records). Upstream codes (e.g. BAD_IMAGE from base64ToBuffer)
 * are preserved, never flattened into an undiagnosable string.
 */
async function screenshotMeta(imageInput) {
  try {
    const buffer = Buffer.isBuffer(imageInput) ? imageInput : base64ToBuffer(imageInput);
    const meta = await sharp(buffer).metadata();
    if (!Number.isInteger(meta.width) || !Number.isInteger(meta.height)) {
      return { error: { code: 'UNREADABLE_DIMENSIONS', message: 'source image dimensions are unreadable' } };
    }
    return {
      sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
      width: meta.width,
      height: meta.height
    };
  } catch (err) {
    return {
      error: {
        code: (err && err.code) || 'IMAGE_META_FAILED',
        message: `metadata-failed: ${String(err && err.message || err).slice(0, 200)}`
      }
    };
  }
}

/**
 * Crops a bounding region from an image buffer or base64 string.
 * Phase 2: invalid boxes THROW a coded CropError and are never silently
 * replaced with the full screenshot. Partial overlap is still clamped.
 * @param {string|Buffer} imageInput
 * @param {{x: number, y: number, width: number, height: number}} box
 * @returns {Promise<Buffer>}
 */
async function cropImageRegion(imageInput, box) {
  if (!box || typeof box !== 'object') {
    throw imageError('BAD_BOX', 'crop box must be an object with x, y, width, height');
  }
  for (const k of ['x', 'y', 'width', 'height']) {
    if (!Number.isFinite(box[k])) {
      throw imageError('BAD_BOX', `crop box field "${k}" must be a finite number`);
    }
  }
  if (box.x < 0 || box.y < 0) {
    throw imageError('BAD_BOX', `crop origin must be non-negative (got x=${box.x}, y=${box.y})`);
  }
  if (box.width <= 0 || box.height <= 0) {
    throw imageError('BAD_BOX', `crop dimensions must be positive (got ${box.width}x${box.height})`);
  }
  const buffer = Buffer.isBuffer(imageInput) ? imageInput : base64ToBuffer(imageInput);

  const left = Math.round(box.x);
  const top = Math.round(box.y);
  const width = Math.round(box.width);
  const height = Math.round(box.height);

  const metadata = await sharp(buffer).metadata();
  const imgW = metadata.width;
  const imgH = metadata.height;
  if (!Number.isInteger(imgW) || !Number.isInteger(imgH)) {
    throw imageError('BAD_IMAGE', 'source image dimensions are unreadable');
  }
  if (left >= imgW || top >= imgH) {
    throw imageError('BOX_OUT_OF_BOUNDS', `crop origin (${left},${top}) lies outside ${imgW}x${imgH}`);
  }

  // Clamp width and height to image boundaries
  const validWidth = Math.min(width, imgW - left);
  const validHeight = Math.min(height, imgH - top);

  if (validWidth <= 0 || validHeight <= 0) {
    throw imageError('BOX_OUT_OF_BOUNDS', `crop ${width}x${height} at (${left},${top}) has zero intersection with ${imgW}x${imgH}`);
  }

  return await sharp(buffer)
    .extract({ left, top, width: validWidth, height: validHeight })
    .toBuffer();
}

/**
 * OCR crop preparation: short crops are upscaled (lanczos) toward ~120px
 * height (at most 4x) and grayscaled before recognition. Measured on the
 * repo's swap fixture with the production Tesseract engine: a 56x29 pill
 * misread as "usb" becomes exact "USDC", and a noisy 378x48 button crop
 * becomes exact "Swap", with no regression on already-correct crops.
 * Tall crops pass through byte-identical (unmeasured there; existing
 * behavior preserved). Deterministic: pure function of input dimensions.
 * @param {Buffer} cropBuffer Raw bytes of the extracted region.
 * @returns {Promise<Buffer>} PNG ready for recognition.
 */
const OCR_TARGET_HEIGHT = 120;
const OCR_MAX_UPSCALE = 4;

async function prepareOcrCrop(cropBuffer) {
  const meta = await sharp(cropBuffer).metadata();
  const height = meta && meta.height;
  const factor = Number.isInteger(height) && height > 0
    ? Math.min(OCR_MAX_UPSCALE, Math.ceil(OCR_TARGET_HEIGHT / height))
    : 1;
  if (factor <= 1) return cropBuffer;
  return sharp(cropBuffer)
    .resize({ height: height * factor, kernel: 'lanczos3' })
    .grayscale()
    .png()
    .toBuffer();
}

module.exports = {
  base64ToBuffer,
  cropImageRegion,
  prepareOcrCrop,
  screenshotMeta
};
