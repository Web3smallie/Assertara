const sharp = require('sharp');

/**
 * Strips data URI prefix (e.g. "data:image/png;base64,") and returns raw Buffer
 */
function base64ToBuffer(base64String) {
  const cleanBase64 = base64String.replace(/^data:image\/\w+;base64,/, '');
  return Buffer.from(cleanBase64, 'base64');
}

/**
 * Converts Buffer back to base64 Data URI
 */
function bufferToBase64(buffer, mimeType = 'image/png') {
  return `data:${mimeType};base64,${buffer.toString('base64')}`;
}

/**
 * Crops a bounding region from an image buffer or base64 string
 * @param {string|Buffer} imageInput 
 * @param {{x: number, y: number, width: number, height: number}} box 
 * @returns {Promise<Buffer>}
 */
async function cropImageRegion(imageInput, box) {
  const buffer = Buffer.isBuffer(imageInput) ? imageInput : base64ToBuffer(imageInput);
  
  // Ensure bounding box coordinates are non-negative integers
  const left = Math.max(0, Math.round(box.x || 0));
  const top = Math.max(0, Math.round(box.y || 0));
  const width = Math.max(1, Math.round(box.width || 100));
  const height = Math.max(1, Math.round(box.height || 100));

  const metadata = await sharp(buffer).metadata();
  
  // Clamp width and height to image boundaries
  const validWidth = Math.min(width, (metadata.width || width) - left);
  const validHeight = Math.min(height, (metadata.height || height) - top);

  if (validWidth <= 0 || validHeight <= 0) {
    return buffer; // Return original if crop is invalid
  }

  return await sharp(buffer)
    .extract({ left, top, width: validWidth, height: validHeight })
    .toBuffer();
}

module.exports = {
  base64ToBuffer,
  bufferToBase64,
  cropImageRegion
};
