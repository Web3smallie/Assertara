/**
 * Visual-confidence assessment (Phase 5C extension).
 *
 * Pure helper deciding whether a MATCH verdict's confidence must be capped
 * for lack of genuine visual text evidence. Never counts synthetic fallback
 * OCR as genuine. States, in evaluation order:
 *   1. No screenshot supplied -> no cap (title/URL/tx MATCH contract).
 *   2. Zero genuine detections -> ZERO_GENUINE_DETECTIONS (original 5C cap).
 *   3. Genuine regions exist but none yielded non-empty OCR text ->
 *      ZERO_USABLE_OCR_TEXT, with the reason distinguishing all-failed
 *      from empty/no-usable-text outcomes (neither implies deception).
 *   4. At least one genuine region with non-empty OCR text -> no cap.
 */

const ZERO_VISUAL_CAP = 0.65;

/**
 * @param {{screenshotProvided: boolean, detectedCount: number,
 *   regionTexts: Array, fallbackReason: string|null}} visual
 * @returns {{capped: boolean, trigger: string|null, detail: string|null,
 *   reason: string|null}} `detail` is the short clause reused by the
 *   summary disclosure; `reason` is the full evidence-bundle record text.
 */
function assessVisualConfidenceCap({ screenshotProvided, detectedCount, regionTexts, fallbackReason }) {
  const none = { capped: false, trigger: null, detail: null, reason: null };
  if (!screenshotProvided) return none;

  if ((detectedCount || 0) === 0) {
    const detail = fallbackReason === 'error'
      ? 'visual segmentation failed'
      : fallbackReason === 'partial-error'
        ? 'visual segmentation partially failed'
        : fallbackReason === 'incomplete'
          ? 'visual segmentation response incomplete'
          : 'no genuine visual regions detected';
    return {
      capped: true,
      trigger: 'ZERO_GENUINE_DETECTIONS',
      detail,
      reason: `Screenshot supplied but ${detail}; MATCH confidence capped at ${ZERO_VISUAL_CAP}.`
    };
  }

  // Genuine-only by construction upstream; filter defensively so a
  // mislabeled or synthetic record can never satisfy the text requirement.
  const genuine = (regionTexts || []).filter((r) => r && r.genuine !== false && r.synthetic !== true);
  const usable = genuine.filter((r) => !r.ocrError && typeof r.text === 'string' && r.text.length > 0);
  if (usable.length > 0) return none;

  const failed = genuine.filter((r) => r.ocrError).length;
  const empty = genuine.filter((r) => !r.ocrError && (typeof r.text !== 'string' || r.text.length === 0)).length;
  const detail = failed > 0 && empty === 0
    ? `every genuine region OCR attempt failed (${genuine.length} region(s))`
    : `no genuine region yielded usable OCR text (${genuine.length} region(s): ${failed} failed, ${empty} empty)`;
  return {
    capped: true,
    trigger: 'ZERO_USABLE_OCR_TEXT',
    detail,
    reason: `Screenshot supplied but ${detail}; MATCH confidence capped at ${ZERO_VISUAL_CAP}.`
  };
}

module.exports = { assessVisualConfidenceCap, ZERO_VISUAL_CAP };
