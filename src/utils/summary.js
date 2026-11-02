/**
 * Transaction-summary text selection (visual roadmap Phase 3).
 *
 * Derives the primary transaction-intent text from regions produced by the
 * summary prompt, keeping it separate from the full combined OCR scan.
 * Pure and deterministic: identical inputs always yield identical output.
 *
 * Statuses:
 * - targeted: exactly one summary region with usable text.
 * - ambiguous: several summary regions; usable texts are joined WITHOUT
 *   choosing a candidate, and the ambiguity is explicit.
 * - ocr-failed / ocr-empty / ocr-unusable: summary regions exist but no
 *   usable text (all failed / all empty / mixed).
 * - no-summary-regions: no region came from a summary prompt.
 * - unavailable: no region evidence to assess.
 *
 * Only genuine regions with successful non-empty OCR contribute text.
 * Unrelated regions never enter the summary text; when isolation is
 * impossible the caller falls back to the full scan (recorded separately).
 */

function byRegionId(a, b) {
  return String(a.regionId ?? '').localeCompare(String(b.regionId ?? ''));
}

/**
 * @param {Array} regions Joined entries {regionId, prompts?, genuine?,
 *   synthetic?, ocr?: {text?, empty?, error?}}.
 * @param {{summaryPrompts: Array<string>}} opts Prompt strings that mark a
 *   region as a transaction-summary candidate.
 */
function selectSummaryText(regions, opts = {}) {
  const prompts = Array.isArray(opts.summaryPrompts) ? opts.summaryPrompts : [];
  const empty = (status, reason) => ({ status, regionIds: [], text: '', reason, issues: [] });
  if (!Array.isArray(regions)) {
    return empty('unavailable', 'No region evidence to assess');
  }
  const cands = regions
    .filter((r) => r && Array.isArray(r.prompts) && r.prompts.some((p) => prompts.includes(p))
      && r.genuine !== false && r.synthetic !== true)
    .sort(byRegionId);
  if (cands.length === 0) {
    return empty('no-summary-regions', prompts.length > 0
      ? `No regions from summary prompt(s): ${prompts.join(', ')}`
      : 'No summary prompts configured');
  }
  const usable = cands.filter((c) => {
    const o = c.ocr || {};
    return !o.error && typeof o.text === 'string' && o.text.length > 0;
  });
  const issues = cands
    .filter((c) => !usable.includes(c))
    .map((c) => {
      const o = c.ocr || {};
      return { regionId: c.regionId, issue: o.error ? `ocr-failed:${o.error.code || 'UNKNOWN'}` : 'ocr-empty' };
    });
  const text = usable.map((u) => u.ocr.text).join('\n');
  const regionIds = usable.map((u) => u.regionId);
  if (usable.length === 0) {
    const failed = issues.filter((i) => i.issue.startsWith('ocr-failed')).length;
    const status = failed === cands.length ? 'ocr-failed' : (failed === 0 ? 'ocr-empty' : 'ocr-unusable');
    return {
      status, regionIds: [], text: '',
      reason: `No usable summary text (${cands.length} candidate(s): ${failed} failed, ${cands.length - failed} empty)`,
      issues
    };
  }
  if (cands.length === 1) {
    return {
      status: 'targeted', regionIds, text,
      reason: `Single summary region ${regionIds[0]} with ${text.length} chars`,
      issues
    };
  }
  return {
    status: 'ambiguous', regionIds, text,
    reason: `${cands.length} summary candidates (${usable.length} readable); texts joined without choosing`,
    issues
  };
}

module.exports = { selectSummaryText };
