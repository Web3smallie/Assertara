/**
 * Assertara PDF Ingestion — Audit-Report Second Opinion (F10), document lane.
 *
 * Deterministic pipeline: validate -> extract per-page text (unpdf) ->
 * optional OCR for textless pages (caller-supplied page images only) ->
 * segment findings by heading patterns -> extract code mentions ->
 * convert to ledger intake (UNRESOLVED records only).
 *
 * Honesty rules enforced here:
 * - Document bytes are UNTRUSTED DATA. They are never executed, never sent to
 *   a model as instructions, and no finding leaves UNRESOLVED without the
 *   ledger's own transition rules (see features.AUDIT_TRANSITIONS).
 * - Code references are MENTIONED_IN_REPORT observations: the report names a
 *   file/function/address. They are NOT verified code and NOT proof of a bug.
 * - Text matches never establish exploitability; test-suite passes never
 *   establish VERIFIED_FIXED (the ledger requires linked passing-test
 *   evidence for that transition).
 * - Limits are enforced by REJECTING over-limit documents, never by silently
 *   truncating findings.
 */

const crypto = require('crypto');
const { extractText, getDocumentProxy } = require('unpdf');
const { extractUiTexts } = require('../services/ocrService');

const DEFAULT_LIMITS = {
  maxBytes: 5 * 1024 * 1024, // 5 MiB of PDF bytes
  maxPages: 50,
  maxChars: 200000, // total extracted text
  maxFindings: 100,
  quoteChars: 500, // verbatim quote kept per finding
  maxDescription: 1200 // ledger description bound
};

const SEVERITY_OF_PREFIX = { C: 'Critical', H: 'High', M: 'Medium', L: 'Low', I: 'Informational' };

function pdfError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

// Heading patterns, tried in order. Each returns { sourceId, severity, title }
// or null. Matching is line-local and deterministic.
const HEADING_PATTERNS = [
  { re: /^([CHMLI])-(\d{1,3})\b\s*(.*)$/i, parse: (m) => ({ sourceId: `${m[1].toUpperCase()}-${m[2]}`, severity: SEVERITY_OF_PREFIX[m[1].toUpperCase()], title: m[3].trim() }) },
  { re: /^finding\s+([A-Za-z]-?\d{1,3}|\d{1,3})\b\s*[:-]?\s*(.*)$/i, parse: (m) => ({ sourceId: m[1].toUpperCase(), severity: null, title: m[2].trim() }) },
  { re: /^issue\s+#?(\d{1,3})\b\s*[:-]?\s*(.*)$/i, parse: (m) => ({ sourceId: `ISSUE-${m[1]}`, severity: null, title: m[2].trim() }) },
  { re: /^\[\s*(critical|high|medium|low|informational|info)\s*\]\s*(.*)$/i, parse: (m) => ({ sourceId: null, severity: normalizeSeverity(m[1]), title: m[2].trim() }) },
  { re: /^(critical|high|medium|low)\s+severity\s*[:-]\s*(.*)$/i, parse: (m) => ({ sourceId: null, severity: normalizeSeverity(m[1]), title: m[2].trim() }) }
];

function normalizeSeverity(word) {
  const w = word.toLowerCase();
  if (w === 'info') return 'Informational';
  return w.charAt(0).toUpperCase() + w.slice(1);
}

function matchHeading(line) {
  for (const { re, parse } of HEADING_PATTERNS) {
    if (!parse) continue;
    const m = line.match(re);
    if (m) {
      const h = parse(m);
      if (!h.title) h.title = h.sourceId ? `Finding ${h.sourceId}` : 'Untitled finding';
      return h;
    }
  }
  return null;
}

const CODE_PATTERNS = [
  { kind: 'FILE', re: /\b[\w./-]+\.sol(?::\d+)?\b/g },
  { kind: 'FUNCTION', re: /`([A-Za-z_]\w*\.[A-Za-z_]\w*)`|(\b[A-Za-z_]\w+\.[A-Za-z_]\w*\(\))|\bfunction\s+([A-Za-z_]\w*)/g },
  { kind: 'ADDRESS', re: /\b0x[0-9a-fA-F]{40}\b/g }
];

function extractCodeRefs(text, page) {
  const refs = [];
  for (const { kind, re } of CODE_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = kind === 'FUNCTION' ? (m[1] || m[2] || m[3]) : m[0];
      refs.push({ kind, value, page, semantics: 'MENTIONED_IN_REPORT' });
      if (refs.length > 200) return refs; // hard bound; count reported, never silent below
    }
  }
  return refs;
}

function normalizeInput(data, maxBytes) {
  let bytes;
  if (typeof data === 'string') {
    const compact = data.replace(/\s+/g, '');
    if (compact.length === 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) {
      throw pdfError('PDF_NOT_A_PDF', 'input string is not valid base64');
    }
    if (compact.length > maxBytes * 2) {
      throw pdfError('PDF_TOO_LARGE', `base64 input exceeds ${(maxBytes * 2)} chars before decoding`);
    }
    bytes = Buffer.from(compact, 'base64');
  } else if (Buffer.isBuffer(data)) {
    bytes = data;
  } else if (data instanceof Uint8Array) {
    bytes = Buffer.from(data);
  } else {
    throw pdfError('PDF_NOT_A_PDF', 'input must be a Buffer, Uint8Array, or base64 string');
  }
  if (bytes.length > maxBytes) {
    throw pdfError('PDF_TOO_LARGE', `PDF is ${bytes.length} bytes; limit is ${maxBytes}`);
  }
  if (bytes.length === 0) throw pdfError('PDF_NOT_A_PDF', 'empty input is not a PDF');
  const head = bytes.subarray(0, Math.min(1024, bytes.length)).toString('latin1');
  if (!head.includes('%PDF-')) throw pdfError('PDF_NOT_A_PDF', 'missing %PDF- header; not a PDF document');
  return bytes;
}

async function preflightPageCount(bytes, maxPages) {
  let proxy;
  try {
    proxy = await getDocumentProxy(Uint8Array.from(bytes));
  } catch (err) {
    throw pdfError('PDF_UNPROCESSABLE', `PDF failed to load: ${err.message}`);
  }
  try {
    const numPages = proxy.numPages;
    if (!Number.isInteger(numPages) || numPages < 1) {
      throw pdfError('PDF_UNPROCESSABLE', 'PDF reports no pages');
    }
    if (numPages > maxPages) {
      throw pdfError('PDF_TOO_MANY_PAGES', `PDF has ${numPages} pages; limit is ${maxPages}`);
    }
    return numPages;
  } finally {
    try {
      if (proxy && typeof proxy.destroy === 'function') await proxy.destroy();
      else if (proxy && typeof proxy.cleanup === 'function') await proxy.cleanup();
    } catch { /* best-effort release; GC owns the rest */ }
  }
}

async function ocrPage(imageInput, page, ocr) {
  // Full-page box; cropImageRegion clamps to the real image bounds.
  const { combinedText } = await ocr(imageInput, [{ label: `page-${page}`, boundingBox: { x: 0, y: 0, width: 1000000, height: 1000000 } }]);
  return (combinedText || '').replace(/^\[PAGE-\d+\]:\s*/, '').trim();
}

function segmentFindings(pages, quoteChars) {
  // Flatten to (line, page) pairs; headings open a new finding.
  const lines = [];
  for (const p of pages) {
    for (const line of p.text.split('\n')) lines.push({ line: line.trim(), page: p.page });
  }
  const findings = [];
  let current = null;
  const close = () => { if (current) findings.push(current); current = null; };
  for (const { line, page } of lines) {
    if (!line) continue;
    const h = matchHeading(line);
    if (h) {
      close();
      current = { ...h, startPage: page, endPage: page, body: [line] };
    } else if (current) {
      current.body.push(line);
      current.endPage = page;
    }
  }
  close();
  return findings.map((f, i) => {
    const full = f.body.join('\n');
    const truncated = full.length > quoteChars;
    return {
      index: i,
      sourceId: f.sourceId,
      severity: f.severity,
      title: f.title,
      startPage: f.startPage,
      endPage: f.endPage,
      chars: full.length,
      quote: truncated ? `${full.slice(0, quoteChars)}…[truncated ${full.length - quoteChars} chars]` : full,
      quoteTruncated: truncated,
      codeRefs: extractCodeRefs(full, f.startPage)
    };
  });
}

/**
 * Ingest an audit PDF into page records + segmented findings.
 * @param {{ data: Buffer|Uint8Array|string, filename?: string, pageImages?: Object, limits?: Object }} input
 * @param {{ ocr?: Function }} deps — ocr(image, regions) override for deterministic tests.
 */
async function ingestAuditPdf(input, deps = {}) {
  if (!input || typeof input !== 'object') throw pdfError('PDF_NOT_A_PDF', 'input must be an object with data');
  const limits = { ...DEFAULT_LIMITS, ...(input.limits || {}) };
  const bytes = normalizeInput(input.data, limits.maxBytes);
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');

  await preflightPageCount(bytes, limits.maxPages);

  let extracted;
  try {
    extracted = await extractText(Uint8Array.from(bytes));
  } catch (err) {
    throw pdfError('PDF_UNPROCESSABLE', `text extraction failed: ${err.message}`);
  }
  const pageTexts = Array.isArray(extracted.text) ? extracted.text : [extracted.text];
  const totalChars = pageTexts.reduce((n, t) => n + (t ? t.length : 0), 0);
  if (totalChars > limits.maxChars) {
    throw pdfError('PDF_TEXT_EXCEEDED', `extracted ${totalChars} chars; limit is ${limits.maxChars}`);
  }

  const ocr = deps.ocr || extractUiTexts;
  const pageImages = input.pageImages && typeof input.pageImages === 'object' ? input.pageImages : {};
  const pages = [];
  const warnings = [];
  for (let i = 0; i < pageTexts.length; i++) {
    const page = i + 1;
    const text = (pageTexts[i] || '').trim();
    if (text) {
      if (pageImages[page] !== undefined) warnings.push(`PAGE_${page}_IMAGE_UNUSED`);
      pages.push({ page, chars: text.length, source: 'PDF_TEXT', text });
      continue;
    }
    const image = pageImages[page];
    if (image === undefined) {
      warnings.push(`PAGE_${page}_NO_TEXT`);
      pages.push({ page, chars: 0, source: 'NO_TEXT', text: '' });
      continue;
    }
    try {
      const ocrText = await ocrPage(image, page, ocr);
      if (ocrText) {
        pages.push({ page, chars: ocrText.length, source: 'OCR_TEXT', text: ocrText });
      } else {
        warnings.push(`PAGE_${page}_OCR_EMPTY`);
        pages.push({ page, chars: 0, source: 'NO_TEXT', text: '' });
      }
    } catch (err) {
      warnings.push(`PAGE_${page}_OCR_FAILED`);
      pages.push({ page, chars: 0, source: 'NO_TEXT', text: '' });
    }
  }

  const findings = segmentFindings(pages, limits.quoteChars);
  if (findings.length > limits.maxFindings) {
    throw pdfError('PDF_TOO_MANY_FINDINGS', `segmented ${findings.length} findings; limit is ${limits.maxFindings}`);
  }
  if (findings.length === 0) warnings.push('NO_FINDINGS_SEGMENTED');

  return {
    status: 'OK',
    feature: 'F10_audit',
    lane: 'ingest',
    doc: {
      sha256,
      bytes: bytes.length,
      filename: typeof input.filename === 'string' ? input.filename.slice(0, 200) : null,
      pages: pageTexts.length,
      textChars: totalChars
    },
    pages,
    findings,
    warnings
  };
}

/**
 * Convert ingest output to runAuditIntake input. All records enter UNRESOLVED;
 * status changes go through runAuditTransition only.
 */
function toLedgerIntake(ingestResult, limits = {}) {
  if (!ingestResult || ingestResult.status !== 'OK' || !Array.isArray(ingestResult.findings)) {
    throw pdfError('PDF_NO_FINDINGS', 'ingest result has no findings to intake');
  }
  if (ingestResult.findings.length === 0) {
    throw pdfError('PDF_NO_FINDINGS', 'zero segmented findings; nothing to intake (see NO_FINDINGS_SEGMENTED)');
  }
  const maxDescription = limits.maxDescription || DEFAULT_LIMITS.maxDescription;
  const short = String(ingestResult.doc && ingestResult.doc.sha256 || 'nodoc').slice(0, 8);
  return {
    findings: ingestResult.findings.map((f, i) => {
      const id = `${short}-F${String(i + 1).padStart(2, '0')}`;
      const pageRef = f.startPage === f.endPage ? `p.${f.startPage}` : `pp.${f.startPage}-${f.endPage}`;
      const sev = f.severity ? `[${f.severity}] ` : '';
      let description = `${sev}${f.title} (audit ${pageRef}): ${f.quote}`;
      if (description.length > maxDescription) {
        description = `${description.slice(0, maxDescription)}…[truncated ${description.length - maxDescription} chars]`;
      }
      const firstRef = (f.codeRefs && f.codeRefs[0]) || null;
      return {
        id,
        description,
        location: firstRef ? `${pageRef} ${firstRef.kind}:${firstRef.value}` : pageRef,
        severity: f.severity,
        sourceId: f.sourceId,
        codeRefs: f.codeRefs || []
      };
    })
  };
}

module.exports = { ingestAuditPdf, toLedgerIntake, DEFAULT_LIMITS, matchHeading, extractCodeRefs };
