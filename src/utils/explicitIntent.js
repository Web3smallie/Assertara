/**
 * Explicit vs inferred intent separation (Capability 5, B8).
 *
 * Explicit intent = verbatim user/agent statements, segmented
 * deterministically with exact quotes and character spans. No
 * paraphrase, no meaning classification, no inference: the quote IS
 * the statement. Anything the model says about intent is INFERENCE
 * (schema-enforced kind: 'inferred') and can never silently become
 * authorization.
 *
 * Sources: agent purpose text, admitted agent-evidence items of type
 * objective/intent, and browser page text. Visual claims are already
 * region-grounded elsewhere and are not re-extracted here.
 *
 * Pure and deterministic. Never throws on malformed input.
 */

const MAX_STATEMENTS = 12;
const MAX_QUOTE_CHARS = 300;

// Split on sentence/clause boundaries, keeping offsets for spans.
// Digit-dot-digit runs (0.001, 1.5) are protected: amounts must
// never split a quote. Abbreviations (e.g.) still split — accepted
// narrow limitation, documented: quotes stay verbatim regardless.
function segment(text) {
  const out = [];
  const safe = String(text).replace(/(\d)\.(\d)/g, '$1\uFFFF$2');
  const re = /[^.!?;\n]+[.!?;\n]?/g;
  let m;
  while ((m = re.exec(safe)) !== null) {
    const raw = m[0];
    const trimmed = raw.trim().split('\uFFFF').join('.');
    if (trimmed.length < 4) continue;
    if (!/[A-Za-z0-9]/.test(trimmed)) continue;
    const start = m.index + raw.indexOf(raw.trim());
    out.push({ quote: trimmed.slice(0, MAX_QUOTE_CHARS), start, end: start + trimmed.length });
  }
  return out;
}

function padId(n) {
  return `EI-${String(n).padStart(3, '0')}`;
}

/**
 * Extract explicit statements.
 * @param {{purposeText: string|null, purposeSource: string, agentEvidence: Array}} args
 */
function extractExplicitIntent(args) {
  const a = args && typeof args === 'object' ? args : {};
  const statements = [];
  const notes = [];
  const seen = new Set();
  let seq = 0;

  const push = (quote, source, start, end, truncatedQuote) => {
    const key = `${source}::${quote.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    seq += 1;
    statements.push({
      id: padId(seq),
      quote,
      source,
      span: { start, end },
      truncated: truncatedQuote === true
    });
  };

  const purpose = typeof a.purposeText === 'string' ? a.purposeText : '';
  const purposeSource = typeof a.purposeSource === 'string' && a.purposeSource.length > 0
    ? a.purposeSource
    : 'agent-purpose';
  if (purpose.trim().length > 0) {
    for (const s of segment(purpose)) {
      push(s.quote, purposeSource, s.start, s.end, s.quote.length >= MAX_QUOTE_CHARS);
    }
  }

  const admitted = Array.isArray(a.agentEvidence) ? a.agentEvidence : [];
  for (const item of admitted) {
    if (!item || typeof item !== 'object') continue;
    if (item.type !== 'objective' && item.type !== 'intent') continue;
    if (typeof item.content !== 'string' || item.content.trim().length === 0) continue;
    const source = typeof item.serverId === 'string' ? `agent-evidence:${item.serverId}` : `agent-evidence:${item.type}`;
    for (const s of segment(item.content)) {
      push(s.quote, source, s.start, s.end, s.quote.length >= MAX_QUOTE_CHARS);
    }
  }

  let truncated = false;
  let kept = statements;
  if (statements.length > MAX_STATEMENTS) {
    truncated = true;
    kept = statements.slice(0, MAX_STATEMENTS);
    notes.push(`${statements.length - MAX_STATEMENTS} statement(s) withheld by display cap; full text remains in source.`);
  }
  if (kept.length === 0) {
    notes.push('no explicit statements supplied; intent is entirely uninformed — nothing quotable exists.');
  }

  return {
    statements: kept,
    truncated,
    total: statements.length,
    summary: {
      statements: kept.length,
      sources: [...new Set(kept.map((s) => s.source))],
      truncated
    },
    notes
  };
}

module.exports = { extractExplicitIntent, MAX_STATEMENTS };
