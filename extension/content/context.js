/**
 * Assertara page-context collector. Runs on demand in the active tab only when
 * the user clicks Inspect. Returns visible, non-sensitive page context.
 * Never reads input, textarea, select, password, or hidden-field values.
 */
(() => {
  const MAX_TEXT_CHARS = 4000;

  function visibleText() {
    try {
      const text = (document.body ? document.body.innerText : '') || '';
      return text.replace(/\s+/g, ' ').trim().slice(0, MAX_TEXT_CHARS);
    } catch {
      return '';
    }
  }

  function domContext() {
    // Short structural summary: headings + button labels (visible text only).
    const parts = [];
    try {
      for (const el of document.querySelectorAll('h1, h2, h3')) {
        const t = (el.innerText || '').replace(/\s+/g, ' ').trim();
        if (t) parts.push(`heading: ${t.slice(0, 120)}`);
        if (parts.length >= 8) break;
      }
      for (const el of document.querySelectorAll('button')) {
        const t = (el.innerText || '').replace(/\s+/g, ' ').trim();
        if (t) parts.push(`button: ${t.slice(0, 80)}`);
        if (parts.length >= 16) break;
      }
    } catch {
      /* fall through with whatever was collected */
    }
    return parts;
  }

  return {
    url: window.location.href,
    title: document.title || '',
    visibleText: visibleText(),
    domContext: domContext()
  };
})();
