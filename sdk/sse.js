/**
 * Minimal fetch-based SSE reader (zero dependencies).
 *
 * Forwards ONLY genuine server-sent events to onEvent, in arrival
 * order. Nothing is synthesized: no fake progress, no fabricated
 * reasoning text. Resolves on the server's terminal event
 * (`stream-end`, or a `trace-finish` envelope when the server closes
 * without the marker). The caller cancels by returning exactly
 * `false` from onEvent or by aborting the passed AbortSignal.
 */

async function streamSSE(url, { headers, onEvent, signal, fetchImpl } = {}) {
  const doFetch = fetchImpl || fetch;
  const res = await doFetch(url, {
    method: 'GET',
    headers: { Accept: 'text/event-stream', ...(headers || {}) },
    signal
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const { fromHttp } = require('./errors');
    throw fromHttp(res.status, body, `Event stream failed with status ${res.status}.`);
  }
  if (!res.body || typeof res.body.getReader !== 'function') {
    throw new Error('Event stream requires a streaming fetch body.');
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let last = null;
  const deliver = (raw) => {
    const lines = raw.split('\n');
    const data = lines
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).trim())
      .join('\n');
    if (!data) return true; // comment/heartbeat: genuine keep-alive, no event
    let event;
    try {
      event = JSON.parse(data);
    } catch {
      return true; // unparseable frame: ignore, never invent
    }
    last = event;
    if (typeof onEvent === 'function' && onEvent(event) === false) return false;
    if (event && (event.type === 'stream-end' || event.type === 'trace-finish')) return false;
    return true;
  };
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (value) {
        buffer += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 2);
          if (!deliver(frame)) {
            try { await reader.cancel(); } catch { /* already closed */ }
            return last;
          }
        }
      }
      if (done) {
        if (buffer.trim()) deliver(buffer);
        return last;
      }
    }
  } finally {
    try { reader.releaseLock(); } catch { /* already released */ }
  }
}

module.exports = { streamSSE };
