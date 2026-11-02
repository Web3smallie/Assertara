/**
 * Assertara shared pure helpers.
 * Runs in the popup, the service worker, and injected page contexts, and is
 * also loaded by the Node regression tests. No browser or Node APIs here.
 */
(function () {
  const VERDICTS = ['MATCH', 'MISMATCH', 'UNCERTAIN'];

  function verdictClass(verdict) {
    const v = String(verdict || '').toUpperCase();
    if (v === 'MATCH') return 'match';
    if (v === 'MISMATCH') return 'mismatch';
    return 'uncertain';
  }

  function verdictLabel(verdict) {
    const v = String(verdict || '').toUpperCase();
    return VERDICTS.includes(v) ? v : 'UNCERTAIN';
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function shortAddress(address) {
    const a = String(address || '');
    if (!/^0x[0-9a-fA-F]{40}$/.test(a)) return a || 'Unknown';
    return `${a.slice(0, 6)}…${a.slice(-4)}`;
  }

  function isValidAddress(address) {
    return /^0x[0-9a-fA-F]{40}$/.test(String(address || '').trim());
  }

  function formatConfidence(confidence) {
    const n = Number(confidence);
    if (!Number.isFinite(n)) return 'n/a';
    return `${Math.round(Math.max(0, Math.min(1, n)) * 100)}%`;
  }

  function deltaLine(d) {
    return `${d.asset || 'asset'} ${d.type || ''} ${d.delta || ''} (${d.risk || 'unknown risk'})`.trim();
  }

  function reasoningOriginLabel(origin) {
    if (origin === 'model') return 'Muse Spark analysis';
    if (origin === 'heuristic-fallback') return 'Heuristic fallback (model unavailable — unverified)';
    return 'Reasoning source unknown';
  }

  // Verdict-safeguard display. Accepts the backend's `verdictSafeguards`
  // array (preferred) or a single legacy `verdictSafeguard` object. Each
  // entry is { trigger, from, to, reason }. An empty array means none
  // triggered; a missing/malformed value means unknown — never invented,
  // never silently treated as "none".
  function safeguardText(value) {
    const list = Array.isArray(value) ? value
      : (value && typeof value === 'object' ? [value] : null);
    if (list === null) return 'Safeguard information unavailable.';
    const lines = [];
    for (const entry of list) {
      if (entry && typeof entry === 'object' && typeof entry.trigger === 'string' && entry.trigger.length > 0) {
        lines.push(typeof entry.reason === 'string' && entry.reason.length > 0
          ? `${entry.trigger}: ${entry.reason}`
          : `${entry.trigger}: no reason recorded.`);
      } else {
        lines.push('Unrecognized safeguard record.');
      }
    }
    if (lines.length === 0) return 'None triggered.';
    const n = lines.length;
    return `${n} safeguard${n === 1 ? '' : 's'} triggered: ${lines.join('; ')}`;
  }

  // Confidence-cap display. The backend sends `confidenceCap` as null when
  // no cap applied, or { trigger, previousConfidence, cap, reason }. The
  // original (previous) and final confidence stay distinguishable; values
  // use the same percentage formatting as the main confidence row.
  function confidenceCapText(cap) {
    if (cap === null || cap === undefined) return 'No confidence cap applied.';
    if (!cap || typeof cap !== 'object' || Array.isArray(cap)
        || typeof cap.cap !== 'number' || !Number.isFinite(cap.cap)) {
      return 'Confidence-cap information unavailable.';
    }
    const was = (typeof cap.previousConfidence === 'number' && Number.isFinite(cap.previousConfidence))
      ? ` (was ${formatConfidence(cap.previousConfidence)})`
      : '';
    const reason = (typeof cap.reason === 'string' && cap.reason.length > 0) ? cap.reason : 'No reason recorded.';
    return `Confidence capped at ${formatConfidence(cap.cap)}${was} — ${reason}`;
  }

  function simulationStatus(simulation) {
    const status = simulation && simulation.status;
    if (status === 'EXECUTED') {
      const outcome = simulation.success === true ? 'Executed successfully.' : 'Executed and FAILED.';
      const deltas = (simulation.assetDeltas || []).map(deltaLine).join('; ');
      const esc = simulation.escalationDetected ? ' Allowance escalation detected.' : '';
      const err = simulation.success === true ? '' : ` Error: ${simulation.error || 'see logs'}.`;
      return `${outcome}${esc}${err}${deltas ? ` Deltas: ${deltas}.` : ''} Mode: ${simulation.mode || 'foundry'}.`;
    }
    if (status === 'FALLBACK') {
      const analysis = (simulation.fallbackAnalysis || []).map(deltaLine).join('; ');
      return `Not executed — ${simulation.reason || 'deterministic fallback only.'}${analysis ? ` Estimates (not measured): ${analysis}.` : ''}`;
    }
    if (status === 'FAILED') {
      return `Attempted but failed: ${simulation.error || simulation.reason || 'no result'}. No EVM state was measured.`;
    }
    return 'Not performed — no simulation was required for this verdict.';
  }

  globalThis.AssertaraFormat = {
    verdictClass,
    verdictLabel,
    escapeHtml,
    shortAddress,
    isValidAddress,
    formatConfidence,
    reasoningOriginLabel,
    simulationStatus,
    safeguardText,
    confidenceCapText
  };
})();
