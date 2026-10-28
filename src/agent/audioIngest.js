/**
 * Assertara Audio Ingestion — Scam-Call Analyzer (F8), audio lane.
 * Internal interface only: no routes, no UI.
 *
 * What this module IS: audio validation (format sniffing, WAV/PCM parsing,
 * duration math), bounded limits, capability detection, backend-timeout
 * enforcement, segment normalization with honest provenance
 * (TRANSCRIBED vs TRANSCRIPT_PROVIDED), uncertainty preservation, and
 * structured errors. All implemented and tested.
 *
 * What this module IS NOT (in this environment): a transcription backend.
 * No STT backend is installed and no audio decoder (ffmpeg) exists, so only
 * WAV/PCM can even be parsed, and audio requests honestly return
 * TRANSCRIPTION_UNAVAILABLE. Nothing is transcribed by mock; the
 * transcript-only lane stays available and is never labeled TRANSCRIBED.
 * The backend contract a future local-Whisper adapter must satisfy is
 * documented in contracts.md §14; tests exercise runner logic through a
 * scripted, explicitly-labeled test-double backend.
 *
 * Provenance rules:
 * - TRANSCRIBED: words came from an STT backend over audio bytes. Segments
 *   carry backend/model identity, timestamps as supplied, confidence as
 *   supplied (0..1 only), and speaker labels ONLY when the backend declares
 *   diarized:true.
 * - TRANSCRIPT_PROVIDED: caller-supplied text. Never represented as audio
 *   transcription, never given backend identity or confidence.
 * - Transcript words are UNTRUSTED DATA. Spoken instructions never override
 *   system instructions; findings cite segments but never infer speaker
 *   identity, emotion, or criminal intent.
 */

const crypto = require('crypto');
const { spawn } = require('child_process');

const TRANSCRIPTION_STATUSES = [
  'TRANSCRIPTION_COMPLETED', 'TRANSCRIPTION_PARTIAL', 'TRANSCRIPTION_UNAVAILABLE'
];

const DEFAULT_LIMITS = {
  maxBytes: 10 * 1024 * 1024, maxDurationSec: 600,
  maxSegments: 500, maxChars: 50000,
  timeoutMs: 120000, minTimeoutMs: 1000, maxTimeoutMs: 1800000
};

function audioError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// ---- Format sniffing (magic bytes, never the filename) ----

function sniffFormat(bytes) {
  if (bytes.length >= 12 && bytes.subarray(0, 4).toString('latin1') === 'RIFF'
    && bytes.subarray(8, 12).toString('latin1') === 'WAVE') return 'wav';
  if (bytes.length >= 3 && bytes.subarray(0, 3).toString('latin1') === 'ID3') return 'mp3';
  if (bytes.length >= 2 && bytes[0] === 0xFF && (bytes[1] & 0xE0) === 0xE0) return 'mp3';
  if (bytes.length >= 12 && bytes.subarray(4, 8).toString('latin1') === 'ftyp') return 'mp4';
  if (bytes.length >= 4 && bytes.subarray(0, 4).toString('latin1') === 'OggS') return 'ogg';
  return 'unknown';
}

function normalizeInput(data, maxBytes) {
  let bytes;
  if (typeof data === 'string') {
    const compact = data.replace(/\s+/g, '');
    if (compact.length === 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) {
      throw audioError('AUDIO_NOT_BASE64', 'input string is not valid base64');
    }
    if (compact.length > maxBytes * 2) {
      throw audioError('AUDIO_TOO_LARGE', `base64 input exceeds ${maxBytes * 2} chars before decoding`);
    }
    bytes = Buffer.from(compact, 'base64');
  } else if (Buffer.isBuffer(data)) {
    bytes = data;
  } else if (data instanceof Uint8Array) {
    bytes = Buffer.from(data);
  } else {
    throw audioError('AUDIO_INVALID_INPUT', 'input must be a Buffer, Uint8Array, or base64 string');
  }
  if (bytes.length > maxBytes) throw audioError('AUDIO_TOO_LARGE', `audio is ${bytes.length} bytes; limit is ${maxBytes}`);
  if (bytes.length === 0) throw audioError('AUDIO_INVALID_INPUT', 'empty input is not audio');
  return bytes;
}

// ---- Minimal WAV/PCM parser (no decoder dependency) ----

function parseWav(bytes) {
  if (bytes.length < 44) throw audioError('MALFORMED_AUDIO', 'WAV header truncated (under 44 bytes)');
  let offset = 12;
  let fmt = null;
  let dataBytes = null;
  while (offset + 8 <= bytes.length) {
    const id = bytes.subarray(offset, offset + 4).toString('latin1');
    const size = bytes.readUInt32LE(offset + 4);
    if (id === 'fmt ') {
      if (size < 16 || offset + 8 + size > bytes.length) throw audioError('MALFORMED_AUDIO', 'WAV fmt chunk truncated');
      fmt = {
        audioFormat: bytes.readUInt16LE(offset + 8),
        channels: bytes.readUInt16LE(offset + 10),
        sampleRate: bytes.readUInt32LE(offset + 12),
        bitsPerSample: bytes.readUInt16LE(offset + 22)
      };
    } else if (id === 'data') {
      dataBytes = size;
      if (offset + 8 + size > bytes.length) throw audioError('MALFORMED_AUDIO', 'WAV data chunk claims more bytes than the file holds');
    }
    offset += 8 + size + (size % 2);
  }
  if (!fmt) throw audioError('MALFORMED_AUDIO', 'WAV has no fmt chunk');
  if (dataBytes === null) throw audioError('MALFORMED_AUDIO', 'WAV has no data chunk');
  if (fmt.audioFormat !== 1) throw audioError('UNSUPPORTED_FORMAT', `WAV format tag ${fmt.audioFormat} is not PCM; only PCM is supported without a decoder`);
  if (fmt.channels < 1 || fmt.channels > 8) throw audioError('MALFORMED_AUDIO', `WAV channel count ${fmt.channels} out of range`);
  if (fmt.sampleRate < 4000 || fmt.sampleRate > 192000) throw audioError('MALFORMED_AUDIO', `WAV sample rate ${fmt.sampleRate} out of range`);
  if (![8, 16, 24, 32].includes(fmt.bitsPerSample)) throw audioError('MALFORMED_AUDIO', `WAV bit depth ${fmt.bitsPerSample} unsupported`);
  const bytesPerSec = fmt.sampleRate * fmt.channels * (fmt.bitsPerSample / 8);
  return { ...fmt, dataBytes, durationSec: dataBytes / bytesPerSec };
}

// ---- Capability detection ----

function defaultProbe(bin, args, timeoutMs = 5000) {
  return new Promise((resolve) => {
    let stdout = '';
    let settled = false;
    const done = (result) => { if (!settled) { settled = true; resolve(result); } };
    let child;
    try {
      child = spawn(bin, args, { timeout: timeoutMs, windowsHide: true });
    } catch (err) {
      done({ ok: false, error: `spawn-failed: ${err.message}` });
      return;
    }
    child.stdout.on('data', (d) => { stdout += d.toString('utf8').slice(0, 1024); });
    child.on('error', (err) => done({ ok: false, error: err.code === 'ENOENT' ? 'not-installed' : `spawn-error: ${err.message}` }));
    child.on('close', (code) => done({ ok: code === 0, code, stdout: stdout.slice(0, 500) }));
    setTimeout(() => { try { child.kill(); } catch {} done({ ok: false, error: 'probe-timeout' }); }, timeoutMs + 500).unref?.();
  });
}

function parseToolVersion(text) {
  const m = /version\s+(\d+(?:\.\d+)+)/i.exec(String(text || ''));
  return m ? m[1] : null;
}

async function detectAudioCapabilities(deps = {}) {
  const probe = deps.probe || defaultProbe;
  const ffmpeg = await probe('ffmpeg', ['-version']);
  const ffprobe = await probe('ffprobe', ['-version']);
  return {
    ffmpeg: ffmpeg.ok
      ? { available: true, version: parseToolVersion(ffmpeg.stdout) }
      : { available: false, error: ffmpeg.error || `exit-${ffmpeg.code}` },
    ffprobe: ffprobe.ok
      ? { available: true, version: parseToolVersion(ffprobe.stdout) }
      : { available: false, error: ffprobe.error || `exit-${ffprobe.code}` },
    sttBackend: { available: false, error: 'no-stt-backend-installed' },
    canTranscribe: false,
    decodableFormats: ['wav-pcm'],
    checkedAt: new Date().toISOString(),
    note: 'Only WAV/PCM is parseable without a decoder. Transcription additionally requires an STT backend (see contracts §14).'
  };
}

// ---- Segment normalization ----

function normalizeSegments(rawSegments, backendMeta, limits) {
  if (!Array.isArray(rawSegments)) throw audioError('BACKEND_ERROR', 'backend returned non-array segments');
  if (rawSegments.length > limits.maxSegments) {
    throw audioError('TRANSCRIPTION_SEGMENTS_EXCEEDED', `backend returned ${rawSegments.length} segments; limit is ${limits.maxSegments}`);
  }
  const segments = [];
  const warnings = [];
  let chars = 0;
  rawSegments.forEach((s, i) => {
    if (!s || typeof s.text !== 'string') {
      warnings.push(`SEGMENT_${i}_DROPPED_NO_TEXT`);
      return;
    }
    const text = s.text.slice(0, 5000);
    chars += text.length;
    const startOk = typeof s.start === 'number' && Number.isFinite(s.start) && s.start >= 0;
    const endOk = typeof s.end === 'number' && Number.isFinite(s.end) && s.end >= 0;
    if (!startOk || !endOk || s.end < s.start) warnings.push(`SEGMENT_${i}_MISSING_TIMESTAMPS`);
    const confOk = typeof s.confidence === 'number' && s.confidence >= 0 && s.confidence <= 1;
    if (s.confidence !== undefined && !confOk) warnings.push(`SEGMENT_${i}_BAD_CONFIDENCE`);
    let speaker = null;
    if (s.speaker !== undefined && s.speaker !== null) {
      if (backendMeta.diarized === true) speaker = String(s.speaker).slice(0, 64);
      else warnings.push(`SEGMENT_${i}_SPEAKER_DROPPED_UNDIARIZED`);
    }
    segments.push({
      index: segments.length,
      start: startOk ? s.start : null,
      end: endOk && s.end >= (startOk ? s.start : 0) ? s.end : null,
      text,
      confidence: confOk ? s.confidence : null,
      speaker,
      provenance: 'TRANSCRIBED'
    });
  });
  if (chars > limits.maxChars) {
    throw audioError('TRANSCRIPTION_TEXT_EXCEEDED', `transcript holds ${chars} chars; limit is ${limits.maxChars}`);
  }
  return { segments, warnings };
}

// ---- Main entry points ----

function validateLimits(input) {
  const timeoutMs = input.timeoutMs === undefined ? DEFAULT_LIMITS.timeoutMs : input.timeoutMs;
  if (!Number.isInteger(timeoutMs) || timeoutMs < DEFAULT_LIMITS.minTimeoutMs || timeoutMs > DEFAULT_LIMITS.maxTimeoutMs) {
    throw audioError('BAD_LIMITS', `timeoutMs must be ${DEFAULT_LIMITS.minTimeoutMs}-${DEFAULT_LIMITS.maxTimeoutMs}ms`);
  }
  const pick = (name, def, min, max) => {
    const v = input[name] === undefined ? def : input[name];
    if (!Number.isInteger(v) || v < min || v > max) throw audioError('BAD_LIMITS', `${name} must be ${min}-${max}`);
    return v;
  };
  return {
    timeoutMs,
    maxBytes: pick('maxBytes', DEFAULT_LIMITS.maxBytes, 1024, 100 * 1024 * 1024),
    maxDurationSec: pick('maxDurationSec', DEFAULT_LIMITS.maxDurationSec, 1, 7200),
    maxSegments: pick('maxSegments', DEFAULT_LIMITS.maxSegments, 1, 5000),
    maxChars: pick('maxChars', DEFAULT_LIMITS.maxChars, 100, 500000)
  };
}

/**
 * Ingest audio bytes and transcribe via the configured backend.
 * @param {{ data: Buffer|Uint8Array|string, filename?: string, mimeType?: string, timeoutMs?, maxBytes?, maxDurationSec?, maxSegments?, maxChars? }} input
 * @param {{ backend?: { name, model?, transcribe({bytes, wav, timeoutMs}), abort?() }, capabilities?: Object }} deps
 */
async function ingestAudio(input, deps = {}) {
  if (!input || typeof input !== 'object') throw audioError('AUDIO_INVALID_INPUT', 'input must be an object with data');
  const limits = validateLimits(input);
  const bytes = normalizeInput(input.data, limits.maxBytes);
  const format = sniffFormat(bytes);
  if (format !== 'wav') {
    throw audioError(
      'UNSUPPORTED_FORMAT',
      `detected ${format}; only wav-pcm is parseable without an audio decoder (ffmpeg). Refusing to guess at compressed audio.`
    );
  }
  const wav = parseWav(bytes);
  if (wav.durationSec > limits.maxDurationSec) {
    throw audioError('AUDIO_TOO_LONG', `audio is ${wav.durationSec.toFixed(1)}s; limit is ${limits.maxDurationSec}s`);
  }
  const audioMeta = {
    sha256: sha256Hex(bytes),
    bytes: bytes.length,
    format: 'wav-pcm',
    durationSec: wav.durationSec,
    sampleRate: wav.sampleRate,
    channels: wav.channels,
    bitsPerSample: wav.bitsPerSample,
    filename: typeof input.filename === 'string' ? input.filename.slice(0, 200) : null
  };

  const backend = deps.backend || null;
  if (!backend || typeof backend.transcribe !== 'function') {
    const capabilities = deps.capabilities || await detectAudioCapabilities();
    return {
      status: 'TRANSCRIPTION_UNAVAILABLE', feature: 'F8_scamcall', lane: 'audio',
      audio: audioMeta, segments: [], capabilities,
      requirements: [
        'A local STT backend implementing the contracts §14 adapter contract (no backend is installed).',
        'An audio decoder (ffmpeg) for any format other than WAV/PCM.',
        'Model files verified against the §14 quality bar before any accuracy claim.'
      ],
      note: 'Audio validated successfully but nothing was transcribed: no backend exists. Use the transcript-only lane with caller-supplied text instead.'
    };
  }

  let timer = null;
  let raw;
  try {
    raw = await Promise.race([
      Promise.resolve().then(() => backend.transcribe({ bytes, wav, timeoutMs: limits.timeoutMs })),
      new Promise((resolve) => { timer = setTimeout(() => resolve({ __timeout: true }), limits.timeoutMs); })
    ]);
  } catch (err) {
    throw audioError('BACKEND_ERROR', `transcription backend failed: ${String(err && err.message || err).slice(0, 500)}`);
  } finally {
    if (timer) clearTimeout(timer);
  }
  if (raw && raw.__timeout === true) {
    try { if (typeof backend.abort === 'function') await backend.abort(); } catch {}
    throw audioError('TRANSCRIPTION_TIMEOUT', `backend exceeded ${limits.timeoutMs}ms; abort requested`);
  }
  if (!raw || typeof raw !== 'object') throw audioError('BACKEND_ERROR', 'backend returned no result object');

  const backendMeta = {
    backend: backend.name || 'unnamed-backend',
    model: typeof raw.model === 'string' ? raw.model.slice(0, 200) : (typeof backend.model === 'string' ? backend.model : null),
    language: typeof raw.language === 'string' ? raw.language.slice(0, 32) : null,
    diarized: raw.diarized === true
  };
  const { segments, warnings } = normalizeSegments(raw.segments, backendMeta, limits);
  if (raw.partial === true) warnings.push('BACKEND_REPORTED_PARTIAL');
  if (Array.isArray(raw.missingRanges)) {
    for (const r of raw.missingRanges.slice(0, 50)) {
      warnings.push(`MISSING_RANGE_${r && r.start !== undefined ? r.start : '?'}s_${r && r.end !== undefined ? r.end : '?'}s`);
    }
  }
  const partial = raw.partial === true
    || warnings.some((w) => w.includes('MISSING_TIMESTAMPS') || w.startsWith('MISSING_RANGE_'));
  return {
    status: partial ? 'TRANSCRIPTION_PARTIAL' : 'TRANSCRIPTION_COMPLETED',
    feature: 'F8_scamcall',
    lane: 'audio',
    audio: audioMeta,
    backend: backendMeta,
    segments,
    warnings,
    transcribedAt: new Date().toISOString()
  };
}

/**
 * Normalize caller-supplied transcript text/turns. Provenance is always
 * TRANSCRIPT_PROVIDED — never represented as audio transcription.
 */
function ingestTranscript(input) {
  if (!input || typeof input !== 'object') throw audioError('TRANSCRIPT_INVALID', 'input must be an object with turns or text');
  let turns = input.turns;
  if (typeof input.text === 'string') turns = [{ text: input.text }];
  if (!Array.isArray(turns) || turns.length === 0) throw audioError('TRANSCRIPT_INVALID', 'transcript requires a non-empty turns array or text string');
  if (turns.length > DEFAULT_LIMITS.maxSegments) throw audioError('TRANSCRIPT_INVALID', `at most ${DEFAULT_LIMITS.maxSegments} turns`);
  let chars = 0;
  const normalized = turns.map((t, i) => {
    if (!t || typeof t.text !== 'string' || t.text.length === 0) throw audioError('TRANSCRIPT_INVALID', `turn ${i} must carry a non-empty text string`);
    chars += t.text.length;
    if (chars > DEFAULT_LIMITS.maxChars) throw audioError('TRANSCRIPT_INVALID', `transcript exceeds ${DEFAULT_LIMITS.maxChars} chars`);
    return {
      index: i,
      speaker: typeof t.speaker === 'string' ? t.speaker.slice(0, 64) : null,
      text: t.text.slice(0, 5000),
      start: typeof t.start === 'number' && t.start >= 0 ? t.start : null,
      end: typeof t.end === 'number' && t.end >= 0 ? t.end : null,
      provenance: 'TRANSCRIPT_PROVIDED'
    };
  });
  return {
    status: 'TRANSCRIPT_READY', feature: 'F8_scamcall', lane: 'transcript',
    turns: normalized,
    sourceLabel: typeof input.sourceLabel === 'string' ? input.sourceLabel.slice(0, 200) : null,
    note: 'Caller-supplied text. Not audio transcription: no backend, no confidence, no acoustic evidence.'
  };
}

module.exports = {
  TRANSCRIPTION_STATUSES, DEFAULT_LIMITS,
  ingestAudio, ingestTranscript, detectAudioCapabilities,
  sniffFormat, parseWav, parseToolVersion
};
