/**
 * Assertara Muse Spark Intelligence Adapter.
 * Encapsulates the documented Meta Model API Responses surface:
 * POST /v1/responses, reasoning.effort, text.format json_schema,
 * previous_response_id threading, prompt_cache_key, usage/cached_tokens,
 * /v1/responses/input_tokens preflight, typed error mapping.
 * Never logs or includes the API key in errors. No calls in tests (stub fetch).
 */

const DEFAULT_BASE_URL = 'https://api.meta.ai/v1';
const DEFAULT_MODEL = 'muse-spark-1.3';
// Documented standard-tier Spark pricing (USD per 1M tokens). Used ONLY to
// estimate cost when the API returns usage; never invents usage.
const PRICE = { input: 1.25, cachedInput: 0.15, output: 4.25 };

const EFFORTS = ['minimal', 'low', 'medium', 'high', 'xhigh', 'max'];

class SparkApiError extends Error {
  constructor({ status, type, code, message, retryable, retryAfterMs }) {
    super(message || `Spark API error (HTTP ${status})`);
    this.name = 'SparkApiError';
    this.status = status;
    this.type = type || null;
    this.code = code || null;
    this.retryable = Boolean(retryable);
    this.retryAfterMs = Number.isFinite(retryAfterMs) ? retryAfterMs : null;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Retry-once backoff: honor the server's Retry-After (capped), else a short fixed delay.
function backoffMs(err) {
  if (err && Number.isFinite(err.retryAfterMs)) return Math.min(Math.max(0, err.retryAfterMs), 10000);
  return 500;
}

function mapError(status, body, retryAfterMs) {
  const err = (body && body.error) || {};
  if (status === 429) {
    return new SparkApiError({
      status, type: err.type || 'rate_limit_error', code: err.code || null,
      message: err.message || 'Rate limited; honor Retry-After and retry with backoff.',
      retryable: true, retryAfterMs
    });
  }
  if (status >= 500) {
    return new SparkApiError({
      status, type: err.type || 'server_error', code: err.code || null,
      message: err.message || `Server error (HTTP ${status}).`,
      retryable: true
    });
  }
  return new SparkApiError({
    status, type: err.type || 'invalid_request_error', code: err.code || null,
    message: err.message || `Request rejected (HTTP ${status}).`,
    retryable: false
  });
}

// Extract the first balanced top-level JSON object from model text. The
// Responses API usually returns pure schema JSON, but live calls prove it can
// prefix prose ("Decoding your approval...\n{...}"). This is repair, not
// fabrication: the candidate must still JSON-parse, and every lane validates
// the parsed object before use. Refusals and truncated output (no balanced
// object) still fail as invalid_response.
function extractBalancedJson(text) {
  const s = String(text || '');
  for (let start = s.indexOf('{'); start !== -1; start = s.indexOf('{', start + 1)) {
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let i = start; i < s.length; i += 1) {
      const ch = s[i];
      if (inString) {
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === '"') inString = false;
      } else if (ch === '"') {
        inString = true;
      } else if (ch === '{') {
        depth += 1;
      } else if (ch === '}') {
        depth -= 1;
        if (depth === 0) {
          try {
            return { ok: true, content: JSON.parse(s.slice(start, i + 1)), repaired: start > 0 || i + 1 < s.length };
          } catch {
            break; // this candidate is corrupt; try a later '{'
          }
        }
      }
    }
  }
  return { ok: false };
}

function truncateErr(err) {
  const msg = (err && err.message) || String(err);
  return msg.length > 200 ? `${msg.slice(0, 200)}…` : msg;
}

function estimateCostUsd(usage) {
  if (!usage) return null;
  const input = usage.input_tokens;
  const output = usage.output_tokens;
  if (!Number.isFinite(input) || !Number.isFinite(output)) return null;
  const cached = (usage.input_tokens_details && usage.input_tokens_details.cached_tokens) || 0;
  const fresh = Math.max(0, input - cached);
  return (fresh * PRICE.input + cached * PRICE.cachedInput + output * PRICE.output) / 1e6;
}

class SparkAdapter {
  constructor({ baseUrl, apiKey, model, promptCacheKey, fetchImpl, defaultTimeoutMs } = {}) {
    this.baseUrl = (baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    this.apiKey = apiKey || '';
    this.model = model || DEFAULT_MODEL;
    this.promptCacheKey = promptCacheKey || 'assertara-investigate';
    this.fetchImpl = fetchImpl || fetch;
    this.defaultTimeoutMs = defaultTimeoutMs || 120000;
  }

  get configured() {
    return Boolean(this.apiKey) && !this.apiKey.includes('your_meta') && !this.apiKey.startsWith('mock_');
  }

  buildBody({ input, schema, schemaName, tools, effort, previousResponseId, maxOutputTokens, stream }) {
    if (!EFFORTS.includes(effort || 'low')) throw new Error(`reasoning effort must be one of ${EFFORTS.join(',')}`);
    const body = { model: this.model, input };
    if (previousResponseId) body.previous_response_id = previousResponseId;
    if (effort) body.reasoning = { effort };
    if (schema) {
      body.text = { format: { type: 'json_schema', name: schemaName || 'assertara_turn', schema, strict: true } };
    }
    if (tools) body.tools = tools;
    if (maxOutputTokens !== undefined) body.max_output_tokens = maxOutputTokens;
    if (this.promptCacheKey) body.prompt_cache_key = this.promptCacheKey;
    if (stream !== undefined) body.stream = stream;
    return body;
  }

  // POST with retry-once for transient failures only (HTTP 429, HTTP 5xx,
  // timeouts). Validation errors and other 4xx responses are never retried.
  async _post(path, bodyObj, timeoutMs) {
    let lastErr;
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(bodyObj),
          signal: controller.signal
        });
        clearTimeout(timer);
        const text = await res.text();
        let data = null;
        try {
          data = text ? JSON.parse(text) : null;
        } catch {
          throw new SparkApiError({ status: res.status, type: 'transport_error', message: `Spark returned an invalid HTTP body (HTTP ${res.status}).`, retryable: false });
        }
        if (!res.ok) {
          const retryAfter = res.headers && typeof res.headers.get === 'function' ? res.headers.get('retry-after') : null;
          throw mapError(res.status, data, retryAfter ? Number(retryAfter) * 1000 : null);
        }
        return { res, data };
      } catch (err) {
        clearTimeout(timer);
        // Type every failure; never let raw fetch errors escape untyped.
        // Retry policy is unchanged: only 429/5xx/timeout retry.
        const normalized = err && err.name === 'AbortError'
          ? new SparkApiError({ status: 0, type: 'timeout', message: `Spark request timed out after ${timeoutMs}ms.`, retryable: true })
          : (err instanceof SparkApiError
            ? err
            : new SparkApiError({ status: 0, type: 'transport_error', message: `Spark transport failed: ${truncateErr(err)}.`, retryable: false }));
        const retryable = normalized instanceof SparkApiError && normalized.retryable;
        if (!retryable || attempt === 2) throw normalized;
        lastErr = normalized;
        await sleep(backoffMs(normalized));
      }
    }
    throw lastErr;
  }

  async request(opts = {}) {
    if (!this.configured) {
      throw new SparkApiError({ status: 0, type: 'configuration_error', message: 'MODEL_API_KEY is missing or a placeholder; live Spark calls are disabled.' });
    }
    const timeoutMs = opts.timeoutMs || this.defaultTimeoutMs;
    const { data } = await this._post('/responses', this.buildBody(opts), timeoutMs);
    return this.normalize(data);
  }

  // Single-shot structured completion. Returns { content, ... } where content
  // is the parsed JSON. Malformed model JSON is a typed, non-retryable error.
  async complete({ system, input, schema, schemaName, effort, previousResponseId, maxOutputTokens, timeoutMs }) {
    const items = [];
    if (system) items.push({ type: 'message', role: 'developer', content: [{ type: 'input_text', text: system }] });
    if (typeof input === 'string') {
      items.push({ type: 'message', role: 'user', content: [{ type: 'input_text', text: input }] });
    } else if (Array.isArray(input)) {
      items.push(...input);
    } else {
      throw new Error('complete: input must be a string or item array');
    }
    const res = await this.request({ input: items, schema, schemaName, effort: effort || 'low', previousResponseId, maxOutputTokens, timeoutMs });
    // Attempt provenance rides on every content-level throw so callers can
    // account for (and chain off) failed attempts instead of losing them.
    const attempt = { responseId: res.id || null, usage: res.usage || null, estimatedCostUsd: res.estimatedCostUsd ?? null };
    if (res.refusal) {
      const err = new SparkApiError({ status: 200, type: 'refusal', message: 'Spark refused the request; refusal text is not echoed.' });
      err.attempt = attempt;
      throw err;
    }
    if (res.incomplete) {
      const err = new SparkApiError({ status: 200, type: 'truncated_response', message: `Spark response incomplete (reason: ${res.incomplete.reason}); not safely validatable.` });
      err.attempt = attempt;
      throw err;
    }
    const extracted = extractBalancedJson(res.text);
    if (!extracted.ok) {
      const err = new SparkApiError({ status: 200, type: 'invalid_response', message: 'Spark returned malformed JSON for a schema-constrained request.' });
      err.attempt = attempt;
      throw err;
    }
    return { content: extracted.content, repaired: extracted.repaired, usage: res.usage, estimatedCostUsd: res.estimatedCostUsd, responseId: res.id };
  }

  // Preflight: exact input-token count + request validation, no generation.
  // Same retry-once policy as request().
  async preflightCount({ input, tools, previousResponseId, timeoutMs }) {
    if (!this.configured) {
      throw new SparkApiError({ status: 0, type: 'configuration_error', message: 'MODEL_API_KEY is missing; preflight disabled.' });
    }
    const { data } = await this._post(
      '/responses/input_tokens',
      { model: this.model, input, ...(tools ? { tools } : {}), ...(previousResponseId ? { previous_response_id: previousResponseId } : {}) },
      timeoutMs || this.defaultTimeoutMs
    );
    return data && Number.isFinite(data.input_tokens) ? data.input_tokens : null;
  }

  // Normalize to the shape the orchestrator consumes. Keeps raw output items
  // for reasoning replay; extracts text, tool calls, usage, response id.
  normalize(data) {
    const output = (data && data.output) || [];
    const texts = [];
    const toolCalls = [];
    let reasoningItems = [];
    let refused = false;
    for (const item of output) {
      if (!item || typeof item !== 'object') continue;
      if (item.type === 'reasoning') reasoningItems.push(item);
      // Structural refusal signals only (item/block type + incomplete status
      // below) — never guessed from message text.
      if (item.type === 'refusal') refused = true;
      if (item.type === 'message' && Array.isArray(item.content)) {
        for (const block of item.content) {
          if (block && (block.type === 'output_text' || block.type === 'text') && typeof block.text === 'string') {
            texts.push(block.text);
          }
          if (block && block.type === 'refusal') refused = true;
        }
      }
      if (item.type === 'function_call') {
        toolCalls.push({
          callId: item.call_id || item.id || null,
          name: item.name || null,
          // Arguments arrive as a JSON string per the Responses protocol.
          argsRaw: typeof item.arguments === 'string' ? item.arguments : JSON.stringify(item.arguments ?? {})
        });
      }
    }
    const incomplete = data && data.status === 'incomplete'
      ? { reason: (data.incomplete_details && data.incomplete_details.reason) || 'unknown' }
      : null;
    return {
      id: data && data.id ? data.id : null,
      status: data && data.status ? data.status : null,
      text: texts.join('\n'),
      toolCalls,
      reasoningItems,
      refusal: refused,
      incomplete,
      usage: (data && data.usage) || null,
      estimatedCostUsd: estimateCostUsd(data && data.usage),
      cachedTokens: data && data.usage && data.usage.input_tokens_details
        ? data.usage.input_tokens_details.cached_tokens || 0
        : 0
    };
  }
}

module.exports = { SparkAdapter, SparkApiError, estimateCostUsd, EFFORTS, PRICE };
