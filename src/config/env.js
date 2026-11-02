require('dotenv').config();

const { parseTimeoutMs } = require('./validate');

const config = {
  port: parseInt(process.env.PORT, 10) || 3001,
  nodeEnv: process.env.NODE_ENV || 'development',
  modelApiKey: process.env.MODEL_API_KEY || '',
  metaApiBaseUrl: process.env.META_API_BASE_URL || 'https://api.meta.ai/v1',
  samModel: process.env.SAM_MODEL || 'sam-3.1',
  museModel: process.env.MUSE_MODEL || 'muse-spark-1.3',
  // Fix 3: per-request bounds (ms) for production SAM/Muse calls. Observed
  // live latency is ~2s per SAM prompt and ~13s per full evaluation; the
  // defaults leave wide headroom while preventing indefinite hangs.
  // Invalid values sanitize to the defaults (see validate.js) instead of
  // silently becoming near-zero timeouts.
  samTimeoutMs: parseTimeoutMs(process.env.SAM_TIMEOUT_MS, 30000),
  museTimeoutMs: parseTimeoutMs(process.env.MUSE_TIMEOUT_MS, 60000),
  // Capability 2: explicit output-token limit for investigation responses.
  // muse-spark-1.3 is a reasoning model: it spends hidden reasoning
  // tokens BEFORE emitting content (observed ~4000 reasoning tokens on
  // a methodology-heavy prompt), so the cap must cover reasoning PLUS
  // the structured output — a small cap yields finish_reason=length
  // with empty content. Raised 16000 -> 24000 for the investigate-2.7
  // prompt: hard scenarios intermittently exhausted 16k mid-JSON
  // (labeled fallback, safe direction). Invalid values sanitize to
  // the default.
  museMaxTokens: parseTimeoutMs(process.env.MUSE_MAX_TOKENS, 24000),
  // Evidence Assembly (Phase B): optional chain RPC for investigation-time
  // state reads, screenshot freshness bound, and operator label file. All
  // optional — absence yields explicit unavailable statuses, never failure.
  evidenceChainRpcUrl: typeof process.env.EVIDENCE_CHAIN_RPC_URL === 'string' && process.env.EVIDENCE_CHAIN_RPC_URL.length > 0
    ? process.env.EVIDENCE_CHAIN_RPC_URL : null,
  evidenceChainTimeoutMs: parseTimeoutMs(process.env.EVIDENCE_CHAIN_TIMEOUT_MS, 8000),
  screenshotMaxAgeMs: parseTimeoutMs(process.env.SCREENSHOT_MAX_AGE_MS, 300000),
  counterpartyLabelsFile: typeof process.env.COUNTERPARTY_LABELS_FILE === 'string' && process.env.COUNTERPARTY_LABELS_FILE.length > 0
    ? process.env.COUNTERPARTY_LABELS_FILE : null,
  // Capability 3 B1: append-only investigation record store (JSONL).
  investigationsFile: typeof process.env.INVESTIGATIONS_FILE === 'string' && process.env.INVESTIGATIONS_FILE.length > 0
    ? process.env.INVESTIGATIONS_FILE : 'data/investigations.jsonl',
  // Capability 4 B5: contract identity verification. External directory
  // lookups are bounded and failure-safe; each can be disabled outright
  // by setting its flag to '0'/'false'. Bytecode refs are an optional
  // operator file (chain → address → codeHash); absence skips the tier.
  selectorLookupEnabled: process.env.SELECTOR_LOOKUP_ENABLED !== '0' && process.env.SELECTOR_LOOKUP_ENABLED !== 'false',
  selectorLookupTimeoutMs: parseTimeoutMs(process.env.SELECTOR_LOOKUP_TIMEOUT_MS, 2500),
  sourcifyLookupEnabled: process.env.SOURCIFY_LOOKUP_ENABLED !== '0' && process.env.SOURCIFY_LOOKUP_ENABLED !== 'false',
  sourcifyLookupTimeoutMs: parseTimeoutMs(process.env.SOURCIFY_LOOKUP_TIMEOUT_MS, 2500),
  contractBytecodeRefsFile: typeof process.env.CONTRACT_BYTECODE_REFS_FILE === 'string' && process.env.CONTRACT_BYTECODE_REFS_FILE.length > 0
    ? process.env.CONTRACT_BYTECODE_REFS_FILE : null,
  // Capability 4 B8: bounded transaction-history window. Chain event
  // logs cover the last HISTORY_BLOCK_WINDOW blocks; at most
  // HISTORY_MAX_ENTRIES entries reach the investigator. Set the flag
  // to '0'/'false' to disable history assembly.
  historyEnabled: process.env.HISTORY_ENABLED !== '0' && process.env.HISTORY_ENABLED !== 'false',
  historyBlockWindow: (() => {
    const n = Number.parseInt(process.env.HISTORY_BLOCK_WINDOW || '', 10);
    return Number.isSafeInteger(n) ? Math.min(50000, Math.max(100, n)) : 2000;
  })(),
  historyMaxEntries: (() => {
    const n = Number.parseInt(process.env.HISTORY_MAX_ENTRIES || '', 10);
    return Number.isSafeInteger(n) ? Math.min(32, Math.max(1, n)) : 8;
  })(),
};

module.exports = config;
