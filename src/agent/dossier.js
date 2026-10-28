/**
 * Assertara Contract Dossier Builder (F7) — structured evidence gathering.
 * Internal service only: no routes, no UI.
 *
 * buildDossier assembles nine sections for a contract address: identity,
 * bytecode, verified source, ABI, privileges, proxy indicators, history,
 * limitations, and risk observations. Every section/item carries a standing:
 * OBSERVED (retrieved data), INFERRED (derived from documented evidence),
 * UNAVAILABLE (could not retrieve), or UNRESOLVED (insufficient evidence).
 * The dossier assigns NO finding statuses and CANNOT produce VERIFIED —
 * verification stays with the verifier/ledger over their own evidence.
 *
 * Data reality in this environment: on-chain reads (bytecode, proxy slots,
 * history) work via the configured RPC; NO verified-source provider is
 * configured, so source sections honestly report UNAVAILABLE unless the
 * caller injects a sourceProvider or supplies an ABI (labeled PROVIDED,
 * never verified). The source-provider contract is documented in
 * contracts.md §16.
 */

const crypto = require('crypto');
const { keccak256, toHex } = require('viem');
const { readContractMeta, discoverApprovals, withRetryOnce } = require('./chain');

const STANDINGS = ['OBSERVED', 'INFERRED', 'UNAVAILABLE', 'UNRESOLVED'];

// EIP-1967 beacon slot, computed definitionally (never hardcoded from memory).
const BEACON_SLOT = `0x${(BigInt(keccak256(toHex('eip1967.proxy.beacon'))) - 1n).toString(16).padStart(64, '0')}`;
const MINIMAL_PROXY_PREFIX = '0x363d3d373d3d3d363d73';

function dossierError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function isAddress(value) {
  return /^0x[0-9a-fA-F]{40}$/.test(String(value || '').trim());
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function functionSelector(name, inputs) {
  const sig = `${name}(${(inputs || []).map((i) => i.type).join(',')})`;
  return { signature: sig, selector: keccak256(toHex(sig)).slice(0, 10) };
}

// ---- ABI handling ----

function parseAbi(abi, origin) {
  const list = Array.isArray(abi) ? abi : (abi && Array.isArray(abi.abi) ? abi.abi : null);
  if (!list) throw dossierError('MALFORMED_ABI', `${origin}: ABI must be an array of entries`);
  const functions = [];
  let events = 0;
  for (const entry of list) {
    if (!entry || typeof entry !== 'object') throw dossierError('MALFORMED_ABI', `${origin}: ABI entries must be objects`);
    if (entry.type === 'function') {
      if (typeof entry.name !== 'string' || !Array.isArray(entry.inputs)) {
        throw dossierError('MALFORMED_ABI', `${origin}: function entries need name + inputs`);
      }
      const { signature, selector } = functionSelector(entry.name, entry.inputs);
      functions.push({
        name: entry.name,
        signature,
        selector,
        inputs: entry.inputs.map((i) => ({ name: i.name || '', type: i.type })),
        outputs: Array.isArray(entry.outputs) ? entry.outputs.map((o) => ({ name: o.name || '', type: o.type })) : [],
        stateMutability: entry.stateMutability || 'unknown',
        payable: entry.stateMutability === 'payable'
      });
    } else if (entry.type === 'event') {
      events += 1;
    }
  }
  return { functions, events, entries: list.length };
}

// ---- Deterministic privilege-pattern scans (leads, never verdicts) ----

const SOURCE_PATTERNS = [
  { indicator: 'owner-restricted-functions', re: /\bonlyOwner\b/, note: 'Functions gated by onlyOwner.' },
  { indicator: 'role-restricted-functions', re: /\bonlyRole\b|hasRole\s*\(|AccessControl/, note: 'Role-based access control usage.' },
  { indicator: 'ownership-transfer', re: /transferOwnership|renounceOwnership/, note: 'Ownership can change hands.' },
  { indicator: 'minting-controls', re: /function\s+mint\b|_mint\s*\(/, note: 'Token minting entry points.' },
  { indicator: 'pausing-controls', re: /function\s+(pause|unpause)\b|_pause\s*\(|_unpause\s*\(/, note: 'Pause/unpause controls.' },
  { indicator: 'blocklist-controls', re: /blacklist|blocklist/i, note: 'Blocklist-related logic.' },
  { indicator: 'emergency-controls', re: /emergency|circuitBreaker/i, note: 'Emergency-path logic.' },
  { indicator: 'upgrade-admin', re: /upgradeTo|upgradeProxy|ProxyAdmin/, note: 'Upgrade-path references.' },
  { indicator: 'delegatecall-usage', re: /\.delegatecall\s*[\({]/, note: 'delegatecall usage (context needed).' },
  { indicator: 'selfdestruct-usage', re: /selfdestruct\s*\(/, note: 'selfdestruct usage.' },
  { indicator: 'external-calls', re: /\.call\s*\{\s*value|\.call\s*\(/, note: 'Low-level external calls.' }
];

const ABI_NAME_PATTERNS = [
  { indicator: 'owner-restricted-functions', re: /^(owner|getOwner)$/i, note: 'Ownership interface present (name-only).' },
  { indicator: 'ownership-transfer', re: /^(transferOwnership|renounceOwnership|setOwner|nominateOwner)$/i, note: 'Ownership-change function present (name-only).' },
  { indicator: 'minting-controls', re: /^mint/i, note: 'Mint-named function present (name-only, not behavior proof).' },
  { indicator: 'pausing-controls', re: /^(pause|unpause|paused)$/i, note: 'Pause-named function present (name-only).' },
  { indicator: 'blocklist-controls', re: /blacklist|blocklist/i, note: 'Blocklist-named function present (name-only).' },
  { indicator: 'emergency-controls', re: /emergency/i, note: 'Emergency-named function present (name-only).' },
  { indicator: 'upgrade-admin', re: /^(upgradeTo|upgradeProxy|upgradeToAndCall|setImplementation)$/i, note: 'Upgrade-named function present (name-only).' },
  { indicator: 'role-restricted-functions', re: /^(grantRole|revokeRole|hasRole|getRoleAdmin)$/i, note: 'AccessControl-style interface present (name-only).' }
];

function scanSourcePrivileges(sourceFiles) {
  const observations = [];
  for (const { indicator, re, note } of SOURCE_PATTERNS) {
    const refs = [];
    for (const f of sourceFiles) {
      const lines = f.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (re.test(lines[i])) refs.push(`${f.path}:${i + 1}`);
        if (refs.length >= 10) break;
      }
      if (refs.length >= 10) break;
    }
    if (refs.length > 0) {
      observations.push({ indicator, standing: 'INFERRED', basis: 'source', evidence: refs, note });
    }
  }
  return observations;
}

function scanAbiPrivileges(functions) {
  const observations = [];
  for (const { indicator, re, note } of ABI_NAME_PATTERNS) {
    const refs = functions.filter((f) => re.test(f.name)).map((f) => `${f.signature} [${f.selector}]`);
    if (refs.length > 0) {
      observations.push({ indicator, standing: 'INFERRED', basis: 'abi', evidence: refs.slice(0, 10), note });
    }
  }
  return observations;
}

// ---- Source provider handling ----

function normalizeSourceFiles(raw, providerName) {
  // Etherscan shape: SourceCode is a string (single file) or {sources:{...}}
  // JSON (multi-file). Anything else is a provider-data fault, not dossier death.
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed.slice(0, 2000000));
        if (parsed && typeof parsed === 'object' && parsed.sources && typeof parsed.sources === 'object') {
          return Object.entries(parsed.sources)
            .filter(([, v]) => v && typeof v.content === 'string')
            .map(([path, v]) => ({ path: String(path).slice(0, 300), content: v.content.slice(0, 500000) }));
        }
      } catch {
        return null;
      }
      return null;
    }
    if (trimmed.length === 0) return null;
    return [{ path: 'Contract.sol', content: trimmed.slice(0, 500000) }];
  }
  return null;
}

/**
 * Build a structured contract dossier.
 * @param {{ address, chainId?, client?, rpcUrl?, sourceProvider?, abi?, history?: {tokens?, fromBlock?, toBlock?, maxLogs?}|false }} input
 * @param {{ sleep? }} deps
 */
async function buildDossier(input, deps = {}) {
  const { address, chainId = 1, client, rpcUrl, sourceProvider, abi: callerAbi, history } = input || {};
  if (!isAddress(address)) throw dossierError('BAD_ADDRESS', 'buildDossier: address must be a 0x address');
  if (!Number.isInteger(chainId) || chainId < 1) throw dossierError('BAD_CHAIN', 'buildDossier: chainId must be a positive integer');
  const normAddress = address.toLowerCase();
  const sleep = deps.sleep || undefined;
  const retried = (fn) => withRetryOnce(fn, sleep ? { sleep } : {});

  // §1 identity + §2 bytecode + §6 proxy slots (core: failures propagate).
  const c = client || null;
  const meta = await retried(() => readContractMeta({ address, client: c || undefined, rpcUrl }));
  let live = null;
  if (!c) {
    const { createPublicClient, http } = require('viem');
    const config = require('../config/env');
    live = createPublicClient({ transport: http(rpcUrl || config.ethereumRpcUrl) });
  }
  const reader = c && typeof c.getStorageAt === 'function' ? c : live;
  let beacon = null;
  if (reader) {
    const slot = await retried(() => reader.getStorageAt({ address, slot: BEACON_SLOT }));
    beacon = !slot || /^0x0+$/.test(slot) ? null : `0x${slot.slice(-40)}`;
  }
  let chainVerified = false;
  if (c && typeof c.getChainId === 'function') {
    const providerChain = Number(await c.getChainId());
    if (providerChain !== chainId) throw dossierError('CHAIN_MISMATCH', `provider chain ${providerChain} does not match requested chain ${chainId}`);
    chainVerified = true;
  }

  const byteReader = c && typeof c.getBytecode === 'function' ? c : live;
  const bytecode = meta.hasCode && byteReader ? await retried(() => byteReader.getBytecode({ address })) : null;
  const codeHash = bytecode && bytecode !== '0x' ? keccak256(bytecode) : null;

  // Minimal-proxy (EIP-1167) bytecode pattern.
  let minimalProxy = null;
  if (bytecode && bytecode.toLowerCase().startsWith(MINIMAL_PROXY_PREFIX)) {
    const hex = bytecode.toLowerCase().slice(2);
    minimalProxy = hex.length >= 80 ? `0x${hex.slice(20, 60)}` : null;
  }
  const proxyIndicated = Boolean(meta.eip1967Implementation || meta.eip1967Admin || beacon || minimalProxy);

  // §3 verified source (auxiliary: failures become UNAVAILABLE, never fatal).
  let source = {
    standing: 'UNAVAILABLE',
    reason: 'no-source-provider-configured',
    requirements: ['A source-provider adapter implementing the contracts §16 fetch contract (none is configured).']
  };
  let providerAbi = null;
  let sourceFiles = [];
  if (sourceProvider && typeof sourceProvider.fetch === 'function') {
    try {
      const fetched = await sourceProvider.fetch({ address, chainId });
      const files = normalizeSourceFiles(fetched && fetched.SourceCode, sourceProvider.name || 'unnamed-provider');
      if (!files || files.length === 0) {
        source = { standing: 'UNAVAILABLE', reason: 'provider-returned-no-source', provider: sourceProvider.name || 'unnamed-provider' };
      } else {
        sourceFiles = files;
        if (fetched.ABI) {
          try { providerAbi = parseAbi(typeof fetched.ABI === 'string' ? JSON.parse(fetched.ABI.slice(0, 2000000)) : fetched.ABI, 'provider-abi'); }
          catch { providerAbi = null; }
        }
        source = {
          standing: 'OBSERVED',
          provider: sourceProvider.name || 'unnamed-provider',
          contractName: typeof fetched.ContractName === 'string' ? fetched.ContractName.slice(0, 200) : null,
          compilerVersion: typeof fetched.CompilerVersion === 'string' ? fetched.CompilerVersion.slice(0, 100) : null,
          licenseType: typeof fetched.LicenseType === 'string' ? fetched.LicenseType.slice(0, 100) : null,
          fileCount: files.length,
          sourceHash: sha256Hex(files.map((f) => `${f.path}\n${f.content}`).join('\n')),
          fetchedAt: new Date().toISOString()
        };
      }
    } catch (err) {
      source = {
        standing: 'UNAVAILABLE',
        reason: 'provider-fetch-failed',
        provider: sourceProvider.name || 'unnamed-provider',
        error: String(err && err.message || err).slice(0, 300)
      };
    }
  }

  // §4 ABI: caller-supplied (labeled PROVIDED) wins over provider ABI.
  let abiSection;
  let functions = [];
  if (callerAbi !== undefined) {
    const parsed = parseAbi(callerAbi, 'caller-abi'); // malformed caller ABI throws loudly
    functions = parsed.functions;
    abiSection = { standing: 'OBSERVED', origin: 'PROVIDED', functionCount: parsed.functions.length, events: parsed.events, functions: parsed.functions };
  } else if (providerAbi) {
    functions = providerAbi.functions;
    abiSection = { standing: 'OBSERVED', origin: 'verified-source', functionCount: providerAbi.functions.length, events: providerAbi.events, functions: providerAbi.functions };
  } else {
    abiSection = {
      standing: source.standing === 'OBSERVED' ? 'UNRESOLVED' : 'UNAVAILABLE',
      reason: source.standing === 'OBSERVED' ? 'source-present-but-no-abi' : 'no-source-and-no-provided-abi'
    };
  }

  // §5 privileges from the strongest available basis.
  let privileges;
  if (sourceFiles.length > 0) {
    privileges = { standing: 'INFERRED', basis: 'source', observations: scanSourcePrivileges(sourceFiles) };
  } else if (functions.length > 0) {
    privileges = { standing: 'INFERRED', basis: 'abi', observations: scanAbiPrivileges(functions) };
  } else {
    privileges = { standing: 'UNRESOLVED', reason: 'privilege-analysis-needs-source-or-abi', observations: [] };
  }

  // §7 history via the Sentinel discovery path (auxiliary: failures contained).
  let historySection = { standing: 'UNAVAILABLE', reason: 'history-disabled' };
  if (history !== false) {
    const opts = (history && typeof history === 'object') ? history : {};
    try {
      const { discoverApprovals, computeExposure } = require('./chain');
      const found = await discoverApprovals({
        owner: address, chainId, client: c || undefined, rpcUrl,
        tokens: opts.tokens, fromBlock: opts.fromBlock, toBlock: opts.toBlock, maxLogs: opts.maxLogs || 100,
        ...(sleep ? { sleep } : {})
      });
      if (found.coverage.status === 'HISTORY_UNAVAILABLE') {
        historySection = {
          standing: 'UNAVAILABLE',
          reason: 'history-query-failed',
          coverage: found.coverage.status,
          errors: found.coverage.errors.slice(0, 5)
        };
      } else {
        historySection = {
          standing: 'OBSERVED',
          scopeNote: 'Approvals granted BY this address (owner-side). Approvals granted TO it by others are out of scope.',
          approvalCount: found.approvals.length,
          exposure: computeExposure(found.approvals),
          coverage: found.coverage.status,
          gaps: found.coverage.gaps.length,
          sample: found.approvals.slice(0, 5).map((a) => ({ token: a.token, spender: a.spender, txHash: a.txHash, logIndex: a.logIndex }))
        };
      }
    } catch (err) {
      historySection = { standing: 'UNAVAILABLE', reason: 'history-query-failed', error: String(err && err.message || err).slice(0, 300) };
    }
  }

  // §8 limitations.
  const limitations = [];
  if (source.standing !== 'OBSERVED') limitations.push({ scope: 'source', reason: source.reason || 'unavailable', question: 'Is verified source retrievable from a configured provider?' });
  if (abiSection.standing !== 'OBSERVED') limitations.push({ scope: 'abi', reason: abiSection.reason || 'unavailable', question: 'Can an ABI be supplied or retrieved for selector-level analysis?' });
  if (privileges.standing === 'UNRESOLVED') limitations.push({ scope: 'privileges', reason: privileges.reason, question: 'Which privileged functions exist? Needs source or ABI.' });
  if (historySection.standing !== 'OBSERVED') limitations.push({ scope: 'history', reason: historySection.reason, question: 'What approval activity involves this address?' });
  else if (historySection.coverage !== 'COMPLETE_WITHIN_REQUESTED_SCOPE') limitations.push({ scope: 'history', reason: `coverage-${historySection.coverage.toLowerCase()}`, question: 'What activity hides in the uncovered ranges?' });
  if (!meta.hasCode) limitations.push({ scope: 'contract', reason: 'no-bytecode', question: 'Address holds no code (EOA or undeployed). Nothing further to analyze on-chain.' });
  if (proxyIndicated && !meta.eip1967Implementation && !minimalProxy) limitations.push({ scope: 'proxy', reason: 'implementation-unresolved', question: 'Proxy indicated but implementation address not resolved.' });
  if (meta.hasCode && !proxyIndicated) limitations.push({ scope: 'proxy', reason: 'non-1967-patterns-unresolved', question: 'No EIP-1967/EIP-1167 indicators; bespoke proxy layouts (e.g. pre-1967) are not detectable from slots alone.' });

  // §9 risk observations (INFERRED leads with evidence; never verdicts).
  const riskObservations = [];
  const OBS_CAP = 20;
  const pushRisk = (o) => { if (riskObservations.length < OBS_CAP) riskObservations.push({ standing: 'INFERRED', severity: 'notable', ...o }); };
  if (!meta.hasCode) {
    pushRisk({ observation: 'Address holds no bytecode.', severity: 'info', basis: 'bytecode-absence', evidence: [`${normAddress} eth_getCode=0x`] });
  }
  if (meta.eip1967Implementation) {
    pushRisk({ observation: `EIP-1967 proxy delegating to ${meta.eip1967Implementation}.`, basis: 'proxy-slot', evidence: [`${normAddress} eip1967Implementation=${meta.eip1967Implementation}`] });
  }
  if (meta.eip1967Admin) {
    pushRisk({ observation: `EIP-1967 proxy admin is ${meta.eip1967Admin}.`, basis: 'proxy-slot', evidence: [`${normAddress} eip1967Admin=${meta.eip1967Admin}`] });
  }
  if (beacon) {
    pushRisk({ observation: `EIP-1967 beacon at ${beacon}.`, basis: 'proxy-slot', evidence: [`${normAddress} eip1967Beacon=${beacon}`] });
  }
  if (minimalProxy) {
    pushRisk({ observation: `EIP-1167 minimal proxy forwarding to ${minimalProxy}.`, basis: 'bytecode-pattern', evidence: [`${normAddress} minimal-proxy-prefix`] });
  }
  for (const p of privileges.observations || []) {
    pushRisk({ observation: `${p.indicator}: ${p.note}`, basis: p.basis, evidence: p.evidence.slice(0, 5) });
  }
  if (historySection.standing === 'OBSERVED' && historySection.exposure && historySection.exposure.unlimitedCount > 0) {
    pushRisk({
      observation: `${historySection.exposure.unlimitedCount} unlimited approval(s) granted by this address.`,
      basis: 'history',
      evidence: (historySection.sample || []).filter((s) => s.txHash).map((s) => `${s.txHash}:${s.logIndex}`).slice(0, 5)
    });
  }

  return {
    feature: 'F7_dossier',
    identity: { address: normAddress, chainId, chainVerified },
    bytecode: meta.hasCode
      ? { standing: 'OBSERVED', hasCode: true, bytecodeLength: meta.bytecodeLength, codeHash }
      : { standing: 'OBSERVED', hasCode: false, note: 'Observed absence: eth_getCode returned 0x.' },
    meta: { ...meta, eip1967Beacon: beacon },
    source,
    abi: abiSection,
    privileges,
    proxy: {
      standing: 'OBSERVED',
      eip1967Implementation: meta.eip1967Implementation,
      eip1967Admin: meta.eip1967Admin,
      eip1967Beacon: beacon,
      minimalProxyImplementation: minimalProxy,
      assessment: proxyIndicated ? 'proxy-indicated' : 'no-proxy-indicators'
    },
    history: historySection,
    limitations,
    riskObservations,
    builtAt: new Date().toISOString()
  };
}

module.exports = { buildDossier, parseAbi, scanSourcePrivileges, scanAbiPrivileges, STANDINGS, BEACON_SLOT, MINIMAL_PROXY_PREFIX };
