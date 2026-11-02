/**
 * Narrow bridge transaction understanding (Capability 5, B5).
 *
 * Deterministic extraction + comparison of bridge-deposit terms for
 * exactly two protocols:
 *
 * - Across V3 `depositV3` (all terms explicit in calldata);
 * - Circle CCTP V1 `depositForBurn` (destination via domain map).
 *
 * A deposit is SUPPORTED only when the decoded function matches AND
 * the target equals the canonical contract for the source chain.
 * Anything else bridge-shaped (unknown contract, unknown chain,
 * undecodable terms, unmapped domain) is reported UNSUPPORTED with
 * the exact reason — never silently treated as understood, never
 * force-fit into a protocol.
 *
 * Canonical addresses are RPC-verified values from the dedaub
 * protocol reference (2026-06-09/2026-10-05 reads), cross-checked
 * against block-explorer labels and independent integration tables.
 * Across SpokePools are chain-unique UUPS proxies; CCTP V1
 * TokenMessengers are chain-unique non-proxies. Out of scope by
 * design: Across bytes32 `deposit(...)`, speed-ups, fills, CCTP V2,
 * and every other bridge protocol.
 *
 * Pure and deterministic. Never throws on malformed input: bad
 * shapes yield explicit unsupported statuses, and non-bridge
 * transactions yield null.
 */

const ACROSS_V3_SPOKEPOOLS = {
  1: '0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5',
  8453: '0x09aea4b2242abc8bb4bb78d537a67a245a7bec64',
  56: '0x4e8e101924ede233c13e2d8622dc8aed2872d505',
  42161: '0xe35e9842fceaca96570b734083f4a58e8f7c5f2a',
  10: '0x6f26bf09b1c792e3228e5467807a900a503c0281',
  137: '0x9295ee1d8c5b022be115a2ad3c30c72e34e7f096',
  43114: '0xfe9d541c92e4e90437c7152a00244886de37a658',
  4663: '0xd29c85f15df544ba632c9e25829fd29d767d7978',
  5042: '0x9b4a302a548c7e313c2b74c461db7b84d3074a84'
};

const CCTP_V1_MESSENGERS = {
  1: '0xbd3fa81b58ba92a82136038b25adec7066af3155',
  43114: '0x6b25532e1060ce10cc3b0a99e5683b91bfde6982',
  10: '0x2b4069517957735be00cee0fadae88a26365528f',
  42161: '0x19330d10d9cc8751218eaf51e8885d058642e08a',
  8453: '0x1682ae6375c4e4a97e4b583bc394c861a46d8962',
  137: '0x9daf8c91aefae50b9c0e69629d3f6ca40ca3b3fe'
};

// CCTP V1 domain -> EVM chain id. Domains outside this map
// (Noble, Solana, ...) have no EVM destination chain and stay
// unestablished: the burn is understood, its destination is not.
const CCTP_DOMAIN_TO_CHAIN = {
  0: '1', 1: '43114', 2: '10', 3: '42161', 6: '8453', 7: '137'
};

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

function lowerAddr(v) {
  return typeof v === 'string' && ADDRESS_RE.test(v) ? v.toLowerCase() : null;
}

function exactUint(v) {
  try {
    if (typeof v === 'bigint') return v >= 0n ? v.toString() : null;
    if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? String(v) : null;
    if (typeof v === 'string') {
      const s = v.trim();
      if (/^[0-9]+$/.test(s)) return BigInt(s).toString();
      if (/^0[xX][0-9a-fA-F]+$/.test(s)) return BigInt(s).toString();
    }
  } catch { /* fall through */ }
  return null;
}

function chainKey(chainId) {
  const dec = exactUint(chainId);
  return dec === null ? null : dec;
}

// bytes32 mintRecipient -> EVM address when left-padded (12 zero
// bytes + 20 address bytes). Anything else (Solana-style full-width
// recipients, garbage) stays unestablished.
function bytes32ToAddress(v) {
  if (typeof v !== 'string') return null;
  const m = /^0x0{24}([0-9a-fA-F]{40})$/.exec(v.trim());
  return m ? `0x${m[1]}`.toLowerCase() : null;
}

function messageNonEmpty(v) {
  return typeof v === 'string' && v.startsWith('0x') && v.length > 2;
}

function finding(ruleId, severity, description, metadata) {
  return { ruleId, severity, description, triggered: true, metadata: metadata || {} };
}

function unsupported(protocol, reason, metadata) {
  return {
    status: 'unsupported',
    protocol,
    reason,
    terms: null,
    notes: [reason],
    finding: finding(
      'BRIDGE_UNVERIFIED_CONTRACT',
      'HIGH',
      `Bridge-shaped ${protocol} call cannot be understood: ${reason} Destination outcome unestablished; held for review.`,
      { protocol, ...(metadata || {}) }
    )
  };
}

function analyzeAcross({ decodedTx, target, sourceChain }) {
  const p = decodedTx.parameters || {};
  const inputToken = lowerAddr(p.inputToken);
  const outputToken = lowerAddr(p.outputToken);
  const inputAmount = exactUint(p.inputAmount);
  const outputAmount = exactUint(p.outputAmount);
  const destinationChainId = exactUint(p.destinationChainId);
  const recipient = lowerAddr(p.recipient);
  const depositor = lowerAddr(p.depositor);
  const exclusiveRelayer = lowerAddr(p.exclusiveRelayer);
  const quoteTimestamp = exactUint(p.quoteTimestamp);
  const fillDeadline = exactUint(p.fillDeadline);
  const exclusivityDeadline = exactUint(p.exclusivityDeadline);
  const hasMessage = messageNonEmpty(p.message);

  const missing = [];
  if (!inputToken) missing.push('inputToken');
  if (!outputToken) missing.push('outputToken');
  if (inputAmount === null) missing.push('inputAmount');
  if (outputAmount === null) missing.push('outputAmount');
  if (destinationChainId === null) missing.push('destinationChainId');
  if (!recipient) missing.push('recipient');
  if (missing.length > 0) {
    return unsupported('across-v3',
      `canonical SpokePool but undecodable terms (${missing.join(', ')}).`,
      { target, sourceChain });
  }

  const notes = [];
  if (inputToken !== outputToken) notes.push('cross-token route: input and output assets differ (relayer swap on delivery)');
  if (hasMessage) notes.push('non-empty message: arbitrary destination-side execution accompanies the fill');
  if (exclusiveRelayer && exclusiveRelayer !== ZERO_ADDRESS) notes.push(`exclusive relayer ${exclusiveRelayer} until ${exclusivityDeadline === null ? 'undecodable deadline' : exclusivityDeadline}`);
  if (destinationChainId === sourceChain) notes.push('destination chain equals source chain: unusual route, terms still extracted as stated');
  notes.push('destination delivery is a relayer fill, not an atomic leg: source execution never proves destination receipt');

  const terms = {
    protocol: 'across-v3',
    sourceChain,
    destinationChain: destinationChainId,
    sourceAsset: { contract: inputToken },
    destinationAsset: { contract: outputToken },
    amount: inputAmount,
    expectedOutput: outputAmount,
    destinationRecipient: recipient,
    depositor,
    exclusiveRelayer,
    quoteTimestamp,
    fillDeadline,
    exclusivityDeadline,
    hasMessage
  };
  return {
    status: 'supported',
    protocol: 'across-v3',
    reason: null,
    terms,
    notes,
    finding: finding(
      'BRIDGE_DEPOSIT',
      'HIGH',
      `Across V3 bridge deposit: ${inputAmount} of ${inputToken} from chain ${sourceChain} to ${outputAmount} of ${outputToken} `
        + `on chain ${destinationChainId} for ${recipient} (fill deadline ${fillDeadline === null ? 'undecodable' : fillDeadline}). `
        + `Destination delivery is a later relayer fill — source execution never proves receipt. Held for review.`,
      { protocol: 'across-v3', target, sourceChain, destinationChain: destinationChainId }
    )
  };
}

function analyzeCctp({ decodedTx, target, sourceChain }) {
  const p = decodedTx.parameters || {};
  const amount = exactUint(p.amount);
  const domain = exactUint(p.destinationDomain);
  const burnToken = lowerAddr(p.burnToken);
  const recipient = bytes32ToAddress(p.mintRecipient);

  const missing = [];
  if (amount === null) missing.push('amount');
  if (domain === null) missing.push('destinationDomain');
  if (!burnToken) missing.push('burnToken');
  if (missing.length > 0) {
    return unsupported('cctp-v1',
      `canonical TokenMessenger but undecodable terms (${missing.join(', ')}).`,
      { target, sourceChain });
  }
  const destinationChain = Object.prototype.hasOwnProperty.call(CCTP_DOMAIN_TO_CHAIN, domain)
    ? CCTP_DOMAIN_TO_CHAIN[domain]
    : null;
  if (destinationChain === null) {
    return unsupported('cctp-v1',
      `destination domain ${domain} maps to no known EVM chain; destination outcome unestablished.`,
      { target, sourceChain, domain });
  }
  if (recipient === null) {
    return unsupported('cctp-v1',
      'mintRecipient is not a left-padded EVM address; destination recipient unestablished.',
      { target, sourceChain, domain });
  }

  const notes = [
    'destination mints native USDC on the destination chain (contract unestablished there)',
    'destination mint follows attestation: source execution never proves destination receipt'
  ];
  if (destinationChain === sourceChain) notes.push('destination chain equals source chain: unusual route, terms still extracted as stated');

  const terms = {
    protocol: 'cctp-v1',
    sourceChain,
    destinationChain,
    sourceAsset: { contract: burnToken },
    destinationAsset: { contract: null, note: 'native USDC on destination chain' },
    amount,
    expectedOutput: amount,
    destinationRecipient: recipient,
    destinationDomain: domain
  };
  return {
    status: 'supported',
    protocol: 'cctp-v1',
    reason: null,
    terms,
    notes,
    finding: finding(
      'BRIDGE_DEPOSIT',
      'HIGH',
      `CCTP V1 bridge deposit: burn ${amount} of ${burnToken} on chain ${sourceChain}; native USDC mints on chain ${destinationChain} `
        + `(domain ${domain}) for ${recipient}. Destination mint follows attestation — source execution never proves receipt. Held for review.`,
      { protocol: 'cctp-v1', target, sourceChain, destinationChain, domain }
    )
  };
}

/**
 * Analyze a decoded transaction for supported bridge deposits.
 * @param {{decodedTx: object, chainId: string|number|null}} args
 * @returns {object|null} null when the call is not bridge-shaped.
 */
function analyzeBridge(args) {
  try {
    const a = args && typeof args === 'object' ? args : {};
    const d = a.decodedTx && typeof a.decodedTx === 'object' ? a.decodedTx : {};
    const fn = d.functionName;
    const std = d.standard;
    const isAcross = fn === 'depositV3' && std === 'AcrossV3';
    const isCctp = fn === 'depositForBurn' && std === 'CCTPV1';
    if (!isAcross && !isCctp) return null;

    const target = typeof d.contract === 'string' ? d.contract.toLowerCase() : null;
    const sourceChain = chainKey(a.chainId !== undefined && a.chainId !== null ? a.chainId : d.chainId);
    const protocol = isAcross ? 'across-v3' : 'cctp-v1';
    if (sourceChain === null) {
      return unsupported(protocol, 'source chain id unestablished; canonical contract unverifiable.', { target });
    }
    const allowlist = isAcross ? ACROSS_V3_SPOKEPOOLS : CCTP_V1_MESSENGERS;
    const canonical = Object.prototype.hasOwnProperty.call(allowlist, sourceChain) ? allowlist[sourceChain] : null;
    if (canonical === null || target !== canonical) {
      return unsupported(protocol,
        canonical === null
          ? `no canonical ${protocol} contract known on chain ${sourceChain}.`
          : `target ${target || '(missing)'} is not the canonical ${protocol} contract on chain ${sourceChain}.`,
        { target, sourceChain });
    }
    return isAcross
      ? analyzeAcross({ decodedTx: d, target, sourceChain })
      : analyzeCctp({ decodedTx: d, target, sourceChain });
  } catch (err) {
    return {
      status: 'unsupported',
      protocol: 'unknown',
      reason: `bridge analysis failed (${String((err && err.message) || err).slice(0, 160)}); terms unestablished.`,
      terms: null,
      notes: ['bridge analysis failed; terms unestablished'],
      finding: finding('BRIDGE_UNVERIFIED_CONTRACT', 'HIGH',
        'Bridge-shaped call failed analysis; destination outcome unestablished. Held for review.', {})
    };
  }
}

module.exports = {
  analyzeBridge,
  bytes32ToAddress,
  ACROSS_V3_SPOKEPOOLS,
  CCTP_V1_MESSENGERS,
  CCTP_DOMAIN_TO_CHAIN
};
