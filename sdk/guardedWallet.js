/**
 * Guarded wallet (agent-agnostic, zero dependencies).
 *
 * The interception boundary: once an agent routes its sends through
 * here, every transaction is investigated by Assertara and only
 * executed via the controlled signer on a fresh ALLOW with a complete
 * approval. There is deliberately NO raw send, NO local signing, NO
 * broadcast, NO force/override path in this module.
 *
 * Framework support is duck-typed (no viem/ethers imports): the core
 * accepts plain transaction objects, and thin adapters map viem and
 * ethers call shapes onto it. Anything else can call sendTransaction
 * directly with { to, value, data, chainId }.
 *
 * Boundary honesty: this module intercepts what flows through it. A
 * separately held external wallet or direct RPC path outside the SDK
 * is outside its enforcement boundary, and nothing here claims
 * otherwise.
 */

const { notExecutable } = require('./errors');

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;

// viem chain objects ({ id }) and ethers networkish ({ chainId })
// both reduce to a numeric chain id for normalization.
function chainIdToHex(chainId) {
  if (typeof chainId === 'number' && Number.isSafeInteger(chainId) && chainId >= 0) {
    return `0x${chainId.toString(16)}`;
  }
  if (typeof chainId === 'bigint' && chainId >= 0n) return `0x${chainId.toString(16)}`;
  if (typeof chainId === 'string') {
    const s = chainId.trim();
    if (/^0[xX][0-9a-fA-F]+$/.test(s)) return `0x${BigInt(s).toString(16)}`;
    if (/^[0-9]+$/.test(s)) return `0x${BigInt(s).toString(16)}`;
  }
  throw new Error('chainId must be a numeric quantity.');
}

function valueToHex(value) {
  if (value === undefined || value === null) return '0x0';
  if (typeof value === 'bigint') {
    if (value < 0n) throw new Error('value must be non-negative.');
    return `0x${value.toString(16)}`;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('value must be a non-negative safe integer, bigint, or quantity string.');
    return `0x${value.toString(16)}`;
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (s === '') return '0x0';
    if (/^0[xX][0-9a-fA-F]+$/.test(s) || /^[0-9]+$/.test(s)) return s.startsWith('0x') || s.startsWith('0X') ? s : s;
    throw new Error('value must be a hex or decimal quantity string.');
  }
  // ethers BigNumber / viem-style objects with exact decimal rendering.
  if (typeof value === 'object' && typeof value.toString === 'function') {
    const s = value.toString();
    if (/^[0-9]+$/.test(s)) return s;
  }
  throw new Error('value must be a bigint, safe integer, quantity string, or BigNumber-like.');
}

// Normalize caller-shaped input into the exact server transaction
// object. Fails fast on malformed fields; the server revalidates
// everything (client checks are convenience, never authority).
function normalizeTx({ to, from, value, data, chainId, nonce, gas, gasPrice, maxFeePerGas, maxPriorityFeePerGas, type, accessList } = {}) {
  if (typeof to !== 'string' || !ADDRESS_RE.test(to)) {
    throw new Error('Transaction.to must be a valid address.');
  }
  if (from !== undefined && from !== null && (typeof from !== 'string' || !ADDRESS_RE.test(from))) {
    throw new Error('Transaction.from must be a valid address when present.');
  }
  if (data !== undefined && data !== null && (typeof data !== 'string' || !HEX_RE.test(data))) {
    throw new Error('Transaction.data must be a 0x hex string when present.');
  }
  const tx = {
    ...(from ? { from } : {}),
    to,
    value: valueToHex(value),
    data: data === undefined || data === null || data === '' ? '0x' : data,
    ...(chainId !== undefined && chainId !== null ? { chainId: chainIdToHex(chainId) } : {})
  };
  for (const [k, v] of Object.entries({ nonce, gas, gasPrice, maxFeePerGas, maxPriorityFeePerGas, type })) {
    if (v !== undefined && v !== null) tx[k] = valueToHex(v);
  }
  if (accessList !== undefined && accessList !== null) {
    if (!Array.isArray(accessList)) throw new Error('Transaction.accessList must be an array when present.');
    tx.accessList = accessList;
  }
  return tx;
}

function defaultPurpose(tx) {
  return `Agent transaction to ${tx.to} (${tx.value} wei).`;
}

// The guarded flow every send executes: submit the EXACT bytes for
// investigation, await the published decision, and continue only on
// ALLOW with a complete approval (REVIEW waits for out-of-band
// operator release; BLOCK/UNCERTAIN/REJECTED stop here, unsigned).
async function guardedSend(client, tx, { purpose, agentId, idempotencyKey, evidence, operatorTimeoutMs, onProgress } = {}) {
  const investigation = await client.submit({
    transaction: tx, purpose: purpose || defaultPurpose(tx), agentId, idempotencyKey, evidence
  });
  const decided = await investigation.wait({ onProgress });
  if (decided.decision === 'REVIEW') {
    const released = await client.waitForOperatorApproval(investigation.requestId, { timeoutMs: operatorTimeoutMs });
    const signed = await investigation.execute(tx);
    const execution = await investigation.waitForExecution();
    return { requestId: investigation.requestId, traceId: investigation.traceId, decision: released.decision, txHash: signed.txHash, receipt: signed.receipt, execution };
  }
  if (decided.decision !== 'ALLOW') {
    throw notExecutable(decided.decision, decided.reasons);
  }
  const signed = await investigation.execute(tx);
  const execution = await investigation.waitForExecution();
  return { requestId: investigation.requestId, traceId: investigation.traceId, decision: decided.decision, txHash: signed.txHash, receipt: signed.receipt, execution };
}

function createGuardedWallet({ client, account, chainId, purpose, agentId } = {}) {
  if (!client) throw new Error('createGuardedWallet requires an AssertaraClient.');
  if (typeof account !== 'string' || !ADDRESS_RE.test(account)) {
    throw new Error('createGuardedWallet requires the agent sending address (account).');
  }
  const defaultChain = chainId !== undefined && chainId !== null ? chainIdToHex(chainId) : null;
  return {
    account,
    getAddress() {
      return account;
    },
    // Every send is investigated; only ALLOW (or operator-released
    // REVIEW) reaches the controlled signer. Resolves after the
    // execution is recorded and verified.
    async sendTransaction(tx, opts) {
      const full = normalizeTx({
        ...(tx || {}),
        from: (tx && tx.from) || account,
        chainId: (tx && (tx.chainId !== undefined && tx.chainId !== null ? tx.chainId : defaultChain)) ?? undefined
      });
      if (!full.chainId) throw new Error('Transaction chainId is required (per-call or wallet default).');
      return guardedSend(client, full, {
        purpose: (opts && opts.purpose) || purpose,
        agentId: (opts && opts.agentId) || agentId,
        idempotencyKey: opts && opts.idempotencyKey,
        evidence: opts && opts.evidence,
        operatorTimeoutMs: opts && opts.operatorTimeoutMs,
        onProgress: opts && opts.onProgress
      });
    }
  };
}

// viem-shaped adapter: maps walletClient.sendTransaction and a
// pre-encoded writeContract onto the guarded wallet. No viem import:
// anything with the same call shape works.
function wrapViemWallet({ wallet, account, chain, encode } = {}) {
  if (!wallet || typeof wallet.sendTransaction !== 'function') {
    throw new Error('wrapViemWallet requires a guarded wallet (createGuardedWallet).');
  }
  const address = account || (typeof wallet.getAddress === 'function' ? wallet.getAddress() : null);
  const chainId = chain && typeof chain.id === 'number' ? chain.id : undefined;
  return {
    async sendTransaction(args = {}, opts) {
      return wallet.sendTransaction(
        { from: args.account || address, to: args.to, value: args.value, data: args.data, chainId: chainIdFrom(args.chain) ?? chainId },
        opts
      );
    },
    // Contract writes must arrive pre-encoded as `data`, or with an
    // `encode` function supplied here (e.g. viem's encodeFunctionData
    // passed in by the caller, keeping the SDK dependency-free).
    async writeContract(args = {}, opts) {
      const data = typeof args.data === 'string'
        ? args.data
        : (typeof encode === 'function' ? encode(args) : null);
      if (typeof data !== 'string') {
        throw new Error('writeContract requires pre-encoded data or an encode() function.');
      }
      return wallet.sendTransaction(
        { from: args.account || address, to: args.address, value: args.value, data, chainId: chainIdFrom(args.chain) ?? chainId },
        opts
      );
    }
  };
}

function chainIdFrom(chain) {
  if (!chain) return undefined;
  if (typeof chain.id === 'number') return chain.id;
  if (typeof chain.chainId !== 'undefined') return chain.chainId;
  return undefined;
}

// ethers-shaped adapter: maps signer.sendTransaction onto the guarded
// wallet. Resolves with the guarded result (not an ethers
// TransactionResponse): hash, verified execution, decision, ids.
function wrapEthersSigner({ wallet, address } = {}) {
  if (!wallet || typeof wallet.sendTransaction !== 'function') {
    throw new Error('wrapEthersSigner requires a guarded wallet (createGuardedWallet).');
  }
  const from = address || (typeof wallet.getAddress === 'function' ? wallet.getAddress() : null);
  return {
    async getAddress() {
      return from;
    },
    async sendTransaction(tx = {}, opts) {
      return wallet.sendTransaction(
        {
          from: tx.from || from,
          to: tx.to,
          value: tx.value,
          data: tx.data,
          chainId: tx.chainId,
          nonce: tx.nonce,
          gas: tx.gasLimit !== undefined ? tx.gasLimit : tx.gas,
          gasPrice: tx.gasPrice,
          maxFeePerGas: tx.maxFeePerGas,
          maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
          type: tx.type,
          accessList: tx.accessList
        },
        opts
      );
    }
  };
}

module.exports = {
  normalizeTx, valueToHex, chainIdToHex, defaultPurpose,
  createGuardedWallet, wrapViemWallet, wrapEthersSigner
};
