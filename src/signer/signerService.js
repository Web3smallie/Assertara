/**
 * Controlled signer service (agent execution system).
 *
 * Separate trust boundary from the policy service: it holds the signing
 * key (which the policy service, agents, and models never see) and
 * trusts NOTHING except approval HMACs, exact transaction bytes, its
 * own mandate copy, and chain RPC reads. Split into two stages so the
 * verification logic is unit-testable without a chain:
 *
 *   verify()  — stateless checks (HMAC, expiry, binding, mandate,
 *               operator, chain, sender). No chain I/O, no state change.
 *   execute() — serialized critical section: recheck single-use,
 *               mark consumed (persisted BEFORE broadcast, fail closed),
 *               sign, broadcast; then receipt wait + policy callback.
 *
 * The viem clients are injectable for tests; production passes none
 * and gets real clients bound to the mandate's chain RPC.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { verifyApproval, verifyOperatorSignature } = require('../services/approvals');
const { checkMandateContinuity, verifyMandateSeal } = require('../services/mandate');
const { openReplayStore } = require('./replayStore');
const { digestTx, isValidDigest } = require('../../extension/shared/txDigest');

async function createSigner(deps) {
  const {
    approvalSecret, operatorSecret, mandate, mandateAuthorities, privateKey,
    consumedFile, anchorFile, stateFile, policyCallbackUrl, nowFn, clients
  } = deps || {};
  const now = typeof nowFn === 'function' ? nowFn : Date.now;

  if (!approvalSecret || typeof approvalSecret !== 'string' || approvalSecret.length < 16) {
    throw new Error('signer requires APPROVAL_SECRET of at least 16 characters');
  }
  if (!mandate || typeof mandate !== 'object') throw new Error('signer requires an active mandate');

  // Mandate authenticity: the signer serves ONLY a cryptographically
  // verified mandate from a trusted authority. Unsigned, tampered,
  // foreign-authority, or malformed seals refuse startup — never silent
  // trust in file provenance.
  const sealCheck = await verifyMandateSeal({ mandate, authorities: mandateAuthorities });
  if (!sealCheck.ok) throw new Error(`signer refusing to start: ${sealCheck.error}`);

  // Development-phase chain restriction: the signer serves ONLY the local
  // Anvil chain (id 31337 over a loopback RPC URL). Any mandate that lists
  // mainnet, a public testnet, or a non-local RPC refuses startup instead
  // of signing anywhere unexpected. The signer is the enforcement point:
  // policy evaluation may consider other chains, but no signature leaves
  // this process for them.
  const DEV_CHAIN_ID = '0x7a69';
  if (!Array.isArray(mandate.chains) || mandate.chains.length === 0) {
    throw new Error('signer refusing to start: mandate lists no chains');
  }
  for (const c of mandate.chains) {
    let host = '';
    try {
      host = new URL(c.rpcUrl).hostname.toLowerCase();
    } catch {
      host = '';
    }
    const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
    if (c.id !== DEV_CHAIN_ID || !loopback) {
      throw new Error(`signer refusing to start: chain ${c.id} @ ${c.rpcUrl} is not the local dev chain (31337 on loopback)`);
    }
  }
  if (!privateKey || typeof privateKey !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new Error('signer requires SIGNER_PRIVATE_KEY as a 0x 32-byte hex key');
  }

  // Key custody: derived once, kept in closure scope, never returned or logged.
  const { privateKeyToAccount } = require('viem/accounts');
  const account = privateKeyToAccount(privateKey);
  const address = account.address.toLowerCase();
  if (address !== String(mandate.signerAddress).toLowerCase()) {
    throw new Error('signer key does not match the mandate signerAddress');
  }

  // Single-use nonces: HMAC-chained append-only log plus a separate
  // integrity anchor. Verified at boot; any gap, corruption, truncation,
  // or rollback refuses startup (see replayStore for the trust model).
  // Consumption persists BEFORE broadcast so a crash can burn an
  // approval but never allow a replay.
  const replay = openReplayStore({ approvalSecret, consumedFile, anchorFile, mandate });
  const consumed = { has: (nonce) => replay.has(nonce) };
  function markConsumed(nonce, requestId, txHash) {
    replay.consume({ nonce, requestId, txHash });
  }

  // Mandate continuity: the last-boot mandate id/version persists so a
  // restart cannot silently revert to an older mandate file. A rollback
  // refuses startup; a corrupt state file does the same.
  if (stateFile) {
    try {
      let last = null;
      if (fs.existsSync(stateFile)) {
        const parsed = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
        if (!parsed || parsed.format !== 'assertara-signer-state-1'
          || typeof parsed.mandateId !== 'string' || !Number.isSafeInteger(parsed.mandateVersion)) {
          throw new Error('signer state file is corrupt or unrecognized');
        }
        last = { id: parsed.mandateId, version: parsed.mandateVersion };
      }
      const continuity = checkMandateContinuity({ last, current: mandate });
      if (!continuity.ok) throw new Error(continuity.error);
      const body = JSON.stringify({ format: 'assertara-signer-state-1', mandateId: mandate.id, mandateVersion: mandate.version, at: now() });
      fs.mkdirSync(path.dirname(stateFile), { recursive: true });
      fs.writeFileSync(`${stateFile}.tmp`, body, 'utf8');
      fs.renameSync(`${stateFile}.tmp`, stateFile);
    } catch (err) {
      throw new Error(`signer mandate continuity failed: ${err.message}`);
    }
  }

  // Serializes the consume+sign+send critical section (auto-nonce safety).
  let chain = Promise.resolve();
  function withSignLock(fn) {
    const run = chain.then(fn);
    chain = run.catch(() => {});
    return run;
  }

  function chainEntry(chainIdHex) {
    return (mandate.chains || []).find((c) => c.id === chainIdHex) || null;
  }

  function mandateLive() {
    const t = now();
    if (!(t >= mandate.notBeforeMs && t < mandate.expiresAtMs)) return { ok: false, error: 'mandate expired' };
    if ((mandate.revokedVersions || []).indexOf(mandate.version) !== -1) return { ok: false, error: 'mandate revoked' };
    return { ok: true };
  }

  function realClients(rpcUrl, chainIdNum, chainName) {
    const { createWalletClient, createPublicClient, http, defineChain } = require('viem');
    const chain = defineChain({
      id: chainIdNum,
      name: chainName || 'assertara-local',
      nativeCurrency: { decimals: 18, name: 'Ether', symbol: 'ETH' },
      rpcUrls: { default: { http: [rpcUrl] } }
    });
    return {
      wallet: createWalletClient({ account, chain, transport: http(rpcUrl) }),
      public: createPublicClient({ chain, transport: http(rpcUrl) })
    };
  }

  /**
   * Stateless verification. Returns { ok:true, context } or
   * { ok:false, code, error }. No chain I/O, no state change.
   */
  function verify({ requestId, transaction, approval }) {
    if (typeof requestId !== 'string' || !requestId) return { ok: false, code: 'BAD_REQUEST', error: 'requestId is required' };
    if (!transaction || typeof transaction !== 'object' || Array.isArray(transaction)) {
      return { ok: false, code: 'BAD_REQUEST', error: 'transaction must be an object' };
    }
    const checked = verifyApproval({ secret: approvalSecret, token: approval, nowMs: now() });
    if (!checked.ok) return { ok: false, code: 'REFUSED', error: `approval invalid: ${checked.error}` };
    const p = checked.payload;
    if (p.requestId !== requestId) return { ok: false, code: 'REFUSED', error: 'approval belongs to a different request' };
    if (p.mandateId !== mandate.id || p.mandateVersion !== mandate.version) {
      return { ok: false, code: 'REFUSED', error: 'approval mandate does not match the active mandate' };
    }
    const live = mandateLive();
    if (!live.ok) return { ok: false, code: 'REFUSED', error: live.error };
    if (p.requiresOperator && !verifyOperatorSignature({ operatorSecret, nonce: p.nonce, signature: p.operatorSig })) {
      return { ok: false, code: 'REFUSED', error: 'operator authorization missing or invalid' };
    }
    let actualDigest = null;
    try {
      actualDigest = digestTx(transaction);
    } catch {
      actualDigest = null;
    }
    if (!isValidDigest(actualDigest) || actualDigest !== p.txDigest) {
      return { ok: false, code: 'REFUSED', error: 'transaction does not match the approved digest' };
    }
    // Capability 5 B1: subcall-tree binding. The approval authorizes
    // the exact nested structure the mandate evaluated; the signer
    // re-derives it from the presented transaction bytes and refuses
    // on any difference, so inner-operation mutations between
    // evaluation and signing cannot execute. Approvals without the
    // binding (issued before B1) are refused: fail closed, re-propose.
    if (typeof p.subcallTreeHash !== 'string' || !/^[0-9a-f]{64}$/.test(p.subcallTreeHash)) {
      return { ok: false, code: 'REFUSED', error: 'approval lacks a subcall-tree binding' };
    }
    let presentedTreeHash = null;
    try {
      const { decodeTransactionCalldata } = require('../services/decoderService');
      const { hashSubcallTree } = require('../services/nestedCalls');
      const decoded = decodeTransactionCalldata({
        to: transaction.to, data: transaction.data, value: transaction.value
      });
      presentedTreeHash = hashSubcallTree(decoded);
    } catch {
      presentedTreeHash = null;
    }
    if (presentedTreeHash !== p.subcallTreeHash) {
      return { ok: false, code: 'REFUSED', error: 'presented nested operations do not match the authorized subcall tree' };
    }
    let chainIdHex = null;
    try {
      chainIdHex = `0x${BigInt(transaction.chainId).toString(16)}`;
    } catch {
      return { ok: false, code: 'BAD_REQUEST', error: 'transaction.chainId is not a valid quantity' };
    }
    const entry = chainEntry(chainIdHex);
    if (!entry) return { ok: false, code: 'REFUSED', error: 'chain not permitted by the mandate' };
    let chainMatchesApproval = false;
    try {
      chainMatchesApproval = String(transaction.chainId).toLowerCase() === String(p.chainId).toLowerCase()
        || BigInt(transaction.chainId) === BigInt(p.chainId);
    } catch {
      chainMatchesApproval = false;
    }
    if (!chainMatchesApproval) {
      return { ok: false, code: 'REFUSED', error: 'chain does not match the approval' };
    }
    const sender = typeof transaction.from === 'string' ? transaction.from.toLowerCase() : '';
    if (sender !== address || sender !== String(p.sender).toLowerCase()) {
      return { ok: false, code: 'REFUSED', error: 'sender is not this signer' };
    }
    if (typeof transaction.to !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(transaction.to)) {
      return { ok: false, code: 'BAD_REQUEST', error: 'transaction.to must be a valid address' };
    }
    return { ok: true, context: { approval: p, transaction, chainIdHex, chainIdNum: Number(BigInt(transaction.chainId)), rpcUrl: entry.rpcUrl, chainName: entry.name } };
  }

  function toBigIntField(v, name) {
    if (v === undefined || v === null) return undefined;
    try {
      if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
      if (typeof v === 'string') return BigInt(v.trim() === '' ? '0x0' : v);
      if (typeof v === 'bigint' && v >= 0n) return v;
    } catch {
      /* fall through */
    }
    throw new Error(`transaction.${name} is not a valid quantity`);
  }

  async function buildClients(ctx) {
    if (clients && clients.wallet && clients.public) return clients;
    return realClients(ctx.rpcUrl, ctx.chainIdNum, ctx.chainName);
  }

  async function execute({ requestId, transaction, approval }) {
    const v = verify({ requestId, transaction, approval });
    if (!v.ok) return v;
    const ctx = v.context;
    return withSignLock(async () => {
      if (consumed.has(ctx.approval.nonce)) {
        return { ok: false, code: 'REFUSED', error: 'approval already consumed' };
      }
      let io;
      try {
        io = await buildClients(ctx);
      } catch (err) {
        return { ok: false, code: 'CHAIN_ERROR', error: `chain client unavailable: ${err.message}` };
      }
      const tx = ctx.transaction;
      const isNative = !tx.data || tx.data === '0x';
      let valueWei;
      try {
        valueWei = toBigIntField(tx.value === undefined || tx.value === null ? '0x0' : tx.value, 'value');
      } catch (err) {
        return { ok: false, code: 'BAD_REQUEST', error: err.message };
      }
      // Assemble the exact sendable tx: authorized fields verbatim,
      // absent operational fields filled deterministically here.
      let sendable;
      try {
        sendable = {
          to: tx.to,
          value: valueWei,
          data: tx.data && tx.data !== '' ? tx.data : '0x',
          chainId: ctx.chainIdNum
        };
        if (tx.nonce !== undefined && tx.nonce !== null) sendable.nonce = Number(toBigIntField(tx.nonce, 'nonce'));
        else sendable.nonce = await io.public.getTransactionCount({ address: account.address, blockTag: 'pending' });
        if (tx.gas !== undefined && tx.gas !== null) sendable.gas = toBigIntField(tx.gas, 'gas');
        const maxFee = tx.maxFeePerGas !== undefined && tx.maxFeePerGas !== null ? toBigIntField(tx.maxFeePerGas, 'maxFeePerGas') : undefined;
        const maxPrio = tx.maxPriorityFeePerGas !== undefined && tx.maxPriorityFeePerGas !== null ? toBigIntField(tx.maxPriorityFeePerGas, 'maxPriorityFeePerGas') : undefined;
        const gasPrice = tx.gasPrice !== undefined && tx.gasPrice !== null ? toBigIntField(tx.gasPrice, 'gasPrice') : undefined;
        if (maxFee !== undefined || maxPrio !== undefined) {
          if (maxFee !== undefined) sendable.maxFeePerGas = maxFee;
          if (maxPrio !== undefined) sendable.maxPriorityFeePerGas = maxPrio;
        } else if (gasPrice !== undefined) {
          sendable.gasPrice = gasPrice;
        }
        if (tx.type !== undefined && tx.type !== null) {
          const t = toBigIntField(tx.type, 'type');
          sendable.type = t === 0n ? 'legacy' : t === 2n ? 'eip1559' : undefined;
          if (sendable.type === undefined) return { ok: false, code: 'BAD_REQUEST', error: 'unsupported transaction type (only legacy and eip1559)' };
        }
        if (tx.accessList !== undefined && tx.accessList !== null) {
          if (!Array.isArray(tx.accessList)) return { ok: false, code: 'BAD_REQUEST', error: 'accessList must be an array' };
          sendable.accessList = tx.accessList;
        }
      } catch (err) {
        return { ok: false, code: 'BAD_REQUEST', error: err.message };
      }

      let balanceBefore = null;
      const checkDelta = isNative && valueWei > 0n && String(tx.to).toLowerCase() !== address;
      if (checkDelta) {
        try {
          balanceBefore = await io.public.getBalance({ address: tx.to });
        } catch {
          balanceBefore = null;
        }
      }

      // Fail-closed ordering: consume BEFORE broadcast. A crash here
      // burns the approval (re-propose) but can never allow a replay.
      try {
        markConsumed(ctx.approval.nonce, requestId, null);
      } catch (err) {
        return { ok: false, code: 'REFUSED', error: `cannot record approval consumption: ${err.message}` };
      }

      let hash;
      try {
        hash = await io.wallet.sendTransaction(sendable);
      } catch (err) {
        return { ok: false, code: 'CHAIN_ERROR', error: `broadcast failed: ${err.message}` };
      }

      let receipt = null;
      try {
        receipt = await io.public.waitForTransactionReceipt({ hash, timeout: 60000 });
      } catch (err) {
        return { ok: true, broadcast: true, txHash: hash, receipt: null, verification: { receiptVerified: false, note: `receipt wait failed: ${err.message}` } };
      }

      // Normalize receipt fields to JSON-safe strings: real viem receipts
      // carry BigInt blockNumber/gasUsed (JSON.stringify would throw),
      // while test fakes use hex strings. Both pass through as strings.
      const safeString = (v) => (v === undefined || v === null ? null : String(v));
      const verification = { receiptVerified: true, status: safeString(receipt.status) };
      if (checkDelta && balanceBefore !== null) {
        try {
          const after = await io.public.getBalance({ address: tx.to });
          verification.balanceDeltaOk = after - balanceBefore === valueWei;
        } catch {
          verification.balanceDeltaOk = null;
        }
      }

      // Best-effort delivery to the policy service (the agent
      // receipt-report endpoint is the backup path for the same record).
      if (policyCallbackUrl) {
        try {
          const sig = crypto.createHmac('sha256', approvalSecret).update(`signer-delivery:${ctx.approval.nonce}:${hash}`, 'utf8').digest('hex');
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 10000);
          try {
            await fetch(policyCallbackUrl, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ requestId, nonce: ctx.approval.nonce, txHash: hash, sig }),
              signal: controller.signal
            });
          } finally {
            clearTimeout(timer);
          }
        } catch {
          /* delivery failure must not unsettle a verified execution */
        }
      }

      return { ok: true, broadcast: true, txHash: hash, receipt: { status: safeString(receipt.status), blockNumber: safeString(receipt.blockNumber), gasUsed: safeString(receipt.gasUsed) }, verification };
    });
  }

  return {
    address,
    mandateId: mandate.id,
    mandateVersion: mandate.version,
    sealAuthority: sealCheck.authority,
    chainIds: (mandate.chains || []).map((c) => c.id),
    verify,
    execute,
    consumedCount: () => replay.size()
  };
}

module.exports = { createSigner };
