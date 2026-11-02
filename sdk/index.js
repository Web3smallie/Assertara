/**
 * Assertara agent SDK (public surface).
 *
 * Deliberately narrow: submit, observe, decide, execute-through-signer.
 * No keys, no signing, no broadcast, no overrides — see README.md for
 * the enforcement boundary statement.
 */

const { AssertaraClient, isCleanExecution, DEFAULT_TIMEOUTS } = require('./client');
const { Investigation } = require('./investigation');
const {
  normalizeTx, valueToHex, chainIdToHex, defaultPurpose,
  createGuardedWallet, wrapViemWallet, wrapEthersSigner
} = require('./guardedWallet');
const { AssertaraError, CODES } = require('./errors');
const TxDigest = require('./digest');

module.exports = {
  AssertaraClient,
  Investigation,
  isCleanExecution,
  DEFAULT_TIMEOUTS,
  normalizeTx,
  valueToHex,
  chainIdToHex,
  defaultPurpose,
  createGuardedWallet,
  wrapViemWallet,
  wrapEthersSigner,
  AssertaraError,
  CODES,
  TxDigest
};
