/**
 * SDK transaction digest: the exact shared canonicalization the policy
 * service and signer verify against (no forked implementation).
 *
 * Vendored copy of extension/shared/txDigest.js (byte-identical at
 * SDK-upgrade time) so the published package is self-contained and
 * never requires files outside sdk/. Parity with the extension copy
 * is asserted by test/unit/sdkPackage.test.js.
 */
module.exports = require('./internal/txDigest');
