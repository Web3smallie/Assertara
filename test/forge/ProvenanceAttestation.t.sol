// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// NOTE: this file is executed inside a temporary Foundry project built
// by test/e2e/attestationContract.test.js, where the contract under
// test is copied to <tmp>/src/ProvenanceAttestation.sol — hence the
// relative import below. No forge-std dependency: reverts are checked
// via low-level calls compared against custom-error selectors, and
// event contents are verified in the Anvil e2e via eth_getLogs.

import "../src/ProvenanceAttestation.sol";

contract ProvenanceAttestationTest {
    ProvenanceAttestation private registry;

    // Deliberately not the test contract's own address: every test that
    // uses ATTESTER proves the declared-attester path (attester is a
    // parameter, never msg.sender).
    address private constant ATTESTER = 0x1111111111111111111111111111111111111111;
    address private constant ATTESTER2 = 0x2222222222222222222222222222222222222222;

    bytes32 private constant DIGEST = keccak256("manifest-a");
    bytes32 private constant DIGEST_B = keccak256("manifest-b");
    bytes32 private constant TXHASH = keccak256("payment-tx");
    bytes32 private constant ZERO = bytes32(0);

    uint8 private constant ALLOW = 0;
    uint8 private constant BLOCK = 1;
    uint8 private constant REVIEW = 2;

    function setUp() public {
        registry = new ProvenanceAttestation();
        require(ATTESTER != address(this), "fixture broken: attester must differ from sender");
    }

    // -- low-level call helpers (no forge-std) ---------------------------

    function _attestRaw(
        string memory investigationId,
        bytes32 manifestDigest,
        uint8 modelBitmap,
        uint8 decision,
        bytes32 txHash,
        address attester
    ) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = address(registry).call(
            abi.encodeCall(
                registry.attest,
                (investigationId, manifestDigest, modelBitmap, decision, txHash, attester)
            )
        );
    }

    function _selector(bytes memory ret) internal pure returns (bytes4 sel) {
        require(ret.length >= 4, "no revert data");
        assembly {
            sel := mload(add(ret, 32))
        }
    }

    function _expectRevert(
        string memory investigationId,
        bytes32 manifestDigest,
        uint8 modelBitmap,
        uint8 decision,
        bytes32 txHash,
        address attester,
        bytes4 expected
    ) internal {
        (bool ok, bytes memory ret) = _attestRaw(
            investigationId, manifestDigest, modelBitmap, decision, txHash, attester
        );
        require(!ok, "expected revert, call succeeded");
        require(_selector(ret) == expected, "wrong custom error");
    }

    function _get(string memory investigationId, address attester)
        internal
        view
        returns (string memory, bytes32, uint8, ProvenanceAttestation.Decision, bytes32, address)
    {
        return registry.getAttestation(investigationId, attester);
    }

    // -- valid attestations ------------------------------------------------

    function testAllowWithTxHash() external {
        registry.attest("inv-allow", DIGEST, 3, ALLOW, TXHASH, ATTESTER);
        (string memory id, bytes32 d, uint8 b, ProvenanceAttestation.Decision dec, bytes32 t, address a) =
            _get("inv-allow", ATTESTER);
        require(keccak256(bytes(id)) == keccak256("inv-allow"), "id");
        require(d == DIGEST, "digest");
        require(b == 3, "bitmap");
        require(dec == ProvenanceAttestation.Decision.ALLOW, "decision");
        require(t == TXHASH, "txhash");
        require(a == ATTESTER, "attester");
    }

    function testAllowZeroHash() external {
        // Pre-execution ALLOW attestation: zero hash is legitimate.
        registry.attest("inv-allow-early", DIGEST, 1, ALLOW, ZERO, ATTESTER);
        (, , , ProvenanceAttestation.Decision dec, bytes32 t,) = _get("inv-allow-early", ATTESTER);
        require(dec == ProvenanceAttestation.Decision.ALLOW, "decision");
        require(t == ZERO, "zero hash kept");
    }

    function testBlockZeroHash() external {
        registry.attest("inv-block", DIGEST, 1, BLOCK, ZERO, ATTESTER);
        (, , , ProvenanceAttestation.Decision dec, bytes32 t,) = _get("inv-block", ATTESTER);
        require(dec == ProvenanceAttestation.Decision.BLOCK, "decision");
        require(t == ZERO, "zero hash");
    }

    function testReviewZeroHash() external {
        registry.attest("inv-review", DIGEST, 2, REVIEW, ZERO, ATTESTER);
        (, , uint8 b, ProvenanceAttestation.Decision dec,,) = _get("inv-review", ATTESTER);
        require(b == 2, "bitmap");
        require(dec == ProvenanceAttestation.Decision.REVIEW, "decision");
    }

    function testBitmapZeroValid() external {
        registry.attest("inv-nomodel", DIGEST, 0, BLOCK, ZERO, ATTESTER);
        (, , uint8 b,,,) = _get("inv-nomodel", ATTESTER);
        require(b == 0, "bitmap");
    }

    function testBoundaryId256() external {
        string memory id256 = new string(256);
        registry.attest(id256, DIGEST, 1, ALLOW, ZERO, ATTESTER);
        (string memory id,,,,,) = _get(id256, ATTESTER);
        require(bytes(id).length == 256, "length");
    }

    // -- invalid inputs -----------------------------------------------------

    function testEmptyInvestigationId() external {
        _expectRevert(
            "", DIGEST, 1, ALLOW, ZERO, ATTESTER, ProvenanceAttestation.EmptyInvestigationId.selector
        );
    }

    function testLongInvestigationId() external {
        string memory longId = new string(257);
        _expectRevert(
            longId, DIGEST, 1, ALLOW, ZERO, ATTESTER, ProvenanceAttestation.InvestigationIdTooLong.selector
        );
    }

    function testZeroDigest() external {
        _expectRevert(
            "inv", ZERO, 1, ALLOW, ZERO, ATTESTER, ProvenanceAttestation.ZeroManifestDigest.selector
        );
    }

    function testBadBitmap() external {
        _expectRevert(
            "inv", DIGEST, 4, ALLOW, ZERO, ATTESTER, ProvenanceAttestation.InvalidModelBitmap.selector
        );
        _expectRevert(
            "inv", DIGEST, 255, ALLOW, ZERO, ATTESTER, ProvenanceAttestation.InvalidModelBitmap.selector
        );
    }

    function testBadDecision() external {
        _expectRevert(
            "inv", DIGEST, 1, 3, ZERO, ATTESTER, ProvenanceAttestation.InvalidDecision.selector
        );
        _expectRevert(
            "inv", DIGEST, 1, 255, ZERO, ATTESTER, ProvenanceAttestation.InvalidDecision.selector
        );
    }

    function testZeroAttester() external {
        _expectRevert(
            "inv", DIGEST, 1, ALLOW, ZERO, address(0), ProvenanceAttestation.ZeroAttester.selector
        );
    }

    function testBlockNonZeroHash() external {
        _expectRevert(
            "inv",
            DIGEST,
            1,
            BLOCK,
            TXHASH,
            ATTESTER,
            ProvenanceAttestation.NonZeroTxHashForNonExecuted.selector
        );
    }

    function testReviewNonZeroHash() external {
        _expectRevert(
            "inv",
            DIGEST,
            1,
            REVIEW,
            TXHASH,
            ATTESTER,
            ProvenanceAttestation.NonZeroTxHashForNonExecuted.selector
        );
    }

    // -- duplicates ----------------------------------------------------------

    function testIdenticalResubmit() external {
        registry.attest("inv-dup", DIGEST, 3, ALLOW, TXHASH, ATTESTER);
        // Identical resubmission succeeds silently (idempotent publishers).
        registry.attest("inv-dup", DIGEST, 3, ALLOW, TXHASH, ATTESTER);
        (, bytes32 d, uint8 b, ProvenanceAttestation.Decision dec, bytes32 t, address a) =
            _get("inv-dup", ATTESTER);
        require(d == DIGEST && b == 3, "fields intact");
        require(dec == ProvenanceAttestation.Decision.ALLOW && t == TXHASH && a == ATTESTER, "fields intact");
    }

    function testConflictingResubmit() external {
        registry.attest("inv-conflict", DIGEST, 3, ALLOW, TXHASH, ATTESTER);
        _expectRevert(
            "inv-conflict", DIGEST_B, 3, ALLOW, TXHASH, ATTESTER, ProvenanceAttestation.ConflictingAttestation.selector
        );
        _expectRevert(
            "inv-conflict", DIGEST, 2, BLOCK, ZERO, ATTESTER, ProvenanceAttestation.ConflictingAttestation.selector
        );
        // Original record untouched by the failed conflicts.
        (, bytes32 d,, ProvenanceAttestation.Decision dec,,) = _get("inv-conflict", ATTESTER);
        require(d == DIGEST && dec == ProvenanceAttestation.Decision.ALLOW, "original intact");
    }

    function testSeparateAttestersSameInvestigation() external {
        registry.attest("inv-shared", DIGEST, 1, ALLOW, ZERO, ATTESTER);
        registry.attest("inv-shared", DIGEST_B, 3, ALLOW, TXHASH, ATTESTER2);
        (, bytes32 d1,,,,) = _get("inv-shared", ATTESTER);
        (, bytes32 d2,,,, address a2) = _get("inv-shared", ATTESTER2);
        require(d1 == DIGEST && d2 == DIGEST_B && a2 == ATTESTER2, "independent records");
    }

    // -- attester identity -----------------------------------------------------

    function testAttesterDiffersFromSender() external {
        // msg.sender here is this test contract; the recorded attester
        // must be the declared parameter (the publisher/signer split).
        registry.attest("inv-split", DIGEST, 1, ALLOW, ZERO, ATTESTER);
        (, , , , , address a) = _get("inv-split", ATTESTER);
        require(a == ATTESTER, "declared attester recorded");
        require(a != address(this), "attester is not msg.sender");
        // No record exists under the sender's own address.
        (bool ok, bytes memory ret) = address(registry).call(
            abi.encodeCall(registry.getAttestation, ("inv-split", address(this)))
        );
        require(!ok, "sender-keyed lookup must miss");
        require(_selector(ret) == ProvenanceAttestation.UnknownAttestation.selector, "unknown code");
    }

    function testUnknownGetter() external {
        (bool ok, bytes memory ret) = address(registry).call(
            abi.encodeCall(registry.getAttestation, ("nope", ATTESTER))
        );
        require(!ok, "unknown lookup must revert");
        require(_selector(ret) == ProvenanceAttestation.UnknownAttestation.selector, "unknown code");
    }
}
