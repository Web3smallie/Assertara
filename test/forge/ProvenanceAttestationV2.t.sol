// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// NOTE: executed inside a temporary Foundry project (see the V2 e2e),
// where the contract under test is copied to <tmp>/src/ — hence the
// relative import below. No forge-std dependency: reverts are checked
// via low-level calls compared against custom-error selectors, and
// event contents are verified in the Anvil e2e via eth_getLogs.
//
// Fixture model entries use arbitrary test strings: the contract is
// model-agnostic and this suite must pass for ANY names.

import "../src/ProvenanceAttestationV2.sol";

contract ProvenanceAttestationV2Test {
    ProvenanceAttestationV2 private registry;

    // Deliberately not the test contract's own address: every test that
    // uses ATTESTER proves the declared-attester path (attester is a
    // parameter, never msg.sender).
    address private constant ATTESTER = 0x1111111111111111111111111111111111111111;

    bytes32 private constant DIGEST = keccak256("v2-manifest-a");
    bytes32 private constant DIGEST_B = keccak256("v2-manifest-b");
    bytes32 private constant TXHASH = keccak256("v2-payment-tx");
    bytes32 private constant ZERO = bytes32(0);

    uint8 private constant ALLOW = 0;
    uint8 private constant BLOCK = 1;
    uint8 private constant REVIEW = 2;

    function setUp() public {
        registry = new ProvenanceAttestationV2();
        require(ATTESTER != address(this), "fixture broken: attester must differ from sender");
    }

    // -- fixtures ------------------------------------------------------

    function _twoModels() private pure returns (ProvenanceAttestationV2.ModelProvenance[] memory) {
        ProvenanceAttestationV2.ModelProvenance[] memory m = new ProvenanceAttestationV2.ModelProvenance[](2);
        m[0] = ProvenanceAttestationV2.ModelProvenance({
            name: "alpha-reasoner",
            provider: "provider-acme",
            modelId: "acme-1",
            endpoint: "chat/completions",
            status: "success",
            contribution: "VERDICT_ACCEPTED",
            verdict: "MATCH",
            inputDigest: keccak256("in-0"),
            outputDigest: keccak256("out-0")
        });
        m[1] = ProvenanceAttestationV2.ModelProvenance({
            name: "beta-segmenter",
            provider: "",
            modelId: "",
            endpoint: "",
            status: "skipped",
            contribution: "NOT_INVOKED",
            verdict: "",
            inputDigest: bytes32(0),
            outputDigest: bytes32(0)
        });
        return m;
    }

    // -- low-level call helpers (no forge-std) ---------------------------

    function _attestRaw(
        string memory investigationId,
        bytes32 manifestDigest,
        uint8 modelBitmap,
        uint8 decision,
        bytes32 txHash,
        address attester,
        ProvenanceAttestationV2.ModelProvenance[] memory models
    ) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = address(registry).call(
            abi.encodeCall(
                registry.attest,
                (investigationId, manifestDigest, modelBitmap, decision, txHash, attester, models)
            )
        );
    }

    function _selector(bytes memory ret) internal pure returns (bytes4 sel) {
        require(ret.length >= 4, "no revert data");
        assembly {
            sel := mload(add(ret, 32))
        }
    }

    function _expectRevert(bytes4 expected, bytes memory ret, bool ok) internal pure {
        require(!ok, "expected revert, call succeeded");
        require(_selector(ret) == expected, "wrong custom error");
    }

    function _get(string memory investigationId, address attester)
        internal
        view
        returns (
            string memory,
            bytes32,
            uint8,
            ProvenanceAttestationV2.Decision,
            bytes32,
            address,
            ProvenanceAttestationV2.ModelProvenance[] memory
        )
    {
        return registry.getAttestation(investigationId, attester);
    }

    function _strEq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    // -- valid attestations ------------------------------------------------

    function testAllowStoresModels() external {
        registry.attest("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, _twoModels());
        (
            string memory id,
            bytes32 d,
            uint8 b,
            ProvenanceAttestationV2.Decision dec,
            bytes32 t,
            address a,
            ProvenanceAttestationV2.ModelProvenance[] memory models
        ) = _get("inv-v2-1", ATTESTER);
        require(_strEq(id, "inv-v2-1"), "id");
        require(d == DIGEST, "digest");
        require(b == 1, "bitmap");
        require(dec == ProvenanceAttestationV2.Decision.ALLOW, "decision");
        require(t == TXHASH, "txhash");
        require(a == ATTESTER, "attester");
        require(models.length == 2, "model count");
        require(_strEq(models[0].name, "alpha-reasoner"), "m0 name");
        require(_strEq(models[0].provider, "provider-acme"), "m0 provider");
        require(_strEq(models[0].modelId, "acme-1"), "m0 modelId");
        require(_strEq(models[0].status, "success"), "m0 status");
        require(_strEq(models[0].contribution, "VERDICT_ACCEPTED"), "m0 contribution");
        require(_strEq(models[1].status, "skipped"), "m1 status");
        require(_strEq(models[1].contribution, "NOT_INVOKED"), "m1 contribution");
        require(models[1].inputDigest == bytes32(0), "m1 zero digest");
    }

    function testBlockZeroHash() external {
        registry.attest("inv-v2-block", DIGEST, 0, BLOCK, ZERO, ATTESTER, _twoModels());
        (, , , ProvenanceAttestationV2.Decision dec, bytes32 t, , ) = _get("inv-v2-block", ATTESTER);
        require(dec == ProvenanceAttestationV2.Decision.BLOCK, "decision");
        require(t == ZERO, "zero hash");
    }

    function testReviewZeroHash() external {
        registry.attest("inv-v2-review", DIGEST, 0, REVIEW, ZERO, ATTESTER, _twoModels());
        (, , , ProvenanceAttestationV2.Decision dec, bytes32 t, , ) = _get("inv-v2-review", ATTESTER);
        require(dec == ProvenanceAttestationV2.Decision.REVIEW, "decision");
        require(t == ZERO, "zero hash");
    }

    // -- core input validation (mirrors V1) --------------------------------

    function testRejectsEmptyId() external {
        (bool ok, bytes memory ret) =
            _attestRaw("", DIGEST, 1, ALLOW, TXHASH, ATTESTER, _twoModels());
        _expectRevert(ProvenanceAttestationV2.EmptyInvestigationId.selector, ret, ok);
    }

    function testRejectsZeroDigest() external {
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", ZERO, 1, ALLOW, TXHASH, ATTESTER, _twoModels());
        _expectRevert(ProvenanceAttestationV2.ZeroManifestDigest.selector, ret, ok);
    }

    function testRejectsBitmap4() external {
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 4, ALLOW, TXHASH, ATTESTER, _twoModels());
        _expectRevert(ProvenanceAttestationV2.InvalidModelBitmap.selector, ret, ok);
    }

    function testRejectsDecision3() external {
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, 3, TXHASH, ATTESTER, _twoModels());
        _expectRevert(ProvenanceAttestationV2.InvalidDecision.selector, ret, ok);
    }

    function testRejectsZeroAttester() external {
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, address(0), _twoModels());
        _expectRevert(ProvenanceAttestationV2.ZeroAttester.selector, ret, ok);
    }

    function testRejectsBlockWithHash() external {
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, BLOCK, TXHASH, ATTESTER, _twoModels());
        _expectRevert(ProvenanceAttestationV2.NonZeroTxHashForNonExecuted.selector, ret, ok);
    }

    function testRejectsReviewWithHash() external {
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, REVIEW, TXHASH, ATTESTER, _twoModels());
        _expectRevert(ProvenanceAttestationV2.NonZeroTxHashForNonExecuted.selector, ret, ok);
    }

    // -- model-array validation --------------------------------------------

    function testRejectsEmptyModels() external {
        ProvenanceAttestationV2.ModelProvenance[] memory none = new ProvenanceAttestationV2.ModelProvenance[](0);
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, none);
        _expectRevert(ProvenanceAttestationV2.InvalidModelMetadata.selector, ret, ok);
    }

    function testRejectsTooManyModels() external {
        ProvenanceAttestationV2.ModelProvenance[] memory many = new ProvenanceAttestationV2.ModelProvenance[](17);
        for (uint256 i = 0; i < 17; i++) {
            many[i] = ProvenanceAttestationV2.ModelProvenance({
                name: "m", provider: "", modelId: "", endpoint: "",
                status: "success", contribution: "SUCCEEDED", verdict: "",
                inputDigest: ZERO, outputDigest: ZERO
            });
        }
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, many);
        _expectRevert(ProvenanceAttestationV2.InvalidModelMetadata.selector, ret, ok);
    }

    function testRejectsOverlongString() external {
        ProvenanceAttestationV2.ModelProvenance[] memory m = _twoModels();
        m[0].name = new string(257);
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, m);
        _expectRevert(ProvenanceAttestationV2.InvalidModelMetadata.selector, ret, ok);
    }

    function testRejectsEmptyStatus() external {
        ProvenanceAttestationV2.ModelProvenance[] memory m = _twoModels();
        m[0].status = "";
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, m);
        _expectRevert(ProvenanceAttestationV2.InvalidModelMetadata.selector, ret, ok);
    }

    function testRejectsEmptyContribution() external {
        ProvenanceAttestationV2.ModelProvenance[] memory m = _twoModels();
        m[1].contribution = "";
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, m);
        _expectRevert(ProvenanceAttestationV2.InvalidModelMetadata.selector, ret, ok);
    }

    // -- duplicate policy ----------------------------------------------------

    function testIdenticalResubmitSucceeds() external {
        registry.attest("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, _twoModels());
        // Identical resubmission must succeed silently (event-count
        // assertion lives in the Anvil e2e).
        registry.attest("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, _twoModels());
        (, bytes32 d, , , , , ProvenanceAttestationV2.ModelProvenance[] memory models) =
            _get("inv-v2-1", ATTESTER);
        require(d == DIGEST, "record intact");
        require(models.length == 2, "models intact");
    }

    function testConflictingDigestReverts() external {
        registry.attest("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, _twoModels());
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST_B, 1, ALLOW, TXHASH, ATTESTER, _twoModels());
        _expectRevert(ProvenanceAttestationV2.ConflictingAttestation.selector, ret, ok);
    }

    function testConflictingModelsRevert() external {
        registry.attest("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, _twoModels());
        ProvenanceAttestationV2.ModelProvenance[] memory altered = _twoModels();
        altered[1].contribution = "SUCCEEDED";
        (bool ok, bytes memory ret) =
            _attestRaw("inv-v2-1", DIGEST, 1, ALLOW, TXHASH, ATTESTER, altered);
        _expectRevert(ProvenanceAttestationV2.ConflictingAttestation.selector, ret, ok);
    }

    function testUnknownAttestationReverts() external {
        (bool ok, bytes memory ret) = address(registry).call(
            abi.encodeCall(registry.getAttestation, ("nope", ATTESTER))
        );
        _expectRevert(ProvenanceAttestationV2.UnknownAttestation.selector, ret, ok);
    }
}
