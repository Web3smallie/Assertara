// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title Assertara Provenance Attestation Registry
/// @notice Minimal append-only record of off-chain provenance attestations.
/// @dev TRUST BOUNDARY — READ BEFORE VERIFYING:
///  - This contract does NOT verify EIP-191 signatures and performs no
///    canonical-JSON reconstruction. Signature validity is established
///    OFF-CHAIN by the existing Phase 3 verifier (`verifyAttestation`).
///  - The `attester` field is the address recovered from the Phase 3
///    EIP-191 attestation signature. It is accepted as a declared
///    parameter because the transaction sender (the eventual publisher)
///    may use a separate transaction-signing key: msg.sender is NOT
///    necessarily the attestation signer.
///  - An independent verifier MUST check, off-chain, that the recovered
///    Phase 3 signer matches the recorded `attester`, that the signed
///    manifest digest matches `manifestDigest`, and that the attester
///    was an authorized (ACTIVE, or corroborated retired) registry key.
///  - What this contract DOES enforce: input shape (non-empty bounded
///    investigation id, non-zero digest, bitmap 0-3, known decision),
///    the BLOCK/REVIEW zero-transaction-hash rule, and no conflicting
///    duplicate for the same (investigationId, attester) pair.
///  - Model bitmap semantics (set by the attester from genuine
///    contribution outcomes, never from configured or skipped stages):
///    bit 0 = Muse Spark successfully contributed to the investigation;
///    bit 1 = SAM 3.1 successfully contributed to the investigation.
///  - Non-upgradeable by design: no owner, no pause, no access control.
///    Records, once written, are never modified or deleted.
contract ProvenanceAttestation {
    /// @dev 0 = ALLOW, 1 = BLOCK, 2 = REVIEW. UNCERTAIN investigations
    ///      cannot be attested on-chain; they must resolve first.
    enum Decision {
        ALLOW,
        BLOCK,
        REVIEW
    }

    struct Attestation {
        string investigationId;
        bytes32 manifestDigest;
        uint8 modelBitmap;
        Decision decision;
        bytes32 txHash;
        address attester;
        bool exists;
    }

    /// @dev investigationId and manifestDigest are indexed for lookup;
    ///      attester is indexed so verifiers can filter by authority.
    event Attested(
        string indexed investigationId,
        bytes32 indexed manifestDigest,
        address indexed attester,
        uint8 modelBitmap,
        Decision decision,
        bytes32 txHash
    );

    error EmptyInvestigationId();
    error InvestigationIdTooLong();
    error ZeroManifestDigest();
    error InvalidModelBitmap();
    error InvalidDecision();
    error ZeroAttester();
    error NonZeroTxHashForNonExecuted();
    error ConflictingAttestation();
    error UnknownAttestation();

    uint256 private constant MAX_INVESTIGATION_ID_BYTES = 256;
    uint8 private constant MAX_MODEL_BITMAP = 3;

    mapping(bytes32 => Attestation) private _records;

    /// @notice Record a verified off-chain attestation.
    /// @dev Duplicate policy: an identical resubmission for the same
    ///      (investigationId, attester) succeeds silently WITHOUT emitting
    ///      a second event (idempotent publishers); any differing field
    ///      reverts with ConflictingAttestation. Different attesters hold
    ///      independent records for the same investigation (e.g.
    ///      re-attestation after key rotation).
    function attest(
        string calldata investigationId,
        bytes32 manifestDigest,
        uint8 modelBitmap,
        uint8 decision,
        bytes32 txHash,
        address attester
    ) external {
        uint256 idLen = bytes(investigationId).length;
        if (idLen == 0) revert EmptyInvestigationId();
        if (idLen > MAX_INVESTIGATION_ID_BYTES) revert InvestigationIdTooLong();
        if (manifestDigest == bytes32(0)) revert ZeroManifestDigest();
        if (modelBitmap > MAX_MODEL_BITMAP) revert InvalidModelBitmap();
        if (decision > uint8(Decision.REVIEW)) revert InvalidDecision();
        if (attester == address(0)) revert ZeroAttester();
        // BLOCK and REVIEW attestations must never imply an executed
        // payment. ALLOW permits a zero hash (pre-execution attestation).
        if (decision != uint8(Decision.ALLOW) && txHash != bytes32(0)) {
            revert NonZeroTxHashForNonExecuted();
        }
        bytes32 key = _recordKey(investigationId, attester);
        Attestation storage existing = _records[key];
        if (existing.exists) {
            if (
                existing.manifestDigest == manifestDigest &&
                existing.modelBitmap == modelBitmap &&
                existing.decision == Decision(decision) &&
                existing.txHash == txHash
            ) {
                return;
            }
            revert ConflictingAttestation();
        }
        _records[key] = Attestation({
            investigationId: investigationId,
            manifestDigest: manifestDigest,
            modelBitmap: modelBitmap,
            decision: Decision(decision),
            txHash: txHash,
            attester: attester,
            exists: true
        });
        emit Attested(investigationId, manifestDigest, attester, modelBitmap, Decision(decision), txHash);
    }

    /// @notice Read a stored attestation by investigation id and attester.
    function getAttestation(string calldata investigationId, address attester)
        external
        view
        returns (
            string memory outInvestigationId,
            bytes32 outManifestDigest,
            uint8 outModelBitmap,
            Decision outDecision,
            bytes32 outTxHash,
            address outAttester
        )
    {
        Attestation storage a = _records[_recordKey(investigationId, attester)];
        if (!a.exists) revert UnknownAttestation();
        return (a.investigationId, a.manifestDigest, a.modelBitmap, a.decision, a.txHash, a.attester);
    }

    function _recordKey(string calldata investigationId, address attester) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(investigationId, attester));
    }
}
