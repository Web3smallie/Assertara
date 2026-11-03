// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @title Assertara Provenance Attestation Registry (dynamic model metadata)
/// @notice Append-only record of off-chain provenance attestations that
///         additionally publishes readable per-model provenance.
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
///    manifest digest matches `manifestDigest`, that every `models`
///    entry matches the same manifest's model provenance, and that the
///    attester was an authorized (ACTIVE, or corroborated retired)
///    registry key. The contract cannot check digest-to-metadata
///    linkage itself: the manifest lives off-chain.
///  - What this contract DOES enforce: input shape (non-empty bounded
///    investigation id, non-zero digest, bitmap 0-3, known decision,
///    bounded model array with bounded strings), the BLOCK/REVIEW
///    zero-transaction-hash rule, and no conflicting duplicate for the
///    same (investigationId, attester) pair.
///  - This contract is MODEL-AGNOSTIC: it stores whatever model entries
///    the publisher submits and names no model, provider, or outcome.
///    Model metadata arrives exclusively from the verified manifest via
///    the publisher; the contract only bounds its shape.
///  - `modelBitmap` is a compatibility field preserving the original
///    registry's convention (publisher-derived from manifest
///    contribution levels). Detailed per-model truth lives in `models`.
///  - Non-upgradeable by design: no owner, no pause, no access control.
///    Records, once written, are never modified or deleted.
contract ProvenanceAttestationV2 {
    /// @dev 0 = ALLOW, 1 = BLOCK, 2 = REVIEW. UNCERTAIN investigations
    ///      cannot be attested on-chain; they must resolve first.
    enum Decision {
        ALLOW,
        BLOCK,
        REVIEW
    }

    /// @dev One genuine model-provenance entry, derived dynamically from
    ///      the verified manifest. Empty strings and zero digests mean
    ///      the corresponding metadata was unavailable — never success.
    struct ModelProvenance {
        string name;
        string provider;
        string modelId;
        string endpoint;
        string status;
        string contribution;
        string verdict;
        bytes32 inputDigest;
        bytes32 outputDigest;
    }

    struct Attestation {
        string investigationId;
        bytes32 manifestDigest;
        uint8 modelBitmap;
        Decision decision;
        bytes32 txHash;
        address attester;
        ModelProvenance[] models;
        bool exists;
    }

    /// @dev investigationId and manifestDigest are indexed for lookup;
    ///      attester is indexed so verifiers can filter by authority.
    ///      `models` is dynamic and therefore non-indexed by design.
    event AttestedWithModels(
        string indexed investigationId,
        bytes32 indexed manifestDigest,
        address indexed attester,
        uint8 modelBitmap,
        Decision decision,
        bytes32 txHash,
        ModelProvenance[] models
    );

    error EmptyInvestigationId();
    error InvestigationIdTooLong();
    error ZeroManifestDigest();
    error InvalidModelBitmap();
    error InvalidDecision();
    error ZeroAttester();
    error NonZeroTxHashForNonExecuted();
    error InvalidModelMetadata();
    error ConflictingAttestation();
    error UnknownAttestation();

    uint256 private constant MAX_INVESTIGATION_ID_BYTES = 256;
    uint8 private constant MAX_MODEL_BITMAP = 3;
    uint256 private constant MAX_MODELS = 16;
    uint256 private constant MAX_MODEL_STRING_BYTES = 256;

    mapping(bytes32 => Attestation) private _records;

    /// @notice Record a verified off-chain attestation with model metadata.
    /// @dev Duplicate policy: an identical resubmission for the same
    ///      (investigationId, attester) — core fields AND model entries —
    ///      succeeds silently WITHOUT emitting a second event (idempotent
    ///      publishers); any differing field reverts with
    ///      ConflictingAttestation. Different attesters hold independent
    ///      records for the same investigation (e.g. re-attestation after
    ///      key rotation).
    function attest(
        string calldata investigationId,
        bytes32 manifestDigest,
        uint8 modelBitmap,
        uint8 decision,
        bytes32 txHash,
        address attester,
        ModelProvenance[] calldata models
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
        if (models.length == 0 || models.length > MAX_MODELS) revert InvalidModelMetadata();
        for (uint256 i = 0; i < models.length; i++) {
            ModelProvenance calldata m = models[i];
            if (
                bytes(m.name).length > MAX_MODEL_STRING_BYTES ||
                bytes(m.provider).length > MAX_MODEL_STRING_BYTES ||
                bytes(m.modelId).length > MAX_MODEL_STRING_BYTES ||
                bytes(m.endpoint).length > MAX_MODEL_STRING_BYTES ||
                bytes(m.status).length > MAX_MODEL_STRING_BYTES ||
                bytes(m.contribution).length > MAX_MODEL_STRING_BYTES ||
                bytes(m.verdict).length > MAX_MODEL_STRING_BYTES
            ) revert InvalidModelMetadata();
            if (bytes(m.status).length == 0 || bytes(m.contribution).length == 0) {
                revert InvalidModelMetadata();
            }
        }
        bytes32 key = _recordKey(investigationId, attester);
        Attestation storage existing = _records[key];
        if (existing.exists) {
            if (
                existing.manifestDigest == manifestDigest &&
                existing.modelBitmap == modelBitmap &&
                existing.decision == Decision(decision) &&
                existing.txHash == txHash &&
                keccak256(abi.encode(existing.models)) == keccak256(abi.encode(models))
            ) {
                return;
            }
            revert ConflictingAttestation();
        }
        _records[key].investigationId = investigationId;
        _records[key].manifestDigest = manifestDigest;
        _records[key].modelBitmap = modelBitmap;
        _records[key].decision = Decision(decision);
        _records[key].txHash = txHash;
        _records[key].attester = attester;
        for (uint256 i = 0; i < models.length; i++) {
            _records[key].models.push(models[i]);
        }
        _records[key].exists = true;
        emit AttestedWithModels(
            investigationId,
            manifestDigest,
            attester,
            modelBitmap,
            Decision(decision),
            txHash,
            models
        );
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
            address outAttester,
            ModelProvenance[] memory outModels
        )
    {
        Attestation storage a = _records[_recordKey(investigationId, attester)];
        if (!a.exists) revert UnknownAttestation();
        return (
            a.investigationId,
            a.manifestDigest,
            a.modelBitmap,
            a.decision,
            a.txHash,
            a.attester,
            a.models
        );
    }

    function _recordKey(string calldata investigationId, address attester) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(investigationId, attester));
    }
}
