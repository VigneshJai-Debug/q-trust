// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./AssetRegistry.sol";

/// @title MigrationRegistry — records each PQC migration step
/// @notice Each step is one asset migrating from one algorithm to another.
///         Evidence (e.g., HSM log) is stored off-chain; only its hash is on-chain.
///         Migration steps are validated against the AssetRegistry: an org can
///         only record migrations for assets it actually registered.
contract MigrationRegistry is AccessControl, ReentrancyGuard {

    error MigrationNotFound(bytes32 migrationId);
    error DuplicateMigration(bytes32 migrationId);
    error NotMigrator(address caller);
    error AssetNotRegistered(bytes32 assetId);
    error AssetInactive(bytes32 assetId);
    error EmptyEvidenceHash();
    error SameAlgorithm(string algorithm);
    error ZeroAssetRegistry();

    event MigrationRecorded(
        bytes32 indexed migrationId,
        bytes32 indexed assetId,
        address indexed orgDid,
        string  fromAlgorithm,
        string  toAlgorithm,
        bytes32 evidenceHash,
        string  evidenceURI,
        uint256 timestamp
    );

    struct Migration {
        bytes32 assetId;        // Reference to AssetRegistry entry
        address orgDid;
        string  fromAlgorithm;  // e.g., "RSA-2048"
        string  toAlgorithm;    // e.g., "ML-DSA-441"
        bytes32 evidenceHash;    // Hash of migration evidence (HSM logs, etc.)
        string  evidenceURI;    // IPFS URI for evidence
        uint256 timestamp;
        bool    verified;       // True if auditor verified this migration
    }

    mapping(bytes32 => Migration) private _migrations;
    mapping(bytes32 => bytes32[]) private _migrationsByAsset;   // assetId => migration IDs
    mapping(address => bytes32[]) private _migrationsByOrg;    // org => migration IDs
    bytes32[] private _allMigrationIds;

    bytes32 public constant MIGRATOR_ROLE = keccak256("MIGRATOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /// @notice The AssetRegistry this registry validates against.
    AssetRegistry public immutable assetRegistry;

    constructor(address assetRegistry_) {
        if (assetRegistry_ == address(0)) revert ZeroAssetRegistry();
        assetRegistry = AssetRegistry(assetRegistry_);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MIGRATOR_ROLE, msg.sender);
        _grantRole(AUDITOR_ROLE, msg.sender);
    }

    /// @notice Record a migration step. The referenced asset must exist and be
    ///         active in the AssetRegistry, the evidence hash must be non-zero,
    ///         and the target algorithm must differ from the source.
    /// @param migrationId  The ID of the migration
    /// @param assetId      The ID of the asset being migrated
    /// @param fromAlgorithm The original algorithm
    /// @param toAlgorithm   The target algorithm
    /// @param evidenceHash  Hash of the migration evidence
    /// @param evidenceURI   IPFS URI for evidence
    function recordMigration(
        bytes32 migrationId,
        bytes32 assetId,
        string calldata fromAlgorithm,
        string calldata toAlgorithm,
        bytes32 evidenceHash,
        string calldata evidenceURI
    ) external nonReentrant onlyRole(MIGRATOR_ROLE) {
        if (_migrations[migrationId].orgDid != address(0)) revert DuplicateMigration(migrationId);

        // Cross-contract integrity: the asset must exist and be active.
        (bool exists, bool active, ) = assetRegistry.verifyAsset(assetId);
        if (!exists) revert AssetNotRegistered(assetId);
        if (!active) revert AssetInactive(assetId);

        if (evidenceHash == bytes32(0)) revert EmptyEvidenceHash();
        if (keccak256(abi.encodePacked(fromAlgorithm)) == keccak256(abi.encodePacked(toAlgorithm))) {
            revert SameAlgorithm(fromAlgorithm);
        }

        _migrations[migrationId] = Migration({
            assetId: assetId,
            orgDid: msg.sender,
            fromAlgorithm: fromAlgorithm,
            toAlgorithm: toAlgorithm,
            evidenceHash: evidenceHash,
            evidenceURI: evidenceURI,
            timestamp: block.timestamp,
            verified: false
        });

        _migrationsByAsset[assetId].push(migrationId);
        _migrationsByOrg[msg.sender].push(migrationId);
        _allMigrationIds.push(migrationId);

        emit MigrationRecorded(
            migrationId, assetId, msg.sender,
            fromAlgorithm, toAlgorithm, evidenceHash, evidenceURI, block.timestamp
        );
    }

    /// @notice Auditor marks a migration as verified
    function verifyMigration(bytes32 migrationId) external onlyRole(AUDITOR_ROLE) {
        if (_migrations[migrationId].orgDid == address(0)) revert MigrationNotFound(migrationId);
        _migrations[migrationId].verified = true;
    }

    // ============ View Functions ============

    function getMigration(bytes32 migrationId) external view returns (Migration memory) {
        if (_migrations[migrationId].orgDid == address(0)) revert MigrationNotFound(migrationId);
        return _migrations[migrationId];
    }

    function getMigrationsByAsset(bytes32 assetId) external view returns (bytes32[] memory) {
        return _migrationsByAsset[assetId];
    }

    function getMigrationsByOrg(address orgDid) external view returns (bytes32[] memory) {
        return _migrationsByOrg[orgDid];
    }

    /// @notice Total number of migrations recorded across all orgs
    function migrationCount() external view returns (uint256) {
        return _allMigrationIds.length;
    }
}