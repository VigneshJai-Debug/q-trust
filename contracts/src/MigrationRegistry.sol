// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./AssetRegistry.sol";
import "./lib/StringBounds.sol";

/// @title MigrationRegistry — records each PQC migration step
/// @notice Each step is one asset migrating from one algorithm to another.
///         Supports EIP-712 gasless migration recording and UUPS proxy upgradeability.
contract MigrationRegistry is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error MigrationNotFound(bytes32 migrationId);
    error DuplicateMigration(bytes32 migrationId);
    error NotMigrator(address caller);
    error AssetNotRegistered(bytes32 assetId);
    error AssetInactive(bytes32 assetId);
    error NotAssetOwner(address caller, bytes32 assetId);
    error EmptyEvidenceHash();
    error SameAlgorithm(string algorithm);
    error ZeroAssetRegistry();
    error InvalidSignature();
    error InvalidNonce(address signer, uint256 provided, uint256 expected);

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

    event MigrationVerified(
        bytes32 indexed migrationId,
        address indexed verifiedBy,
        uint256 timestamp
    );

    struct Migration {
        bytes32 assetId;
        address orgDid;
        string  fromAlgorithm;
        string  toAlgorithm;
        bytes32 evidenceHash;
        string  evidenceURI;
        uint256 timestamp;
        bool    verified;
    }

    mapping(bytes32 => Migration) private _migrations;
    mapping(bytes32 => bytes32[]) private _migrationsByAsset;
    mapping(address => bytes32[]) private _migrationsByOrg;
    bytes32[] private _allMigrationIds;

    bytes32 public constant MIGRATOR_ROLE = keccak256("MIGRATOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /// @notice The AssetRegistry this registry validates against.
    AssetRegistry public assetRegistry;

    // ==================== EIP-712 (gasless migration recording) ====================
    bytes32 private constant _MIGRATION_RECORDING_TYPEHASH =
        keccak256(
            "MigrationRecording(bytes32 migrationId,bytes32 assetId,string fromAlgorithm,"
            "string toAlgorithm,bytes32 evidenceHash,string evidenceURI,uint256 nonce)"
        );

    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private _domainSeparator;
    bytes32 public constant EIP712_VERSION_HASH = keccak256("1");

    mapping(address => uint256) public nonces;

    uint256 private _cachedChainId;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Prevent initialization of the raw implementation (UUPS best practice).
        _disableInitializers();
    }

    function initialize(address assetRegistry_) public initializer {
        if (assetRegistry_ == address(0)) revert ZeroAssetRegistry();
        assetRegistry = AssetRegistry(assetRegistry_);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MIGRATOR_ROLE, msg.sender);
        _grantRole(AUDITOR_ROLE, msg.sender);
        _cachedChainId = block.chainid;
        _domainSeparator = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustMigrationRegistry"),
                EIP712_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Domain separator for EIP-712 typed data signing.
    function domainSeparator() external view returns (bytes32) {
        return _currentDomainSeparator();
    }

    /// @dev Build the domain separator for the currently executing chain.
    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustMigrationRegistry"),
                EIP712_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    /// @dev Cached separator when the chain matches, else a freshly built one.
    function _currentDomainSeparator() internal view returns (bytes32) {
        return block.chainid == _cachedChainId ? _domainSeparator : _buildDomainSeparator();
    }

    /// @dev Cache the separator for the current chain (EIP-712 defensive copy).
    function _cacheDomainSeparator() internal {
        if (_cachedChainId != block.chainid) {
            _cachedChainId = block.chainid;
            _domainSeparator = _buildDomainSeparator();
        }
    }

    /// @notice Hash the typed Migration Recording data for EIP-712 signing.
    function hashTypedMigration(
        bytes32 migrationId,
        bytes32 assetId,
        string calldata fromAlgorithm,
        string calldata toAlgorithm,
        bytes32 evidenceHash,
        string calldata evidenceURI,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _currentDomainSeparator(),
                keccak256(
                    abi.encode(
                        _MIGRATION_RECORDING_TYPEHASH,
                        migrationId,
                        assetId,
                        keccak256(abi.encodePacked(fromAlgorithm)),
                        keccak256(abi.encodePacked(toAlgorithm)),
                        evidenceHash,
                        keccak256(abi.encodePacked(evidenceURI)),
                        nonce
                    )
                )
            )
        );
    }

    /// @notice Submit a gasless migration recording signed by the org.
    ///         The org's signature authorizes the migration; the caller
    ///         (any relayer) pays the gas. The recorded orgDid is the signer.
    function recordMigrationSigned(
        bytes32 migrationId,
        bytes32 assetId,
        string calldata fromAlgorithm,
        string calldata toAlgorithm,
        bytes32 evidenceHash,
        string calldata evidenceURI,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant whenNotPaused returns (bytes32 recordedMigrationId) {
        address signer = _recoverMigrationSigner(
            migrationId, assetId, fromAlgorithm, toAlgorithm,
            evidenceHash, evidenceURI, nonce, signature
        );
        if (signer == address(0)) revert InvalidSignature();
        // The signature proves intent, not authority: the signer must hold
        // MIGRATOR_ROLE exactly like the direct path requires.
        if (!hasRole(MIGRATOR_ROLE, signer)) revert NotMigrator(signer);
        if (nonces[signer] != nonce) {
            revert InvalidNonce(signer, nonce, nonces[signer]);
        }

        nonces[signer] = nonce + 1;

        return _recordMigration(signer, migrationId, assetId, fromAlgorithm, toAlgorithm, evidenceHash, evidenceURI);
    }

    /// @dev Recover the EIP-712 signer of a migration recording.
    function _recoverMigrationSigner(
        bytes32 migrationId,
        bytes32 assetId,
        string calldata fromAlgorithm,
        string calldata toAlgorithm,
        bytes32 evidenceHash,
        string calldata evidenceURI,
        uint256 nonce,
        bytes calldata signature
    ) internal returns (address) {
        _cacheDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator,
                keccak256(
                    abi.encode(
                        _MIGRATION_RECORDING_TYPEHASH,
                        migrationId,
                        assetId,
                        keccak256(abi.encodePacked(fromAlgorithm)),
                        keccak256(abi.encodePacked(toAlgorithm)),
                        evidenceHash,
                        keccak256(abi.encodePacked(evidenceURI)),
                        nonce
                    )
                )
            )
        );
        return ECDSA.recover(digest, signature);
    }

    /// @notice Record a migration step (direct, requires MIGRATOR_ROLE)
    function recordMigration(
        bytes32 migrationId,
        bytes32 assetId,
        string calldata fromAlgorithm,
        string calldata toAlgorithm,
        bytes32 evidenceHash,
        string calldata evidenceURI
    ) external nonReentrant whenNotPaused onlyRole(MIGRATOR_ROLE) returns (bytes32 recordedMigrationId) {
        return _recordMigration(msg.sender, migrationId, assetId, fromAlgorithm, toAlgorithm, evidenceHash, evidenceURI);
    }

    /// @dev Internal migration recording logic shared by direct and EIP-712 paths.
    function _recordMigration(
        address orgDid,
        bytes32 migrationId,
        bytes32 assetId,
        string calldata fromAlgorithm,
        string calldata toAlgorithm,
        bytes32 evidenceHash,
        string calldata evidenceURI
    ) internal returns (bytes32 recordedMigrationId) {
        StringBounds.checkID(fromAlgorithm);
        StringBounds.checkID(toAlgorithm);
        StringBounds.checkURI(evidenceURI);

        if (_migrations[migrationId].orgDid != address(0)) revert DuplicateMigration(migrationId);

        // Cross-contract integrity: the asset must exist, be active, AND be
        // owned by the recording org (audit M-1 — without the ownership
        // check any migrator could record migrations against foreign assets).
        // Audit M-2: verifyAsset already returns orgDid — use it instead of
        // issuing a second getAsset cross-contract call just to read owner.
        (bool exists, bool active, address assetOrg) = assetRegistry.verifyAsset(assetId);
        if (!exists) revert AssetNotRegistered(assetId);
        if (!active) revert AssetInactive(assetId);
        if (assetOrg != orgDid) {
            revert NotAssetOwner(orgDid, assetId);
        }

        if (evidenceHash == bytes32(0)) revert EmptyEvidenceHash();
        if (keccak256(abi.encodePacked(fromAlgorithm)) == keccak256(abi.encodePacked(toAlgorithm))) {
            revert SameAlgorithm(fromAlgorithm);
        }

        _migrations[migrationId] = Migration({
            assetId: assetId,
            orgDid: orgDid,
            fromAlgorithm: fromAlgorithm,
            toAlgorithm: toAlgorithm,
            evidenceHash: evidenceHash,
            evidenceURI: evidenceURI,
            timestamp: block.timestamp,
            verified: false
        });

        _migrationsByAsset[assetId].push(migrationId);
        _migrationsByOrg[orgDid].push(migrationId);
        _allMigrationIds.push(migrationId);

        emit MigrationRecorded(
            migrationId, assetId, orgDid,
            fromAlgorithm, toAlgorithm, evidenceHash, evidenceURI, block.timestamp
        );

        return migrationId;
    }

    /// @notice Auditor marks a migration as verified
    function verifyMigration(bytes32 migrationId) external onlyRole(AUDITOR_ROLE) whenNotPaused {
        if (_migrations[migrationId].orgDid == address(0)) revert MigrationNotFound(migrationId);
        _migrations[migrationId].verified = true;
        // Audit L-1: the verified transition is trust-critical — auditors and
        // off-chain indexers must be able to observe it via event logs.
        emit MigrationVerified(migrationId, msg.sender, block.timestamp);
    }

    /// @notice Pause all operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
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

    /// @notice Number of migrations recorded by an org (audit M-1). Also used
    ///         by AuditRegistry to bound claims without copying the full array.
    function getMigrationCountByOrg(address orgDid) external view returns (uint256) {
        return _migrationsByOrg[orgDid].length;
    }

    /// @notice Paginated migration IDs for an org (audit M-1).
    function getMigrationsByOrgPaged(address orgDid, uint256 offset, uint256 limit)
        external view returns (bytes32[] memory page, uint256 total)
    {
        bytes32[] storage ids = _migrationsByOrg[orgDid];
        total = ids.length;
        if (offset >= total || limit == 0) return (new bytes32[](0), total);
        uint256 end = offset + limit;
        if (end > total) end = total;
        uint256 pageSize = end - offset;
        page = new bytes32[](pageSize);
        for (uint256 i = 0; i < pageSize; i++) {
            page[i] = ids[offset + i];
        }
    }

    /// @notice Total number of migrations recorded across all orgs
    function migrationCount() external view returns (uint256) {
        return _allMigrationIds.length;
    }
}
