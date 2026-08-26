// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./MigrationRegistry.sol";
import "./lib/StringBounds.sol";

/// @title AuditRegistry — third-party audit attestations
/// @notice Auditors post attestations that they reviewed an organization's PQC
///         migration posture. Supports EIP-712 gasless posting and UUPS proxy
///         upgradeability.
contract AuditRegistry is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error AuditNotFound(bytes32 auditId);
    error DuplicateAudit(bytes32 auditId);
    error NotAuditor(address caller);
    error EmptyReportHash();
    error InvalidCounts(uint256 assetsReviewed, uint256 assetsMigrated);
    error MigratedCountExceedsOnChain(uint256 claimed, uint256 onChain);
    error ZeroMigrationRegistry();
    error InvalidSignature();
    error InvalidNonce(address signer, uint256 provided, uint256 expected);

    event AuditPosted(
        bytes32 indexed auditId,
        address indexed orgDid,
        address indexed auditorDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string  reportURI,
        uint256 timestamp
    );

    enum AuditResult { Pending, Passed, Failed, Conditional }

    struct AuditAttestation {
        address orgDid;
        address auditorDid;
        AuditResult result;
        uint256 assetsReviewed;
        uint256 assetsMigrated;
        bytes32 reportHash;
        string  reportURI;
        uint256 timestamp;
    }

    mapping(bytes32 => AuditAttestation) private _audits;
    mapping(address => bytes32[]) private _auditsByOrg;
    mapping(address => bytes32[]) private _auditsByAuditor;

    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /// @notice The MigrationRegistry used to bind audits to on-chain state.
    MigrationRegistry public migrationRegistry;

    // ==================== EIP-712 (gasless audit posting) ====================
    bytes32 private constant _AUDIT_TYPEHASH =
        keccak256(
            "Audit(address orgDid,uint8 result,uint256 assetsReviewed,uint256 assetsMigrated,"
            "bytes32 reportHash,string reportURI,uint256 nonce)"
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

    function initialize(address migrationRegistry_) public initializer {
        if (migrationRegistry_ == address(0)) revert ZeroMigrationRegistry();
        migrationRegistry = MigrationRegistry(migrationRegistry_);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _cachedChainId = block.chainid;
        _domainSeparator = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustAuditRegistry"),
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
                keccak256("QTrustAuditRegistry"),
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

    /// @notice Hash the typed Audit data for EIP-712 signing.
    function hashTypedAudit(
        address orgDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string calldata reportURI,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _currentDomainSeparator(),
                keccak256(
                    abi.encode(
                        _AUDIT_TYPEHASH,
                        orgDid,
                        result,
                        assetsReviewed,
                        assetsMigrated,
                        reportHash,
                        keccak256(abi.encodePacked(reportURI)),
                        nonce
                    )
                )
            )
        );
    }

    /// @notice Submit a gasless audit attestation signed by an auditor.
    ///         The signer must hold AUDITOR_ROLE; the caller (any relayer)
    ///         pays the gas. The recorded auditorDid is the signer.
    function postAuditSigned(
        address orgDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string calldata reportURI,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant whenNotPaused returns (bytes32 auditId) {
        address signer = _recoverAuditor(
            orgDid, result, assetsReviewed, assetsMigrated, reportHash, reportURI, nonce, signature
        );
        if (signer == address(0)) revert InvalidSignature();
        if (nonces[signer] != nonce) {
            revert InvalidNonce(signer, nonce, nonces[signer]);
        }
        if (!hasRole(AUDITOR_ROLE, signer)) revert NotAuditor(signer);

        nonces[signer] = nonce + 1;

        return _postAudit(signer, orgDid, result, assetsReviewed, assetsMigrated, reportHash, reportURI);
    }

    /// @dev Recover the EIP-712 signer of an audit attestation.
    function _recoverAuditor(
        address orgDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string calldata reportURI,
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
                        _AUDIT_TYPEHASH,
                        orgDid,
                        result,
                        assetsReviewed,
                        assetsMigrated,
                        reportHash,
                        keccak256(abi.encodePacked(reportURI)),
                        nonce
                    )
                )
            )
        );
        return ECDSA.recover(digest, signature);
    }

    /// @notice Post an audit attestation (direct, requires AUDITOR_ROLE)
    function postAudit(
        address orgDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string calldata reportURI
    ) external nonReentrant onlyRole(AUDITOR_ROLE) whenNotPaused returns (bytes32 auditId) {
        return _postAudit(msg.sender, orgDid, result, assetsReviewed, assetsMigrated, reportHash, reportURI);
    }

    /// @dev Shared audit posting logic shared by direct and EIP-712 paths.
    function _postAudit(
        address auditorDid,
        address orgDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string calldata reportURI
    ) internal returns (bytes32 auditId) {
        if (reportHash == bytes32(0)) revert EmptyReportHash();
        StringBounds.checkURI(reportURI);
        if (assetsMigrated > assetsReviewed) revert InvalidCounts(assetsReviewed, assetsMigrated);

        // Audit-state binding: an auditor cannot claim more migrated assets than
        // exist on-chain for the org.
        // Audit M-1: use the count-only view — fetching the full dynamic array
        // just to read .length was O(N) gas on every audit posting.
        uint256 onChainMigrations = migrationRegistry.getMigrationCountByOrg(orgDid);
        if (assetsMigrated > onChainMigrations) {
            revert MigratedCountExceedsOnChain(assetsMigrated, onChainMigrations);
        }

        auditId = keccak256(abi.encode(
            auditorDid, orgDid, reportHash
        ));

        if (_audits[auditId].auditorDid != address(0)) {
            revert DuplicateAudit(auditId);
        }

        _audits[auditId] = AuditAttestation({
            orgDid: orgDid,
            auditorDid: auditorDid,
            result: result,
            assetsReviewed: assetsReviewed,
            assetsMigrated: assetsMigrated,
            reportHash: reportHash,
            reportURI: reportURI,
            timestamp: block.timestamp
        });

        _auditsByOrg[orgDid].push(auditId);
        _auditsByAuditor[auditorDid].push(auditId);

        emit AuditPosted(
            auditId, orgDid, auditorDid, result,
            assetsReviewed, assetsMigrated,
            reportHash, reportURI, block.timestamp
        );
    }

    /// @notice Pause all operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Get an audit by ID
    function getAudit(bytes32 auditId) external view returns (AuditAttestation memory) {
        if (_audits[auditId].auditorDid == address(0)) revert AuditNotFound(auditId);
        return _audits[auditId];
    }

    /// @notice Get all audits for an org
    /// Audit M-1: unbounded return array; prefer getAuditCountByOrg +
    /// getAuditsByOrgPaged for programmatic consumption.
    function getAuditsByOrg(address orgDid) external view returns (bytes32[] memory) {
        return _auditsByOrg[orgDid];
    }

    /// @notice Get all audits by an auditor
    /// Audit M-1: unbounded return array; prefer getAuditCountByAuditor +
    /// getAuditsByAuditorPaged for programmatic consumption.
    function getAuditsByAuditor(address auditorDid) external view returns (bytes32[] memory) {
        return _auditsByAuditor[auditorDid];
    }

    /// @notice Number of audits posted against an org (audit M-1).
    function getAuditCountByOrg(address orgDid) external view returns (uint256) {
        return _auditsByOrg[orgDid].length;
    }

    /// @notice Number of audits posted by an auditor (audit M-1).
    function getAuditCountByAuditor(address auditorDid) external view returns (uint256) {
        return _auditsByAuditor[auditorDid].length;
    }

    /// @notice Paginated audit IDs for an org (audit M-1).
    function getAuditsByOrgPaged(address orgDid, uint256 offset, uint256 limit)
        external view returns (bytes32[] memory page, uint256 total)
    {
        return _paged(_auditsByOrg[orgDid], offset, limit);
    }

    /// @notice Paginated audit IDs by an auditor (audit M-1).
    function getAuditsByAuditorPaged(address auditorDid, uint256 offset, uint256 limit)
        external view returns (bytes32[] memory page, uint256 total)
    {
        return _paged(_auditsByAuditor[auditorDid], offset, limit);
    }

    /// @dev Shared pagination helper (audit M-1).
    function _paged(bytes32[] storage ids, uint256 offset, uint256 limit)
        internal view returns (bytes32[] memory page, uint256 total)
    {
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

    /// @notice Get the latest audit for an org
    function getLatestAudit(address orgDid)
        external view returns (bool exists, AuditResult result, uint256 timestamp)
    {
        bytes32[] memory ids = _auditsByOrg[orgDid];
        if (ids.length == 0) return (false, AuditResult.Pending, 0);
        AuditAttestation storage latest = _audits[ids[ids.length - 1]];
        return (true, latest.result, latest.timestamp);
    }
}
