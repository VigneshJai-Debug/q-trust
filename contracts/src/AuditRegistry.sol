// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./MigrationRegistry.sol";

/// @title AuditRegistry — third-party audit attestations
/// @notice Auditors post attestations that they reviewed an organization's PQC
///         migration posture. Supports UUPS proxy upgradeability.
contract AuditRegistry is AccessControl, Pausable, Initializable, UUPSUpgradeable {

    error AuditNotFound(bytes32 auditId);
    error DuplicateAudit(bytes32 auditId);
    error NotAuditor(address caller);
    error EmptyReportHash();
    error InvalidCounts(uint256 assetsReviewed, uint256 assetsMigrated);
    error MigratedCountExceedsOnChain(uint256 claimed, uint256 onChain);
    error ZeroMigrationRegistry();
    error NotInitialized();

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

    bool private _initialized;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {}

    function initialize(address migrationRegistry_) public initializer {
        if (_initialized) revert NotInitialized();
        if (migrationRegistry_ == address(0)) revert ZeroMigrationRegistry();
        _initialized = true;
        migrationRegistry = MigrationRegistry(migrationRegistry_);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Post an audit attestation
    function postAudit(
        address orgDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string calldata reportURI
    ) external onlyRole(AUDITOR_ROLE) whenNotPaused returns (bytes32 auditId) {
        if (reportHash == bytes32(0)) revert EmptyReportHash();
        if (assetsMigrated > assetsReviewed) revert InvalidCounts(assetsReviewed, assetsMigrated);

        // Audit-state binding: an auditor cannot claim more migrated assets than
        // exist on-chain for the org.
        uint256 onChainMigrations = migrationRegistry.getMigrationsByOrg(orgDid).length;
        if (assetsMigrated > onChainMigrations) {
            revert MigratedCountExceedsOnChain(assetsMigrated, onChainMigrations);
        }

        auditId = keccak256(abi.encodePacked(
            msg.sender, orgDid, reportHash, block.timestamp
        ));

        if (_audits[auditId].auditorDid != address(0)) {
            revert DuplicateAudit(auditId);
        }

        _audits[auditId] = AuditAttestation({
            orgDid: orgDid,
            auditorDid: msg.sender,
            result: result,
            assetsReviewed: assetsReviewed,
            assetsMigrated: assetsMigrated,
            reportHash: reportHash,
            reportURI: reportURI,
            timestamp: block.timestamp
        });

        _auditsByOrg[orgDid].push(auditId);
        _auditsByAuditor[msg.sender].push(auditId);

        emit AuditPosted(
            auditId, orgDid, msg.sender, result,
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
    function getAuditsByOrg(address orgDid) external view returns (bytes32[] memory) {
        return _auditsByOrg[orgDid];
    }

    /// @notice Get all audits by an auditor
    function getAuditsByAuditor(address auditorDid) external view returns (bytes32[] memory) {
        return _auditsByAuditor[auditorDid];
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
