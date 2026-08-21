// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./MigrationRegistry.sol";

/// @title AuditRegistry — third-party audit attestations
/// @notice Auditors (Big 4, BSI, ORCHA) post attestations that they reviewed
///         an organization's PQC migration posture and either passed or failed it.
///         Audits are bound to on-chain state: the claimed number of migrated
///         assets cannot exceed the migrations actually recorded on-chain.
contract AuditRegistry is AccessControl {

    error AuditNotFound(bytes32 auditId);
    error DuplicateAudit(bytes32 auditId);
    error NotAuditor(address caller);
    error EmptyReportHash();
    error InvalidCounts(uint256 assetsReviewed, uint256 assetsMigrated);
    error MigratedCountExceedsOnChain(uint256 claimed, uint256 onChain);
    error ZeroMigrationRegistry();

    event AuditPosted(
        bytes32 indexed auditId,
        address indexed orgDid,        // The org being audited
        address indexed auditorDid,    // The auditor
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,            // Hash of the audit report (off-chain)
        string  reportURI,             // IPFS URI of the report
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
    mapping(address => bytes32[]) private _auditsByOrg;     // org -> audit IDs
    mapping(address => bytes32[]) private _auditsByAuditor;  // auditor -> audit IDs

    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /// @notice The MigrationRegistry used to bind audits to on-chain state.
    MigrationRegistry public immutable migrationRegistry;

    constructor(address migrationRegistry_) {
        if (migrationRegistry_ == address(0)) revert ZeroMigrationRegistry();
        migrationRegistry = MigrationRegistry(migrationRegistry_);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Post an audit attestation
    /// @param orgDid          The organization being audited
    /// @param result         Audit result (Passed/Failed/Conditional)
    /// @param assetsReviewed Total assets the auditor reviewed
    /// @param assetsMigrated How many of those were already migrated
    /// @param reportHash     Hash of the audit report PDF
    /// @param reportURI      IPFS URI of the report
    function postAudit(
        address orgDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string calldata reportURI
    ) external onlyRole(AUDITOR_ROLE) returns (bytes32 auditId) {
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
    /// @return exists  True if any audit exists
    /// @return result  The result of the latest audit
    /// @return timestamp When the audit was posted
    function getLatestAudit(address orgDid)
        external view returns (bool exists, AuditResult result, uint256 timestamp)
    {
        bytes32[] memory ids = _auditsByOrg[orgDid];
        if (ids.length == 0) return (false, AuditResult.Pending, 0);
        AuditAttestation storage latest = _audits[ids[ids.length - 1]];
        return (true, latest.result, latest.timestamp);
    }
}
