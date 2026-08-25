// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./lib/StringBounds.sol";

/// @title PolicyCommitment — on-chain anchor for versioned policy hashes
/// @notice Each policy version has its hash committed on-chain. Trust assessments
///         reference the policy version used, enabling reproducible historical evaluation.
///         The full policy text is stored off-chain (IPFS); only hashes live here.
///         Supports UUPS proxy upgradeability.
contract PolicyCommitment is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error PolicyNotFound(string policyId);
    error PolicyAlreadyExists(string policyId, uint256 version);
    error EmptyPolicyHash();
    error NotPolicyAuthority(address caller);
    error NotInitialized();

    event PolicyCommitted(
        string  indexed policyId,
        uint256 indexed version,
        bytes32 policyHash,
        string  policyURI,
        address committedBy,
        uint256 timestamp
    );

    event PolicyDeactivated(
        string  indexed policyId,
        uint256 indexed version,
        uint256 timestamp
    );

    struct PolicyVersion {
        string  policyId;
        uint256 version;
        bytes32 policyHash;
        string  policyURI;
        address committedBy;
        uint256 timestamp;
        bool    active;
    }

    struct PolicyInfo {
        uint256 latestVersion;
        uint256 totalVersions;
        bool    exists;
    }

    mapping(string => PolicyInfo) private _policyInfos;
    mapping(string => mapping(uint256 => PolicyVersion)) private _policyVersions;
    mapping(string => uint256[]) private _versionsByPolicyId;
    string[] private _allPolicyIds;

    bytes32 public constant POLICY_AUTHORITY_ROLE = keccak256("POLICY_AUTHORITY_ROLE");

    bool private _initialized;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Prevent initialization of the raw implementation (UUPS best practice).
        _disableInitializers();
    }

    function initialize() public initializer {
        if (_initialized) revert NotInitialized();
        _initialized = true;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(POLICY_AUTHORITY_ROLE, msg.sender);
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Commit a new policy version on-chain (direct, requires POLICY_AUTHORITY_ROLE)
    /// @param policyId   Unique policy identifier (e.g., "ncua_part_748_pqc")
    /// @param version    Version number (must be latestVersion + 1)
    /// @param policyHash SHA-256 of the policy text
    /// @param policyURI  IPFS URI for the full policy text
    function commitPolicy(
        string calldata policyId,
        uint256 version,
        bytes32 policyHash,
        string calldata policyURI
    ) external nonReentrant whenNotPaused onlyRole(POLICY_AUTHORITY_ROLE) {
        StringBounds.checkDID(policyId);
        StringBounds.checkURI(policyURI);
        if (policyHash == bytes32(0)) revert EmptyPolicyHash();

        PolicyInfo storage info = _policyInfos[policyId];
        if (info.exists && version <= info.latestVersion) {
            revert PolicyAlreadyExists(policyId, version);
        }

        _policyVersions[policyId][version] = PolicyVersion({
            policyId: policyId,
            version: version,
            policyHash: policyHash,
            policyURI: policyURI,
            committedBy: msg.sender,
            timestamp: block.timestamp,
            active: true
        });

        _versionsByPolicyId[policyId].push(version);

        if (!info.exists) {
            _allPolicyIds.push(policyId);
            info.exists = true;
        }
        info.latestVersion = version;
        info.totalVersions++;

        emit PolicyCommitted(policyId, version, policyHash, policyURI, msg.sender, block.timestamp);
    }

    /// @notice Deactivate a specific policy version (admin only)
    function deactivatePolicy(
        string calldata policyId,
        uint256 version
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        PolicyVersion storage pv = _policyVersions[policyId][version];
        if (pv.timestamp == 0) revert PolicyNotFound(policyId);
        pv.active = false;

        emit PolicyDeactivated(policyId, version, block.timestamp);
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

    /// @notice Get a specific policy version
    function getPolicyVersion(
        string calldata policyId,
        uint256 version
    ) external view returns (PolicyVersion memory) {
        PolicyVersion storage pv = _policyVersions[policyId][version];
        if (pv.timestamp == 0) revert PolicyNotFound(policyId);
        return pv;
    }

    /// @notice Get policy info (latest version, total versions)
    function getPolicyInfo(string calldata policyId) external view returns (PolicyInfo memory) {
        return _policyInfos[policyId];
    }

    /// @notice Get all versions for a policy ID
    function getVersionsByPolicyId(string calldata policyId) external view returns (uint256[] memory) {
        return _versionsByPolicyId[policyId];
    }

    /// @notice Get all policy IDs
    function getAllPolicyIds() external view returns (string[] memory) {
        return _allPolicyIds;
    }

    /// @notice Verify a policy commitment: hash matches the committed version
    function verifyPolicy(
        string calldata policyId,
        uint256 version,
        bytes32 policyHash
    ) external view returns (bool) {
        PolicyVersion storage pv = _policyVersions[policyId][version];
        if (pv.timestamp == 0) return false;
        return pv.policyHash == policyHash && pv.active;
    }

    /// @notice Total number of distinct policies
    function policyCount() external view returns (uint256) {
        return _allPolicyIds.length;
    }
}
