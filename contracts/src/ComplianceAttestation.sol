// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./lib/StringBounds.sol";

/// @title ComplianceAttestation — compliance attestation results from scanner evaluations
/// @notice Organizations post compliance scores against standard frameworks (e.g.,
///         NIST SP 800-131A, CNSA 2.0). Each attestation records the score, rule
///         breakdown, and links to supporting evidence. Supports EIP-712 gasless
///         attestation and UUPS proxy upgradeability.
contract ComplianceAttestation is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error AttestationNotFound(bytes32 attestationId);
    error DuplicateAttestation(bytes32 attestationId);
    error EmptyFramework();
    error ScoreOutOfBounds(uint256 score);
    error RuleCountMismatch(uint256 totalRules, uint256 compliantCount, uint256 nonCompliantCount);
    error InvalidValidityDays(uint256 validityDays);
    error NotOwner(address caller);
    error NotAttester(address caller);
    error AlreadyRevoked(bytes32 attestationId);
    error InvalidSignature();
    error InvalidNonce(address signer, uint256 provided, uint256 expected);

    event ComplianceAttested(
        bytes32 indexed attestationId,
        address indexed orgDid,
        string  framework,
        uint256 score,
        uint256 timestamp
    );

    event ComplianceRevoked(
        bytes32 indexed attestationId,
        string  reason,
        uint256 timestamp
    );

    struct Attestation {
        bytes32 attestationId;
        address orgDid;
        string  framework;       // e.g., "NIST_SP_800_131A", "CNSA_2_0"
        uint256 score;           // 0-100 compliance score
        uint256 totalRules;
        uint256 compliantCount;
        uint256 nonCompliantCount;
        bytes32 evidenceHash;    // hash of supporting evidence bundle
        uint256 timestamp;
        uint256 validUntil;
        bool    revoked;
    }

    mapping(bytes32 => Attestation) private _attestations;
    mapping(address => bytes32[]) private _attestationsByOrg;
    mapping(string => bytes32[]) private _attestationsByFramework;

    bytes32 public constant ATTESTER_ROLE = keccak256("ATTESTER_ROLE");

    // ==================== EIP-712 (gasless compliance attestation) ====================
    bytes32 private constant _ATTESTATION_TYPEHASH =
        keccak256(
            "AttestCompliance(string framework,uint256 score,uint256 totalRules,uint256 compliantCount,uint256 nonCompliantCount,bytes32 evidenceHash,uint256 validityDays,uint256 nonce)"
        );

    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private _domainSeparator;
    bytes32 public constant EIP712_VERSION_HASH = keccak256("1");

    mapping(address => uint256) public nonces;

    uint256 private _cachedChainId;

    // Audit M-4: latest attestation per (org, frameworkHash) so compliance
    // lookups are O(1) instead of scanning the entire unbounded per-org list
    // (an ATTESTER_ROLE holder could otherwise make lookups OOG by posting
    // thousands of attestations for a target org). Appended last to keep the
    // UUPS storage layout compatible with prior deployments.
    mapping(address => mapping(bytes32 => bytes32)) private _latestAttestation;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Prevent initialization of the raw implementation (UUPS best practice).
        _disableInitializers();
    }

    function initialize() public initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ATTESTER_ROLE, msg.sender);
        _cachedChainId = block.chainid;
        _domainSeparator = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustComplianceAttestation"),
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
                keccak256("QTrustComplianceAttestation"),
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

    /// @notice Hash the typed Attest Compliance data for EIP-712 signing.
    function hashTypedAttestCompliance(
        string calldata framework,
        uint256 score,
        uint256 totalRules,
        uint256 compliantCount,
        uint256 nonCompliantCount,
        bytes32 evidenceHash,
        uint256 validityDays,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _currentDomainSeparator(),
                keccak256(
                    abi.encode(
                        _ATTESTATION_TYPEHASH,
                        keccak256(abi.encodePacked(framework)),
                        score,
                        totalRules,
                        compliantCount,
                        nonCompliantCount,
                        evidenceHash,
                        validityDays,
                        nonce
                    )
                )
            )
        );
    }

    /// @notice Submit a gasless compliance attestation signed by the organization.
    ///         The signer's address becomes the orgDid; the caller (any relayer)
    ///         pays the gas.
    function attestComplianceSigned(
        string calldata framework,
        uint256 score,
        uint256 totalRules,
        uint256 compliantCount,
        uint256 nonCompliantCount,
        bytes32 evidenceHash,
        uint256 validityDays,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant whenNotPaused returns (bytes32 attestationId) {
        address signer = _recoverAttestationSigner(
            framework, score, totalRules, compliantCount, nonCompliantCount,
            evidenceHash, validityDays, nonce, signature
        );
        if (signer == address(0)) revert InvalidSignature();
        // The signature proves intent, not authority: the signer must hold
        // ATTESTER_ROLE exactly like the direct path requires.
        if (!hasRole(ATTESTER_ROLE, signer)) revert NotAttester(signer);
        if (nonces[signer] != nonce) {
            revert InvalidNonce(signer, nonce, nonces[signer]);
        }

        nonces[signer] = nonce + 1;

        return _attestCompliance(
            signer, framework, score, totalRules, compliantCount,
            nonCompliantCount, evidenceHash, validityDays
        );
    }

    /// @dev Recover the EIP-712 signer of a compliance attestation.
    function _recoverAttestationSigner(
        string calldata framework,
        uint256 score,
        uint256 totalRules,
        uint256 compliantCount,
        uint256 nonCompliantCount,
        bytes32 evidenceHash,
        uint256 validityDays,
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
                        _ATTESTATION_TYPEHASH,
                        keccak256(abi.encodePacked(framework)),
                        score,
                        totalRules,
                        compliantCount,
                        nonCompliantCount,
                        evidenceHash,
                        validityDays,
                        nonce
                    )
                )
            )
        );
        return ECDSA.recover(digest, signature);
    }

    /// @notice Record a compliance attestation (direct, requires ATTESTER_ROLE)
    /// @param framework        Compliance framework identifier
    /// @param score            Compliance score (0-100)
    /// @param totalRules       Total rules evaluated
    /// @param compliantCount   Number of compliant rules
    /// @param nonCompliantCount Number of non-compliant rules
    /// @param evidenceHash     Hash of the supporting evidence bundle
    /// @param validityDays     Number of days the attestation remains valid
    /// @return attestationId   The ID under which this attestation is stored
    function attestCompliance(
        string calldata framework,
        uint256 score,
        uint256 totalRules,
        uint256 compliantCount,
        uint256 nonCompliantCount,
        bytes32 evidenceHash,
        uint256 validityDays
    ) external nonReentrant whenNotPaused onlyRole(ATTESTER_ROLE) returns (bytes32 attestationId) {
        return _attestCompliance(
            msg.sender, framework, score, totalRules, compliantCount,
            nonCompliantCount, evidenceHash, validityDays
        );
    }

    /// @dev Internal attestation logic shared by direct and EIP-712 paths.
    function _attestCompliance(
        address orgDid,
        string calldata framework,
        uint256 score,
        uint256 totalRules,
        uint256 compliantCount,
        uint256 nonCompliantCount,
        bytes32 evidenceHash,
        uint256 validityDays
    ) internal returns (bytes32 attestationId) {
        StringBounds.checkID(framework);
        if (bytes(framework).length == 0) revert EmptyFramework();
        if (score > 100) revert ScoreOutOfBounds(score);
        if (compliantCount + nonCompliantCount != totalRules) {
            revert RuleCountMismatch(totalRules, compliantCount, nonCompliantCount);
        }
        if (validityDays == 0) revert InvalidValidityDays(validityDays);

        attestationId = keccak256(abi.encode(
            orgDid, framework, score, totalRules, block.timestamp
        ));

        if (_attestations[attestationId].orgDid != address(0)) {
            revert DuplicateAttestation(attestationId);
        }

        uint256 validUntil = block.timestamp + (validityDays * 1 days);

        _attestations[attestationId] = Attestation({
            attestationId: attestationId,
            orgDid: orgDid,
            framework: framework,
            score: score,
            totalRules: totalRules,
            compliantCount: compliantCount,
            nonCompliantCount: nonCompliantCount,
            evidenceHash: evidenceHash,
            timestamp: block.timestamp,
            validUntil: validUntil,
            revoked: false
        });

        _attestationsByOrg[orgDid].push(attestationId);
        _attestationsByFramework[framework].push(attestationId);
        _latestAttestation[orgDid][keccak256(abi.encodePacked(framework))] = attestationId;

        emit ComplianceAttested(attestationId, orgDid, framework, score, block.timestamp);
    }

    /// @dev Clears the latest-attestation pointer when it is revoked so the
    ///      O(1) status view never reports a revoked attestation (audit M-4).
    function _clearLatestIfCurrent(Attestation storage att) internal {
        bytes32 slot = _latestAttestation[att.orgDid][keccak256(abi.encodePacked(att.framework))];
        if (slot == att.attestationId) {
            delete _latestAttestation[att.orgDid][keccak256(abi.encodePacked(att.framework))];
        }
    }

    /// @notice Revoke a compliance attestation. Only the original attestation
    ///         owner may revoke their own attestation.
    function revokeAttestation(
        bytes32 attestationId,
        string calldata reason
    ) external nonReentrant whenNotPaused {
        StringBounds.checkLen(reason, StringBounds.REASON_MAX);
        Attestation storage att = _attestations[attestationId];
        if (att.orgDid == address(0)) revert AttestationNotFound(attestationId);
        if (att.revoked) revert AlreadyRevoked(attestationId);
        if (att.orgDid != msg.sender) revert NotOwner(msg.sender);

        att.revoked = true;
        _clearLatestIfCurrent(att);

        emit ComplianceRevoked(attestationId, reason, block.timestamp);
    }

    /// @notice Governance-controlled revocation for lapsed/lost-issuer cases.
    function adminRevokeAttestation(
        bytes32 attestationId,
        string calldata reason
    ) external nonReentrant whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        StringBounds.checkLen(reason, StringBounds.REASON_MAX);
        Attestation storage att = _attestations[attestationId];
        if (att.orgDid == address(0)) revert AttestationNotFound(attestationId);
        if (att.revoked) revert AlreadyRevoked(attestationId);

        att.revoked = true;
        _clearLatestIfCurrent(att);

        emit ComplianceRevoked(attestationId, reason, block.timestamp);
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

    /// @notice Get an attestation by ID
    function getAttestation(bytes32 attestationId) external view returns (Attestation memory) {
        if (_attestations[attestationId].orgDid == address(0)) revert AttestationNotFound(attestationId);
        return _attestations[attestationId];
    }

    /// @notice Get all attestation IDs for an organization
    function getAttestationsByOrg(address orgDid) external view returns (bytes32[] memory) {
        return _attestationsByOrg[orgDid];
    }

    /// @notice Get all attestation IDs for a framework
    function getAttestationsByFramework(string calldata framework) external view returns (bytes32[] memory) {
        return _attestationsByFramework[framework];
    }

    /// @notice Number of attestations posted by an org (audit M-1).
    function getAttestationCountByOrg(address orgDid) external view returns (uint256) {
        return _attestationsByOrg[orgDid].length;
    }

    /// @notice Paginated attestation IDs for an org (audit M-1).
    function getAttestationsByOrgPaged(address orgDid, uint256 offset, uint256 limit)
        external view returns (bytes32[] memory page, uint256 total)
    {
        bytes32[] storage ids = _attestationsByOrg[orgDid];
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

    /// @notice Check whether an attestation is currently valid (not revoked and
    ///         within its validity window)
    function isComplianceValid(bytes32 attestationId) external view returns (bool) {
        Attestation storage att = _attestations[attestationId];
        if (att.orgDid == address(0)) return false;
        return !att.revoked && block.timestamp <= att.validUntil;
    }

    /// @notice Get an organization's compliance status for a given framework.
    ///         Returns whether a valid attestation exists and the latest score.
    /// Audit M-4: O(1) via the _latestAttestation pointer instead of scanning
    /// the full per-org attestation array (which was unbounded / OOG-able).
    function getOrgComplianceStatus(address orgDid, string calldata framework)
        external view returns (bool valid, uint256 latestScore)
    {
        bytes32 id = _latestAttestation[orgDid][keccak256(abi.encodePacked(framework))];
        if (id == bytes32(0)) return (false, 0);
        Attestation storage att = _attestations[id];
        if (att.orgDid == address(0) || att.revoked || block.timestamp > att.validUntil) {
            return (false, 0);
        }
        return (true, att.score);
    }
}
