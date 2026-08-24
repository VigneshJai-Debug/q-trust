// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./lib/StringBounds.sol";

/// @title TrustAnchorRegistry — issuer accreditation and trust anchor management
/// @notice Trust anchors (governance multisig) accredit issuers. VCs issued by
///         non-accredited issuers are rejected by verifiers. The registry tracks
///         which issuers are accredited, their scope, and revocation status.
///         Supports UUPS proxy upgradeability.
contract TrustAnchorRegistry is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error IssuerNotAccredited(address issuer);
    error IssuerAlreadyAccredited(address issuer);
    error EmptyIssuerDid();
    error NotGovernance(address caller);
    error NotInitialized();

    event IssuerAccredited(
        address indexed issuer,
        string  issuerDid,
        string  scope,
        uint256 validFrom,
        uint256 validUntil,
        address accreditedBy,
        uint256 timestamp
    );

    event IssuerAccreditationRevoked(
        address indexed issuer,
        string  reason,
        uint256 timestamp
    );

    event IssuerReaccredited(
        address indexed issuer,
        uint256 newValidUntil,
        uint256 timestamp
    );

    struct IssuerAccreditation {
        address issuer;
        string  issuerDid;
        string  scope;            // e.g., "pqc-readiness", "sbom", "general"
        uint256 validFrom;
        uint256 validUntil;
        address accreditedBy;
        uint256 timestamp;
        bool    active;
        string  revocationReason;
    }

    mapping(address => IssuerAccreditation) private _accreditations;
    address[] private _allAccreditedIssuers;
    mapping(address => bool) private _isAccredited;

    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    bool private _initialized;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {}

    function initialize() public initializer {
        if (_initialized) revert NotInitialized();
        _initialized = true;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GOVERNANCE_ROLE, msg.sender);
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Accredit an issuer (requires GOVERNANCE_ROLE)
    /// @param issuer     Address of the issuer to accredit
    /// @param issuerDid  W3C DID of the issuer (e.g., "did:web:trailofbits.com")
    /// @param scope      What the issuer can attest (e.g., "pqc-readiness")
    /// @param validFor   Duration in seconds the accreditation is valid
    function accreditIssuer(
        address issuer,
        string calldata issuerDid,
        string calldata scope,
        uint256 validFor
    ) external nonReentrant whenNotPaused onlyRole(GOVERNANCE_ROLE) {
        StringBounds.checkDID(issuerDid);
        StringBounds.checkID(scope);
        if (issuer == address(0) || bytes(issuerDid).length == 0) revert EmptyIssuerDid();
        if (_isAccredited[issuer]) revert IssuerAlreadyAccredited(issuer);

        _accreditations[issuer] = IssuerAccreditation({
            issuer: issuer,
            issuerDid: issuerDid,
            scope: scope,
            validFrom: block.timestamp,
            validUntil: block.timestamp + validFor,
            accreditedBy: msg.sender,
            timestamp: block.timestamp,
            active: true,
            revocationReason: ""
        });

        _allAccreditedIssuers.push(issuer);
        _isAccredited[issuer] = true;

        emit IssuerAccredited(issuer, issuerDid, scope, block.timestamp, block.timestamp + validFor, msg.sender, block.timestamp);
    }

    /// @notice Revoke an issuer's accreditation (requires GOVERNANCE_ROLE)
    function revokeAccreditation(
        address issuer,
        string calldata reason
    ) external onlyRole(GOVERNANCE_ROLE) {
        StringBounds.checkLen(reason, StringBounds.REASON_MAX);
        if (!_isAccredited[issuer]) revert IssuerNotAccredited(issuer);

        _accreditations[issuer].active = false;
        _accreditations[issuer].revocationReason = reason;
        _isAccredited[issuer] = false;

        emit IssuerAccreditationRevoked(issuer, reason, block.timestamp);
    }

    /// @notice Extend an issuer's accreditation (requires GOVERNANCE_ROLE)
    function reaccreditIssuer(
        address issuer,
        uint256 additionalTime
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (!_isAccredited[issuer]) revert IssuerNotAccredited(issuer);

        _accreditations[issuer].validUntil += additionalTime;
        _accreditations[issuer].active = true;

        emit IssuerReaccredited(issuer, _accreditations[issuer].validUntil, block.timestamp);
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

    /// @notice Check if an issuer is currently accredited and not expired
    function isIssuerAccredited(address issuer) external view returns (bool) {
        IssuerAccreditation storage acc = _accreditations[issuer];
        return acc.active && block.timestamp >= acc.validFrom && block.timestamp <= acc.validUntil;
    }

    /// @notice Get the full accreditation record for an issuer
    function getAccreditation(address issuer) external view returns (IssuerAccreditation memory) {
        if (!_isAccredited[issuer] && _accreditations[issuer].timestamp == 0) {
            revert IssuerNotAccredited(issuer);
        }
        return _accreditations[issuer];
    }

    /// @notice Get all accredited issuer addresses
    function getAllAccreditedIssuers() external view returns (address[] memory) {
        return _allAccreditedIssuers;
    }

    /// @notice Total number of ever-accredited issuers
    function accreditedIssuerCount() external view returns (uint256) {
        return _allAccreditedIssuers.length;
    }

    /// @notice Verify an issuer's accreditation: is active, not expired, matches scope
    function verifyAccreditation(
        address issuer,
        string calldata scope
    ) external view returns (bool accredited, string memory issuerDid, uint256 validUntil) {
        IssuerAccreditation storage acc = _accreditations[issuer];
        bool valid = acc.active
            && block.timestamp >= acc.validFrom
            && block.timestamp <= acc.validUntil
            && keccak256(abi.encodePacked(acc.scope)) == keccak256(abi.encodePacked(scope));
        return (valid, acc.issuerDid, acc.validUntil);
    }
}
