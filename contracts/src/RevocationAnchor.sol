// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./lib/StringBounds.sol";

/// @title RevocationAnchor — on-chain Merkle root for credential revocation
/// @notice Issuers maintain a Merkle tree of revoked credential IDs off-chain.
///         The root is anchored here. Verifiers check if a credential is revoked
///         via a Merkle proof — learning only whether THIS credential is revoked.
///         Supports EIP-712 gasless root updates and UUPS proxy upgradeability.
contract RevocationAnchor is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error IssuerNotRegistered(address issuer);
    error IssuerInactive(address issuer);
    error EmptyRoot();
    error InvalidNonce(address signer, uint256 provided, uint256 expected);
    error InvalidSignature();
    error NotInitialized();

    event RevocationRootUpdated(
        address indexed issuer,
        bytes32 newRoot,
        bytes32 previousRoot,
        uint256 timestamp
    );

    event IssuerRegistered(
        address indexed issuer,
        string  issuerDid,
        uint256 timestamp
    );

    struct IssuerInfo {
        string  issuerDid;
        bytes32 currentRoot;
        bytes32 previousRoot;
        uint256 lastUpdated;
        bool    active;
    }

    mapping(address => IssuerInfo) private _issuers;
    address[] private _allIssuers;

    bytes32 public constant ISSUER_ADMIN_ROLE = keccak256("ISSUER_ADMIN_ROLE");

    // ==================== EIP-712 (gasless root update) ====================
    bytes32 private constant _ROOT_UPDATE_TYPEHASH =
        keccak256(
            "RevocationRootUpdate(address issuer,bytes32 newRoot,uint256 nonce)"
        );

    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private _domainSeparator;
    bytes32 public constant EIP712_VERSION_HASH = keccak256("1");

    mapping(address => uint256) public nonces;

    bool private _initialized;
    uint256 private _cachedChainId;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Prevent initialization of the raw implementation (UUPS best practice).
        _disableInitializers();
    }

    function initialize() public initializer {
        if (_initialized) revert NotInitialized();
        _initialized = true;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ISSUER_ADMIN_ROLE, msg.sender);
        _cachedChainId = block.chainid;
        _domainSeparator = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustRevocationAnchor"),
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
                keccak256("QTrustRevocationAnchor"),
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

    /// @notice Hash the typed Revocation Root Update data for EIP-712 signing.
    function hashTypedRootUpdate(
        address issuer,
        bytes32 newRoot,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _currentDomainSeparator(),
                keccak256(
                    abi.encode(
                        _ROOT_UPDATE_TYPEHASH,
                        issuer,
                        newRoot,
                        nonce
                    )
                )
            )
        );
    }

    /// @notice Submit a gasless root update signed by the issuer.
    function updateRootSigned(
        address issuer,
        bytes32 newRoot,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant whenNotPaused returns (bytes32 previousRoot) {
        address signer = ECDSA.recover(
            hashTypedRootUpdate(issuer, newRoot, nonce),
            signature
        );
        if (signer != issuer) revert InvalidSignature();
        if (nonces[issuer] != nonce) {
            revert InvalidNonce(issuer, nonce, nonces[issuer]);
        }

        nonces[issuer] = nonce + 1;

        return _updateRoot(issuer, newRoot);
    }

    /// @notice Register a new issuer (admin only)
    function registerIssuer(
        address issuer,
        string calldata issuerDid
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        StringBounds.checkDID(issuerDid);
        _issuers[issuer] = IssuerInfo({
            issuerDid: issuerDid,
            currentRoot: bytes32(0),
            previousRoot: bytes32(0),
            lastUpdated: block.timestamp,
            active: true
        });
        _allIssuers.push(issuer);

        emit IssuerRegistered(issuer, issuerDid, block.timestamp);
    }

    /// @notice Update the revocation Merkle root for an issuer (direct, requires ISSUER_ADMIN_ROLE)
    function updateRoot(
        address issuer,
        bytes32 newRoot
    ) external nonReentrant whenNotPaused onlyRole(ISSUER_ADMIN_ROLE) returns (bytes32 previousRoot) {
        return _updateRoot(issuer, newRoot);
    }

    /// @dev Internal root update logic shared by direct and EIP-712 paths.
    function _updateRoot(
        address issuer,
        bytes32 newRoot
    ) internal returns (bytes32 previousRoot) {
        if (bytes(_issuers[issuer].issuerDid).length == 0) revert IssuerNotRegistered(issuer);
        // A deactivated issuer must not anchor new revocation roots (this
        // guards both the direct ISSUER_ADMIN_ROLE path and the EIP-712 path).
        if (!_issuers[issuer].active) revert IssuerInactive(issuer);
        if (newRoot == bytes32(0)) revert EmptyRoot();

        previousRoot = _issuers[issuer].currentRoot;
        _issuers[issuer].previousRoot = previousRoot;
        _issuers[issuer].currentRoot = newRoot;
        _issuers[issuer].lastUpdated = block.timestamp;

        emit RevocationRootUpdated(issuer, newRoot, previousRoot, block.timestamp);

        return previousRoot;
    }

    /// @notice Deactivate an issuer (admin only)
    function deactivateIssuer(address issuer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _issuers[issuer].active = false;
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

    /// @notice Get the current revocation root for an issuer
    function getIssuer(address issuer) external view returns (IssuerInfo memory) {
        if (bytes(_issuers[issuer].issuerDid).length == 0) revert IssuerNotRegistered(issuer);
        return _issuers[issuer];
    }

    /// @notice Check if an issuer is registered and active
    function isIssuerActive(address issuer) external view returns (bool) {
        return _issuers[issuer].active;
    }

    /// @notice Get the current revocation root for an issuer
    function getRevocationRoot(address issuer) external view returns (bytes32) {
        return _issuers[issuer].currentRoot;
    }

    /// @notice Get all registered issuer addresses
    function getAllIssuers() external view returns (address[] memory) {
        return _allIssuers;
    }

    /// @notice Total number of registered issuers
    function issuerCount() external view returns (uint256) {
        return _allIssuers.length;
    }
}
