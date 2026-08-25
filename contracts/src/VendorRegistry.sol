// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./lib/StringBounds.sol";

/// @title VendorRegistry — vendors post PQC readiness attestations
/// @notice Vendors (DigiCert, Thales, AWS, etc.) attest which products
///         and versions support which PQC algorithms.
///         Supports EIP-712 gasless attestations and UUPS proxy upgradeability.
contract VendorRegistry is AccessControl, Pausable, Initializable, UUPSUpgradeable {

    error VendorNotFound(address vendorDid);
    error VendorAlreadyRegistered(address vendorDid);
    error VendorInactive(address vendorDid);
    error AttestationNotFound(bytes32 attestationId);
    error NotVendor(address caller);
    error DuplicateAttestation(bytes32 attestationId);
    error AttestationLimitExceeded(bytes32 productIdHash);
    error InvalidAttestationLimit(uint256 provided);
    error InvalidSignature();
    error InvalidNonce(address signer, uint256 provided, uint256 expected);
    error NotInitialized();

    /// @notice Default, minimum, and maximum bounds for the configurable
    ///         per-product attestation cap.
    uint16 public constant DEFAULT_MAX_ATTESTATIONS_PER_PRODUCT = 256;
    uint16 public constant MIN_ATTESTATIONS_PER_PRODUCT = 16;
    uint16 public constant MAX_ATTESTATIONS_PER_PRODUCT_BOUND = 4096;

    /// @notice Maximum number of attestations allowed per product
    ///         (governance-configurable via setMaxAttestationsPerProduct).
    uint16 public maxAttestationsPerProduct;

    bytes32 public constant VENDOR_ADMIN_ROLE = keccak256("VENDOR_ADMIN_ROLE");

    event VendorRegistered(address indexed vendorDid, string name, string metadataURI, uint256 timestamp);
    event VendorDeactivated(address indexed vendorDid, uint256 timestamp);
    event ProductAttested(
        bytes32 indexed attestationId,
        address indexed vendorDid,
        string  productId,
        string  version,
        string  algorithm,
        bool    supported,
        string  evidenceURI,
        uint256 timestamp
    );
    event AttestationRevoked(bytes32 indexed attestationId, uint256 timestamp);
    event MaxAttestationsPerProductChanged(uint256 oldLimit, uint256 newLimit);

    struct VendorInfo {
        string name;
        string metadataURI;
        uint256 registeredAt;
        bool   active;
    }

    struct ProductAttestation {
        address vendorDid;
        string  productId;
        string  version;
        string  algorithm;
        bool    supported;
        string  evidenceURI;
        uint256 timestamp;
        bool    revoked;
    }

    mapping(address => VendorInfo) private _vendors;
    mapping(bytes32 => ProductAttestation) private _attestations;
    mapping(address => bytes32[]) private _attestationsByVendor;
    mapping(bytes32 => bytes32[]) private _attestationsByProduct;

    bytes32 public constant VENDOR_ROLE = keccak256("VENDOR_ROLE");

    // ==================== EIP-712 (gasless attestations) ====================
    bytes32 private constant _PRODUCT_ATTESTATION_TYPEHASH =
        keccak256(
            "ProductAttestation(string productId,string version,string algorithm,"
            "bool supported,string evidenceURI,uint256 nonce)"
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
        _grantRole(VENDOR_ADMIN_ROLE, msg.sender);
        maxAttestationsPerProduct = DEFAULT_MAX_ATTESTATIONS_PER_PRODUCT;
        _cachedChainId = block.chainid;
        _domainSeparator = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustVendorRegistry"),
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
                keccak256("QTrustVendorRegistry"),
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

    /// @notice Hash the typed ProductAttestation data for EIP-712 signing.
    function hashTypedAttestation(
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _currentDomainSeparator(),
                keccak256(
                    abi.encode(
                        _PRODUCT_ATTESTATION_TYPEHASH,
                        keccak256(abi.encodePacked(productId)),
                        keccak256(abi.encodePacked(version)),
                        keccak256(abi.encodePacked(algorithm)),
                        supported,
                        keccak256(abi.encodePacked(evidenceURI)),
                        nonce
                    )
                )
            )
        );
    }

    /// @notice Submit a gasless product attestation signed by the vendor.
    function attestProductSigned(
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI,
        uint256 nonce,
        bytes calldata signature
    ) external whenNotPaused returns (bytes32 attestationId) {
        address signer = _recoverSigner(
            productId, version, algorithm, supported, evidenceURI, nonce, signature
        );
        if (signer == address(0)) revert InvalidSignature();
        if (nonces[signer] != nonce) {
            revert InvalidNonce(signer, nonce, nonces[signer]);
        }
        if (!_vendors[signer].active) revert VendorInactive(signer);

        nonces[signer] = nonce + 1;

        return _storeAttestation(
            signer, productId, version, algorithm, supported, evidenceURI
        );
    }

    /// @dev Recover the EIP-712 signer of a product attestation.
    function _recoverSigner(
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
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
                        _PRODUCT_ATTESTATION_TYPEHASH,
                        keccak256(abi.encodePacked(productId)),
                        keccak256(abi.encodePacked(version)),
                        keccak256(abi.encodePacked(algorithm)),
                        supported,
                        keccak256(abi.encodePacked(evidenceURI)),
                        nonce
                    )
                )
            )
        );
        return ECDSA.recover(digest, signature);
    }

    /// @notice Governance-configurable per-product attestation cap. Bounded to
    ///         [MIN_ATTESTATIONS_PER_PRODUCT, MAX_ATTESTATIONS_PER_PRODUCT_BOUND].
    function setMaxAttestationsPerProduct(uint16 newLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newLimit < MIN_ATTESTATIONS_PER_PRODUCT || newLimit > MAX_ATTESTATIONS_PER_PRODUCT_BOUND) {
            revert InvalidAttestationLimit(newLimit);
        }
        uint256 oldLimit = maxAttestationsPerProduct;
        maxAttestationsPerProduct = newLimit;
        emit MaxAttestationsPerProductChanged(oldLimit, newLimit);
    }

    /// @dev Shared storage write for product attestations.
    function _storeAttestation(
        address vendorDid,
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI
    ) internal returns (bytes32 attestationId) {
        StringBounds.checkID(productId);
        StringBounds.checkID(version);
        StringBounds.checkID(algorithm);
        StringBounds.checkURI(evidenceURI);

        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));
        if (_attestationsByProduct[productIdHash].length >= maxAttestationsPerProduct) {
            revert AttestationLimitExceeded(productIdHash);
        }
        attestationId = keccak256(abi.encode(vendorDid, productIdHash));

        if (_attestations[attestationId].vendorDid != address(0)) {
            revert DuplicateAttestation(attestationId);
        }

        _attestations[attestationId] = ProductAttestation({
            vendorDid: vendorDid,
            productId: productId,
            version: version,
            algorithm: algorithm,
            supported: supported,
            evidenceURI: evidenceURI,
            timestamp: block.timestamp,
            revoked: false
        });

        _attestationsByVendor[vendorDid].push(attestationId);
        _attestationsByProduct[productIdHash].push(attestationId);

        emit ProductAttested(
            attestationId, vendorDid, productId, version,
            algorithm, supported, evidenceURI, block.timestamp
        );
    }

    /// @notice Register a new vendor
    function registerVendor(
        address vendorDid,
        string calldata name,
        string calldata metadataURI
    ) external onlyRole(VENDOR_ADMIN_ROLE) whenNotPaused {
        StringBounds.checkDID(name);
        StringBounds.checkURI(metadataURI);
        if (_vendors[vendorDid].registeredAt != 0) revert VendorAlreadyRegistered(vendorDid);
        _vendors[vendorDid] = VendorInfo({
            name: name,
            metadataURI: metadataURI,
            registeredAt: block.timestamp,
            active: true
        });
        _grantRole(VENDOR_ROLE, vendorDid);
        emit VendorRegistered(vendorDid, name, metadataURI, block.timestamp);
    }

    /// @notice Deactivate a vendor
    function deactivateVendor(address vendorDid) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        if (_vendors[vendorDid].registeredAt == 0) revert VendorNotFound(vendorDid);
        if (!_vendors[vendorDid].active) return;
        _vendors[vendorDid].active = false;
        emit VendorDeactivated(vendorDid, block.timestamp);
    }

    /// @notice Check whether a vendor is currently active
    function isVendorActive(address vendorDid) external view returns (bool) {
        return _vendors[vendorDid].registeredAt != 0 && _vendors[vendorDid].active;
    }

    /// @notice Deterministically compute the attestation ID for a vendor/product
    ///         triple without attesting. Pair with getAttestation() to find an
    ///         existing attestation.
    function computeAttestationId(
        address vendorDid,
        string calldata productId,
        string calldata version,
        string calldata algorithm
    ) external pure returns (bytes32) {
        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));
        return keccak256(abi.encode(vendorDid, productIdHash));
    }

    /// @notice Vendor posts a product PQC attestation (direct, requires VENDOR_ROLE)
    function attestProduct(
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI
    ) external onlyRole(VENDOR_ROLE) whenNotPaused returns (bytes32 attestationId) {
        if (!_vendors[msg.sender].active) revert VendorInactive(msg.sender);

        return _storeAttestation(
            msg.sender, productId, version, algorithm, supported, evidenceURI
        );
    }

    /// @notice Revoke an attestation
    function revokeAttestation(bytes32 attestationId) external whenNotPaused {
        ProductAttestation storage att = _attestations[attestationId];
        if (att.vendorDid == address(0)) revert AttestationNotFound(attestationId);
        if (att.vendorDid != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotVendor(msg.sender);
        }
        att.revoked = true;
        emit AttestationRevoked(attestationId, block.timestamp);
    }

    /// @notice Pause all operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Get vendor info
    function getVendor(address vendorDid) external view returns (VendorInfo memory) {
        if (_vendors[vendorDid].registeredAt == 0) revert VendorNotFound(vendorDid);
        return _vendors[vendorDid];
    }

    /// @notice Get a specific attestation
    function getAttestation(bytes32 attestationId) external view returns (ProductAttestation memory) {
        if (_attestations[attestationId].vendorDid == address(0)) revert AttestationNotFound(attestationId);
        return _attestations[attestationId];
    }

    /// @notice Get all attestations by a vendor
    function getAttestationsByVendor(address vendorDid) external view returns (bytes32[] memory) {
        return _attestationsByVendor[vendorDid];
    }

    /// @notice Get all attestations for a product
    function getAttestationsByProduct(
        string calldata productId,
        string calldata version,
        string calldata algorithm
    ) external view returns (bytes32[] memory) {
        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));
        return _attestationsByProduct[productIdHash];
    }

    /// @notice Check if a product version supports an algorithm
    function checkProductSupport(
        string calldata productId,
        string calldata version,
        string calldata algorithm
    ) external view returns (bool supported, address vendorDid, bytes32 attestationId) {
        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));
        bytes32[] memory ids = _attestationsByProduct[productIdHash];
        uint256 n = ids.length;
        for (uint256 i = 0; i < n; i++) {
            ProductAttestation storage att = _attestations[ids[i]];
            if (!att.revoked && att.supported) {
                return (true, att.vendorDid, ids[i]);
            }
        }
        return (false, address(0), bytes32(0));
    }
}
