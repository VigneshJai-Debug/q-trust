// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title VendorRegistry — vendors post PQC readiness attestations
/// @notice Vendors (DigiCert, Thales, AWS, etc.) attest which products
///         and versions support which PQC algorithms.
contract VendorRegistry is AccessControl {

    error VendorNotFound(address vendorDid);
    error VendorAlreadyRegistered(address vendorDid);
    error VendorInactive(address vendorDid);
    error AttestationNotFound(bytes32 attestationId);
    error NotVendor(address caller);
    error DuplicateAttestation(bytes32 attestationId);
    error AttestationLimitExceeded(bytes32 productIdHash);

    /// @notice Maximum number of attestations per product (productId+version+algorithm)
    ///         — bounds on-chain iteration cost in checkProductSupport.
    uint256 public constant MAX_ATTESTATIONS_PER_PRODUCT = 256;

    /// @notice Day-to-day operator role for onboarding vendors. Held by the
    ///         deployer; NOT routed through the timelock (registering a vendor
    ///         is operational, deactivating one is a governance decision).
    bytes32 public constant VENDOR_ADMIN_ROLE = keccak256("VENDOR_ADMIN_ROLE");

    event VendorRegistered(address indexed vendorDid, string name, string metadataURI, uint256 timestamp);
    event VendorDeactivated(address indexed vendorDid, uint256 timestamp);
    event ProductAttested(
        bytes32 indexed attestationId,
        address indexed vendorDid,
        string  productId,
        string  version,
        string  algorithm,     // e.g. "ML-KEM-512", "ML-DSA-441"
        bool    supported,
        string  evidenceURI,   // IPFS URI for test results
        uint256 timestamp
    );
    event AttestationRevoked(bytes32 indexed attestationId, uint256 timestamp);

    struct VendorInfo {
        string name;
        string metadataURI;
        uint256 registeredAt;
        bool   active;
    }

    struct ProductAttestation {
        address vendorDid;
        string  productId;       // e.g. "thales-luna-hsm"
        string  version;          // e.g. "7.3.0"
        string  algorithm;        // e.g. "ML-KEM-512"
        bool    supported;        // true = supports PQC, false = does not
        string  evidenceURI;     // IPFS URI for test results / evidence
        uint256 timestamp;
        bool    revoked;
    }

    mapping(address => VendorInfo) private _vendors;
    mapping(bytes32 => ProductAttestation) private _attestations;
    mapping(address => bytes32[]) private _attestationsByVendor;
    mapping(bytes32 => bytes32[]) private _attestationsByProduct; // productIdHash -> attestationIds

    bytes32 public constant VENDOR_ROLE = keccak256("VENDOR_ROLE");

    // ==================== EIP-712 (gasless attestations) ====================
    // Vendors sign typed data off-chain; any relayer can submit the signed
    // attestation. The on-chain attestation records the SIGNER as the vendor,
    // so the vendor never needs to hold funds or run a node.

    bytes32 private constant _PRODUCT_ATTESTATION_TYPEHASH =
        keccak256(
            "ProductAttestation(string productId,string version,string algorithm,"
            "bool supported,string evidenceURI,uint256 nonce)"
        );

    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private immutable _DOMAIN_SEPARATOR;
    bytes32 public constant EIP712_VERSION_HASH = keccak256("1");

    mapping(address => uint256) public nonces;

    error InvalidSignature();
    error InvalidNonce(address signer, uint256 provided, uint256 expected);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VENDOR_ADMIN_ROLE, msg.sender);
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustVendorRegistry"),
                EIP712_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Domain separator for EIP-712 typed data signing.
    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
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
                _DOMAIN_SEPARATOR,
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
    ///         The vendor's signature authorizes the attestation; the caller
    ///         (any relayer) pays the gas. The recorded vendorDid is the signer.
    function attestProductSigned(
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bytes32 attestationId) {
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
    ///      Split out so the stack stays shallow in attestProductSigned.
    function _recoverSigner(
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI,
        uint256 nonce,
        bytes calldata signature
    ) internal view returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _DOMAIN_SEPARATOR,
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

    /// @dev Shared storage write for product attestations. Kept in a separate
    ///      function to keep stack usage bounded in the signed-attestation path.
    function _storeAttestation(
        address vendorDid,
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI
    ) internal returns (bytes32 attestationId) {
        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));
        if (_attestationsByProduct[productIdHash].length >= MAX_ATTESTATIONS_PER_PRODUCT) {
            revert AttestationLimitExceeded(productIdHash);
        }
        attestationId = keccak256(abi.encodePacked(vendorDid, productIdHash, block.timestamp));

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
    ) external onlyRole(VENDOR_ADMIN_ROLE) {
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

    /// @notice Deactivate a vendor (e.g., for compliance or trust reasons).
    ///         Deactivated vendors cannot post new attestations; existing
    ///         attestations remain readable but should be re-checked.
    function deactivateVendor(address vendorDid) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_vendors[vendorDid].registeredAt == 0) revert VendorNotFound(vendorDid);
        if (!_vendors[vendorDid].active) return;
        _vendors[vendorDid].active = false;
        emit VendorDeactivated(vendorDid, block.timestamp);
    }

    /// @notice Check whether a vendor is currently active
    function isVendorActive(address vendorDid) external view returns (bool) {
        return _vendors[vendorDid].registeredAt != 0 && _vendors[vendorDid].active;
    }

    /// @notice Vendor posts a product PQC attestation
    /// @param productId   e.g. "thales-luna-hsm"
    /// @param version     e.g. "7.3.0"
    /// @param algorithm   e.g. "ML-KEM-512" (see NIST FIPS 203/204/205)
    /// @param supported   true if this product version supports this algorithm
    /// @param evidenceURI IPFS URI for test results / evidence
    function attestProduct(
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI
    ) external onlyRole(VENDOR_ROLE) returns (bytes32 attestationId) {
        if (!_vendors[msg.sender].active) revert VendorInactive(msg.sender);

        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));

        if (_attestationsByProduct[productIdHash].length >= MAX_ATTESTATIONS_PER_PRODUCT) {
            revert AttestationLimitExceeded(productIdHash);
        }

        attestationId = keccak256(abi.encodePacked(
            msg.sender, productIdHash, block.timestamp
        ));

        if (_attestations[attestationId].vendorDid != address(0)) {
            revert DuplicateAttestation(attestationId);
        }

        _attestations[attestationId] = ProductAttestation({
            vendorDid: msg.sender,
            productId: productId,
            version: version,
            algorithm: algorithm,
            supported: supported,
            evidenceURI: evidenceURI,
            timestamp: block.timestamp,
            revoked: false
        });

        _attestationsByVendor[msg.sender].push(attestationId);
        _attestationsByProduct[productIdHash].push(attestationId);

        emit ProductAttested(
            attestationId, msg.sender, productId, version,
            algorithm, supported, evidenceURI, block.timestamp
        );
    }

    /// @notice Revoke an attestation (e.g., if a vulnerability was found)
    function revokeAttestation(bytes32 attestationId) external {
        ProductAttestation storage att = _attestations[attestationId];
        if (att.vendorDid == address(0)) revert AttestationNotFound(attestationId);
        if (att.vendorDid != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotVendor(msg.sender);
        }
        att.revoked = true;
        emit AttestationRevoked(attestationId, block.timestamp);
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

    /// @notice Get all attestations for a product (productId + version + algorithm)
    function getAttestationsByProduct(
        string calldata productId,
        string calldata version,
        string calldata algorithm
    ) external view returns (bytes32[] memory) {
        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));
        return _attestationsByProduct[productIdHash];
    }

    /// @notice Check if a product version supports an algorithm
    /// @return supported  true if any non-revoked attestation says supported
    /// @return vendorDid   the vendor that attested
    /// @return attestationId  the attestation ID
    function checkProductSupport(
        string calldata productId,
        string calldata version,
        string calldata algorithm
    ) external view returns (bool supported, address vendorDid, bytes32 attestationId) {
        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));
        bytes32[] memory ids = _attestationsByProduct[productIdHash];
        // Iteration is bounded by MAX_ATTESTATIONS_PER_PRODUCT (enforced in attestProduct),
        // so worst-case gas cost is fixed and cannot be griefed.
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
