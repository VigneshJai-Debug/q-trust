// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title AssetRegistry — registers Cryptographic Bills of Materials (CBOMs)
/// @notice Organizations post the hash of their CBOM (asset inventory) on-chain.
///         The full CBOM is stored off-chain (IPFS or S3); only its hash is here.
///         Supports EIP-712 gasless registration and UUPS proxy upgradeability.
contract AssetRegistry is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error AssetNotFound(bytes32 assetId);
    error AssetAlreadyExists(bytes32 assetId);
    error NotRegistrar(address caller);
    error EmptyHash();
    error MetadataTooLong();
    error AssetAlreadyRetired(bytes32 assetId);
    error InvalidSignature();
    error InvalidNonce(address signer, uint256 provided, uint256 expected);
    error NotInitialized();

    event CBOMRegistered(
        bytes32 indexed assetId,
        address indexed orgDid,
        bytes32 cbomHash,
        string  metadataURI,
        uint256 timestamp
    );

    event CBOMUpdated(
        bytes32 indexed assetId,
        bytes32 newCbomHash,
        string  newMetadataURI,
        uint256 timestamp
    );

    event CBOMRetired(
        bytes32 indexed assetId,
        uint256 timestamp
    );

    struct Asset {
        address orgDid;          // Organization that registered
        bytes32 cbomHash;         // SHA-256 of the CBOM JSON
        string  metadataURI;      // IPFS URI for full CBOM
        uint256 timestamp;        // When registered
        uint256 lastUpdated;      // Last update timestamp
        bool    active;
    }

    mapping(bytes32 => Asset) private _assets;
    bytes32[] private _allAssetIds;
    mapping(address => bytes32[]) private _assetsByOrg;

    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    // ==================== EIP-712 (gasless CBOM registration) ====================
    bytes32 private constant _CBOM_REGISTRATION_TYPEHASH =
        keccak256(
            "CBOMRegistration(bytes32 cbomHash,string metadataURI,uint256 nonce)"
        );

    bytes32 private constant _DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private _domainSeparator;
    bytes32 public constant EIP712_VERSION_HASH = keccak256("1");

    mapping(address => uint256) public nonces;

    bool private _initialized;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {}

    function initialize() public initializer {
        if (_initialized) revert NotInitialized();
        _initialized = true;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRAR_ROLE, msg.sender);
        _domainSeparator = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustAssetRegistry"),
                EIP712_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Domain separator for EIP-712 typed data signing.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator;
    }

    /// @notice Hash the typed CBOM Registration data for EIP-712 signing.
    function hashTypedCBOMRegistration(
        bytes32 cbomHash,
        string calldata metadataURI,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator,
                keccak256(
                    abi.encode(
                        _CBOM_REGISTRATION_TYPEHASH,
                        cbomHash,
                        keccak256(abi.encodePacked(metadataURI)),
                        nonce
                    )
                )
            )
        );
    }

    /// @notice Submit a gasless CBOM registration signed by the org.
    ///         The org's signature authorizes the registration; the caller
    ///         (any relayer) pays the gas. The recorded orgDid is the signer.
    function registerCBOMSigned(
        bytes32 cbomHash,
        string calldata metadataURI,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant whenNotPaused returns (bytes32 assetId) {
        address signer = _recoverCBOMSigner(cbomHash, metadataURI, nonce, signature);
        if (signer == address(0)) revert InvalidSignature();
        if (nonces[signer] != nonce) {
            revert InvalidNonce(signer, nonce, nonces[signer]);
        }

        nonces[signer] = nonce + 1;

        return _registerCBOM(signer, cbomHash, metadataURI);
    }

    /// @dev Recover the EIP-712 signer of a CBOM registration.
    function _recoverCBOMSigner(
        bytes32 cbomHash,
        string calldata metadataURI,
        uint256 nonce,
        bytes calldata signature
    ) internal view returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _domainSeparator,
                keccak256(
                    abi.encode(
                        _CBOM_REGISTRATION_TYPEHASH,
                        cbomHash,
                        keccak256(abi.encodePacked(metadataURI)),
                        nonce
                    )
                )
            )
        );
        return ECDSA.recover(digest, signature);
    }

    /// @notice Register a new CBOM (direct, requires REGISTRAR_ROLE)
    /// @param cbomHash     SHA-256 of the CBOM JSON file
    /// @param metadataURI  IPFS URI (ipfs://...) for the full CBOM
    /// @return assetId     The ID under which this CBOM is stored
    function registerCBOM(
        bytes32 cbomHash,
        string calldata metadataURI
    ) external nonReentrant whenNotPaused onlyRole(REGISTRAR_ROLE) returns (bytes32 assetId) {
        return _registerCBOM(msg.sender, cbomHash, metadataURI);
    }

    /// @dev Internal CBOM registration logic shared by direct and EIP-712 paths.
    function _registerCBOM(
        address orgDid,
        bytes32 cbomHash,
        string calldata metadataURI
    ) internal returns (bytes32 assetId) {
        if (cbomHash == bytes32(0)) revert EmptyHash();
        if (bytes(metadataURI).length > 512) revert MetadataTooLong();

        assetId = keccak256(abi.encode(orgDid, cbomHash));

        if (_assets[assetId].orgDid != address(0)) {
            revert AssetAlreadyExists(assetId);
        }

        _assets[assetId] = Asset({
            orgDid: orgDid,
            cbomHash: cbomHash,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            lastUpdated: block.timestamp,
            active: true
        });

        _allAssetIds.push(assetId);
        _assetsByOrg[orgDid].push(assetId);

        emit CBOMRegistered(assetId, orgDid, cbomHash, metadataURI, block.timestamp);
    }

    /// @notice Update a CBOM (e.g., after re-scanning)
    function updateCBOM(
        bytes32 assetId,
        bytes32 newCbomHash,
        string calldata newMetadataURI
    ) external nonReentrant whenNotPaused {
        Asset storage asset = _assets[assetId];
        if (asset.orgDid == address(0)) revert AssetNotFound(assetId);
        if (asset.orgDid != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotRegistrar(msg.sender);
        }
        asset.cbomHash = newCbomHash;
        asset.metadataURI = newMetadataURI;
        asset.lastUpdated = block.timestamp;

        emit CBOMUpdated(assetId, newCbomHash, newMetadataURI, block.timestamp);
    }

    /// @notice Retire a CBOM registration.
    function retireAsset(bytes32 assetId) external nonReentrant whenNotPaused {
        Asset storage asset = _assets[assetId];
        if (asset.orgDid == address(0)) revert AssetNotFound(assetId);
        if (asset.orgDid != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotRegistrar(msg.sender);
        }
        if (!asset.active) revert AssetAlreadyRetired(assetId);
        asset.active = false;
        asset.lastUpdated = block.timestamp;

        emit CBOMRetired(assetId, block.timestamp);
    }

    /// @notice Pause all registrations, updates, and retirements
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Get a CBOM by ID
    function getAsset(bytes32 assetId) external view returns (Asset memory) {
        if (_assets[assetId].orgDid == address(0)) revert AssetNotFound(assetId);
        return _assets[assetId];
    }

    /// @notice Verify a CBOM exists and is active
    function verifyAsset(bytes32 assetId)
        external view returns (bool exists, bool active, address orgDid)
    {
        Asset storage asset = _assets[assetId];
        if (asset.orgDid == address(0)) return (false, false, address(0));
        return (true, asset.active, asset.orgDid);
    }

    /// @notice Total number of registered CBOMs
    function assetCount() external view returns (uint256) {
        return _allAssetIds.length;
    }

    /// @notice Get all CBOM IDs for an org
    function getAssetsByOrg(address orgDid) external view returns (bytes32[] memory) {
        return _assetsByOrg[orgDid];
    }

    /// @notice Get all CBOM IDs (paginated)
    function getAllAssetIds(uint256 offset, uint256 limit)
        external view returns (bytes32[] memory page, uint256 total)
    {
        total = _allAssetIds.length;
        if (offset >= total) return (new bytes32[](0), total);
        uint256 end = offset + limit;
        if (end > total) end = total;
        uint256 pageSize = end - offset;
        page = new bytes32[](pageSize);
        for (uint256 i = 0; i < pageSize; i++) {
            page[i] = _allAssetIds[offset + i];
        }
    }
}
