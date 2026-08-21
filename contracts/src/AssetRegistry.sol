// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title AssetRegistry — registers Cryptographic Bills of Materials (CBOMs)
/// @notice Organizations post the hash of their CBOM (asset inventory) on-chain.
///         The full CBOM is stored off-chain (IPFS or S3); only its hash is here.
contract AssetRegistry is AccessControl, ReentrancyGuard {

    error AssetNotFound(bytes32 assetId);
    error AssetAlreadyExists(bytes32 assetId);
    error NotRegistrar(address caller);
    error EmptyHash();
    error AssetAlreadyRetired(bytes32 assetId);

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

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRAR_ROLE, msg.sender);
    }

    /// @notice Register a new CBOM
    /// @param cbomHash     SHA-256 of the CBOM JSON file
    /// @param metadataURI  IPFS URI (ipfs://...) for the full CBOM
    /// @return assetId     The ID under which this CBOM is stored
    function registerCBOM(
        bytes32 cbomHash,
        string calldata metadataURI
    ) external nonReentrant onlyRole(REGISTRAR_ROLE) returns (bytes32 assetId) {
        if (cbomHash == bytes32(0)) revert EmptyHash();

        assetId = keccak256(abi.encodePacked(msg.sender, cbomHash, block.timestamp));

        if (_assets[assetId].orgDid != address(0)) {
            revert AssetAlreadyExists(assetId);
        }

        _assets[assetId] = Asset({
            orgDid: msg.sender,
            cbomHash: cbomHash,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            lastUpdated: block.timestamp,
            active: true
        });

        _allAssetIds.push(assetId);
        _assetsByOrg[msg.sender].push(assetId);

        emit CBOMRegistered(assetId, msg.sender, cbomHash, metadataURI, block.timestamp);
    }

    /// @notice Update a CBOM (e.g., after re-scanning)
    function updateCBOM(
        bytes32 assetId,
        bytes32 newCbomHash,
        string calldata newMetadataURI
    ) external nonReentrant {
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

    /// @notice Retire a CBOM registration. The owning org (or an admin) marks
    ///         the asset inactive; retired assets can no longer back migration
    ///         records and are shown as REVOKED in verification UIs.
    function retireAsset(bytes32 assetId) external nonReentrant {
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
