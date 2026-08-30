// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./lib/StringBounds.sol";

/// @title SchemaRegistry — register and query credential schemas
/// @notice Issuers and verifiers reference schemas by URN. The registry resolves
///         schemas to their JSON Schema documents and tracks versions.
///         Schemas can have cross-domain equivalence mappings.
///         Supports UUPS proxy upgradeability.
contract SchemaRegistry is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error SchemaNotFound(string schemaId);
    error SchemaAlreadyExists(string schemaId);
    error EmptySchemaHash();
    error NotSchemaAuthority(address caller);

    event SchemaRegistered(
        string  indexed schemaId,
        uint256 indexed version,
        bytes32 schemaHash,
        string  schemaURI,
        string  schemaType,
        address registeredBy,
        uint256 timestamp
    );

    event SchemaEquivalenceAdded(
        string  indexed fromSchemaId,
        string  indexed toSchemaId,
        string  equivalenceType,
        uint256 timestamp
    );

    event SchemaDeactivated( // REG-26: was missing (monitoring gap)
        string indexed schemaId,
        uint256 indexed version,
        uint256 timestamp
    );

    struct SchemaInfo {
        string  schemaId;
        uint256 version;
        bytes32 schemaHash;
        string  schemaURI;
        string  schemaType;      // e.g., "pqc-readiness", "sbom", "audit-note"
        address registeredBy;
        uint256 timestamp;
        bool    active;
    }

    struct SchemaEntry {
        uint256 latestVersion;
        uint256 totalVersions;
        bool    exists;
    }

    struct EquivalenceMapping {
        string fromSchemaId;
        string toSchemaId;
        string equivalenceType;  // e.g., "equivalent", "subset", "superset"
    }

    mapping(string => SchemaEntry) private _schemas;
    mapping(string => mapping(uint256 => SchemaInfo)) private _schemaVersions;
    mapping(string => uint256[]) private _versionsBySchemaId;
    string[] private _allSchemaIds;

    mapping(string => EquivalenceMapping[]) private _equivalences;

    bytes32 public constant SCHEMA_AUTHORITY_ROLE = keccak256("SCHEMA_AUTHORITY_ROLE");


    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Prevent initialization of the raw implementation (UUPS best practice).
        _disableInitializers();
    }

    function initialize() public initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SCHEMA_AUTHORITY_ROLE, msg.sender);
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Register a new schema (direct, requires SCHEMA_AUTHORITY_ROLE)
    /// @param schemaId   Unique schema identifier (e.g., "https://qtrust.dev/schemas/pqc-readiness/v1")
    /// @param version    Version number (must be latestVersion + 1 for existing schemas)
    /// @param schemaHash SHA-256 of the JSON Schema document
    /// @param schemaURI  IPFS URI for the full JSON Schema
    /// @param schemaType Human-readable type (e.g., "pqc-readiness")
    function registerSchema(
        string calldata schemaId,
        uint256 version,
        bytes32 schemaHash,
        string calldata schemaURI,
        string calldata schemaType
    ) external nonReentrant whenNotPaused onlyRole(SCHEMA_AUTHORITY_ROLE) {
        StringBounds.checkDID(schemaId);
        StringBounds.checkURI(schemaURI);
        StringBounds.checkID(schemaType);
        if (schemaHash == bytes32(0)) revert EmptySchemaHash();

        SchemaEntry storage entry = _schemas[schemaId];
        if (entry.exists) {
            // Audit M-5 / REG-23: strict version sequencing (same as
            // PolicyCommitment). A new schema must start at version 1 and
            // every next version must be exactly latest + 1 — otherwise a
            // malicious authority could register v=type(uint256).max for a
            // fresh schema and permanently brick all future versions.
            if (version != entry.latestVersion + 1) {
                revert SchemaAlreadyExists(schemaId);
            }
        } else if (version != 1) {
            revert SchemaNotFound(schemaId);
        }

        _schemaVersions[schemaId][version] = SchemaInfo({
            schemaId: schemaId,
            version: version,
            schemaHash: schemaHash,
            schemaURI: schemaURI,
            schemaType: schemaType,
            registeredBy: msg.sender,
            timestamp: block.timestamp,
            active: true
        });

        _versionsBySchemaId[schemaId].push(version);

        if (!entry.exists) {
            _allSchemaIds.push(schemaId);
            entry.exists = true;
        }
        entry.latestVersion = version;
        entry.totalVersions++;

        emit SchemaRegistered(schemaId, version, schemaHash, schemaURI, schemaType, msg.sender, block.timestamp);
    }

    /// @notice Add a cross-domain equivalence mapping (admin only)
    /// Audit H-2: added whenNotPaused + nonReentrant so the Pausable
    /// circuit-breaker freezes this mutation during an incident.
    function addEquivalence(
        string calldata fromSchemaId,
        string calldata toSchemaId,
        string calldata equivalenceType
    ) external nonReentrant whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        StringBounds.checkDID(fromSchemaId);
        StringBounds.checkDID(toSchemaId);
        StringBounds.checkID(equivalenceType);
        // Audit L-6: refuse equivalence mappings that reference schemas which
        // were never registered — they pollute the equivalence graph.
        if (!_schemas[fromSchemaId].exists) revert SchemaNotFound(fromSchemaId);
        if (!_schemas[toSchemaId].exists) revert SchemaNotFound(toSchemaId);
        _equivalences[fromSchemaId].push(EquivalenceMapping({
            fromSchemaId: fromSchemaId,
            toSchemaId: toSchemaId,
            equivalenceType: equivalenceType
        }));

        emit SchemaEquivalenceAdded(fromSchemaId, toSchemaId, equivalenceType, block.timestamp);
    }

    /// @notice Deactivate a schema version (admin only) — REG-26 + REG-27
    function deactivateSchema(
        string calldata schemaId,
        uint256 version
    ) external nonReentrant whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        SchemaInfo storage sv = _schemaVersions[schemaId][version];
        if (sv.timestamp == 0) revert SchemaNotFound(schemaId);
        sv.active = false;
        emit SchemaDeactivated(schemaId, version, block.timestamp); // REG-26
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

    /// @notice Get a specific schema version
    function getSchema(
        string calldata schemaId,
        uint256 version
    ) external view returns (SchemaInfo memory) {
        SchemaInfo storage sv = _schemaVersions[schemaId][version];
        if (sv.timestamp == 0) revert SchemaNotFound(schemaId);
        return sv;
    }

    /// @notice Get schema entry info
    function getSchemaEntry(string calldata schemaId) external view returns (SchemaEntry memory) {
        return _schemas[schemaId];
    }

    /// @notice Get all versions for a schema
    function getVersionsBySchemaId(string calldata schemaId) external view returns (uint256[] memory) {
        return _versionsBySchemaId[schemaId];
    }

    /// @notice Get all schema IDs
    // REG-27: unbounded view — prefer paginated getPolicyIds(offset,limit) to avoid gas griefing
    function getAllSchemaIds() external view returns (string[] memory) {
        return _allSchemaIds;
    }

    /// @notice Get equivalence mappings for a schema
    function getEquivalences(string calldata schemaId)
        external view returns (EquivalenceMapping[] memory)
    {
        return _equivalences[schemaId];
    }

    /// @notice Verify a schema: hash matches the registered version
    function verifySchema(
        string calldata schemaId,
        uint256 version,
        bytes32 schemaHash
    ) external view returns (bool) {
        SchemaInfo storage sv = _schemaVersions[schemaId][version];
        if (sv.timestamp == 0) return false;
        return sv.schemaHash == schemaHash && sv.active;
    }

    /// @notice Total number of distinct schemas
    function schemaCount() external view returns (uint256) {
        return _allSchemaIds.length;
    }
}
