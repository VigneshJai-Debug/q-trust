// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./lib/StringBounds.sol";

/// @title EvidenceRegistry — hash-chained evidence ledger roots
/// @notice Organizations post the Merkle root of a tamper-evident evidence
///         ledger on-chain. The full ledger is stored off-chain (IPFS or S3);
///         only its root hash lives here. Supports EIP-712 gasless registration
///         and UUPS proxy upgradeability.
contract EvidenceRegistry is AccessControl, ReentrancyGuard, Pausable, Initializable, UUPSUpgradeable {

    error EvidenceNotFound(bytes32 evidenceId);
    error DuplicateEvidence(bytes32 evidenceId);
    error EmptyEvidenceRoot();
    error NotOwnerOrAdmin(address caller);
    error NotRegistrar(address caller);
    error AlreadyRevoked(bytes32 evidenceId);
    error InvalidSignature();
    error InvalidNonce(address signer, uint256 provided, uint256 expected);
    error NotInitialized();

    event EvidenceRegistered(
        bytes32 indexed evidenceId,
        bytes32 evidenceRoot,
        uint256 entryCount,
        string  scanTarget,
        uint256 timestamp
    );

    event EvidenceRevoked(
        bytes32 indexed evidenceId,
        string  reason,
        uint256 timestamp
    );

    struct EvidenceRecord {
        string  batchId;
        bytes32 evidenceRoot;
        uint256 entryCount;
        string  scanTarget;
        uint256 findingsCount;
        bytes32 riskSummaryHash;
        uint256 timestamp;
        address owner;
        bool    active;
    }

    mapping(bytes32 => EvidenceRecord) private _evidence;
    bytes32[] private _allEvidenceIds;
    mapping(address => bytes32[]) private _evidenceByOwner;

    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    // ==================== EIP-712 (gasless evidence registration) ====================
    bytes32 private constant _EVIDENCE_REGISTRATION_TYPEHASH =
        keccak256(
            "EvidenceRegistration(bytes32 evidenceRoot,uint256 entryCount,string scanTarget,uint256 findingsCount,bytes32 riskSummaryHash,uint256 nonce)"
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
        _grantRole(REGISTRAR_ROLE, msg.sender);
        _cachedChainId = block.chainid;
        _domainSeparator = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256("QTrustEvidenceRegistry"),
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
                keccak256("QTrustEvidenceRegistry"),
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

    /// @notice Hash the typed Evidence Registration data for EIP-712 signing.
    function hashTypedEvidenceRegistration(
        bytes32 evidenceRoot,
        uint256 entryCount,
        string calldata scanTarget,
        uint256 findingsCount,
        bytes32 riskSummaryHash,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                _currentDomainSeparator(),
                keccak256(
                    abi.encode(
                        _EVIDENCE_REGISTRATION_TYPEHASH,
                        evidenceRoot,
                        entryCount,
                        keccak256(abi.encodePacked(scanTarget)),
                        findingsCount,
                        riskSummaryHash,
                        nonce
                    )
                )
            )
        );
    }

    /// @notice Submit a gasless evidence registration signed by the owner.
    ///         The signer's address becomes the owner of the evidence record;
    ///         the caller (any relayer) pays the gas.
    function registerEvidenceSigned(
        bytes32 evidenceRoot,
        uint256 entryCount,
        string calldata scanTarget,
        uint256 findingsCount,
        bytes32 riskSummaryHash,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant whenNotPaused returns (bytes32 evidenceId) {
        address signer = _recoverEvidenceSigner(
            evidenceRoot, entryCount, scanTarget, findingsCount, riskSummaryHash, nonce, signature
        );
        if (signer == address(0)) revert InvalidSignature();
        // The signature proves intent, not authority: the signer must hold
        // REGISTRAR_ROLE exactly like the direct path requires.
        if (!hasRole(REGISTRAR_ROLE, signer)) revert NotRegistrar(signer);
        if (nonces[signer] != nonce) {
            revert InvalidNonce(signer, nonce, nonces[signer]);
        }

        nonces[signer] = nonce + 1;

        return _registerEvidence(signer, evidenceRoot, entryCount, scanTarget, findingsCount, riskSummaryHash);
    }

    /// @dev Recover the EIP-712 signer of an evidence registration.
    function _recoverEvidenceSigner(
        bytes32 evidenceRoot,
        uint256 entryCount,
        string calldata scanTarget,
        uint256 findingsCount,
        bytes32 riskSummaryHash,
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
                        _EVIDENCE_REGISTRATION_TYPEHASH,
                        evidenceRoot,
                        entryCount,
                        keccak256(abi.encodePacked(scanTarget)),
                        findingsCount,
                        riskSummaryHash,
                        nonce
                    )
                )
            )
        );
        return ECDSA.recover(digest, signature);
    }

    /// @notice Register a new evidence ledger root (direct, requires REGISTRAR_ROLE)
    /// @param evidenceRoot     Merkle root of the hash-chained evidence ledger
    /// @param entryCount       Number of entries in the ledger
    /// @param scanTarget       Target identifier that was scanned
    /// @param findingsCount    Number of findings produced by the scan
    /// @param riskSummaryHash  Hash of the risk summary document
    /// @return evidenceId      The ID under which this evidence is stored
    function registerEvidence(
        bytes32 evidenceRoot,
        uint256 entryCount,
        string calldata scanTarget,
        uint256 findingsCount,
        bytes32 riskSummaryHash
    ) external nonReentrant whenNotPaused onlyRole(REGISTRAR_ROLE) returns (bytes32 evidenceId) {
        return _registerEvidence(msg.sender, evidenceRoot, entryCount, scanTarget, findingsCount, riskSummaryHash);
    }

    /// @dev Internal evidence registration logic shared by direct and EIP-712 paths.
    function _registerEvidence(
        address owner_,
        bytes32 evidenceRoot,
        uint256 entryCount,
        string calldata scanTarget,
        uint256 findingsCount,
        bytes32 riskSummaryHash
    ) internal returns (bytes32 evidenceId) {
        if (evidenceRoot == bytes32(0)) revert EmptyEvidenceRoot();
        StringBounds.checkDID(scanTarget);

        evidenceId = keccak256(abi.encode(owner_, evidenceRoot, entryCount));

        if (_evidence[evidenceId].owner != address(0)) {
            revert DuplicateEvidence(evidenceId);
        }

        string memory batchId = _generateBatchId(owner_, evidenceRoot);

        _evidence[evidenceId] = EvidenceRecord({
            batchId: batchId,
            evidenceRoot: evidenceRoot,
            entryCount: entryCount,
            scanTarget: scanTarget,
            findingsCount: findingsCount,
            riskSummaryHash: riskSummaryHash,
            timestamp: block.timestamp,
            owner: owner_,
            active: true
        });

        _allEvidenceIds.push(evidenceId);
        _evidenceByOwner[owner_].push(evidenceId);

        emit EvidenceRegistered(evidenceId, evidenceRoot, entryCount, scanTarget, block.timestamp);
    }

    /// @dev Derive a deterministic batch ID from the owner and root.
    function _generateBatchId(address owner_, bytes32 evidenceRoot)
        internal pure returns (string memory)
    {
        return string(abi.encodePacked("batch-", _toHex(owner_), "-", _toHex(evidenceRoot)));
    }

    /// @dev Encode an address as a hex string (without "0x" prefix).
    function _toHex(address value) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(40);
        for (uint256 i = 0; i < 40; i++) {
            str[i] = hexChars[uint8(uint160(value) >> (156 - i * 4)) & 0x0f];
        }
        return string(str);
    }

    /// @dev Encode a bytes32 as a hex string (without "0x" prefix).
    function _toHex(bytes32 value) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            str[i] = hexChars[uint8(uint256(value) >> (252 - i * 4)) & 0x0f];
        }
        return string(str);
    }

    /// @notice Revoke (deactivate) an evidence record.
    ///         Only the original registrant or an admin may revoke.
    function revokeEvidence(
        bytes32 evidenceId,
        string calldata reason
    ) external nonReentrant whenNotPaused {
        StringBounds.checkLen(reason, StringBounds.REASON_MAX);
        EvidenceRecord storage record = _evidence[evidenceId];
        if (record.owner == address(0)) revert EvidenceNotFound(evidenceId);
        if (!record.active) revert AlreadyRevoked(evidenceId);
        if (record.owner != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotOwnerOrAdmin(msg.sender);
        }

        record.active = false;

        emit EvidenceRevoked(evidenceId, reason, block.timestamp);
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

    /// @notice Get an evidence record by ID
    function getEvidence(bytes32 evidenceId) external view returns (EvidenceRecord memory) {
        if (_evidence[evidenceId].owner == address(0)) revert EvidenceNotFound(evidenceId);
        return _evidence[evidenceId];
    }

    /// @notice Total number of registered evidence records
    function getEvidenceCount() external view returns (uint256) {
        return _allEvidenceIds.length;
    }

    /// @notice Verify that a stored evidence root matches an expected root
    function verifyEvidence(bytes32 evidenceId, bytes32 expectedRoot)
        external view returns (bool)
    {
        EvidenceRecord storage record = _evidence[evidenceId];
        if (record.owner == address(0)) return false;
        return record.evidenceRoot == expectedRoot && record.active;
    }

    /// @notice Get all evidence IDs for an owner
    function getEvidenceByOwner(address owner_) external view returns (bytes32[] memory) {
        return _evidenceByOwner[owner_];
    }

    /// @notice Get all evidence IDs (paginated)
    function getAllEvidenceIds(uint256 offset, uint256 limit)
        external view returns (bytes32[] memory page, uint256 total)
    {
        total = _allEvidenceIds.length;
        if (offset >= total) return (new bytes32[](0), total);
        uint256 end = offset + limit;
        if (end > total) end = total;
        uint256 pageSize = end - offset;
        page = new bytes32[](pageSize);
        for (uint256 i = 0; i < pageSize; i++) {
            page[i] = _allEvidenceIds[offset + i];
        }
    }
}
