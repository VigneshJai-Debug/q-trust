// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {ProxyDeploy} from "../helpers/ProxyDeploy.sol";
import "../../src/AssetRegistry.sol";
import "../../src/VendorRegistry.sol";
import "../../src/MigrationRegistry.sol";

/// @title RegistryHandler — stateful-fuzz driver for the registry invariants
/// @notice Every write entrypoint is exercised both unpaused and paused. While
///         a registry is paused the handler wraps the write in expectRevert,
///         so any accepted write while paused fails the run (Invariant C).
contract RegistryHandler is Test {

    AssetRegistry public assets;
    VendorRegistry public vendors;
    MigrationRegistry public migrations;

    address[] public actors;
    mapping(address => uint256) internal _keyOfActor;

    bytes32[] internal _createdAssetIds;
    mapping(bytes32 => bool) public seenAssetId;
    bytes32[] internal _createdAttestationIds;
    mapping(bytes32 => bool) public seenAttestationId;

    // Ghost dedup keys: content-addressed IDs are deterministic, and the v2
    // registries revert on duplicates — the handler must not replay them.
    mapping(bytes32 => bool) internal _seenCbomHash;
    mapping(bytes32 => bool) internal _seenProductKey; // keccak(actor, productId)
    mapping(bytes32 => bool) internal _seenMigrationId;
    mapping(address => bool) internal _seenVendor;

    mapping(address => uint256) internal _lastNonceAssets;
    mapping(address => uint256) internal _lastNonceVendors;
    mapping(address => uint256) internal _lastNonceMigrations;

    uint256 public assetsPauseToggles;
    uint256 public vendorsPauseToggles;
    uint256 public migrationsPauseToggles;

    bytes32 private immutable _seedAssetId;
    mapping(address => bytes32) internal _assetOf;

    constructor() {
        assets = ProxyDeploy.asset();
        vendors = ProxyDeploy.vendor();
        migrations = ProxyDeploy.migration(address(assets));

        // Three actors, unrolled: Halmos treats loops as symbolic path joins
        // ("Multiple paths were found in setUp()"), so setup must be
        // straight-line code.
        _addActor(0xA1100);
        _addActor(0xA1100 + 0x111);
        _addActor(0xA1100 + 2 * 0x111);

        // The handler toggles pause states directly, so it needs each
        // registry's admin role (pause()/unpause() are DEFAULT_ADMIN-gated).
        // Without this the toggles silently reverted under
        // fail_on_revert = false — and failed runs under true.
        bytes32 adminRole = assets.DEFAULT_ADMIN_ROLE();
        assets.grantRole(adminRole, address(this));
        vendors.grantRole(adminRole, address(this));
        migrations.grantRole(adminRole, address(this));

        vm.prank(actors[0]);
        _seedAssetId = assets.registerCBOM(keccak256("seed-cbom"), "ipfs://QmSeed");
        seenAssetId[_seedAssetId] = true;
        _createdAssetIds.push(_seedAssetId);

        // Each actor owns a dedicated asset so migrations respect the
        // ownership rule (audit M-1): recordMigration* must only be invoked
        // with an asset owned by the recording org.
        for (uint256 i = 0; i < actors.length; i++) {
            vm.prank(actors[i]);
            bytes32 owned = assets.registerCBOM(
                keccak256(abi.encode("owned-cbom", actors[i])),
                "ipfs://QmOwned"
            );
            _assetOf[actors[i]] = owned;
            seenAssetId[owned] = true;
            _createdAssetIds.push(owned);
        }
    }

    function _ownedAsset(address actor) internal view returns (bytes32) {
        return _assetOf[actor];
    }

    function _addActor(uint256 key_) internal {
        address actor = vm.addr(key_);
        actors.push(actor);
        _keyOfActor[actor] = key_;

        assets.grantRole(assets.REGISTRAR_ROLE(), actor);
        vendors.registerVendor(actor, _shortName(actors.length - 1), "ipfs://QmVendor");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), actor);
    }

    // ==================== Write entrypoints ====================

    function registerAssetDirect(uint256 actorSeed, uint256 salt) external {
        address actor = _actor(actorSeed);
        bytes32 cbomHash = keccak256(abi.encode("cbom", salt));
        string memory uri = _uri(salt);

        if (_seenCbomHash[cbomHash]) return;

        if (assets.paused()) {
            vm.expectRevert();
            assets.registerCBOM(cbomHash, uri);
            _seenCbomHash[cbomHash] = true;
            return;
        }

        vm.prank(actor);
        bytes32 assetId = assets.registerCBOM(cbomHash, uri);
        _seenCbomHash[cbomHash] = true;
        if (!seenAssetId[assetId]) {
            seenAssetId[assetId] = true;
            _createdAssetIds.push(assetId);
        }
    }

    function registerAssetSigned(uint256 actorSeed, uint256 salt) external {
        address actor = _actor(actorSeed);
        bytes32 cbomHash = keccak256(abi.encode("signed-cbom", salt));
        string memory uri = _uri(salt);

        if (_seenCbomHash[cbomHash]) return;

        uint256 nonce = assets.nonces(actor);
        bytes memory sig = _signCBOM(actor, cbomHash, uri, nonce);

        if (assets.paused()) {
            vm.expectRevert();
            assets.registerCBOMSigned(cbomHash, uri, nonce, sig);
            return;
        }

        bytes32 assetId = assets.registerCBOMSigned(cbomHash, uri, nonce, sig);
        _seenCbomHash[cbomHash] = true;
        _lastNonceAssets[actor] = assets.nonces(actor);
        if (!seenAssetId[assetId]) {
            seenAssetId[assetId] = true;
            _createdAssetIds.push(assetId);
        }
    }

    function attestProductDirect(uint256 actorSeed, uint256 salt) external {
        address actor = _actor(actorSeed);
        string memory pid = _productId(salt);
        bytes32 dedupKey = keccak256(abi.encode(actor, pid));

        if (_seenProductKey[dedupKey]) return;

        if (vendors.paused()) {
            vm.expectRevert();
            vm.prank(actor);
            vendors.attestProduct(pid, "1.0", "ML-KEM-512", true, "ipfs://QmE");
            return;
        }

        vm.prank(actor);
        bytes32 attestationId = vendors.attestProduct(pid, "1.0", "ML-KEM-512", true, "ipfs://QmE");
        _seenProductKey[dedupKey] = true;
        if (!seenAttestationId[attestationId]) {
            seenAttestationId[attestationId] = true;
            _createdAttestationIds.push(attestationId);
        }
    }

    function attestProductSigned(uint256 actorSeed, uint256 salt) external {
        address actor = _actor(actorSeed);
        string memory pid = _productId(salt);
        bytes32 dedupKey = keccak256(abi.encode(actor, pid));

        if (_seenProductKey[dedupKey]) return;

        uint256 nonce = vendors.nonces(actor);
        bytes memory sig = _signAttestation(actor, pid, "1.0", "ML-KEM-512", true, "ipfs://QmE", nonce);

        if (vendors.paused()) {
            vm.expectRevert();
            vendors.attestProductSigned(pid, "1.0", "ML-KEM-512", true, "ipfs://QmE", nonce, sig);
            return;
        }

        bytes32 attestationId =
            vendors.attestProductSigned(pid, "1.0", "ML-KEM-512", true, "ipfs://QmE", nonce, sig);
        _seenProductKey[dedupKey] = true;
        _lastNonceVendors[actor] = vendors.nonces(actor);
        if (!seenAttestationId[attestationId]) {
            seenAttestationId[attestationId] = true;
            _createdAttestationIds.push(attestationId);
        }
    }

    function recordMigration(uint256 actorSeed, uint256 salt) external {
        address actor = _actor(actorSeed);
        bytes32 migrationId = keccak256(abi.encode("migration", salt));

        if (_seenMigrationId[migrationId]) return;

        bytes32 assetId = _ownedAsset(actor);

        if (migrations.paused()) {
            vm.expectRevert();
            vm.prank(actor);
            migrations.recordMigration(
                migrationId, assetId, "RSA-2048", "ML-DSA-441",
                keccak256("evd"), "ipfs://QmEv"
            );
            _seenMigrationId[migrationId] = true;
            return;
        }

        vm.prank(actor);
        migrations.recordMigration(
            migrationId, assetId, "RSA-2048", "ML-DSA-441",
            keccak256("evd"), "ipfs://QmEv"
        );
        _seenMigrationId[migrationId] = true;
    }

    function recordMigrationSigned(uint256 actorSeed, uint256 salt) external {
        address actor = _actor(actorSeed);
        bytes32 migrationId = keccak256(abi.encode("signed-migration", salt));

        if (_seenMigrationId[migrationId]) return;

        uint256 nonce = migrations.nonces(actor);
        bytes32 assetId = _ownedAsset(actor);
        bytes memory sig = _signMigration(
            actor, migrationId, assetId, "RSA-2048", "SLH-DSA-128s",
            keccak256("evd-signed"), "ipfs://QmEvS", nonce
        );

        if (migrations.paused()) {
            vm.expectRevert();
            migrations.recordMigrationSigned(
                migrationId, assetId, "RSA-2048", "SLH-DSA-128s",
                keccak256("evd-signed"), "ipfs://QmEvS", nonce, sig
            );
            return;
        }

        migrations.recordMigrationSigned(
            migrationId, assetId, "RSA-2048", "SLH-DSA-128s",
            keccak256("evd-signed"), "ipfs://QmEvS", nonce, sig
        );
        _seenMigrationId[migrationId] = true;
        _lastNonceMigrations[actor] = migrations.nonces(actor);
    }

    function toggleAssetsPause() external {
        if (assets.paused()) {
            assets.unpause();
        } else {
            assets.pause();
        }
        assetsPauseToggles++;
    }

    function toggleVendorsPause() external {
        if (vendors.paused()) {
            vendors.unpause();
        } else {
            vendors.pause();
        }
        vendorsPauseToggles++;
    }

    function toggleMigrationsPause() external {
        if (migrations.paused()) {
            migrations.unpause();
        } else {
            migrations.pause();
        }
        migrationsPauseToggles++;
    }

    // ==================== Ghost accessors ====================

    function allCreatedAssetIds() external view returns (bytes32[] memory) {
        return _createdAssetIds;
    }

    function allCreatedAttestationIds() external view returns (bytes32[] memory) {
        return _createdAttestationIds;
    }

    function lastNonceAssets(address actor) external view returns (uint256) {
        return _lastNonceAssets[actor];
    }

    function lastNonceVendors(address actor) external view returns (uint256) {
        return _lastNonceVendors[actor];
    }

    function lastNonceMigrations(address actor) external view returns (uint256) {
        return _lastNonceMigrations[actor];
    }

    // ==================== Helpers ====================

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function _uri(uint256 salt) internal pure returns (string memory) {
        return string.concat("ipfs://Qm", vm.toString(bound(salt, 0, 1e12)));
    }

    function _productId(uint256 salt) internal pure returns (string memory) {
        return string.concat("Prod-", vm.toString(bound(salt, 0, 1e12)));
    }

    function _shortName(uint256 i) internal pure returns (string memory) {
        return string.concat("Vendor-", vm.toString(i));
    }

    function _signCBOM(
        address signer,
        bytes32 cbomHash,
        string memory metadataURI,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("CBOMRegistration(bytes32 cbomHash,string metadataURI,uint256 nonce)"),
                cbomHash,
                keccak256(bytes(metadataURI)),
                nonce
            )
        );
        return _signRaw(signer, assets.domainSeparator(), structHash);
    }

    function _signAttestation(
        address signer,
        string memory productId,
        string memory version,
        string memory algorithm,
        bool supported,
        string memory evidenceURI,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "ProductAttestation(string productId,string version,string algorithm,"
                    "bool supported,string evidenceURI,uint256 nonce)"
                ),
                keccak256(bytes(productId)),
                keccak256(bytes(version)),
                keccak256(bytes(algorithm)),
                supported,
                keccak256(bytes(evidenceURI)),
                nonce
            )
        );
        return _signRaw(signer, vendors.domainSeparator(), structHash);
    }

    function _signMigration(
        address signer,
        bytes32 migrationId,
        bytes32 assetId,
        string memory fromAlgorithm,
        string memory toAlgorithm,
        bytes32 evidenceHash,
        string memory evidenceURI,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "MigrationRecording(bytes32 migrationId,bytes32 assetId,string fromAlgorithm,"
                    "string toAlgorithm,bytes32 evidenceHash,string evidenceURI,uint256 nonce)"
                ),
                migrationId,
                assetId,
                keccak256(bytes(fromAlgorithm)),
                keccak256(bytes(toAlgorithm)),
                evidenceHash,
                keccak256(bytes(evidenceURI)),
                nonce
            )
        );
        return _signRaw(signer, migrations.domainSeparator(), structHash);
    }

    function _signRaw(address signer, bytes32 domainSep, bytes32 structHash)
        internal view returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(_keyOfActor[signer], keccak256(abi.encodePacked("\x19\x01", domainSep, structHash)));
        return abi.encodePacked(r, s, v);
    }
}
