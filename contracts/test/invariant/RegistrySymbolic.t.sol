// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../../src/AssetRegistry.sol";
import "../../src/VendorRegistry.sol";
import "../../src/MigrationRegistry.sol";

/// @title RegistrySymbolicTest — Halmos symbolic verification of the core
///        registry integrity properties, on the raw implementations.
///
/// WHY RAW, NOT PROXY: the registries are UUPS upgradeable and disable their
/// initializers at construction (audit C-2), so the only production setup is
/// an ERC1967Proxy delegatecall into initialize(). Halmos cannot flatten the
/// OZ initializer guard's internal branch ("Multiple paths were found in
/// setUp()"), and the full stateful handler path-explodes. Deploying the raw
/// implementation and granting roles via direct storage writes exercises the
/// exact same registry logic (hasRole/onlyRole, EIP-712 recovery, nonce
/// accounting, asset/migration state) without the proxy indirection, which
/// Halmos verifies in seconds. The stateful fuzz invariants on the proxied
/// stack remain covered by forge (RegistryInvariant.t.sol).
///
/// Properties (check_* run under `halmos`; test_* also run under `forge`):
///   A. Every signed registration advances the signer's nonce by exactly one
///      (asset / vendor / migration registries).
///   B. A signed registration is immediately resolvable.
///   C. Replaying the same signed registration reverts (duplicate detection).
contract RegistrySymbolicTest is Test {
    uint256 internal constant KEY = 1;
    address internal actor;

    AssetRegistry internal assets;
    VendorRegistry internal vendors;
    MigrationRegistry internal migrations;

    // ==================== Setup ====================

    function setUp() public {
        actor = vm.addr(KEY);

        assets = new AssetRegistry();
        _grantRole(address(assets), assets.REGISTRAR_ROLE(), actor);

        vendors = new VendorRegistry();
        // initialize() sets maxAttestationsPerProduct = 256 (slot 1, offset 1,
        // packed after _paused); the raw implementation never runs
        // initialize(), so write the default directly to storage.
        vm.store(
            address(vendors),
            bytes32(uint256(1)),
            bytes32(uint256(vendors.DEFAULT_MAX_ATTESTATIONS_PER_PRODUCT()) << 8)
        );
        // registerVendor grants VENDOR_ROLE and marks the vendor active (the
        // signed attestation path requires _vendors[signer].active). Grant
        // VENDOR_ADMIN_ROLE to this test so the registration is authorized.
        _grantRole(address(vendors), vendors.VENDOR_ADMIN_ROLE(), address(this));
        vendors.registerVendor(actor, "Vendor", "ipfs://QmVendor");

        migrations = new MigrationRegistry();
        // _migrations storage: assetRegistry lives at slot 6 (see
        // forge inspect storageLayout); wire the raw AssetRegistry so the
        // cross-contract ownership check (audit M-1) can run.
        vm.store(address(migrations), bytes32(uint256(6)), bytes32(uint256(uint160(address(assets)))));
        _grantRole(address(migrations), migrations.MIGRATOR_ROLE(), actor);

        // One asset owned by the actor, for migration ownership checks.
        vm.prank(actor);
        assets.registerCBOM(keccak256("owned"), "ipfs://QmOwned");
    }

    /// @dev Grant role via direct storage write. AccessControl's `_roles`
    ///      mapping is the first state variable (slot 0) in every registry;
    ///      `_roles[role].hasRole[account]` sits at
    ///      keccak256(account, keccak256(role, 0)).
    function _grantRole(address registry, bytes32 role, address account) internal {
        bytes32 membersMappingSlot = keccak256(abi.encode(role, uint256(0)));
        bytes32 memberSlot = keccak256(abi.encode(account, membersMappingSlot));
        vm.store(registry, memberSlot, bytes32(uint256(1)));
    }

    function _sign(bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    // ==================== A: nonce monotonicity ====================

    function check_AssetNonceAdvancesExactlyOne(uint256 salt) public {
        bytes32 cbomHash = keccak256(abi.encode("cbom", salt));
        uint256 nonce = assets.nonces(actor);
        bytes memory sig = _sign(assets.hashTypedCBOMRegistration(cbomHash, "ipfs://QmP", nonce));
        assets.registerCBOMSigned(cbomHash, "ipfs://QmP", nonce, sig);
        assertEq(assets.nonces(actor), nonce + 1, "asset nonce must advance by exactly one");
    }

    function check_VendorNonceAdvancesExactlyOne(uint256 salt) public {
        string memory pid = string(abi.encodePacked("P", bytes32(salt)));
        uint256 nonce = vendors.nonces(actor);
        bytes memory sig = _sign(
            vendors.hashTypedAttestation(pid, "1.0", "ML-KEM-512", true, "ipfs://QmE", nonce)
        );
        vendors.attestProductSigned(pid, "1.0", "ML-KEM-512", true, "ipfs://QmE", nonce, sig);
        assertEq(vendors.nonces(actor), nonce + 1, "vendor nonce must advance by exactly one");
    }

    function check_MigrationNonceAdvancesExactlyOne(uint256 salt) public {
        bytes32 migrationId = keccak256(abi.encode("migration", salt));
        bytes32 assetId = keccak256(abi.encode(actor, keccak256("owned")));
        uint256 nonce = migrations.nonces(actor);
        bytes memory sig = _sign(
            migrations.hashTypedMigration(
                migrationId, assetId, "RSA-2048", "ML-DSA-441", keccak256("evd"), "ipfs://QmEv", nonce
            )
        );
        migrations.recordMigrationSigned(
            migrationId, assetId, "RSA-2048", "ML-DSA-441", keccak256("evd"), "ipfs://QmEv", nonce, sig
        );
        assertEq(migrations.nonces(actor), nonce + 1, "migration nonce must advance by exactly one");
    }

    // ==================== B: resolvability ====================

    function check_SignedAssetIsResolvable(uint256 salt) public {
        bytes32 cbomHash = keccak256(abi.encode("cbom", salt));
        uint256 nonce = assets.nonces(actor);
        bytes memory sig = _sign(assets.hashTypedCBOMRegistration(cbomHash, "ipfs://QmP", nonce));
        assets.registerCBOMSigned(cbomHash, "ipfs://QmP", nonce, sig);
        bytes32 assetId = keccak256(abi.encode(actor, cbomHash));
        (bool exists, bool active,) = assets.verifyAsset(assetId);
        assertTrue(exists, "signed asset must be resolvable");
        assertTrue(active, "signed asset must be active");
    }

    // NOTE: replay protection (a second identical submission reverting) is
    // verified in the forge unit suite — halmos does not support
    // vm.expectRevert, so it cannot be expressed symbolically.

    // ==================== forge-side sanity (test_*) ====================

    function test_symbolicSetupsAreFunctional() public {
        // Direct registration works for the actor (role granted via storage).
        vm.prank(actor);
        assets.registerCBOM(keccak256("direct"), "ipfs://QmDirect");
        (bool exists,,) = assets.verifyAsset(keccak256(abi.encode(actor, keccak256("direct"))));
        assertTrue(exists, "direct registration failed");

        // Migration ownership check passes for the actor's own asset.
        vm.prank(actor);
        migrations.recordMigration(
            keccak256("m1"), keccak256(abi.encode(actor, keccak256("owned"))),
            "RSA-2048", "ML-DSA-441", keccak256("evd"), "ipfs://QmEv"
        );
        assertEq(migrations.nonces(actor), 0, "direct path must not touch nonce");
    }

    function test_signedPathAdvancesNonce() public {
        uint256 before_ = assets.nonces(actor);
        bytes32 cbomHash = keccak256("probe");
        bytes memory sig = _sign(assets.hashTypedCBOMRegistration(cbomHash, "ipfs://QmP", before_));
        assets.registerCBOMSigned(cbomHash, "ipfs://QmP", before_, sig);
        assertEq(assets.nonces(actor), before_ + 1, "nonce not advanced");
    }
}
