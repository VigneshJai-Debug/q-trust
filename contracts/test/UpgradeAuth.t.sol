// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/AssetRegistry.sol";
import "../src/VendorRegistry.sol";
import "../src/MigrationRegistry.sol";
import "../src/AuditRegistry.sol";

/// @title UpgradeAuthTest — tests UUPS proxy upgrade authorization
/// @notice Uses ERC1967Proxy (same as Deploy.s.sol) to verify that only
///         the DEFAULT_ADMIN_ROLE can authorize upgrades.
contract UpgradeAuthTest is Test {
    AssetRegistry assets;
    VendorRegistry vendors;
    MigrationRegistry migrations;
    AuditRegistry audits;

    address admin = address(0xA);
    address nonAdmin = address(0xB);

    function setUp() public {
        vm.startPrank(admin);

        AssetRegistry assetsImpl = new AssetRegistry();
        VendorRegistry vendorsImpl = new VendorRegistry();
        MigrationRegistry migrationsImpl = new MigrationRegistry();
        AuditRegistry auditsImpl = new AuditRegistry();

        assets = AssetRegistry(
            address(new ERC1967Proxy(
                address(assetsImpl),
                abi.encodeCall(AssetRegistry.initialize, ())
            ))
        );
        vendors = VendorRegistry(
            address(new ERC1967Proxy(
                address(vendorsImpl),
                abi.encodeCall(VendorRegistry.initialize, ())
            ))
        );
        migrations = MigrationRegistry(
            address(new ERC1967Proxy(
                address(migrationsImpl),
                abi.encodeCall(MigrationRegistry.initialize, (address(assets)))
            ))
        );
        audits = AuditRegistry(
            address(new ERC1967Proxy(
                address(auditsImpl),
                abi.encodeCall(AuditRegistry.initialize, (address(migrations)))
            ))
        );

        vm.stopPrank();
    }

    // ==================== Admin Upgrade ====================

    function test_AdminCanUpgradeAssetRegistry() public {
        vm.startPrank(admin);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");

        AssetRegistry newImpl = new AssetRegistry();
        assets.upgradeToAndCall(address(newImpl), "");

        AssetRegistry.Asset memory a = assets.getAsset(assetId);
        assertEq(a.orgDid, admin);
        assertEq(a.cbomHash, keccak256("cbom1"));
        vm.stopPrank();
    }

    function test_AdminCanUpgradeVendorRegistry() public {
        vm.startPrank(admin);
        vendors.registerVendor(admin, "Acme", "ipfs://QmVendor");

        VendorRegistry newImpl = new VendorRegistry();
        vendors.upgradeToAndCall(address(newImpl), "");

        VendorRegistry.VendorInfo memory v = vendors.getVendor(admin);
        assertTrue(v.active);
        assertEq(v.name, "Acme");
        vm.stopPrank();
    }

    function test_AdminCanUpgradeMigrationRegistry() public {
        vm.startPrank(admin);
        assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), admin);

        MigrationRegistry newImpl = new MigrationRegistry();
        migrations.upgradeToAndCall(address(newImpl), "");

        assertEq(migrations.migrationCount(), 0);
        vm.stopPrank();
    }

    function test_AdminCanUpgradeAuditRegistry() public {
        vm.startPrank(admin);
        audits.grantRole(audits.AUDITOR_ROLE(), admin);

        AuditRegistry newImpl = new AuditRegistry();
        audits.upgradeToAndCall(address(newImpl), "");

        assertEq(audits.getAuditsByOrg(admin).length, 0);
        vm.stopPrank();
    }

    // ==================== Non-Admin Rejection ====================

    function test_NonAdminCannotUpgradeAssetRegistry() public {
        vm.prank(nonAdmin);
        try assets.upgradeToAndCall(address(new AssetRegistry()), "") {
            revert("nonAdmin upgrade should have reverted");
        } catch {}
    }

    function test_NonAdminCannotUpgradeVendorRegistry() public {
        vm.prank(nonAdmin);
        try vendors.upgradeToAndCall(address(new VendorRegistry()), "") {
            revert("nonAdmin upgrade should have reverted");
        } catch {}
    }

    function test_NonAdminCannotUpgradeMigrationRegistry() public {
        vm.prank(nonAdmin);
        try migrations.upgradeToAndCall(address(new MigrationRegistry()), "") {
            revert("nonAdmin upgrade should have reverted");
        } catch {}
    }

    function test_NonAdminCannotUpgradeAuditRegistry() public {
        vm.prank(nonAdmin);
        try audits.upgradeToAndCall(address(new AuditRegistry()), "") {
            revert("nonAdmin upgrade should have reverted");
        } catch {}
    }

    // ==================== Storage Preservation After Upgrade ====================

    function test_AssetRegistry_StoragePreservedAfterUpgrade() public {
        vm.startPrank(admin);

        bytes32 id1 = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        bytes32 id2 = assets.registerCBOM(keccak256("cbom2"), "ipfs://Qm2");
        assertEq(assets.assetCount(), 2);

        AssetRegistry newImpl = new AssetRegistry();
        assets.upgradeToAndCall(address(newImpl), "");

        assertEq(assets.assetCount(), 2);
        AssetRegistry.Asset memory a1 = assets.getAsset(id1);
        assertEq(a1.cbomHash, keccak256("cbom1"));
        assertTrue(a1.active);

        AssetRegistry.Asset memory a2 = assets.getAsset(id2);
        assertEq(a2.cbomHash, keccak256("cbom2"));
        assertTrue(a2.active);

        vm.stopPrank();
    }

    function test_VendorRegistry_StoragePreservedAfterUpgrade() public {
        vm.startPrank(admin);

        vendors.registerVendor(admin, "Acme", "ipfs://QmVendor");

        VendorRegistry newImpl = new VendorRegistry();
        vendors.upgradeToAndCall(address(newImpl), "");
        VendorRegistry.VendorInfo memory v = vendors.getVendor(admin);
        assertTrue(v.active);

        vm.stopPrank();
    }

    function test_MigrationRegistry_StoragePreservedAfterUpgrade() public {
        vm.startPrank(admin);

        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), admin);
        migrations.recordMigration(
            keccak256("m1"), assetId,
            "RSA-2048", "ML-DSA-441",
            keccak256("evidence"), "ipfs://QmEv"
        );
        assertEq(migrations.migrationCount(), 1);

        MigrationRegistry newImpl = new MigrationRegistry();
        migrations.upgradeToAndCall(address(newImpl), "");

        assertEq(migrations.migrationCount(), 1);
        vm.stopPrank();
    }

    function test_AuditRegistry_StoragePreservedAfterUpgrade() public {
        vm.startPrank(admin);

        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), admin);
        migrations.recordMigration(
            keccak256("m1"), assetId,
            "RSA-2048", "ML-DSA-441",
            keccak256("evidence"), "ipfs://QmEv"
        );
        audits.grantRole(audits.AUDITOR_ROLE(), admin);
        audits.postAudit(
            admin, AuditRegistry.AuditResult.Passed,
            10, 1, keccak256("report"), "ipfs://QmR"
        );
        assertEq(audits.getAuditsByOrg(admin).length, 1);

        AuditRegistry newImpl = new AuditRegistry();
        audits.upgradeToAndCall(address(newImpl), "");

        assertEq(audits.getAuditsByOrg(admin).length, 1);
        vm.stopPrank();
    }

    // ==================== Upgrade and Functionality ====================

    function test_FunctionalityPreservedAfterUpgrade() public {
        vm.startPrank(admin);

        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");

        AssetRegistry newImpl = new AssetRegistry();
        assets.upgradeToAndCall(address(newImpl), "");

        assets.updateCBOM(assetId, keccak256("cbom-v2"), "ipfs://Qm2");
        AssetRegistry.Asset memory a = assets.getAsset(assetId);
        assertEq(a.cbomHash, keccak256("cbom-v2"));

        assets.retireAsset(assetId);
        (bool exists, bool active, ) = assets.verifyAsset(assetId);
        assertTrue(exists);
        assertFalse(active);

        vm.stopPrank();
    }
}
