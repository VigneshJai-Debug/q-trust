// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "../src/AssetRegistry.sol";
import "../src/VendorRegistry.sol";
import "../src/MigrationRegistry.sol";
import "../src/AuditRegistry.sol";

contract AttackTest is Test {
    AssetRegistry assets;
    VendorRegistry vendors;
    MigrationRegistry migrations;
    AuditRegistry audits;
    ProxyAdmin proxyAdmin;

    address deployer = address(0xD);
    address attacker = address(0xA);

    function setUp() public {
        vm.startPrank(deployer);

        proxyAdmin = new ProxyAdmin(deployer);

        AssetRegistry assetsImpl = new AssetRegistry();
        VendorRegistry vendorsImpl = new VendorRegistry();
        MigrationRegistry migrationsImpl = new MigrationRegistry();
        AuditRegistry auditsImpl = new AuditRegistry();

        assets = AssetRegistry(address(new TransparentUpgradeableProxy(
            address(assetsImpl), address(proxyAdmin),
            abi.encodeCall(AssetRegistry.initialize, ())
        )));
        vendors = VendorRegistry(address(new TransparentUpgradeableProxy(
            address(vendorsImpl), address(proxyAdmin),
            abi.encodeCall(VendorRegistry.initialize, ())
        )));
        migrations = MigrationRegistry(address(new TransparentUpgradeableProxy(
            address(migrationsImpl), address(proxyAdmin),
            abi.encodeCall(MigrationRegistry.initialize, (address(assets)))
        )));
        audits = AuditRegistry(address(new TransparentUpgradeableProxy(
            address(auditsImpl), address(proxyAdmin),
            abi.encodeCall(AuditRegistry.initialize, (address(migrations)))
        )));

        vm.stopPrank();
    }

    // ==================== Proxy Upgrade Authorization ====================

    function test_NonAdminCannotUpgradeProxy() public {
        address newImpl = address(new AssetRegistry());
        vm.prank(attacker);
        vm.expectRevert();
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(payable(address(assets))),
            newImpl,
            ""
        );
    }

    // ==================== Pause Bypass ====================

    function test_PausePreventsCBOMRegistration() public {
        vm.prank(deployer);
        assets.pause();
        vm.prank(deployer);
        vm.expectRevert();
        assets.registerCBOM(keccak256("cbom"), "ipfs://Qm1");
    }

    function test_PausePreventsMigrationRecording() public {
        vm.startPrank(deployer);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), deployer);
        migrations.pause();
        vm.stopPrank();

        vm.prank(deployer);
        vm.expectRevert();
        migrations.recordMigration(
            keccak256("m1"), assetId,
            "RSA-2048", "ML-DSA-441",
            keccak256("evidence"), "ipfs://QmEv"
        );
    }

    function test_PausePreventsAuditPosting() public {
        vm.startPrank(deployer);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), deployer);
        migrations.recordMigration(
            keccak256("m1"), assetId,
            "RSA-2048", "ML-DSA-441",
            keccak256("evidence"), "ipfs://QmEv"
        );
        audits.grantRole(audits.AUDITOR_ROLE(), deployer);
        audits.pause();
        vm.stopPrank();

        vm.prank(deployer);
        vm.expectRevert();
        audits.postAudit(deployer, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmR");
    }

    function test_OnlyAdminCanPause() public {
        vm.prank(attacker);
        vm.expectRevert();
        assets.pause();
    }

    function test_OnlyAdminCanUnpause() public {
        vm.prank(deployer);
        assets.pause();
        vm.prank(attacker);
        vm.expectRevert();
        assets.unpause();
    }

    // ==================== Access Control ====================

    function test_NonRegistrarCannotRegisterCBOM() public {
        vm.prank(attacker);
        vm.expectRevert();
        assets.registerCBOM(keccak256("cbom"), "ipfs://Qm1");
    }

    function test_NonMigratorCannotRecordMigration() public {
        vm.startPrank(deployer);
        assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        vm.stopPrank();

        vm.prank(attacker);
        vm.expectRevert();
        migrations.recordMigration(
            keccak256("m1"), keccak256("cbom1"),
            "RSA-2048", "ML-DSA-441",
            keccak256("evidence"), "ipfs://QmEv"
        );
    }

    function test_NonAuditorCannotPostAudit() public {
        vm.prank(attacker);
        vm.expectRevert();
        audits.postAudit(deployer, AuditRegistry.AuditResult.Passed, 10, 0, keccak256("report"), "ipfs://QmR");
    }

    function test_NonAdminCannotDeactivateVendor() public {
        vm.prank(deployer);
        vendors.registerVendor(attacker, "Attacker", "ipfs://");

        vm.prank(attacker);
        vm.expectRevert();
        vendors.deactivateVendor(attacker);
    }

    function test_NonOwnerCannotRetireAsset() public {
        vm.prank(deployer);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");

        vm.prank(attacker);
        vm.expectRevert();
        assets.retireAsset(assetId);
    }

    // ==================== Cross-Registry Integrity ====================

    function test_CannotRecordMigrationForUnregisteredAsset() public {
        vm.startPrank(deployer);
        migrations.grantRole(migrations.MIGRATOR_ROLE(), deployer);
        vm.expectRevert(
            abi.encodeWithSelector(MigrationRegistry.AssetNotRegistered.selector, keccak256("ghost"))
        );
        migrations.recordMigration(
            keccak256("m1"), keccak256("ghost"),
            "RSA-2048", "ML-DSA-441",
            keccak256("evidence"), "ipfs://QmEv"
        );
        vm.stopPrank();
    }

    function test_CannotRecordMigrationForInactiveAsset() public {
        vm.startPrank(deployer);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        assets.retireAsset(assetId);
        migrations.grantRole(migrations.MIGRATOR_ROLE(), deployer);

        vm.expectRevert(
            abi.encodeWithSelector(MigrationRegistry.AssetInactive.selector, assetId)
        );
        migrations.recordMigration(
            keccak256("m1"), assetId,
            "RSA-2048", "ML-DSA-441",
            keccak256("evidence"), "ipfs://QmEv"
        );
        vm.stopPrank();
    }

    function test_CannotPostAuditExceedingOnChainMigrations() public {
        vm.startPrank(deployer);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), deployer);
        migrations.recordMigration(
            keccak256("m1"), assetId,
            "RSA-2048", "ML-DSA-441",
            keccak256("evidence"), "ipfs://QmEv"
        );
        audits.grantRole(audits.AUDITOR_ROLE(), deployer);

        vm.expectRevert(
            abi.encodeWithSelector(AuditRegistry.MigratedCountExceedsOnChain.selector, 5, 1)
        );
        audits.postAudit(deployer, AuditRegistry.AuditResult.Passed, 10, 5, keccak256("report"), "ipfs://QmR");
        vm.stopPrank();
    }

    // ==================== Duplicate Prevention ====================

    function test_CannotRecordDuplicateMigration() public {
        vm.startPrank(deployer);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), deployer);
        bytes32 migrationId = keccak256("m1");
        migrations.recordMigration(migrationId, assetId, "RSA-2048", "ML-DSA-441", keccak256("evidence"), "ipfs://QmEv");

        vm.expectRevert(
            abi.encodeWithSelector(MigrationRegistry.DuplicateMigration.selector, migrationId)
        );
        migrations.recordMigration(migrationId, assetId, "RSA-2048", "ML-DSA-441", keccak256("evidence2"), "ipfs://QmEv2");
        vm.stopPrank();
    }

    // ==================== Validation ====================

    function test_CannotRecordSameAlgorithmMigration() public {
        vm.startPrank(deployer);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom1"), "ipfs://Qm1");
        migrations.grantRole(migrations.MIGRATOR_ROLE(), deployer);

        vm.expectRevert(
            abi.encodeWithSelector(MigrationRegistry.SameAlgorithm.selector, "RSA-2048")
        );
        migrations.recordMigration(
            keccak256("m1"), assetId,
            "RSA-2048", "RSA-2048",
            keccak256("evidence"), "ipfs://QmEv"
        );
        vm.stopPrank();
    }

    function test_CannotRegisterWithEmptyHash() public {
        vm.prank(deployer);
        vm.expectRevert(AssetRegistry.EmptyHash.selector);
        assets.registerCBOM(bytes32(0), "ipfs://Qm1");
    }

    function test_CannotPostAuditWithEmptyReportHash() public {
        vm.startPrank(deployer);
        audits.grantRole(audits.AUDITOR_ROLE(), deployer);
        vm.expectRevert(AuditRegistry.EmptyReportHash.selector);
        audits.postAudit(deployer, AuditRegistry.AuditResult.Passed, 10, 0, bytes32(0), "ipfs://QmR");
        vm.stopPrank();
    }

    function test_CannotPostAuditWithInvalidCounts() public {
        vm.startPrank(deployer);
        audits.grantRole(audits.AUDITOR_ROLE(), deployer);
        vm.expectRevert(
            abi.encodeWithSelector(AuditRegistry.InvalidCounts.selector, 3, 5)
        );
        audits.postAudit(deployer, AuditRegistry.AuditResult.Passed, 3, 5, keccak256("report"), "ipfs://QmR");
        vm.stopPrank();
    }
}
