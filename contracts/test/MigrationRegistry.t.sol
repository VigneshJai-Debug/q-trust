// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/MigrationRegistry.sol";
import "../src/AssetRegistry.sol";

contract MigrationRegistryTest is Test {
    MigrationRegistry public registry;
    AssetRegistry public assets;

    address admin = address(0xAD0F);
    address migrator = address(0xB0B);
    address nonAuditor = address(0xDEADBEEF);

    bytes32 ASSET_ID;
    bytes32 constant EVIDENCE_HASH = keccak256("evidence-1");

    function setUp() public {
        assets = new AssetRegistry();
        assets.initialize();
        assets.grantRole(assets.REGISTRAR_ROLE(), migrator);
        registry = new MigrationRegistry();
        registry.initialize(address(assets));
        registry.grantRole(registry.MIGRATOR_ROLE(), migrator);

        vm.prank(migrator);
        ASSET_ID = assets.registerCBOM(keccak256("cbom"), "ipfs://QmCBOM");
    }

    function _record(bytes32 migrationId, bytes32 assetId) internal {
        vm.prank(migrator);
        registry.recordMigration(
            migrationId,
            assetId,
            "RSA-2048",
            "ML-DSA-441",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );
    }

    function test_RecordMigration() public {
        _record(keccak256("migration-1"), ASSET_ID);

        MigrationRegistry.Migration memory m = registry.getMigration(keccak256("migration-1"));
        assertEq(m.assetId, ASSET_ID, "assetId should match");
        assertEq(m.fromAlgorithm, "RSA-2048", "fromAlgorithm should match");
        assertEq(m.toAlgorithm, "ML-DSA-441", "toAlgorithm should match");
        assertFalse(m.verified, "should not be verified by default");
    }

    function test_RevertWhen_AssetNotRegistered() public {
        bytes32 ghost = keccak256("ghost-asset");
        vm.prank(migrator);
        vm.expectRevert(
            abi.encodeWithSelector(MigrationRegistry.AssetNotRegistered.selector, ghost)
        );
        registry.recordMigration(
            keccak256("m-x"),
            ghost,
            "RSA-2048",
            "ML-DSA-441",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );
    }

    function test_RevertWhen_AssetInactive() public {
        vm.prank(migrator);
        assets.retireAsset(ASSET_ID);

        vm.prank(migrator);
        vm.expectRevert(
            abi.encodeWithSelector(MigrationRegistry.AssetInactive.selector, ASSET_ID)
        );
        registry.recordMigration(
            keccak256("m-x"),
            ASSET_ID,
            "RSA-2048",
            "ML-DSA-441",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );
    }

    function test_RevertWhen_EmptyEvidence() public {
        vm.prank(migrator);
        vm.expectRevert(MigrationRegistry.EmptyEvidenceHash.selector);
        registry.recordMigration(
            keccak256("m-x"),
            ASSET_ID,
            "RSA-2048",
            "ML-DSA-441",
            bytes32(0),
            "ipfs://QmEvidence"
        );
    }

    function test_RevertWhen_SameAlgorithm() public {
        vm.prank(migrator);
        vm.expectRevert(
            abi.encodeWithSelector(MigrationRegistry.SameAlgorithm.selector, "RSA-2048")
        );
        registry.recordMigration(
            keccak256("m-x"),
            ASSET_ID,
            "RSA-2048",
            "RSA-2048",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );
    }

    function test_RevertWhen_NonMigratorRecords() public {
        vm.prank(nonAuditor);
        vm.expectRevert();
        registry.recordMigration(
            keccak256("m-x"),
            ASSET_ID,
            "RSA-2048",
            "ML-DSA-441",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );
    }

    function test_VerifyMigration_ByAdmin() public {
        _record(keccak256("migration-1"), ASSET_ID);
        registry.verifyMigration(keccak256("migration-1"));

        MigrationRegistry.Migration memory m = registry.getMigration(keccak256("migration-1"));
        assertTrue(m.verified, "should be verified");
    }

    function test_RevertWhen_NonAuditorVerifies() public {
        _record(keccak256("migration-1"), ASSET_ID);
        vm.prank(nonAuditor);
        vm.expectRevert();
        registry.verifyMigration(keccak256("migration-1"));
    }

    function test_RevertWhen_VerifyMissingMigration() public {
        bytes32 missing = keccak256("nope");
        vm.expectRevert(
            abi.encodeWithSelector(MigrationRegistry.MigrationNotFound.selector, missing)
        );
        registry.verifyMigration(missing);
    }

    function test_GetMigrationsByAsset() public {
        vm.startPrank(migrator);
        registry.recordMigration(
            keccak256("m1"),
            ASSET_ID,
            "RSA-2048",
            "ML-DSA-441",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );
        registry.recordMigration(
            keccak256("m2"),
            ASSET_ID,
            "ECC-P256",
            "ML-KEM-512",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );
        vm.stopPrank();

        bytes32[] memory migrations = registry.getMigrationsByAsset(ASSET_ID);
        assertEq(migrations.length, 2, "should have 2 migrations");
    }

    function test_GlobalMigrationCount() public {
        assertEq(registry.migrationCount(), 0, "starts at zero");
        _record(keccak256("m1"), ASSET_ID);
        assertEq(registry.migrationCount(), 1, "counts across orgs, not msg.sender");
    }

    function test_PauseUnpause() public {
        registry.pause();
        vm.prank(migrator);
        vm.expectRevert();
        registry.recordMigration(
            keccak256("m-x"),
            ASSET_ID,
            "RSA-2048",
            "ML-DSA-441",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );

        registry.unpause();
        vm.prank(migrator);
        registry.recordMigration(
            keccak256("m-x"),
            ASSET_ID,
            "RSA-2048",
            "ML-DSA-441",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );
        assertTrue(true);
    }
}
