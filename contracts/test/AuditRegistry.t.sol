// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/AuditRegistry.sol";
import "../src/MigrationRegistry.sol";
import "../src/AssetRegistry.sol";

contract AuditRegistryTest is Test {
    AuditRegistry public registry;
    MigrationRegistry public migrations;
    AssetRegistry public assets;

    address admin = address(0xAD0F);
    address auditor = address(0xA11CE);
    address org = address(0x0A6);
    address nonAuditor = address(0xBAD);

    bytes32 ORG_ASSET_ID;
    bytes32 constant EVIDENCE_HASH = keccak256("evidence");

    function setUp() public {
        assets = new AssetRegistry();
        assets.initialize();
        assets.grantRole(assets.REGISTRAR_ROLE(), org);
        migrations = new MigrationRegistry(address(assets));
        migrations.initialize();
        migrations.grantRole(migrations.MIGRATOR_ROLE(), org);
        registry = new AuditRegistry(address(migrations));
        registry.initialize();
        registry.grantRole(registry.AUDITOR_ROLE(), auditor);

        vm.startPrank(org);
        ORG_ASSET_ID = assets.registerCBOM(keccak256("cbom"), "ipfs://QmCBOM");
        migrations.recordMigration(
            keccak256("m1"), ORG_ASSET_ID,
            "RSA-2048", "ML-DSA-441", EVIDENCE_HASH, "ipfs://QmEv"
        );
        vm.stopPrank();
    }

    function test_PostAudit() public {
        vm.prank(auditor);
        bytes32 auditId = registry.postAudit(
            org,
            AuditRegistry.AuditResult.Passed,
            10,
            1,
            keccak256("report"),
            "ipfs://QmReport"
        );

        AuditRegistry.AuditAttestation memory att = registry.getAudit(auditId);
        assertEq(att.orgDid, org, "orgDid should match");
        assertEq(att.auditorDid, auditor, "auditorDid should match");
        assertEq(uint8(att.result), uint8(AuditRegistry.AuditResult.Passed), "result should be Passed");
        assertEq(att.assetsReviewed, 10, "assetsReviewed should match");
        assertEq(att.assetsMigrated, 1, "assetsMigrated should match");
    }

    function test_RevertWhen_NonAuditorPosts() public {
        vm.prank(nonAuditor);
        vm.expectRevert();
        registry.postAudit(org, AuditRegistry.AuditResult.Failed, 1, 0, keccak256("r"), "");
    }

    function test_RevertWhen_EmptyReportHash() public {
        vm.prank(auditor);
        vm.expectRevert(AuditRegistry.EmptyReportHash.selector);
        registry.postAudit(org, AuditRegistry.AuditResult.Passed, 1, 0, bytes32(0), "ipfs://QmR");
    }

    function test_RevertWhen_MigratedExceedsReviewed() public {
        vm.prank(auditor);
        vm.expectRevert(
            abi.encodeWithSelector(AuditRegistry.InvalidCounts.selector, 3, 5)
        );
        registry.postAudit(org, AuditRegistry.AuditResult.Passed, 3, 5, keccak256("r"), "");
    }

    function test_RevertWhen_ClaimExceedsOnChain() public {
        vm.prank(auditor);
        vm.expectRevert(
            abi.encodeWithSelector(AuditRegistry.MigratedCountExceedsOnChain.selector, 7, 1)
        );
        registry.postAudit(org, AuditRegistry.AuditResult.Passed, 10, 7, keccak256("r"), "");
    }

    function test_AuditTracksOnChainMigrations() public {
        // One migration exists on-chain; claiming exactly 1 must succeed.
        vm.prank(auditor);
        registry.postAudit(org, AuditRegistry.AuditResult.Conditional, 5, 1, keccak256("r1"), "");

        // Claiming 2 while only 1 exists must revert.
        vm.prank(auditor);
        vm.expectRevert(
            abi.encodeWithSelector(AuditRegistry.MigratedCountExceedsOnChain.selector, 2, 1)
        );
        registry.postAudit(org, AuditRegistry.AuditResult.Conditional, 5, 2, keccak256("r2"), "");
    }

    function test_GetAuditsByOrg() public {
        vm.prank(auditor);
        registry.postAudit(org, AuditRegistry.AuditResult.Conditional, 5, 1, keccak256("r1"), "");
        vm.prank(auditor);
        registry.postAudit(org, AuditRegistry.AuditResult.Passed, 5, 1, keccak256("r2"), "");

        bytes32[] memory ids = registry.getAuditsByOrg(org);
        assertEq(ids.length, 2, "two audits expected");

        bool exists;
        AuditRegistry.AuditResult result;
        uint256 timestamp;
        (exists, result, timestamp) = registry.getLatestAudit(org);
        assertTrue(exists, "latest audit should exist");
        assertEq(uint8(result), uint8(AuditRegistry.AuditResult.Passed), "latest should be Passed");
    }

    function test_GetAuditsByAuditor() public {
        vm.prank(auditor);
        registry.postAudit(org, AuditRegistry.AuditResult.Failed, 3, 1, keccak256("r"), "");

        bytes32[] memory ids = registry.getAuditsByAuditor(auditor);
        assertEq(ids.length, 1, "one audit expected");
    }
}