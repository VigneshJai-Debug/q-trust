// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/AuditRegistry.sol";
import "../src/MigrationRegistry.sol";
import "../src/AssetRegistry.sol";
import "../src/lib/StringBounds.sol";

contract AuditRegistryTest is Test {
    AuditRegistry public registry;
    MigrationRegistry public migrations;
    AssetRegistry public assets;

    address admin = address(0xAD0F);
    address auditor = address(0xA11CE);
    address org = address(0x0A6);
    address nonAuditor = address(0xBAD);
    address relayer = address(0xAE1A73);

    uint256 auditorKey = 0xA11CEC;
    address signerAuditor;

    bytes32 ORG_ASSET_ID;
    bytes32 constant EVIDENCE_HASH = keccak256("evidence");

    bytes32 private constant _AUDIT_TYPEHASH =
        keccak256(
            "Audit(address orgDid,uint8 result,uint256 assetsReviewed,uint256 assetsMigrated,"
            "bytes32 reportHash,string reportURI,uint256 nonce)"
        );

    function _sign(
        address signer,
        uint256 sk,
        address orgDid,
        AuditRegistry.AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsMigrated,
        bytes32 reportHash,
        string memory reportURI,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                _AUDIT_TYPEHASH,
                orgDid,
                result,
                assetsReviewed,
                assetsMigrated,
                reportHash,
                keccak256(abi.encodePacked(reportURI)),
                nonce
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", registry.domainSeparator(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function setUp() public {
        signerAuditor = vm.addr(auditorKey);
        assets = new AssetRegistry();
        assets.initialize();
        assets.grantRole(assets.REGISTRAR_ROLE(), org);
        migrations = new MigrationRegistry();
        migrations.initialize(address(assets));
        migrations.grantRole(migrations.MIGRATOR_ROLE(), org);
        registry = new AuditRegistry();
        registry.initialize(address(migrations));
        registry.grantRole(registry.AUDITOR_ROLE(), auditor);
        registry.grantRole(registry.AUDITOR_ROLE(), signerAuditor);

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

    // ==================== EIP-712 gasless path ====================

    function test_DomainSeparator_MatchEIP712() public {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("QTrustAuditRegistry"),
                keccak256("1"),
                block.chainid,
                address(registry)
            )
        );
        assertEq(registry.domainSeparator(), expected);
    }

    function test_PostAuditSigned_RecordsSignerAsAuditor() public {
        bytes memory sig = _sign(
            signerAuditor, auditorKey,
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0
        );

        vm.prank(relayer);
        bytes32 auditId = registry.postAuditSigned(
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0, sig
        );

        AuditRegistry.AuditAttestation memory att = registry.getAudit(auditId);
        assertEq(att.auditorDid, signerAuditor, "signer must be recorded as the auditor");
        assertEq(att.orgDid, org);
        assertEq(uint8(att.result), uint8(AuditRegistry.AuditResult.Passed));
        assertEq(att.assetsReviewed, 10);
        assertEq(att.assetsMigrated, 1);
        assertEq(registry.nonces(signerAuditor), 1, "nonce must increment");
        assertEq(registry.getAuditsByAuditor(signerAuditor).length, 1);
    }

    function test_RevertWhen_SignedReplay() public {
        bytes memory sig = _sign(
            signerAuditor, auditorKey,
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0
        );

        vm.prank(relayer);
        registry.postAuditSigned(
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0, sig
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(AuditRegistry.InvalidNonce.selector, signerAuditor, 0, 1)
        );
        registry.postAuditSigned(
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0, sig
        );
    }

    function test_RevertWhen_SignedSignerLacksAuditorRole() public {
        uint256 outsiderSk = 0xBAD60D;
        address outsider = vm.addr(outsiderSk);

        bytes memory sig = _sign(
            outsider, outsiderSk,
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0
        );

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(AuditRegistry.NotAuditor.selector, outsider));
        registry.postAuditSigned(
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0, sig
        );
        assertEq(registry.nonces(outsider), 0, "nonce must not advance on rejection");
    }

    function test_RevertWhen_TamperedSignature() public {
        bytes memory sig = _sign(
            signerAuditor, auditorKey,
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0
        );
        sig[0] ^= 0x01;

        vm.prank(relayer);
        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        registry.postAuditSigned(
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0, sig
        );
    }

    function test_RevertWhen_WrongNonce() public {
        bytes memory sig = _sign(
            signerAuditor, auditorKey,
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 5
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(AuditRegistry.InvalidNonce.selector, signerAuditor, 5, 0)
        );
        registry.postAuditSigned(
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 5, sig
        );
    }

    function test_RevertWhen_Paused_SignedPath() public {
        registry.pause();

        bytes memory sig = _sign(
            signerAuditor, auditorKey,
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0
        );

        vm.prank(relayer);
        vm.expectRevert();
        registry.postAuditSigned(
            org, AuditRegistry.AuditResult.Passed, 10, 1, keccak256("report"), "ipfs://QmReport", 0, sig
        );
    }

    function test_DomainSeparator_ChainFork_SignedStillVerifies() public {
        bytes32 sepBefore = registry.domainSeparator();

        // Simulate a chain fork: the separator must re-derive for chain 999.
        vm.chainId(999);
        assertFalse(registry.domainSeparator() == sepBefore, "separator must re-derive on new chainid");

        bytes memory sig = _sign(
            signerAuditor, auditorKey,
            org, AuditRegistry.AuditResult.Conditional, 5, 1, keccak256("fork-report"), "", 0
        );
        vm.prank(relayer);
        bytes32 auditId = registry.postAuditSigned(
            org, AuditRegistry.AuditResult.Conditional, 5, 1, keccak256("fork-report"), "", 0, sig
        );

        assertTrue(auditId != bytes32(0), "signed attestation must verify on the forked chain");
        assertEq(registry.getAudit(auditId).auditorDid, signerAuditor);
    }

    function test_RevertWhen_ReportURITooLong() public {
        string memory longURI = string(new bytes(513));
        vm.prank(auditor);
        vm.expectRevert(
            abi.encodeWithSelector(StringBounds.StringTooLong.selector, 513, 512)
        );
        registry.postAudit(org, AuditRegistry.AuditResult.Passed, 1, 0, keccak256("r"), longURI);
    }
}