// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {ProxyDeploy} from "./helpers/ProxyDeploy.sol";
import "../src/MigrationRegistry.sol";
import "../src/AssetRegistry.sol";
import "../src/lib/StringBounds.sol";

contract MigrationRegistryTest is Test {
    MigrationRegistry public registry;
    AssetRegistry public assets;

    address admin = address(0xAD0F);
    address migrator = address(0xB0B);
    address nonAuditor = address(0xDEADBEEF);
    address relayer = address(0xAE1A73);

    uint256 orgKey = 0x0A6C3;
    address orgSigner;

    bytes32 ASSET_ID;
    bytes32 constant EVIDENCE_HASH = keccak256("evidence-1");

    bytes32 private constant _MIGRATION_RECORDING_TYPEHASH =
        keccak256(
            "MigrationRecording(bytes32 migrationId,bytes32 assetId,string fromAlgorithm,"
            "string toAlgorithm,bytes32 evidenceHash,string evidenceURI,uint256 nonce)"
        );

    function _sign(
        address signer,
        uint256 sk,
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
                _MIGRATION_RECORDING_TYPEHASH,
                migrationId,
                assetId,
                keccak256(abi.encodePacked(fromAlgorithm)),
                keccak256(abi.encodePacked(toAlgorithm)),
                evidenceHash,
                keccak256(abi.encodePacked(evidenceURI)),
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
        orgSigner = vm.addr(orgKey);
        assets = ProxyDeploy.asset();
        assets.grantRole(assets.REGISTRAR_ROLE(), migrator);
        registry = ProxyDeploy.migration(address(assets));
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

    function test_DomainSeparator_ChainFork_SignedStillVerifies() public {
        bytes32 sepBefore = registry.domainSeparator();

        // Simulate a chain fork: the separator must re-derive for chain 999.
        vm.chainId(999);
        assertFalse(registry.domainSeparator() == sepBefore, "separator must re-derive on new chainid");

        bytes32 migrationId = keccak256("fork-migration");
        bytes memory sig = _sign(
            orgSigner, orgKey, migrationId, ASSET_ID, "RSA-2048", "ML-DSA-441", EVIDENCE_HASH, "ipfs://QmEv", 0
        );
        vm.prank(relayer);
        bytes32 recorded = registry.recordMigrationSigned(
            migrationId, ASSET_ID, "RSA-2048", "ML-DSA-441", EVIDENCE_HASH, "ipfs://QmEv", 0, sig
        );

        assertEq(recorded, migrationId, "signed migration must verify on the forked chain");
        assertEq(registry.nonces(orgSigner), 1);
    }

    function test_RevertWhen_AlgorithmTooLong() public {
        vm.startPrank(migrator);
        string memory longAlgo = string(new bytes(65));
        vm.expectRevert(
            abi.encodeWithSelector(StringBounds.StringTooLong.selector, 65, 64)
        );
        registry.recordMigration(
            keccak256("m-long"), ASSET_ID,
            longAlgo, "ML-DSA-441",
            EVIDENCE_HASH, "ipfs://QmEvidence"
        );
        vm.stopPrank();
    }

    function test_RevertWhen_EvidenceURITooLong() public {
        vm.startPrank(migrator);
        string memory longURI = string(new bytes(513));
        vm.expectRevert(
            abi.encodeWithSelector(StringBounds.StringTooLong.selector, 513, 512)
        );
        registry.recordMigration(
            keccak256("m-long-uri"), ASSET_ID,
            "RSA-2048", "ML-DSA-441",
            EVIDENCE_HASH, longURI
        );
        vm.stopPrank();
    }
}
