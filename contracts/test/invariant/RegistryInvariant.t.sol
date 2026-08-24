// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../src/AssetRegistry.sol";
import "../../src/VendorRegistry.sol";
import "../../src/MigrationRegistry.sol";
import "./RegistryHandler.t.sol";

/// @title RegistryInvariantTest — §12.2 #1 stateful fuzz invariants
/// @notice A: nonces never decrease. B: registered asset/attestation IDs are
///         unique and remain resolvable. C: while paused, every write
///         entrypoint reverts (enforced inside the handler via expectRevert).
contract RegistryInvariantTest is Test {
    RegistryHandler internal handler;

    address[] internal actors;

    function setUp() public {
        handler = new RegistryHandler();
        actors.push(handler.actors(0));
        actors.push(handler.actors(1));
        actors.push(handler.actors(2));
        targetContract(address(handler));
    }

    // ==================== Invariant A ====================

    function invariant_NoncesNeverDecrease() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            address actor = actors[i];
            assertGe(
                handler.assets().nonces(actor),
                handler.lastNonceAssets(actor),
                "AssetRegistry nonce decreased"
            );
            assertGe(
                handler.vendors().nonces(actor),
                handler.lastNonceVendors(actor),
                "VendorRegistry nonce decreased"
            );
            assertGe(
                handler.migrations().nonces(actor),
                handler.lastNonceMigrations(actor),
                "MigrationRegistry nonce decreased"
            );
        }
    }

    // ==================== Invariant B ====================

    function invariant_AssetIdsUniqueAndResolvable() public view {
        bytes32[] memory ids = handler.allCreatedAssetIds();
        for (uint256 i = 0; i < ids.length; i++) {
            (bool exists,, ) = handler.assets().verifyAsset(ids[i]);
            assertTrue(exists, "recorded asset must stay resolvable");
            for (uint256 j = i + 1; j < ids.length; j++) {
                assertFalse(ids[i] == ids[j], "duplicate asset id recorded");
            }
        }
    }

    function invariant_AttestationIdsUniqueAndResolvable() public view {
        bytes32[] memory ids = handler.allCreatedAttestationIds();
        for (uint256 i = 0; i < ids.length; i++) {
            assertTrue(
                handler.vendors().getAttestation(ids[i]).vendorDid != address(0),
                "recorded attestation must stay resolvable"
            );
            for (uint256 j = i + 1; j < ids.length; j++) {
                assertFalse(ids[i] == ids[j], "duplicate attestation id recorded");
            }
        }
    }

    // ==================== Invariant C (explicit regression) ====================

    function test_WhenPaused_AllWriteEntrypointsRevert() public {
        handler.toggleAssetsPause();
        handler.toggleVendorsPause();
        handler.toggleMigrationsPause();

        assertTrue(Pausable(address(handler.assets())).paused());
        assertTrue(Pausable(address(handler.vendors())).paused());
        assertTrue(Pausable(address(handler.migrations())).paused());

        // Every write path reverts while paused — including gasless ones.
        // The handler wraps each attempt in expectRevert internally, so any
        // accepted write fails this test.
        handler.registerAssetDirect(0, 777);
        handler.registerAssetSigned(1, 778);
        handler.attestProductDirect(0, 779);
        handler.attestProductSigned(1, 780);
        handler.recordMigration(2, 781);
        handler.recordMigrationSigned(0, 782);

        // Unpausing restores writes.
        handler.toggleAssetsPause();
        handler.registerAssetDirect(0, 783);
        assertTrue(handler.assets().assetCount() > 1);
    }
}
