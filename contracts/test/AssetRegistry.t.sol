// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/AssetRegistry.sol";

contract AssetRegistryTest is Test {
    AssetRegistry public registry;
    address registrar = address(0xA11CE);
    address unauthorized = address(0xEEEE);

    bytes32 constant CBOM_HASH = keccak256("cbom-v1");
    string constant METADATA_URI = "ipfs://QmTestCBOM";

    function setUp() public {
        registry = new AssetRegistry();
        registry.grantRole(registry.REGISTRAR_ROLE(), registrar);
    }

    function test_RegisterCBOM() public {
        vm.prank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);
        assertTrue(assetId != bytes32(0));

        (bool exists, bool active, address orgDid) = registry.verifyAsset(assetId);
        assertTrue(exists);
        assertTrue(active);
        assertEq(orgDid, registrar);
    }

    function test_RevertWhen_NotRegistrar() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        registry.registerCBOM(CBOM_HASH, METADATA_URI);
    }

    function test_RevertWhen_EmptyHash() public {
        vm.prank(registrar);
        vm.expectRevert(AssetRegistry.EmptyHash.selector);
        registry.registerCBOM(bytes32(0), METADATA_URI);
    }

    function test_UpdateCBOM() public {
        vm.prank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);

        vm.prank(registrar);
        registry.updateCBOM(assetId, keccak256("cbom-v2"), "ipfs://QmTestCBOMv2");

        AssetRegistry.Asset memory asset = registry.getAsset(assetId);
        assertEq(asset.cbomHash, keccak256("cbom-v2"));
    }

    function test_RetireAsset_ByOwner() public {
        vm.prank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);

        vm.prank(registrar);
        registry.retireAsset(assetId);

        (bool exists, bool active, ) = registry.verifyAsset(assetId);
        assertTrue(exists);
        assertFalse(active, "asset should be inactive after retirement");
    }

    function test_RetireAsset_ByAdmin() public {
        vm.prank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);

        registry.retireAsset(assetId);
        (bool exists, bool active, ) = registry.verifyAsset(assetId);
        assertTrue(exists);
        assertFalse(active);
    }

    function test_RevertWhen_UnauthorizedRetire() public {
        vm.prank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);

        vm.prank(unauthorized);
        vm.expectRevert(
            abi.encodeWithSelector(AssetRegistry.NotRegistrar.selector, unauthorized)
        );
        registry.retireAsset(assetId);
    }

    function test_RevertWhen_RetireTwice() public {
        vm.prank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);

        vm.prank(registrar);
        registry.retireAsset(assetId);

        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(AssetRegistry.AssetAlreadyRetired.selector, assetId)
        );
        registry.retireAsset(assetId);
    }

    function test_AssetCount() public {
        assertEq(registry.assetCount(), 0);
        vm.prank(registrar);
        registry.registerCBOM(CBOM_HASH, METADATA_URI);
        assertEq(registry.assetCount(), 1);
    }

    function test_GetAssetsByOrg() public {
        vm.startPrank(registrar);
        registry.registerCBOM(CBOM_HASH, METADATA_URI);
        vm.warp(block.timestamp + 1);
        registry.registerCBOM(keccak256("cbom-v2"), METADATA_URI);
        vm.stopPrank();

        bytes32[] memory assets = registry.getAssetsByOrg(registrar);
        assertEq(assets.length, 2);
    }
}