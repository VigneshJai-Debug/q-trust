// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/AssetRegistry.sol";
import "../src/VendorRegistry.sol";
import "./mocks/RegistryV2Mocks.sol";

/// @title UpgradeTest — §12.2 #6: real UUPS upgrade with state preservation
/// @notice Deploys each registry behind an ERC1967Proxy (same pattern as
///         script/Deploy.s.sol), upgrades to a V2 mock, and verifies prior
///         state survives, new functionality works, and unauthorized
///         upgrades revert.
contract UpgradeTest is Test {
    address admin = address(0xA5AD);
    address attacker = address(0xBAD);

    function _deployAssetRegistry() internal returns (AssetRegistry) {
        vm.startPrank(admin);
        AssetRegistry impl = new AssetRegistry();
        AssetRegistry proxy = AssetRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(AssetRegistry.initialize, ())))
        );
        vm.stopPrank();
        return proxy;
    }

    function _deployVendorRegistry() internal returns (VendorRegistry) {
        vm.startPrank(admin);
        VendorRegistry impl = new VendorRegistry();
        VendorRegistry proxy = VendorRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(VendorRegistry.initialize, ())))
        );
        vm.stopPrank();
        return proxy;
    }

    function test_AssetRegistry_UpgradePreservesStateAndAddsFunctionality() public {
        AssetRegistry assets = _deployAssetRegistry();

        vm.startPrank(admin);
        bytes32 assetId = assets.registerCBOM(keccak256("cbom-v1"), "ipfs://QmCBOMv1");
        assertEq(assets.assetCount(), 1);

        AssetRegistryV2Mock v2 = new AssetRegistryV2Mock();
        assets.upgradeToAndCall(address(v2), "");
        vm.stopPrank();

        // Prior state readable and intact through the new implementation.
        assertEq(assets.assetCount(), 1, "asset count must survive the upgrade");
        AssetRegistry.Asset memory a = assets.getAsset(assetId);
        assertEq(a.orgDid, admin);
        assertEq(a.cbomHash, keccak256("cbom-v1"));
        assertTrue(a.active);

        // New storage var + setter/getter + version() work.
        assertEq(
            AssetRegistryV2Mock(address(assets)).version(),
            "AssetRegistry v2"
        );
        AssetRegistryV2Mock(address(assets)).setV2Value(42);
        assertEq(AssetRegistryV2Mock(address(assets)).v2Value(), 42);

        // V1 entrypoints keep working after the upgrade.
        vm.startPrank(admin);
        assets.updateCBOM(assetId, keccak256("cbom-v2"), "ipfs://QmCBOMv2");
        assertEq(assets.getAsset(assetId).cbomHash, keccak256("cbom-v2"));
        vm.stopPrank();
    }

    function test_VendorRegistry_UpgradePreservesStateAndAddsFunctionality() public {
        VendorRegistry vendors = _deployVendorRegistry();

        vm.startPrank(admin);
        vendors.registerVendor(admin, "Acme", "ipfs://QmVendor");
        assertTrue(vendors.isVendorActive(admin));

        VendorRegistryV2Mock v2 = new VendorRegistryV2Mock();
        vendors.upgradeToAndCall(address(v2), "");
        vm.stopPrank();

        // Prior state readable and intact through the new implementation.
        VendorRegistry.VendorInfo memory v = vendors.getVendor(admin);
        assertEq(v.name, "Acme", "vendor name must survive the upgrade");
        assertTrue(v.active);

        // New storage var + setter/getter + version() work.
        assertEq(
            VendorRegistryV2Mock(address(vendors)).version(),
            "VendorRegistry v2"
        );
        VendorRegistryV2Mock(address(vendors)).setV2Value(1337);
        assertEq(VendorRegistryV2Mock(address(vendors)).v2Value(), 1337);

        // Configurable limit state also survives.
        assertEq(vendors.maxAttestationsPerProduct(), 256);
    }

    function test_UnauthorizedCannotUpgradeAssetRegistry() public {
        AssetRegistry assets = _deployAssetRegistry();
        AssetRegistryV2Mock v2 = new AssetRegistryV2Mock();

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                attacker,
                bytes32(0)
            )
        );
        assets.upgradeToAndCall(address(v2), "");
    }

    function test_UnauthorizedCannotUpgradeVendorRegistry() public {
        VendorRegistry vendors = _deployVendorRegistry();
        VendorRegistryV2Mock v2 = new VendorRegistryV2Mock();

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                attacker,
                bytes32(0)
            )
        );
        vendors.upgradeToAndCall(address(v2), "");
    }
}
