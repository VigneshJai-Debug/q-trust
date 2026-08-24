// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/AssetRegistry.sol";
import "../src/lib/StringBounds.sol";

contract AssetRegistryTest is Test {
    AssetRegistry public registry;
    address registrar = address(0xA11CE);
    address unauthorized = address(0xEEEE);
    address relayer = address(0xAE1A73);

    bytes32 constant CBOM_HASH = keccak256("cbom-v1");
    string constant METADATA_URI = "ipfs://QmTestCBOM";

    bytes32 private constant _CBOM_REGISTRATION_TYPEHASH =
        keccak256(
            "CBOMRegistration(bytes32 cbomHash,string metadataURI,uint256 nonce)"
        );

    function _sign(
        address signer,
        uint256 sk,
        bytes32 cbomHash,
        string memory metadataURI,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                _CBOM_REGISTRATION_TYPEHASH,
                cbomHash,
                keccak256(abi.encodePacked(metadataURI)),
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
        registry = new AssetRegistry();
        registry.initialize();
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

    function test_PauseUnpause() public {
        registry.pause();
        vm.prank(registrar);
        vm.expectRevert();
        registry.registerCBOM(CBOM_HASH, METADATA_URI);

        registry.unpause();
        vm.prank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);
        assertTrue(assetId != bytes32(0));
    }

    function test_RevertWhen_DuplicateCBOM() public {
        bytes32 expectedId = keccak256(abi.encode(registrar, CBOM_HASH));

        vm.startPrank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);
        assertEq(assetId, expectedId, "ID must be deterministic (orgDid + cbomHash)");
        vm.expectRevert(
            abi.encodeWithSelector(AssetRegistry.AssetAlreadyExists.selector, expectedId)
        );
        registry.registerCBOM(CBOM_HASH, METADATA_URI);
        vm.stopPrank();

        // The duplicate must be findable via the deterministic getter.
        (bool exists, , address orgDid) = registry.verifyAsset(expectedId);
        assertTrue(exists);
        assertEq(orgDid, registrar);
    }

    function test_ComputeAssetId_MatchesStoredId() public {
        vm.prank(registrar);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);
        assertEq(assetId, registry.computeAssetId(registrar, CBOM_HASH));
    }

    function test_DomainSeparator_ChainFork_SignedStillVerifies() public {
        uint256 orgSk = 0x0A6C1;
        address orgSigner = vm.addr(orgSk);
        registry.grantRole(registry.REGISTRAR_ROLE(), orgSigner);
        bytes32 sepBefore = registry.domainSeparator();

        // Simulate a chain fork: the separator must re-derive for chain 999.
        vm.chainId(999);
        assertFalse(registry.domainSeparator() == sepBefore, "separator must re-derive on new chainid");

        bytes memory sig = _sign(orgSigner, orgSk, CBOM_HASH, METADATA_URI, 0);
        vm.prank(relayer);
        bytes32 assetId = registry.registerCBOMSigned(CBOM_HASH, METADATA_URI, 0, sig);

        assertTrue(assetId != bytes32(0), "signed registration must verify on the forked chain");
        assertEq(registry.nonces(orgSigner), 1);
        assertEq(registry.getAsset(assetId).orgDid, orgSigner);
    }

    function test_RevertWhen_MetadataURITooLong_SignedPath() public {
        string memory longURI = string(new bytes(513));
        uint256 orgSk = 0x0A6C2;
        bytes32 hash = keccak256("cbom-long-uri");
        bytes memory sig = _sign(vm.addr(orgSk), orgSk, hash, longURI, 0);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(StringBounds.StringTooLong.selector, 513, 512));
        registry.registerCBOMSigned(hash, longURI, 0, sig);
    }
}
