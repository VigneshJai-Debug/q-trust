// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {ProxyDeploy} from "./helpers/ProxyDeploy.sol";
import "../src/VendorRegistry.sol";

/// @title VendorRegistrySecurityTest — regression tests for the silent
///         overwrite DoS in _storeAttestation (duplicate attestation IDs).
contract VendorRegistrySecurityTest is Test {
    VendorRegistry public registry;

    address relayer = address(0xAE1A73);

    uint256 vendorSk = 0xB0B001;
    address vendorSigner;

    bytes32 private constant _PRODUCT_ATTESTATION_TYPEHASH =
        keccak256(
            "ProductAttestation(string productId,string version,string algorithm,"
            "bool supported,string evidenceURI,uint256 nonce)"
        );

    function _sign(
        address signer,
        uint256 sk,
        string memory productId,
        string memory version,
        string memory algorithm,
        bool supported,
        string memory evidenceURI,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                _PRODUCT_ATTESTATION_TYPEHASH,
                keccak256(abi.encodePacked(productId)),
                keccak256(abi.encodePacked(version)),
                keccak256(abi.encodePacked(algorithm)),
                supported,
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

    function _expectedAttestationId(
        address v,
        string memory productId,
        string memory version,
        string memory algorithm
    ) internal pure returns (bytes32) {
        bytes32 productIdHash = keccak256(abi.encodePacked(productId, version, algorithm));
        return keccak256(abi.encode(v, productIdHash));
    }

    function setUp() public {
        registry = ProxyDeploy.vendor();
        vendorSigner = vm.addr(vendorSk);
        registry.registerVendor(vendorSigner, "SignerCorp", "ipfs://QmS");
    }

    function test_RevertWhen_SignedDuplicateDifferentNonce() public {
        bytes memory sig0 = _sign(
            vendorSigner, vendorSk, "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0
        );
        vm.prank(relayer);
        bytes32 attId = registry.attestProductSigned(
            "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0, sig0
        );
        assertEq(attId, _expectedAttestationId(vendorSigner, "Prod-A", "2.0", "ML-KEM-768"));

        assertEq(registry.getAttestationsByProduct("Prod-A", "2.0", "ML-KEM-768").length, 1);
        assertEq(registry.getAttestationsByVendor(vendorSigner).length, 1);

        bytes memory sig1 = _sign(
            vendorSigner, vendorSk, "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE-v2", 1
        );
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(VendorRegistry.DuplicateAttestation.selector, attId)
        );
        registry.attestProductSigned(
            "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE-v2", 1, sig1
        );

        // No silent overwrite: lookup arrays stay at one entry and the nonce
        // bump from the reverted transaction is rolled back.
        assertEq(registry.getAttestationsByProduct("Prod-A", "2.0", "ML-KEM-768").length, 1);
        assertEq(registry.getAttestationsByVendor(vendorSigner).length, 1);
        assertEq(registry.nonces(vendorSigner), 1);
    }

    function test_RevertWhen_DirectDuplicate() public {
        vm.startPrank(vendorSigner);
        registry.attestProduct("Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE");
        vm.expectRevert(
            abi.encodeWithSelector(
                VendorRegistry.DuplicateAttestation.selector,
                _expectedAttestationId(vendorSigner, "Prod-A", "2.0", "ML-KEM-768")
            )
        );
        registry.attestProduct("Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE-other");
        vm.stopPrank();

        assertEq(registry.getAttestationsByVendor(vendorSigner).length, 1);
    }

    function testFuzz_SignedDistinctProducts_NoFalsePositives(uint256 count, uint256 seed)
        public
    {
        uint256 n = bound(count, 1, 24);
        // Keep generated product ids within the on-chain length bounds.
        seed = bound(seed, 0, 1e12);

        for (uint256 i = 0; i < n; i++) {
            string memory pid = string.concat("Prod-", vm.toString(seed), "-", vm.toString(i));
            bytes memory sig = _sign(
                vendorSigner, vendorSk, pid, "2.0", "ML-KEM-768", true, "ipfs://QmE", i
            );
            vm.prank(relayer);
            bytes32 attId = registry.attestProductSigned(
                pid, "2.0", "ML-KEM-768", true, "ipfs://QmE", i, sig
            );

            assertTrue(attId != bytes32(0), "distinct product must attest successfully");
            assertEq(
                attId,
                _expectedAttestationId(vendorSigner, pid, "2.0", "ML-KEM-768"),
                "attestation id mismatch"
            );
            assertEq(
                registry.getAttestationsByVendor(vendorSigner).length,
                i + 1,
                "vendor array must grow by exactly one per success"
            );
            assertEq(registry.getAttestationsByProduct(pid, "2.0", "ML-KEM-768").length, 1);
        }

        assertEq(registry.nonces(vendorSigner), n);
    }

    function test_AttestationsByVendor_MatchesSuccessfulAttestations() public {
        for (uint256 i = 0; i < 5; i++) {
            string memory pid = string.concat("Good-", vm.toString(i));
            bytes memory sig = _sign(
                vendorSigner, vendorSk, pid, "3.1", "SLH-DSA-128s", true, "ipfs://QmE", i
            );
            vm.prank(relayer);
            registry.attestProductSigned(pid, "3.1", "SLH-DSA-128s", true, "ipfs://QmE", i, sig);
        }
        assertEq(registry.getAttestationsByVendor(vendorSigner).length, 5);

        bytes memory dupSig = _sign(
            vendorSigner, vendorSk, "Good-0", "3.1", "SLH-DSA-128s", true, "ipfs://QmDup", 5
        );
        vm.prank(relayer);
        vm.expectRevert();
        registry.attestProductSigned(
            "Good-0", "3.1", "SLH-DSA-128s", true, "ipfs://QmDup", 5, dupSig
        );

        assertEq(
            registry.getAttestationsByVendor(vendorSigner).length,
            5,
            "failed duplicate must not extend the vendor lookup array"
        );
    }
}
