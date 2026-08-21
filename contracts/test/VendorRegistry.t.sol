// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/VendorRegistry.sol";

contract VendorRegistryTest is Test {
    VendorRegistry public registry;

    address admin = address(0xAD0FD);
    address vendor = address(0xB0B);
    address nonVendor = address(0xDEADBEEF);
    address relayer = address(0xAE1A73);

    uint256 vendorKey = 0xB0B; // dummy — replaced by prank-based signing below
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

    function setUp() public {
        registry = new VendorRegistry();
        registry.initialize();
    }

    function test_RegisterVendor() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigint");
        VendorRegistry.VendorInfo memory v = registry.getVendor(vendor);
        assertEq(v.name, "DigiCert", "name should match");
        assertTrue(registry.getVendor(vendor).registeredAt != 0, "vendor should be registered");
        assertTrue(registry.isVendorActive(vendor), "vendor should be active after registration");
    }

    function test_AttestProduct() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");

        vm.prank(vendor);
        registry.attestProduct(
            "DigiCert-TLS",
            "5.2.1",
            "ML-DSA-441",
            true,
            "ipfs://QmEvidence"
        );

        bytes32[] memory ids = registry.getAttestationsByProduct(
            "DigiCert-TLS",
            "5.2.1",
            "ML-DSA-441"
        );
        require(ids.length > 0, "No attestation found");
        bytes32 attestationId = ids[0];

        VendorRegistry.ProductAttestation memory att = registry.getAttestation(attestationId);
        assertEq(att.vendorDid, vendor, "vendorDid should match");

        assertTrue(att.supported, "should be supported");
        assertEq(att.algorithm, "ML-DSA-441", "algorithm should match");
    }

    function test_RevertWhen_NonVendorAttests() public {
        vm.prank(nonVendor);
        vm.expectRevert();
        registry.attestProduct(
            "DigiCert-TLS",
            "5.2.1",
            "ML-DSA-441",
            true,
            "ipfs://QmEvidence"
        );
    }

    function test_RevertWhen_InactiveVendorAttests() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");
        registry.deactivateVendor(vendor);

        vm.prank(vendor);
        vm.expectRevert(
            abi.encodeWithSelector(VendorRegistry.VendorInactive.selector, vendor)
        );
        registry.attestProduct(
            "DigiCert-TLS",
            "5.2.1",
            "ML-DSA-441",
            true,
            "ipfs://QmEvidence"
        );
    }

    function test_DeactivateVendor() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");
        assertTrue(registry.isVendorActive(vendor));

        registry.deactivateVendor(vendor);
        assertFalse(registry.isVendorActive(vendor), "vendor should be inactive after deactivation");
    }

    function test_DeactivateMissingVendor_Reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(VendorRegistry.VendorNotFound.selector, vendor)
        );
        registry.deactivateVendor(vendor);
    }

    function test_RevokeAttestation() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");
        vm.prank(vendor);
        registry.attestProduct("DigiCert-TLS", "5.2.1", "ML-DSA-441", true, "ipfs://QmEvidence");

        bytes32[] memory ids = registry.getAttestationsByProduct("DigiCert-TLS", "5.2.1", "ML-DSA-441");
        require(ids.length > 0, "No attestation found");
        bytes32 attestationId = ids[0];

        vm.prank(address(this));
        registry.revokeAttestation(attestationId);

        VendorRegistry.ProductAttestation memory att = registry.getAttestation(attestationId);
        assertTrue(att.revoked, "should be revoked");
    }

    function test_AttestationLimitEnforced() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");
        vm.startPrank(vendor);

        uint256 limit = registry.MAX_ATTESTATIONS_PER_PRODUCT();
        for (uint256 i = 0; i < limit; i++) {
            vm.warp(block.timestamp + 1);
            registry.attestProduct("Prod", "1.0", "ML-KEM-512", true, "ipfs://QmE");
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                VendorRegistry.AttestationLimitExceeded.selector,
                keccak256(abi.encodePacked("Prod", "1.0", "ML-KEM-512"))
            )
        );
        registry.attestProduct("Prod", "1.0", "ML-KEM-512", true, "ipfs://QmE");
        vm.stopPrank();
    }

    function test_CheckProductSupport_BoundedAfterLimit() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");
        vm.startPrank(vendor);
        uint256 limit = registry.MAX_ATTESTATIONS_PER_PRODUCT();
        for (uint256 i = 0; i < limit; i++) {
            vm.warp(block.timestamp + 1);
            registry.attestProduct("Prod", "1.0", "ML-KEM-512", false, "ipfs://QmE");
        }
        vm.stopPrank();

        (bool supported, address v, bytes32 attId) = registry.checkProductSupport("Prod", "1.0", "ML-KEM-512");
        assertFalse(supported, "all attestations unsupported");
        assertEq(v, address(0));
        assertEq(attId, bytes32(0));
    }

    function test_AttestProductSigned_RecordsSigner() public {
        uint256 vendorSk = 0xABCDEF01;
        address signer = vm.addr(vendorSk);
        registry.registerVendor(signer, "SignerCorp", "ipfs://QmS");

        bytes memory sig = _sign(
            signer, vendorSk, "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0
        );

        // A third-party relayer submits the signed attestation.
        vm.prank(relayer);
        bytes32 attId = registry.attestProductSigned(
            "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0, sig
        );

        VendorRegistry.ProductAttestation memory att = registry.getAttestation(attId);
        assertEq(att.vendorDid, signer, "signer must be recorded as the vendor");
        assertTrue(att.supported);
        assertEq(registry.nonces(signer), 1, "nonce must increment");
    }

    function test_RevertWhen_SignedReplay() public {
        uint256 vendorSk = 0xABCDEF01;
        address signer = vm.addr(vendorSk);
        registry.registerVendor(signer, "SignerCorp", "ipfs://QmS");

        bytes memory sig = _sign(
            signer, vendorSk, "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0
        );

        vm.prank(relayer);
        registry.attestProductSigned("Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0, sig);

        // Same signature + nonce must be rejected on replay.
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(VendorRegistry.InvalidNonce.selector, signer, 0, 1)
        );
        registry.attestProductSigned("Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0, sig);
    }

    function test_RevertWhen_TamperedSignature() public {
        uint256 vendorSk = 0xABCDEF01;
        address signer = vm.addr(vendorSk);
        registry.registerVendor(signer, "SignerCorp", "ipfs://QmS");

        bytes memory sig = _sign(
            signer, vendorSk, "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0
        );
        sig[0] ^= 0x01; // flip a bit — must break recovery

        vm.prank(relayer);
        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        registry.attestProductSigned("Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0, sig);
    }

    function test_RevertWhen_InactiveSigner() public {
        uint256 vendorSk = 0xABCDEF01;
        address signer = vm.addr(vendorSk);
        registry.registerVendor(signer, "SignerCorp", "ipfs://QmS");
        registry.deactivateVendor(signer);

        bytes memory sig = _sign(
            signer, vendorSk, "Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(VendorRegistry.VendorInactive.selector, signer)
        );
        registry.attestProductSigned("Prod-A", "2.0", "ML-KEM-768", true, "ipfs://QmE", 0, sig);
    }

    function test_DomainSeparator_MatchEIP712() public {
        // The separator must match a manually computed EIP-712 domain hash.
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("QTrustVendorRegistry"),
                keccak256("1"),
                block.chainid,
                address(registry)
            )
        );
        assertEq(registry.domainSeparator(), expected);
    }
}