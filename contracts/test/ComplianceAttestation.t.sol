// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/ComplianceAttestation.sol";
import "../src/lib/StringBounds.sol";

/// @title ComplianceAttestationTest — coverage for TD8/L1 remediation paths
contract ComplianceAttestationTest is Test {
    ComplianceAttestation public registry;

    address attester = address(0xA77E);

    function setUp() public {
        registry = new ComplianceAttestation();
        registry.initialize();
        registry.grantRole(registry.ATTESTER_ROLE(), attester);
    }

    function _attest(string memory framework) internal returns (bytes32 attestationId) {
        vm.prank(attester);
        attestationId = registry.attestCompliance(framework, 80, 10, 8, 2, keccak256("evd"), 30);
    }

    function test_AttestCompliance() public {
        bytes32 id = _attest("CNSA_2_0");
        ComplianceAttestation.Attestation memory att = registry.getAttestation(id);
        assertEq(att.framework, "CNSA_2_0");
        assertEq(att.score, 80);
        assertFalse(att.revoked);
        assertTrue(registry.isComplianceValid(id));
    }

    function test_RevertWhen_FrameworkTooLong() public {
        string memory longFramework = string(new bytes(65));
        vm.prank(attester);
        vm.expectRevert(
            abi.encodeWithSelector(StringBounds.StringTooLong.selector, 65, 64)
        );
        registry.attestCompliance(longFramework, 80, 10, 8, 2, keccak256("evd"), 30);
    }

    function test_RevertWhen_RevokeReasonTooLong() public {
        bytes32 id = _attest("NIST_SP_800_131A");
        string memory longReason = string(new bytes(257));
        vm.prank(attester);
        vm.expectRevert(
            abi.encodeWithSelector(StringBounds.StringTooLong.selector, 257, 256)
        );
        registry.revokeAttestation(id, longReason);
    }

    function _signCompliance(
        uint256 sk,
        string memory framework,
        bytes32 evidenceHash,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "AttestCompliance(string framework,uint256 score,uint256 totalRules,"
                    "uint256 compliantCount,uint256 nonCompliantCount,bytes32 evidenceHash,"
                    "uint256 validityDays,uint256 nonce)"
                ),
                keccak256(bytes(framework)),
                uint256(90),
                uint256(10),
                uint256(9),
                uint256(1),
                evidenceHash,
                uint256(30),
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_DomainSeparator_ChainFork_SignedStillVerifies() public {
        uint256 orgSk = 0x0A6C4;
        address orgSigner = vm.addr(orgSk);
        bytes32 sepBefore = registry.domainSeparator();

        // Simulate a chain fork: the separator must re-derive for chain 999.
        vm.chainId(999);
        assertFalse(registry.domainSeparator() == sepBefore, "separator must re-derive on new chainid");

        bytes memory sig = _signCompliance(orgSk, "CNSA_2_0", keccak256("fork-evd"), 0);

        vm.prank(address(0xAE1A73));
        bytes32 id = registry.attestComplianceSigned(
            "CNSA_2_0", 90, 10, 9, 1, keccak256("fork-evd"), 30, 0, sig
        );

        assertTrue(id != bytes32(0), "signed attestation must verify on the forked chain");
        assertEq(registry.getAttestation(id).orgDid, orgSigner);
    }
}
