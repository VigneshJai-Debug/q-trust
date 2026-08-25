// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {ProxyDeploy} from "./helpers/ProxyDeploy.sol";
import "../src/EvidenceRegistry.sol";
import "../src/lib/StringBounds.sol";

/// @title EvidenceRegistryTest — coverage for TD8/L1 remediation paths
contract EvidenceRegistryTest is Test {
    EvidenceRegistry public registry;

    address registrar = address(0xE0CE);

    function setUp() public {
        registry = ProxyDeploy.evidence();
        registry.grantRole(registry.REGISTRAR_ROLE(), registrar);
    }

    function test_RegisterEvidence() public {
        vm.prank(registrar);
        bytes32 id = registry.registerEvidence(keccak256("root"), 5, "host.example", 2, keccak256("risk"));

        assertTrue(registry.verifyEvidence(id, keccak256("root")));
        assertEq(registry.getEvidenceCount(), 1);
    }

    function test_RevertWhen_ScanTargetTooLong() public {
        string memory longTarget = string(new bytes(129));
        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(StringBounds.StringTooLong.selector, 129, 128)
        );
        registry.registerEvidence(keccak256("root"), 5, longTarget, 2, keccak256("risk"));
    }

    function test_RevertWhen_RevokeReasonTooLong() public {
        vm.startPrank(registrar);
        bytes32 id = registry.registerEvidence(keccak256("root"), 5, "t", 2, keccak256("risk"));
        string memory longReason = string(new bytes(257));
        vm.expectRevert(
            abi.encodeWithSelector(StringBounds.StringTooLong.selector, 257, 256)
        );
        registry.revokeEvidence(id, longReason);
        vm.stopPrank();
    }

    function test_DomainSeparator_ChainFork_SignedStillVerifies() public {
        uint256 ownerSk = 0x0A6C5;
        address ownerSigner = vm.addr(ownerSk);
        uint256 nonce = 0;
        bytes32 sepBefore = registry.domainSeparator();

        // Simulate a chain fork: the separator must re-derive for chain 999.
        vm.chainId(999);
        assertFalse(registry.domainSeparator() == sepBefore, "separator must re-derive on new chainid");

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "EvidenceRegistration(bytes32 evidenceRoot,uint256 entryCount,string scanTarget,"
                    "uint256 findingsCount,bytes32 riskSummaryHash,uint256 nonce)"
                ),
                keccak256("fork-root"),
                uint256(3),
                keccak256(bytes("fork-host")),
                uint256(1),
                keccak256("fork-risk"),
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerSk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(address(0xAE1A73));
        bytes32 id = registry.registerEvidenceSigned(
            keccak256("fork-root"), 3, "fork-host", 1, keccak256("fork-risk"), nonce, sig
        );

        assertTrue(id != bytes32(0), "signed registration must verify on the forked chain");
        assertEq(registry.getEvidence(id).owner, ownerSigner);
    }
}
