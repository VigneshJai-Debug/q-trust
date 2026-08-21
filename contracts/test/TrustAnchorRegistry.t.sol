// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/TrustAnchorRegistry.sol";

contract TrustAnchorRegistryTest is Test {
    TrustAnchorRegistry public registry;

    address admin = address(0xA001);
    address issuer1 = address(0xB001);
    address issuer2 = address(0xC001);
    address nonIssuer = address(0xDEADBEEF);

    function setUp() public {
        registry = new TrustAnchorRegistry();
        registry.initialize();
    }

    // ======== Accreditation ========

    function test_AccreditIssuer() public {
        registry.accreditIssuer(issuer1, "did:web:trailofbits.com", "pqc-readiness", 365 days);

        TrustAnchorRegistry.IssuerAccreditation memory acc = registry.getAccreditation(issuer1);
        assertEq(acc.issuerDid, "did:web:trailofbits.com");
        assertEq(acc.scope, "pqc-readiness");
        assertTrue(acc.active);
        assertEq(acc.accreditedBy, address(this));
    }

    function test_IsIssuerAccredited() public {
        registry.accreditIssuer(issuer1, "did:web:trailofbits.com", "pqc-readiness", 365 days);
        assertTrue(registry.isIssuerAccredited(issuer1));
    }

    function test_IsIssuerAccredited_False_NonExistent() public {
        assertFalse(registry.isIssuerAccredited(nonIssuer));
    }

    function test_AccreditedIssuerCount() public {
        assertEq(registry.accreditedIssuerCount(), 0);
        registry.accreditIssuer(issuer1, "did:web:a.com", "scope", 365 days);
        assertEq(registry.accreditedIssuerCount(), 1);
        registry.accreditIssuer(issuer2, "did:web:b.com", "scope", 365 days);
        assertEq(registry.accreditedIssuerCount(), 2);
    }

    function test_GetAllAccreditedIssuers() public {
        registry.accreditIssuer(issuer1, "did:web:a.com", "scope", 365 days);
        registry.accreditIssuer(issuer2, "did:web:b.com", "scope", 365 days);

        address[] memory issuers = registry.getAllAccreditedIssuers();
        assertEq(issuers.length, 2);
        assertEq(issuers[0], issuer1);
        assertEq(issuers[1], issuer2);
    }

    // ======== Revocation ========

    function test_RevokeAccreditation() public {
        registry.accreditIssuer(issuer1, "did:web:trailofbits.com", "pqc-readiness", 365 days);
        registry.revokeAccreditation(issuer1, "ethics_violation");

        assertFalse(registry.isIssuerAccredited(issuer1));

        TrustAnchorRegistry.IssuerAccreditation memory acc = registry.getAccreditation(issuer1);
        assertFalse(acc.active);
        assertEq(acc.revocationReason, "ethics_violation");
    }

    function test_RevokeAccreditation_Revert_NotAccredited() public {
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.IssuerNotAccredited.selector, nonIssuer));
        registry.revokeAccreditation(nonIssuer, "reason");
    }

    // ======== Re-accreditation ========

    function test_ReaccreditIssuer() public {
        registry.accreditIssuer(issuer1, "did:web:trailofbits.com", "pqc-readiness", 365 days);
        uint256 validUntilBefore = registry.getAccreditation(issuer1).validUntil;

        registry.reaccreditIssuer(issuer1, 365 days);

        TrustAnchorRegistry.IssuerAccreditation memory acc = registry.getAccreditation(issuer1);
        assertEq(acc.validUntil, validUntilBefore + 365 days);
        assertTrue(acc.active);
    }

    // ======== Verify Accreditation ========

    function test_VerifyAccreditation_True() public {
        registry.accreditIssuer(issuer1, "did:web:trailofbits.com", "pqc-readiness", 365 days);

        (bool accredited, string memory issuerDid, uint256 validUntil) =
            registry.verifyAccreditation(issuer1, "pqc-readiness");

        assertTrue(accredited);
        assertEq(issuerDid, "did:web:trailofbits.com");
        assertTrue(validUntil > block.timestamp);
    }

    function test_VerifyAccreditation_False_WrongScope() public {
        registry.accreditIssuer(issuer1, "did:web:trailofbits.com", "pqc-readiness", 365 days);

        (bool accredited, , ) = registry.verifyAccreditation(issuer1, "sbom");
        assertFalse(accredited);
    }

    function test_VerifyAccreditation_False_Revoked() public {
        registry.accreditIssuer(issuer1, "did:web:trailofbits.com", "pqc-readiness", 365 days);
        registry.revokeAccreditation(issuer1, "revoked");

        (bool accredited, , ) = registry.verifyAccreditation(issuer1, "pqc-readiness");
        assertFalse(accredited);
    }

    // ======== Revert Cases ========

    function test_AccreditIssuer_Revert_AlreadyAccredited() public {
        registry.accreditIssuer(issuer1, "did:web:a.com", "scope", 365 days);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.IssuerAlreadyAccredited.selector, issuer1));
        registry.accreditIssuer(issuer1, "did:web:b.com", "scope", 365 days);
    }

    function test_AccreditIssuer_Revert_EmptyDid() public {
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.EmptyIssuerDid.selector));
        registry.accreditIssuer(issuer1, "", "scope", 365 days);
    }

    function test_GetAccreditation_Revert_NotFound() public {
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.IssuerNotAccredited.selector, nonIssuer));
        registry.getAccreditation(nonIssuer);
    }

    // ======== Pausable ========

    function test_Pause_Unpause() public {
        registry.pause();
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        registry.accreditIssuer(issuer1, "did:web:a.com", "scope", 365 days);

        registry.unpause();
        registry.accreditIssuer(issuer1, "did:web:a.com", "scope", 365 days);
        assertTrue(true);
    }
}
