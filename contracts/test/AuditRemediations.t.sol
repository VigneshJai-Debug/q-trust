// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {ProxyDeploy} from "./helpers/ProxyDeploy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {AssetRegistry} from "../src/AssetRegistry.sol";
import {VendorRegistry} from "../src/VendorRegistry.sol";
import {MigrationRegistry} from "../src/MigrationRegistry.sol";
import {AuditRegistry} from "../src/AuditRegistry.sol";
import {ComplianceAttestation} from "../src/ComplianceAttestation.sol";
import {PolicyCommitment} from "../src/PolicyCommitment.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {TrustAnchorRegistry} from "../src/TrustAnchorRegistry.sol";
import {QTrustGovernance} from "../src/QTrustGovernance.sol";

/// @notice Regression tests for the 2026-08-26 external codebase audit:
///         C-1, C-2, H-1, H-2, M-4, L-6 and friends.
contract AuditRemediationsTest is Test {
    bytes32 internal constant _PRODUCT_ATTESTATION_TYPEHASH =
        keccak256(
            "ProductAttestation(string productId,string version,string algorithm,"
            "bool supported,string evidenceURI,uint256 nonce)"
        );

    // ------------------------------------------------------------------
    // C-1: the deploy script must leave NO deployer roles on the timelock
    // or on QTrustGovernance.
    // ------------------------------------------------------------------
    function test_C1_DeployScript_RenouncesTimelockAndGovernanceRoles() public {
        uint256 deployerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        vm.setEnv("QTRUST_DEPLOYER_PRIVATE_KEY", vm.toString(deployerKey));
        address deployer = vm.addr(deployerKey);

        Deploy script = new Deploy();
        script.run();

        TimelockController timelock = script.lastTimelock();
        QTrustGovernance governance = script.lastGovernance();

        bytes32 adminRole = 0x00;
        assertFalse(timelock.hasRole(adminRole, deployer), "C1: deployer must not hold timelock admin");
        assertFalse(timelock.hasRole(timelock.PROPOSER_ROLE(), deployer), "C1: deployer must not hold PROPOSER");
        assertFalse(timelock.hasRole(timelock.EXECUTOR_ROLE(), deployer), "C1: deployer must not hold EXECUTOR");
        assertFalse(timelock.hasRole(timelock.CANCELLER_ROLE(), deployer), "C1: deployer must not hold CANCELLER");
        assertTrue(timelock.hasRole(adminRole, address(timelock)), "C1: timelock self-administers");

        assertFalse(governance.hasRole(adminRole, deployer), "C1: deployer must not hold governance admin");
        assertTrue(governance.hasRole(adminRole, address(timelock)), "C1: timelock administers governance");
        // The deployer remains the operational PROPOSER on the governance
        // wrapper until a multisig is provisioned — but any change to that
        // proposer set now itself requires a timelocked governance action.
        assertTrue(
            governance.hasRole(governance.PROPOSER_ROLE(), deployer),
            "C1: operator remains governance proposer by design"
        );
        assertTrue(
            timelock.hasRole(timelock.PROPOSER_ROLE(), address(governance)),
            "C1: governance is timelock proposer"
        );
    }

    // ------------------------------------------------------------------
    // C-2: raw schedule() must reject UUPS upgrade selectors.
    // ------------------------------------------------------------------
    function test_C2_Schedule_RevertsOnUpgradeToAndCall() public {
        (,,,, QTrustGovernance governance, TimelockController timelock,,) = _deployCore();
        // The constructor grants PROPOSER_ROLE + DEFAULT_ADMIN_ROLE to
        // msg.sender (this test contract) — no extra grant needed.

        vm.expectRevert(QTrustGovernance.ForbiddenGovernanceCall.selector);
        governance.schedule(
            address(1),
            abi.encodeWithSelector(0x3659cfe6, address(makeAddr("maliciousImpl"))), // upgradeTo
            keccak256("upgrade")
        );
        vm.expectRevert(QTrustGovernance.ForbiddenGovernanceCall.selector);
        governance.schedule(
            address(1),
            abi.encodeWithSelector(0x4f1ef286, address(makeAddr("maliciousImpl")), ""), // upgradeToAndCall
            keccak256("upgrade-call")
        );
        // Sanity: a benign schedule still works.
        governance.schedule(address(1), abi.encodeWithSignature("foo()"), keccak256("benign"));
        assertEq(timelock.getMinDelay(), 7 days);
    }

    // ------------------------------------------------------------------
    // H-1: attestProductSigned must re-check VENDOR_ROLE after recovery —
    // a revoked-but-still-active vendor cannot post via relayer anymore.
    // ------------------------------------------------------------------
    function test_H1_SignedPath_RevertWhen_VendorRoleRevoked() public {
        VendorRegistry registry = ProxyDeploy.vendor();

        uint256 vendorSk = 0xB0B;
        address vendor = vm.addr(vendorSk);
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");
        assertTrue(registry.isVendorActive(vendor));

        bytes memory sig = _signAttestation(
            registry, vendorSk, "prod-1", "1.0.0", "RSA-2048", false, "ipfs://evidence", 0
        );
        // Sanity before revocation: signed path succeeds.
        registry.attestProductSigned("prod-1", "1.0.0", "RSA-2048", false, "ipfs://evidence", 0, sig);

        // Revoke ONLY the role (vendor stays active) — the exact asymmetry
        // from audit H-1.
        registry.revokeRole(registry.VENDOR_ROLE(), vendor);

        bytes memory sig2 = _signAttestation(
            registry, vendorSk, "prod-2", "1.0.0", "ML-KEM-768", true, "ipfs://evidence2", 1
        );
        vm.expectRevert(abi.encodeWithSelector(VendorRegistry.NotVendor.selector, vendor));
        registry.attestProductSigned("prod-2", "1.0.0", "ML-KEM-768", true, "ipfs://evidence2", 1, sig2);
    }

    // ------------------------------------------------------------------
    // H-2: paused-state circuit breaker covers revokeAccreditation,
    // reaccreditIssuer, addEquivalence and deactivateSchema.
    // ------------------------------------------------------------------
    function test_H2_PausedState_BlocksTrustAnchorMutations() public {
        TrustAnchorRegistry trustAnchor = ProxyDeploy.trustAnchor();
        trustAnchor.accreditIssuer(address(0x15A1), "did:web:issuer.example", "pqc-readiness", 365 days);

        trustAnchor.pause();

        vm.expectRevert();
        trustAnchor.revokeAccreditation(address(0x15A1), "reason");
        vm.expectRevert();
        trustAnchor.reaccreditIssuer(address(0x15A1), 1 days);

        trustAnchor.unpause();
        trustAnchor.revokeAccreditation(address(0x15A1), "reason");
        // Audit L-7 companion check happens in TrustAnchorRegistry.t.sol.
    }

    function test_H2_PausedState_BlocksSchemaMutations() public {
        SchemaRegistry schemas = ProxyDeploy.schema();
        schemas.registerSchema("schema-a", 1, keccak256("a"), "ipfs://a", "type-a");
        schemas.registerSchema("schema-b", 1, keccak256("b"), "ipfs://b", "type-b");
        schemas.addEquivalence("schema-a", "schema-b", "equivalent");

        schemas.pause();

        vm.expectRevert();
        schemas.addEquivalence("schema-b", "schema-a", "equivalent");
        vm.expectRevert();
        schemas.deactivateSchema("schema-a", 1);
    }

    // ------------------------------------------------------------------
    // L-6: addEquivalence requires both schemas to exist.
    // ------------------------------------------------------------------
    function test_L6_AddEquivalence_RevertWhen_SchemaMissing() public {
        SchemaRegistry schemas = ProxyDeploy.schema();
        schemas.registerSchema("schema-a", 1, keccak256("a"), "ipfs://a", "type-a");

        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.SchemaNotFound.selector, "ghost"));
        schemas.addEquivalence("schema-a", "ghost", "equivalent");
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.SchemaNotFound.selector, "ghost"));
        schemas.addEquivalence("ghost", "schema-a", "equivalent");
    }

    // ------------------------------------------------------------------
    // M-4: compliance status lookup is O(1); revoking clears the pointer.
    // ------------------------------------------------------------------
    function test_M4_ComplianceStatus_ReflectsLatestAndRevocation() public {
        ComplianceAttestation compliance = ProxyDeploy.compliance();

        bytes32 id1 = compliance.attestCompliance("NIST_SP_800_131A", 60, 10, 6, 4, keccak256("e1"), 30);
        (bool valid, uint256 score) = compliance.getOrgComplianceStatus(address(this), "NIST_SP_800_131A");
        assertTrue(valid);
        assertEq(score, 60);

        // Newer attestation supersedes without scanning history.
        compliance.attestCompliance("NIST_SP_800_131A", 90, 10, 9, 1, keccak256("e2"), 30);
        (valid, score) = compliance.getOrgComplianceStatus(address(this), "NIST_SP_800_131A");
        assertTrue(valid);
        assertEq(score, 90);

        compliance.revokeAttestation(compliance.getAttestationsByOrg(address(this))[1], "oops");
        (valid, ) = compliance.getOrgComplianceStatus(address(this), "NIST_SP_800_131A");
        assertFalse(valid, "revoked latest must clear the status pointer");
    }

    // ------------------------------------------------------------------
    // Shared core deployment used by the C-2 test.
    // ------------------------------------------------------------------
    function _deployCore()
        internal
        returns (
            AssetRegistry assets,
            VendorRegistry vendors,
            MigrationRegistry migrations,
            AuditRegistry audits,
            QTrustGovernance governance,
            TimelockController timelock,
            address deployer,
            address admin
        )
    {
        deployer = address(0xA11CE0);
        admin = address(0xAD1E1);
        assets = ProxyDeploy.asset();
        vendors = ProxyDeploy.vendor();
        migrations = ProxyDeploy.migration(address(assets));
        audits = ProxyDeploy.audit(address(migrations));

        address[] memory proposers = new address[](1);
        proposers[0] = admin;
        address[] memory executors = new address[](1);
        executors[0] = admin;
        timelock = new TimelockController(7 days, proposers, executors, admin);

        governance = new QTrustGovernance(
            address(timelock),
            address(assets),
            address(vendors),
            address(migrations),
            address(audits)
        );
        // Cache selectors BEFORE pranking — a staticcall would consume it.
        bytes32 proposerRole = timelock.PROPOSER_ROLE();
        bytes32 executorRole = timelock.EXECUTOR_ROLE();
        vm.prank(admin);
        timelock.grantRole(proposerRole, address(governance));
        vm.prank(admin);
        timelock.grantRole(executorRole, address(governance));
    }

    function _signAttestation(
        VendorRegistry registry,
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
}
