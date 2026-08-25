// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {AssetRegistry} from "../src/AssetRegistry.sol";
import {AuditRegistry} from "../src/AuditRegistry.sol";
import {ComplianceAttestation} from "../src/ComplianceAttestation.sol";
import {EvidenceRegistry} from "../src/EvidenceRegistry.sol";
import {MigrationRegistry} from "../src/MigrationRegistry.sol";
import {PolicyCommitment} from "../src/PolicyCommitment.sol";
import {RevocationAnchor} from "../src/RevocationAnchor.sol";
import {SchemaRegistry} from "../src/SchemaRegistry.sol";
import {TrustAnchorRegistry} from "../src/TrustAnchorRegistry.sol";
import {VendorRegistry} from "../src/VendorRegistry.sol";

/**
 * @notice Audit C-2 regression: raw UUPS implementation contracts must have
 *         their initializers disabled at construction so an attacker can never
 *         initialize (and take over) the unproxied logic contract.
 */
contract ImplementationInitializersDisabledTest is Test {
    function test_AllImplementationInitializersAreDisabled() public {
        AssetRegistry a = new AssetRegistry();
        AuditRegistry au = new AuditRegistry();
        ComplianceAttestation c = new ComplianceAttestation();
        EvidenceRegistry e = new EvidenceRegistry();
        MigrationRegistry m = new MigrationRegistry();
        PolicyCommitment pc = new PolicyCommitment();
        RevocationAnchor ra = new RevocationAnchor();
        SchemaRegistry sr = new SchemaRegistry();
        TrustAnchorRegistry ta = new TrustAnchorRegistry();
        VendorRegistry v = new VendorRegistry();

        vm.expectRevert(); a.initialize();
        vm.expectRevert(); au.initialize(address(m));
        vm.expectRevert(); c.initialize();
        vm.expectRevert(); e.initialize();
        vm.expectRevert(); m.initialize(address(a));
        vm.expectRevert(); pc.initialize();
        vm.expectRevert(); ra.initialize();
        vm.expectRevert(); sr.initialize();
        vm.expectRevert(); ta.initialize();
        vm.expectRevert(); v.initialize();
    }
}
