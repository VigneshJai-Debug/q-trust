// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AssetRegistry} from "../../src/AssetRegistry.sol";
import {AuditRegistry} from "../../src/AuditRegistry.sol";
import {ComplianceAttestation} from "../../src/ComplianceAttestation.sol";
import {EvidenceRegistry} from "../../src/EvidenceRegistry.sol";
import {MigrationRegistry} from "../../src/MigrationRegistry.sol";
import {PolicyCommitment} from "../../src/PolicyCommitment.sol";
import {RevocationAnchor} from "../../src/RevocationAnchor.sol";
import {SchemaRegistry} from "../../src/SchemaRegistry.sol";
import {TrustAnchorRegistry} from "../../src/TrustAnchorRegistry.sol";
import {VendorRegistry} from "../../src/VendorRegistry.sol";

/// @notice Shared helpers: deploy each registry behind an ERC1967Proxy exactly
///         like Deploy.s.sol does. Required since implementations disable
///         their initializers at construction (audit C-2).
library ProxyDeploy {
    function asset() internal returns (AssetRegistry) {
        AssetRegistry impl = new AssetRegistry();
        return AssetRegistry(address(new ERC1967Proxy(address(impl), abi.encodeCall(AssetRegistry.initialize, ()))));
    }

    function vendor() internal returns (VendorRegistry) {
        VendorRegistry impl = new VendorRegistry();
        return VendorRegistry(address(new ERC1967Proxy(address(impl), abi.encodeCall(VendorRegistry.initialize, ()))));
    }

    function migration(address assetRegistry) internal returns (MigrationRegistry) {
        MigrationRegistry impl = new MigrationRegistry();
        return MigrationRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(MigrationRegistry.initialize, (assetRegistry))))
        );
    }

    function audit(address migrationRegistry) internal returns (AuditRegistry) {
        AuditRegistry impl = new AuditRegistry();
        return AuditRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(AuditRegistry.initialize, (migrationRegistry))))
        );
    }

    function evidence() internal returns (EvidenceRegistry) {
        EvidenceRegistry impl = new EvidenceRegistry();
        return
            EvidenceRegistry(address(new ERC1967Proxy(address(impl), abi.encodeCall(EvidenceRegistry.initialize, ()))));
    }

    function compliance() internal returns (ComplianceAttestation) {
        ComplianceAttestation impl = new ComplianceAttestation();
        return ComplianceAttestation(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(ComplianceAttestation.initialize, ())))
        );
    }

    function revocation() internal returns (RevocationAnchor) {
        RevocationAnchor impl = new RevocationAnchor();
        return
            RevocationAnchor(address(new ERC1967Proxy(address(impl), abi.encodeCall(RevocationAnchor.initialize, ()))));
    }

    function policy() internal returns (PolicyCommitment) {
        PolicyCommitment impl = new PolicyCommitment();
        return
            PolicyCommitment(address(new ERC1967Proxy(address(impl), abi.encodeCall(PolicyCommitment.initialize, ()))));
    }

    function schema() internal returns (SchemaRegistry) {
        SchemaRegistry impl = new SchemaRegistry();
        return SchemaRegistry(address(new ERC1967Proxy(address(impl), abi.encodeCall(SchemaRegistry.initialize, ()))));
    }

    function trustAnchor() internal returns (TrustAnchorRegistry) {
        TrustAnchorRegistry impl = new TrustAnchorRegistry();
        return TrustAnchorRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(TrustAnchorRegistry.initialize, ())))
        );
    }
}
