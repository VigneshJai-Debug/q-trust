// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import "../src/AssetRegistry.sol";
import "../src/VendorRegistry.sol";
import "../src/MigrationRegistry.sol";
import "../src/AuditRegistry.sol";
import "../src/ComplianceAttestation.sol";
import "../src/EvidenceRegistry.sol";
import "../src/QTrustGovernance.sol";
import "../src/RevocationAnchor.sol";
import "../src/PolicyCommitment.sol";
import "../src/SchemaRegistry.sol";
import "../src/TrustAnchorRegistry.sol";

contract Deploy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("QTRUST_DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);

        (AssetRegistry assets, VendorRegistry vendors, MigrationRegistry migrations, AuditRegistry audits) =
            _deployRegistries(deployer);

        // Deploy the compliance and evidence registries alongside the core
        // four so every registry is governed by the same timelock (audit M-6).
        ComplianceAttestation compliance = _deployCompliance(deployer);
        EvidenceRegistry evidence = _deployEvidence(deployer);

        TimelockController timelock = _deployTimelock(deployer);

        _handAdminToTimelock(
            assets, vendors, migrations, audits, compliance, evidence, timelock, deployer
        );

        QTrustGovernance governance = new QTrustGovernance(
            address(timelock),
            address(assets),
            address(vendors),
            address(migrations),
            address(audits)
        );
        timelock.grantRole(timelock.PROPOSER_ROLE(), address(governance));
        timelock.grantRole(timelock.EXECUTOR_ROLE(), address(governance));

        console2.log("TimelockController deployed: ", address(timelock));
        console2.log("QTrustGovernance deployed:   ", address(governance));

        // Deploy new trust infrastructure contracts
        _deployTrustInfrastructure(deployer, timelock);

        vm.stopBroadcast();
    }

    function _deployRegistries(address deployer)
        internal
        returns (AssetRegistry, VendorRegistry, MigrationRegistry, AuditRegistry)
    {
        AssetRegistry assetsImpl = new AssetRegistry();
        VendorRegistry vendorsImpl = new VendorRegistry();
        MigrationRegistry migrationsImpl = new MigrationRegistry();
        AuditRegistry auditsImpl = new AuditRegistry();

        AssetRegistry assets = AssetRegistry(
            address(new ERC1967Proxy(
                address(assetsImpl),
                abi.encodeCall(AssetRegistry.initialize, ())
            ))
        );
        VendorRegistry vendors = VendorRegistry(
            address(new ERC1967Proxy(
                address(vendorsImpl),
                abi.encodeCall(VendorRegistry.initialize, ())
            ))
        );
        MigrationRegistry migrations = MigrationRegistry(
            address(new ERC1967Proxy(
                address(migrationsImpl),
                abi.encodeCall(MigrationRegistry.initialize, (address(assets)))
            ))
        );
        AuditRegistry audits = AuditRegistry(
            address(new ERC1967Proxy(
                address(auditsImpl),
                abi.encodeCall(AuditRegistry.initialize, (address(migrations)))
            ))
        );

        console2.log("AssetRegistry impl:     ", address(assetsImpl));
        console2.log("VendorRegistry impl:    ", address(vendorsImpl));
        console2.log("MigrationRegistry impl: ", address(migrationsImpl));
        console2.log("AuditRegistry impl:     ", address(auditsImpl));
        console2.log("AssetRegistry proxy:    ", address(assets));
        console2.log("VendorRegistry proxy:   ", address(vendors));
        console2.log("MigrationRegistry proxy:", address(migrations));
        console2.log("AuditRegistry proxy:    ", address(audits));

        return (assets, vendors, migrations, audits);
    }

    function _deployTrustInfrastructure(address deployer, TimelockController timelock) internal {
        // RevocationAnchor
        RevocationAnchor revocationImpl = new RevocationAnchor();
        RevocationAnchor revocation = RevocationAnchor(
            address(new ERC1967Proxy(
                address(revocationImpl),
                abi.encodeCall(RevocationAnchor.initialize, ())
            ))
        );
        bytes32 adminRole = 0x00;
        // Operational roles must not remain exclusively on the deployer:
        // transfer them to the timelock BEFORE renouncing admin.
        revocation.grantRole(revocation.ISSUER_ADMIN_ROLE(), address(timelock));
        console2.log("  RevocationAnchor.ISSUER_ADMIN_ROLE ->", address(timelock));
        revocation.grantRole(adminRole, address(timelock));
        revocation.renounceRole(adminRole, deployer);

        // PolicyCommitment
        PolicyCommitment policyImpl = new PolicyCommitment();
        PolicyCommitment policy = PolicyCommitment(
            address(new ERC1967Proxy(
                address(policyImpl),
                abi.encodeCall(PolicyCommitment.initialize, ())
            ))
        );
        policy.grantRole(policy.POLICY_AUTHORITY_ROLE(), address(timelock));
        console2.log("  PolicyCommitment.POLICY_AUTHORITY_ROLE ->", address(timelock));
        policy.grantRole(adminRole, address(timelock));
        policy.renounceRole(adminRole, deployer);

        // SchemaRegistry
        SchemaRegistry schemaImpl = new SchemaRegistry();
        SchemaRegistry schema = SchemaRegistry(
            address(new ERC1967Proxy(
                address(schemaImpl),
                abi.encodeCall(SchemaRegistry.initialize, ())
            ))
        );
        schema.grantRole(schema.SCHEMA_AUTHORITY_ROLE(), address(timelock));
        console2.log("  SchemaRegistry.SCHEMA_AUTHORITY_ROLE ->", address(timelock));
        schema.grantRole(adminRole, address(timelock));
        schema.renounceRole(adminRole, deployer);

        // TrustAnchorRegistry
        TrustAnchorRegistry trustAnchorImpl = new TrustAnchorRegistry();
        TrustAnchorRegistry trustAnchor = TrustAnchorRegistry(
            address(new ERC1967Proxy(
                address(trustAnchorImpl),
                abi.encodeCall(TrustAnchorRegistry.initialize, ())
            ))
        );
        trustAnchor.grantRole(trustAnchor.GOVERNANCE_ROLE(), address(timelock));
        console2.log("  TrustAnchorRegistry.GOVERNANCE_ROLE ->", address(timelock));
        trustAnchor.grantRole(adminRole, address(timelock));
        trustAnchor.renounceRole(adminRole, deployer);

        console2.log("RevocationAnchor impl:      ", address(revocationImpl));
        console2.log("RevocationAnchor proxy:     ", address(revocation));
        console2.log("PolicyCommitment impl:      ", address(policyImpl));
        console2.log("PolicyCommitment proxy:     ", address(policy));
        console2.log("SchemaRegistry impl:        ", address(schemaImpl));
        console2.log("SchemaRegistry proxy:       ", address(schema));
        console2.log("TrustAnchorRegistry impl:   ", address(trustAnchorImpl));
        console2.log("TrustAnchorRegistry proxy:  ", address(trustAnchor));
    }

    function _deployCompliance(address deployer) internal returns (ComplianceAttestation) {
        ComplianceAttestation impl = new ComplianceAttestation();
        ComplianceAttestation compliance = ComplianceAttestation(
            address(new ERC1967Proxy(
                address(impl),
                abi.encodeCall(ComplianceAttestation.initialize, ())
            ))
        );
        console2.log("ComplianceAttestation impl: ", address(impl));
        console2.log("ComplianceAttestation proxy:", address(compliance));
        return compliance;
    }

    function _deployEvidence(address deployer) internal returns (EvidenceRegistry) {
        EvidenceRegistry impl = new EvidenceRegistry();
        EvidenceRegistry evidence = EvidenceRegistry(
            address(new ERC1967Proxy(
                address(impl),
                abi.encodeCall(EvidenceRegistry.initialize, ())
            ))
        );
        console2.log("EvidenceRegistry impl:      ", address(impl));
        console2.log("EvidenceRegistry proxy:     ", address(evidence));
        return evidence;
    }

    function _deployTimelock(address deployer) internal returns (TimelockController) {
        address[] memory proposers = new address[](1);
        proposers[0] = deployer;
        address[] memory executors = new address[](1);
        executors[0] = deployer;
        return new TimelockController(7 days, proposers, executors, deployer);
    }

    function _handAdminToTimelock(
        AssetRegistry assets,
        VendorRegistry vendors,
        MigrationRegistry migrations,
        AuditRegistry audits,
        ComplianceAttestation compliance,
        EvidenceRegistry evidence,
        TimelockController timelock,
        address deployer
    ) internal {
        bytes32 adminRole = 0x00;

        // Transfer operational roles to the timelock BEFORE renouncing admin,
        // otherwise they would be stranded on the deployer with no way to
        // ever be reassigned once admin control moves to governance.
        assets.grantRole(assets.REGISTRAR_ROLE(), address(timelock));
        vendors.grantRole(vendors.VENDOR_ADMIN_ROLE(), address(timelock));
        migrations.grantRole(migrations.MIGRATOR_ROLE(), address(timelock));
        migrations.grantRole(migrations.AUDITOR_ROLE(), address(timelock));
        audits.grantRole(audits.AUDITOR_ROLE(), address(timelock));
        compliance.grantRole(compliance.ATTESTER_ROLE(), address(timelock));
        evidence.grantRole(evidence.REGISTRAR_ROLE(), address(timelock));

        console2.log("Operational roles transferred to timelock:");
        console2.log("  AssetRegistry.REGISTRAR_ROLE           ->", address(timelock));
        console2.log("  VendorRegistry.VENDOR_ADMIN_ROLE       ->", address(timelock));
        console2.log("  MigrationRegistry.MIGRATOR_ROLE        ->", address(timelock));
        console2.log("  MigrationRegistry.AUDITOR_ROLE         ->", address(timelock));
        console2.log("  AuditRegistry.AUDITOR_ROLE             ->", address(timelock));
        console2.log("  ComplianceAttestation.ATTESTER_ROLE    ->", address(timelock));
        console2.log("  EvidenceRegistry.REGISTRAR_ROLE        ->", address(timelock));

        assets.grantRole(adminRole, address(timelock));
        vendors.grantRole(adminRole, address(timelock));
        migrations.grantRole(adminRole, address(timelock));
        audits.grantRole(adminRole, address(timelock));
        compliance.grantRole(adminRole, address(timelock));
        evidence.grantRole(adminRole, address(timelock));

        // Renounce ALL deployer roles (admin AND operational): retaining the
        // operational roles would let the deployer bypass the timelock for
        // every registration, migration, attestation, and evidence record.
        _renounceDeployerRoles(assets, deployer, [assets.REGISTRAR_ROLE(), bytes32(0)]);
        _renounceDeployerRoles(vendors, deployer, [vendors.VENDOR_ADMIN_ROLE(), bytes32(0)]);
        _renounceDeployerRoles(
            migrations,
            deployer,
            [
                migrations.MIGRATOR_ROLE(),
                migrations.AUDITOR_ROLE()
            ]
        );
        _renounceDeployerRoles(audits, deployer, [bytes32(0), bytes32(0)]);
        _renounceDeployerRoles(compliance, deployer, [compliance.ATTESTER_ROLE(), bytes32(0)]);
        _renounceDeployerRoles(evidence, deployer, [evidence.REGISTRAR_ROLE(), bytes32(0)]);

        console2.log("DEFAULT_ADMIN_ROLE granted to timelock; all deployer roles renounced:");
        console2.log("  AssetRegistry     ", address(assets));
        console2.log("  VendorRegistry    ", address(vendors));
        console2.log("  MigrationRegistry ", address(migrations));
        console2.log("  AuditRegistry     ", address(audits));
        console2.log("  ComplianceAttestation", address(compliance));
        console2.log("  EvidenceRegistry     ", address(evidence));
    }

    /// @dev Renounce DEFAULT_ADMIN_ROLE plus each supplied operational role
    ///      when the deployer still holds it.
    function _renounceDeployerRoles(
        IAccessControl accessControl,
        address account,
        bytes32[2] memory extraRoles
    ) internal {
        bytes32 adminRole = 0x00;
        if (accessControl.hasRole(adminRole, account)) {
            accessControl.renounceRole(adminRole, account);
        }
        for (uint256 i = 0; i < extraRoles.length; i++) {
            if (extraRoles[i] == bytes32(0)) continue;
            if (accessControl.hasRole(extraRoles[i], account)) {
                accessControl.renounceRole(extraRoles[i], account);
            }
        }
    }
}
