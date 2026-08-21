// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import "../src/AssetRegistry.sol";
import "../src/VendorRegistry.sol";
import "../src/MigrationRegistry.sol";
import "../src/AuditRegistry.sol";
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

        TimelockController timelock = _deployTimelock(deployer);
        _handAdminToTimelock(assets, vendors, migrations, audits, timelock);

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
            address(new TransparentUpgradeableProxy(
                address(assetsImpl), deployer,
                abi.encodeCall(AssetRegistry.initialize, ())
            ))
        );
        VendorRegistry vendors = VendorRegistry(
            address(new TransparentUpgradeableProxy(
                address(vendorsImpl), deployer,
                abi.encodeCall(VendorRegistry.initialize, ())
            ))
        );
        MigrationRegistry migrations = MigrationRegistry(
            address(new TransparentUpgradeableProxy(
                address(migrationsImpl), deployer,
                abi.encodeCall(MigrationRegistry.initialize, (address(assets)))
            ))
        );
        AuditRegistry audits = AuditRegistry(
            address(new TransparentUpgradeableProxy(
                address(auditsImpl), deployer,
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
            address(new TransparentUpgradeableProxy(
                address(revocationImpl), deployer,
                abi.encodeCall(RevocationAnchor.initialize, ())
            ))
        );
        bytes32 adminRole = 0x00;
        revocation.grantRole(adminRole, address(timelock));
        revocation.renounceRole(adminRole, deployer);

        // PolicyCommitment
        PolicyCommitment policyImpl = new PolicyCommitment();
        PolicyCommitment policy = PolicyCommitment(
            address(new TransparentUpgradeableProxy(
                address(policyImpl), deployer,
                abi.encodeCall(PolicyCommitment.initialize, ())
            ))
        );
        policy.grantRole(adminRole, address(timelock));
        policy.renounceRole(adminRole, deployer);

        // SchemaRegistry
        SchemaRegistry schemaImpl = new SchemaRegistry();
        SchemaRegistry schema = SchemaRegistry(
            address(new TransparentUpgradeableProxy(
                address(schemaImpl), deployer,
                abi.encodeCall(SchemaRegistry.initialize, ())
            ))
        );
        schema.grantRole(adminRole, address(timelock));
        schema.renounceRole(adminRole, deployer);

        // TrustAnchorRegistry
        TrustAnchorRegistry trustAnchorImpl = new TrustAnchorRegistry();
        TrustAnchorRegistry trustAnchor = TrustAnchorRegistry(
            address(new TransparentUpgradeableProxy(
                address(trustAnchorImpl), deployer,
                abi.encodeCall(TrustAnchorRegistry.initialize, ())
            ))
        );
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

    function _deployTimelock(address deployer) internal returns (TimelockController) {
        address[] memory proposers = new address[](1);
        proposers[0] = deployer;
        address[] memory executors = new address[](1);
        executors[0] = deployer;
        return new TimelockController(2 days, proposers, executors, deployer);
    }

    function _handAdminToTimelock(
        AssetRegistry assets,
        VendorRegistry vendors,
        MigrationRegistry migrations,
        AuditRegistry audits,
        TimelockController timelock
    ) internal {
        bytes32 adminRole = 0x00;
        assets.grantRole(adminRole, address(timelock));
        vendors.grantRole(adminRole, address(timelock));
        migrations.grantRole(adminRole, address(timelock));
        audits.grantRole(adminRole, address(timelock));

        assets.renounceRole(adminRole, msg.sender);
        vendors.renounceRole(adminRole, msg.sender);
        migrations.renounceRole(adminRole, msg.sender);
        audits.renounceRole(adminRole, msg.sender);
    }
}
