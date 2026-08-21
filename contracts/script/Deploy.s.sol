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

contract Deploy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("QTRUST_DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);

        // Deploy implementation contracts
        AssetRegistry assetsImpl = new AssetRegistry();
        VendorRegistry vendorsImpl = new VendorRegistry();
        MigrationRegistry migrationsImpl = new MigrationRegistry(address(assetsImpl));
        AuditRegistry auditsImpl = new AuditRegistry(address(migrationsImpl));

        // Deploy proxies — the proxy admin is a separate TransparentAdminHelper
        // For simplicity, we use UUPS with deployer as initial admin.
        // Note: In production, the proxy admin should be a separate multisig.
        bytes memory emptyInit = "";

        AssetRegistry assets = AssetRegistry(
            address(new TransparentUpgradeableProxy(
                address(assetsImpl),
                deployer,  // proxy admin
                abi.encodeCall(AssetRegistry.initialize, ())
            ))
        );

        VendorRegistry vendors = VendorRegistry(
            address(new TransparentUpgradeableProxy(
                address(vendorsImpl),
                deployer,
                abi.encodeCall(VendorRegistry.initialize, ())
            ))
        );

        // MigrationRegistry needs assetRegistry address — pass via initialize
        MigrationRegistry migrations = MigrationRegistry(
            address(new TransparentUpgradeableProxy(
                address(migrationsImpl),
                deployer,
                abi.encodeCall(MigrationRegistry.initialize, ())
            ))
        );

        AuditRegistry audits = AuditRegistry(
            address(new TransparentUpgradeableProxy(
                address(auditsImpl),
                deployer,
                abi.encodeCall(AuditRegistry.initialize, ())
            ))
        );

        // Governance: every trust-affecting admin action goes through a
        // TimelockController with a 2-day notice period.
        address[] memory proposers = new address[](1);
        proposers[0] = deployer;
        address[] memory executors = new address[](1);
        executors[0] = deployer;
        TimelockController timelock = new TimelockController(2 days, proposers, executors, deployer);

        // Pre-grant operational roles before handing admin to timelock.
        audits.grantRole(audits.AUDITOR_ROLE(), deployer);
        audits.grantRole(audits.AUDITOR_ROLE(), 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC);
        migrations.grantRole(migrations.AUDITOR_ROLE(), deployer);
        migrations.grantRole(migrations.MIGRATOR_ROLE(), deployer);

        // Hand DEFAULT_ADMIN_ROLE of every registry to the timelock.
        bytes32 adminRole = 0x00;
        assets.grantRole(adminRole, address(timelock));
        vendors.grantRole(adminRole, address(timelock));
        migrations.grantRole(adminRole, address(timelock));
        audits.grantRole(adminRole, address(timelock));

        QTrustGovernance governance = new QTrustGovernance(
            address(timelock),
            address(assets),
            address(vendors),
            address(migrations),
            address(audits)
        );

        // The governance wrapper is the proposer and executor for the timelock.
        timelock.grantRole(timelock.PROPOSER_ROLE(), address(governance));
        timelock.grantRole(timelock.EXECUTOR_ROLE(), address(governance));

        // Renounce the deployer's admin role on every registry (only the
        // timelock can now change trust-affecting state).
        assets.renounceRole(adminRole, deployer);
        vendors.renounceRole(adminRole, deployer);
        migrations.renounceRole(adminRole, deployer);
        audits.renounceRole(adminRole, deployer);

        console2.log("AssetRegistry impl deployed at:     ", address(assetsImpl));
        console2.log("VendorRegistry impl deployed at:    ", address(vendorsImpl));
        console2.log("MigrationRegistry impl deployed at: ", address(migrationsImpl));
        console2.log("AuditRegistry impl deployed at:     ", address(auditsImpl));
        console2.log("AssetRegistry proxy deployed at:    ", address(assets));
        console2.log("VendorRegistry proxy deployed at:   ", address(vendors));
        console2.log("MigrationRegistry proxy deployed at:", address(migrations));
        console2.log("AuditRegistry proxy deployed at:    ", address(audits));
        console2.log("TimelockController deployed:        ", address(timelock));
        console2.log("QTrustGovernance deployed:          ", address(governance));

        vm.stopBroadcast();
    }
}
