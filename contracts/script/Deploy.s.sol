// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Script.sol";
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

        AssetRegistry assets = new AssetRegistry();
        VendorRegistry vendors = new VendorRegistry();
        MigrationRegistry migrations = new MigrationRegistry(address(assets));
        AuditRegistry audits = new AuditRegistry(address(migrations));

        // Governance: every trust-affecting admin action goes through a
        // TimelockController with a 2-day notice period.
        address[] memory proposers = new address[](1);
        proposers[0] = deployer;
        address[] memory executors = new address[](1);
        executors[0] = deployer;
        TimelockController timelock = new TimelockController(2 days, proposers, executors, deployer);

        // Pre-grant operational roles before handing admin to timelock.
        // These are needed for local E2E / pilot on a fresh anvil chain.
        // The deployer retains MIGRATOR/AUDITOR operational roles; admin is timelock.
        audits.grantRole(audits.AUDITOR_ROLE(), deployer);
        // Also grant to the known test auditor key (used in sdk/tests/e2e_anvil.py)
        // to allow a separate auditor account without a timelock delay in tests.
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

        console2.log("AssetRegistry deployed at:     ", address(assets));
        console2.log("VendorRegistry deployed at:   ", address(vendors));
        console2.log("MigrationRegistry deployed at:", address(migrations));
        console2.log("AuditRegistry deployed at:    ", address(audits));
        console2.log("TimelockController deployed:  ", address(timelock));
        console2.log("QTrustGovernance deployed:    ", address(governance));

        vm.stopBroadcast();
    }
}