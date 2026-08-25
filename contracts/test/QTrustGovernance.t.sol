// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {ProxyDeploy} from "./helpers/ProxyDeploy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {AssetRegistry} from "../src/AssetRegistry.sol";
import {VendorRegistry} from "../src/VendorRegistry.sol";
import {MigrationRegistry} from "../src/MigrationRegistry.sol";
import {AuditRegistry} from "../src/AuditRegistry.sol";
import {QTrustGovernance} from "../src/QTrustGovernance.sol";

contract QTrustGovernanceTest is Test {
    AssetRegistry assets;
    VendorRegistry vendors;
    MigrationRegistry migrations;
    AuditRegistry audits;
    TimelockController timelock;
    QTrustGovernance governance;

    address deployer = address(0xA11CE0);
    address admin = address(0xAD1E1);
    address vendor = address(0xB0B0);

    function setUp() public {
        vm.startPrank(deployer);
        assets = ProxyDeploy.asset();
        vendors = ProxyDeploy.vendor();
        migrations = ProxyDeploy.migration(address(assets));
        audits = ProxyDeploy.audit(address(migrations));

        address[] memory proposers = new address[](1);
        proposers[0] = admin;
        address[] memory executors = new address[](1);
        executors[0] = admin;
        timelock = new TimelockController(2 days, proposers, executors, admin);

        bytes32 adminRole = 0x00;
        assets.grantRole(adminRole, address(timelock));
        vendors.grantRole(adminRole, address(timelock));
        migrations.grantRole(adminRole, address(timelock));
        audits.grantRole(adminRole, address(timelock));

        governance = new QTrustGovernance(
            address(timelock),
            address(assets),
            address(vendors),
            address(migrations),
            address(audits)
        );
        vm.stopPrank();

        // The governance wrapper is the proposer and executor for the timelock.
        bytes32 proposerRole = timelock.PROPOSER_ROLE();
        bytes32 executorRole = timelock.EXECUTOR_ROLE();
        vm.prank(admin);
        timelock.grantRole(proposerRole, address(governance));
        vm.prank(admin);
        timelock.grantRole(executorRole, address(governance));

        vm.startPrank(deployer);
        assets.renounceRole(adminRole, deployer);
        vendors.renounceRole(adminRole, deployer);
        migrations.renounceRole(adminRole, deployer);
        audits.renounceRole(adminRole, deployer);
        vm.stopPrank();
    }

    function test_DeployerCannotDirectlyDeactivateVendor() public {
        vm.startPrank(deployer);
        vendors.registerVendor(vendor, "ACME", "ipfs://");
        vm.expectRevert();
        vendors.deactivateVendor(vendor);
        vm.stopPrank();
    }

    function test_ScheduleThenExecuteDeactivateVendor() public {
        vm.startPrank(deployer);
        vendors.registerVendor(vendor, "ACME", "ipfs://");
        assertTrue(vendors.isVendorActive(vendor));

        bytes32 salt = keccak256("deactivate-vendor-1");
        governance.scheduleDeactivateVendor(vendor, salt);
        vm.stopPrank();

        // Still active during the notice period.
        assertTrue(vendors.isVendorActive(vendor));

        // Advance past the 7-day delay and execute as the executor.
        vm.warp(block.timestamp + 8 days);
        vm.prank(admin);
        governance.execute(
            address(vendors),
            abi.encodeCall(VendorRegistry.deactivateVendor, (vendor)),
            salt
        );

        assertFalse(vendors.isVendorActive(vendor));
    }

    function test_AdminRoleHeldByTimelockNotDeployer() public view {
        assertEq(
            assets.hasRole(0x00, address(timelock)),
            true,
            "timelock must hold admin on AssetRegistry"
        );
        assertEq(
            assets.hasRole(0x00, deployer),
            false,
            "deployer must not hold admin after renounce"
        );
        assertEq(
            vendors.hasRole(0x00, address(timelock)),
            true,
            "timelock must hold admin on VendorRegistry"
        );
    }

    function test_DeployerKeepsOperationalRoles() public view {
        assertTrue(assets.hasRole(assets.REGISTRAR_ROLE(), deployer));
        assertTrue(vendors.hasRole(vendors.VENDOR_ADMIN_ROLE(), deployer));
        assertTrue(migrations.hasRole(migrations.MIGRATOR_ROLE(), deployer));
        assertTrue(migrations.hasRole(migrations.AUDITOR_ROLE(), deployer));
    }

    function test_ScheduleRetireAssetViaGovernance() public {
        bytes32 cbomHash = keccak256("cbom-1");
        vm.startPrank(deployer);
        bytes32 assetId = assets.registerCBOM(cbomHash, "ipfs://cbom-1");
        bytes32 salt = keccak256("retire-1");
        governance.scheduleRetireAsset(assetId, salt);
        vm.stopPrank();

        assertTrue(assets.getAsset(assetId).active, "asset still active during delay");

        vm.warp(block.timestamp + 8 days);
        vm.prank(admin);
        governance.execute(
            address(assets),
            abi.encodeCall(AssetRegistry.retireAsset, (assetId)),
            salt
        );
        assertFalse(assets.getAsset(assetId).active, "asset retired after delay");
    }

    function test_ScheduleGrantRoleThroughTimelock() public {
        bytes32 registrarRole = assets.REGISTRAR_ROLE();
        bytes32 salt = keccak256("grant-registrar");
        vm.startPrank(deployer);
        // Operational roles may only be granted to the timelock itself (or an
        // account already holding PROPOSER_ROLE) — never an arbitrary EOA.
        governance.scheduleGrantRole(0, registrarRole, address(timelock), salt);
        vm.stopPrank();

        assertFalse(assets.hasRole(registrarRole, address(timelock)), "role not granted yet");

        vm.warp(block.timestamp + 8 days);
        vm.prank(admin);
        governance.execute(
            address(assets),
            abi.encodeCall(IAccessControl.grantRole, (registrarRole, address(timelock))),
            salt
        );
        assertTrue(assets.hasRole(registrarRole, address(timelock)), "role granted via timelock");
    }

    function test_ScheduleGrantRoleToArbitraryAccountReverts() public {
        bytes32 registrarRole = assets.REGISTRAR_ROLE();
        vm.prank(deployer);
        vm.expectRevert(QTrustGovernance.ForbiddenGovernanceCall.selector);
        governance.scheduleGrantRole(0, registrarRole, makeAddr("attacker"), keccak256("evil"));
    }

    function test_NonProposerCannotSchedule() public {
        vm.prank(makeAddr("random-caller"));
        vm.expectRevert();
        governance.scheduleDeactivateVendor(makeAddr("vendor"), keccak256("s"));
    }

    function test_ExecutionRemainsPermissionless() public {
        // Anyone — not only the proposer — may execute an already-scheduled,
        // delay-elapsed operation (censorship-resistant execution).
        bytes32 salt = keccak256("open-execute");
        vm.startPrank(deployer);
        vendors.registerVendor(vendor, "ACME", "ipfs://");
        governance.scheduleDeactivateVendor(vendor, salt);
        vm.stopPrank();
        vm.warp(block.timestamp + 8 days);
        vm.prank(makeAddr("anyone"));
        governance.execute(
            address(vendors),
            abi.encodeCall(VendorRegistry.deactivateVendor, (vendor)),
            salt
        );
        assertFalse(vendors.isVendorActive(vendor), "executed by third party");
    }
}