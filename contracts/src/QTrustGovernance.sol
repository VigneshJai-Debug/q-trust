// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {AssetRegistry} from "./AssetRegistry.sol";
import {VendorRegistry} from "./VendorRegistry.sol";
import {MigrationRegistry} from "./MigrationRegistry.sol";
import {AuditRegistry} from "./AuditRegistry.sol";

/**
 * @title QTrustGovernance
 * @notice Time-locked admin operations for the Q-Trust registries.
 *
 * All administrative state changes that affect trust guarantees (retiring a
 * CBOM, deactivating a vendor, changing roles, pausing, upgrading) are routed
 * through an OpenZeppelin TimelockController so that no single key can mutate
 * the registry without a public notice period.
 */
contract QTrustGovernance {
    TimelockController public immutable timelock;
    AssetRegistry public immutable assetRegistry;
    VendorRegistry public immutable vendorRegistry;
    MigrationRegistry public immutable migrationRegistry;
    AuditRegistry public immutable auditRegistry;

    uint256 public constant DEFAULT_DELAY = 2 days;

    event GovernanceCallScheduled(
        address indexed target,
        bytes data,
        uint256 delay,
        bytes32 salt
    );

    constructor(
        address timelock_,
        address assetRegistry_,
        address vendorRegistry_,
        address migrationRegistry_,
        address auditRegistry_
    ) {
        timelock = TimelockController(payable(timelock_));
        assetRegistry = AssetRegistry(assetRegistry_);
        vendorRegistry = VendorRegistry(vendorRegistry_);
        migrationRegistry = MigrationRegistry(migrationRegistry_);
        auditRegistry = AuditRegistry(auditRegistry_);
    }

    /** @notice Schedule deactivation of a vendor (public notice, then executed). */
    function scheduleDeactivateVendor(address vendor, bytes32 salt) external {
        bytes memory data = abi.encodeCall(VendorRegistry.deactivateVendor, (vendor));
        _schedule(address(vendorRegistry), data, salt);
    }

    /** @notice Schedule retirement of a CBOM asset. */
    function scheduleRetireAsset(bytes32 assetId, bytes32 salt) external {
        bytes memory data = abi.encodeCall(AssetRegistry.retireAsset, (assetId));
        _schedule(address(assetRegistry), data, salt);
    }

    /** @notice Schedule a role grant on any registry. */
    function scheduleGrantRole(
        uint256 registryIndex,
        bytes32 role,
        address account,
        bytes32 salt
    ) external {
        address target = _getRegistry(registryIndex);
        bytes memory data = abi.encodeCall(IAccessControl.grantRole, (role, account));
        _schedule(target, data, salt);
    }

    /** @notice Schedule pausing a registry. */
    function schedulePause(uint256 registryIndex, bytes32 salt) external {
        address target = _getRegistry(registryIndex);
        bytes memory data = abi.encodeCall(AssetRegistry.pause, ());
        _schedule(target, data, salt);
    }

    /** @notice Schedule unpausing a registry. */
    function scheduleUnpause(uint256 registryIndex, bytes32 salt) external {
        address target = _getRegistry(registryIndex);
        bytes memory data = abi.encodeCall(AssetRegistry.unpause, ());
        _schedule(target, data, salt);
    }

    /** @notice Schedule an arbitrary call through the timelock. */
    function schedule(address target, bytes calldata data, bytes32 salt) external {
        _schedule(target, data, salt);
    }

    function _schedule(address target, bytes memory data, bytes32 salt) internal {
        timelock.schedule(target, 0, data, bytes32(0), salt, DEFAULT_DELAY);
        emit GovernanceCallScheduled(target, data, DEFAULT_DELAY, salt);
    }

    /** @notice Execute a previously scheduled call (after its delay elapses). */
    function execute(address target, bytes calldata data, bytes32 salt) external {
        timelock.execute(target, 0, data, bytes32(0), salt);
    }

    function _getRegistry(uint256 registryIndex) internal view returns (address) {
        if (registryIndex == 0) return address(assetRegistry);
        else if (registryIndex == 1) return address(vendorRegistry);
        else if (registryIndex == 2) return address(migrationRegistry);
        else if (registryIndex == 3) return address(auditRegistry);
        else revert("QTrustGovernance: invalid registry index");
    }
}
