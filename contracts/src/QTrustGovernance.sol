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
 * CBOM, deactivating a vendor, changing roles) are routed through an
 * OpenZeppelin TimelockController so that no single key can mutate the
 * registry without a public notice period.
 *
 * The TimelockController holds DEFAULT_ADMIN_ROLE on every registry; this
 * contract is a thin proposer-side convenience wrapper that encodes the
 * calls. The executor (typically the same admin set) calls
 * `timelock.execute(...)` after the delay elapses.
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
        address target;
        if (registryIndex == 0) target = address(assetRegistry);
        else if (registryIndex == 1) target = address(vendorRegistry);
        else if (registryIndex == 2) target = address(migrationRegistry);
        else if (registryIndex == 3) target = address(auditRegistry);
        else revert("QTrustGovernance: invalid registry index");

        bytes memory data = abi.encodeCall(IAccessControl.grantRole, (role, account));
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
}