// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {AssetRegistry} from "./AssetRegistry.sol";
import {VendorRegistry} from "./VendorRegistry.sol";
import {MigrationRegistry} from "./MigrationRegistry.sol";
import {AuditRegistry} from "./AuditRegistry.sol";

/**
 * @title IPausable
 * @notice Minimal interface for pausable contracts used by governance.
 */
interface IPausable {
    function pause() external;
    function unpause() external;
}

/**
 * @title QTrustGovernance
 * @notice Time-locked admin operations for the Q-Trust registries.
 *
 * All administrative state changes that affect trust guarantees (retiring a
 * CBOM, deactivating a vendor, changing roles, pausing, upgrading) are routed
 * through an OpenZeppelin TimelockController so that no single key can mutate
 * the registry without a public notice period.
 */
contract QTrustGovernance is AccessControl {
    /// @notice Role required to schedule governance operations. Execution of an
    ///         already-scheduled operation remains permissionless by design
    ///         (censorship-resistant, matching TimelockController's open
    ///         executor pattern).
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");

    TimelockController public immutable timelock;
    AssetRegistry public immutable assetRegistry;
    VendorRegistry public immutable vendorRegistry;
    MigrationRegistry public immutable migrationRegistry;
    AuditRegistry public immutable auditRegistry;

    uint256 public constant DEFAULT_DELAY = 7 days;

    /// @dev DEFAULT_ADMIN_ROLE in AccessControl-based registries is bytes32(0).
    bytes32 private constant _DEFAULT_ADMIN_ROLE = bytes32(0);

    /// @notice Reverted when a scheduled call would grant, revoke, or renounce
    ///         the DEFAULT_ADMIN_ROLE, allowing governance to escalate itself.
    error ForbiddenGovernanceCall();

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
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PROPOSER_ROLE, msg.sender);
    }

    /** @notice Schedule deactivation of a vendor (public notice, then executed). */
    function scheduleDeactivateVendor(address vendor, bytes32 salt) external onlyRole(PROPOSER_ROLE) {
        bytes memory data = abi.encodeCall(VendorRegistry.deactivateVendor, (vendor));
        _schedule(address(vendorRegistry), data, salt);
    }

    /** @notice Schedule retirement of a CBOM asset. */
    function scheduleRetireAsset(bytes32 assetId, bytes32 salt) external onlyRole(PROPOSER_ROLE) {
        bytes memory data = abi.encodeCall(AssetRegistry.retireAsset, (assetId));
        _schedule(address(assetRegistry), data, salt);
    }

    /** @notice Schedule a role grant on any registry. */
    function scheduleGrantRole(
        uint256 registryIndex,
        bytes32 role,
        address account,
        bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {
        // Prevent governance from escalating itself to full admin.
        if (role == _DEFAULT_ADMIN_ROLE) revert ForbiddenGovernanceCall();
        // Operational roles must be granted to the timelock (or an explicitly
        // provisioned operator) — never to an arbitrary account proposed by a
        // compromised or malicious proposer.
        if (!_isTimelockOrProposed(account)) revert ForbiddenGovernanceCall();
        address target = _getRegistry(registryIndex);
        bytes memory data = abi.encodeCall(IAccessControl.grantRole, (role, account));
        _schedule(target, data, salt);
    }

    /** @notice Schedule pausing a registry. */
    function schedulePause(uint256 registryIndex, bytes32 salt) external onlyRole(PROPOSER_ROLE) {
        address target = _getRegistry(registryIndex);
        bytes memory data = abi.encodeCall(IPausable.pause, ());
        _schedule(target, data, salt);
    }

    /** @notice Schedule unpausing a registry. */
    function scheduleUnpause(uint256 registryIndex, bytes32 salt) external onlyRole(PROPOSER_ROLE) {
        address target = _getRegistry(registryIndex);
        bytes memory data = abi.encodeCall(IPausable.unpause, ());
        _schedule(target, data, salt);
    }

    /** @notice Schedule an arbitrary call through the timelock. */
    function schedule(address target, bytes calldata data, bytes32 salt) external onlyRole(PROPOSER_ROLE) {
        _schedule(target, data, salt);
    }

    function _schedule(address target, bytes memory data, bytes32 salt) internal {
        // Prevent governance from escalating itself to full admin.
        if (_isAdminRoleCall(data)) revert ForbiddenGovernanceCall();
        timelock.schedule(target, 0, data, bytes32(0), salt, DEFAULT_DELAY);
        emit GovernanceCallScheduled(target, data, DEFAULT_DELAY, salt);
    }

    /// @dev True when calldata targets grantRole/revokeRole/renounceRole with
    ///      the DEFAULT_ADMIN_ROLE (bytes32(0)) as the role argument.
    function _isAdminRoleCall(bytes memory data) internal pure returns (bool) {
        if (data.length < 4 + 64) return false; // selector + role + account
        bytes4 selector = bytes4(data);
        bool isRoleCall = selector == IAccessControl.grantRole.selector ||
            selector == IAccessControl.revokeRole.selector ||
            selector == IAccessControl.renounceRole.selector;
        if (!isRoleCall) return false;
        bytes32 role;
        assembly {
            role := mload(add(data, 36))
        }
        return role == _DEFAULT_ADMIN_ROLE;
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

    /// @dev Operational roles may only land on the timelock itself or on an
    ///      account the proposer has been explicitly authorized to provision.
    ///      The timelock is always allowed (it is the governance executor);
    ///      any other account must already hold PROPOSER_ROLE.
    function _isTimelockOrProposed(address account) internal view returns (bool) {
        return account == address(timelock) || hasRole(PROPOSER_ROLE, account);
    }
}
