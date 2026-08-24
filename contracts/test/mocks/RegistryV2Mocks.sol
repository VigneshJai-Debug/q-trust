// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../../src/AssetRegistry.sol";
import "../../src/VendorRegistry.sol";

/// @title AssetRegistryV2Mock — UUPS upgrade target adding new storage
/// @notice Appends a storage slot and accessors on top of the V1 layout to
///         prove upgrades preserve prior state and extend functionality.
contract AssetRegistryV2Mock is AssetRegistry {

    uint256 public v2Value;

    function setV2Value(uint256 newValue) external {
        v2Value = newValue;
    }

    function version() external pure returns (string memory) {
        return "AssetRegistry v2";
    }
}

/// @title VendorRegistryV2Mock — UUPS upgrade target adding new storage
contract VendorRegistryV2Mock is VendorRegistry {

    uint256 public v2Value;

    function setV2Value(uint256 newValue) external {
        v2Value = newValue;
    }

    function version() external pure returns (string memory) {
        return "VendorRegistry v2";
    }
}
