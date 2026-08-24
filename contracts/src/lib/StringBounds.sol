// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title StringBounds — length validation for string inputs
/// @notice Shared gas-griefing guard: caps calldata string lengths at
///         well-defined bounds across all Q-Trust registries.
library StringBounds {

    error StringTooLong(uint256 length, uint256 max);

    uint256 internal constant URI_MAX = 512;
    uint256 internal constant DID_MAX = 128;
    uint256 internal constant ID_MAX = 64;
    uint256 internal constant REASON_MAX = 256;

    /// @dev Reverts when `s` exceeds `max` bytes.
    function checkLen(string calldata s, uint256 max) internal pure {
        if (bytes(s).length > max) revert StringTooLong(bytes(s).length, max);
    }

    /// @dev Reverts when `s` exceeds the metadata/evidence/report/policy URI cap.
    function checkURI(string calldata s) internal pure {
        checkLen(s, URI_MAX);
    }

    /// @dev Reverts when `s` exceeds the DID/identifier cap.
    function checkDID(string calldata s) internal pure {
        checkLen(s, DID_MAX);
    }

    /// @dev Reverts when `s` exceeds the short-identifier (productId, version,
    ///      algorithm, framework, scope...) cap.
    function checkID(string calldata s) internal pure {
        checkLen(s, ID_MAX);
    }
}
