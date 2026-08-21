// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/PolicyCommitment.sol";

contract PolicyCommitmentTest is Test {
    PolicyCommitment public policy;

    address admin = address(0xA001);
    address authority = address(0xB001);

    function setUp() public {
        policy = new PolicyCommitment();
        policy.initialize();
    }

    // ======== Commit Policy ========

    function test_CommitPolicy() public {
        bytes32 hash = keccak256("policy-text-v1");
        policy.commitPolicy("ncua_part_748_pqc", 1, hash, "ipfs://QmPolicyV1");

        PolicyCommitment.PolicyVersion memory pv = policy.getPolicyVersion("ncua_part_748_pqc", 1);
        assertEq(pv.policyHash, hash);
        assertEq(pv.version, 1);
        assertTrue(pv.active);
        assertEq(pv.committedBy, address(this));
    }

    function test_CommitPolicy_MultipleVersions() public {
        bytes32 hash1 = keccak256("policy-v1");
        bytes32 hash2 = keccak256("policy-v2");

        policy.commitPolicy("ncua_part_748_pqc", 1, hash1, "ipfs://QmV1");
        policy.commitPolicy("ncua_part_748_pqc", 2, hash2, "ipfs://QmV2");

        PolicyCommitment.PolicyInfo memory info = policy.getPolicyInfo("ncua_part_748_pqc");
        assertEq(info.latestVersion, 2);
        assertEq(info.totalVersions, 2);

        assertEq(policy.getPolicyVersion("ncua_part_748_pqc", 1).policyHash, hash1);
        assertEq(policy.getPolicyVersion("ncua_part_748_pqc", 2).policyHash, hash2);
    }

    function test_CommitPolicy_DifferentPolicies() public {
        policy.commitPolicy("ncua_part_748_pqc", 1, keccak256("ncua-v1"), "ipfs://ncua");
        policy.commitPolicy("nis2_article_21", 1, keccak256("nis2-v1"), "ipfs://nis2");

        assertEq(policy.policyCount(), 2);

        string[] memory ids = policy.getAllPolicyIds();
        assertEq(ids[0], "ncua_part_748_pqc");
        assertEq(ids[1], "nis2_article_21");
    }

    // ======== Revert Cases ========

    function test_CommitPolicy_Revert_EmptyHash() public {
        vm.expectRevert(abi.encodeWithSelector(PolicyCommitment.EmptyPolicyHash.selector));
        policy.commitPolicy("test", 1, bytes32(0), "ipfs://test");
    }

    function test_CommitPolicy_Revert_DuplicateVersion() public {
        policy.commitPolicy("test", 1, keccak256("v1"), "ipfs://v1");
        vm.expectRevert(abi.encodeWithSelector(PolicyCommitment.PolicyAlreadyExists.selector, "test", 1));
        policy.commitPolicy("test", 1, keccak256("v1-again"), "ipfs://v1-again");
    }

    function test_CommitPolicy_Revert_VersionNotIncremented() public {
        policy.commitPolicy("test", 2, keccak256("v2"), "ipfs://v2");
        vm.expectRevert(abi.encodeWithSelector(PolicyCommitment.PolicyAlreadyExists.selector, "test", 1));
        policy.commitPolicy("test", 1, keccak256("v1"), "ipfs://v1");
    }

    // ======== Deactivation ========

    function test_DeactivatePolicy() public {
        policy.commitPolicy("test", 1, keccak256("v1"), "ipfs://v1");
        policy.deactivatePolicy("test", 1);

        PolicyCommitment.PolicyVersion memory pv = policy.getPolicyVersion("test", 1);
        assertFalse(pv.active);
    }

    // ======== Verify ========

    function test_VerifyPolicy_True() public {
        bytes32 hash = keccak256("policy-text");
        policy.commitPolicy("test", 1, hash, "ipfs://test");
        assertTrue(policy.verifyPolicy("test", 1, hash));
    }

    function test_VerifyPolicy_False_WrongHash() public {
        bytes32 hash = keccak256("policy-text");
        policy.commitPolicy("test", 1, hash, "ipfs://test");
        assertFalse(policy.verifyPolicy("test", 1, keccak256("wrong-hash")));
    }

    function test_VerifyPolicy_False_Deactivated() public {
        bytes32 hash = keccak256("policy-text");
        policy.commitPolicy("test", 1, hash, "ipfs://test");
        policy.deactivatePolicy("test", 1);
        assertFalse(policy.verifyPolicy("test", 1, hash));
    }

    function test_VerifyPolicy_False_Nonexistent() public {
        assertFalse(policy.verifyPolicy("nonexistent", 1, keccak256("hash")));
    }

    // ======== View Functions ========

    function test_GetVersionsByPolicyId() public {
        policy.commitPolicy("test", 1, keccak256("v1"), "ipfs://v1");
        policy.commitPolicy("test", 2, keccak256("v2"), "ipfs://v2");
        policy.commitPolicy("test", 3, keccak256("v3"), "ipfs://v3");

        uint256[] memory versions = policy.getVersionsByPolicyId("test");
        assertEq(versions.length, 3);
        assertEq(versions[0], 1);
        assertEq(versions[1], 2);
        assertEq(versions[2], 3);
    }

    function test_PolicyCount() public {
        assertEq(policy.policyCount(), 0);
        policy.commitPolicy("a", 1, keccak256("a"), "ipfs://a");
        assertEq(policy.policyCount(), 1);
        policy.commitPolicy("b", 1, keccak256("b"), "ipfs://b");
        assertEq(policy.policyCount(), 2);
    }

    // ======== Pausable ========

    function test_Pause_Unpause() public {
        policy.pause();
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        policy.commitPolicy("test", 1, keccak256("v1"), "ipfs://v1");

        policy.unpause();
        policy.commitPolicy("test", 1, keccak256("v1"), "ipfs://v1");
        assertTrue(true);
    }
}
