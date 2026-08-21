// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/SchemaRegistry.sol";

contract SchemaRegistryTest is Test {
    SchemaRegistry public registry;

    address admin = address(0xA001);

    function setUp() public {
        registry = new SchemaRegistry();
        registry.initialize();
    }

    // ======== Register Schema ========

    function test_RegisterSchema() public {
        bytes32 hash = keccak256("json-schema-v1");
        registry.registerSchema(
            "https://qtrust.dev/schemas/pqc-readiness/v1",
            1,
            hash,
            "ipfs://QmSchemaV1",
            "pqc-readiness"
        );

        SchemaRegistry.SchemaInfo memory s = registry.getSchema(
            "https://qtrust.dev/schemas/pqc-readiness/v1", 1
        );
        assertEq(s.schemaHash, hash);
        assertEq(s.schemaType, "pqc-readiness");
        assertTrue(s.active);
    }

    function test_RegisterSchema_MultipleVersions() public {
        string memory id = "https://qtrust.dev/schemas/pqc-readiness/v1";
        registry.registerSchema(id, 1, keccak256("v1"), "ipfs://v1", "pqc-readiness");
        registry.registerSchema(id, 2, keccak256("v2"), "ipfs://v2", "pqc-readiness");

        SchemaRegistry.SchemaEntry memory entry = registry.getSchemaEntry(id);
        assertEq(entry.latestVersion, 2);
        assertEq(entry.totalVersions, 2);
    }

    function test_RegisterSchema_DifferentSchemas() public {
        registry.registerSchema("schema-a", 1, keccak256("a"), "ipfs://a", "type-a");
        registry.registerSchema("schema-b", 1, keccak256("b"), "ipfs://b", "type-b");

        assertEq(registry.schemaCount(), 2);
        string[] memory ids = registry.getAllSchemaIds();
        assertEq(ids[0], "schema-a");
        assertEq(ids[1], "schema-b");
    }

    // ======== Revert Cases ========

    function test_RegisterSchema_Revert_EmptyHash() public {
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.EmptySchemaHash.selector));
        registry.registerSchema("test", 1, bytes32(0), "ipfs://test", "test");
    }

    function test_RegisterSchema_Revert_Duplicate() public {
        registry.registerSchema("test", 1, keccak256("v1"), "ipfs://v1", "test");
        vm.expectRevert(abi.encodeWithSelector(SchemaRegistry.SchemaAlreadyExists.selector, "test"));
        registry.registerSchema("test", 1, keccak256("v1-again"), "ipfs://v1-again", "test");
    }

    // ======== Equivalence ========

    function test_AddEquivalence() public {
        registry.registerSchema("schema-a", 1, keccak256("a"), "ipfs://a", "pqc");
        registry.registerSchema("schema-b", 1, keccak256("b"), "ipfs://b", "pqc");

        registry.addEquivalence("schema-a", "schema-b", "equivalent");

        SchemaRegistry.EquivalenceMapping[] memory eqs = registry.getEquivalences("schema-a");
        assertEq(eqs.length, 1);
        assertEq(eqs[0].toSchemaId, "schema-b");
        assertEq(eqs[0].equivalenceType, "equivalent");
    }

    // ======== Deactivation ========

    function test_DeactivateSchema() public {
        registry.registerSchema("test", 1, keccak256("v1"), "ipfs://v1", "test");
        registry.deactivateSchema("test", 1);

        SchemaRegistry.SchemaInfo memory s = registry.getSchema("test", 1);
        assertFalse(s.active);
    }

    // ======== Verify ========

    function test_VerifySchema_True() public {
        bytes32 hash = keccak256("schema-content");
        registry.registerSchema("test", 1, hash, "ipfs://test", "test");
        assertTrue(registry.verifySchema("test", 1, hash));
    }

    function test_VerifySchema_False_WrongHash() public {
        registry.registerSchema("test", 1, keccak256("schema-content"), "ipfs://test", "test");
        assertFalse(registry.verifySchema("test", 1, keccak256("wrong")));
    }

    function test_VerifySchema_False_Deactivated() public {
        bytes32 hash = keccak256("schema-content");
        registry.registerSchema("test", 1, hash, "ipfs://test", "test");
        registry.deactivateSchema("test", 1);
        assertFalse(registry.verifySchema("test", 1, hash));
    }

    // ======== View Functions ========

    function test_GetVersionsBySchemaId() public {
        string memory id = "test";
        registry.registerSchema(id, 1, keccak256("v1"), "ipfs://v1", "t");
        registry.registerSchema(id, 2, keccak256("v2"), "ipfs://v2", "t");

        uint256[] memory versions = registry.getVersionsBySchemaId(id);
        assertEq(versions.length, 2);
        assertEq(versions[0], 1);
        assertEq(versions[1], 2);
    }

    function test_SchemaCount() public {
        assertEq(registry.schemaCount(), 0);
        registry.registerSchema("a", 1, keccak256("a"), "ipfs://a", "a");
        assertEq(registry.schemaCount(), 1);
    }

    // ======== Pausable ========

    function test_Pause_Unpause() public {
        registry.pause();
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        registry.registerSchema("test", 1, keccak256("v1"), "ipfs://v1", "test");

        registry.unpause();
        registry.registerSchema("test", 1, keccak256("v1"), "ipfs://v1", "test");
        assertTrue(true);
    }
}
