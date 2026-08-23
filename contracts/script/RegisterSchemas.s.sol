// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Script.sol";

/// @notice Minimal EAS SchemaRegistry interface (see https://docs.eas.attest.so).
interface ISchemaRegistry {
    function register(
        string calldata schema,
        bool revocable,
        string calldata resolver
    ) external returns (bytes32);
}

/// @notice Registers Q-Trust PQC attestation schemas on the EAS SchemaRegistry.
/// @dev Pure registration — deploys nothing custom. Reads config from env:
///      QTRUST_DEPLOYER_PRIVATE_KEY (required), EAS_SCHEMA_REGISTRY (optional,
///      defaults to the canonical Base predeploy address).
contract RegisterSchemas is Script {
    // Canonical EAS SchemaRegistry predeploy on Base mainnet AND Base Sepolia.
    // Verify at https://docs.eas.attest.so before use.
    address constant BASE_SCHEMA_REGISTRY = 0x4200000000000000000000000000000000000020;

    string constant PQC_COMPLIANCE_SCHEMA =
        "bytes32 cbomHash,string framework,uint8 score,bool compliant,uint64 validUntil,string evidenceURI";
    string constant VENDOR_READINESS_SCHEMA =
        "address vendor,string productId,string[] algorithms,bool pqReady,uint64 attestedAt";
    string constant MIGRATION_MILESTONE_SCHEMA =
        "bytes32 evidenceRoot,uint8 phase,uint256 assetsTotal,uint256 assetsMigrated";

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("QTRUST_DEPLOYER_PRIVATE_KEY");
        address registry = vm.envOr("EAS_SCHEMA_REGISTRY", BASE_SCHEMA_REGISTRY);

        console2.log("Registering Q-Trust PQC schemas on EAS SchemaRegistry:", registry);

        ISchemaRegistry schemaRegistry = ISchemaRegistry(registry);

        vm.startBroadcast(deployerPrivateKey);

        bytes32 complianceUid =
            schemaRegistry.register(PQC_COMPLIANCE_SCHEMA, true, "");
        console2.log("PQC_COMPLIANCE_SCHEMA_UID:", vm.toString(complianceUid));

        bytes32 readinessUid =
            schemaRegistry.register(VENDOR_READINESS_SCHEMA, false, "");
        console2.log("VENDOR_READINESS_SCHEMA_UID:", vm.toString(readinessUid));

        bytes32 milestoneUid =
            schemaRegistry.register(MIGRATION_MILESTONE_SCHEMA, true, "");
        console2.log("MIGRATION_MILESTONE_SCHEMA_UID:", vm.toString(milestoneUid));

        vm.stopBroadcast();
    }
}
