# Phase 1: Smart Contracts

## Objectives
- Initialize Foundry project
- Write 4 Solidity contracts
- Write tests
- Deploy to Base Sepolia

## Status
- [x] Contracts written — AssetRegistry, VendorRegistry, MigrationRegistry, AuditRegistry (contracts/src/)
- [x] Tests written + fixed — contracts/test/ (incl. added AuditRegistry.t.sol)
- [x] Deployment script updated + verified — script/Deploy.s.sol works on local anvil
- [~] Deployed to Base Sepolia — deployed & verified on local anvil (chain-id 84532); real Base Sepolia requires env secrets (none available)

## Verification
- `forge test`: 17/17 pass (12 original + 4 AuditRegistry + regression on revoke logic)
- `forge script script/Deploy.s.sol --broadcast`: ONCHAIN EXECUTION SUCCESSFUL

## Deployed addresses (local anvil, deterministic)
| Contract | Address |
|---|---|
| AssetRegistry | 0x5fbdb2315678afecb367f032d93f642f64180aa3 |
| VendorRegistry | 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 |
| MigrationRegistry | 0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0 |
| AuditRegistry | 0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9 |

## Role model
- Deployer holds DEFAULT_ADMIN_ROLE on all registries
- Auditor needs AUDITOR_ROLE granted by admin before postAudit
- Registrar/Vendor roles exist for extensibility