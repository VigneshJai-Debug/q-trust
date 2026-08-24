# Multi-Chain Deployment Runbook (Arbitrum + Optimism Sepolia)

Q-Trust contracts are plain UUPS with no chain-specific assumptions
(chain-id-defensive EIP-712 domain separators per ADR-0002), so the same
`Deploy.s.sol` runs on any EVM network.

## Prerequisites

- Deployer key funded on the target testnet:
  - Arbitrum Sepolia: https://faucets.chain.link/arbitrum-sepolia or https://www.alchemy.com/faucets/arbitrum-sepolia
  - Optimism Sepolia: https://faucets.chain.link/optimism-sepolia
- Explorer API keys for verification:
  - Arbiscan: https://api.arbiscan.io (key env `ARBISCAN_API_KEY`)
  - Blockscout/Optimistic Etherscan: https://optimistic.etherscan.io (key env `OP_ETHERSCAN_API_KEY`)

## Arbitrum Sepolia (chain-id 421614)

```bash
cd contracts
forge script script/Deploy.s.sol \
  --rpc-url https://sepolia-rollup.arbitrum.io/rpc \
  --private-key $QTRUST_DEPLOYER_PRIVATE_KEY \
  --broadcast --verify \
  --etherscan-api-key $ARBISCAN_API_KEY \
  --chain-id 421614
```

## Optimism Sepolia (chain-id 11155420)

```bash
cd contracts
forge script script/Deploy.s.sol \
  --rpc-url https://sepolia.optimism.io \
  --private-key $QTRUST_DEPLOYER_PRIVATE_KEY \
  --broadcast --verify \
  --etherscan-api-key $OP_ETHERSCAN_API_KEY \
  --chain-id 11155420
```

## Post-deploy checklist

1. Copy proxy addresses from script output.
2. Add them to GitHub repo variables (`DEPLOYED_PROXY_ADDRESSES`) so the
   `contract-verify` CI job can re-verify on merges.
3. Update backend `.env` (`QTRUST_*_REGISTRY_ADDRESS`) and frontend env
   (`NEXT_PUBLIC_*_ADDRESS`) per chain.
4. Register a smoke CBOM through the SDK and verify via `/v1/assets/:id`.
5. Record the deployment in this file:

| Chain | Chain ID | AssetRegistry | Status |
|---|---|---|---|
| Base Sepolia | 84532 | _pending faucet funding_ | documented, not deployed |
| Arbitrum Sepolia | 421614 | — | not deployed |
| Optimism Sepolia | 11155420 | — | not deployed |

> Deployment requires a funded deployer key; addresses are intentionally not
> fabricated here. The local anvil deployment used in tests/perf docs uses
> chain-id 84532 to mirror Base Sepolia exactly.
