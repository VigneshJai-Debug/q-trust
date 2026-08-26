# Guide — Deploy to Base Sepolia

End-to-end from local chain to testnet in under 10 minutes.

## 1 — Deploy contracts

```bash
cp .env.example .env   # set QTRUST_BASE_SEPOLIA_RPC, QTRUST_DEPLOYER_PRIVATE_KEY
cd contracts
forge script script/Deploy.s.sol --rpc-url $QTRUST_BASE_SEPOLIA_RPC --broadcast
# Fill the 11 QTRUST_*_ADDRESS vars in .env from the deploy log
```

Verify on Basescan:

```bash
forge verify-contract --chain-id 84532 --verifier etherscan \
  --verifier-url https://api-sepolia.basescan.org/api \
  <address> src/AssetRegistry.sol:AssetRegistry
```

See [deployment/BASE_SEPOLIA.md](../deployment/BASE_SEPOLIA.md) for the full checklist.

## 2 — Bring the stack up

```bash
docker compose up -d --build
./scripts/verify_all.sh   # 9-step full-stack verification
```

API at `http://127.0.0.1:3001/docs`, frontend at `http://localhost:3000`, planner at `8000`.

## 3 — Gasless relay check

```bash
curl -s http://localhost:3001/v1/relay/cbom-nonce/0xYourAddr | jq
# Sign EIP-712 typed data (domain: Q-Trust, chainId 84532) → POST /v1/relay/cbom
```

The indexer backfills from the chain; reorgs are detected and replayed automatically.

*Last verified: 2026-08-27 · against commit f02d106 · verifier: ./scripts/verify_all.sh*
