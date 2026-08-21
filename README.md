# Q-Trust — PQC Migration Coordinator

Cross-organizational protocol that coordinates the migration from classical cryptography
(RSA, ECC) to post-quantum cryptography (PQC), on Base L2. Only hashes live on-chain;
full CBOMs stay off-chain.

## Architecture

```
contracts/   Solidity registries (Foundry) — AssetRegistry, VendorRegistry, MigrationRegistry, AuditRegistry
sdk/         Python SDK (web3.py) — QTrustClient, Pydantic models, Pinata IPFS, generated ABIs
inspector/   cryptography-inspector CLI — scans TLS/SSH/code-signing assets → CBOM JSON
notebooks/   Quantum threat demo (Shor) + Phase 8 bank pilot notebook
planner/     GNN migration planner (PyTorch Geometric) — ranks CBOM assets by priority/risk
backend/     Fastify + viem API (TS ESM), attestation relayer, BullMQ webhook delivery, docker-compose
frontend/    Next.js 16 app — public verification, org dashboard, vendor portal
pilot/       End-to-end bank PQC migration demo script
docs/        Phase docs (0–8)
```

## Quick start

### 1. Contracts (Phase 1)
```bash
cd contracts
forge test                                # 49/49 pass (5 suites)
forge script script/Deploy.s.sol --rpc-url <RPC> --broadcast
```

### 2. SDK (Phase 2)
```bash
pip install -e ./sdk
cd sdk && python tests/e2e_anvil.py        # ALL E2E CHECKS PASSED
```

### 3. Inspector (Phase 3)
```bash
pip install -e .                          # installs `crypto-inspector`
crypto-inspector host example.com
crypto-inspector directory /path/to/dir
```

### 4. Quantum notebook (Phase 4)
```bash
jupyter nbconvert --to notebook --execute notebooks/01_quantum_threat_demo.ipynb
```

### 5. GNN planner (Phase 5)
```bash
cd planner && python -m qtrust_planner.train
python -m qtrust_planner.predict /tmp/bank_cbom.json        # positional CBOM path
```

### 6. Backend (Phase 6)
```bash
cd backend && npm install && npm run build
cp .env.example .env                       # fill RPC + deployed addresses
npm start                                  # http://localhost:3001
# Webhook delivery (needs Redis):
docker run -d -p 6379:6379 redis:7-alpine
node dist/services/webhook.js
# Or everything at once:
docker compose up -d --build               # api + webhook + redis
```

### 7. Frontend (Phase 7)
```bash
cd frontend && npm install && npm run build
NEXT_PUBLIC_QTRUST_API_URL=http://localhost:3001 npm start   # http://localhost:3000
# Verify an attestation: /v/<asset-id>
```

### 8. Pilot (Phase 8)
```bash
cd pilot && python run_pilot.py            # full bank migration demo, PILOT COMPLETE
jupyter nbconvert --to notebook --execute notebooks/08_bank_pilot.ipynb
```

## Environment variables

| Variable | Purpose |
|---|---|
| `QTRUST_BASE_SEPOLIA_RPC` | RPC endpoint (default `http://127.0.0.1:8545` for local anvil) |
| `QTRUST_DEPLOYER_PRIVATE_KEY` | Signer key (anvil dev key `0xac09…2ff80` for local) |
| `QTRUST_ASSET_REGISTRY_ADDRESS` | Deployed AssetRegistry |
| `QTRUST_VENDOR_REGISTRY_ADDRESS` | Deployed VendorRegistry |
| `QTRUST_MIGRATION_REGISTRY_ADDRESS` | Deployed MigrationRegistry |
| `QTRUST_AUDIT_REGISTRY_ADDRESS` | Deployed AuditRegistry |
| `QTRUST_REDIS_URL` | Redis for webhook service (`redis://localhost:6379`) |
| `QTRUST_BASESCAN_API_KEY` | Optional Basescan verification key |
| `NEXT_PUBLIC_QTRUST_API_URL` | Frontend → backend base URL |
| `NEXT_PUBLIC_IPFS_GATEWAY` | IPFS gateway for metadata (default ipfs.io) |

## Status

All phases 0–8 complete and verified against local anvil (chain-id 84532):

| Phase | Deliverable | Verification |
|---|---|---|
| 0 | Environment + structure | forge/node/python, anvil chain |
| 1 | 5 contracts (4 registries + QTrustGovernance timelock) | `forge test` 49/49, deployment with governance OK |
| 2 | Python SDK | pytest 5/5, E2E all checks passed |
| 3 | Crypto scanner + CBOM | pytest 5 pass (1 skip), live scans work |
| 4 | Shor quantum notebook | executes with 0 errors |
| 5 | GNN planner | **ListMLE-trained hybrid GCN+GAT (80 epochs, 1200 graphs): Kendall τ 0.387, top-5 0.656, top-10 0.528**; honest 3-seed 40-epoch benchmark: τ 0.266±0.023 vs 0.144 (MSE) vs ~0 (random); top-5 0.500±0.061 — see `planner/results/benchmark.json` |
| 6 | Backend API + webhooks | tsc clean, all `/v1` routes live-tested, webhook delivery verified end-to-end |
| 7 | Frontend | next build clean, all routes 200, attestation page renders VALID |
| 8 | Bank pilot | `run_pilot.py` → PILOT COMPLETE; pilot notebook executes 0 errors |

## Reproducing the numbers

```bash
./scripts/verify_all.sh          # one-command full-stack verification
cd planner && python -m qtrust_planner.benchmark --seeds 42 43 44   # honest multi-seed benchmark
```

## Known limitations (honest)

- **Planner evaluation is on synthetic data only** (layered enterprise + random DAGs, 20–100 nodes, 1000 graphs).
  The GNN is trained and evaluated on procedurally generated dependency graphs; real-world CBOM evaluation is future work
  and is NOT claimed in the patent. Production `model.pt` (80 epochs, 1200 graphs): τ 0.387, top-5 0.656.
- The rule-based heuristic used to *label* the synthetic data is included in the
  benchmark as an upper-bound baseline (`heuristic` τ 0.997); the GNN is expected to approach,
  not exceed, it on this synthetic task. GNN(ListMLE) τ 0.266±0.023 significantly outperforms MSE (0.144) and random (~0).
- Earlier README claims of "exact-rank 24%, Kendall τ 0.924" were not reproducible from
  the code and have been removed. The current benchmark reports exact-rank, top-k
  overlap, Kendall τ, and node-rank with mean±std across 3 seeds.
- SDK E2E must run on a fresh anvil chain (see `sdk/tests/run_e2e.sh`); it is not
  idempotent against a warm chain because it reuses fixed product identifiers.
- Contracts are verified on local anvil only; a live Base Sepolia deployment is
  pending external credentials (faucet, RPC).
- **Patent scope**: CBOM format (ECMA-424), generic blockchain PKI, and generic GNNs are NOT claimed;
  claims cover the combination: discovery → learned ordering (dual heads, ListMLE) → hash-only 4-registry coordination → public verification.

Remaining (credential-dependent, not possible without external accounts):
deploy to real Base Sepolia, MetaMask/faucet setup, Vercel deploy, Dynamic Labs wallet SDK.