# Q-Trust

**On-chain coordination for the largest cryptographic migration in history.**

Q-Trust is a production-grade protocol for discovering, planning, executing,
and *verifying* the migration of enterprise cryptography to post-quantum
algorithms — combining CBOM scanning, GPU-accelerated analysis (GNN planner,
RL agent, side-channel detector), and tamper-proof provenance on Base L2.

## Quick links

| Section | Description |
|---|---|
| [Architecture](ARCHITECTURE.md) | System design: contracts, indexer, backend, SDK, frontend |
| [Whitepaper](WHITEPAPER.md) | Protocol thesis and mechanism design |
| [GPU Features](GPU_FEATURES.md) | The six A100-accelerated features and how to run them |
| [Base Sepolia deployment](deployment/BASE_SEPOLIA.md) | Deploying the contract suite |
| [ADRs](adr/0000-record-architecture-decisions.md) | Architecture decision records |

## Repository layout

```
contracts/   Foundry workspace — 11 Solidity contracts (UUPS, EIP-712)
inspector/   Python scanner producing CBOMs / SARIF / compliance reports
planner/     FastAPI microservice — GNN + RL migration planning
backend/     Fastify API — verification, attestation, relay, GPU bridge
sdk/         qtrust Python SDK for on-chain registration
frontend/    Next.js dApp — wallet, dashboard, scanner, GPU panels
ops/         Prometheus, Grafana, AlertManager, load tests
docs/        Whitepaper, ADRs, runbooks, patent disclosures
```

## Development quickstart

```bash
# Contracts
cd contracts && forge test

# Inspector
pip install -e ./inspector[dev] && pytest inspector/tests/

# Backend
cd backend && npm ci && npm test

# Planner
pip install -r planner/requirements.txt && pytest planner/tests/

# Full local stack
cp .env.example .env  # fill in secrets
docker compose up -d
```

See [GPU Features](GPU_FEATURES.md) to put the A100 to work.
