---
title: Installation
outline: [2, 3]
---

# Installation

Q-Trust ships as two PyPI packages plus a monorepo for contributors. Install
the packages for scanning and on-chain work; clone the monorepo only if you
plan to change Q-Trust itself.

## From PyPI (recommended)

```bash
pip install qtrust-inspector   # scanner CLI: crypto-inspector
pip install qtrust-sdk         # on-chain client, trust & VC engines
```

Optional inspector extras: `qtrust-inspector[net]` adds nmap-based network
scanning; `qtrust-inspector[ml]` adds the PyTorch anomaly/side-channel
detectors.

### SDK quickstart

Mirrored from the repo's `sdk/README.md` — register a CBOM on Base Sepolia
(chain-id 84532) and pin its metadata to IPFS in one call:

```python
from qtrust import QTrustClient, CBOM, CBOMEntry

client = QTrustClient(
    private_key="0x...",
    rpc_url="https://sepolia.base.org",
    asset_registry_address="0x...",
)

cbom = CBOM(
    org_did="did:ethr:0x...",
    generated_at=1700000000,
    scanner_version="1.1.0",
    assets=[CBOMEntry(asset_type="tls_cert", algorithm="RSA-2048", location="example.com:443")],
)
asset_id, cid = client.register_cbom(cbom)
```

The SDK is configured by `QTRUST_*` environment variables (RPC endpoint,
chain ID, registry addresses, IPFS providers) — see
[the SDK page](/packages/sdk) for the full table and relay-nonce rules.

## From source (monorepo)

```bash
git clone https://github.com/humoge7502/q-trust.git
cd q-trust
cp .env.example .env   # then fill in RPC URL + contract addresses

# Python packages in editable mode (same commands CI uses)
pip install -e "./sdk[dev]"
pip install -e "./inspector[dev,ml]"
pip install -r planner/requirements.txt

# Node subsystems (Node 20+)
cd backend  && npm ci && cd ..
cd frontend && npm ci && cd ..

# Contracts (Foundry)
cd contracts && forge build && cd ..
```

Each subsystem has its own test suite — `forge test` in `contracts/`,
`pytest` in `sdk/`/`inspector/`/`planner/`, `vitest run` in `backend/` and
`frontend/` — see [CONTRIBUTING](https://github.com/humoge7502/q-trust/blob/main/CONTRIBUTING.md)
for the full per-subsystem matrix.

## Docker Compose profile

The repo's `docker-compose.yml` starts the whole backend stack — API,
webhook watcher, Postgres indexer store, Redis, the AI planner, Prometheus,
Alertmanager and Grafana:

```bash
cp .env.example .env   # set POSTGRES_PASSWORD, REDIS_PASSWORD, GRAFANA_PASSWORD, ...
docker compose up -d
```

The API listens on `127.0.0.1:3001`, the planner on `127.0.0.1:8000`,
Prometheus on `127.0.0.1:9090`, and Grafana on `127.0.0.1:3002`. The planner
service transparently uses a GPU when one is passed through
(`QTRUST_DEVICE=auto`) and falls back to CPU otherwise.
