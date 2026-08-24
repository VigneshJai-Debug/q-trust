# Q-Trust v2.0.0 — Enterprise PQC Migration Protocol

[![CI](https://github.com/humoge7502/q-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/humoge7502/q-trust/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/humoge7502/q-trust)](https://github.com/humoge7502/q-trust/releases/tag/v2.0.0)
[![Documentation](https://img.shields.io/badge/docs-mkdocs%20material-blue)](https://humoge7502.github.io/q-trust)

**The world's most comprehensive post-quantum cryptography migration protocol.** Enterprise-grade scanning, risk scoring, compliance verification, AI-powered planning, and blockchain-anchored attestation on Base L2.

## What's New in v1.0.0

| Feature | Description |
|---------|-------------|
| **Multi-Language Source Scanner** | Scans 12+ languages (Python, Java, Go, JS/TS, Rust, C/C++, Ruby, PHP, Swift, C#) for crypto API usage |
| **Package Manifest Scanner** | Detects crypto dependencies in Cargo.toml, package.json, requirements.txt, go.mod, pom.xml, and 10+ formats |
| **Risk Scoring Engine** | NIST SP 800-131A, CNSA 2.0, HNDL exposure scoring, quantum vulnerability classification |
| **Compliance Frameworks** | NIST SP 800-131A, CNSA 2.0, FIPS 140-3, EU NIS2, FISMA, FedRAMP, CMMC |
| **CycloneDX 1.7 CBOM** | Industry-standard Cryptographic Bill of Materials output |
| **SARIF 2.1 Output** | GitHub Advanced Security integration |
| **Migration Roadmap** | 5-phase migration planning with cost estimation |
| **Evidence Trail** | Hash-chained tamper-evident audit ledger |
| **On-Chain Evidence** | EvidenceRegistry + ComplianceAttestation contracts |
| **SDK Risk & Compliance** | Python SDK with risk scoring and compliance checking APIs |
| **Scanner Dashboard** | Real-time risk visualization, compliance reports, roadmap UI |

## Architecture

```
contracts/        11 Solidity contracts (Foundry) — registries, governance, evidence, compliance
sdk/              Python SDK — QTrustClient, risk scoring, compliance, CycloneDX, evidence, W3C VCs
inspector/        Enterprise PQC scanner — 10 scanning modules, 7 compliance frameworks, evidence trail
planner/          GNN migration planner (PyTorch Geometric) — priority/risk ranking, cost estimation
backend/          Fastify + viem API — scanner orchestration, risk dashboard, compliance reports
frontend/         Next.js 16 — scanner dashboard, risk gauge, compliance panel, roadmap visualization
pilot/            End-to-end bank PQC migration demo
notebooks/        Quantum threat demo + bank pilot notebook
scripts/          ABI generation, full-stack verification
docs/             Whitepaper, phase docs, patent materials
```

## Quick Start

### 1. Scanner (v1.0.0 — NEW)
```bash
cd inspector && pip install -e .
crypto-inspector scan /path/to/project --cyclonedx cbom.json --sarif results.sarif --risk --compliance nist,cnsa
crypto-inspector scan example.com --cyclonedx host_cbom.json --evidence ledger.json --roadmap plan.json
```

### 2. Contracts
```bash
cd contracts && forge test                                # 127+ tests
forge script script/Deploy.s.sol --rpc-url <RPC> --broadcast
```

### 3. SDK
```bash
pip install -e ./sdk
python -c "from qtrust import RiskScoringEngine, ComplianceEngine; print('OK')"
```

### 4. Backend
```bash
cd backend && npm install && npm run build
docker compose up -d --build               # api + webhook + redis + planner
```

### 5. Frontend
```bash
cd frontend && npm install && npm run build
NEXT_PUBLIC_QTRUST_API_URL=http://localhost:3001 npm start
```

### 6. GNN Planner
```bash
cd planner && python -m qtrust_planner.train
python -m qtrust_planner.predict /tmp/bank_cbom.json
```

## Scanner Capabilities

| Scanner Module | Target | Detection |
|---------------|--------|-----------|
| TLS Scanner | Network endpoints | Certificate algorithms, key sizes, expiry |
| SSH Scanner | Network endpoints | Host key algorithms, key types |
| Source Scanner | 12+ languages | Crypto API usage, hardcoded keys |
| Manifest Scanner | 10+ formats | Crypto library dependencies |
| Binary Scanner | Compiled binaries | Algorithm strings, OIDs |
| Config Scanner | YAML/TOML/JSON | Crypto settings, cipher suites |
| Evidence Ledger | All findings | Hash-chained audit trail |

## Risk & Compliance

| Framework | Scope | Rules |
|-----------|-------|-------|
| NIST SP 800-131A | Algorithm deprecation | RSA key sizes, ECDSA curves, hash algorithms |
| CNSA 2.0 | NSA approved algorithms | ML-KEM-1024, ML-DSA-87, AES-256, SHA-384+ |
| FIPS 140-3 | Module validation | Approved algorithms, key sizes, modes |
| EU NIS2 | EU cybersecurity | Crypto measures, quantum risk, incident reporting |
| FISMA | Federal systems | FIPS modules, NIST algorithms, key management |
| FedRAMP | Cloud services | CNSA Suite, TLS 1.2+, validated modules |
| CMMC | DoD supply chain | CUI protection, key management, audit trails |

## Output Formats

| Format | Standard | Use Case |
|--------|----------|----------|
| CycloneDX 1.7 CBOM | OWASP | Cryptographic Bill of Materials |
| SARIF 2.1 | OASIS | GitHub Advanced Security |
| JSON | Custom | Risk scores, compliance reports |
| Evidence Ledger | Custom | Tamper-evident audit trail |
| Migration Roadmap | Custom | Phase planning, cost estimation |

## On-Chain (Base L2)

| Contract | Purpose |
|----------|---------|
| AssetRegistry | CBOM hash registration, verification |
| VendorRegistry | PQC readiness attestations |
| MigrationRegistry | Migration step recording |
| AuditRegistry | Third-party audit attestations |
| EvidenceRegistry | **NEW** — Evidence ledger root anchoring |
| ComplianceAttestation | **NEW** — Compliance score attestation |
| TrustAnchorRegistry | Issuer accreditation |
| RevocationAnchor | Merkle root revocation |
| PolicyCommitment | Versioned policy hashes |
| SchemaRegistry | Schema registration |
| QTrustGovernance | Timelock-controlled admin |

## GPU-Accelerated Features (Optional)

On CUDA hardware (A100-class), Q-Trust unlocks 6 GPU features — large-scale
GNN training (100K graphs, BF16), timing side-channel analysis of PQC
implementations, quantum threat simulation/estimation, an RL migration
agent, parallel enterprise scanning with GPU-batch risk scoring, and CBOM
anomaly detection. Exposed via REST when `QTRUST_GPU_ENABLED=true`
(`/v1/gpu/*`) and surfaced in the dashboard's **Side Channel** tab and GPU
analysis panels.

**Trained checkpoints & measured results** (A100-SXM4-80GB):

| Model | Result |
|---|---|
| GNN v2 (`planner/model.pt`) | canonical held-out Kendall τ **0.961** |
| GNN v3 (`planner/model_gpu_v3.pt`) | trained at 100K-graph / BF16 scale (best-val checkpoint); own-split val τ 0.703 · canonical held-out τ 0.898 |
| RL agent (`planner/rl_agent.pt`) | 10K episodes; best mean reward **+6.24** (untrained: −8.6) |
| Side-channel detector | clean → 0.05 `VERIFIED`, leaky → 0.95 `HIGH_RISK` (calibrated) |
| Anomaly VAE | flags weak-key inventories; calibrated threshold persisted in checkpoint |

> Ranking metrics use the corrected per-node-rank Kendall protocol (a
> sequence-correlation bug previously understated every GNN τ by ~0.5;
> fixed in v2.1 with regression tests — see CHANGELOG). Canonical numbers:
> heuristic upper bound τ 1.00, ListMLE-trained v2-family models
> τ 0.94 ± 0.01 (`results/benchmark.json`).

Run the v2-vs-v3 comparison yourself: `python -m qtrust_planner.benchmark_v3`.
See [docs/GPU_FEATURES.md](docs/GPU_FEATURES.md),
[docs/PERFORMANCE.md](docs/PERFORMANCE.md), and
`make -f Makefile.gpu help`.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `QTRUST_BASE_SEPOLIA_RPC` | RPC endpoint |
| `QTRUST_DEPLOYER_PRIVATE_KEY` | Signer key |
| `QTRUST_ASSET_REGISTRY_ADDRESS` | Deployed AssetRegistry |
| `QTRUST_VENDOR_REGISTRY_ADDRESS` | Deployed VendorRegistry |
| `QTRUST_MIGRATION_REGISTRY_ADDRESS` | Deployed MigrationRegistry |
| `QTRUST_AUDIT_REGISTRY_ADDRESS` | Deployed AuditRegistry |
| `QTRUST_IPFS_PROVIDERS` | IPFS pinning providers, comma-separated in priority order (default `pinata`; supports `pinata`, `kubo`, `web3`) |
| `QTRUST_PINATA_API_KEY` / `QTRUST_PINATA_API_SECRET` | Pinata credentials |
| `QTRUST_IPFS_KUBO_API` | Kubo node HTTP API endpoint (default `http://127.0.0.1:5001`) |
| `QTRUST_IPFS_KUBO_USER` / `QTRUST_IPFS_KUBO_PASS` | Optional basic auth for Kubo |
| `QTRUST_WEB3_STORAGE_TOKEN` | Bearer token for web3.storage uploads |
| `QTRUST_REDIS_URL` | Redis for webhook service |
| `NEXT_PUBLIC_QTRUST_API_URL` | Frontend → backend base URL |

## API Endpoints (v1.0.0)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/health` | System health check |
| POST | `/v1/scan/source` | Source code scanning |
| POST | `/v1/scan/manifests` | Manifest scanning |
| POST | `/v1/scan/full` | Full target scanning |
| POST | `/v1/risk/score` | Risk scoring for findings |
| POST | `/v1/risk/summary` | Aggregate risk summary |
| POST | `/v1/compliance/evaluate` | Framework compliance check |
| POST | `/v1/compliance/full-report` | All-frameworks compliance report |
| POST | `/v1/evidence/create` | Create evidence entry |
| POST | `/v1/evidence/verify` | Verify evidence ledger |
| POST | `/v1/roadmap/generate` | Generate migration roadmap |
| GET | `/v1/stats` | Aggregate statistics |

## Testing

```bash
# Full stack verification
./scripts/verify_all.sh

# Component tests
cd contracts && forge test
cd sdk && pytest
cd planner && python -m qtrust_planner.benchmark --seeds 42 43 44
cd backend && npm test
```

## Documentation

- [Documentation site](https://humoge7502.github.io/q-trust) — rendered MkDocs Material (source: `mkdocs.yml` + `docs/`)
- [Whitepaper](docs/WHITEPAPER.md) — Technical specification
- [Architecture](docs/ARCHITECTURE.md) — System design
- [GPU Features](docs/GPU_FEATURES.md) — The six A100-accelerated features
- [Performance Benchmarks](docs/PERFORMANCE.md) — k6 load tests + GPU latencies
- [Case Study: example.com TLS](docs/case-studies/CASE_STUDY_EXAMPLE_COM.md) — scan → CBOM → on-chain → verify
- [Release v2.0.0](https://github.com/humoge7502/q-trust/releases/tag/v2.0.0) — release notes + audit PDF
- [Contributing](CONTRIBUTING.md) — Development guide
- [ADRs & Runbooks](docs/) — Decision records, operations, patent disclosures

## License

MIT License. See [LICENSE](LICENSE) for details.
