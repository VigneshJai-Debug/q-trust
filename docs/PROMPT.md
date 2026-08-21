# Q-Trust: Master Build Prompt for Qwen 2.5

## Project Overview

Q-Trust is a cross-organizational protocol that coordinates the global migration from classical cryptography (RSA, ECC) to post-quantum cryptography (PQC). It uses Base (Ethereum L2) for shared trust, IPFS for off-chain storage, and combines smart contracts with a Python SDK, a cryptography scanner, a qiskit quantum simulation notebook, and a PyTorch GNN migration planner.

**Target environment:** BrevLab (institutional JupyterLab with A100 GPU)
**Blockchain:** Base Sepolia (testnet) / Base (mainnet)
**No token, no speculation.** Revenue from SaaS subscriptions.

## Your Task

Build the complete Q-Trust MVP. All source files are provided in this directory as reference implementations. Your job is to:

1. Read each file in this package
2. Understand the architecture from `docs/ARCHITECTURE.md`
3. Follow the build order in `docs/BUILD_ORDER.md`
4. Create each file in the user's BrevLab environment at `/home/z/qtrust/`
5. Test each component before moving to the next
6. Fix any bugs you encounter

## Build Order (Follow Strictly)

### Phase 0: Environment Setup (Day 1)
- Set up BrevLab instance, install Foundry, Node.js, Python env
- Configure MetaMask with Base Sepolia, get testnet ETH from faucet
- Store secrets in BrevLab environment variables
- Create project structure at `/home/z/qtrust/`
- File: `docs/PHASE_0_SETUP.md`

### Phase 1: Smart Contracts (Week 1-2)
- Initialize Foundry project in `contracts/`
- Write 4 Solidity contracts:
  - `contracts/src/AssetRegistry.sol` — registers CBOM (Cryptographic Bill of Materials) hashes
  - `contracts/src/VendorRegistry.sol` — vendors post PQC readiness attestations
  - `contracts/src/MigrationRegistry.sol` — records each migration step
  - `contracts/src/AuditRegistry.sol` — third-party audit attestations
- Write tests in `contracts/test/`
- Write deployment script in `contracts/script/Deploy.s.sol`
- Deploy to Base Sepolia
- File: `docs/PHASE_1_CONTRACTS.md`

### Phase 2: Python SDK (Week 3)
- Create `sdk/` package with:
  - `sdk/qtrust/client.py` — QTrustClient class (web3.py, EIP-712 signing)
  - `sdk/qtrust/schema.py` — Pydantic models (AssetData, VendorAttestation, MigrationRecord)
  - `sdk/qtrust/ipfs.py` — Pinata IPFS pinning
  - `sdk/qtrust/contracts.py` — contract ABIs
- Install with `pip install -e .`
- File: `docs/PHASE_2_SDK.md`

### Phase 3: Cryptography Scanner (Week 4)
- Create `scanner/` package with:
  - `scanner/cryptography_inspector/scanner.py` — scans hosts for TLS certs, SSH keys, code-signing certs
  - `scanner/cryptography_inspector/main.py` — CLI entry point
  - Uses Python `cryptography`, `ssl`, `socket`, `nmap`
- Generates CBOM (Cryptographic Bill of Materials) JSON
- File: `docs/PHASE_3_SCANNER.md`

### Phase 4: Quantum Shor Simulation (Week 5)
- Create `quantum/shor_demo.ipynb` — Jupyter notebook
- Uses qiskit311 kernel
- Simulates Shor's algorithm against RSA keys
- Shows "qubits needed to break" + timeline (IBM/Google roadmaps)
- This is the SALES TOOL — converts abstract threat to concrete timeline
- File: `docs/PHASE_4_QUANTUM.md`

### Phase 5: GNN Migration Planner (Week 6)
- Create `gnn/` package with:
  - `gnn/model.py` — MigrationGNN class (PyTorch Geometric GCN)
  - `gnn/data_generator.py` — generates synthetic migration dependency graphs
  - `gnn/train.py` — training script
  - `gnn/predict.py` — takes a CBOM + dependency graph, returns migration order
- Uses FIGNN kernel (fignn_env)
- File: `docs/PHASE_5_GNN.md`

### Phase 6: Backend Services (Week 7-8)
- Create `backend/` with:
  - `backend/src/server.ts` — Fastify REST API
  - `backend/src/services/attestation.ts` — relayer service
  - `backend/src/services/verify.ts` — verification API (viem)
  - `backend/src/services/webhook.ts` — webhook delivery (BullMQ + Redis)
  - `backend/docker-compose.yml` — Docker Compose deployment
- File: `docs/PHASE_6_BACKEND.md`

### Phase 7: Frontend Dashboard (Week 9-10)
- Create Next.js 16 app in `frontend/`:
  - `frontend/src/app/v/[id]/page.tsx` — public verification page (React Flow graph)
  - `frontend/src/app/dashboard/page.tsx` — org dashboard
  - `frontend/src/app/vendors/page.tsx` — vendor portal
  - Uses Tailwind CSS, shadcn/ui, Dynamic SDK for SIWE auth
- Deploy to Vercel
- File: `docs/PHASE_7_FRONTEND.md`

### Phase 8: Bank Pilot (Week 11-12)
- Create `notebooks/08_bank_pilot.ipynb`
- Simulates a bank (First National) running the full flow:
  1. Scan infrastructure → CBOM
  2. Register CBOM on-chain
  3. Check vendor attestations
  4. Run Shor simulation (sales demo)
  5. Run GNN migration planner
  6. Execute migrations (simulated)
  7. Auditor verification
- File: `docs/PHASE_8_PILOT.md`

## Key Design Decisions

1. **No token** — revenue from SaaS subscriptions ($1K/mo Pro, $10-50K/mo Enterprise)
2. **Base L2** — gas costs ~$0.01 per attestation, EVM-compatible, Coinbase-backed
3. **Only hashes on-chain** — full CBOMs on IPFS, personal data never on-chain
4. **ERC-4337 paymaster** — non-crypto customers pay in fiat via Stripe
5. **EIP-712 signing** — typed-data signatures for all attestations
6. **OpenZeppelin AccessControl** — role-based permissions (ATTESTER_ROLE, VENDOR_ROLE, AUDITOR_ROLE)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Q-Trust Protocol                         │
├─────────────────────────────────────────────────────────────────┤
│  ON-CHAIN (Base L2)                    OFF-CHAIN                │
│  ┌─────────────────────┐               ┌──────────────────────┐ │
│  │ AssetRegistry       │               │ IPFS (Pinata)        │ │
│  │ VendorRegistry     │◄──────────────│   CBOM JSONs         │ │
│  │ MigrationRegistry  │   hash refs   │   Audit reports      │ │
│  │ AuditRegistry     │               │   Migration evidence  │ │
│  └────────┬────────────┘               └──────────────────────┘ │
│           │                                      │              │
│           │ viem / web3.py                       │ HTTP          │
│           ▼                                      ▼              │
│  ┌─────────────────────┐               ┌──────────────────────┐ │
│  │ Backend (Fastify)   │               │ Frontend (Next.js)   │ │
│  │  - Attestation API  │◄──────────────│  - Verification page │ │
│  │  - Verify API       │   REST API    │  - Org dashboard    │ │
│  │  - Webhook service  │               │  - Vendor portal    │ │
│  │  - Paymaster        │               └──────────────────────┘ │
│  └─────────────────────┘                                        │
│           │                                                     │
│           │ Python SDK                                          │
│           ▼                                                     │
│  ┌─────────────────────┐               ┌──────────────────────┐ │
│  │ QTrustClient       │               │ cryptography-        │ │
│  │  - register_cbom()  │               │ inspector scanner   │ │
│  │  - attest_vendor()  │               │  (TLS/SSH/HSM scan) │ │
│  │  - record_migration││               └──────────────────────┘ │
│  └─────────────────────┘                                        │
│           │                                                     │
│           │ qiskit311 kernel         FIGNN kernel               │
│           ▼                          ▼                         │
│  ┌─────────────────────┐   ┌──────────────────────┐             │
│  │ Shor Simulation     │   │ GNN Migration        │             │
│  │ (sales tool)       │   │ Planner             │             │
│  └─────────────────────┘   └──────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## File Tree

```
qtrust/
├── contracts/
│   ├── foundry.toml
│   ├── src/
│   │   ├── AssetRegistry.sol
│   │   ├── VendorRegistry.sol
│   │   ├── MigrationRegistry.sol
│   │   └── AuditRegistry.sol
│   ├── test/
│   │   └── AssetRegistry.t.sol
│   └── script/
│       └── Deploy.s.sol
├── sdk/
│   ├── pyproject.toml
│   └── qtrust/
│       ├── __init__.py
│       ├── client.py
│       ├── schema.py
│       ├── ipfs.py
│       └── contracts.py
├── scanner/
│   ├── pyproject.toml
│   └── cryptography_inspector/
│       ├── __init__.py
│       ├── scanner.py
│       └── main.py
├── quantum/
│   └── shor_demo.ipynb
├── gnn/
│   ├── model.py
│   ├── data_generator.py
│   ├── train.py
│   └── predict.py
├── backend/
│   ├── package.json
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── src/
│       ├── server.ts
│       └── services/
│           ├── attestation.ts
│           ├── verify.ts
│           └── webhook.ts
├── frontend/
│   ├── package.json
│   └── src/
│       └── app/
│           ├── layout.tsx
│           ├── v/[id]/page.tsx
│           ├── dashboard/page.tsx
│           └── vendors/page.tsx
├── notebooks/
│   └── 08_bank_pilot.ipynb
├── docs/
│   ├── ARCHITECTURE.md
│   ├── BUILD_ORDER.md
│   └── PHASE_*.md
├── environment.yml
├── Makefile
└── README.md
```

## Important Notes for Qwen 2.5

1. **Do NOT skip any phase.** Each phase builds on the previous one.
2. **Test each component before moving on.** Run the tests, verify expected output.
3. **Handle secrets properly.** Never commit private keys, API keys, or RPC URLs to git. Use environment variables.
4. **Use the provided code as-is.** The code files in this package are complete, tested reference implementations. Copy them verbatim, then adapt as needed.
5. **Fix bugs as you encounter them.** If a test fails, debug it before proceeding.
6. **Commit after each phase.** `git add . && git commit -m "Phase N: description" && git push`
7. **Ask for help if stuck.** If you encounter an error you cannot resolve after 3 attempts, pause and ask the user for clarification.

## Environment Variables (set in BrevLab)

```
QTRUST_DEPLOYER_PRIVATE_KEY=0x...
QTRUST_BASE_SEPOLIA_RPC=https://base-sepolia.g.alchemy.com/v2/...
QTRUST_PINATA_API_KEY=...
QTRUST_PINATA_API_SECRET=...
QTRUST_ORG_DID=did:ethr:0x...
QTRUST_REGISTRY_ADDRESS=(set after Phase 1)
QTRUST_VENDOR_REGISTRY_ADDRESS=(set after Phase 1)
QTRUST_MIGRATION_REGISTRY_ADDRESS=(set after Phase 1)
QTRUST_AUDIT_REGISTRY_ADDRESS=(set after Phase 1)
```

## Success Criteria

The MVP is complete when:
1. ✅ All 4 contracts deployed to Base Sepolia and verified on Basescan
2. ✅ SDK can register a CBOM and verify it on-chain
3. ✅ Scanner can scan a host and produce a CBOM JSON
4. ✅ Quantum notebook runs Shor's algorithm and shows qubit estimates
5. ✅ GNN can take a dependency graph and output migration order
6. ✅ Backend API serves verification requests
7. ✅ Frontend shows a provenance graph for a given attestation ID
8. ✅ Bank pilot notebook runs end-to-end without errors
