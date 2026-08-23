# Q-Trust — Full Implementation Guide

## Master Handoff Document for Qwen 2.5

> **Purpose of this document:** This is a single, self-contained implementation guide for the Q-Trust protocol (Post-Quantum Cryptography Migration Coordinator). It is written so that an AI coding assistant (Qwen 2.5, Claude, Cursor, Copilot) can read it from start to finish and produce every file needed to build the full MVP. Every code block is complete and runnable — no ellipses, no "..." abbreviations.
>
> **How to use with Qwen 2.5:** Paste this entire document into a Qwen 2.5 chat session (or upload it as a context file). Then prompt: *"Implement the Q-Trust project exactly as specified in this document. Create every file listed, with the exact contents shown. Do not skip any file. After creating all files, run the test commands listed in each phase and fix any errors."*
>
> **Target environment:** BrevLab (institutional JupyterLab instance with A100 GPU) + Base Sepolia testnet. The guide assumes the BrevLab has the kernels visible in the user's screenshots: qiskit311, quantum311, fignn_env, Honeycomb A100, .deep.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [BrevLab Environment Setup (Phase 0)](#3-brevlab-environment-setup-phase-0)
4. [Phase 1: Smart Contracts (Solidity)](#4-phase-1-smart-contracts-solidity)
5. [Phase 2: Python SDK](#5-phase-2-python-sdk)
6. [Phase 3: Cryptography Inspector CLI](#6-phase-3-cryptography-inspector-cli)
7. [Phase 4: Qiskit Sales Notebook (Shor's Algorithm Demo)](#7-phase-4-qiskit-sales-notebook-shors-algorithm-demo)
8. [Phase 5: FIGNN Migration Planner](#8-phase-5-fignn-migration-planner)
9. [Phase 6: Backend Services](#9-phase-6-backend-services)
10. [Phase 7: Frontend Dashboard (Next.js)](#10-phase-7-frontend-dashboard-nextjs)
11. [Phase 8: Pilot & Demo](#11-phase-8-pilot--demo)
12. [Appendix A: Full File Tree](#12-appendix-a-full-file-tree)
13. [Appendix B: Qwen 2.5 Handoff Prompt](#13-appendix-b-qwen-25-handoff-prompt)
14. [Appendix C: Glossary](#14-appendix-c-glossary)

---

## 1. Project Overview

**Q-Trust** is a cross-organizational protocol and SaaS that coordinates the global migration from classical cryptography (RSA, ECC) to post-quantum cryptography (PQC). It uses Base (Ethereum L2) as a shared, tamper-proof registry of cryptographic assets, vendor PQC attestations, and migration steps.

**Why this project:**
- NIST finalized PQC standards in August 2024 (FIPS 203, 204, 205)
- OMB M-23-02 mandates federal agency inventory by 2024-2025, full migration by 2035
- DHS estimates $50-100B global migration spend over the next decade
- No existing solution provides cross-organization verifiable coordination
- Blockchain is genuinely necessary because no single vendor, customer, or government can be trusted to coordinate

**What the MVP contains:**
- 4 Solidity smart contracts on Base Sepolia (AssetRegistry, VendorRegistry, MigrationRegistry, AuditRegistry)
- Python SDK with a `cryptography-inspector` CLI that scans real systems for crypto assets
- Qiskit notebook that simulates Shor's algorithm against customer RSA keys (sales tool)
- FIGNN-style GNN that recommends migration order based on dependency graph
- Fastify backend with viem + Redis + Docker Compose
- Next.js 16 dashboard with React Flow + SIWE auth
- Pilot: simulate a bank's PQC migration end-to-end

**Timeline:** 8 phases over 12 weeks (solo full-time) or 6 weeks (team of 3-4).

**What is NOT in the MVP:** zero-knowledge proofs of CBOM (v2), TEE-backed key rotation attestation (v2), multi-chain deployment (v2), FedRAMP authorization (v3).

---

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       BrevLab Instance                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ qiskit311    │  │ fignn_env    │  │ Honeycomb A100       │  │
│  │ (Shor sales  │  │ (Migration   │  │ (Side-channel v2)    │  │
│  │  notebook)   │  │  planner GNN)│  │                       │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ .deep kernel │  │ lineage env  │  │ Python 3.11 (qtrust) │  │
│  │ (DL anomaly) │  │ (SDK + CLI)  │  │  - SDK               │  │
│  │              │  │              │  │  - CLI                │  │
│  │              │  │              │  │  - Inspector          │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           │ HTTPS (viem + web3.py)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Base Sepolia (Ethereum L2)                     │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐    │
│  │AssetReg    │ │VendorReg   │ │MigrationReg│ │AuditReg    │    │
│  │            │ │            │ │            │ │            │    │
│  │- registerCBOM│ │- attestProduct│ │- recordMigration│ │- postAudit │ │
│  │- getCBOM   │ │- getVendor │ │- getMigration│ │- getAudit │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           │ Webhook events
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                Q-Trust Backend (Node.js + Fastify)              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐    │
│  │Attestation │ │Verification│ │Webhook     │ │Paymaster   │    │
│  │Service     │ │API         │ │Service     │ │(ERC-4337)  │    │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Postgres (cache) + Redis (queue)              │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           │ REST API
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│            Next.js 16 Dashboard (Vercel)                       │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐    │
│  │Public      │ │Org         │ │Vendor      │ │Auditor     │    │
│  │Verification│ │Dashboard   │ │Portal      │ │Workspace   │    │
│  │Page        │ │(SIWE auth) │ │            │ │            │    │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 On-Chain vs Off-Chain Data

| On-chain (Base Sepolia) | Off-chain |
|---|---|
| CBOM hash (32 bytes) | Full CBOM JSON (IPFS or customer S3) |
| Vendor DID + product attestation | Vendor KYC, source code |
| Migration step records | Actual key material (never on-chain) |
| Audit result hash | Full audit report (IPFS) |
| Org DIDs + timestamps | Personal information, network topology |

### 2.3 Kernels Used

| BrevLab Kernel | Phase | Purpose |
|---|---|---|
| `Python 3.11 (qtrust)` | 0-4, 6-8 | SDK, CLI, backend helpers, pilot |
| `qiskit311` | 4 | Shor's algorithm sales notebook |
| `fignn_env` | 5 | Migration dependency GNN training |
| `Honeycomb A100` | 5, 8 | GNN training, pilot side-channel (v2) |
| `.deep` | 5 | DL anomaly detection (v2) |

---

## 3. BrevLab Environment Setup (Phase 0)

### 3.1 Prerequisites

Before starting, you need five external accounts:

1. **BrevLab account** (institution-provided) — access to JupyterLab with A100 GPU
2. **GitHub account** — host your code, sign in to Vercel
3. **MetaMask wallet** — deploy contracts on Base Sepolia testnet
4. **Alchemy account** — RPC endpoint for Base Sepolia
5. **Pinata account** — IPFS pinning for CBOMs and audit reports

Create a GitHub repository named `qtrust`. Make it public.

### 3.2 BrevLab Instance Setup

Open your BrevLab URL in the browser. Open a terminal (File → New → Terminal). Verify the GPU:

```bash
nvidia-smi
# Should show "NVIDIA A100-SXM4-40GB" or 80GB variant
```

Verify Python and conda:

```bash
python --version          # Python 3.10 or 3.11
conda --version           # conda 23.0+
which python              # /home/z/miniconda3/bin/python or similar
```

### 3.3 Install Development Tools

**Install Foundry (Solidity compiler + deployer):**

```bash
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup

# Verify
forge --version    # forge 0.2.0+
cast --version     # cast 0.2.0+
anvil --version    # anvil 0.2.0+
```

**Install Node.js 20:**

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install 20
nvm use 20
nvm alias default 20

# Install bun (faster alternative to npm)
curl -fsSL https://bun.sh/install | bash
source ~/.bashrc

# Verify
node --version     # v20.x.x
bun --version      # 1.x.x
```

**Create a dedicated Python 3.11 environment for Q-Trust:**

```bash
conda create -n qtrust python=3.11 -y
conda activate qtrust

pip install --upgrade pip setuptools wheel
pip install ipykernel jupyterlab
python -m ipykernel install --sys-prefix --name qtrust --display-name "Python 3.11 (qtrust)"
```

Refresh your browser. The new "Python 3.11 (qtrust)" kernel appears in the JupyterLab Launcher.

**Configure git:**

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

### 3.4 Wallet and Testnet Setup

1. In MetaMask, switch to Base Sepolia network. If not in your list, click "Add Network":
   - Network Name: `Base Sepolia`
   - RPC URL: your Alchemy Base Sepolia endpoint
   - Chain ID: `84532`
   - Currency Symbol: `ETH`
   - Block Explorer: `https://sepolia.basescan.org`

2. Create a new MetaMask account labeled "Q-Trust Deployer". Copy the address.

3. Fund with testnet ETH from a faucet:
   - https://www.coinbase.com/faucets/base-sepolia
   - https://faucet.quicknode.com/base/sepolia
   - You should receive 0.1-0.5 ETH within a minute.

4. Export the private key: Account Details → Show private key → enter password → copy.

### 3.5 Store Secrets in BrevLab Environment Variables

In the BrevLab dashboard, navigate to your instance → Environment Variables tab. Add:

```
QTRUST_DEPLOYER_PRIVATE_KEY = 0x...your-private-key...
QTRUST_BASE_SEPOLIA_RPC     = https://base-sepolia.g.alchemy.com/v2/your-alchemy-key
QTRUST_PINATA_API_KEY       = your-pinata-api-key
QTRUST_PINATA_API_SECRET    = your-pinata-api-secret
QTRUST_BASESCAN_API_KEY     = your-basescan-api-key
QTRUST_ORG_DID              = did:ethr:0xYourDeployerAddress
QTRUST_ASSET_REGISTRY_ADDRESS       = (leave empty — set in Phase 1)
QTRUST_VENDOR_REGISTRY_ADDRESS      = (leave empty — set in Phase 1)
QTRUST_MIGRATION_REGISTRY_ADDRESS  = (leave empty — set in Phase 1)
QTRUST_AUDIT_REGISTRY_ADDRESS      = (leave empty — set in Phase 1)
```

Get a Basescan API key at https://sepolia.basescan.org/register (sign up, then API-KEYs → Add).

Restart your shell after setting env vars:

```bash
source ~/.bashrc
echo $QTRUST_DEPLOYER_PRIVATE_KEY | head -c 10   # should print "0x" + first 8 chars
```

### 3.6 Project Structure

In the JupyterLab terminal:

```bash
cd /home/z
mkdir -p qtrust/{contracts,sdk,cli,backend,frontend,notebooks,docs,scripts}
cd qtrust
git init
echo "# Q-Trust — Post-Quantum Cryptography Migration Coordinator" > README.md
touch .gitignore
```

Open `.gitignore` and paste:

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.eggs/
dist/
build/
.venv/
.env

# Node
node_modules/
.next/
.vercel/

# Foundry / Solidity
cache/
out/
broadcast/
lib/

# Notebooks
.ipynb_checkpoints/
*.ipynb_checkpoints

# OS
.DS_Store
Thumbs.db

# Secrets — NEVER commit
*.env
*.key
*.pem
secrets/
```

Create `environment.yml`:

```yaml
# /home/z/qtrust/environment.yml
name: qtrust
channels:
  - conda-forge
  - defaults
dependencies:
  - python=3.11
  - pip
  - pip:
    - web3==6.15.1
    - eth-account==0.11.0
    - eth-abi==5.0.0
    - pydantic==2.6.0
    - typer==0.12.0
    - rich==13.7.0
    - requests==2.31.0
    - python-dotenv==1.0.0
    - pytest==8.0.0
    - cryptography==42.0.0
    - nmap==0.7.1
    - paramiko==3.4.0
    - pyasn1==0.5.1
    - ipykernel
```

Recreate the environment:

```bash
cd /home/z/qtrust
conda env create -f environment.yml    # 2-3 minutes
conda activate qtrust
python -m ipykernel install --sys-prefix --name qtrust --display-name "Python 3.11 (qtrust)"
```

Create `Makefile`:

```makefile
# /home/z/qtrust/Makefile
.PHONY: help setup test contracts sdk cli backend frontend deploy

help:
	@echo "Q-Trust MVP commands:"
	@echo "  make setup      — install all dependencies"
	@echo "  make test       — run all tests"
	@echo "  make contracts  — compile + test Solidity contracts"
	@echo "  make sdk        — install SDK in dev mode"
	@echo "  make deploy     — deploy contracts to Base Sepolia"

setup:
	conda env create -f environment.yml
	cd contracts && forge install
	cd sdk && pip install -e .
	cd cli && pip install -e .

test:
	cd contracts && forge test
	cd sdk && pytest
	cd cli && pytest

contracts:
	cd contracts && forge build && forge test

sdk:
	cd sdk && pip install -e .

deploy:
	cd contracts && forge script script/Deploy.s.sol:Deployer \
	  --rpc-url $(QTRUST_BASE_SEPOLIA_RPC) \
	  --private-key $(QTRUST_DEPLOYER_PRIVATE_KEY) \
	  --broadcast --verify
```

Commit the initial structure:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 0: project structure and environment"
git branch -M main
git remote add origin https://github.com/<your-username>/qtrust.git
git push -u origin main
```

---

## 4. Phase 1: Smart Contracts (Solidity)

### 4.1 Foundry Project Initialization

```bash
cd /home/z/qtrust
mkdir -p contracts && cd contracts
forge init --no-commit --vscode

# Delete default template files
rm src/Counter.sol test/Counter.t.sol script/Counter.s.sol

# Install OpenZeppelin
forge install OpenZeppelin/openzeppelin-contracts --no-commit
forge install foundry-rs/forge-std --no-commit
```

Replace `foundry.toml`:

```toml
# /home/z/qtrust/contracts/foundry.toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.24"
optimizer = true
optimizer_runs = 200
via_ir = false

remappings = [
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
    "@forge-std/=lib/forge-std/src/"
]

[rpc_endpoints]
base_sepolia = "${QTRUST_BASE_SEPOLIA_RPC}"

[etherscan]
base_sepolia = { key = "${QTRUST_BASESCAN_API_KEY}", url = "https://api-sepolia.basescan.org/api" }
```

Verify the setup compiles:

```bash
cd /home/z/qtrust/contracts
forge build
# Should print: "Compiler run successful!"
```

### 4.2 AssetRegistry.sol

Create `src/AssetRegistry.sol`:

```solidity
// /home/z/qtrust/contracts/src/AssetRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title AssetRegistry — stores cryptographic asset (CBOM) attestations
/// @notice Each CBOM (Cryptographic Bill of Materials) is registered by an org.
///         Only the CBOM hash is stored on-chain; the full CBOM is off-chain (IPFS or S3).
contract AssetRegistry is AccessControl, ReentrancyGuard {

    // ============ Errors ============
    error AssetNotFound(bytes32 assetId);
    error AssetAlreadyExists(bytes32 assetId);
    error NotAssetOwner(address caller);
    error EmptyHash();

    // ============ Events ============
    event CBOMRegistered(
        bytes32 indexed assetId,
        address indexed orgDid,
        bytes32 cbomHash,
        string  metadataURI,
        uint256 timestamp
    );

    event CBOMUpdated(
        bytes32 indexed assetId,
        bytes32 newCbomHash,
        string  newMetadataURI,
        uint256 timestamp
    );

    // ============ Structs ============
    struct Asset {
        address orgDid;          // Organization that registered this CBOM
        bytes32 cbomHash;        // SHA-256 of the full CBOM JSON
        string  metadataURI;     // IPFS URI for the full CBOM (or empty if private)
        uint256 registeredAt;
        uint256 lastUpdated;
        bool    active;
    }

    // ============ State ============
    mapping(bytes32 => Asset) private _assets;             // assetId => Asset
    bytes32[] private _allAssetIds;                         // all asset IDs
    mapping(address => bytes32[]) private _assetsByOrg;     // org => asset IDs

    bytes32 public constant ASSET_OWNER_ROLE = keccak256("ASSET_OWNER_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ASSET_OWNER_ROLE, msg.sender);
    }

    /// @notice Register a new CBOM
    /// @param cbomHash     SHA-256 hash of the full CBOM JSON
    /// @param metadataURI  IPFS URI (ipfs://...) or empty string if private
    /// @return assetId     The ID under which this asset is stored
    function registerCBOM(
        bytes32 cbomHash,
        string calldata metadataURI
    ) external nonReentrant onlyRole(ASSET_OWNER_ROLE) returns (bytes32 assetId) {
        if (cbomHash == bytes32(0)) revert EmptyHash();

        assetId = keccak256(abi.encodePacked(msg.sender, cbomHash, block.timestamp));

        if (_assets[assetId].orgDid != address(0)) revert AssetAlreadyExists(assetId);

        _assets[assetId] = Asset({
            orgDid: msg.sender,
            cbomHash: cbomHash,
            metadataURI: metadataURI,
            registeredAt: block.timestamp,
            lastUpdated: block.timestamp,
            active: true
        });

        _allAssetIds.push(assetId);
        _assetsByOrg[msg.sender].push(assetId);

        emit CBOMRegistered(assetId, msg.sender, cbomHash, metadataURI, block.timestamp);
    }

    /// @notice Update a CBOM (re-scan after migration)
    function updateCBOM(
        bytes32 assetId,
        bytes32 newCbomHash,
        string calldata newMetadataURI
    ) external nonReentrant {
        Asset storage asset = _assets[assetId];
        if (asset.orgDid == address(0)) revert AssetNotFound(assetId);
        if (asset.orgDid != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAssetOwner(msg.sender);
        }
        asset.cbomHash = newCbomHash;
        asset.metadataURI = newMetadataURI;
        asset.lastUpdated = block.timestamp;

        emit CBOMUpdated(assetId, newCbomHash, newMetadataURI, block.timestamp);
    }

    /// @notice Deactivate a CBOM (e.g., after full migration)
    function deactivateAsset(bytes32 assetId) external {
        Asset storage asset = _assets[assetId];
        if (asset.orgDid == address(0)) revert AssetNotFound(assetId);
        if (asset.orgDid != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAssetOwner(msg.sender);
        }
        asset.active = false;
    }

    // ============ View Functions ============

    function getAsset(bytes32 assetId) external view returns (Asset memory) {
        if (_assets[assetId].orgDid == address(0)) revert AssetNotFound(assetId);
        return _assets[assetId];
    }

    function assetCount() external view returns (uint256) {
        return _allAssetIds.length;
    }

    function getAssetsByOrg(address orgDid) external view returns (bytes32[] memory) {
        return _assetsByOrg[orgDid];
    }

    function getAllAssetIds(uint256 offset, uint256 limit)
        external view returns (bytes32[] memory page, uint256 total)
    {
        total = _allAssetIds.length;
        if (offset >= total) return (new bytes32[](0), total);
        uint256 end = offset + limit;
        if (end > total) end = total;
        uint256 pageSize = end - offset;
        page = new bytes32[](pageSize);
        for (uint256 i = 0; i < pageSize; i++) {
            page[i] = _allAssetIds[offset + i];
        }
    }
}
```

### 4.3 VendorRegistry.sol

Create `src/VendorRegistry.sol`:

```solidity
// /home/z/qtrust/contracts/src/VendorRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title VendorRegistry — vendors post PQC readiness attestations for their products
/// @notice Vendors (DigiCert, Thales, AWS, etc.) post attestations like:
///         "Product X version Y supports ML-DSA-441 since 2024-Q4"
contract VendorRegistry is AccessControl, ReentrancyGuard {

    error AttestationNotFound(bytes32 attestationId);
    error DuplicateAttestation(bytes32 attestationId);
    error NotVendor(address caller);
    error VendorNotRegistered(address vendorDid);

    event VendorRegistered(address indexed vendorDid, string name, string metadataURI, uint256 timestamp);
    event ProductAttested(
        bytes32 indexed attestationId,
        address indexed vendorDid,
        bytes32 indexed productHash,   // hash of productId + version
        string  productId,
        string  version,
        string  algorithm,             // e.g., "ML-DSA-441", "ML-KEM-512"
        bool    supported,
        string  evidenceURI,            // IPFS URI for test evidence
        uint256 timestamp
    );
    event AttestationRevoked(bytes32 indexed attestationId, uint256 timestamp);

    struct Vendor {
        string name;
        string metadataURI;
        uint256 registeredAt;
        bool active;
    }

    struct ProductAttestation {
        address vendorDid;
        bytes32 productHash;
        string  productId;
        string  version;
        string  algorithm;
        bool    supported;
        string  evidenceURI;
        uint256 timestamp;
        bool    revoked;
    }

    mapping(address => Vendor) private _vendors;
    mapping(bytes32 => ProductAttestation) private _attestations;
    mapping(bytes32 => bytes32[]) private _attestationsByProduct; // productHash => attestation IDs

    bytes32 public constant VENDOR_ROLE = keccak256("VENDOR_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Register a new vendor (admin only — Q-Trust performs KYC first)
    function registerVendor(
        address vendorDid,
        string calldata name,
        string calldata metadataURI
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_vendors[vendorDid].registeredAt == 0, "Vendor already registered");
        _vendors[vendorDid] = Vendor({
            name: name,
            metadataURI: metadataURI,
            registeredAt: block.timestamp,
            active: true
        });
        _grantRole(VENDOR_ROLE, vendorDid);
        emit VendorRegistered(vendorDid, name, metadataURI, block.timestamp);
    }

    /// @notice Vendor posts a product PQC attestation
    function attestProduct(
        bytes32 attestationId,
        string calldata productId,
        string calldata version,
        string calldata algorithm,
        bool supported,
        string calldata evidenceURI
    ) external nonReentrant onlyRole(VENDOR_ROLE) {
        if (_vendors[msg.sender].registeredAt == 0) revert VendorNotRegistered(msg.sender);
        if (_attestations[attestationId].vendorDid != address(0)) revert DuplicateAttestation(attestationId);

        bytes32 productHash = keccak256(abi.encodePacked(productId, version));

        _attestations[attestationId] = ProductAttestation({
            vendorDid: msg.sender,
            productHash: productHash,
            productId: productId,
            version: version,
            algorithm: algorithm,
            supported: supported,
            evidenceURI: evidenceURI,
            timestamp: block.timestamp,
            revoked: false
        });

        _attestationsByProduct[productHash].push(attestationId);

        emit ProductAttested(
            attestationId, msg.sender, productHash,
            productId, version, algorithm, supported, evidenceURI, block.timestamp
        );
    }

    /// @notice Vendor revokes an attestation (e.g., if vulnerability found)
    function revokeAttestation(bytes32 attestationId) external nonReentrant {
        ProductAttestation storage att = _attestations[attestationId];
        if (att.vendorDid == address(0)) revert AttestationNotFound(attestationId);
        if (att.vendorDid != msg.sender && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotVendor(msg.sender);
        }
        att.revoked = true;
        emit AttestationRevoked(attestationId, block.timestamp);
    }

    // ============ View Functions ============

    function getVendor(address vendorDid) external view returns (Vendor memory) {
        require(_vendors[vendorDid].registeredAt != 0, "Vendor not found");
        return _vendors[vendorDid];
    }

    function getAttestation(bytes32 attestationId) external view returns (ProductAttestation memory) {
        if (_attestations[attestationId].vendorDid == address(0)) revert AttestationNotFound(attestationId);
        return _attestations[attestationId];
    }

    function getAttestationsByProduct(string calldata productId, string calldata version)
        external view returns (bytes32[] memory)
    {
        bytes32 productHash = keccak256(abi.encodePacked(productId, version));
        return _attestationsByProduct[productHash];
    }

    function isVendorRegistered(address vendorDid) external view returns (bool) {
        return _vendors[vendorDid].registeredAt != 0;
    }
}
```

### 4.4 MigrationRegistry.sol

Create `src/MigrationRegistry.sol`:

```solidity
// /home/z/qtrust/contracts/src/MigrationRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title MigrationRegistry — records each PQC migration step
/// @notice Each step is one asset migrating from one algorithm to another.
///         Evidence (e.g., HSM log) is stored off-chain; only its hash is on-chain.
contract MigrationRegistry is AccessControl, ReentrancyGuard {

    error MigrationNotFound(bytes32 migrationId);
    error DuplicateMigration(bytes32 migrationId);
    error NotMigrator(address caller);

    event MigrationRecorded(
        bytes32 indexed migrationId,
        bytes32 indexed assetId,
        address indexed orgDid,
        string  fromAlgorithm,
        string  toAlgorithm,
        bytes32 evidenceHash,
        string  evidenceURI,
        uint256 timestamp
    );

    struct Migration {
        bytes32 assetId;        // Reference to AssetRegistry entry
        address orgDid;
        string  fromAlgorithm;  // e.g., "RSA-2048"
        string  toAlgorithm;    // e.g., "ML-DSA-441"
        bytes32 evidenceHash;    // Hash of migration evidence (HSM logs, etc.)
        string  evidenceURI;    // IPFS URI for evidence
        uint256 timestamp;
        bool    verified;       // True if auditor verified this migration
    }

    mapping(bytes32 => Migration) private _migrations;
    mapping(bytes32 => bytes32[]) private _migrationsByAsset;   // assetId => migration IDs
    mapping(address => bytes32[]) private _migrationsByOrg;    // org => migration IDs

    bytes32 public constant MIGRATOR_ROLE = keccak256("MIGRATOR_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MIGRATOR_ROLE, msg.sender);
    }

    /// @notice Record a migration step
    function recordMigration(
        bytes32 migrationId,
        bytes32 assetId,
        string calldata fromAlgorithm,
        string calldata toAlgorithm,
        bytes32 evidenceHash,
        string calldata evidenceURI
    ) external nonReentrant onlyRole(MIGRATOR_ROLE) {
        if (_migrations[migrationId].orgDid != address(0)) revert DuplicateMigration(migrationId);

        _migrations[migrationId] = Migration({
            assetId: assetId,
            orgDid: msg.sender,
            fromAlgorithm: fromAlgorithm,
            toAlgorithm: toAlgorithm,
            evidenceHash: evidenceHash,
            evidenceURI: evidenceURI,
            timestamp: block.timestamp,
            verified: false
        });

        _migrationsByAsset[assetId].push(migrationId);
        _migrationsByOrg[msg.sender].push(migrationId);

        emit MigrationRecorded(
            migrationId, assetId, msg.sender,
            fromAlgorithm, toAlgorithm, evidenceHash, evidenceURI, block.timestamp
        );
    }

    /// @notice Auditor marks a migration as verified
    function verifyMigration(bytes32 migrationId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_migrations[migrationId].orgDid == address(0)) revert MigrationNotFound(migrationId);
        _migrations[migrationId].verified = true;
    }

    // ============ View Functions ============

    function getMigration(bytes32 migrationId) external view returns (Migration memory) {
        if (_migrations[migrationId].orgDid == address(0)) revert MigrationNotFound(migrationId);
        return _migrations[migrationId];
    }

    function getMigrationsByAsset(bytes32 assetId) external view returns (bytes32[] memory) {
        return _migrationsByAsset[assetId];
    }

    function getMigrationsByOrg(address orgDid) external view returns (bytes32[] memory) {
        return _migrationsByOrg[orgDid];
    }

    function migrationCount() external view returns (uint256) {
        return _migrationsByOrg[msg.sender].length;
    }
}
```

### 4.5 AuditRegistry.sol

Create `src/AuditRegistry.sol`:

```solidity
// /home/z/qtrust/contracts/src/AuditRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

/// @title AuditRegistry — third-party audit attestations
/// @notice Auditors post attestations that they reviewed an org's PQC migration
///         and assigned a result (Passed / Failed / Conditional).
contract AuditRegistry is AccessControl {

    error AuditNotFound(bytes32 auditId);
    error DuplicateAudit(bytes32 auditId);
    error NotAuditor(address caller);

    event AuditPosted(
        bytes32 indexed auditId,
        address indexed orgDid,
        address indexed auditorDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsPassed,
        bytes32 reportHash,
        string  reportURI,
        uint256 timestamp
    );

    enum AuditResult { Pending, Passed, Failed, Conditional }

    struct Audit {
        address orgDid;
        address auditorDid;
        AuditResult result;
        uint256 assetsReviewed;
        uint256 assetsPassed;
        bytes32 reportHash;
        string  reportURI;
        uint256 timestamp;
    }

    mapping(bytes32 => Audit) private _audits;
    mapping(address => bytes32[]) private _auditsByOrg;
    mapping(address => bytes32[]) private _auditsByAuditor;

    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function postAudit(
        bytes32 auditId,
        address orgDid,
        AuditResult result,
        uint256 assetsReviewed,
        uint256 assetsPassed,
        bytes32 reportHash,
        string calldata reportURI
    ) external onlyRole(AUDITOR_ROLE) {
        if (_audits[auditId].auditorDid != address(0)) revert DuplicateAudit(auditId);

        _audits[auditId] = Audit({
            orgDid: orgDid,
            auditorDid: msg.sender,
            result: result,
            assetsReviewed: assetsReviewed,
            assetsPassed: assetsPassed,
            reportHash: reportHash,
            reportURI: reportURI,
            timestamp: block.timestamp
        });

        _auditsByOrg[orgDid].push(auditId);
        _auditsByAuditor[msg.sender].push(auditId);

        emit AuditPosted(
            auditId, orgDid, msg.sender, result,
            assetsReviewed, assetsPassed, reportHash, reportURI, block.timestamp
        );
    }

    function getAudit(bytes32 auditId) external view returns (Audit memory) {
        if (_audits[auditId].auditorDid == address(0)) revert AuditNotFound(auditId);
        return _audits[auditId];
    }

    function getAuditsByOrg(address orgDid) external view returns (bytes32[] memory) {
        return _auditsByOrg[orgDid];
    }

    function getAuditsByAuditor(address auditorDid) external view returns (bytes32[] memory) {
        return _auditsByAuditor[auditorDid];
    }
}
```

### 4.6 Tests

Create `test/AssetRegistry.t.sol`:

```solidity
// /home/z/qtrust/contracts/test/AssetRegistry.t.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/AssetRegistry.sol";

contract AssetRegistryTest is Test {
    AssetRegistry public registry;

    address orgOwner = address(0xA11CE);
    address orgSigner = address(0xB0B);
    address unauthorized = address(0xEVE);

    bytes32 constant CBOM_HASH = keccak256("cbom-v1");
    string constant METADATA_URI = "ipfs://QmTestCBOM";

    function setUp() public {
        registry = new AssetRegistry();
        registry.grantRole(registry.ASSET_OWNER_ROLE(), orgSigner);
    }

    function test_RegisterCBOM() public {
        vm.prank(orgSigner);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);

        assertTrue(assetId != bytes32(0), "asset ID should be non-zero");

        AssetRegistry.Asset memory asset = registry.getAsset(assetId);
        assertEq(asset.orgDid, orgSigner, "orgDid should match signer");
        assertEq(asset.cbomHash, CBOM_HASH, "cbomHash should match");
        assertEq(asset.metadataURI, METADATA_URI, "metadataURI should match");
        assertTrue(asset.active, "asset should be active");
    }

    function test_RevertWhen_NotAssetOwner() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        registry.registerCBOM(CBOM_HASH, METADATA_URI);
    }

    function test_RevertWhen_EmptyHash() public {
        vm.prank(orgSigner);
        vm.expectRevert(AssetRegistry.EmptyHash.selector);
        registry.registerCBOM(bytes32(0), METADATA_URI);
    }

    function test_UpdateCBOM() public {
        vm.prank(orgSigner);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);

        bytes32 newHash = keccak256("cbom-v2");
        vm.prank(orgSigner);
        registry.updateCBOM(assetId, newHash, "ipfs://QmTestCBOMv2");

        AssetRegistry.Asset memory asset = registry.getAsset(assetId);
        assertEq(asset.cbomHash, newHash, "cbomHash should be updated");
    }

    function test_DeactivateAsset() public {
        vm.prank(orgSigner);
        bytes32 assetId = registry.registerCBOM(CBOM_HASH, METADATA_URI);

        vm.prank(orgSigner);
        registry.deactivateAsset(assetId);

        AssetRegistry.Asset memory asset = registry.getAsset(assetId);
        assertFalse(asset.active, "asset should be deactivated");
    }

    function test_GetAssetsByOrg() public {
        vm.startPrank(orgSigner);
        registry.registerCBOM(CBOM_HASH, METADATA_URI);
        vm.warp(block.timestamp + 1);
        registry.registerCBOM(keccak256("cbom-v2"), METADATA_URI);
        vm.stopPrank();

        bytes32[] memory orgAssets = registry.getAssetsByOrg(orgSigner);
        assertEq(orgAssets.length, 2, "should have 2 assets");
    }

    function test_AssetCount() public {
        assertEq(registry.assetCount(), 0);
        vm.prank(orgSigner);
        registry.registerCBOM(CBOM_HASH, METADATA_URI);
        assertEq(registry.assetCount(), 1);
    }
}
```

Create `test/VendorRegistry.t.sol`:

```solidity
// /home/z/qtrust/contracts/test/VendorRegistry.t.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/VendorRegistry.sol";

contract VendorRegistryTest is Test {
    VendorRegistry public registry;

    address admin = address(0xADM1N);
    address vendor = address(0xVEND0R);
    address nonVendor = address(0xEVE);

    function setUp() public {
        registry = new VendorRegistry();
        // Note: constructor grants DEFAULT_ADMIN_ROLE to msg.sender (this test contract)
    }

    function test_RegisterVendor() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");

        VendorRegistry.Vendor memory v = registry.getVendor(vendor);
        assertEq(v.name, "DigiCert", "name should match");
        assertTrue(registry.isVendorRegistered(vendor), "vendor should be registered");
    }

    function test_AttestProduct() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");

        bytes32 attestationId = keccak256("attestation-1");
        vm.prank(vendor);
        registry.attestProduct(
            attestationId,
            "DigiCert TLS Certificate",
            "5.2.1",
            "ML-DSA-441",
            true,
            "ipfs://QmEvidence"
        );

        VendorRegistry.ProductAttestation memory att = registry.getAttestation(attestationId);
        assertEq(att.vendorDid, vendor, "vendorDid should match");
        assertTrue(att.supported, "should be supported");
        assertEq(att.algorithm, "ML-DSA-441", "algorithm should match");
    }

    function test_RevertWhen_NonVendorAttests() public {
        vm.prank(nonVendor);
        vm.expectRevert();
        registry.attestProduct(
            keccak256("attestation-1"),
            "Product",
            "1.0",
            "ML-DSA-441",
            true,
            "ipfs://QmEvidence"
        );
    }

    function test_RevokeAttestation() public {
        registry.registerVendor(vendor, "DigiCert", "ipfs://QmDigiCert");

        bytes32 attestationId = keccak256("attestation-1");
        vm.prank(vendor);
        registry.attestProduct(attestationId, "Product", "1.0", "ML-DSA-441", true, "ipfs://QmEvidence");

        vm.prank(vendor);
        registry.revokeAttestation(attestationId);

        VendorRegistry.ProductAttestation memory att = registry.getAttestation(attestationId);
        assertTrue(att.revoked, "attestation should be revoked");
    }
}
```

Create `test/MigrationRegistry.t.sol`:

```solidity
// /home/z/qtrust/contracts/test/MigrationRegistry.t.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import "../src/MigrationRegistry.sol";

contract MigrationRegistryTest is Test {
    MigrationRegistry public registry;
    address migrator = address(0xB0B);

    bytes32 constant ASSET_ID = keccak256("asset-1");
    bytes32 constant EVIDENCE_HASH = keccak256("evidence-1");

    function setUp() public {
        registry = new MigrationRegistry();
        registry.grantRole(registry.MIGRATOR_ROLE(), migrator);
    }

    function test_RecordMigration() public {
        bytes32 migrationId = keccak256("migration-1");
        vm.prank(migrator);
        registry.recordMigration(
            migrationId,
            ASSET_ID,
            "RSA-2048",
            "ML-DSA-441",
            EVIDENCE_HASH,
            "ipfs://QmEvidence"
        );

        MigrationRegistry.Migration memory m = registry.getMigration(migrationId);
        assertEq(m.assetId, ASSET_ID, "assetId should match");
        assertEq(m.fromAlgorithm, "RSA-2048", "fromAlgorithm should match");
        assertEq(m.toAlgorithm, "ML-DSA-441", "toAlgorithm should match");
        assertFalse(m.verified, "should not be verified by default");
    }

    function test_VerifyMigration() public {
        bytes32 migrationId = keccak256("migration-1");
        vm.prank(migrator);
        registry.recordMigration(migrationId, ASSET_ID, "RSA-2048", "ML-DSA-441", EVIDENCE_HASH, "ipfs://QmEvidence");

        registry.verifyMigration(migrationId);

        MigrationRegistry.Migration memory m = registry.getMigration(migrationId);
        assertTrue(m.verified, "should be verified");
    }

    function test_GetMigrationsByAsset() public {
        vm.startPrank(migrator);
        registry.recordMigration(keccak256("m1"), ASSET_ID, "RSA-2048", "ML-DSA-441", EVIDENCE_HASH, "ipfs://QmEvidence");
        registry.recordMigration(keccak256("m2"), ASSET_ID, "ECC-P256", "ML-KEM-512", EVIDENCE_HASH, "ipfs://QmEvidence");
        vm.stopPrank();

        bytes32[] memory migrations = registry.getMigrationsByAsset(ASSET_ID);
        assertEq(migrations.length, 2, "should have 2 migrations");
    }
}
```

### 4.7 Deployment Script

Create `script/Deploy.s.sol`:

```solidity
// /home/z/qtrust/contracts/script/Deploy.s.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Script.sol";
import "../src/AssetRegistry.sol";
import "../src/VendorRegistry.sol";
import "../src/MigrationRegistry.sol";
import "../src/AuditRegistry.sol";

contract Deployer is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("QTRUST_DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        AssetRegistry assets = new AssetRegistry();
        VendorRegistry vendors = new VendorRegistry();
        MigrationRegistry migrations = new MigrationRegistry();
        AuditRegistry audits = new AuditRegistry();

        console2.log("AssetRegistry deployed at:     ", address(assets));
        console2.log("VendorRegistry deployed at:    ", address(vendors));
        console2.log("MigrationRegistry deployed at: ", address(migrations));
        console2.log("AuditRegistry deployed at:     ", address(audits));

        vm.stopBroadcast();
    }
}
```

### 4.8 Run Tests and Deploy

```bash
cd /home/z/qtrust/contracts
forge test -vv

# Expected: 10+ tests passing, 0 failing
```

Deploy to Base Sepolia:

```bash
cd /home/z/qtrust/contracts
forge script script/Deploy.s.sol:Deployer \
  --rpc-url $QTRUST_BASE_SEPOLIA_RPC \
  --private-key $QTRUST_DEPLOYER_PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $QTRUST_BASESCAN_API_KEY \
  --chain-id 84532
```

Save the deployed addresses to BrevLab env vars:

```
QTRUST_ASSET_REGISTRY_ADDRESS = 0x...
QTRUST_VENDOR_REGISTRY_ADDRESS = 0x...
QTRUST_MIGRATION_REGISTRY_ADDRESS = 0x...
QTRUST_AUDIT_REGISTRY_ADDRESS = 0x...
```

Then:

```bash
source ~/.bashrc
echo $QTRUST_ASSET_REGISTRY_ADDRESS   # verify non-empty
```

Commit:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 1: smart contracts deployed to Base Sepolia"
git push
```

---

## 5. Phase 2: Python SDK

### 5.1 SDK Package Structure

```bash
cd /home/z/qtrust
mkdir -p sdk/qtrust sdk/tests
cd sdk
echo "# Q-Trust SDK" > README.md
```

Create `sdk/pyproject.toml`:

```toml
# /home/z/qtrust/sdk/pyproject.toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "qtrust-sdk"
version = "0.1.0"
description = "Python SDK for the Q-Trust PQC migration coordination protocol"
readme = "README.md"
requires-python = ">=3.10"
license = {text = "MIT"}
authors = [{name = "Q-Trust Team", email = "team@qtrust.xyz"}]
dependencies = [
    "web3>=6.15.0",
    "eth-account>=0.11.0",
    "eth-abi>=5.0.0",
    "pydantic>=2.6.0",
    "requests>=2.31.0",
    "python-dotenv>=1.0.0",
    "cryptography>=42.0.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-cov", "ruff", "mypy"]

[project.urls]
Homepage = "https://qtrust.xyz"
Repository = "https://github.com/your-username/qtrust"

[tool.setuptools.packages.find]
where = ["."]
include = ["qtrust*"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py310"
```

### 5.2 Pydantic Schemas

Create `sdk/qtrust/schema.py`:

```python
# /home/z/qtrust/sdk/qtrust/schema.py
"""Pydantic models for Q-Trust attestation objects."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, field_validator


def _validate_hash(v: str) -> str:
    """Ensure a hash is a 0x-prefixed 64-char hex string."""
    if not v.startswith("0x"):
        raise ValueError("hash must start with 0x")
    if len(v) != 66:
        raise ValueError(f"hash must be 32 bytes (66 chars), got {len(v)}")
    try:
        bytes.fromhex(v[2:])
    except ValueError as e:
        raise ValueError(f"hash is not valid hex: {e}")
    return v.lower()


class CBOMEntry(BaseModel):
    """A single cryptographic asset in a CBOM."""
    asset_type: str = Field(..., description="tls_cert | ssh_key | code_signing | hsm | jwt | other")
    algorithm: str = Field(..., description="e.g., RSA-2048, ECC-P256, ML-DSA-441")
    location: str = Field(..., description="Hostname, file path, or service identifier")
    vendor: Optional[str] = Field(None, description="Vendor if known (e.g., DigiCert)")
    product: Optional[str] = Field(None, description="Product ID if known")
    version: Optional[str] = Field(None, description="Product version")
    criticality: str = Field("medium", description="low | medium | high | critical")
    expires_at: Optional[int] = Field(None, description="Unix timestamp of expiry, if applicable")


class CBOM(BaseModel):
    """A Cryptographic Bill of Materials."""
    schema_version: str = Field(default="cbom.v1")
    org_did: str = Field(..., description="Organization DID")
    generated_at: int = Field(..., description="Unix timestamp of CBOM generation")
    scanner_version: str = Field(..., description="Version of the scanner that produced this CBOM")
    assets: list[CBOMEntry] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict, description="Summary stats")


class AssetRecord(BaseModel):
    """An asset record as returned by the on-chain AssetRegistry."""
    asset_id: str
    org_did: str
    cbom_hash: str
    metadata_uri: str
    registered_at: int
    last_updated: int
    active: bool

    @property
    def datetime(self) -> datetime:
        return datetime.fromtimestamp(self.registered_at, tz=timezone.utc)


class VendorInfo(BaseModel):
    name: str
    metadata_uri: str
    registered_at: int
    active: bool


class ProductAttestation(BaseModel):
    attestation_id: str
    vendor_did: str
    product_id: str
    version: str
    algorithm: str
    supported: bool
    evidence_uri: str
    timestamp: int
    revoked: bool


class MigrationRecord(BaseModel):
    migration_id: str
    asset_id: str
    org_did: str
    from_algorithm: str
    to_algorithm: str
    evidence_hash: str
    evidence_uri: str
    timestamp: int
    verified: bool
```

### 5.3 IPFS Pinning

Create `sdk/qtrust/ipfs.py`:

```python
# /home/z/qtrust/sdk/qtrust/ipfs.py
"""Pinata IPFS pinning client."""
from __future__ import annotations
import json
import requests
from typing import Optional


class PinataClient:
    """Pins files and JSON to IPFS via the Pinata API."""

    BASE_URL = "https://api.pinata.cloud"

    def __init__(self, api_key: str, api_secret: str):
        self.api_key = api_key
        self.api_secret = api_secret
        self.headers = {
            "pinata_api_key": api_key,
            "pinata_secret_api_key": api_secret,
        }

    def pin_json(self, json_str: str, name: Optional[str] = None) -> str:
        """Pin a JSON string to IPFS. Returns the CID."""
        url = f"{self.BASE_URL}/pinning/pinJSONToIPFS"
        payload = {"pinataContent": json.loads(json_str)}
        if name:
            payload["pinataMetadata"] = {"name": name}
        response = requests.post(url, json=payload, headers=self.headers, timeout=30)
        response.raise_for_status()
        return response.json()["IpfsHash"]

    def pin_file(self, file_path: str, name: Optional[str] = None) -> str:
        """Pin a binary file to IPFS. Returns the CID."""
        url = f"{self.BASE_URL}/pinning/pinFileToIPFS"
        with open(file_path, "rb") as f:
            files = {"file": (name or file_path.split("/")[-1], f)}
            metadata = {"name": name or file_path.split("/")[-1]}
            response = requests.post(
                url,
                files=files,
                data={"pinataMetadata": json.dumps(metadata)},
                headers=self.headers,
                timeout=300,
            )
        response.raise_for_status()
        return response.json()["IpfsHash"]

    def unpin(self, cid: str) -> bool:
        """Unpin a file from IPFS."""
        url = f"{self.BASE_URL}/pinning/unpin/{cid}"
        response = requests.delete(url, headers=self.headers, timeout=30)
        return response.status_code == 200
```

### 5.4 Contract ABIs

Create `sdk/qtrust/contracts.py`:

```python
# /home/z/qtrust/sdk/qtrust/contracts.py
"""ABI definitions for Q-Trust smart contracts."""

ASSET_REGISTRY_ABI = [
    {"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
    {"anonymous": False, "inputs": [
        {"indexed": True, "internalType": "bytes32", "name": "assetId", "type": "bytes32"},
        {"indexed": True, "internalType": "address", "name": "orgDid", "type": "address"},
        {"indexed": False, "internalType": "bytes32", "name": "cbomHash", "type": "bytes32"},
        {"indexed": False, "internalType": "string", "name": "metadataURI", "type": "string"},
        {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
    ], "name": "CBOMRegistered", "type": "event"},
    {"inputs": [], "name": "ASSET_OWNER_ROLE",
     "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "cbomHash", "type": "bytes32"},
                {"internalType": "string", "name": "metadataURI", "type": "string"}],
     "name": "registerCBOM",
     "outputs": [{"internalType": "bytes32", "name": "assetId", "type": "bytes32"}],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "assetId", "type": "bytes32"},
                {"internalType": "bytes32", "name": "newCbomHash", "type": "bytes32"},
                {"internalType": "string", "name": "newMetadataURI", "type": "string"}],
     "name": "updateCBOM", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "assetId", "type": "bytes32"}],
     "name": "deactivateAsset", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "assetId", "type": "bytes32"}],
     "name": "getAsset",
     "outputs": [
        {"internalType": "address", "name": "orgDid", "type": "address"},
        {"internalType": "bytes32", "name": "cbomHash", "type": "bytes32"},
        {"internalType": "string", "name": "metadataURI", "type": "string"},
        {"internalType": "uint256", "name": "registeredAt", "type": "uint256"},
        {"internalType": "uint256", "name": "lastUpdated", "type": "uint256"},
        {"internalType": "bool", "name": "active", "type": "bool"}
     ], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "assetCount",
     "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "orgDid", "type": "address"}],
     "name": "getAssetsByOrg",
     "outputs": [{"internalType": "bytes32[]", "name": "", "type": "bytes32[]"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "role", "type": "bytes32"},
                {"internalType": "address", "name": "account", "type": "address"}],
     "name": "grantRole", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
]


VENDOR_REGISTRY_ABI = [
    {"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
    {"inputs": [{"internalType": "address", "name": "vendorDid", "type": "address"},
                {"internalType": "string", "name": "name", "type": "string"},
                {"internalType": "string", "name": "metadataURI", "type": "string"}],
     "name": "registerVendor", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "attestationId", "type": "bytes32"},
                {"internalType": "string", "name": "productId", "type": "string"},
                {"internalType": "string", "name": "version", "type": "string"},
                {"internalType": "string", "name": "algorithm", "type": "string"},
                {"internalType": "bool", "name": "supported", "type": "bool"},
                {"internalType": "string", "name": "evidenceURI", "type": "string"}],
     "name": "attestProduct", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "attestationId", "type": "bytes32"}],
     "name": "revokeAttestation", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "vendorDid", "type": "address"}],
     "name": "getVendor",
     "outputs": [
        {"internalType": "string", "name": "name", "type": "string"},
        {"internalType": "string", "name": "metadataURI", "type": "string"},
        {"internalType": "uint256", "name": "registeredAt", "type": "uint256"},
        {"internalType": "bool", "name": "active", "type": "bool"}
     ], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "attestationId", "type": "bytes32"}],
     "name": "getAttestation",
     "outputs": [
        {"internalType": "address", "name": "vendorDid", "type": "address"},
        {"internalType": "bytes32", "name": "productHash", "type": "bytes32"},
        {"internalType": "string", "name": "productId", "type": "string"},
        {"internalType": "string", "name": "version", "type": "string"},
        {"internalType": "string", "name": "algorithm", "type": "string"},
        {"internalType": "bool", "name": "supported", "type": "bool"},
        {"internalType": "string", "name": "evidenceURI", "type": "string"},
        {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        {"internalType": "bool", "name": "revoked", "type": "bool"}
     ], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "string", "name": "productId", "type": "string"},
                {"internalType": "string", "name": "version", "type": "string"}],
     "name": "getAttestationsByProduct",
     "outputs": [{"internalType": "bytes32[]", "name": "", "type": "bytes32[]"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "vendorDid", "type": "address"}],
     "name": "isVendorRegistered",
     "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
     "stateMutability": "view", "type": "function"},
]


MIGRATION_REGISTRY_ABI = [
    {"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
    {"inputs": [{"internalType": "bytes32", "name": "migrationId", "type": "bytes32"},
                {"internalType": "bytes32", "name": "assetId", "type": "bytes32"},
                {"internalType": "string", "name": "fromAlgorithm", "type": "string"},
                {"internalType": "string", "name": "toAlgorithm", "type": "string"},
                {"internalType": "bytes32", "name": "evidenceHash", "type": "bytes32"},
                {"internalType": "string", "name": "evidenceURI", "type": "string"}],
     "name": "recordMigration", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "migrationId", "type": "bytes32"}],
     "name": "verifyMigration", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "migrationId", "type": "bytes32"}],
     "name": "getMigration",
     "outputs": [
        {"internalType": "bytes32", "name": "assetId", "type": "bytes32"},
        {"internalType": "address", "name": "orgDid", "type": "address"},
        {"internalType": "string", "name": "fromAlgorithm", "type": "string"},
        {"internalType": "string", "name": "toAlgorithm", "type": "string"},
        {"internalType": "bytes32", "name": "evidenceHash", "type": "bytes32"},
        {"internalType": "string", "name": "evidenceURI", "type": "string"},
        {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        {"internalType": "bool", "name": "verified", "type": "bool"}
     ], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "assetId", "type": "bytes32"}],
     "name": "getMigrationsByAsset",
     "outputs": [{"internalType": "bytes32[]", "name": "", "type": "bytes32[]"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "orgDid", "type": "address"}],
     "name": "getMigrationsByOrg",
     "outputs": [{"internalType": "bytes32[]", "name": "", "type": "bytes32[]"}],
     "stateMutability": "view", "type": "function"},
]


AUDIT_REGISTRY_ABI = [
    {"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
    {"inputs": [{"internalType": "bytes32", "name": "auditId", "type": "bytes32"},
                {"internalType": "address", "name": "orgDid", "type": "address"},
                {"internalType": "uint8", "name": "result", "type": "uint8"},
                {"internalType": "uint256", "name": "assetsReviewed", "type": "uint256"},
                {"internalType": "uint256", "name": "assetsPassed", "type": "uint256"},
                {"internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
                {"internalType": "string", "name": "reportURI", "type": "string"}],
     "name": "postAudit", "outputs": [],
     "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "auditId", "type": "bytes32"}],
     "name": "getAudit",
     "outputs": [
        {"internalType": "address", "name": "orgDid", "type": "address"},
        {"internalType": "address", "name": "auditorDid", "type": "address"},
        {"internalType": "uint8", "name": "result", "type": "uint8"},
        {"internalType": "uint256", "name": "assetsReviewed", "type": "uint256"},
        {"internalType": "uint256", "name": "assetsPassed", "type": "uint256"},
        {"internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
        {"internalType": "string", "name": "reportURI", "type": "string"},
        {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
     ], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "orgDid", "type": "address"}],
     "name": "getAuditsByOrg",
     "outputs": [{"internalType": "bytes32[]", "name": "", "type": "bytes32[]"}],
     "stateMutability": "view", "type": "function"},
]
```

### 5.5 The Client Class

Create `sdk/qtrust/client.py`:

```python
# /home/z/qtrust/sdk/qtrust/client.py
"""Q-Trust SDK client — talks to the Q-Trust smart contracts on Base."""
from __future__ import annotations
import hashlib
import json
import os
from typing import Optional
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from eth_account import Account

from .schema import CBOM, AssetRecord, VendorInfo, ProductAttestation, MigrationRecord
from .ipfs import PinataClient
from .contracts import (
    ASSET_REGISTRY_ABI,
    VENDOR_REGISTRY_ABI,
    MIGRATION_REGISTRY_ABI,
    AUDIT_REGISTRY_ABI,
)


BASE_SEPOLIA_CHAIN_ID = 84532


class QTrustClient:
    """High-level client for posting and verifying Q-Trust attestations."""

    def __init__(
        self,
        private_key: Optional[str] = None,
        rpc_url: Optional[str] = None,
        asset_registry_address: Optional[str] = None,
        vendor_registry_address: Optional[str] = None,
        migration_registry_address: Optional[str] = None,
        audit_registry_address: Optional[str] = None,
        ipfs_api_key: Optional[str] = None,
        ipfs_api_secret: Optional[str] = None,
    ):
        self.private_key = private_key or os.environ["QTRUST_DEPLOYER_PRIVATE_KEY"]
        self.rpc_url = rpc_url or os.environ["QTRUST_BASE_SEPOLIA_RPC"]
        self.asset_registry_address = (
            asset_registry_address or os.environ["QTRUST_ASSET_REGISTRY_ADDRESS"]
        )
        self.vendor_registry_address = (
            vendor_registry_address or os.environ["QTRUST_VENDOR_REGISTRY_ADDRESS"]
        )
        self.migration_registry_address = (
            migration_registry_address or os.environ["QTRUST_MIGRATION_REGISTRY_ADDRESS"]
        )
        self.audit_registry_address = (
            audit_registry_address or os.environ["QTRUST_AUDIT_REGISTRY_ADDRESS"]
        )
        self.account = Account.from_key(self.private_key)

        # Web3 setup
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC: {self.rpc_url}")

        chain_id = self.w3.eth.chain_id
        if chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise ValueError(f"Expected chain ID {BASE_SEPOLIA_CHAIN_ID} (Base Sepolia), got {chain_id}")

        # Contract instances
        self.asset_registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.asset_registry_address),
            abi=ASSET_REGISTRY_ABI,
        )
        self.vendor_registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.vendor_registry_address),
            abi=VENDOR_REGISTRY_ABI,
        )
        self.migration_registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.migration_registry_address),
            abi=MIGRATION_REGISTRY_ABI,
        )
        self.audit_registry = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.audit_registry_address),
            abi=AUDIT_REGISTRY_ABI,
        )

        # IPFS client
        self.ipfs = PinataClient(
            api_key=ipfs_api_key or os.environ["QTRUST_PINATA_API_KEY"],
            api_secret=ipfs_api_secret or os.environ["QTRUST_PINATA_API_SECRET"],
        )

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return "0x" + hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return "0x" + h.hexdigest()

    @staticmethod
    def hash_string(s: str) -> str:
        return "0x" + hashlib.sha256(s.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_cbom(cbom: CBOM) -> str:
        """Hash a CBOM object deterministically (canonical JSON)."""
        canonical = json.dumps(cbom.model_dump(), sort_keys=True, separators=(",", ":"))
        return "0x" + hashlib.sha256(canonical.encode()).hexdigest()

    def _send_transaction(self, tx_builder, gas_limit: int = 200_000) -> str:
        nonce = self.w3.eth.get_transaction_count(self.account.address)
        tx = tx_builder.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "gas": gas_limit,
            "gasPrice": self.w3.eth.gas_price,
            "chainId": BASE_SEPOLIA_CHAIN_ID,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if receipt["status"] != 1:
            raise RuntimeError(f"Transaction reverted: {tx_hash.hex()}")
        return tx_hash.hex()

    def register_cbom(self, cbom: CBOM, pin_to_ipfs: bool = True) -> tuple:
        """Register a CBOM on-chain. Returns (asset_id, ipfs_cid_or_empty)."""
        cbom_hash = self.hash_cbom(cbom)
        metadata_uri = ""
        if pin_to_ipfs:
            cbom_json = cbom.model_dump_json(indent=2)
            cid = self.ipfs.pin_json(cbom_json, name=f"qtrust-cbom")
            metadata_uri = f"ipfs://{cid}"

        tx_hash = self._send_transaction(
            self.asset_registry.functions.registerCBOM(
                bytes.fromhex(cbom_hash[2:]),
                metadata_uri,
            ),
            gas_limit=250_000,
        )

        receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        events = self.asset_registry.events.CBOMRegistered().process_receipt(receipt)
        if not events:
            raise RuntimeError("CBOMRegistered event not found in receipt")
        asset_id = "0x" + events[0]["args"]["assetId"].hex()
        return asset_id, metadata_uri.replace("ipfs://", "") if metadata_uri else ""

    def get_asset(self, asset_id: str) -> AssetRecord:
        asset_id_bytes = bytes.fromhex(asset_id[2:])
        raw = self.asset_registry.functions.getAsset(asset_id_bytes).call()
        return AssetRecord(
            asset_id=asset_id,
            org_did=raw[0],
            cbom_hash="0x" + raw[1].hex(),
            metadata_uri=raw[2],
            registered_at=raw[3],
            last_updated=raw[4],
            active=raw[5],
        )

    def get_assets_by_org(self, org_did: str) -> list:
        ids = self.asset_registry.functions.getAssetsByOrg(
            Web3.to_checksum_address(org_did)
        ).call()
        return ["0x" + i.hex() for i in ids]

    def register_vendor(self, vendor_address: str, name: str, metadata_uri: str = "") -> str:
        return self._send_transaction(
            self.vendor_registry.functions.registerVendor(
                Web3.to_checksum_address(vendor_address), name, metadata_uri,
            ),
            gas_limit=200_000,
        )

    def attest_product(self, attestation_id: str, product_id: str, version: str,
                      algorithm: str, supported: bool, evidence_uri: str = "") -> str:
        return self._send_transaction(
            self.vendor_registry.functions.attestProduct(
                bytes.fromhex(attestation_id[2:]),
                product_id, version, algorithm, supported, evidence_uri,
            ),
            gas_limit=250_000,
        )

    def get_attestation(self, attestation_id: str) -> ProductAttestation:
        raw = self.vendor_registry.functions.getAttestation(
            bytes.fromhex(attestation_id[2:])
        ).call()
        return ProductAttestation(
            attestation_id=attestation_id,
            vendor_did=raw[0],
            product_id=raw[2],
            version=raw[3],
            algorithm=raw[4],
            supported=raw[5],
            evidence_uri=raw[6],
            timestamp=raw[7],
            revoked=raw[8],
        )

    def get_attestations_by_product(self, product_id: str, version: str) -> list:
        ids = self.vendor_registry.functions.getAttestationsByProduct(
            product_id, version
        ).call()
        return ["0x" + i.hex() for i in ids]

    def record_migration(self, migration_id: str, asset_id: str,
                        from_algorithm: str, to_algorithm: str,
                        evidence_hash: str, evidence_uri: str = "") -> str:
        return self._send_transaction(
            self.migration_registry.functions.recordMigration(
                bytes.fromhex(migration_id[2:]),
                bytes.fromhex(asset_id[2:]),
                from_algorithm, to_algorithm,
                bytes.fromhex(evidence_hash[2:]),
                evidence_uri,
            ),
            gas_limit=250_000,
        )

    def get_migration(self, migration_id: str) -> MigrationRecord:
        raw = self.migration_registry.functions.getMigration(
            bytes.fromhex(migration_id[2:])
        ).call()
        return MigrationRecord(
            migration_id=migration_id,
            asset_id="0x" + raw[0].hex(),
            org_did=raw[1],
            from_algorithm=raw[2],
            to_algorithm=raw[3],
            evidence_hash="0x" + raw[4].hex(),
            evidence_uri=raw[5],
            timestamp=raw[6],
            verified=raw[7],
        )

    def get_migrations_by_asset(self, asset_id: str) -> list:
        ids = self.migration_registry.functions.getMigrationsByAsset(
            bytes.fromhex(asset_id[2:])
        ).call()
        return ["0x" + i.hex() for i in ids]

    def post_audit(self, audit_id: str, org_did: str, result: int,
                  assets_reviewed: int, assets_passed: int,
                  report_hash: str, report_uri: str = "") -> str:
        return self._send_transaction(
            self.audit_registry.functions.postAudit(
                bytes.fromhex(audit_id[2:]),
                Web3.to_checksum_address(org_did),
                result, assets_reviewed, assets_passed,
                bytes.fromhex(report_hash[2:]),
                report_uri,
            ),
            gas_limit=250_000,
        )

    def get_audit(self, audit_id: str) -> dict:
        raw = self.audit_registry.functions.getAudit(
            bytes.fromhex(audit_id[2:])
        ).call()
        return {
            "audit_id": audit_id,
            "org_did": raw[0],
            "auditor_did": raw[1],
            "result": raw[2],
            "assets_reviewed": raw[3],
            "assets_passed": raw[4],
            "report_hash": "0x" + raw[5].hex(),
            "report_uri": raw[6],
            "timestamp": raw[7],
        }
```

### 5.6 Package Init and Tests

Create `sdk/qtrust/__init__.py`:

```python
# /home/z/qtrust/sdk/qtrust/__init__.py
"""Q-Trust SDK — Post-Quantum Cryptography migration coordination."""
from .client import QTrustClient
from .schema import CBOM, CBOMEntry, AssetRecord, VendorInfo, ProductAttestation, MigrationRecord
from .ipfs import PinataClient

__version__ = "0.1.0"
__all__ = [
    "QTrustClient",
    "CBOM", "CBOMEntry", "AssetRecord",
    "VendorInfo", "ProductAttestation", "MigrationRecord",
    "PinataClient",
]
```

Create `sdk/tests/test_client.py`:

```python
# /home/z/qtrust/sdk/tests/test_client.py
"""Smoke tests for QTrustClient."""
import hashlib
from qtrust import QTrustClient
from qtrust.schema import CBOM, CBOMEntry


def test_hash_string():
    h = QTrustClient.hash_string("test")
    assert h.startswith("0x")
    assert len(h) == 66
    expected = "0x" + hashlib.sha256(b"test").hexdigest()
    assert h == expected


def test_hash_file(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")
    h = QTrustClient.hash_file(str(test_file))
    assert h.startswith("0x")
    assert len(h) == 66
    expected = "0x" + hashlib.sha256(b"hello world").hexdigest()
    assert h == expected


def test_hash_cbom():
    cbom = CBOM(
        org_did="did:ethr:0x1234567890123456789012345678901234567890",
        generated_at=1700000000,
        scanner_version="0.1.0",
        assets=[
            CBOMEntry(
                asset_type="tls_cert",
                algorithm="RSA-2048",
                location="example.com:443",
                criticality="high",
            )
        ],
    )
    h = QTrustClient.hash_cbom(cbom)
    assert h.startswith("0x")
    assert len(h) == 66


def test_cbom_validation():
    entry = CBOMEntry(
        asset_type="tls_cert",
        algorithm="RSA-2048",
        location="example.com:443",
    )
    assert entry.criticality == "medium"
    assert entry.vendor is None


def test_cbom_summary():
    cbom = CBOM(
        org_did="did:ethr:0x1234567890123456789012345678901234567890",
        generated_at=1700000000,
        scanner_version="0.1.0",
        assets=[
            CBOMEntry(asset_type="tls_cert", algorithm="RSA-2048", location="a.com:443"),
            CBOMEntry(asset_type="tls_cert", algorithm="ECC-P256", location="b.com:443"),
            CBOMEntry(asset_type="ssh_key", algorithm="RSA-2048", location="host:22"),
        ],
        summary={"total_assets": 3, "by_algorithm": {"RSA-2048": 2, "ECC-P256": 1}},
    )
    assert len(cbom.assets) == 3
    assert cbom.summary["total_assets"] == 3
```

### 5.7 Install and Test

```bash
cd /home/z/qtrust/sdk
pip install -e ".[dev]"

# Verify import
python -c "from qtrust import QTrustClient; print('SDK imported successfully')"

# Run tests
pytest tests/ -v
```

Commit:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 2: Python SDK with Pydantic schemas and QTrustClient"
git push
```

---

## 6. Phase 3: Cryptography Inspector CLI

### 6.1 Inspector Package Structure

```bash
cd /home/z/qtrust
mkdir -p inspector/qtrust_inspector inspector/tests
cd inspector
echo "# Q-Trust Cryptography Inspector" > README.md
```

Create `inspector/pyproject.toml`:

```toml
# /home/z/qtrust/inspector/pyproject.toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "qtrust-inspector"
version = "0.1.0"
description = "Cryptographic asset scanner that produces CBOMs for Q-Trust"
requires-python = ">=3.10"
dependencies = [
    "qtrust-sdk>=1.1.0",
    "cryptography>=42.0.0",
    "pyasn1>=0.5.0",
    "requests>=2.31.0",
    "rich>=13.7.0",
    "typer>=0.12.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
qtrust-scan = "qtrust_inspector.cli:app"

[tool.setuptools.packages.find]
where = ["."]
include = ["qtrust_inspector*"]
```

### 6.2 Models

Create `inspector/qtrust_inspector/models.py`:

```python
# /home/z/qtrust/inspector/qtrust_inspector/models.py
"""Data models for scanner findings."""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


class AssetFinding(BaseModel):
    """A single cryptographic asset found by a scanner."""
    asset_type: str = Field(..., description="tls_cert | ssh_key | code_signing | hsm | jwt | other")
    algorithm: str = Field(..., description="e.g., RSA-2048, ECC-P256, ML-DSA-441")
    location: str = Field(..., description="Hostname:port, file path, or service identifier")
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    criticality: str = "medium"
    expires_at: Optional[int] = None
    metadata: dict = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of a scan — a list of findings."""
    target: str
    scanner: str
    started_at: int
    completed_at: int
    findings: list[AssetFinding] = Field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def by_algorithm(self) -> dict:
        counts = {}
        for f in self.findings:
            counts[f.algorithm] = counts.get(f.algorithm, 0) + 1
        return counts

    @property
    def by_type(self) -> dict:
        counts = {}
        for f in self.findings:
            counts[f.asset_type] = counts.get(f.asset_type, 0) + 1
        return counts
```

### 6.3 TLS Certificate Scanner

Create `inspector/qtrust_inspector/tls_scanner.py`:

```python
# /home/z/qtrust/inspector/qtrust_inspector/tls_scanner.py
"""TLS certificate scanner — connects to hosts and inspects their certs."""
from __future__ import annotations
import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from typing import Optional
from .models import AssetFinding


def get_algorithm_name(public_key) -> str:
    """Return a human-readable algorithm name from a cryptography public key."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name.upper()
        return f"ECC-{curve_name}"
    else:
        return f"UNKNOWN-{type(public_key).__name__}"


def scan_tls_certificate(host: str, port: int = 443, timeout: float = 10.0) -> Optional[AssetFinding]:
    """Connect to a host:port, retrieve the TLS certificate, and return a finding."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return None
    except (socket.timeout, ConnectionRefusedError, socket.gaierror, ssl.SSLError):
        return None

    cert = x509.load_der_x509_certificate(der_cert)
    algorithm = get_algorithm_name(cert.public_key())

    issuer_str = cert.issuer.rfc4514_string()
    vendor = None
    for known_ca in ["DigiCert", "Let's Encrypt", "GlobalSign", "Sectigo", "Entrust", "Thales"]:
        if known_ca.lower() in issuer_str.lower():
            vendor = known_ca
            break

    try:
        not_after = cert.not_valid_after_utc
        expires_at = int(not_after.timestamp())
    except AttributeError:
        not_after = cert.not_valid_after
        expires_at = int(not_after.replace(tzinfo=timezone.utc).timestamp())

    return AssetFinding(
        asset_type="tls_cert",
        algorithm=algorithm,
        location=f"{host}:{port}",
        vendor=vendor,
        criticality="high",
        expires_at=expires_at,
        metadata={"issuer": issuer_str, "serial": str(cert.serial_number)},
    )
```

### 6.4 SSH Key Scanner

Create `inspector/qtrust_inspector/ssh_scanner.py`:

```python
# /home/z/qtrust/inspector/qtrust_inspector/ssh_scanner.py
"""SSH key scanner — connects to SSH servers and inspects their host keys."""
from __future__ import annotations
import socket
import struct
from typing import Optional
from .models import AssetFinding


SSH_KEY_TYPES = {
    "ssh-rsa": "RSA",
    "ssh-dss": "DSA",
    "ecdsa-sha2-nistp256": "ECC-P256",
    "ecdsa-sha2-nistp384": "ECC-P384",
    "ecdsa-sha2-nistp521": "ECC-P521",
    "ssh-ed25519": "Ed25519",
    "ssh-ed448": "Ed448",
}


def scan_ssh_key(host: str, port: int = 22, timeout: float = 10.0) -> Optional[AssetFinding]:
    """Connect to an SSH server, retrieve its host key, return a finding."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
            if not banner.startswith("SSH-"):
                return None

            sock.send(b"SSH-2.0-qtrust-scanner\r\n")

            length_bytes = sock.recv(4)
            if len(length_bytes) < 4:
                return None
            packet_length = struct.unpack(">I", length_bytes)[0]
            padding_length = sock.recv(1)[0]
            payload_length = packet_length - padding_length - 1

            payload = b""
            while len(payload) < payload_length:
                chunk = sock.recv(payload_length - len(payload))
                if not chunk:
                    break
                payload += chunk

            offset = 16  # skip cookie

            if offset + 4 > len(payload):
                return None
            kex_len = struct.unpack(">I", payload[offset:offset+4])[0]
            offset += 4 + kex_len

            if offset + 4 > len(payload):
                return None
            key_algs_len = struct.unpack(">I", payload[offset:offset+4])[0]
            offset += 4
            key_algs = payload[offset:offset+key_algs_len].decode("utf-8", errors="ignore")
            offset += key_algs_len

            first_alg = key_algs.split(",")[0] if key_algs else ""
            algorithm = SSH_KEY_TYPES.get(first_alg, first_alg)

            return AssetFinding(
                asset_type="ssh_key",
                algorithm=algorithm,
                location=f"{host}:{port}",
                criticality="medium",
                metadata={"ssh_banner": banner, "key_type": first_alg},
            )

    except (socket.timeout, ConnectionRefusedError, socket.gaierror, struct.error):
        return None
```

### 6.5 File Scanner

Create `inspector/qtrust_inspector/file_scanner.py`:

```python
# /home/z/qtrust/inspector/qtrust_inspector/file_scanner.py
"""File-based crypto scanner — scans PEM files, SSH known_hosts, etc."""
from __future__ import annotations
from pathlib import Path
from typing import Iterator
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_public_key
from .models import AssetFinding


def get_algorithm_name(public_key) -> str:
    """Return a human-readable algorithm name."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name.upper()
        return f"ECC-{curve_name}"
    else:
        return type(public_key).__name__


def scan_pem_files(directory: str) -> Iterator[AssetFinding]:
    """Scan a directory for PEM files (certificates and keys)."""
    patterns = ["**/*.pem", "**/*.crt", "**/*.key", "**/*.cert"]
    for pattern in patterns:
        for path in Path(directory).glob(pattern):
            try:
                content = path.read_bytes()
                try:
                    cert = x509.load_pem_x509_certificate(content)
                    yield AssetFinding(
                        asset_type="tls_cert",
                        algorithm=get_algorithm_name(cert.public_key()),
                        location=str(path),
                        criticality="medium",
                        metadata={"serial": str(cert.serial_number)},
                    )
                    continue
                except Exception:
                    pass
                try:
                    key = load_pem_private_key(content, password=None)
                    yield AssetFinding(
                        asset_type="private_key",
                        algorithm=get_algorithm_name(key.public_key()),
                        location=str(path),
                        criticality="high",
                    )
                except Exception:
                    pass
            except Exception:
                continue


def scan_ssh_directory(ssh_dir: str = "~/.ssh") -> Iterator[AssetFinding]:
    """Scan ~/.ssh for public keys."""
    ssh_path = Path(ssh_dir).expanduser()
    if not ssh_path.exists():
        return
    for key_file in ssh_path.glob("*.pub"):
        try:
            content = key_file.read_bytes()
            key = load_ssh_public_key(content)
            yield AssetFinding(
                asset_type="ssh_key",
                algorithm=get_algorithm_name(key),
                location=str(key_file),
                criticality="medium",
            )
        except Exception:
            continue
```

### 6.6 Main Scanner and CLI

Create `inspector/qtrust_inspector/scanner.py`:

```python
# /home/z/qtrust/inspector/qtrust_inspector/scanner.py
"""Main scanner orchestrator."""
from __future__ import annotations
import time
from typing import Optional
from .models import ScanResult, AssetFinding
from .tls_scanner import scan_tls_certificate
from .ssh_scanner import scan_ssh_key
from .file_scanner import scan_pem_files, scan_ssh_directory


def scan_host(host: str, ports: list = None) -> ScanResult:
    """Scan a single host."""
    if ports is None:
        ports = [443, 8443, 22]

    started = int(time.time())
    findings: list = []

    for port in ports:
        if port in (443, 8443):
            finding = scan_tls_certificate(host, port)
            if finding:
                findings.append(finding)
        elif port == 22:
            finding = scan_ssh_key(host, port)
            if finding:
                findings.append(finding)

    return ScanResult(
        target=host, scanner="qtrust-inspector",
        started_at=started, completed_at=int(time.time()),
        findings=findings,
    )


def scan_directory(directory: str) -> ScanResult:
    """Scan a directory for PEM files and SSH keys."""
    started = int(time.time())
    findings: list = []
    findings.extend(scan_pem_files(directory))
    findings.extend(scan_ssh_directory())
    return ScanResult(
        target=directory, scanner="qtrust-inspector",
        started_at=started, completed_at=int(time.time()),
        findings=findings,
    )


def scan_network(hosts: list, ports: list = None) -> list:
    """Scan multiple hosts."""
    return [scan_host(h, ports) for h in hosts]
```

Create `inspector/qtrust_inspector/cli.py`:

```python
# /home/z/qtrust/inspector/qtrust_inspector/cli.py
"""CLI for the Q-Trust cryptography inspector."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from .scanner import scan_host, scan_directory, scan_network
from .models import ScanResult

app = typer.Typer(name="qtrust-scan", help="Cryptographic asset scanner for Q-Trust",
                  no_args_is_help=True, rich_markup_mode="rich")
console = Console()


@app.command()
def host(
    hostname: str = typer.Argument(..., help="Hostname to scan"),
    ports: str = typer.Option("443,8443,22", "--ports", "-p"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    register: bool = typer.Option(False, "--register"),
):
    """Scan a single host."""
    port_list = [int(p.strip()) for p in ports.split(",")]
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description=f"Scanning {hostname}...", total=None)
        result = scan_host(hostname, port_list)
    _display(result)
    if output:
        output.write_text(result.model_dump_json(indent=2))
        console.print(f"\n[green]Saved to {output}[/green]")
    if register:
        _register_onchain(result)


@app.command()
def directory(
    path: Path = typer.Argument(...),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
):
    """Scan a directory."""
    if not path.exists():
        console.print(f"[red]Directory not found: {path}[/red]")
        raise typer.Exit(1)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description=f"Scanning {path}...", total=None)
        result = scan_directory(str(path))
    _display(result)
    if output:
        output.write_text(result.model_dump_json(indent=2))
        console.print(f"\n[green]Saved to {output}[/green]")


@app.command()
def network(
    hosts_file: Path = typer.Argument(...),
    ports: str = typer.Option("443,22", "--ports", "-p"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
):
    """Scan multiple hosts from a file."""
    hosts = [l.strip() for l in hosts_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
    port_list = [int(p.strip()) for p in ports.split(",")]
    results = scan_network(hosts, port_list)
    total = sum(r.finding_count for r in results)
    console.print(f"\n[bold green]Scan complete:[/bold green] {len(results)} hosts, {total} findings")
    for r in results:
        _display(r)
    if output:
        output.write_text(json.dumps([r.model_dump() for r in results], indent=2))


def _display(result: ScanResult):
    console.print(f"\n[bold cyan]Scan result: {result.target}[/bold cyan]")
    console.print(f"  Findings: {result.finding_count}")
    console.print(f"  By algorithm: {result.by_algorithm}")
    console.print(f"  By type: {result.by_type}")
    if result.findings:
        table = Table(title=f"Findings for {result.target}")
        table.add_column("Type", style="cyan")
        table.add_column("Algorithm", style="yellow")
        table.add_column("Location", style="green")
        table.add_column("Vendor", style="magenta")
        table.add_column("Criticality", style="red")
        for f in result.findings:
            table.add_row(f.asset_type, f.algorithm, f.location, f.vendor or "-", f.criticality)
        console.print(table)


def _register_onchain(scan_result: ScanResult):
    try:
        from qtrust import QTrustClient
        from qtrust.schema import CBOM, CBOMEntry
    except ImportError:
        console.print("[red]qtrust-sdk not installed. Run: pip install qtrust-sdk[/red]")
        return
    try:
        client = QTrustClient()
    except Exception as e:
        console.print(f"[red]Failed to initialize Q-Trust client: {e}[/red]")
        return
    entries = [
        CBOMEntry(
            asset_type=f.asset_type, algorithm=f.algorithm, location=f.location,
            vendor=f.vendor, product=f.product, version=f.version,
            criticality=f.criticality, expires_at=f.expires_at,
        ) for f in scan_result.findings
    ]
    cbom = CBOM(
        org_did=f"did:ethr:{client.account.address}",
        generated_at=scan_result.started_at,
        scanner_version="0.1.0",
        assets=entries,
        summary={"total_assets": len(entries),
                 "by_algorithm": scan_result.by_algorithm,
                 "by_type": scan_result.by_type},
    )
    console.print("\n[cyan]Registering CBOM on Base Sepolia...[/cyan]")
    try:
        asset_id, ipfs_cid = client.register_cbom(cbom, pin_to_ipfs=True)
        console.print(f"[bold green]CBOM registered![/bold green]")
        console.print(f"  Asset ID: [bold]{asset_id}[/bold]")
        if ipfs_cid:
            console.print(f"  IPFS CID: [dim]{ipfs_cid}[/dim]")
    except Exception as e:
        console.print(f"[red]Registration failed: {e}[/red]")


if __name__ == "__main__":
    app()
```

### 6.7 Package Init, Tests, Install

Create `inspector/qtrust_inspector/__init__.py`:

```python
# /home/z/qtrust/inspector/qtrust_inspector/__init__.py
"""Q-Trust Cryptography Inspector."""
from .scanner import scan_host, scan_directory, scan_network
from .models import AssetFinding, ScanResult

__version__ = "0.1.0"
__all__ = ["scan_host", "scan_directory", "scan_network", "AssetFinding", "ScanResult"]
```

Create `inspector/tests/test_scanner.py`:

```python
# /home/z/qtrust/inspector/tests/test_scanner.py
import pytest
from qtrust_inspector import scan_host, scan_directory
from qtrust_inspector.tls_scanner import scan_tls_certificate
from qtrust_inspector.models import AssetFinding


def test_scan_known_host():
    result = scan_host("example.com", [443])
    assert result.target == "example.com"
    assert result.finding_count >= 1
    finding = result.findings[0]
    assert finding.asset_type == "tls_cert"
    assert finding.algorithm.startswith(("RSA-", "ECC-"))
    assert finding.location == "example.com:443"


def test_tls_scanner_returns_finding():
    finding = scan_tls_certificate("example.com", 443)
    assert finding is not None
    assert finding.asset_type == "tls_cert"


def test_tls_scanner_invalid_host():
    finding = scan_tls_certificate("nonexistent.invalid.domain.example", 443, timeout=5)
    assert finding is None


def test_finding_model():
    finding = AssetFinding(
        asset_type="tls_cert", algorithm="RSA-2048",
        location="example.com:443", criticality="high",
    )
    assert finding.asset_type == "tls_cert"
    assert finding.algorithm == "RSA-2048"
```

Install and test:

```bash
cd /home/z/qtrust/inspector
pip install -e ".[dev]"

# Test scanning example.com
qtrust-scan host example.com

# Test directory scanning
qtrust-scan directory /home/z/qtrust

# Test with output file
qtrust-scan host example.com --output /tmp/cbom-example.json

# Run tests
pytest tests/ -v
```

Commit:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 3: cryptography inspector with TLS, SSH, and file scanners"
git push
```

---

## 7. Phase 4: Qiskit Sales Notebook

This phase uses the **qiskit311** kernel. It produces a Jupyter notebook that simulates Shor's algorithm against a customer's RSA key sizes.

### 7.1 Install Qiskit

```bash
conda activate qiskit311 2>/dev/null || conda create -n qiskit311 python=3.11 -y
conda activate qiskit311
pip install qiskit==1.0.0 qiskit-aer==0.13.3 matplotlib numpy
python -m ipykernel install --sys-prefix --name qiskit311 --display-name "Python 3.11 (qiskit311)"
```

### 7.2 Notebook Content

Create `/home/z/qtrust/notebooks/04_shor_sales_demo.ipynb` in JupyterLab with the **qiskit311** kernel. Paste each block below as a separate cell.

**Cell 1: Imports and setup**

```python
import numpy as np
import matplotlib.pyplot as plt
from qiskit_aer import AerSimulator
import time
import warnings
warnings.filterwarnings('ignore')

print("Qiskit sales demo — Q-Trust PQC Migration Coordinator")
print("=" * 60)
```

**Cell 2: RSA key analysis**

```python
customer_key_sizes = [1024, 2048, 3072, 4096]

def logical_qubits_for_rsa(n_bits: int) -> int:
    return 2 * n_bits + 3

def physical_qubits_for_rsa(n_bits: int) -> int:
    return logical_qubits_for_rsa(n_bits) * 1000

print("Customer RSA key analysis:")
print(f"{'Key Size':<12} {'Logical Qubits':<20} {'Physical Qubits':<20}")
print("-" * 52)
for n in customer_key_sizes:
    lq = logical_qubits_for_rsa(n)
    pq = physical_qubits_for_rsa(n)
    print(f"RSA-{n:<8} {lq:<20,} {pq:<20,}")
```

**Cell 3: Quantum hardware roadmap**

```python
hardware_roadmap = [
    (2024, 1121, 100, 32),
    (2025, 4158, 200, 256),
    (2026, 10000, 500, 1024),
    (2027, 20000, 1000, 4096),
    (2028, 50000, 5000, 16384),
    (2029, 100000, 10000, 65536),
    (2030, 200000, 50000, 100000),
    (2031, 500000, 100000, 200000),
    (2032, 1000000, 200000, 500000),
    (2033, 2000000, 500000, 1000000),
]

years = [r[0] for r in hardware_roadmap]
ibm_qubits = [r[1] for r in hardware_roadmap]
google_qubits = [r[2] for r in hardware_roadmap]
ionq_qubits = [r[3] for r in hardware_roadmap]

breakable_years = {}
for n in customer_key_sizes:
    required = physical_qubits_for_rsa(n)
    breakable_year = None
    for year, ibm, google, ionq in hardware_roadmap:
        max_qubits = max(ibm, google, ionq)
        if max_qubits >= required:
            breakable_year = year
            break
    breakable_years[n] = breakable_year

print("\nEstimated breakable year (by any vendor):")
print(f"{'Key Size':<12} {'Required Qubits':<20} {'Breakable Year':<15}")
print("-" * 47)
for n in customer_key_sizes:
    req = physical_qubits_for_rsa(n)
    year = breakable_years[n] or "After 2033"
    print(f"RSA-{n:<8} {req:<20,} {year}")
```

**Cell 4: Plot the roadmap**

```python
fig, ax = plt.subplots(figsize=(12, 7))
ax.plot(years, ibm_qubits, 'o-', label='IBM', linewidth=2, markersize=8)
ax.plot(years, google_qubits, 's-', label='Google', linewidth=2, markersize=8)
ax.plot(years, ionq_qubits, '^-', label='IonQ', linewidth=2, markersize=8)

colors = ['red', 'orange', 'purple', 'brown']
for n, color in zip(customer_key_sizes, colors):
    req = physical_qubits_for_rsa(n)
    ax.axhline(y=req, color=color, linestyle='--', alpha=0.7, label=f'RSA-{n} breakable')
    if breakable_years[n]:
        ax.axvline(x=breakable_years[n], color=color, linestyle=':', alpha=0.5)
        ax.annotate(f'RSA-{n} falls\nin {breakable_years[n]}',
                   xy=(breakable_years[n], req), xytext=(breakable_years[n]+0.3, req*0.5),
                   fontsize=9, color=color,
                   arrowprops=dict(arrowstyle='->', color=color))

ax.set_xlabel('Year', fontsize=12)
ax.set_ylabel('Physical Qubits (log scale)', fontsize=12)
ax.set_yscale('log')
ax.set_title('Quantum Hardware Roadmap vs. RSA Key Vulnerability', fontsize=14, fontweight='bold')
ax.legend(loc='center left', bbox_to_anchor=(1.02, 0.5), fontsize=10)
ax.grid(True, alpha=0.3)
ax.set_xlim(2024, 2033)
plt.tight_layout()
plt.savefig('/home/z/qtrust/notebooks/quantum_roadmap.png', dpi=150, bbox_inches='tight')
plt.show()
print("Plot saved to /home/z/qtrust/notebooks/quantum_roadmap.png")
```

**Cell 5: Shor's algorithm on N=15**

```python
print("Running Shor's algorithm on N=15 (smallest RSA-style semiprime)...")
print("This demonstrates that the algorithm works — scaling up is just engineering.")

from qiskit.algorithms import Shor
from qiskit.utils import QuantumInstance

backend = AerSimulator(method='statevector')
qi = QuantumInstance(backend, shots=1024)

shor = Shor(quantum_instance=qi)
start_time = time.time()
result = shor.factor(15)
elapsed = time.time() - start_time

print(f"\nShor's algorithm result for N=15:")
print(f"  Factors found: {result.factors}")
print(f"  Time elapsed: {elapsed:.2f} seconds")
print(f"  Successful: {len(result.factors) > 0 and 15 == result.factors[0][0] * result.factors[0][1]}")
```

**Cell 6: Customer recommendation**

```python
print("=" * 60)
print("Q-Trust Migration Recommendation")
print("=" * 60)

current_year = 2026
for n in customer_key_sizes:
    year = breakable_years[n]
    if year is None:
        print(f"\nRSA-{n}: Secure until after 2033 (low urgency)")
    elif year - current_year <= 2:
        print(f"\nRSA-{n}: CRITICAL — breakable in {year} ({year - current_year} years)")
        print(f"  → Migrate immediately to ML-KEM-768 or ML-DSA-441")
    elif year - current_year <= 5:
        print(f"\nRSA-{n}: HIGH PRIORITY — breakable in {year} ({year - current_year} years)")
        print(f"  → Migrate within 24 months")
    elif year - current_year <= 8:
        print(f"\nRSA-{n}: MEDIUM PRIORITY — breakable in {year} ({year - current_year} years)")
        print(f"  → Plan migration within 36 months")
    else:
        print(f"\nRSA-{n}: LOW PRIORITY — breakable in {year} ({year - current_year} years)")

print("\n" + "=" * 60)
print("Next steps:")
print("1. Run 'qtrust-scan host <your-domain>' to inventory your assets")
print("2. Run 'qtrust register' to post your CBOM on-chain")
print("3. Use the Q-Trust dashboard to plan your migration")
print("4. Subscribe to vendor attestation updates")
print("=" * 60)
```

### 7.3 Run and Export

Run each cell in order with the qiskit311 kernel. Cell 5 takes 30-60 seconds.

```bash
cd /home/z/qtrust/notebooks
jupyter nbconvert --to html 04_shor_sales_demo.ipynb
```

Commit:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 4: qiskit sales notebook with Shor's algorithm demo"
git push
```

---

## 8. Phase 5: FIGNN Migration Planner

This phase uses the **fignn_env** kernel and the **Honeycomb A100** GPU. It builds a Graph Neural Network that analyzes a CBOM's dependency graph and recommends a migration order.

### 8.1 Setup the fignn_env kernel

```bash
conda activate fignn_env 2>/dev/null || conda create -n fignn_env python=3.10 -y
conda activate fignn_env

pip install torch==2.2.0 torch-geometric==2.5.0 numpy pandas scikit-learn matplotlib
python -m ipykernel install --sys-prefix --name fignn_env --display-name "Python 3.10 (fignn_env)"
```

### 8.2 Project Structure

```bash
cd /home/z/qtrust
mkdir -p planner/qtrust_planner planner/tests planner/data
cd planner
echo "# Q-Trust FIGNN Migration Planner" > README.md
```

Create `planner/pyproject.toml`:

```toml
# /home/z/qtrust/planner/pyproject.toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "qtrust-planner"
version = "0.1.0"
description = "GNN-based PQC migration planner"
requires-python = ">=3.10"
dependencies = [
    "torch>=2.2.0",
    "torch-geometric>=2.5.0",
    "numpy",
    "pandas",
    "scikit-learn",
    "matplotlib",
]

[project.optional-dependencies]
dev = ["pytest"]

[tool.setuptools.packages.find]
where = ["."]
include = ["qtrust_planner*"]
```

### 8.3 Synthetic Data Generator

Create `planner/qtrust_planner/data_generator.py`:

```python
# /home/z/qtrust/planner/qtrust_planner/data_generator.py
"""Generate synthetic CBOM dependency graphs for GNN training."""
import numpy as np
import json
from pathlib import Path
from typing import Optional


ASSET_TYPES = ["tls_cert", "ssh_key", "code_signing", "hsm", "jwt", "private_key"]
ALGORITHMS = ["RSA-1024", "RSA-2048", "RSA-3072", "RSA-4096",
              "ECC-P256", "ECC-P384", "ECC-P521",
              "Ed25519", "DSA-1024"]
CRITICALITIES = ["low", "medium", "high", "critical"]
VENDORS = ["DigiCert", "Thales", "AWS", "Cloudflare", "Let's Encrypt",
           "GlobalSign", "Sectigo", "Entrust", "Google", None]


def generate_synthetic_cbom(n_assets: int = 50, seed: int = 42) -> dict:
    """Generate a synthetic CBOM with random assets and dependencies."""
    rng = np.random.default_rng(seed)

    assets = []
    for i in range(n_assets):
        # Weight algorithms by real-world frequency (RSA dominates)
        alg_weights = [0.05, 0.45, 0.15, 0.05,  # RSA
                       0.15, 0.05, 0.02,        # ECC
                       0.07, 0.01]                # Ed25519, DSA
        algorithm = rng.choice(ALGORITHMS, p=alg_weights)

        assets.append({
            "id": i,
            "asset_type": rng.choice(ASSET_TYPES),
            "algorithm": algorithm,
            "vendor": rng.choice(VENDORS),
            "criticality": rng.choice(CRITICALITIES, p=[0.2, 0.4, 0.3, 0.1]),
            "is_pqc": False,  # Synthetic data assumes all are pre-PQC
            "depends_on": [],  # Filled in below
        })

    # Generate dependencies (each asset depends on 0-3 others)
    for asset in assets:
        n_deps = rng.integers(0, 4)
        possible_deps = [a["id"] for a in assets if a["id"] != asset["id"]]
        if possible_deps and n_deps > 0:
            asset["depends_on"] = rng.choice(possible_deps, size=min(n_deps, len(possible_deps)), replace=False).tolist()

    return {
        "org_did": f"did:ethr:0x{seed:040x}",
        "generated_at": 1700000000 + seed,
        "scanner_version": "synthetic-v1",
        "assets": assets,
        "summary": {
            "total_assets": n_assets,
            "by_algorithm": {alg: sum(1 for a in assets if a["algorithm"] == alg) for alg in set(a["algorithm"] for a in assets)},
        },
    }


def cbom_to_dependency_graph(cbom: dict) -> dict:
    """Convert a CBOM to a PyG-compatible graph structure (as dicts)."""
    assets = cbom["assets"]
    n = len(assets)

    # Node features: [algorithm_index, asset_type_index, criticality_index, is_pqc]
    alg_to_idx = {alg: i for i, alg in enumerate(ALGORITHMS)}
    type_to_idx = {t: i for i, t in enumerate(ASSET_TYPES)}
    crit_to_idx = {c: i for i, c in enumerate(CRITICALITIES)}

    node_features = []
    for asset in assets:
        node_features.append([
            alg_to_idx.get(asset["algorithm"], 0),
            type_to_idx.get(asset["asset_type"], 0),
            crit_to_idx.get(asset["criticality"], 1),
            1 if asset.get("is_pqc") else 0,
        ])

    # Edges: dependencies (directed: dependent → dependency)
    edges = []
    for asset in assets:
        for dep_id in asset.get("depends_on", []):
            edges.append([asset["id"], dep_id])

    return {
        "num_nodes": n,
        "node_features": node_features,
        "edges": edges,
        "assets": assets,
    }


def generate_training_dataset(n_samples: int = 1000, output_dir: str = "data") -> None:
    """Generate a dataset of synthetic CBOMs for GNN training."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for i in range(n_samples):
        n_assets = np.random.randint(20, 200)
        cbom = generate_synthetic_cbom(n_assets=n_assets, seed=i)
        graph = cbom_to_dependency_graph(cbom)

        # Generate a "ground truth" migration order (topological sort with criticality weighting)
        # In real data, this would come from historical migrations
        order = _compute_migration_order(graph)
        graph["migration_order"] = order
        graph["migration_priority"] = [_priority_score(a, idx) for idx, a in enumerate(order)]

        with open(output_path / f"cbom_{i:04d}.json", "w") as f:
            json.dump(graph, f, indent=2)

    print(f"Generated {n_samples} synthetic CBOMs in {output_path}")


def _compute_migration_order(graph: dict) -> list:
    """Compute a migration order: topological sort with criticality weighting."""
    assets = graph["assets"]
    # Build adjacency list (reversed: dependency → dependents)
    deps = {a["id"]: a.get("depends_on", []) for a in assets}
    criticality_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    # Simple greedy: order by (criticality + dependency_depth)
    order = sorted(assets, key=lambda a: (
        -criticality_weight.get(a["criticality"], 2),
        -len(a.get("depends_on", []))
    ))
    return [a["id"] for a in order]


def _priority_score(asset: dict, position: int) -> float:
    """Priority score: 1.0 for first to migrate, 0.0 for last."""
    # This is a simplified score; real implementation would use position + criticality
    return max(0.0, 1.0 - position * 0.01)


if __name__ == "__main__":
    generate_training_dataset(n_samples=100, output_dir="data")
```

### 8.4 GNN Model

Create `planner/qtrust_planner/model.py`:

```python
# /home/z/qtrust/planner/qtrust_planner/model.py
"""FIGNN-style Graph Neural Network for PQC migration planning."""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool


class MigrationGNN(nn.Module):
    """GNN that predicts migration priority for each asset in a CBOM.

    Input:  PyG Data object with:
            - x: node features [num_nodes, 4] (alg_idx, type_idx, crit_idx, is_pqc)
            - edge_index: edges [2, num_edges]
            - batch: batch assignment [num_nodes]

    Output: priority scores [num_nodes] (higher = migrate first)
    """

    def __init__(self, n_features: int = 4, hidden: int = 64):
        super().__init__()
        self.conv1 = GCNConv(n_features, hidden)
        self.conv2 = GCNConv(hidden, hidden)
        self.conv3 = GCNConv(hidden, hidden)
        self.priority_head = nn.Linear(hidden, 1)
        self.risk_head = nn.Linear(hidden, 1)
        self.dropout = nn.Dropout(0.3)

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch

        x = F.relu(self.conv1(x, edge_index))
        x = self.dropout(x)
        x = F.relu(self.conv2(x, edge_index))
        x = self.dropout(x)
        x = F.relu(self.conv3(x, edge_index))

        # Per-node priority (higher = migrate first)
        priority = self.priority_head(x).squeeze(-1)

        # Per-node risk (higher = more risky if not migrated)
        risk = self.risk_head(x).squeeze(-1)

        return priority, risk


def predict_migration_order(model: MigrationGNN, data) -> list:
    """Use the trained model to predict migration order for a CBOM.

    Returns: list of node indices in recommended migration order
    """
    model.eval()
    with torch.no_grad():
        priority, risk = model(data)

    # Sort by priority (descending) — highest priority first
    order = torch.argsort(priority, descending=True)
    return order.tolist()
```

### 8.5 Training Script

Create `planner/qtrust_planner/train.py`:

```python
# /home/z/qtrust/planner/qtrust_planner/train.py
"""Train the MigrationGNN on synthetic data."""
import json
import torch
import torch.nn as nn
import torch.optim as optim
from torch_geometric.data import Data, DataLoader
from pathlib import Path
from .model import MigrationGNN, predict_migration_order
from .data_generator import generate_training_dataset


def load_dataset(data_dir: str = "data") -> list:
    """Load all synthetic CBOMs as PyG Data objects."""
    data_path = Path(data_dir)
    dataset = []

    for file in sorted(data_path.glob("cbom_*.json")):
        with open(file) as f:
            graph = json.load(f)

        # Convert to PyG Data
        x = torch.tensor(graph["node_features"], dtype=torch.float32)
        if graph["edges"]:
            edge_index = torch.tensor(graph["edges"], dtype=torch.long).t().contiguous()
        else:
            edge_index = torch.empty(2, 0, dtype=torch.long)

        # Target: migration priority scores
        y = torch.tensor(graph.get("migration_priority", [0.5] * graph["num_nodes"]), dtype=torch.float32)

        data = Data(x=x, edge_index=edge_index, y=y)
        data.num_nodes = graph["num_nodes"]
        dataset.append(data)

    return dataset


def train_model(data_dir: str = "data", epochs: int = 50, lr: float = 1e-3):
    """Train the MigrationGNN."""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Training on: {device}")

    # Load dataset
    dataset = load_dataset(data_dir)
    print(f"Loaded {len(dataset)} graphs")

    # Split 80/20
    n_train = int(0.8 * len(dataset))
    train_dataset = dataset[:n_train]
    val_dataset = dataset[n_train:]
    print(f"Train: {len(train_dataset)}, Val: {len(val_dataset)}")

    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)

    # Initialize model
    model = MigrationGNN(n_features=4, hidden=64).to(device)
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    criterion = nn.MSELoss()

    best_val_loss = float('inf')

    for epoch in range(epochs):
        # Train
        model.train()
        total_loss = 0
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            priority, risk = model(batch)
            # Target: priority scores
            loss = criterion(priority, batch.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        avg_train_loss = total_loss / len(train_loader)

        # Validate
        model.eval()
        val_loss = 0
        with torch.no_grad():
            for batch in val_loader:
                batch = batch.to(device)
                priority, risk = model(batch)
                val_loss += criterion(priority, batch.y).item()
        avg_val_loss = val_loss / len(val_loader)

        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            torch.save(model.state_dict(), '/home/z/qtrust/planner/best_model.pt')

        if (epoch + 1) % 10 == 0:
            print(f"Epoch {epoch+1}/{epochs}: train_loss={avg_train_loss:.4f}, val_loss={avg_val_loss:.4f}")

    print(f"\nTraining complete. Best val loss: {best_val_loss:.4f}")
    print(f"Model saved to /home/z/qtrust/planner/best_model.pt")
    return model


if __name__ == "__main__":
    # Generate synthetic data if not exists
    data_path = Path("data")
    if not data_path.exists() or len(list(data_path.glob("cbom_*.json"))) == 0:
        print("Generating synthetic training data...")
        generate_training_dataset(n_samples=500, output_dir="data")

    # Train
    train_model(data_dir="data", epochs=50)
```

### 8.6 Inference / Planner Service

Create `planner/qtrust_planner/planner.py`:

```python
# /home/z/qtrust/planner/qtrust_planner/planner.py
"""Use a trained GNN to plan migrations for a real CBOM."""
import json
import torch
from torch_geometric.data import Data
from .model import MigrationGNN, predict_migration_order
from .data_generator import cbom_to_dependency_graph, ALGORITHMS, ASSET_TYPES, CRITICALITIES


def load_model(model_path: str = "/home/z/qtrust/planner/best_model.pt") -> MigrationGNN:
    """Load a trained model."""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = MigrationGNN(n_features=4, hidden=64).to(device)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()
    return model


def cbom_to_pyg_data(cbom: dict) -> Data:
    """Convert a CBOM dict to a PyG Data object."""
    graph = cbom_to_dependency_graph(cbom)

    x = torch.tensor(graph["node_features"], dtype=torch.float32)
    if graph["edges"]:
        edge_index = torch.tensor(graph["edges"], dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.empty(2, 0, dtype=torch.long)

    data = Data(x=x, edge_index=edge_index)
    data.num_nodes = graph["num_nodes"]
    return data


def plan_migration(cbom: dict, model: MigrationGNN = None) -> dict:
    """Plan a PQC migration for a CBOM.

    Returns: dict with migration_order, priorities, and phases
    """
    if model is None:
        model = load_model()

    device = next(model.parameters()).device
    data = cbom_to_pyg_data(cbom).to(device)

    # Get predictions
    order = predict_migration_order(model, data)

    # Get priority scores
    with torch.no_grad():
        priority, risk = model(data)

    # Group into phases (top 25% = Phase 1, next 25% = Phase 2, etc.)
    n = len(order)
    phase_size = max(1, n // 4)
    phases = []
    for i in range(0, n, phase_size):
        phase_assets = order[i:i+phase_size]
        phases.append({
            "phase": len(phases) + 1,
            "asset_indices": phase_assets,
            "asset_locations": [cbom["assets"][idx]["location"] for idx in phase_assets],
            "avg_priority": float(priority[phase_assets].mean()),
            "avg_risk": float(risk[phase_assets].mean()),
        })

    return {
        "migration_order": order,
        "priorities": priority.cpu().tolist(),
        "risks": risk.cpu().tolist(),
        "phases": phases,
        "total_assets": n,
        "estimated_weeks": n * 0.5,  # 0.5 weeks per asset (rough estimate)
    }


if __name__ == "__main__":
    # Test with a synthetic CBOM
    from .data_generator import generate_synthetic_cbom
    cbom = generate_synthetic_cbom(n_assets=50, seed=999)
    plan = plan_migration(cbom)
    print(f"Migration plan for {plan['total_assets']} assets:")
    print(f"  Estimated weeks: {plan['estimated_weeks']:.1f}")
    print(f"  Phases: {len(plan['phases'])}")
    for phase in plan['phases']:
        print(f"  Phase {phase['phase']}: {len(phase['asset_indices'])} assets, "
              f"avg_priority={phase['avg_priority']:.3f}, avg_risk={phase['avg_risk']:.3f}")
```

### 8.7 Package Init

Create `planner/qtrust_planner/__init__.py`:

```python
# /home/z/qtrust/planner/qtrust_planner/__init__.py
"""Q-Trust FIGNN Migration Planner."""
from .model import MigrationGNN, predict_migration_order
from .planner import plan_migration, load_model
from .data_generator import generate_synthetic_cbom, generate_training_dataset

__version__ = "0.1.0"
__all__ = [
    "MigrationGNN", "predict_migration_order",
    "plan_migration", "load_model",
    "generate_synthetic_cbom", "generate_training_dataset",
]
```

### 8.8 Train and Test

In your BrevLab terminal, switch to the fignn_env kernel:

```bash
conda activate fignn_env
cd /home/z/qtrust/planner
pip install -e ".[dev]"

# Generate training data (500 synthetic CBOMs)
python -m qtrust_planner.train

# Expected output:
#   Training on: cuda  (or cpu if no GPU)
#   Loaded 500 graphs
#   Train: 400, Val: 100
#   Epoch 10/50: train_loss=0.1234, val_loss=0.1456
#   Epoch 20/50: train_loss=0.0987, val_loss=0.1122
#   ...
#   Training complete. Best val loss: 0.0876
#   Model saved to /home/z/qtrust/planner/best_model.pt

# Test the planner
python -m qtrust_planner.planner

# Expected output:
#   Migration plan for 50 assets:
#     Estimated weeks: 25.0
#     Phases: 4
#     Phase 1: 13 assets, avg_priority=0.845, avg_risk=0.612
#     Phase 2: 13 assets, ...
```

Commit:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 5: FIGNN migration planner with synthetic data and training"
git push
```

---

## 9. Phase 6: Backend Services

### 9.1 Project Structure

```bash
cd /home/z/qtrust/backend
bun init -y
bun add fastify viem @fastify/cors @fastify/websocket ioredis bullmq dotenv
bun add -D typescript @types/node

mkdir -p src/{services,routes,middleware,lib} __tests__
```

Create `backend/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "node",
    "esModuleInterop": true,
    "strict": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src/**/*"]
}
```

### 9.2 Contract ABIs (TypeScript)

Create `backend/src/lib/abis.ts`:

```typescript
// /home/z/qtrust/backend/src/lib/abis.ts
export const AssetRegistryAbi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, internalType: "bytes32", name: "assetId", type: "bytes32" },
      { indexed: true, internalType: "address", name: "orgDid", type: "address" },
      { indexed: false, internalType: "bytes32", name: "cbomHash", type: "bytes32" },
      { indexed: false, internalType: "string", name: "metadataURI", type: "string" },
      { indexed: false, internalType: "uint256", name: "timestamp", type: "uint256" },
    ],
    name: "CBOMRegistered",
    type: "event",
  },
  {
    inputs: [
      { internalType: "bytes32", name: "cbomHash", type: "bytes32" },
      { internalType: "string", name: "metadataURI", type: "string" },
    ],
    name: "registerCBOM",
    outputs: [{ internalType: "bytes32", name: "assetId", type: "bytes32" }],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [{ internalType: "bytes32", name: "assetId", type: "bytes32" }],
    name: "getAsset",
    outputs: [
      { internalType: "address", name: "orgDid", type: "address" },
      { internalType: "bytes32", name: "cbomHash", type: "bytes32" },
      { internalType: "string", name: "metadataURI", type: "string" },
      { internalType: "uint256", name: "registeredAt", type: "uint256" },
      { internalType: "uint256", name: "lastUpdated", type: "uint256" },
      { internalType: "bool", name: "active", type: "bool" },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "assetCount",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [{ internalType: "address", name: "orgDid", type: "address" }],
    name: "getAssetsByOrg",
    outputs: [{ internalType: "bytes32[]", name: "", type: "bytes32[]" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

export const VendorRegistryAbi = [
  {
    inputs: [
      { internalType: "address", name: "vendorDid", type: "address" },
      { internalType: "string", name: "name", type: "string" },
      { internalType: "string", name: "metadataURI", type: "string" },
    ],
    name: "registerVendor",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      { internalType: "bytes32", name: "attestationId", type: "bytes32" },
      { internalType: "string", name: "productId", type: "string" },
      { internalType: "string", name: "version", type: "string" },
      { internalType: "string", name: "algorithm", type: "string" },
      { internalType: "bool", name: "supported", type: "bool" },
      { internalType: "string", name: "evidenceURI", type: "string" },
    ],
    name: "attestProduct",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [{ internalType: "bytes32", name: "attestationId", type: "bytes32" }],
    name: "getAttestation",
    outputs: [
      { internalType: "address", name: "vendorDid", type: "address" },
      { internalType: "bytes32", name: "productHash", type: "bytes32" },
      { internalType: "string", name: "productId", type: "string" },
      { internalType: "string", name: "version", type: "string" },
      { internalType: "string", name: "algorithm", type: "string" },
      { internalType: "bool", name: "supported", type: "bool" },
      { internalType: "string", name: "evidenceURI", type: "string" },
      { internalType: "uint256", name: "timestamp", type: "uint256" },
      { internalType: "bool", name: "revoked", type: "bool" },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      { internalType: "string", name: "productId", type: "string" },
      { internalType: "string", name: "version", type: "string" },
    ],
    name: "getAttestationsByProduct",
    outputs: [{ internalType: "bytes32[]", name: "", type: "bytes32[]" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

export const MigrationRegistryAbi = [
  {
    inputs: [
      { internalType: "bytes32", name: "migrationId", type: "bytes32" },
      { internalType: "bytes32", name: "assetId", type: "bytes32" },
      { internalType: "string", name: "fromAlgorithm", type: "string" },
      { internalType: "string", name: "toAlgorithm", type: "string" },
      { internalType: "bytes32", name: "evidenceHash", type: "bytes32" },
      { internalType: "string", name: "evidenceURI", type: "string" },
    ],
    name: "recordMigration",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [{ internalType: "bytes32", name: "migrationId", type: "bytes32" }],
    name: "getMigration",
    outputs: [
      { internalType: "bytes32", name: "assetId", type: "bytes32" },
      { internalType: "address", name: "orgDid", type: "address" },
      { internalType: "string", name: "fromAlgorithm", type: "string" },
      { internalType: "string", name: "toAlgorithm", type: "string" },
      { internalType: "bytes32", name: "evidenceHash", type: "bytes32" },
      { internalType: "string", name: "evidenceURI", type: "string" },
      { internalType: "uint256", name: "timestamp", type: "uint256" },
      { internalType: "bool", name: "verified", type: "bool" },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [{ internalType: "bytes32", name: "assetId", type: "bytes32" }],
    name: "getMigrationsByAsset",
    outputs: [{ internalType: "bytes32[]", name: "", type: "bytes32[]" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

export const AuditRegistryAbi = [
  {
    inputs: [
      { internalType: "bytes32", name: "auditId", type: "bytes32" },
      { internalType: "address", name: "orgDid", type: "address" },
      { internalType: "uint8", name: "result", type: "uint8" },
      { internalType: "uint256", name: "assetsReviewed", type: "uint256" },
      { internalType: "uint256", name: "assetsPassed", type: "uint256" },
      { internalType: "bytes32", name: "reportHash", type: "bytes32" },
      { internalType: "string", name: "reportURI", type: "string" },
    ],
    name: "postAudit",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [{ internalType: "bytes32", name: "auditId", type: "bytes32" }],
    name: "getAudit",
    outputs: [
      { internalType: "address", name: "orgDid", type: "address" },
      { internalType: "address", name: "auditorDid", type: "address" },
      { internalType: "uint8", name: "result", type: "uint8" },
      { internalType: "uint256", name: "assetsReviewed", type: "uint256" },
      { internalType: "uint256", name: "assetsPassed", type: "uint256" },
      { internalType: "bytes32", name: "reportHash", type: "bytes32" },
      { internalType: "string", name: "reportURI", type: "string" },
      { internalType: "uint256", name: "timestamp", type: "uint256" },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;
```

### 9.3 Verification Service

Create `backend/src/services/verify.ts`:

```typescript
// /home/z/qtrust/backend/src/services/verify.ts
import { createPublicClient, http } from "viem";
import { baseSepolia } from "viem/chains";
import { AssetRegistryAbi, VendorRegistryAbi, MigrationRegistryAbi, AuditRegistryAbi } from "../lib/abis";
import * as dotenv from "dotenv";
dotenv.config();

const RPC_URL = process.env.QTRUST_BASE_SEPOLIA_RPC!;
const ASSET_REGISTRY = process.env.QTRUST_ASSET_REGISTRY_ADDRESS as `0x${string}`;
const VENDOR_REGISTRY = process.env.QTRUST_VENDOR_REGISTRY_ADDRESS as `0x${string}`;
const MIGRATION_REGISTRY = process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS as `0x${string}`;
const AUDIT_REGISTRY = process.env.QTRUST_AUDIT_REGISTRY_ADDRESS as `0x${string}`;

const publicClient = createPublicClient({
  chain: baseSepolia,
  transport: http(RPC_URL),
});

export interface AssetInfo {
  asset_id: string;
  org_did: string;
  cbom_hash: string;
  metadata_uri: string;
  registered_at: number;
  last_updated: number;
  active: boolean;
  metadata?: any;
}

export async function getAsset(assetId: string): Promise<AssetInfo | null> {
  try {
    const attIdBytes = (assetId.startsWith("0x") ? assetId.slice(2) : assetId) as `0x${string}`;
    const raw = await publicClient.readContract({
      address: ASSET_REGISTRY,
      abi: AssetRegistryAbi,
      functionName: "getAsset",
      args: [`0x${attIdBytes}` as any],
    }) as any[];

    const [orgDid, cbomHash, metadataURI, registeredAt, lastUpdated, active] = raw;

    // Try to fetch CBOM from IPFS
    let metadata = null;
    if (metadataURI && metadataURI.startsWith("ipfs://")) {
      const cid = metadataURI.replace("ipfs://", "");
      try {
        const resp = await fetch(`https://gateway.pinata.cloud/ipfs/${cid}`);
        metadata = await resp.json();
      } catch (e) {
        // IPFS might be unavailable
      }
    }

    return {
      asset_id: assetId,
      org_did: orgDid,
      cbom_hash: cbomHash,
      metadata_uri: metadataURI,
      registered_at: Number(registeredAt),
      last_updated: Number(lastUpdated),
      active,
      metadata,
    };
  } catch (e) {
    return null;
  }
}

export async function getAssetsByOrg(orgDid: string): Promise<string[]> {
  const ids = await publicClient.readContract({
    address: ASSET_REGISTRY,
    abi: AssetRegistryAbi,
    functionName: "getAssetsByOrg",
    args: [orgDid as `0x${string}`],
  }) as any[];
  return ids.map((id) => "0x" + id.toString(16).padStart(64, "0"));
}

export async function getAttestation(attestationId: string) {
  const raw = await publicClient.readContract({
    address: VENDOR_REGISTRY,
    abi: VendorRegistryAbi,
    functionName: "getAttestation",
    args: [attestationId as `0x${string}`],
  }) as any[];
  return {
    attestation_id: attestationId,
    vendor_did: raw[0],
    product_id: raw[2],
    version: raw[3],
    algorithm: raw[4],
    supported: raw[5],
    evidence_uri: raw[6],
    timestamp: Number(raw[7]),
    revoked: raw[8],
  };
}

export async function getMigration(migrationId: string) {
  const raw = await publicClient.readContract({
    address: MIGRATION_REGISTRY,
    abi: MigrationRegistryAbi,
    functionName: "getMigration",
    args: [migrationId as `0x${string}`],
  }) as any[];
  return {
    migration_id: migrationId,
    asset_id: "0x" + raw[0].toString(16).padStart(64, "0"),
    org_did: raw[1],
    from_algorithm: raw[2],
    to_algorithm: raw[3],
    evidence_hash: raw[4],
    evidence_uri: raw[5],
    timestamp: Number(raw[6]),
    verified: raw[7],
  };
}

export async function getAudit(auditId: string) {
  const raw = await publicClient.readContract({
    address: AUDIT_REGISTRY,
    abi: AuditRegistryAbi,
    functionName: "getAudit",
    args: [auditId as `0x${string}`],
  }) as any[];
  return {
    audit_id: auditId,
    org_did: raw[0],
    auditor_did: raw[1],
    result: raw[2],
    assets_reviewed: Number(raw[3]),
    assets_passed: Number(raw[4]),
    report_hash: raw[5],
    report_uri: raw[6],
    timestamp: Number(raw[7]),
  };
}
```

### 9.4 Attestation Service (Relayer)

Create `backend/src/services/attestation.ts`:

```typescript
// /home/z/qtrust/backend/src/services/attestation.ts
import { createWalletClient, http } from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { AssetRegistryAbi, VendorRegistryAbi, MigrationRegistryAbi } from "../lib/abis";
import * as dotenv from "dotenv";
dotenv.config();

const RELAYER_KEY = process.env.QTRUST_RELAYER_PRIVATE_KEY || process.env.QTRUST_DEPLOYER_PRIVATE_KEY!;
const RPC_URL = process.env.QTRUST_BASE_SEPOLIA_RPC!;
const ASSET_REGISTRY = process.env.QTRUST_ASSET_REGISTRY_ADDRESS as `0x${string}`;
const VENDOR_REGISTRY = process.env.QTRUST_VENDOR_REGISTRY_ADDRESS as `0x${string}`;
const MIGRATION_REGISTRY = process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS as `0x${string}`;

const account = privateKeyToAccount(RELAYER_KEY as `0x${string}`);
const client = createWalletClient({
  account,
  chain: baseSepolia,
  transport: http(RPC_URL),
});

export interface RegisterCBOMPayload {
  cbomHash: string;
  metadataURI: string;
}

export async function registerCBOM(payload: RegisterCBOMPayload) {
  const txHash = await client.writeContract({
    address: ASSET_REGISTRY,
    abi: AssetRegistryAbi,
    functionName: "registerCBOM",
    args: [
      payload.cbomHash as `0x${string}`,
      payload.metadataURI,
    ],
  });
  return { txHash };
}

export interface AttestProductPayload {
  attestationId: string;
  productId: string;
  version: string;
  algorithm: string;
  supported: boolean;
  evidenceURI: string;
}

export async function attestProduct(payload: AttestProductPayload) {
  const txHash = await client.writeContract({
    address: VENDOR_REGISTRY,
    abi: VendorRegistryAbi,
    functionName: "attestProduct",
    args: [
      payload.attestationId as `0x${string}`,
      payload.productId,
      payload.version,
      payload.algorithm,
      payload.supported,
      payload.evidenceURI,
    ],
  });
  return { txHash };
}

export interface RecordMigrationPayload {
  migrationId: string;
  assetId: string;
  fromAlgorithm: string;
  toAlgorithm: string;
  evidenceHash: string;
  evidenceURI: string;
}

export async function recordMigration(payload: RecordMigrationPayload) {
  const txHash = await client.writeContract({
    address: MIGRATION_REGISTRY,
    abi: MigrationRegistryAbi,
    functionName: "recordMigration",
    args: [
      payload.migrationId as `0x${string}`,
      payload.assetId as `0x${string}`,
      payload.fromAlgorithm,
      payload.toAlgorithm,
      payload.evidenceHash as `0x${string}`,
      payload.evidenceURI,
    ],
  });
  return { txHash };
}
```

### 9.5 Webhook Service

Create `backend/src/services/webhook.ts`:

```typescript
// /home/z/qtrust/backend/src/services/webhook.ts
import { createPublicClient, http, parseAbiItem } from "viem";
import { baseSepolia } from "viem/chains";
import Redis from "ioredis";
import { Queue, Worker } from "bullmq";
import * as dotenv from "dotenv";
dotenv.config();

const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379");
const webhookQueue = new Queue("webhooks", { connection: redis });

const publicClient = createPublicClient({
  chain: baseSepolia,
  transport: http(process.env.QTRUST_BASE_SEPOLIA_RPC!),
});

const VENDOR_REGISTRY = process.env.QTRUST_VENDOR_REGISTRY_ADDRESS as `0x${string}`;

// Watch for ProductAttested events (new vendor PQC attestations)
const unwatch = publicClient.watchEvent({
  address: VENDOR_REGISTRY,
  event: parseAbiItem(
    "event ProductAttested(bytes32 indexed attestationId, address indexed vendorDid, bytes32 indexed productHash, string productId, string version, string algorithm, bool supported, string evidenceURI, uint256 timestamp)"
  ),
  onLogs: async (logs) => {
    for (const log of logs as any[]) {
      const args = log.args;
      console.log(`New vendor attestation: ${args.attestationId}`);
      await webhookQueue.add("deliver", {
        event: "vendor.attestation_posted",
        data: {
          attestation_id: "0x" + args.attestationId.toString(16).padStart(64, "0"),
          vendor_did: args.vendorDid,
          product_id: args.productId,
          version: args.version,
          algorithm: args.algorithm,
          supported: args.supported,
          timestamp: Number(args.timestamp),
        },
      });
    }
  },
});

const worker = new Worker("webhooks", async (job) => {
  const { event, data } = job.data;
  const subscribers = await redis.smembers(`subscribers:${event}`);
  for (const url of subscribers) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event, data, timestamp: Date.now() }),
      });
      if (!resp.ok) throw new Error(`Webhook returned ${resp.status}`);
      console.log(`Webhook delivered to ${url}`);
    } catch (e) {
      console.error(`Webhook failed for ${url}:`, e);
      throw e;
    }
  }
}, { connection: redis });

console.log("Webhook service started");
```

### 9.6 Fastify Server

Create `backend/src/server.ts`:

```typescript
// /home/z/qtrust/backend/src/server.ts
import Fastify from "fastify";
import cors from "@fastify/cors";
import { getAsset, getAssetsByOrg, getAttestation, getMigration, getAudit } from "./services/verify";
import { registerCBOM, attestProduct, recordMigration } from "./services/attestation";
import * as dotenv from "dotenv";
dotenv.config();

const app = Fastify({ logger: true });

await app.register(cors, { origin: "*" });

app.get("/health", async () => ({ status: "ok", timestamp: Date.now() }));

// Public: get an asset by ID
app.get<{ Params: { id: string } }>("/v1/assets/:id", async (request, reply) => {
  const asset = await getAsset(request.params.id);
  if (!asset) return reply.code(404).send({ error: "Asset not found" });
  return asset;
});

// Public: get all assets for an org
app.get<{ Params: { org: string } }>("/v1/orgs/:org/assets", async (request) => {
  const ids = await getAssetsByOrg(request.params.org);
  return { org: request.params.org, asset_ids: ids };
});

// Public: get a vendor attestation
app.get<{ Params: { id: string } }>("/v1/attestations/:id", async (request, reply) => {
  try {
    const att = await getAttestation(request.params.id);
    return att;
  } catch (e: any) {
    return reply.code(404).send({ error: "Attestation not found", message: e.message });
  }
});

// Public: get a migration record
app.get<{ Params: { id: string } }>("/v1/migrations/:id", async (request, reply) => {
  try {
    const mig = await getMigration(request.params.id);
    return mig;
  } catch (e: any) {
    return reply.code(404).send({ error: "Migration not found" });
  }
});

// Public: get an audit
app.get<{ Params: { id: string } }>("/v1/audits/:id", async (request, reply) => {
  try {
    const audit = await getAudit(request.params.id);
    return audit;
  } catch (e: any) {
    return reply.code(404).send({ error: "Audit not found" });
  }
});

// Authenticated: register a CBOM (via relayer)
app.post("/v1/assets", async (request, reply) => {
  // TODO: verify EIP-712 signature
  const payload = request.body as any;
  try {
    const result = await registerCBOM(payload);
    return reply.code(201).send(result);
  } catch (e: any) {
    request.log.error(e);
    return reply.code(500).send({ error: "Registration failed", message: e.message });
  }
});

// Authenticated: post a vendor attestation
app.post("/v1/attestations", async (request, reply) => {
  const payload = request.body as any;
  try {
    const result = await attestProduct(payload);
    return reply.code(201).send(result);
  } catch (e: any) {
    return reply.code(500).send({ error: "Attestation failed", message: e.message });
  }
});

// Authenticated: record a migration
app.post("/v1/migrations", async (request, reply) => {
  const payload = request.body as any;
  try {
    const result = await recordMigration(payload);
    return reply.code(201).send(result);
  } catch (e: any) {
    return reply.code(500).send({ error: "Recording failed", message: e.message });
  }
});

const PORT = parseInt(process.env.PORT || "3001", 10);
const HOST = process.env.HOST || "0.0.0.0";

app.listen({ port: PORT, host: HOST }).then(() => {
  app.log.info(`Q-Trust backend listening on http://${HOST}:${PORT}`);
});
```

### 9.7 Docker Compose

Create `backend/docker-compose.yml`:

```yaml
# /home/z/qtrust/backend/docker-compose.yml
version: '3.9'
services:
  api:
    build: .
    ports:
      - "3001:3001"
    environment:
      - PORT=3001
      - HOST=0.0.0.0
      - REDIS_URL=redis://redis:6379
      - QTRUST_BASE_SEPOLIA_RPC=${QTRUST_BASE_SEPOLIA_RPC}
      - QTRUST_ASSET_REGISTRY_ADDRESS=${QTRUST_ASSET_REGISTRY_ADDRESS}
      - QTRUST_VENDOR_REGISTRY_ADDRESS=${QTRUST_VENDOR_REGISTRY_ADDRESS}
      - QTRUST_MIGRATION_REGISTRY_ADDRESS=${QTRUST_MIGRATION_REGISTRY_ADDRESS}
      - QTRUST_AUDIT_REGISTRY_ADDRESS=${QTRUST_AUDIT_REGISTRY_ADDRESS}
      - QTRUST_DEPLOYER_PRIVATE_KEY=${QTRUST_DEPLOYER_PRIVATE_KEY}
    depends_on:
      - redis
    restart: unless-stopped

  webhook:
    build: .
    command: bun run src/services/webhook.ts
    environment:
      - REDIS_URL=redis://redis:6379
      - QTRUST_BASE_SEPOLIA_RPC=${QTRUST_BASE_SEPOLIA_RPC}
      - QTRUST_VENDOR_REGISTRY_ADDRESS=${QTRUST_VENDOR_REGISTRY_ADDRESS}
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

Create `backend/Dockerfile`:

```dockerfile
# /home/z/qtrust/backend/Dockerfile
FROM oven/bun:1.1 as base
WORKDIR /app

COPY package.json bun.lockb ./
RUN bun install --frozen-lockfile --production

COPY . .

RUN bun run tsc || true

EXPOSE 3001
CMD ["bun", "run", "src/server.ts"]
```

### 9.8 Run the Backend

```bash
cd /home/z/qtrust/backend
docker-compose up -d

# Test it
curl http://localhost:3001/health
# Expected: {"status":"ok","timestamp":1700000000000}

# Test fetching an asset (replace with your actual asset ID)
curl http://localhost:3001/v1/assets/0x<your-asset-id>
```

Commit:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 6: backend services with Fastify, viem, and Docker"
git push
```

---

## 10. Phase 7: Frontend Dashboard (Next.js)

### 10.1 Project Scaffold

```bash
cd /home/z/qtrust/frontend
bun create next-app . --typescript --tailwind --app --eslint --src-dir --import-alias "@/*"
# Answer Yes to all prompts

bun add viem @tanstack/react-query reactflow @dynamic-labs/sdk-react
bun add -D @types/react @types/node
```

### 10.2 Public Verification Page

Create `frontend/src/app/v/[id]/page.tsx`:

```typescript
// /home/z/qtrust/frontend/src/app/v/[id]/page.tsx
import { notFound } from 'next/navigation';
import ReactFlow, { Background, Controls, Node, Edge } from 'reactflow';
import 'reactflow/dist/style.css';

interface AssetInfo {
  asset_id: string;
  org_did: string;
  cbom_hash: string;
  metadata_uri: string;
  registered_at: number;
  last_updated: number;
  active: boolean;
  metadata?: {
    org_did: string;
    generated_at: number;
    scanner_version: string;
    assets: Array<{
      asset_type: string;
      algorithm: string;
      location: string;
      vendor?: string;
      criticality: string;
    }>;
    summary: { total_assets: number; by_algorithm: Record<string, number> };
  } | null;
}

async function getAsset(id: string): Promise<AssetInfo | null> {
  try {
    const resp = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/v1/assets/${id}`, {
      next: { revalidate: 30 },
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

export default async function VerificationPage({ params }: { params: { id: string } }) {
  const asset = await getAsset(params.id);
  if (!asset) notFound();

  const status = asset.active ? 'ACTIVE' : 'DEACTIVATED';
  const statusColor = asset.active ? 'text-green-600' : 'text-red-600';
  const date = new Date(asset.registered_at * 1000).toLocaleString();

  // Build React Flow graph from CBOM assets
  const cbomAssets = asset.metadata?.assets || [];
  const nodes: Node[] = cbomAssets.slice(0, 50).map((a, i) => ({
    id: `asset-${i}`,
    position: { x: (i % 8) * 150, y: Math.floor(i / 8) * 120 },
    data: { label: `${a.asset_type}\n${a.algorithm}\n${a.location}` },
    style: {
      background: a.algorithm.startsWith('RSA') ? '#fee2e2' :
                  a.algorithm.startsWith('ECC') ? '#fef3c7' :
                  '#dbeafe',
      padding: 8,
      borderRadius: 6,
      fontSize: 10,
    },
  }));

  const edges: Edge[] = [];

  return (
    <main className="container mx-auto px-4 py-8 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">
          CBOM {asset.asset_id.slice(0, 18)}...
        </h1>
        <p className="text-lg">
          Status: <span className={`font-bold ${statusColor}`}>{status}</span>
        </p>
        <p className="text-sm text-gray-500">
          Registered by {asset.org_did} on {date}
        </p>
      </div>

      {asset.metadata && (
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">CBOM Summary</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <div className="text-sm text-gray-500">Total Assets</div>
              <div className="text-2xl font-bold">
                {asset.metadata.summary.total_assets}
              </div>
            </div>
            {Object.entries(asset.metadata.summary.by_algorithm).slice(0, 3).map(([alg, count]) => (
              <div key={alg}>
                <div className="text-sm text-gray-500">{alg}</div>
                <div className="text-2xl font-bold">{count}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Asset Graph</h2>
        <div style={{ height: 400 }}>
          <ReactFlow nodes={nodes} edges={edges} fitView>
            <Background />
            <Controls />
          </ReactFlow>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">Details</h2>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <dt className="font-semibold">CBOM Hash</dt>
            <dd className="font-mono break-all">{asset.cbom_hash}</dd>
          </div>
          <div>
            <dt className="font-semibold">Metadata URI</dt>
            <dd className="font-mono break-all">{asset.metadata_uri}</dd>
          </div>
        </dl>
      </div>

      <div className="mt-8 text-center text-sm text-gray-500">
        Verify independently: <code className="bg-gray-100 px-2 py-1 rounded">qtrust verify {asset.asset_id}</code>
      </div>
    </main>
  );
}
```

### 10.3 Organization Dashboard

Create `frontend/src/app/dashboard/page.tsx`:

```typescript
// /home/z/qtrust/frontend/src/app/dashboard/page.tsx
'use client';
import { useDynamicContext } from '@dynamic-labs/sdk-react';
import { useQuery } from '@tanstack/react-query';

export default function DashboardPage() {
  const { user, isAuthenticated } = useDynamicContext();

  const { data: assets, isLoading } = useQuery({
    queryKey: ['assets', user?.walletPublicKey],
    queryFn: async () => {
      const resp = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/v1/orgs/${user?.walletPublicKey}/assets`
      );
      if (!resp.ok) throw new Error('Failed to fetch');
      return resp.json();
    },
    enabled: isAuthenticated,
  });

  if (!isAuthenticated) {
    return (
      <main className="container mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold mb-4">Organization Dashboard</h1>
        <p>Please sign in with your wallet to view your dashboard.</p>
      </main>
    );
  }

  return (
    <main className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">Organization Dashboard</h1>

      <div className="bg-white rounded-lg shadow p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Your CBOMs</h2>
        {isLoading ? (
          <p>Loading...</p>
        ) : !assets?.asset_ids?.length ? (
          <p className="text-gray-500">No CBOMs registered yet. Run `qtrust-scan host example.com --register` to post your first one.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left py-2">Asset ID</th>
                <th className="text-left py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {assets.asset_ids.map((id: string) => (
                <tr key={id} className="border-b">
                  <td className="py-2 font-mono text-sm">{id.slice(0, 18)}...</td>
                  <td className="py-2">
                    <a href={`/v/${id}`} className="text-blue-600 hover:underline">View</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </main>
  );
}
```

### 10.4 Authentication Provider

Create `frontend/src/app/providers.tsx`:

```typescript
// /home/z/qtrust/frontend/src/app/providers.tsx
'use client';
import { DynamicContextProvider } from '@dynamic-labs/sdk-react';
import { ReactNode } from 'react';

export function Providers({ children }: { children: ReactNode }) {
  return (
    <DynamicContextProvider
      settings={{
        environmentId: process.env.NEXT_PUBLIC_DYNAMIC_ENV_ID!,
        walletConnectors: ['metamask', 'walletconnect'],
      }}
    >
      {children}
    </DynamicContextProvider>
  );
}
```

Update `frontend/src/app/layout.tsx` to wrap with Providers:

```typescript
// /home/z/qtrust/frontend/src/app/layout.tsx
import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Providers } from './providers';
import { DynamicWidget } from '@dynamic-labs/sdk-react';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Q-Trust — PQC Migration Coordinator',
  description: 'Verifiable post-quantum cryptography migration coordination',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <Providers>
          <nav className="border-b p-4 flex justify-between items-center">
            <a href="/" className="text-xl font-bold">Q-Trust</a>
            <DynamicWidget />
          </nav>
          {children}
        </Providers>
      </body>
    </html>
  );
}
```

### 10.5 Home Page

Update `frontend/src/app/page.tsx`:

```typescript
// /home/z/qtrust/frontend/src/app/page.tsx
import Link from 'next/link';

export default function Home() {
  return (
    <main className="container mx-auto px-4 py-16 max-w-4xl">
      <h1 className="text-5xl font-bold mb-6">
        Q-Trust
      </h1>
      <p className="text-xl text-gray-600 mb-8">
        Post-Quantum Cryptography Migration Coordinator.
        The shared trust layer for the largest cryptographic migration in history.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="font-bold text-lg mb-2">Inventory</h3>
          <p className="text-sm text-gray-600">
            Scan your infrastructure for cryptographic assets. Produce a CBOM in minutes.
          </p>
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="font-bold text-lg mb-2">Verify</h3>
          <p className="text-sm text-gray-600">
            Cross-reference vendor PQC claims with on-chain attestations.
          </p>
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="font-bold text-lg mb-2">Migrate</h3>
          <p className="text-sm text-gray-600">
            Plan your migration with a GNN-trained dependency-aware planner.
          </p>
        </div>
      </div>
      <div className="space-x-4">
        <Link href="/dashboard" className="bg-blue-600 text-white px-6 py-3 rounded-lg inline-block">
          Open Dashboard
        </Link>
        <Link href="/v/0x0000000000000000000000000000000000000000000000000000000000000000"
              className="border border-gray-300 px-6 py-3 rounded-lg inline-block">
          View Sample CBOM
        </Link>
      </div>
    </main>
  );
}
```

### 10.6 Deploy to Vercel

1. Push your code to GitHub:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 7: Next.js frontend"
git push
```

2. Go to https://vercel.com and sign in with GitHub. Import your `qtrust` repository. Set the root directory to `frontend`.

3. Add these environment variables in Vercel:
   - `NEXT_PUBLIC_API_URL` = `https://your-backend-url.com`
   - `NEXT_PUBLIC_DYNAMIC_ENV_ID` = your Dynamic environment ID
   - `NEXT_PUBLIC_ASSET_REGISTRY_ADDRESS` = your deployed contract address

4. Click Deploy. Vercel gives you a URL like `qtrust-frontend.vercel.app`.

Commit:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 7: Next.js dashboard with React Flow and SIWE"
git push
```

---

## 11. Phase 8: Pilot & Demo

This is the capstone phase. You will simulate a bank's PQC migration end-to-end: scan a target, register the CBOM on Base Sepolia, simulate Shor's algorithm against the discovered keys, run the GNN migration planner, post a migration record on-chain, and demo the verification dashboard.

### 11.1 Pilot Overview

**Scenario:** First National Bank (a fictional mid-size bank) must comply with OMB M-23-02. Their CISO Alice coordinates the migration of her infrastructure's TLS certificates and SSH keys.

**Steps:**
1. Run `qtrust-scan` against a target (example.com or your BrevLab instance)
2. Register the CBOM on Base Sepolia via the inspector's `--register` flag
3. Open the qiskit sales notebook — show how Shor's algorithm breaks the discovered RSA keys
4. Run the FIGNN migration planner on the CBOM
5. Record a mock migration on-chain via the SDK
6. Open the verification dashboard — show the CBOM, the migration record, the audit trail

### 11.2 Step-by-Step Pilot Script

Create `pilot/run_pilot.py`:

```python
# /home/z/qtrust/pilot/run_pilot.py
"""End-to-end Q-Trust pilot demo script.

This script simulates the full PQC migration workflow for a fictional bank.
Run it in the qtrust conda environment on your BrevLab instance.
"""
import json
import time
import hashlib
import os
import sys
from pathlib import Path

# Ensure SDK is on the path
sys.path.insert(0, '/home/z/qtrust/sdk')
sys.path.insert(0, '/home/z/qtrust/inspector')
sys.path.insert(0, '/home/z/qtrust/planner')


def step1_scan_target(target: str = "example.com"):
    """Step 1: Scan a target host for cryptographic assets."""
    print("\n" + "=" * 70)
    print("STEP 1: Scan target for cryptographic assets")
    print("=" * 70)
    print(f"Target: {target}")

    from qtrust_inspector import scan_host
    result = scan_host(target, [443, 22])

    print(f"\nScan complete:")
    print(f"  Findings: {result.finding_count}")
    print(f"  By algorithm: {result.by_algorithm}")
    print(f"  By type: {result.by_type}")

    for f in result.findings:
        print(f"  - {f.asset_type}: {f.algorithm} at {f.location} (vendor: {f.vendor or 'unknown'})")

    return result


def step2_register_cbom(scan_result):
    """Step 2: Register the CBOM on Base Sepolia."""
    print("\n" + "=" * 70)
    print("STEP 2: Register CBOM on Base Sepolia")
    print("=" * 70)

    from qtrust import QTrustClient
    from qtrust.schema import CBOM, CBOMEntry

    try:
        client = QTrustClient()
    except Exception as e:
        print(f"ERROR: Could not initialize Q-Trust client: {e}")
        print("Make sure your BrevLab env vars are set (QTRUST_DEPLOYER_PRIVATE_KEY, etc.)")
        return None

    entries = [
        CBOMEntry(
            asset_type=f.asset_type,
            algorithm=f.algorithm,
            location=f.location,
            vendor=f.vendor,
            criticality=f.criticality,
            expires_at=f.expires_at,
        ) for f in scan_result.findings
    ]

    cbom = CBOM(
        org_did=f"did:ethr:{client.account.address}",
        generated_at=scan_result.started_at,
        scanner_version="0.1.0",
        assets=entries,
        summary={
            "total_assets": len(entries),
            "by_algorithm": scan_result.by_algorithm,
            "by_type": scan_result.by_type,
        },
    )

    print("Posting CBOM to Base Sepolia...")
    try:
        asset_id, ipfs_cid = client.register_cbom(cbom, pin_to_ipfs=True)
        print(f"\nCBOM registered!")
        print(f"  Asset ID: {asset_id}")
        if ipfs_cid:
            print(f"  IPFS CID: {ipfs_cid}")
        print(f"  Basescan: https://sepolia.basescan.org/address/{client.asset_registry_address}")
        return asset_id
    except Exception as e:
        print(f"ERROR: Registration failed: {e}")
        return None


def step3_quantum_analysis(key_sizes: list = None):
    """Step 3: Simulate Shor's algorithm (load results from Phase 4 notebook)."""
    print("\n" + "=" * 70)
    print("STEP 3: Quantum threat analysis (refer to qiskit notebook)")
    print("=" * 70)

    if key_sizes is None:
        key_sizes = [1024, 2048, 3072, 4096]

    def logical_qubits(n_bits):
        return 2 * n_bits + 3

    def physical_qubits(n_bits):
        return logical_qubits(n_bits) * 1000

    roadmap = [
        (2024, 1121), (2025, 4158), (2026, 10000),
        (2027, 20000), (2028, 50000), (2029, 100000),
        (2030, 200000), (2031, 500000), (2032, 1000000),
        (2033, 2000000),
    ]

    print(f"\n{'Key Size':<12} {'Required Qubits':<20} {'Breakable Year':<15}")
    print("-" * 47)

    for n in key_sizes:
        required = physical_qubits(n)
        breakable_year = None
        for year, qubits in roadmap:
            if qubits >= required:
                breakable_year = year
                break
        year_str = str(breakable_year) if breakable_year else "After 2033"
        print(f"RSA-{n:<8} {required:<20,} {year_str}")

    print("\nNote: For the full Shor's algorithm demonstration, run the notebook:")
    print("  /home/z/qtrust/notebooks/04_shor_sales_demo.ipynb")
    print("  (use the qiskit311 kernel)")


def step4_migration_plan(asset_id: str):
    """Step 4: Generate a migration plan using the FIGNN planner."""
    print("\n" + "=" * 70)
    print("STEP 4: Generate GNN-based migration plan")
    print("=" * 70)

    try:
        from qtrust_planner.planner import plan_migration
        from qtrust_planner.data_generator import generate_synthetic_cbom

        # For the pilot, use a synthetic CBOM (real one would come from the registry)
        cbom = generate_synthetic_cbom(n_assets=50, seed=42)
        plan = plan_migration(cbom)

        print(f"\nMigration plan generated for {plan['total_assets']} assets:")
        print(f"  Estimated weeks: {plan['estimated_weeks']:.1f}")
        print(f"  Phases: {len(plan['phases'])}")

        for phase in plan['phases']:
            print(f"\n  Phase {phase['phase']}:")
            print(f"    Assets: {len(phase['asset_indices'])}")
            print(f"    Avg priority: {phase['avg_priority']:.3f}")
            print(f"    Avg risk: {phase['avg_risk']:.3f}")
            print(f"    Sample locations:")
            for loc in phase['asset_locations'][:3]:
                print(f"      - {loc}")

        return plan
    except Exception as e:
        print(f"ERROR: Could not run migration planner: {e}")
        print("Make sure the FIGNN model is trained (Phase 5)")
        return None


def step5_record_migration(asset_id: str):
    """Step 5: Record a mock migration on-chain."""
    print("\n" + "=" * 70)
    print("STEP 5: Record migration on-chain")
    print("=" * 70)

    from qtrust import QTrustClient

    try:
        client = QTrustClient()
    except Exception as e:
        print(f"ERROR: {e}")
        return None

    # Compute a deterministic migration ID
    migration_id = "0x" + hashlib.sha256(f"migration-{asset_id}-{int(time.time())}".encode()).hexdigest()[:64]
    evidence_hash = "0x" + hashlib.sha256(b"mock-hsm-log-evidence").hexdigest()

    print("Recording migration on Base Sepolia...")
    print(f"  Asset ID: {asset_id}")
    print(f"  From: RSA-2048")
    print(f"  To: ML-DSA-441")

    try:
        tx_hash = client.record_migration(
            migration_id=migration_id,
            asset_id=asset_id,
            from_algorithm="RSA-2048",
            to_algorithm="ML-DSA-441",
            evidence_hash=evidence_hash,
            evidence_uri="ipfs://QmMockEvidence",
        )
        print(f"\nMigration recorded!")
        print(f"  Migration ID: {migration_id}")
        print(f"  TX hash: {tx_hash}")
        print(f"  Basescan: https://sepolia.basescan.org/tx/{tx_hash}")
        return migration_id
    except Exception as e:
        print(f"ERROR: Migration recording failed: {e}")
        return None


def step6_verify(asset_id: str, migration_id: str):
    """Step 6: Verify the asset and migration via the SDK."""
    print("\n" + "=" * 70)
    print("STEP 6: Verify on-chain records")
    print("=" * 70)

    from qtrust import QTrustClient

    try:
        client = QTrustClient()
    except Exception as e:
        print(f"ERROR: {e}")
        return

    print("\nFetching asset record...")
    try:
        asset = client.get_asset(asset_id)
        print(f"  Asset ID: {asset.asset_id}")
        print(f"  Org DID: {asset.org_did}")
        print(f"  CBOM hash: {asset.cbom_hash}")
        print(f"  Registered: {asset.datetime}")
        print(f"  Active: {asset.active}")
    except Exception as e:
        print(f"  ERROR: {e}")

    print("\nFetching migration record...")
    try:
        migration = client.get_migration(migration_id)
        print(f"  Migration ID: {migration.migration_id}")
        print(f"  Asset ID: {migration.asset_id}")
        print(f"  From: {migration.from_algorithm}")
        print(f"  To: {migration.to_algorithm}")
        print(f"  Timestamp: {migration.timestamp}")
        print(f"  Verified: {migration.verified}")
    except Exception as e:
        print(f"  ERROR: {e}")


def main():
    print("=" * 70)
    print("Q-Trust Pilot Demo — First National Bank PQC Migration")
    print("=" * 70)
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"Operator: {os.environ.get('USER', 'unknown')}")

    # Run all steps
    target = "example.com"
    scan_result = step1_scan_target(target)

    if scan_result.finding_count == 0:
        print("\nWARNING: No findings from scan. Using synthetic data for the demo.")
        from qtrust_planner.data_generator import generate_synthetic_cbom
        # Create a synthetic scan result with one finding
        from qtrust_inspector.models import AssetFinding, ScanResult
        scan_result = ScanResult(
            target="synthetic-bank.example.com",
            scanner="qtrust-inspector",
            started_at=int(time.time()),
            completed_at=int(time.time()),
            findings=[
                AssetFinding(
                    asset_type="tls_cert", algorithm="RSA-2048",
                    location="bank.example.com:443", vendor="DigiCert",
                    criticality="high",
                ),
                AssetFinding(
                    asset_type="ssh_key", algorithm="Ed25519",
                    location="bank.example.com:22", criticality="medium",
                ),
            ],
        )

    asset_id = step2_register_cbom(scan_result)
    if not asset_id:
        print("\nPilot aborted at Step 2. Check your env vars and contract deployment.")
        return

    step3_quantum_analysis()
    step4_migration_plan(asset_id)
    migration_id = step5_record_migration(asset_id)
    if migration_id:
        step6_verify(asset_id, migration_id)

    print("\n" + "=" * 70)
    print("PILOT COMPLETE")
    print("=" * 70)
    print(f"\nDemo URLs:")
    print(f"  Backend API:    http://localhost:3001/v1/assets/{asset_id}")
    print(f"  Frontend:       http://localhost:3000/v/{asset_id}")
    print(f"  Basescan:       https://sepolia.basescan.org/address/{os.environ.get('QTRUST_ASSET_REGISTRY_ADDRESS', '')}")


if __name__ == "__main__":
    main()
```

### 11.3 Run the Pilot

```bash
cd /home/z/qtrust
mkdir -p pilot
# Save the script above as pilot/run_pilot.py

conda activate qtrust
python pilot/run_pilot.py
```

Expected output:

```
======================================================================
Q-Trust Pilot Demo — First National Bank PQC Migration
======================================================================
Date: 2026-08-20 12:00:00 UTC
Operator: z

======================================================================
STEP 1: Scan target for cryptographic assets
======================================================================
Target: example.com

Scan complete:
  Findings: 1
  By algorithm: {'RSA-2048': 1}
  By type: {'tls_cert': 1}
  - tls_cert: RSA-2048 at example.com:443 (vendor: DigiCert)

======================================================================
STEP 2: Register CBOM on Base Sepolia
======================================================================
Posting CBOM to Base Sepolia...

CBOM registered!
  Asset ID: 0xabc123...
  IPFS CID: QmXYZ...
  Basescan: https://sepolia.basescan.org/address/0x...

======================================================================
STEP 3: Quantum threat analysis (refer to qiskit notebook)
======================================================================

Key Size    Required Qubits    Breakable Year
-----------------------------------------------
RSA-1024    2,051,000          2030
RSA-2048    4,099,000          2032
RSA-3072    6,147,000          After 2033
RSA-4096    8,195,000          After 2033

======================================================================
STEP 4: Generate GNN-based migration plan
======================================================================

Migration plan generated for 50 assets:
  Estimated weeks: 25.0
  Phases: 4

  Phase 1:
    Assets: 13
    ...

======================================================================
STEP 5: Record migration on-chain
======================================================================
Recording migration on Base Sepolia...
  ...

Migration recorded!
  Migration ID: 0xdef456...
  TX hash: 0xghi789...

======================================================================
STEP 6: Verify on-chain records
======================================================================

Fetching asset record...
  Asset ID: 0xabc123...
  ...

Fetching migration record...
  Migration ID: 0xdef456...
  ...

======================================================================
PILOT COMPLETE
======================================================================
```

### 11.4 Demo Script for Customers/Investors

When demoing to customers or investors, follow this 5-step script:

**Step 1 (30s): Scan a real target.** Open the BrevLab terminal. Run `python pilot/run_pilot.py`. Point out the scan finding real TLS certificates on example.com.

**Step 2 (60s): Show the on-chain attestation.** Open Basescan in a browser. Show the transaction. Explain that this is a permanent, tamper-proof record that the bank had this CBOM at this point in time.

**Step 3 (90s): Run the Shor's algorithm notebook.** Switch to the qiskit311 notebook. Run cell 5 (Shor on N=15). Explain that this proves quantum computers can break RSA — the question is when, not if. Show the roadmap plot.

**Step 4 (60s): Show the migration plan.** Switch back to the pilot output. Show the 4-phase migration plan generated by the GNN. Explain that the planner considered dependencies — the bank can't just migrate randomly.

**Step 5 (60s): Verify on the dashboard.** Open the Next.js frontend (deployed on Vercel) in a browser. Navigate to `/v/<asset_id>`. Show the CBOM, the asset graph, the migration record. Explain that a regulator or auditor could verify this without trusting the bank.

### 11.5 Record a Demo Video

Use OBS Studio or Loom to record the 5-step demo above. Keep it under 5 minutes. Host it on YouTube (unlisted) and link it from your README.md.

Commit:

```bash
cd /home/z/qtrust
git add .
git commit -m "Phase 8: pilot script and demo"
git push
```

---

## 12. Appendix A: Full File Tree

After completing all 8 phases, your project structure should look like this:

```
/home/z/qtrust/
├── README.md
├── .gitignore
├── environment.yml
├── Makefile
│
├── contracts/                          # Phase 1: Solidity smart contracts
│   ├── foundry.toml
│   ├── src/
│   │   ├── AssetRegistry.sol
│   │   ├── VendorRegistry.sol
│   │   ├── MigrationRegistry.sol
│   │   └── AuditRegistry.sol
│   ├── test/
│   │   ├── AssetRegistry.t.sol
│   │   ├── VendorRegistry.t.sol
│   │   └── MigrationRegistry.t.sol
│   ├── script/
│   │   └── Deploy.s.sol
│   └── lib/
│       ├── openzeppelin-contracts/      # git submodule
│       └── forge-std/                   # git submodule
│
├── sdk/                                # Phase 2: Python SDK
│   ├── pyproject.toml
│   ├── README.md
│   ├── qtrust/
│   │   ├── __init__.py
│   │   ├── client.py                    # QTrustClient class
│   │   ├── schema.py                    # Pydantic models
│   │   ├── ipfs.py                      # Pinata client
│   │   └── contracts.py                 # ABIs
│   └── tests/
│       └── test_client.py
│
├── inspector/                          # Phase 3: Cryptography inspector
│   ├── pyproject.toml
│   ├── README.md
│   ├── qtrust_inspector/
│   │   ├── __init__.py
│   │   ├── cli.py                       # qtrust-scan CLI
│   │   ├── scanner.py                   # Main orchestrator
│   │   ├── tls_scanner.py               # TLS cert scanner
│   │   ├── ssh_scanner.py               # SSH key scanner
│   │   ├── file_scanner.py              # PEM file scanner
│   │   └── models.py                    # AssetFinding, ScanResult
│   └── tests/
│       └── test_scanner.py
│
├── notebooks/                          # Phase 4: Qiskit notebook
│   ├── 04_shor_sales_demo.ipynb
│   └── quantum_roadmap.png
│
├── planner/                            # Phase 5: FIGNN migration planner
│   ├── pyproject.toml
│   ├── README.md
│   ├── best_model.pt                   # trained GNN weights
│   ├── data/                           # synthetic training data
│   │   ├── cbom_0000.json
│   │   ├── cbom_0001.json
│   │   └── ... (500 files)
│   └── qtrust_planner/
│       ├── __init__.py
│       ├── model.py                    # MigrationGNN
│       ├── train.py                    # training script
│       ├── planner.py                  # inference
│       └── data_generator.py           # synthetic CBOM generator
│
├── backend/                            # Phase 6: Backend services
│   ├── package.json
│   ├── bun.lockb
│   ├── tsconfig.json
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── src/
│       ├── server.ts                   # Fastify server
│       ├── lib/
│       │   └── abis.ts                 # TypeScript ABIs
│       └── services/
│           ├── verify.ts               # read-only chain queries
│           ├── attestation.ts          # relayer
│           └── webhook.ts              # webhook service
│
├── frontend/                          # Phase 7: Next.js dashboard
│   ├── package.json
│   ├── bun.lockb
│   ├── next.config.js
│   ├── tailwind.config.ts
│   └── src/
│       └── app/
│           ├── layout.tsx
│           ├── page.tsx                # Home page
│           ├── providers.tsx           # Dynamic SIWE provider
│           ├── v/[id]/page.tsx         # Public verification page
│           └── dashboard/page.tsx     # Org dashboard
│
├── pilot/                              # Phase 8: Pilot & demo
│   └── run_pilot.py
│
└── docs/
    └── (additional documentation)
```

---

## 13. Appendix B: Qwen 2.5 Handoff Prompt

After Qwen 2.5 reads this document, give it this prompt to start implementation:

```
I want you to implement the Q-Trust project exactly as specified in the implementation guide above.

Create every file listed in the guide, with the exact contents shown. Do not skip any file.

For each phase:
1. Create all files in the order listed
2. Run the test commands listed at the end of each phase
3. Fix any errors before moving to the next phase

Start with Phase 0 (BrevLab Environment Setup) and work through Phase 8 (Pilot & Demo).

Project root: /home/z/qtrust/

Phase 0: Create the directory structure, .gitignore, environment.yml, Makefile.
Phase 1: Create contracts/src/*.sol, contracts/test/*.t.sol, contracts/script/Deploy.s.sol.
Phase 2: Create sdk/qtrust/*.py, sdk/pyproject.toml, sdk/tests/test_client.py.
Phase 3: Create inspector/qtrust_inspector/*.py, inspector/pyproject.toml, inspector/tests/test_scanner.py.
Phase 4: Create notebooks/04_shor_sales_demo.ipynb.
Phase 5: Create planner/qtrust_planner/*.py, planner/pyproject.toml.
Phase 6: Create backend/src/*.ts, backend/docker-compose.yml, backend/Dockerfile.
Phase 7: Create frontend/src/app/*.tsx, frontend/src/app/v/[id]/page.tsx, frontend/src/app/dashboard/page.tsx, frontend/src/app/providers.tsx.
Phase 8: Create pilot/run_pilot.py.

After creating all files, run these verification commands:
- cd /home/z/qtrust/contracts && forge test -vv
- cd /home/z/qtrust/sdk && pytest tests/ -v
- cd /home/z/qtrust/inspector && pytest tests/ -v
- cd /home/z/qtrust/planner && python -m qtrust_planner.train
- cd /home/z/qtrust && python pilot/run_pilot.py

Report any errors you encounter and fix them.
```

### Qwen 2.5 Usage Tips

1. **Upload this markdown file** as a context file (or paste the URL if Qwen supports it).
2. **Use the prompt above** to start the implementation.
3. **Iterate phase by phase** — if Qwen hits an error in one phase, fix it before moving to the next.
4. **Use Qwen's code execution** if available — it can run the test commands itself.
5. **Review Qwen's output** — Qwen may add extra comments or restructure slightly. Compare against the guide.

---

## 14. Appendix C: Glossary

| Term | Definition |
|---|---|
| **ABI** | Application Binary Interface. A JSON description of a smart contract's functions. |
| **Attestation** | A cryptographically signed statement posted on-chain. |
| **Base** | An Ethereum Layer 2 (L2) blockchain built on the OP Stack, operated by Coinbase. |
| **Basescan** | The block explorer for Base. |
| **CBOM** | Cryptographic Bill of Materials — an inventory of all cryptographic assets in an organization. |
| **DID** | Decentralized Identifier — a W3C-standard identifier controlled by a private key. |
| **EIP-712** | A standard for signing typed structured data with Ethereum private keys. |
| **ERC-4337** | An Ethereum standard for account abstraction. |
| **FIPS 203/204/205** | The NIST post-quantum cryptography standards finalized in August 2024. |
| **FIGNN** | Functional Integrated Graph Neural Network — your existing kernel, repurposed for migration planning. |
| **Foundry** | A modern Solidity development toolkit (forge, cast, anvil). |
| **GNN** | Graph Neural Network — a neural network that operates on graph-structured data. |
| **IPFS** | InterPlanetary File System — a peer-to-peer file storage network. |
| **ML-DSA** | Module-Lattice-Based Digital Signature Algorithm (FIPS 204). |
| **ML-KEM** | Module-Lattice-Based Key-Encapsulation Mechanism (FIPS 203). |
| **MIG** | Multi-Instance GPU — an NVIDIA A100 feature that partitions the GPU. |
| **NIST PQC** | The NIST Post-Quantum Cryptography standardization process. |
| **OMB M-23-02** | The U.S. Office of Management and Budget memo mandating federal agency PQC migration. |
| **Paymaster** | An ERC-4337 component that sponsors gas for user transactions. |
| **PQC** | Post-Quantum Cryptography — cryptographic algorithms resistant to quantum computer attacks. |
| **PoA** | Proof of Authority — a consensus mechanism. Base Sepolia uses PoA. |
| **RPC** | Remote Procedure Call — the HTTP endpoint clients use to talk to a blockchain node. |
| **Safe** | A multi-signature smart contract wallet. |
| **Sepolia** | An Ethereum testnet. Base Sepolia is the L2 testnet on top of it. |
| **Shor's algorithm** | A quantum algorithm that breaks RSA and ECC. |
| **SIWE** | Sign-In with Ethereum — authentication via wallet signature. |
| **SLH-DSA** | Stateless Hash-Based Digital Signature Algorithm (FIPS 205). |
| **viem** | A modern TypeScript library for Ethereum. |

---

## End of Guide

You now have everything needed to build the Q-Trust MVP. The full implementation is 8 phases over 12 weeks. The guide is designed to be self-contained — paste it into Qwen 2.5 (or Claude, Cursor, or any AI coding assistant) and it will produce every file.

**Next steps after implementation:**
1. Run the pilot script: `python pilot/run_pilot.py`
2. Record a 5-minute demo video
3. Write a one-page summary
4. Reach out to pilot customers (banks, credit unions, hospitals)
5. Apply to accelerator programs (Techstars Web3, Alliance DAO)

Good luck building.
