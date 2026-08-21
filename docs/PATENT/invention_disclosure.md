# Invention Disclosure — Cross-Organizational Post-Quantum Cryptography Migration Coordination System

> Template for submission to a technology-transfer office / patent attorney.
> **Do not publish** this document or the accompanying code until filing decisions are made.

| Field | Value |
|---|---|
| Working title | Q-Trust: Cross-Organizational PQC Migration Coordination Protocol |
| Inventor(s) | *(to complete — name, affiliation, department)* |
| Date of conception | 2026-07 (project inception) |
| Date of first written description | 2026-08-20 (this disclosure) |
| Has any disclosure been made public? | *(to verify — repo, demos, talks)* |
| Is this work university-funded / employer-funded? | *(to verify — affects ownership)* |

## 1. Problem solved

Organizations migrating from classical cryptography (RSA, ECC) to post-quantum
cryptography (PQC) face three coupled problems:

1. **Discovery**: knowing which cryptographic assets (TLS/SSH/code-signing/HSM/JWT)
   exist, their algorithms, key sizes, and quantum vulnerability.
2. **Sequencing**: choosing *in what order* assets should migrate. Ordering must respect
   dependency constraints (an asset with many dependents is risky to migrate early),
   criticality, key strength, and vendor PQC-readiness — and must be learned/optimized,
   not merely scored.
3. **Coordination**: multiple organizations (the migrating org, vendors attesting that a
   product version supports a PQC algorithm, auditors attesting the migration) must
   agree on a tamper-evident, verifiable record of what was migrated, when, and with
   what evidence — without exposing proprietary CBOM contents.

Existing tools stop at the decision boundary: Comcast CARAF and QSTriage produce local
scores/decisions; no identified system closes the loop from discovery through learned
ordering to cross-organization on-chain coordination and verifiable delivery.

## 2. Solution (as built — see repo structure)

A layered system:

- **Inspector** (`inspector/`): scanner discovering cryptographic assets
  (TLS/SSH/code-signing), emitting CBOM-structured JSON (CycloneDX-CBOM compatible
  fields) with algorithm, key size, criticality, vendor, product, version.
- **Planner** (`planner/`): a 3-layer GCN (`MigrationGNN`, 6-dim node features: algorithm type, key size, vendor PQC-readiness, criticality, days-to-deadline, required rate) with **dual prediction heads** — an *order head* (priority score per asset, higher = migrate earlier) and a *risk head* (dependency-aware migration risk). Hybrid GAT variant (`model_v2.py`) adds attention + centrality augmentation as embodiment. Trained with a **ListMLE (Plackett-Luce) per-graph ranking loss** plus risk MSE; a heuristic-label generator produces ground-truth orders from criticality/vendor/key-size/dependency/deadline features. Honest 3-seed benchmark (40 epochs, 1000 graphs, 150 held-out): GNN(ListMLE) τ 0.266±0.023, top-5 0.500±0.061 vs MSE τ 0.144 vs random ~0; production 80-epoch model τ 0.388, top-5 0.656.
- **Registries** (`contracts/`): **five** Solidity contracts on Base L2 (chain-id 84532, Foundry 0.8.24, OpenZeppelin AccessControl + ReentrancyGuard):
  - `AssetRegistry` — CBOM hash + org DID + timestamps per asset (hash-only on-chain), `REGISTRAR_ROLE`, `retireAsset` via governance;
  - `VendorRegistry` — vendor registration (`VENDOR_ADMIN_ROLE`), product attestations keyed by **deterministic productHash** = keccak(product, version, algorithm) for idempotent `checkProductSupport`, plus deterministic attestationId = keccak(vendor, productHash) (or vendor+product+version+algorithm) with bounded iteration (`MAX_ATTESTATIONS_PER_PRODUCT=256`), EIP-712 gasless `attestProductSigned` (domain `QTrustVendorRegistry`), revocation;
  - `MigrationRegistry` — migration records (from → to algorithm, evidence hash, URI) with cross-registry integrity (`verifyAsset` against AssetRegistry, `AssetInactive`/`AssetNotRegistered` reverts, `SameAlgorithm` guard);
  - `AuditRegistry` — auditor attestations with audit result & review counts, bound to on-chain migrations (`getMigrationsByOrg` check, `MigratedCountExceedsOnChain`);
  - `QTrustGovernance` — `TimelockController` (2-day delay) wrapper for trust-affecting actions (deactivateVendor, retireAsset, grantRole), deployer admin renounced post-deploy.
  Role-based access: `VENDOR_ROLE`, `MIGRATOR_ROLE`, `AUDITOR_ROLE`, `VENDOR_ADMIN_ROLE`, timelock-held `DEFAULT_ADMIN_ROLE`; 49 Foundry tests cover happy + revert paths, EIP-712, timelock, limits.
- **SDK** (`sdk/`): typed Python client (Pydantic models) for all registry operations
  and verification.
- **Backend** (`backend/`): Fastify + viem API exposing `/v1` read/verify routes and
  **webhook-based attestation delivery** (BullMQ + Redis) so downstream consumers are
  notified of new attestations/migrations.
- **Frontend** (`frontend/`): public verification page `/v/<asset-id>` rendering
  on-chain VALID/INVALID status; org dashboard; vendor portal.

**Data flow (method):**
1. Scan org infrastructure → CBOM (hash of CBOM stored on-chain; content off-chain).
2. Convert CBOM + dependency graph → node features → GNN predicts order + risk scores.
3. Vendor registers and attests `(product, version, algorithm, supported)` — creating a
   deterministic attestation ID on-chain.
4. Org records migration `(asset, from_alg → to_alg, evidence_hash)`; auditor attests.
5. Anyone verifies: `verifyAsset`, `checkProductSupport`, `verifyMigration`,
   `getLatestAudit` — publicly, without trusting any party.

## 3. What is believed new (candidate novel elements)

1. A **learned migration sequencer** (GNN with order+risk heads, ranking-loss trained)
   whose output order is consumed by an on-chain coordination protocol — as opposed to
   rule-based scoring tools that stop at recommendations.
2. **Deterministic attestation IDs** keyed to `(product, version, algorithm)` enabling
   idempotent, queryable vendor support claims with revocation semantics.
3. The **four-registry role-separated lifecycle** (asset/vendor/migration/audit) with
   hash-only on-chain storage, permitting multi-party verification without CBOM
   disclosure.
4. **Webhook delivery of attestation events** tied to registry events (BullMQ).
5. The end-to-end **combination**: discovery → learned ordering → on-chain coordination
   → public verification, on an L2.

## 4. Prior art acknowledged (closest)

- CycloneDX CBOM / ECMA-424 (format — not claimed); NIST SP 1800-38B, IR 8547.
- Comcast CARAF (rule-based risk framework; single-org; no sequencing, no registry).
- QSTriage (deterministic scoring + graph-amplified blast radius; decision-boundary only).
- WO2018004783A1, US20170317833A1/US12126715B2, US11233641B2, US12219071B2
  (blockchain PKI / on-chain attestation — generic mechanisms, not claimed).
- VulRG (arXiv:2502.11143), arXiv:2403.04989, VIVID (arXiv:2505.16205) (GNN/graph
  ranking of security remediations in adjacent domains).

## 5. Commercial advantages / use cases

- Zero-trust multi-org verification for regulated sectors (banks, government supply
  chains) required to demonstrate PQC readiness to auditors.
- Vendor marketplaces: attestations become queryable public records (ML-DSA-441 support
  claims), reducing duplicate vendor evaluation.
- Cheap L2 hash-only records; no CBOM confidentiality loss.

## 6. Experimental evidence (honest status, 2026-08-21)

- Contracts: **49/49 forge tests** (5 suites) — AssetRegistry (10), VendorRegistry (14, incl. EIP-712, limit, timelock), MigrationRegistry (11, incl. cross-registry), AuditRegistry (8), QTrustGovernance (6); `forge build` clean, deployment via `Deploy.s.sol` with Timelock handover, addresses logged.
- SDK: 5/5 pytest (1 skip) + **E2E `python sdk/tests/e2e_anvil.py` → ALL E2E CHECKS PASSED** (7 steps: CBOM, vendor, migration, audit, integrity guards, read-only, EIP-712 gasless) on fresh anvil; SDK supports deterministic hashing, EIP-712 typed data.
- Inspector: 5/5 pytest (1 skip) — TLS/SSH/file scans, CBOM generation, criticality, deterministic hash; live `scan_host(example.com)` works.
- Planner: **honest 3-seed 40-epoch 1000-graph benchmark (150 held-out, seed 999)**: `random` τ −0.009, `gnn-mse` τ 0.144±0.024, **`gnn-listmle` τ 0.266±0.023, top-5 0.500±0.061, top-10 0.371±0.067** vs `heuristic` τ 0.997 (upper bound) — see `planner/results/benchmark.json` (fixed bug 2026-08-21). **Production `planner/model.pt` (80 epochs, 1200 graphs, ListMLE): τ 0.388, top-5 0.656, top-10 0.528, node-rank 0.437** on 180-graph validation. **Synthetic data only (20–100 nodes, random DAGs)**; real-world CBOM evaluation is future work and is NOT claimed.
- Backend: `npm run build` tsc clean, Fastify + viem + BullMQ/Redis webhook (HTTPS-only, bounded retries, HMAC-style), Postgres indexer (optional fallback to RPC), 8 `/v1` routes + health, EIP-712 relayer, CORS/rate-limit/API-key hardening.
- Frontend: `next build` clean (5 routes: /, dashboard, vendors, v, v/[id]), verification page renders VALID with on-chain data, provenance graph, IPFS metadata, independent-verify CLI.
- Pilot: `python pilot/run_pilot.py` → **PILOT COMPLETE** (6-step bank demo: scan → CBOM → Shor table → GNN ranking → on-chain attest/migrate/audit → verify); notebook `08_bank_pilot.ipynb` executes 0 errors.
- **Reproducibility**: `./scripts/verify_all.sh` (9 checks) and `python -m qtrust_planner.benchmark --seeds 42 43 44` both pass locally.

## 7. Items needed from inventors

- Confirm inventor names, employment/funding status, and whether any prior public
  disclosure exists (repo visibility, demos, thesis, preprint).
- Decide filing strategy (see `filing_checklist.md`).
- Provide evidence artifacts: benchmark JSON, E2E logs, pilot transcript, screenshots.

---

*This document is a draft for counsel review; it is not legal advice.*