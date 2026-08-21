# Prior Art Survey — Q-Trust PQC Migration Coordinator

**Purpose:** Landscape of existing standards, tools, publications, and patents relevant to
Q-Trust's claimed invention, for use by patent counsel. This is a preliminary landscape
survey, **not** a legal opinion and **not** a complete §102/§103 search.

**Date:** 2026-08-20
**Scope:** Post-quantum cryptography (PQC) migration coordination, cryptographic asset
inventory (CBOM), on-chain attestation registries, and machine-learning ranking of
migration/remediation order.

---

## 1. Standards & frameworks for cryptographic inventory (CBOM)

| Reference | What it is | Relevance to Q-Trust |
|---|---|---|
| **CycloneDX CBOM** (ECMA-424, 2nd ed. Dec 2025) | Standardized Cryptography Bill of Materials: algorithms, keys, certs, `nistQuantumSecurityLevel`, crypto-agility metadata; explicitly aimed at PQC readiness | The *format* of cryptographic inventory is standardized. Q-Trust does **not** claim the CBOM format itself. Q-Trust's scanner emits CBOM-structured output; novelty is not in the schema |
| **NIST SP 1800-38B** (preliminary draft) "Migration to PQC: Quantum Readiness — Cryptographic Discovery" | NCCoE guide for crypto discovery as step 1 of PQC readiness | Discovery/inventory step is well-established practice; not novel per se |
| **NIST IR 8547** (initial public draft) | NIST's transition plan: which algorithms are quantum-vulnerable, which PQC standards replace them, timelines | The *classification* of algorithms (vulnerable vs. PQC) is public knowledge; Q-Trust uses this only as input data |
| **Post-Quantum Cryptography Coalition Inventory Workbook** | Spreadsheet methodology for building a PQC asset inventory with priority categories | Manual inventory + prioritization practice; no automation, no on-chain coordination |

**Takeaway:** Inventory formats and discovery are crowded, standardized space. Claims
must not cover "building a cryptographic asset inventory" in isolation.

## 2. PQC migration prioritization & decision tools

| Reference | What it is | Relevance to Q-Trust |
|---|---|---|
| **Comcast CARAF** (github.com/Comcast/CARAF) | Crypto Agility Risk Assessment Framework: Phase 0 inventory → Phase 1 crypto-agility measurement → Phase 2 risk estimation → Phase 3 migration recommendation (migrate / phase out / accept risk); Excel calculator | **Closest functional prior art for the prioritization component.** It is rule/questionnaire-based, single-organization, off-chain, and does not produce a *sequenced* migration order over a dependency graph |
| **QSTriage** (PyPI, v1.2.1) | Open-source decision-support: validates CBOM, classifies algorithms, scores assets, "models graph-amplified blast radius", produces deterministic PQC Decision Records (PDR) with integrity hashes | **Closest open-source prior art for scoring/prioritization.** Deterministic rule-based scoring; graph-amplified risk; no learned model, no ordering over dependencies, no multi-party coordination |
| **PQC Migration Advisor / readiness tools** (postquantum.com) | Advisory tools + AI assistant for sequencing (quick wins vs. long-poles) | High-level advisory; heuristic sequencing; no graph model, no registry |

**Takeaway:** The most dangerous prior art for the "migration prioritization" claim:
rule-based scoring with graph-aware risk already exists (CARAF, QSTriage). Q-Trust's
differentiators: (i) *learned* GNN ranking over a dependency graph trained with a
ranking objective; (ii) producing a *full ordered sequence*; (iii) dual order/risk heads;
(iv) the ordering is **coordinated cross-organization on-chain**, not a local report.

## 3. On-chain attestation, PKI & registry patents

| Reference | What it is | Relevance |
|---|---|---|
| **WO2018004783A1** "Public key infrastructure using blockchains" | Blockchain as PKI root/registry; certificate introduction and revocation via ledger transactions | On-chain PKI/registry concept is **prior art**. Q-Trust does not claim general blockchain PKI |
| **US20170317833A1** (+ continuation US12126715B2) | Attestation of information via hash + public key → attestation address on Bitcoin; verification by re-deriving address | Hash-based on-chain attestation and verification is **prior art** |
| **US11233641B2** | Distributed attestations as verifiable claims on a blockchain with identity masking | On-chain attestation claims/records **prior art** |
| **US12219071B2** "Attestation chains using bonded oracles" | Chained attestations with economic bonding on public registries | Attestation chains/lifecycle **prior art** |

**Takeaway:** "Store hash of record on-chain" and "attestation registry" are heavily
patented. Claims must focus on the *specific system*: multi-registry coordination of a
PQC migration lifecycle (asset registry + vendor attestation + migration records +
audit records) with role-based access, deterministic attestation IDs keyed to
product/version/algorithm, revocation semantics, and off-chain CBOM retention.

## 4. ML/GNN ranking for security remediation

| Reference | What it is | Relevance |
|---|---|---|
| **VulRG** (arXiv:2502.11143) | GNN-based vulnerability risk aggregation + patch ranking using dependency & network graphs | GNN ranking of remediation over dependency graphs = **prior art** in adjacent domain (vulnerability patching, not algorithm migration) |
| **GAT dependency remediation profiling** (arXiv:2403.04989) | Modified GAT with centrality metrics to profile dependency-upgrade breakage | GNN on dependency graphs for upgrade/remediation decisions = **prior art** |
| **VIVID** (arXiv:2505.16205) | Graph-theory metrics on vulnerability data-flow graphs for remediation prioritization | Graph-based prioritization **prior art** (non-learned) |
| **Planning-graph centrality ranking** (Ben-Gurion Univ.) | Centrality measures on planning/attack graphs to rank vulnerability fixes | Ranking fixes over graphs **prior art** (non-learned) |

**Takeaway:** GNNs + dependency graphs for ranking security actions exist. Q-Trust's
claim must be specific: a GNN with *dual order/risk heads trained with a ranking loss*
(e.g., ListMLE) applied to *PQC algorithm migration sequencing*, generating an order
consumed by an *on-chain coordination protocol*. Novelty is the combination and the
domain-specific training/labeling design, not GNNs per se.

## 5. Gap analysis — where Q-Trust may be novel (combination claims)

1. **End-to-end cross-organization coordination**: No identified system that *closes the
   loop* from crypto discovery → learned migration ordering → on-chain cross-org
   coordination (vendor attestation, migration records, audits) → verifiable delivery.
   CARAF/QSTriage stop at the decision boundary (both state this explicitly).
2. **Learned sequencing (not scoring)**: CARAF/QSTriage score or classify; Q-Trust
   produces an *ordered migration sequence* from a GNN trained end-to-end with a
   ranking objective on dependency graphs — with a risk head for dependency-aware
   deferral.
3. **Hash-only on-chain posture with role-based registries** specific to the PQC
   migration lifecycle (asset/vendor/migration/audit registries, vendor-only
   attestation/revocation, auditor-only attestation, deterministic attestation IDs).
4. **Webhook-based attestation delivery** (BullMQ queue) for downstream consumers.
5. **L2 (Base, chain-id 84532) deployment** for low-cost hash-only records — cost
   engineering, not a claim by itself, but supports the combination.

## 6. Recommendations for counsel

- File a provisional covering the **system combination** (method claim: discovery →
  GNN ordering → on-chain coordination → verification), not the individual components.
- Explicitly disclaim CBOM formats, generic blockchain PKI, and generic GNN ranking in
  the specification to avoid §112 indefiniteness and strengthen novelty.
- Run a full search on: "PQC migration blockchain", "quantum-safe migration registry",
  "cryptographic agility ledger", "algorithm migration ordering dependency graph".
- Consider citing CARAF, QSTriage, and WO2018004783A1 as the closest art in the IDS.

*This document does not constitute legal advice. Engage qualified patent counsel for a
formal search and opinion.*