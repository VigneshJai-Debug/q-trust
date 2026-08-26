# Q-Trust: Cross-Organizational Post-Quantum Cryptography Migration Protocol

## Abstract

Q-Trust is a cross-organizational protocol that coordinates the migration from classical cryptography (RSA, ECC) to post-quantum cryptography (PQC). It uses blockchain-anchored attestation on Base L2 to create tamper-evident, verifiable migration records. The protocol combines enterprise-grade cryptographic scanning, AI-powered migration planning, and on-chain compliance verification. Q-Trust addresses the coordination problem inherent in multi-organization PQC transitions: each entity in a supply chain must migrate on compatible timelines, using standardized representations, with independently verifiable proof of progress. The protocol ingests cryptographic inventory data in CycloneDX 1.7 CBOM format, scores quantum vulnerability risk using NIST SP 800-131A and CNSA 2.0 baselines, generates deadline-aware migration plans via a trained Graph Neural Network, and anchors compliance attestations on-chain with EIP-712 gasless transactions. Verifiable Credentials (W3C VC Data Model v2.0) enable selective disclosure of migration status across organizational boundaries. Q-Trust is open-source, designed for integration into existing CI/CD pipelines, and targets compliance with NIS2, FISMA, FedRAMP, and CMMC frameworks. The protocol is production-ready across all four planned development phases.

## 1. Introduction

### 1.1 The Quantum Threat

Shor's algorithm, running on a sufficiently powerful quantum computer, can factor large integers and compute discrete logarithms in polynomial time. This directly breaks RSA, DSA, ECDSA, and ECDH — the cryptographic foundations of modern internet security. Grover's algorithm provides a quadratic speedup for symmetric key search, effectively halving the security margin of AES and SHA family primitives.

The practical implications are severe. A cryptographically relevant quantum computer (CRQC) would compromise TLS 1.3 handshakes, SSH sessions, code signing certificates, VPN tunnels, and blockchain transactions simultaneously.

### 1.2 Harvest-Now-Decrypt-Later

The most immediate threat is not a future quantum computer but present-day data collection. Nation-state adversaries and well-funded threat actors are intercepted and storing encrypted communications today, with the explicit intent of decrypting them once quantum capabilities mature. This "harvest-now-decrypt-later" (HNDL) attack vector means that any data with a confidentiality requirement extending beyond 5–10 years is already at risk.

### 1.3 Regulatory Timeline

NIST SP 800-131A Rev. 2 establishes a deprecation schedule:

- **2030**: Disallow RSA-2048, ECDSA-256, ECDH-256, DH-2048 for encryption and key establishment
- **2035**: Disallow all classical asymmetric algorithms for all use cases

NSA CNSA 2.0 imposes even stricter requirements for national security systems, mandating ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA (SPHINCS+). The EU NIS2 Directive, FISMA, FedRAMP, and CMMC frameworks are all converging on similar PQC requirements.

### 1.4 The Coordination Problem

PQC migration is not a single-organization problem. Supply chains, SaaS integrations, API partnerships, and shared infrastructure all require coordinated transitions. An organization that migrates its TLS certificates to ML-KEM while its partners still rely on ECDH achieves nothing if the weaker link is exploited. Q-Trust solves this coordination problem by providing a shared, verifiable migration ledger that all participants can trust.

## 2. Architecture Overview

Q-Trust is organized into five layers:

```
┌─────────────────────────────────────────────────┐
│              Presentation Layer                  │
│  Dashboard · Reports · Verifiable Credentials   │
├─────────────────────────────────────────────────┤
│              On-Chain Layer (Base L2)            │
│  AssetRegistry · VendorRegistry · AuditRegistry  │
│  MigrationRegistry · EvidenceRegistry            │
│  ComplianceAttestation                          │
├─────────────────────────────────────────────────┤
│              Planning Layer                      │
│  AI Migration Planner (GCN + GAT)              │
│  Deadline-Aware Scheduler · Cost Estimator      │
├─────────────────────────────────────────────────┤
│              Risk & Compliance Layer             │
│  Quantum Vulnerability Scorer                   │
│  NIST 800-131A · CNSA 2.0 · NIS2 · FISMA       │
├─────────────────────────────────────────────────┤
│              Scanner Layer                       │
│  TLS · SSH · Source Code · Packages · Binaries  │
│  Configuration Files · CycloneDX CBOM           │
└─────────────────────────────────────────────────┘
```

**Data flow**: Scan → Risk Score → Compliance Check → Plan → Attest → Verify

Each layer operates independently and communicates through well-defined interfaces. The Scanner Layer produces standardized CBOMs. The Risk Layer scores each cryptographic asset. The Planning Layer generates migration plans. The On-Chain Layer anchors attestations. The Presentation Layer renders everything to end users and external verifiers.

## 3. Scanner Layer

The Scanner Layer discovers and classifies cryptographic assets across heterogeneous technology stacks.

### 3.1 Multi-Target Scanning

- **TLS Certificates**: X.509 certificate parsing, chain validation, key algorithm identification
- **SSH Host Keys**: Ed25519, RSA, ECDSA key detection and classification
- **Source Code**: Pattern-matching across 12+ languages (Python, JavaScript/TypeScript, Go, Rust, Java, C/C++, C#, Ruby, PHP, Swift, Kotlin, Scala) for hardcoded algorithm usage, key sizes, and cryptographic library calls
- **Package Manifests**: Dependency analysis across 10+ formats (package.json, requirements.txt, Cargo.toml, go.mod, pom.xml, build.gradle, Gemfile, composer.json, pubspec.yaml, Package.swift, .csproj)
- **Binary Analysis**: ELF/Mach-O/PE inspection for linked cryptographic libraries
- **Configuration Files**: nginx.conf, httpd.conf, openssl.cnf, sshd_config, and custom config formats

### 3.2 Cryptographic Asset Discovery

Each discovered asset is classified with:
- Algorithm family (RSA, ECDSA, AES, SHA-256, etc.)
- Key size or parameter set
- Usage context (key exchange, signing, encryption, hashing)
- Quantum vulnerability status
- Estimated migration complexity

### 3.3 CycloneDX 1.7 CBOM Output

All scan results are serialized as CycloneDX 1.7 Cryptographic Bill of Materials (CBOM). This industry-standard format ensures interoperability with existing SBOM tooling and regulatory reporting requirements. Each CBOM includes:

- Component inventory with version-pinned dependencies
- Cryptographic property annotations (algorithm, key size, usage)
- Vulnerability references (CVE, GHSA)
- Provenance metadata

### 3.4 SARIF 2.1 Integration

Findings are also exported in SARIF 2.1 format for direct integration with GitHub Advanced Security, enabling automatic PR annotations, code scanning alerts, and security dashboard visibility.

## 4. Risk Scoring Engine

### 4.1 Quantum Vulnerability Classification

Each cryptographic asset receives one of four quantum vulnerability statuses:

| Status | Meaning |
|--------|---------|
| **BROKEN** | Algorithm is directly broken by Shor's/Grover's (RSA-2048, ECDSA-256, AES-128) |
| **WEAKENED** | Algorithm's security margin is reduced below acceptable thresholds (SHA-1, 3DES) |
| **SAFE** | Algorithm is quantum-resistant or has sufficient classical margin (AES-256, SHA-384) |
| **PQC_READY** | Algorithm is a NIST-approved post-quantum algorithm (ML-KEM-768, ML-DSA-65) |

### 4.2 Compliance Checking

The engine checks each asset against multiple regulatory baselines:

- **NIST SP 800-131A**: Enforces minimum key sizes and algorithm restrictions per the deprecation timeline
- **CNSA 2.0**: Validates against NSA's Commercial National Security Algorithm Suite requirements
- **FIPS 140-3**: Checks whether cryptographic modules are validated under the current FIPS standard

### 4.3 HNDL Exposure Scoring

Assets are evaluated for harvest-now-decrypt-later exposure based on:
- Data sensitivity classification (public, internal, confidential, restricted)
- Required confidentiality horizon (1 year, 5 years, 10 years, 20+ years)
- Current algorithm quantum vulnerability
- Whether the asset handles key establishment or only signatures

### 4.4 Overall Risk Score

The overall risk score (0–100) is calculated as a weighted composite:

```
score = (0.35 × quantum_vulnerability) +
        (0.25 × compliance_gap) +
        (0.25 × hndl_exposure) +
        (0.15 × migration_complexity)
```

Scores above 70 trigger mandatory migration planning. Scores above 90 are flagged as critical.

## 5. Compliance Frameworks

Q-Trust maps its risk assessments to the following compliance frameworks:

### 5.1 NIST SP 800-131A
Transitions from "Approved" to "Disallowed" for specific algorithms on the NIST timeline. Q-Trust tracks both the 2030 and 2035 deadlines and generates migration plans accordingly.

### 5.2 NSA CNSA 2.0
The Commercial National Security Algorithm Suite mandates ML-KEM-1024, ML-DSA-87, and SLH-DSA-192f for national security systems. Q-Trust validates compliance and flags non-conformant configurations.

### 5.3 FIPS 140-3
Cryptographic modules must be validated under FIPS 140-3 (replacing 140-2). Q-Track checks for valid module certificates and flags modules validated under the legacy standard.

### 5.4 EU NIS2 Directive
The Network and Information Security Directive requires risk management and incident reporting for essential and important entities. Q-Trust generates NIS2-compatible risk reports.

### 5.5 FISMA
Federal Information Security Management Act compliance for U.S. federal agencies. Q-Trust maps findings to FISMA control families.

### 5.6 FedRAMP
Federal Risk and Authorization Management Program for cloud service providers. Q-Trust generates FedRAMP-compatible security posture documentation.

### 5.7 CMMC
Cybersecurity Maturity Model Certification for defense industrial base contractors. Q-Trust maps PQC migration status to CMMC maturity levels.

## 6. AI Migration Planner

### 6.1 Graph Neural Network Architecture

The migration planner models an organization's cryptographic infrastructure as a graph:
- **Nodes**: Cryptographic assets, systems, services, certificates
- **Edges**: Dependencies, trust relationships, data flows

The GNN uses a two-stage architecture:
1. **Graph Convolutional Network (GCN)**: Aggregates neighborhood features to learn node embeddings that capture structural importance
2. **Graph Attention Network (GAT)**: Applies attention mechanisms to weight neighbor contributions, enabling the model to prioritize high-impact migration targets

### 6.2 Training with ListMLE

The planner is trained using ListMLE ranking loss, which optimizes for the quality of the entire ranked migration order rather than per-node classification. This ensures that the top-ranked migration targets are genuinely the most critical.

### 6.3 Synthetic Data Generation

Training data is generated through enterprise topology simulation:
- Random graph generation with realistic organizational structures
- Dependency injection with known criticality patterns
- Deadline assignment based on NIST timeline and business requirements
- Cost estimation based on algorithm complexity and system criticality

### 6.4 Output

For each migration target, the planner produces:
- Priority rank (1 = highest)
- Estimated migration effort (person-days)
- Cost estimate (USD)
- Deadline constraint
- Dependency chain (what must migrate first)
- Recommended replacement algorithm

### 6.5 Benchmark Results

On synthetic test sets, the planner achieves (corrected per-node-rank Kendall
protocol — see README "Trained checkpoints & measured results" and the
CHANGELOG v2.1 notes; numbers refreshed 2026-08-26 after the ranking-metric
protocol bug fix):

- Kendall tau: **0.961** for GNN v2 on the canonical held-out set
  (`results/benchmark.json`; earlier revisions of this section quoted τ=0.89
  computed with the pre-fix index-correlation protocol)
- GNN v3 GPU/DDP variants: held-out τ 0.898 / 0.831 at larger training scale
  (`results/benchmark_v3.json`, `results/benchmark_ddp.json`) — v2 remains the
  default shipped model pending the BatchNorm→LayerNorm retrain
- Top-5 overlap: 0.94 (94% of top-5 targets match optimal set)
- Node-rank accuracy: within ±2 of optimal rank for the large majority of nodes

## 7. On-Chain Layer (Base L2)

Q-Trust anchors migration records on Base, an Ethereum L2 network, for three reasons: low transaction costs (~$0.01), EVM compatibility (Solidity smart contracts, existing tooling), and Ethereum-grade security inheritance.

### 7.1 Smart Contracts

| Contract | Purpose |
|----------|---------|
| **AssetRegistry** | Registers and tracks cryptographic assets with metadata, quantum status, and ownership |
| **VendorRegistry** | Manages vendor profiles, migration capabilities, and compliance certifications |
| **MigrationRegistry** | Records migration events (start, progress, completion) with timestamps and evidence references |
| **AuditRegistry** | Stores audit records with verifier identity, finding summary, and attestation hash |
| **EvidenceRegistry** | Anchors evidence root hashes for tamper-evident audit trails |
| **ComplianceAttestation** | Issues and manages compliance attestations linked to specific assets and frameworks |

### 7.2 EIP-712 Gasless Transactions

End users never interact with the blockchain directly. Instead, they sign EIP-712 typed data messages off-chain. A relayer network submits these signatures as on-chain transactions, abstracting gas costs and wallet management from enterprise users.

### 7.3 UUPS Proxy Upgradeability

All contracts use the Universal Upgradeable Proxy Standard (UUPS). This enables:
- Logic contract upgrades without migrating storage
- Governance-controlled upgrade authorization
- Transparent upgrade history on-chain

### 7.4 Governance

Administrative operations (contract upgrades, parameter changes, registry modifications) are routed through a `TimelockController` with a configurable delay period. This ensures that no single entity can unilaterally modify protocol behavior.

### 7.5 Cross-Contract Integrity

Every attestation in `ComplianceAttestation` references specific asset and audit records. The `EvidenceRegistry` stores Merkle roots of evidence bundles, enabling efficient proof verification without storing full evidence on-chain.

## 8. Evidence Trail

### 8.1 Hash-Chained Evidence Ledger

Every scan, migration event, and attestation produces an evidence record. These records are chained using hash pointers:

```
record[n].hash = SHA-256(record[n].data || record[n-1].hash)
```

This creates a tamper-evident sequence: modifying any record breaks the hash chain, which is immediately detectable during verification.

### 8.2 CBOM Diff

Between successive scans, Q-Trust computes a structural diff of the CycloneDX CBOM:
- New components added
- Removed components
- Updated cryptographic properties (algorithm changes, key rotation)
- New vulnerabilities discovered

This diff is itself evidence of migration progress.

### 8.3 On-Chain Evidence Root

The root hash of each evidence bundle is anchored on-chain via `EvidenceRegistry`. This provides cryptographic proof that evidence existed at a specific point in time and has not been modified since.

### 8.4 Signed Audit Attestations

Auditors sign attestations using Ed25519 keys. Each attestation includes:
- Auditor DID (decentralized identifier)
- Audit scope (asset set, compliance framework)
- Finding summary (pass/fail/warning counts)
- Evidence root hash
- Signature

## 9. Verifiable Credentials

### 9.1 W3C Verifiable Credentials Data Model v2.0

Q-Trust issues migration status and compliance attestations as W3C Verifiable Credentials. This enables:

- **Portable proof**: Credentials can be presented to any verifier, not just Q-Trust infrastructure
- **Selective disclosure**: Holders can reveal only the claims they choose (e.g., "compliant with NIST 800-131A" without revealing specific asset details)
- **Revocation**: Credentials can be revoked via Merkle root-based revocation lists

### 9.2 Ed25519 Signatures

All credentials are signed with Ed25519 keys, providing:
- Fast verification (~10μs)
- Small signature size (64 bytes)
- Strong security margin (128-bit classical, ~128-bit quantum via Grover)

### 9.3 DID:web Issuer Identities

Issuer identities use the `did:web` method, enabling organizations to host their own DID documents on their existing web infrastructure. This avoids reliance on a central DID registry.

### 9.4 Selective Disclosure

Using SD-JWT-style selective disclosure, holders can:
- Prove compliance without revealing specific algorithms
- Prove migration completion without revealing internal infrastructure
- Prove audit passage without revealing audit details

### 9.5 Revocation

Revocation is implemented via compressed Merkle trees. The issuer publishes a Merkle root on-chain (via `EvidenceRegistry`), and holders provide Merkle proofs for non-revocation. This is efficient (logarithmic in the number of revoked credentials) and privacy-preserving.

## 10. Security Model

### 10.1 Trust Assumptions

- The Base L2 blockchain is honest (inherits Ethereum's security model)
- Smart contract code is correct and audited
- Scanner nodes are operated by trusted organizations (no malicious scanners in the baseline model)
- EIP-712 signatures are from authorized signers

### 10.2 Threat Model

| Adversary | Capability | Mitigation |
|-----------|-----------|------------|
| Quantum adversary | Breaks RSA, ECC | Q-Trust tracks quantum-vulnerable assets and enforces PQC migration |
| Malicious scanner | Injects false CBOM data | CBOM integrity verification, multi-scan reconciliation, evidence chaining |
| Compromised registry | Modifies on-chain records | UUPS upgrade governance, TimelockController delay, cross-contract integrity checks |
| Data exfiltrator | Harvests encrypted data for future decryption | HNDL exposure scoring, deadline-aware migration planning |
| Identity spoofing | Forges auditor credentials | Ed25519 signatures, DID:web identity verification, on-chain public key registration |

### 10.3 Mitigation Strategies

- **Defensive depth**: On-chain anchoring, off-chain evidence, hash chaining, W3C VCs
- **Least privilege**: Role-based access control, TimelockController for admin operations
- **Transparency**: All attestations are publicly verifiable on-chain
- **Upgradability**: UUPS proxies enable patching vulnerabilities without data migration

## 11. Comparison with Existing Approaches

| Feature | Q-Trust | acdi | PQCAT | CipherFlag | PQAnalyzer | HarvestGuard |
|---------|---------|------|-------|------------|------------|--------------|
| Cross-organizational | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| On-chain attestation | ✅ (Base L2) | ❌ | ❌ | ✅ (private) | ❌ | ✅ (Ethereum) |
| AI-powered planning | ✅ (GCN+GAT) | ❌ | ❌ | ❌ | ❌ | ❌ |
| CycloneDX CBOM | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ |
| SARIF integration | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Multi-framework compliance | ✅ (7) | ❌ | 1 | 2 | 1 | 3 |
| Verifiable Credentials | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Gasless transactions | ✅ | N/A | N/A | N/A | N/A | ❌ |
| Open source | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| Evidence trail | ✅ | ❌ | ❌ | ❌ | ❌ | Partial |

## 12. Roadmap

### Phase 1: Core Scanner + On-Chain Attestation (COMPLETE)
- Multi-target scanner with CycloneDX 1.7 output
- SARIF 2.1 integration
- Base L2 smart contracts (AssetRegistry, AuditRegistry, EvidenceRegistry)
- EIP-712 gasless transactions

### Phase 2: Risk Scoring + Compliance (COMPLETE)
- Quantum vulnerability classification engine
- NIST SP 800-131A and CNSA 2.0 compliance checking
- HNDL exposure scoring
- Multi-framework compliance mapping (NIS2, FISMA, FedRAMP, CMMC)

### Phase 3: AI Planner + Evidence Trail (COMPLETE)
- GCN + GAT migration priority planner
- ListMLE training with synthetic enterprise data
- Hash-chained evidence ledger
- CBOM diff and change detection

### Phase 4: Enterprise Integration + W3C VCs (COMPLETE)
- W3C Verifiable Credentials issuance and verification
- DID:web issuer identity
- Selective disclosure (SD-JWT)
- Revocation via Merkle roots
- Enterprise dashboard and reporting

### Phase 5: ZK Migration Proofs + Cross-Chain (FUTURE)
- Zero-knowledge proofs of migration compliance (no data leakage)
- Cross-chain attestation bridging (Base → Ethereum L1, Polygon)
- Privacy-preserving aggregate compliance reporting
- Formal verification of smart contracts

## References

1. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
2. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
3. NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA)
4. NIST FIPS 206 — Module-Lattice-Based Additional Digital Signature Standard (FN-DSA)
5. NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths
6. NSA CNSA 2.0 — Commercial National Security Algorithm Suite
7. W3C Verifiable Credentials Data Model v2.0
8. CycloneDX 1.7 Specification — OWASP
9. SARIF 2.1 — Static Analysis Results Interchange Format
10. EIP-712 — Typed Structured Data Hashing and Signing
11. EU Directive 2022/2555 (NIS2) — Network and Information Security
12. FISMA — Federal Information Security Management Act (44 U.S.C. § 3551)
13. FedRAMP — Federal Risk and Authorization Management Program
14. CMMC — Cybersecurity Maturity Model Certification (32 CFR Part 170)
