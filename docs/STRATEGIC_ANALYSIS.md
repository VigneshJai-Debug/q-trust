# Q-Trust — Strategic & Technical Analysis (29 Aug 2026)

> **How I would take this project further if I were its developer.**
> Every section ends with concrete, prioritized actions. Where a claim is
> an inference rather than a verified fact, it is marked **inference**.
> Design mockups referenced below are rendered images in [`docs/design/`](design/).

---

## 0 · Where Q-Trust stands today (verified against the codebase)

| Dimension | Status (this repo) | Verdict |
| --- | --- | --- |
| Discovery (inspector) | TLS/SSH/source/manifest/binary/config/PCAP scanners + ML code model | Strong |
| CBOM | qtrust.cbom.v1 → CycloneDX-aligned, ECMA-424 aware | Strong |
| Risk / compliance | NIST · CNSA · HNDL engines, NVD-backed vendor data | Strong |
| Migration planning | GNN τ 0.976 in-dist · τ-b 0.796 on **real** CBOMs · RL agent beats random | Strong |
| Evidence | 11 UUPS registries on Base, EIP-712 gasless, real Ed25519 VCs | Strong |
| Backend / frontend | Fastify 5 + Next.js 16, 127+ tests, security headers, rate limits | Strong |
| **Real-world AI validation** | Real code corpus (13K files), live TLS scans (131 hosts), NVD (401 CVEs) | **Improving** |
| **Production trust** | No external audit · no public deployment · EOA governance · centralized relayer | **The gap** |

**The honest headline:** the technology is genuinely differentiated on the
*verifiable-evidence + migration-intelligence* axis, but the market will not
credit it until (a) an independent audit exists, (b) there is a public
deployment, and (c) governance/relayer trust is decentralized. None of those
is a code problem — they are execution problems — but the code must be ready
for them. This document is that readiness plan.

---

## 1 · What I would do in the next 30 days (as the developer)

### 1.1 Fix the two things that can actually lose a deal

1. **External smart-contract audit.** The contract suite (11 registries,
   UUPS, EIP-712, reentrancy guards) is well-engineered, but "well-engineered"
   is not "independently verified". Engage a firm (OpenZeppelin, Trail of
   Bits, Code4rena, Hats Finance). Fix the findings, publish the report in
   `docs/audits/`. This single action moves the "production readiness" score
   more than any feature.
2. **Public deployment on Base Sepolia.** The repo's addresses are Anvil
   defaults. Deploy the 11 registries to Sepolia, verify contracts on-chain,
   publish addresses + deployment receipts in `docs/deployment/`. Then run
   the pilot case study against it. A verifiable public anchor turns the
   whole "blockchain is invisible" story from claim to evidence.

### 1.2 Decentralize trust while the audit runs

- **Governance:** move `DEFAULT_ADMIN_ROLE` behind `Multisig → Timelock`.
  Deploy a Safe (2/3) + TimelockController (7-day delay); transfer roles;
  publish the addresses. Keep an emergency pause path that *cannot* upgrade.
- **Relayer:** move the key to KMS/HSM, add per-request rate + spend limits,
  key rotation, and multi-operator approval for large batches.
- **RPC redundancy:** the indexer/relayer should pool ≥2 independent Base
  RPC providers with automatic failover (the repo already separates read
  model from chain; add provider abstraction).

### 1.3 Turn the real-data advantage into a moat

We already train on **real data** (13K real code files from openssl,
boringssl, aws-lc, mbedtls, wolfssl, nodejs, golang, pyca; 131 live TLS
endpoints; 401 real NVD CVEs). The next step is to make the corpus the
product:

- Add a **real-CBOM benchmark suite** as a tracked fixture (39 real
  enterprise CBOMs already in `planner/data/real_cboms/`) with the
  tie-aware τ-b protocol — this is the number to defend publicly.
- Collect **real migration outcomes** (the moat competitors cannot copy):
  every accepted/rejected recommendation, actual migration, and post-migration
  re-scan becomes training data. Add an opt-in telemetry path in the SDK.
- **Explainability:** every recommendation should carry `why` (which
  attributes and dependencies drove the rank), confidence, expected impact,
  and rollback. Enterprise buyers buy the explanation.

---

## 2 · Multi-category critical analysis

### 2.1 Smart contracts — score 76 → target 90

**Strengths (verified):** UUPS + AccessControl + Pausable + ReentrancyGuard
+ EIP-712 with chain/contract/nonce binding; relayer path checks recovered
signer has `REGISTRAR_ROLE`; nonce replay protection; implementation
initializers disabled.

**Gaps:** 11 registries = 11 upgrade surfaces × permission sets × storage
layouts. Group into 3 clusters (Core / Trust & Governance / Compliance) to
shrink the surface — without necessarily merging logic. Add:
- storage-layout validation in CI (OpenZeppelin Upgrades plugin / solc
  storage checks),
- upgrade simulation + public announcement workflow,
- fork tests against Sepolia/Mainnet state.

### 2.2 Backend — score 77 → target 88

**Strengths (verified):** rate limiting, Helmet, OpenAPI, Sentry, pino,
Prometheus metrics, API-key constant-time compare, real Ed25519 VC
issue/verify (byte-compatible with the Python SDK).

**Gaps:**
- **Indexer reorg handling:** if the read model lags or reorgs, evidence
  state can diverge from chain. Add block-tracking with reorg rollback
  (store block numbers, re-fetch on reorg signal).
- **Multi-RPC failover** (see 1.2).
- **Audit logs:** append-only, tamper-evident operational audit trail
  (who scanned what, who attested what).
- **Tenant isolation** before multi-tenant; currently single-org oriented.

### 2.3 Frontend / UX — score 70 → target 85

**The mockups in [`docs/design/`](design/) show the target:**

- `dashboard_mockup.svg` — the **Quantum Security Control Center**: one
  readiness number, top-5 ML-ranked fixes with "why", environment breakdown,
  recommended actions. No wallet, no chain jargon.
- `verify_page_mockup.svg` — public verification with a human result
  ("Evidence verified — cryptographically valid") and the evidence chain
  rendered as a graph, chain details as secondary.
- `architecture_target.svg` — the product architecture with the trust graph
  at the center.

**Gaps:** reduce wallet-first framing; make blockchain invisible; add
executive report generation (PDF) and the PQC Passport view.

### 2.4 ML / planner — score 82 → target 92

**Fixed this cycle (verified):**
- X.509 encoder bug: real certs (`sha256WithRSAEncryption`) were encoded as
  `SHA` instead of `RSA`, silently poisoning real-CBOM features. Now mapped
  correctly in both `model.py` and `model_v3.py`.
- Real-CBOM suite was never actually loading real CBOMs (the loader scanned
  a file path as a directory and fell back to synthetic). Now loads 39 real
  enterprise CBOMs from live TLS scans.
- Ranking metric was tie-blind: identical assets (8× RSA-2048) got arbitrary
  dense ranks and every model scored negative τ. Now **tie-aware τ-b against
  priority scores** — the honest metric for real inventories.
- GNN now fine-tuned on real CBOM graphs: **τ-b 0.796 on real CBOMs**
  (heuristic ceiling 0.855) while holding in-dist τ 0.976 — best model on
  every suite; promoted to canonical default in `predict.py`.

**Next:** model monitoring (drift detection on real CBOM distributions),
retraining pipeline triggered by drift, and the explainability layer.

### 2.5 SDK / developer experience — score 84 → target 92

**Strengths (verified):** PyPI-published `qtrust` SDK, DID + VC + CBOM +
trust modules, cross-language credential verification proven both directions.

**Gaps:** CI integration (GitHub Action wrapper), SBOM/CBOM generation
CLI (`qtrust scan .`), and typed client for the REST API.

### 2.6 DevOps / security — score 76 → target 88

**Strengths (verified):** 7+ CI workflows, npm/pip audits, secret scanning,
Halmos symbolic execution, fuzz + invariant + attack tests, weekly PQC
self-scan, GHCR + PyPI publishing.

**Gaps:** fork tests, upgrade tests, reorg tests, RPC-failure tests,
chaos drills, external audit (1.1), public deployment (1.1).

---

## 3 · Technology research — what to adopt (2026)

Source: current ecosystem research (NIST CSRC, CycloneDX, Base docs,
industry analyses, Aug 2026).

| Technology / standard | Why it matters for Q-Trust | Priority |
| --- | --- | --- |
| **CycloneDX v1.7 (ECMA-424)** | CBOM is now a *standard*, not a differentiator. Align our CBOM emitter to the standardized algorithm-family taxonomy so we interoperate with IBM CBOM kit & CycloneDX tooling. CBOM becomes our open compatibility layer. | **Now** |
| **FIPS 203/204/205 (ML-KEM/ML-DSA/SLH-DSA)** | The migration end-state. Our GNN/RL planner should rank *target algorithms* (ML-KEM-768, ML-DSA-65) in recommendations, and the risk engine should know each algorithm's FIPS status. | **Now** |
| **FIPS 140-2 sunset (Sep 2026)** | Real market deadline. Position the "FIPS 140-3 ready" evidence story in the compliance engine and passport. | **Now** |
| **Google's 2029 PQC deadline** | Anchor our marketing narrative: enterprises need a migration system *now*; we give them the verifiable evidence layer for it. | **Now** |
| **Zero-knowledge proofs (compliance)** | The highest-leverage differentiator: *prove* PQC readiness without revealing the inventory. ZK is entering identity/compliance stacks (2026). Add a "ZK compliance proof" research spike; don't ship a toy. | **P2** |
| **Verifiable Credentials (W3C VC 2.0)** | Already shipped real Ed25519 VCs. Extend: selective disclosure, revocation lists, and the PQC Passport as a VC. | **P1** |
| **Passkeys / account abstraction** | Remove wallet friction for enterprise users (SSO + passkeys first; AA later). | **P1/P2** |
| **Kubernetes-native discovery** | Enterprises live in K8s; a K8s operator/cron scanner is a concrete integration. | **P1** |
| **Multi-chain anchoring** | Base first; anchor evidence roots to Ethereum Mainnet for durability (cheap, once per batch). | **P2** |
| **LLM-assisted explanation** | Only as a *presentation* layer over deterministic explanations — never for risk scoring. | **P2** |

**Research sources consulted (Aug 2026):** NIST CSRC PQC program; CycloneDX
v1.7 release notes (standardized CBOM); IBM CBOM toolkit; Base deployment
docs; industry analyses of enterprise PQC migration timelines (incl. the
2029 Google deadline and FIPS 140-2 sunset).

---

## 4 · The moat, restated

Competitors (Keyfactor, DigiCert Quantum Central, IBM Quantum Safe, and the
CBOM ecosystem) can copy a scanner and a dashboard. They cannot quickly
copy:

1. **A real cryptographic dependency graph** (business → app → service →
   protocol → cert → algorithm) instead of a flat inventory,
2. **Verified migration evidence** (immutable, independently checkable),
3. **Migration intelligence** that improves from actual outcomes,
4. **Honest real-data benchmarks** (τ-b 0.796 on real CBOMs) that
   competitors can't fake.

The plan above converts 1–4 from engineering assets into market position.

---

## 5 · 90-day exit criteria

- [ ] External audit engaged, findings remediated, report in `docs/audits/`
- [ ] Registries deployed + verified on Base Sepolia; receipts committed
- [ ] Governance behind multisig + timelock; relayer in KMS with limits
- [ ] Real-CBOM benchmark suite tracked in CI (τ-b regression gate)
- [ ] PQC Passport v1 shipped in the dashboard
- [ ] GitHub App + Jira/ServiceNow integration live
- [ ] Explainability cards on every recommendation
