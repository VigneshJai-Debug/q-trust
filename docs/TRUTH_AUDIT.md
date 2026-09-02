# Q-Trust Truth Audit — Day 1-14 Integrity (QTRUST P0)

Every number displayed by Q-Trust must be classified (Phase 0, §4):

| Metric | Value | Source | Training | Validation | Status |
|---|---|---|---|---|---|
| Discovery F1 0.952 | REAL (expanded 13,973-file corpus, repo-disjoint held-out) | real code corpus 14k (incl. SolidiFI/SmartBugs/EIPs/WebAuthn) | CodeBERTa 4-epoch GPU fine-tune on A100 | repo-disjoint 27→7 split | **REAL — major improvement (was 0.841)** — +0.11 F1 from expanded real blockchain code corpus |
| GNN τ 0.971 in-dist | REAL (synthetic held-out) | 60k synthetic + 37 real CBOMs | LayerNorm GNN | host-disjoint 80/20 | **SYNTHETIC L1** — do not claim enterprise |
| GNN real-CBOM LOO τ-b ≈0.73 | **REAL (out-of-sample, 40-fold COMPLETE)** | 40 host-disjoint real TLS CBOMs (280 hosts), leave-one-out | 30-epoch real fine-tune per fold on A100, folds sharded across 4 GPUs, deterministic-kernel harness (re-run 2026-09-02; 3-fold repro bit-identical to merged shards) | τ-b **0.7263** vs heuristic **0.7450** (Δ **−0.0188**; 60-epoch overfits, Δ −0.0545); **reproduces the doctrine on 38/40 folds** (0 wins / 38 ties / 2 losses, both n≤13); +0.503 vs random | REAL — 40 CBOMs, 30-epoch fine-tune is the best out-of-sample operating point; the pre-fix τ-b 0.7377 (39/40) is superseded by the deterministic run |
| Risk τ (synthetic demo) | SYNTHETIC | features → synthetic expert formula | RF | synthetic prefs | **DEMO ONLY** (QTRUST-001) — NOT expert |
| WhatIf 43h/4.6%/8.2%/94% | **DEMO FABRICATED** | hard-coded (§QTRUST-002) | — | — | DEMO — production must call calibrated models with intervals |
| Digital Twin 0.6*last | **SIMULATED PLACEHOLDER** (§QTRUST-003) | deterministic growth | — | — | DEMO — requires graph+CP-SAT |
| Graph edges | **SYNTHETIC DEMO** linear chain (§QTRUST-004) | CBOM assets → asset-0→1→2 | — | — | DEMO — replace with imports/calls/SBOM |
| RL agent on real CBOMs | **REAL (out-of-sample on 40 packed real CBOMs)** | 40 packed real-CBOM estates, greedy rollout | PPO on real-CBOM packs (risk labels derived from real scan fields: RSA-1024 → critical, RSA-2048 → high, expired/near-expiry raise the class) | mean reward **140.34** ± 8.13 vs heuristic **140.62** (Δ −0.28 — **tie**) vs random **136.84** (+2.6%), 100% completion (2/40 wins · 27 ties · 11 losses) | **REAL — learns risk-priority and matches the doctrine** (archived 130.20 vs 112.40 “beats heuristic” was NOT reproducible — every real asset defaulted to the builder's `criticality: medium`, zero reward signal; fixed and re-measured 2026-09-02) |
| Real CBOM 39 | REAL (prototype, QTRUST-006) | 277 TLS hosts → 37 CBOMs host-disjoint | — | — | REAL but target 1k orgs / 10k CBOMs |
| Side-channel detector | **REAL (5/5 class-accurate)** | real liboqs ML-KEM-512/768, ML-DSA-44 timing traces | 60-epoch CNN train on real traces + injected leaks | 5/5 clean → VERIFIED (0.05), 5/5 leak → HIGH_RISK (0.95) | REAL — calibrated on liboqs timing data |
| Contracts 11 UUPS | **UNAUDITED** (§QTRUST-010) | no external audit, no Sepolia, EOA governance, backend relayer | — | — | P0 blocker |

**Policy:** Any benchmark using synthetic expert/WhatIf/Twin/graph must be labeled `synthetic` (Level 1) and never published as `expert` or `enterprise` performance. Real RiskBench requires `qtrust_data/gold/riskbench-v1/` human annotations (5-10 experts, 5k-10k pairs, blinded, adjudicated, inter-rater κ).

**Artifact lineage:** Every prediction stores `model_version + dataset_hash + feature_schema + policy` → Merkle → chain (§42, `qtrust/data/lineage.py`).
