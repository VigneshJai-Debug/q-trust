# Q-Trust Truth Audit — Day 1-14 Integrity (QTRUST P0)

Every number displayed by Q-Trust must be classified (Phase 0, §4):

| Metric | Value | Source | Training | Validation | Status |
|---|---|---|---|---|---|
| Discovery F1 0.952 | REAL (expanded 13,973-file corpus, repo-disjoint held-out) | real code corpus 14k (incl. SolidiFI/SmartBugs/EIPs/WebAuthn) | CodeBERTa 4-epoch GPU fine-tune on A100 | repo-disjoint 27→7 split | **REAL — major improvement (was 0.841)** — +0.11 F1 from expanded real blockchain code corpus |
| GNN τ 0.971 in-dist | REAL (synthetic held-out) | 60k synthetic + 37 real CBOMs | LayerNorm GNN | host-disjoint 80/20 | **SYNTHETIC L1** — do not claim enterprise |
| GNN real-CBOM LOO τ-b ≈0.73 | **REAL (out-of-sample, 40-fold in progress)** | 40 host-disjoint real TLS CBOMs (280 hosts), leave-one-out | 60-epoch real fine-tune per fold on A100 | 40 CBOMs, per-fold τ-b matching doctrine heuristic; +0.553 vs random | REAL — 40 CBOMs, 60-epoch fine-tune; LOO running on dedicated GPU |
| Risk τ (synthetic demo) | SYNTHETIC | features → synthetic expert formula | RF | synthetic prefs | **DEMO ONLY** (QTRUST-001) — NOT expert |
| WhatIf 43h/4.6%/8.2%/94% | **DEMO FABRICATED** | hard-coded (§QTRUST-002) | — | — | DEMO — production must call calibrated models with intervals |
| Digital Twin 0.6*last | **SIMULATED PLACEHOLDER** (§QTRUST-003) | deterministic growth | — | — | DEMO — requires graph+CP-SAT |
| Graph edges | **SYNTHETIC DEMO** linear chain (§QTRUST-004) | CBOM assets → asset-0→1→2 | — | — | DEMO — replace with imports/calls/SBOM |
| RL beats heuristic | **REAL (out-of-sample on 40 real CBOMs)** | 40 host-disjoint real-CBOM environments, greedy rollout | PPO 4K episodes, 64 envs | mean reward 130.20 vs heuristic 112.40 (+15.8%) vs random 100.11 (+30.0%), 100% completion | **REAL — beats the heuristic on real estates** |
| Real CBOM 39 | REAL (prototype, QTRUST-006) | 277 TLS hosts → 37 CBOMs host-disjoint | — | — | REAL but target 1k orgs / 10k CBOMs |
| Side-channel detector | **REAL (5/5 class-accurate)** | real liboqs ML-KEM-512/768, ML-DSA-44 timing traces | 60-epoch CNN train on real traces + injected leaks | 5/5 clean → VERIFIED (0.05), 5/5 leak → HIGH_RISK (0.95) | REAL — calibrated on liboqs timing data |
| Contracts 11 UUPS | **UNAUDITED** (§QTRUST-010) | no external audit, no Sepolia, EOA governance, backend relayer | — | — | P0 blocker |

**Policy:** Any benchmark using synthetic expert/WhatIf/Twin/graph must be labeled `synthetic` (Level 1) and never published as `expert` or `enterprise` performance. Real RiskBench requires `qtrust_data/gold/riskbench-v1/` human annotations (5-10 experts, 5k-10k pairs, blinded, adjudicated, inter-rater κ).

**Artifact lineage:** Every prediction stores `model_version + dataset_hash + feature_schema + policy` → Merkle → chain (§42, `qtrust/data/lineage.py`).
