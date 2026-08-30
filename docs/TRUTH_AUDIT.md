# Q-Trust Truth Audit — Day 1-14 Integrity (QTRUST P0)

Every number displayed by Q-Trust must be classified (Phase 0, §4):

| Metric | Value | Source | Training | Validation | Status |
|---|---|---|---|---|---|
| Discovery F1 0.841 | REAL (2764 held-out) | real code corpus 13k | CodeBERTa fine-tune | **repo-disjoint 27→7** (QTRUST-007: recall 0.773 → critical recall 0.99 target) | REAL but needs hard negatives |
| GNN τ 0.971 | REAL (synthetic held-out) | 60k synthetic + 37 real CBOMs | LayerNorm GNN | host-disjoint 80/20 (τ-b 0.807 real) | **SYNTHETIC L1** — do not claim enterprise |
| Risk τ (synthetic demo) | SYNTHETIC | features → synthetic expert formula | RF | synthetic prefs | **DEMO ONLY** (QTRUST-001) — NOT expert |
| WhatIf 43h/4.6%/8.2%/94% | **DEMO FABRICATED** | hard-coded (§QTRUST-002) | — | — | DEMO — production must call calibrated models with intervals |
| Digital Twin 0.6*last | **SIMULATED PLACEHOLDER** (§QTRUST-003) | deterministic growth | — | — | DEMO — requires graph+CP-SAT |
| Graph edges | **SYNTHETIC DEMO** linear chain (§QTRUST-004) | CBOM assets → asset-0→1→2 | — | — | DEMO — replace with imports/calls/SBOM |
| RL beats random | **WEAKLY GROUNDED** (§QTRUST-005) | same feasible distribution as heuristic | PPO | random baseline only | Needs CP-SAT/heuristic/human on unseen |
| Real CBOM 39 | REAL (prototype, QTRUST-006) | 277 TLS hosts → 37 CBOMs host-disjoint | — | — | REAL but target 1k orgs / 10k CBOMs |
| Perf 147.8 req/s p95 11ms | **SIMULATED** (§QTRUST-013) | local tsx + anvil, rate-limit disabled | — | — | Not production representative |
| Contracts 11 UUPS | **UNAUDITED** (§QTRUST-010) | no external audit, no Sepolia, EOA governance, backend relayer | — | — | P0 blocker |

**Policy:** Any benchmark using synthetic expert/WhatIf/Twin/graph must be labeled `synthetic` (Level 1) and never published as `expert` or `enterprise` performance. Real RiskBench requires `qtrust_data/gold/riskbench-v1/` human annotations (5-10 experts, 5k-10k pairs, blinded, adjudicated, inter-rater κ).

**Artifact lineage:** Every prediction stores `model_version + dataset_hash + feature_schema + policy` → Merkle → chain (§42, `qtrust/data/lineage.py`).
