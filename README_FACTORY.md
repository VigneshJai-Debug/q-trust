# Q-Trust ML Factory — Strategy Implementation

This implements the 64-section ML strategy: **"How do I build the world's best labeled dataset for cryptographic migration decisions?"**

## Model Family (no single giant model)
```
                         Q-TRUST ML
   DISCOVERY ML          RISK ML              GRAPH ML
   └─ crypto detection  ├─ exposure          ├─ blast radius
                        ├─ HNDL              └─ prioritization
                        └─ business impact
                 MIGRATION INTELLIGENCE (cost/failure/interop) → CP-SAT/RL → DIGITAL TWIN
```

## Data Factory (§25)
```
RAW (GitHub/packages/containers/TLS) → Bronze → Silver (AST) → Gold (human validated) → Splits (repo/org/temporal)
DVC versioned, MLflow tracked, hash-anchored → Merkle → on-chain.
```

## Labeling
- Weak supervision LFs (§26) → training
- Active learning (§27-28) → uncertain → human → retrain
- Gold dataset 7 dimensions (§5): algorithm, primitive, role, location, reachability, sensitivity, criticality

## Anti-Circular
Risk NOT trained on own risk formula (§9). Expert pairwise preferences (§10-12) → Learning-to-Rank (LambdaMART/GNN) → Kendall τ/NDCG vs expert, not heuristic.

## Progressive GNN (§14)
synthetic → open-source → real → expert → temporal. Temporal predicts future debt (§46).

## Training Infrastructure (§51)
Python/PyTorch/PyG/LightGBM/MLflow/DVC/Postgres/S3. GPU for GNN/transformer, CPU for LightGBM.

## Benchmarks (§39, §63)
```
benchmarks/
  synthetic/      # heuristic labels allowed (L1)
  real_world/     # unseen repos/orgs (L2/L3)
  expert/         # QTrust-RiskBench pairwise (L4)
  temporal/       # future 2026 (L5)
  adversarial/    # obfuscation/aliases (§40)
  migration_outcomes/ # git-history mining (§17-18)
```

Report: `Critical Recall 98.4% | NDCG@50 94.8%` not "Accuracy 97%."

## What-If Engine (§64)
"If I replace RSA-2048 with ML-DSA-65 → Risk 87→12, Cost 43h, Failure 8.2% → Recommended? 94%"

## MLOps (§49-54)
Versioned `risk-v3.2 + dataset hash + feature schema` → Merkle → chain.
Shadow mode (§53): rule→prod, ML→shadow 30-60d. Gates: Critical Recall ≥97%, ECE ≤0.05.

Run:
```bash
dvc repro
python -m qtrust.evaluation.run_all --splits qtrust/data/splits --out qtrust_bench/evaluation/report.json
python -m qtrust.models.discovery.model
```
