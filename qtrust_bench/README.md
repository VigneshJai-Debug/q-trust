# qtrust-bench — Real-World Benchmark Repository (§39)

```
qtrust-bench/
├── datasets/
│   ├── discovery/        # Gold crypto dataset (human validated)
│   ├── ranking/          # QTrust-RiskBench pairwise preferences
│   ├── migration/        # Git-history mining outcomes
│   ├── interoperability/ # Compatibility matrix
│   └── hndl/            # Harvest-now-decrypt-later
├── splits/
│   ├── repository/       # Level 2: unseen repos
│   ├── organization/     # Level 3: unseen orgs
│   └── temporal/         # Level 5: future 2026
├── baselines/
│   ├── rules/
│   ├── xgboost/
│   ├── lightgbm/
│   └── gnn/
├── evaluation/
│   ├── metrics/          # Kendall τ, NDCG, Critical Recall
│   ├── calibration/      # ECE, Brier
│   └── robustness/       # Adversarial
└── models/
    └── registry/         # Versioned artifacts (risk-v3.2)
```

**No single metric.** Report (targets, not claims — see docs/TRUTH_AUDIT.md):

```
Synthetic:      τ = 0.971   (synthetic held-out, SYNTHETIC L1)
Unseen repo:    τ = 0.84    (target)
Expert:         τ = 0.81    (target — requires qtrust_data/gold/riskbench-v1)
Temporal:       NDCG@10 = 0.92   (target)
CriticalRecall: 98.4%       (target)
```

Do not quote these as measured benchmark output (REG-08). Measured values live
in `planner/results/benchmark_v3.json` and `docs/TRUTH_AUDIT.md`.
