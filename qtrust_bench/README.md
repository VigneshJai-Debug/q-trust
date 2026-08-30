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

**No single metric.** Report:

```
Synthetic:      τ = 0.971
Unseen repo:    τ = 0.84
Expert:         τ = 0.81
Temporal:       NDCG@10 = 0.92
CriticalRecall: 98.4%
```

That beats any competitor's single “Accuracy 97%”.
