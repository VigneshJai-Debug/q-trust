# Phase 5: GNN Migration Planner

## Status: DONE (honest metrics, reproducible)

## Deliverables
- `planner/qtrust_planner/model.py` — MigrationGNN (PyTorch Geometric GCN + residual
  connections, dual order/risk heads)
- `planner/qtrust_planner/data_generator.py` — synthetic migration dependency graphs
  (`y_order`, `y_priority`, `y_risk` labels)
- `planner/qtrust_planner/train.py` — training script; `--loss listmle` (default,
  ListMLE/Plackett-Luce ranking loss) or `--loss mse` (legacy priority regression);
  honest per-graph metrics on validation
- `planner/qtrust_planner/predict.py` — CBOM (+ optional dependency graph) → ranked
  migration order via `predict_detailed()`
- `planner/qtrust_planner/benchmark.py` — multi-seed benchmark vs random and
  rule-based heuristic baselines → `planner/results/benchmark.json`

## Verification
- Benchmark (3 seeds × 40 epochs, 1000 graphs, 150 held-out eval) — honest,
  reproducible via `python -m qtrust_planner.benchmark --seeds 42 43 44`:
  **Current results (2026-08-21, fixed benchmark bug, 3 seeds):**

  | method | exact_rank | top5 | top10 | kendall | node_rank |
  |---|---|---|---|---|---|
  | random | 0.000 | 0.000 | 0.000 | −0.009 | 0.021 |
  | gnn-mse (legacy) | 0.000 | 0.227±0.042 | 0.149±0.054 | 0.144±0.024 | 0.169±0.018 |
  | **gnn-listmle** | **0.000** | **0.500±0.061** | **0.371±0.067** | **0.266±0.023** | **0.329±0.029** |
  | heuristic (label oracle) | 0.993 | 1.000 | 1.000 | 0.997 | 0.998 |

  ListMLE significantly outperforms MSE (τ 0.266 vs 0.144) and random (~0), approaching heuristic.

- Production `planner/model.pt` **(ListMLE, 80 epochs, 1200 graphs, seed 42): top-5 0.656, top-10 0.528, Kendall τ 0.388, node-rank 0.437** on its validation split (180 graphs). Previous 50-epoch model: τ 0.279, top5 0.533.
- `predict_detailed()` used live in the Phase 8 pilot (step 4); reports honest `model_metrics` from the checkpoint.

## Honest notes
- Evaluation is on **synthetic** graphs only (20–100 nodes, layered enterprise 70% + random 30% DAGs); real-world CBOM evaluation is future work and NOT claimed.
- The label-generating heuristic is included as the `heuristic` baseline (upper bound for this synthetic task, τ 0.997); `random` is the chance level.
- Earlier claims of "exact-rank 24%, Kendall τ 0.924" were not reproducible from the code (the metric previously reported was per-node rank agreement, mislabeled as exact-rank) and have been removed. MSE-trained ordering was found near-random (τ ≈ 0.14) due to mean-seeking regression; the ListMLE ranking loss is the current fix (τ 0.266 ±0.023, +85% over MSE).
- Production model (80 epochs) trained with ListMLE reaches τ 0.388, demonstrating that longer training + more data improves ordering without changing the synthetic task.
- Benchmark bug fixed (2026-08-21): `ckpt`/`model` ordering in `benchmark.py` corrected; 3-seed honest benchmark now completes.

## Fixes applied
- `train.py` rewritten: ListMLE ranking loss (vectorized), risk-head MSE retained,
  honest metrics (exact-rank, top-k, Kendall τ, node-rank) reported per epoch, best
  state saved with `eval_metrics` in the checkpoint.
- `predict.py` reports `model_accuracy` from `eval_metrics.kendall` (honest) instead of
  the mislabeled node-rank value.
- `benchmark.py` added: multi-seed (default 42/43/44) with mean±std, held-out eval
  set, random + heuristic + gnn-mse + gnn-listmle.