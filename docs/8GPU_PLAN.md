# Multi-GPU Utilization Plan for Q-Trust

## Status: IMPLEMENTED

The training node is shared with other workloads, so GPU assignments are
**adaptive** rather than hard-coded. Every entry point accepts env overrides.

| Job | Default GPUs | Env override | Output |
|---|---|---|---|
| Distributed GNN v3 (DDP, 400K graphs) | `1,2` | `DDP_GPUS` | `planner/model_ddp_v3.pt` |
| RL migration agent (10K episodes) | `5` | `QTRUST_GPU_RL` | `planner/rl_agent.pt` |
| Side-channel detector (20K traces) | `6` | `QTRUST_GPU_INSPECTOR` | `inspector/side_channel_model.pt` |
| Anomaly VAE (5K CBOMs) | `6` | `QTRUST_GPU_INSPECTOR` | `inspector/anomaly_model.pt` |
| Shor simulation N=15..77 | `6` | `QTRUST_GPU_QUANTUM` | `notebooks/quantum_threat_report.json` |

On an idle 8× A100 node you would assign one job per GPU:

```bash
DDP_GPUS="0,1,2,3" QTRUST_GPU_RL=4 QTRUST_GPU_INSPECTOR=5 bash train_8gpu.sh
```

## How to Run

```bash
# Full run (~2h wall on idle A100s; longer when sharing GPUs)
bash train_8gpu.sh

# Smoke pass first (minutes) — always do this before a full run
QUICK=1 bash train_8gpu.sh

# Or drive pieces directly:
torchrun --nproc_per_node=2 -m qtrust_planner.train_ddp --epochs 200   # from planner/
python3 train_all_parallel.py --quick
make -f Makefile.gpu train-ddp          # DDP wrapper target
```

Logs land in `logs/ddp_gnn.log` and `logs/parallel_jobs.log`.

## Implementation Notes

- `planner/qtrust_planner/train_ddp.py` fixes three issues vs. the original draft:
  uses `batch.y_order` / `batch.y_risk` (the dataset has no `.y`), validates on a
  held-out split instead of re-using the training loader, and works both under
  `torchrun` (env-based ranks) and plain `mp.spawn` without double-spawning.
- Validation Kendall tau is averaged across ranks with `all_reduce(AVG)` so the
  best-checkpoint decision is global.
- `quantum_estimator.factor()` falls back GPU -> CPU -> classical Pollard rho,
  so the quantum step never blocks completion if Aer's CUDA build is absent.
- RL/inspector jobs set `CUDA_VISIBLE_DEVICES` per process; inside each process
  its assigned GPU appears as `cuda:0`.

## Results

Held-out protocol: last 15% of `generate_dataset(1000, seed=999)` via
`benchmark_v3.py` (`planner/results/benchmark_ddp.json`).

| Model | Kendall τ | Top-5 | Top-10 | Note |
|---|---|---|---|---|
| v2 (1.2K graphs, CPU) | 0.9605 | 0.6733 | 0.5200 | 9K params |
| v3 single-GPU (100K graphs) | 0.8980 | 0.5200 | 0.2733 | committed as `model_gpu_v3.pt` |
| v3 DDP (400K graphs, 2×A100) | **0.9027** | **0.5400** | TBD | committed as `model_ddp_v3.pt` |

**Interpretation:** the final DDP checkpoint edges out the single-GPU v3 on
this held-out set. Note that v2 — trained directly on heuristic-generated
labels — still ranks highest: on fully synthetic data the rule-based labeler
is effectively the ground truth, so learned models converge toward but rarely
exceed it. Real-world CBOM validation remains the outstanding item for all
planner models.
