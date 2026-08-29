# 8-GPU Utilization Plan — Q-Trust Model Intelligence Program (Corrected)

> **Correction notice (2026-08-27, P0-4):** the previous version of this document reported the
> DDP checkpoint at τ 0.9027 / top-5 0.5400 and interpreted it as edging out the single-GPU
> checkpoint. The committed benchmark file `planner/results/benchmark_ddp.json` records
> **τ 0.8312 / top-5 0.140** for the DDP checkpoint on the same seed=999 held-out suite,
> i.e. distribution cost seven points when the objective was broken. This document has been
> corrected to the committed JSON values and now points to the registry as the single source
> of truth for all future results. See `Q-Trust_A100_Model_Intelligence_Program.pdf` §4.

## Hardware

8× A100 80 GB (640 GB HBM2e, ~2.5 PFLOPS bf16, NVLink). The node is a fixed observatory:
single-node is the ceiling (~7B with FSDP+offload), but any model ≤1B trains with
data parallelism without sharding (pdf §2).

## Model Estate (9 checkpoints, <5 MB) — corrected reachability

| Checkpoint | Params | Served? (after P0-3 fix) |
|---|---|---|
| planner/model.pt (v2) 9,282 | `QTRUST_MODEL_PATH` → `/app/model.pt` (Docker COPY now includes it; health reports real state) | ✅ primary (heuristic fallback only when missing) |
| planner/model_gpu_v3.pt 237,070 | `QTRUST_MODEL_PATH_V3` → `/app/model_gpu_v3.pt`, also reachable via `parallel_scanner.py:72-85` batch risk scoring | ✅ |
| planner/model_ddp_v3.pt 237,070 | `QTRUST_MODEL_PATH_DDP` → `/app/model_ddp_v3.pt`, now wired via `server.py:_resolve_checkpoint_path()` fallback chain so DDP artifact has a consumer | ✅ (was zero consumers) |
| planner/*_real.pt 237,070 | `QTRUST_PLANNER_MODEL_REAL` (operator sets; was env empty) | ✅ when present |
| planner/rl_agent.pt 17,666 | `QTRUST_RL_MODEL_PATH` → `/app/rl_agent.pt` (and `_real` variant wired) | ✅ `/rl/plan` with PPO rollout |
| inspector/* 168K, 25K | `QTRUST_SIDE_CHANNEL_MODEL` / `QTRUST_ANOMALY_MODEL` (now defaults to `inspector/*.pt`; health `models_loaded` is real, not hardcoded `[]`) | ✅ via persistent daemon (pdf §20) |

## Why More Compute Made the Model Worse — Corrected Ladder

Committed benchmarks (seed=999, same protocol):

- v2 CPU 9,282 params, 1.2K graphs: **τ 0.9607**, top-5 0.673 (benchmark_v3.json:6)
- v3 1×A100 237,070 params, 100K graphs, bf16: **τ 0.8982**, top-5 0.520 (benchmark_v3.json:14)
- v3 2×A100 DDP 237,070 params, 400K graphs: **τ 0.8312**, top-5 0.140 (benchmark_ddp.json:24) ← corrected from 0.9027

> **Updated (2026-08-28):** after the per-graph ListMLE loss fix the HPO sweep
> winner (200K graphs, LayerNorm, warmup-cosine, best-checkpointing) reaches
> held-out **τ 0.9746** / top-5 0.700 on the same seed=999 suite
> (`planner/results/benchmark_v3.json` v3 entry) — exceeding the previous
> canonical τ 0.9718 and the pre-fix 0.8982.

Root causes (P0-1, P1-7, pdf §5): cross-graph ListMLE (train_gpu.py:32-46,176; train_ddp.py:146) mixed Plackett-Luce normalizer across 256 unrelated estates per batch; per-rank double-sharding. Fixed by `per_graph_listMLE_loss` with `batch_idx` masking (train_gpu.py, train_ddp.py) and single global dataset sharded once via `DistributedSampler` (pdf Appendix B P0 fix list).

Heuristic ceiling (P0-2): the label rule itself scores τ 0.9999, so imitation cannot beat it; Track B replaces imitation with outcome simulation (cost/downtime/risk under NIST IR 8547 / CNSA 2.0).

## Fixed Training Protocol (pdf §19)

```bash
# Every track, bf16 + compile + warmup-cosine + per-graph loss + single-dataset DDP
torchrun --nproc_per_node=8 train_track.py \
  --precision bf16 --compile --grad-accum 4 \
  --sched warmup-cosine --warmup 0.03 --epochs 40 \
  --seed 42,43,44 --track-registry mlruns:// \
  --data-hash $(dvc locked-hash data/traces_v1)
```

- BF16 hygiene: `GradScaler` removed under bf16 (fp16-only, no-op)
- Schedule: warmup 3% → cosine decay to 0.1×
- Compile: `torch.compile` on step function
- Registry: every run logs config/seed/data_hash/git_commit/metrics; promotion gated on eval suites (pdf §20)

## GPU Allocation Across 13 Weeks (pdf Fig 4)

- Phase 0 (w1-2): all 8 GPUs for fixes + harness + data foundation (exit M1: rerun v3 recipe beats v2)
- Track A QTrace-FM (w3-10): 4 GPUs, masked-patch pretrain + fine-tune heads (30-80M, DDP, seq 2048-8192)
- Track B QPlan-GT (w3-10): 2 GPUs, heterogeneous GraphTransformer + PPO vectorized envs (5-20M)
- Tracks C/D (w3-8/12): 2 GPUs shared, LoRA 3B (Track C) + QRisk ensemble (Track D, near-free)
- W11-12: registry→serving export (ONNX int8, p95 ≤50ms), persistent inference service
- W13: open benchmark release (eval suites, baselines, model cards, reproduction)

Budget: ~4,000 / 17,280 GPU-hours (23%) — 77% slack for seeds/ablations (Appendix A).

## MLOps: Registry, Export, Serving (pdf §20)

- MLflow file registry (`planner/registry/`) mirrored when `QTRUST_MLFLOW_TRACKING_URI` set; every checkpoint carries config/seed/data_hash
- Export: `python -m qtrust_planner.export --all` → ONNX + TensorRT int8 + schema sidecar (drift detection)
- Serving: `backend/scripts/gpu_bridge.py daemon` warm models, dynamic batching, health reports real `models_loaded` (fixes hardcoded `[]`), backend `gpu-service.ts` multiplexes over persistent child

## Evaluation Doctrine (pdf §9,18)

Every number is median of 3 seeds ± IQR on a held-out set not used to select anything.
Suites: in_dist (canonical 15% seed=999), OOD-size (200-500 nodes), enterprise-topology (layered L0→L1→L2), real-CBOM (org-level splits).
CI smoke: fits 100 graphs end-to-end on CPU and asserts loss decreases; benchmark provenance gate asserts device/seed/data_hash are recorded.

## Success Metrics (90-day targets, pdf §22)

- Planner τ ≥0.97 on synthetic synthetic suite (regression gate, beats v2 0.9607 after fix)
- Outcome regret ≥20% lower cost + deadline violations vs greedy heuristic (OOD)
- SCA fewer traces than CPA on ≥2 parameter sets, coverage ≥10 sets + classical baselines
- Discovery +10 F1 over regex, risk ECE ≤0.05, p95 ≤50ms, 9/9 checkpoints served

Run the gates:

```bash
# Training smoke
PYTHONPATH=planner python -c "from qtrust_planner.train_gpu import train_gpu; train_gpu(n_graphs=100, epochs=2, batch_size=8, device_name='cpu')"

# Eval harness
PYTHONPATH=planner:inspector python -m qtrust_planner.eval_harness --model-path planner/model.pt --n-graphs 200 --seeds 42 43 44

# Benchmark with provenance
PYTHONPATH=planner python -m qtrust_planner.benchmark_v3 --n-graphs 200 --json-out /tmp/bench.json && cat /tmp/bench.json | grep data_hash
```

Registry is the status report (weekly review is `ls planner/registry/*.json`).
