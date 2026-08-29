#!/usr/bin/env python3
"""Launch the GNN v3 hyperparameter sweep across free A100 GPUs.

Each config trains with explicit model-path output (never overwrites the
canonical checkpoint), LayerNorm, warmup-cosine, per-epoch best selection.

Usage:
    python scripts/sweep_gnn.py            # launch all configs in background
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLANNER = ROOT / "planner"
OUT = Path("/tmp/gnn_sweep")
OUT.mkdir(parents=True, exist_ok=True)

# (gpu, label, n_graphs, epochs, lr, wd, seed)
CONFIGS = [
    ("0", "A_baseline_scaled", 200_000, 250, 1.0e-3, 1.0e-4, 42),
    ("1", "B_lower_lr", 150_000, 250, 5.0e-4, 5.0e-5, 42),
    ("2", "C_more_data", 250_000, 200, 1.0e-3, 1.0e-4, 42),
    ("5", "D_long_train", 150_000, 300, 8.0e-4, 1.0e-4, 42),
]


def launch(gpu: str, label: str, n_graphs: int, epochs: int, lr: float, wd: float, seed: int) -> None:
    # Use the argument-based wrapper (scripts/run_gnn_train.py) instead of an
    # inline `python -c` blob: the inline form broke on shell quoting and let
    # accidental re-launches pile up as duplicate generations writing the same
    # logs/checkpoints. QTRUST_DISABLE_COMPILE=1 avoids the torch.compile
    # recompilation churn on dynamic PyG shapes (10x slower when enabled).
    model_path = OUT / f"model_{label}.pt"
    log_path = OUT / f"train_{label}.log"
    cmd = [
        "bash", "-c",
        f"cd {ROOT} && CUDA_VISIBLE_DEVICES={gpu} QTRUST_DISABLE_COMPILE=1 "
        f"python scripts/run_gnn_train.py {n_graphs} {epochs} {lr} {wd} {seed} {model_path}",
    ]
    with open(log_path, "w") as logf:
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)
    print(f"[launch] GPU{gpu} {label}: {n_graphs} graphs x {epochs} ep lr={lr} wd={wd} -> pid {proc.pid} log {log_path}")


if __name__ == "__main__":
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for cfg in CONFIGS:
        if only and cfg[1] != only:
            continue
        launch(*cfg)
    print("All launches issued. Monitor: tail -f /tmp/gnn_sweep/train_*.log")
