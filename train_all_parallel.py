#!/usr/bin/env python3
"""Parallel multi-model trainer — trains the non-GNN models on separate GPUs simultaneously.

Sequential 1-GPU order: GNN (4h) -> RL (2h) -> side-channel (5m) -> anomaly (10m) -> quantum (5m).
This script runs RL / inspector suite / quantum concurrently on different GPUs.

GPU assignment is controlled by env vars (defaults suit a node whose busy GPUs are avoided):

    QTRUST_GPU_RL       (default 5)  — RL migration agent
    QTRUST_GPU_INSPECTOR (default 6) — side-channel -> anomaly VAE (sequential)
    QTRUST_GPU_QUANTUM  (default 6)  — Shor simulation N=15..77

Usage:
    python3 train_all_parallel.py            # full training
    python3 train_all_parallel.py --quick    # smoke pass (minutes)
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

RL_GPU = os.environ.get("QTRUST_GPU_RL", "5")
INSPECTOR_GPU = os.environ.get("QTRUST_GPU_INSPECTOR", "6")
QUANTUM_GPU = os.environ.get("QTRUST_GPU_QUANTUM", "6")


def _launch(gpu: str, description: str, code: str) -> subprocess.Popen:
    env = {**os.environ, "CUDA_VISIBLE_DEVICES": gpu}
    print(f"[GPU {gpu}] {description}")
    return subprocess.Popen(
        [sys.executable, "-c", code],
        env=env,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="tiny smoke pass")
    parser.add_argument("--rl-episodes", type=int, default=10_000)
    args = parser.parse_args()

    if args.quick:
        args.rl_episodes = 50

    start = time.time()
    processes: list[tuple[str, str, subprocess.Popen]] = []

    rl_code = f"""
import sys
sys.path.insert(0, "planner")
from qtrust_planner.rl_agent import train_agent
train_agent(n_episodes={args.rl_episodes}, save_path="planner/rl_agent.pt")
print("RL agent complete!")
"""
    processes.append((
        f"RL agent ({args.rl_episodes:,} episodes)",
        RL_GPU,
        _launch(RL_GPU, f"RL agent ({args.rl_episodes:,} episodes)", rl_code),
    ))

    n_clean = n_leak = 100 if args.quick else 10_000
    sc_epochs = 3 if args.quick else 100
    ad_n = 60 if args.quick else 5_000
    ad_epochs = 5 if args.quick else 200
    shor_ns = [15] if args.quick else [15, 21, 35, 77]

    inspector_code = f"""
import sys
sys.path.insert(0, "inspector"); sys.path.insert(0, "planner")
from qtrust_inspector.side_channel import SideChannelAnalyzer
a = SideChannelAnalyzer(device="cuda:0")
a.train_detector(n_clean={n_clean}, n_leaking={n_leak}, epochs={sc_epochs},
                 save_path="inspector/side_channel_model.pt")
print("Side-channel complete!")

from qtrust_inspector.anomaly_detector import CBOMAnomalyDetector
d = CBOMAnomalyDetector(device="cuda:0")
cboms = d.generate_synthetic_training_data(n_cboms={ad_n})
d.train(cboms, epochs={ad_epochs}, save_path="inspector/anomaly_model.pt")
print("Anomaly detector complete!")

from qtrust_planner.quantum_estimator import QuantumThreatEstimator
est = QuantumThreatEstimator()
for N in {shor_ns!r}:
    r = est.factor(N, use_gpu=True)
    print(f"N={{N}}: factors={{r.factors}} time={{r.elapsed_seconds:.1f}}s method={{r.method}}")
est.save_report("notebooks/quantum_threat_report.json")
print("Quantum simulation complete!")
"""
    label = "Inspector suite (side-channel -> anomaly -> quantum)"
    processes.append((label, INSPECTOR_GPU, _launch(INSPECTOR_GPU, label, inspector_code)))

    print(f"\n{'=' * 60}")
    print(f"Launched {len(processes)} parallel jobs (GPUs {RL_GPU}/{INSPECTOR_GPU})")
    print(f"{'=' * 60}\n")

    failures = 0
    for name, gpu, proc in processes:
        out, _ = proc.communicate()
        status = "SUCCESS" if proc.returncode == 0 else "FAILED"
        if proc.returncode != 0:
            failures += 1
        tail = "\n".join(out.splitlines()[-8:])
        print(f"[GPU {gpu}] {name}: {status}\n{tail}\n")

    elapsed = time.time() - start
    print(f"{'=' * 60}")
    print(f"Parallel training complete in {elapsed:.0f}s ({elapsed / 60:.1f} min)")
    print(f"{'=' * 60}")

    artifacts = [
        ("RL Agent", ROOT / "planner/rl_agent.pt"),
        ("Side-Channel", ROOT / "inspector/side_channel_model.pt"),
        ("Anomaly VAE", ROOT / "inspector/anomaly_model.pt"),
        ("Quantum Report", ROOT / "notebooks/quantum_threat_report.json"),
    ]
    missing = 0
    for name, path in artifacts:
        if path.exists():
            print(f"  OK   {name}: {path} ({path.stat().st_size / 1024:.0f} KB)")
        else:
            missing += 1
            print(f"  MISS {name}: {path}")

    sys.exit(1 if (failures or missing) else 0)


if __name__ == "__main__":
    main()
