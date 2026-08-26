"""Benchmark GNN v2 vs v3 on the same held-out dataset.

Follows the exact protocol of qtrust_planner.benchmark (same held-out split
of the seed=999 dataset, same scipy-Kendall-tau / exact-set top-k metrics)
so results are directly comparable with results/benchmark.json:

    - eval set:   last 15% of generate_dataset(n_graphs, seed=999)
    - kendall:    scipy.stats.kendalltau between predicted and true orders
    - top5/top10: exact set match of the top-k candidates

Usage:
    cd planner
    python -m qtrust_planner.benchmark_v3                  # 1000-graph set
    python -m qtrust_planner.benchmark_v3 --n-graphs 200 --json-out out.json
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import torch

if __package__ in (None, ""):
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from benchmark import METRIC_KEYS, score_order
    from data_generator import generate_dataset
    from model import MigrationGNN as V2
    from model_v3 import MigrationGNNv3 as V3
else:
    from .benchmark import METRIC_KEYS, score_order
    from .data_generator import generate_dataset
    from .model import MigrationGNN as V2
    from .model_v3 import MigrationGNNv3 as V3


def _load_v2(path: Path):
    if not path.exists():
        return None
    # nosemgrep — torch.load with weights_only=True: safe deserialization
    payload = torch.load(path, map_location="cpu", weights_only=True)
    if isinstance(payload, dict) and "model_state_dict" in payload:
        cfg = payload.get("model_config", {})
        meta = {"epochs": payload.get("epochs"), "n_graphs": payload.get("n_graphs")}
        model = V2(**cfg)
        model.load_state_dict(payload["model_state_dict"])
    else:
        meta = {}
        model = V2()
        model.load_state_dict(payload)
    return model.eval(), meta


def _load_v3(path: Path):
    if not path.exists():
        return None
    model = V3(
        input_features=6,
        hidden_dim=256,
        embedding_dim=128,
        heads=8,
        dropout=0.15,
        use_centrality=True,
        variant="hybrid",
    )
    # nosemgrep — torch.load with weights_only=True: safe deserialization
    payload = torch.load(path, map_location="cpu", weights_only=True)
    if isinstance(payload, dict) and "state_dict" in payload:
        model.load_state_dict(payload["state_dict"])
    else:
        model.load_state_dict(payload)
    return model.eval(), {}


def evaluate(model, graphs, device) -> list[dict[str, float]]:
    """Score each graph under the canonical protocol."""
    model = model.to(device)
    scores = []
    with torch.no_grad():
        for g in graphs:
            g = g.to(device)
            order_logits, _ = model(g)
            pred_order = torch.argsort(order_logits, descending=True).tolist()
            scores.append(score_order(pred_order, g.cpu()))
    return scores


def mean_metrics(scores: list[dict[str, float]]) -> dict[str, float]:
    return {k: sum(s[k] for s in scores) / len(scores) for k in METRIC_KEYS}


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark GNN v2 vs v3")
    parser.add_argument("--n-graphs", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=999)
    parser.add_argument(
        "--json-out", type=str, default=None, help="Write results to this JSON file"
    )
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {torch.cuda.get_device_name(0) if device.type == 'cuda' else 'CPU'}")

    here = Path(__file__).resolve().parent.parent  # planner/
    candidates = [
        ("v2 (1.2K graphs, 64-dim)", _load_v2(here / "model.pt")),
        ("v3 (GPU-trained, 256-dim)", _load_v3(here / "model_gpu_v3.pt")),
        ("v3 DDP (400K graphs, 256-dim)", _load_v3(here / "model_ddp_v3.pt")),
    ]
    present = [(n, m) for n, m in candidates if m is not None]
    missing = [n for n, m in candidates if m is None]
    for name in missing:
        print(f"{name}: checkpoint missing — train it first (see Makefile.gpu)")

    # Shared held-out set: identical split logic to benchmark.py.
    gen_start = time.time()
    data = generate_dataset(n_graphs=args.n_graphs, seed=args.seed)
    n_train = int(0.85 * len(data))
    eval_set = data[n_train:]
    print(
        f"Held-out validation set: {len(eval_set)} graphs "
        f"(last 15% of {args.n_graphs}, seed={args.seed}; "
        f"generated in {time.time() - gen_start:.1f}s)\n"
    )

    results: dict[str, dict] = {}
    for name, loaded in present:
        model, meta = loaded
        start = time.time()
        scores = evaluate(model, eval_set, device)
        elapsed = time.time() - start
        mean = mean_metrics(scores)
        n_params = sum(p.numel() for p in model.parameters())
        results[name] = {
            **mean,
            "params": n_params,
            "eval_seconds": round(elapsed, 2),
            "n_graphs": len(eval_set),
            **{f"meta_{k}": v for k, v in meta.items()},
        }
        print(
            f"{name}\n"
            f"  Kendall τ  = {mean['kendall']:.4f}\n"
            f"  Top-5 hit  = {mean['top5']:.4f} (exact set)\n"
            f"  Top-10 hit = {mean['top10']:.4f} (exact set)\n"
            f"  Exact rank = {mean['exact_rank']:.4f}\n"
            f"  Node rank  = {mean['node_rank']:.4f}\n"
            f"  params     = {n_params:,} | eval {elapsed:.1f}s\n"
        )

    names = list(results)
    if len(names) == 2:
        delta = results[names[1]]["kendall"] - results[names[0]]["kendall"]
        arrow = "↑" if delta >= 0 else "↓"
        print(f"Δτ ({names[1].split()[0]} − {names[0].split()[0]}) = {delta:+.4f} {arrow}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        print(f"\nResults written to {args.json_out}")


if __name__ == "__main__":
    main()
