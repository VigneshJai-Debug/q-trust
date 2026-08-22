"""Benchmark the MigrationGNN against baselines with honest, multi-seed statistics.

Methods compared on held-out synthetic migration graphs:
  - random:      random permutation (chance level)
  - heuristic:   the rule-based priority formula used to create the labels
                 (upper bound for the synthetic task; see data_generator.py)
  - gnn-mse:     GNN trained with MSE priority regression (legacy)
  - gnn-listmle: GNN trained with ListMLE ranking loss

Metrics (mean over validation graphs, then mean +/- std across seeds):
  - exact_rank: full order matches exactly
  - top5/top10: top-k candidate set matches
  - kendall:    Kendall tau between predicted and true order
  - node_rank:  per-node rank agreement

Usage:
    python -m qtrust_planner.benchmark
    python -m qtrust_planner.benchmark --seeds 42 43 44 --epochs 40
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from pathlib import Path

import numpy as np
import torch
from scipy.stats import kendalltau

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from data_generator import _is_pqc_algorithm, generate_dataset
    from model import MigrationGNN
    from train import evaluate_order, train
else:
    from .data_generator import _is_pqc_algorithm, generate_dataset
    from .model import MigrationGNN
    from .train import evaluate_order, train

BENCH_DIR = Path(__file__).resolve().parents[1] / "results"
METRIC_KEYS = ["exact_rank", "top5", "top10", "kendall", "node_rank"]


def heuristic_order(graph) -> list[int]:
    """Rule-based baseline: replicate the label priority formula from
    data_generator.py using raw asset records and graph in-degree."""
    records = graph.asset_records  # (algorithm, key_size, vendor_pqc_ready, criticality)
    in_degree = np.zeros(len(records), dtype=np.int32)
    for dst in graph.edge_index[1].tolist():
        in_degree[dst] += 1
    days_norm = float(graph.x[0, 4].item()) if graph.x.size(1) > 4 else 0.0
    deadline_pressure = 2.0 if 0 < days_norm * 730 < 180 else (1.0 if days_norm > 0 else 0.0)
    priorities = np.zeros(len(records), dtype=np.float32)
    for i, (alg, key_size, vendor_pqc_ready, criticality) in enumerate(records):
        priority = criticality * 2.0
        if vendor_pqc_ready:
            priority += 1.5
        if not _is_pqc_algorithm(alg):
            priority += np.log1p(key_size) / 4.0
        else:
            priority -= 1.0
        priority += deadline_pressure * criticality / 5.0
        priority -= in_degree[i] * 0.3
        priorities[i] = priority
    return list(np.argsort(-priorities))


def random_order(graph) -> list[int]:
    rng = np.random.default_rng(0)
    order = list(range(graph.num_nodes))
    rng.shuffle(order)
    return order


def score_order(pred_order: list[int], graph) -> dict[str, float]:
    true_order = torch.argsort(graph.y_order).tolist()
    n = len(pred_order)
    kt = kendalltau(pred_order, true_order).statistic if n > 1 else 1.0
    return {
        "exact_rank": float(pred_order == true_order),
        "top5": float(set(pred_order[:5]) == set(true_order[:5])),
        "top10": float(set(pred_order[:10]) == set(true_order[:10])),
        "kendall": float(kt),
        "node_rank": float(
            sum(1 for i, node in enumerate(pred_order) if i == true_order.index(node)) / n
        ),
    }


def mean_metrics(scores: list[dict[str, float]]) -> dict[str, float]:
    return {k: statistics.mean(s[k] for s in scores) for k in METRIC_KEYS}


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark MigrationGNN vs baselines.")
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44], help="Train seeds.")
    parser.add_argument("--epochs", type=int, default=40, help="Epochs per training run.")
    parser.add_argument("--n-graphs", type=int, default=1000, help="Graphs per training run.")
    parser.add_argument("--device", type=str, default="auto",
                        help="auto | cuda | cpu (default: auto)")
    parser.add_argument("--losses", type=str, nargs="+", default=["mse", "listmle"],
                        choices=["mse", "listmle"],
                        help="Losses to benchmark (default: both).")
    parser.add_argument("--out-dir", type=str, default=str(BENCH_DIR),
                        help="Directory for benchmark.json and trained models.")
    args = parser.parse_args()

    device = torch.device(
        "cuda" if args.device == "auto" and torch.cuda.is_available()
        else "cpu" if args.device == "auto"
        else args.device
    )
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Shared held-out evaluation set (independent of any training seed).
    print("Generating evaluation set...")
    eval_data = generate_dataset(n_graphs=args.n_graphs, seed=999)
    n_train = int(0.85 * len(eval_data))
    eval_set = eval_data[n_train:]

    results: dict[str, dict[str, dict[str, float]]] = {}
    run_metrics: dict[str, list[dict[str, float]]] = {
        "random": [], "heuristic": [], "gnn-mse": [], "gnn-listmle": []
    }

    for name, order_fn in (("random", random_order), ("heuristic", heuristic_order)):
        scores = [score_order(order_fn(g), g) for g in eval_set]
        run_metrics[name].append(mean_metrics(scores))

    for seed in args.seeds:
        for loss in args.losses:
            name = f"gnn-{loss}"
            model_path = out_dir / f"model_{loss}_seed{seed}.pt"
            print(f"\n=== Training {name} (seed {seed}) ===")
            train(
                n_graphs=args.n_graphs,
                epochs=args.epochs,
                batch_size=32,
                model_path=str(model_path),
                seed=seed,
                loss=loss,
            )
            ckpt = torch.load(model_path, map_location="cpu", weights_only=True)
            model = MigrationGNN(**ckpt["model_config"])
            model.load_state_dict(ckpt["model_state_dict"])
            model.to(device)
            scores = []
            for g in eval_set:
                g = g.to(device)
                with torch.no_grad():
                    order_logits, _ = model(g)
                pred_order = torch.argsort(order_logits, descending=True).tolist()
                scores.append(score_order(pred_order, g.cpu()))
            run_metrics[name].append(mean_metrics(scores))

    for name, runs in run_metrics.items():
        results[name] = {
            "mean": mean_metrics(runs),
            "std": {k: statistics.stdev([r[k] for r in runs]) if len(runs) > 1 else 0.0
                    for k in METRIC_KEYS},
            "n_runs": len(runs),
        }

    out_path = out_dir / "benchmark.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nSaved results to {out_path}\n")

    header = f"{'method':<14}" + "".join(f"{k:>10}" for k in METRIC_KEYS)
    print(header)
    print("-" * len(header))
    for name, r in results.items():
        row = f"{name:<14}" + "".join(f"{r['mean'][k]:>9.3f}±{r['std'][k]:.3f}" for k in METRIC_KEYS)
        print(row)


if __name__ == "__main__":
    main()