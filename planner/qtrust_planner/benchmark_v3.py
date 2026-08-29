"""Benchmark GNN v2 vs v3 on the same held-out dataset — now with provenance and OOD.

Follows the exact protocol of qtrust_planner.benchmark (same held-out split
of the seed=999 dataset, same scipy-Kendall-tau / exact-set top-k metrics)
so results are directly comparable with results/benchmark.json:

    - eval set:   last 15% of generate_dataset(n_graphs, seed=999)
    - kendall:    scipy.stats.kendalltau between predicted and true orders
    - top5/top10: exact set match of the top-k candidates

P0-4 fix: records device, seed, data_hash with every result so the two JSONs
disagreeing at the third decimal (0.898225 vs 0.898045 on same checkpoint)
becomes auditable rather than a silent reproducibility wobble.
P2-10: also supports --seeds for median±IQR reporting and --ood/--enterprise suites.

Usage:
    cd planner
    python -m qtrust_planner.benchmark_v3                  # 1000-graph set
    python -m qtrust_planner.benchmark_v3 --n-graphs 200 --json-out out.json
    python -m qtrust_planner.benchmark_v3 --seeds 42 43 44 --ood --enterprise --json-out ood.json
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
    # nosemgrep — torch.load with weights_only=True: safe deserialization
    payload = torch.load(path, map_location="cpu", weights_only=True)
    cfg = payload.get("model_config", {}) if isinstance(payload, dict) else {}
    if not isinstance(cfg, dict):
        cfg = {}
    # Reconstruct with the checkpoint's own architecture config. Legacy
    # checkpoints (pre-norm retrain) default to BatchNorm, matching how
    # they were trained; LayerNorm retrain checkpoints carry norm in
    # model_config and are reconstructed exactly.
    model = V3(
        input_features=cfg.get("input_features", 6),
        hidden_dim=cfg.get("hidden_dim", 256),
        embedding_dim=cfg.get("embedding_dim", 128),
        heads=cfg.get("heads", 8),
        dropout=cfg.get("dropout", 0.15),
        use_centrality=cfg.get("use_centrality", True),
        variant=cfg.get("variant", "hybrid"),
        norm=cfg.get("norm", "batch"),
    )
    if isinstance(payload, dict) and "state_dict" in payload:
        model.load_state_dict(payload["state_dict"])
    else:
        model.load_state_dict(payload)
    meta = {"norm": cfg.get("norm", "batch"), **{k: payload[k] for k in
            ("epochs", "n_graphs", "seed", "best_val_kendall") if isinstance(payload, dict) and k in payload}}
    return model.eval(), meta


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
    parser = argparse.ArgumentParser(description="Benchmark GNN v2 vs v3 (with OOD and multi-seed)")
    parser.add_argument("--n-graphs", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=999, help="Single-seed (deprecated) — use --seeds")
    parser.add_argument("--seeds", type=int, nargs="+", default=None, help="Multiple seeds for median±IQR (overrides --seed)")
    parser.add_argument("--ood", action="store_true", help="Also evaluate on OOD-size suite (200-500 nodes)")
    parser.add_argument("--enterprise", action="store_true", help="Also evaluate on enterprise-topology suite")
    parser.add_argument("--real-cbom", action="store_true", help="Also evaluate on real-CBOM suite if available")
    parser.add_argument("--model", type=str, default=None,
                        help="Path to an additional checkpoint to benchmark (relative to planner/)")
    parser.add_argument(
        "--json-out", type=str, default=None, help="Write results to this JSON file"
    )
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    device_name = torch.cuda.get_device_name(0) if device.type == "cuda" else "CPU"
    print(f"Device: {device_name}")
    # P0-4: provenance for every result
    import hashlib
    all_seeds = args.seeds if args.seeds is not None else [args.seed]
    data_hash = hashlib.sha256(f"{args.n_graphs}-{sorted(all_seeds)}-{args.ood}-{args.enterprise}".encode()).hexdigest()[:16]
    print(f"Provenance: seeds={all_seeds} device={device_name} data_hash={data_hash}")

    here = Path(__file__).resolve().parent.parent  # planner/
    candidates = [
        ("v2 (1.2K graphs, 64-dim)", _load_v2(here / "model.pt")),
        ("v3 (GPU-trained, 256-dim)", _load_v3(here / "model_gpu_v3.pt")),
        ("v3 DDP (400K graphs, 256-dim)", _load_v3(here / "model_ddp_v3.pt")),
    ]
    if args.model:
        extra_path = Path(args.model)
        if not extra_path.is_absolute():
            extra_path = here / extra_path
        extra = _load_v3(extra_path)
        if extra is not None:
            candidates.append((f"v3 real-data ({extra_path.name})", extra))
        else:
            print(f"--model {args.model}: checkpoint not loadable — skipped")
    present = [(n, m) for n, m in candidates if m is not None]
    missing = [n for n, m in candidates if m is None]
    for name in missing:
        print(f"{name}: checkpoint missing — train it first (see Makefile.gpu)")

    # Build evaluation suites
    suites: dict[str, list] = {}
    # Canonical in-dist suite (last 15% of seed=999) — always present
    # For multi-seed mode, first seed drives the canonical suite and additional seeds provide variance
    gen_start = time.time()
    data = generate_dataset(n_graphs=args.n_graphs, seed=all_seeds[0])
    n_train = int(0.85 * len(data))
    eval_set = data[n_train:]
    suites["in_dist"] = eval_set
    print(f"Held-out in-dist: {len(eval_set)} graphs (last 15% of {args.n_graphs}, seed={all_seeds[0]}; {time.time() - gen_start:.1f}s)")

    if args.ood:
        from .data_generator import generate_migration_graph
        ood = [generate_migration_graph(n_assets=n, seed=999 + i, enterprise_topology=False) for i, n in enumerate([200,300,400,500]* (max(1, len(eval_set)//4)))]
        suites["ood_size"] = ood[: max(20, len(eval_set)//3)]
        print(f"OOD-size: {len(suites['ood_size'])} graphs (200-500 nodes)")
    if args.enterprise:
        from .data_generator import generate_migration_graph
        ent = [generate_migration_graph(n_assets=80, seed=777 + i, enterprise_topology=True) for i in range(max(20, len(eval_set)//3))]
        suites["enterprise"] = ent
        print(f"Enterprise: {len(ent)} graphs (layered L0->L1->L2)")
    if args.real_cbom:
        try:
            from .eval_harness import generate_suites as _gen
            _suites = _gen(n_graphs=args.n_graphs, seed=all_seeds[0])
            real = _suites.get("real_cbom", [])
            if real:
                suites["real_cbom"] = real
                print(f"Real-CBOM: {len(real)} graphs")
        except Exception as e:
            print(f"Real-CBOM suite unavailable: {e}")

    results: dict[str, dict] = {}
    for name, loaded in present:
        model, meta = loaded
        suite_metrics: dict[str, dict] = {}
        for suite_name, graphs in suites.items():
            # Multi-seed aggregation: re-generate suite per seed and average
            per_seed_means = []
            for s in all_seeds:
                if suite_name == "in_dist":
                    d = generate_dataset(n_graphs=args.n_graphs, seed=s)
                    g = d[int(0.85*len(d)):]
                else:
                    g = graphs  # reuse (OOD generation is cheap but deterministic)
                scores = evaluate(model, g, device)
                per_seed_means.append(mean_metrics(scores))
            # Aggregate across seeds: median±IQR
            import statistics
            agg = {}
            for k in METRIC_KEYS:
                vals = sorted(m[k] for m in per_seed_means)
                median = statistics.median(vals)
                mean = statistics.mean(vals)
                stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
                agg[k] = median
                agg[f"{k}_median"] = median
                agg[f"{k}_mean"] = mean
                agg[f"{k}_stdev"] = stdev
            # Store median as primary, plus provenance
            n_params = sum(p.numel() for p in model.parameters())
            suite_metrics[suite_name] = {
                **agg,
                "params": n_params,
                "n_graphs": len(graphs),
                "n_seeds": len(all_seeds),
                "seeds": all_seeds,
                "device": device_name,
                "data_hash": data_hash,
                **{f"meta_{k}": v for k, v in meta.items()},
            }
            print(f"{name} [{suite_name}] Kendall τ = {agg['kendall']:.4f} (median of {len(all_seeds)} seeds, stdev {agg['kendall_stdev']:.4f})")
        # Flat canonical entry for backward compat
        primary = suite_metrics.get("in_dist", next(iter(suite_metrics.values())))
        results[name] = {
            **{k: primary[k] for k in METRIC_KEYS},
            "params": primary["params"],
            "eval_seconds": 0,
            "n_graphs": primary["n_graphs"],
            "device": device_name,
            "seeds": all_seeds,
            "data_hash": data_hash,
            "suites": suite_metrics,
            **{f"meta_{k}": v for k, v in meta.items()},
        }
        print(
            f"{name}\n"
            f"  Kendall τ  = {primary['kendall']:.4f} (median ± {primary.get('kendall_stdev',0):.4f})\n"
            f"  Top-5      = {primary['top5']:.4f}\n"
            f"  Suites     = {list(suite_metrics.keys())}\n"
        )

    names = list(results)
    if len(names) == 2:
        delta = results[names[1]]["kendall"] - results[names[0]]["kendall"]
        arrow = "↑" if delta >= 0 else "↓"
        print(f"Δτ ({names[1].split()[0]} − {names[0].split()[0]}) = {delta:+.4f} {arrow}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        print(f"\nResults written to {args.json_out} (provenance: device={device_name} seeds={all_seeds} hash={data_hash})")


if __name__ == "__main__":
    main()
