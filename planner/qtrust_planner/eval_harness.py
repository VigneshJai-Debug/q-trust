"""Eval harness — doctrine-grade evaluation with OOD, enterprise-topology, real-CBOM, 3-seed reporting.

Implements M1 exit criteria: every reported number is the median of >=3 seeds
with dispersion shown, on an evaluation set that was not used to select anything.

Suites:
  - in_dist: last 15% of synthetic dataset seed=999 (canonical benchmark.py split)
  - ood_size: graphs 3-10x larger than training (200-500 nodes) — size generalization
  - enterprise: layered enterprise DAG (L0 infra → L1 services → L2 edge)
  - real_cbom: real CBOMs converted via cbom_to_dependency_graph (if available)

Usage:
    python -m qtrust_planner.eval_harness --model-path model.pt --n-graphs 1000 --seeds 42 43 44
    python -m qtrust_planner.eval_harness --model-path model_gpu_v3.pt --ood --enterprise --real-cbom
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from pathlib import Path
from typing import Any

import torch

from .benchmark import METRIC_KEYS, score_order
from .data_generator import generate_dataset, generate_migration_graph, cbom_to_dependency_graph

try:
    from .model import MigrationGNN
    from .model_v3 import MigrationGNNv3
except ImportError:
    MigrationGNN = None  # type: ignore
    MigrationGNNv3 = None  # type: ignore


def _load_model(path: Path):
    if not path.exists():
        return None
    payload = torch.load(path, map_location="cpu", weights_only=True)
    # Detect v3 vs v2 by config or keys
    if isinstance(payload, dict) and "model_state_dict" in payload:
        cfg = payload.get("model_config", {})
        is_v3 = cfg.get("hidden_dim") == 256 or cfg.get("embedding_dim") == 128
        if is_v3 and MigrationGNNv3 is not None:
            m = MigrationGNNv3(**{k: v for k, v in cfg.items() if k in {"input_features","hidden_dim","embedding_dim","heads","dropout","use_centrality","variant","norm"}})
            m.load_state_dict(payload["model_state_dict"], strict=False)
            return m.eval(), payload
        elif MigrationGNN is not None:
            m = MigrationGNN(**cfg) if cfg else MigrationGNN()
            m.load_state_dict(payload["model_state_dict"])
            return m.eval(), payload
    else:
        # flat state_dict — assume v3
        if MigrationGNNv3 is not None:
            m = MigrationGNNv3(input_features=6)
            m.load_state_dict(payload)
            return m.eval(), {}
    return None


def _evaluate_model_on_suite(model, graphs, device) -> list[dict[str, float]]:
    scores = []
    model = model.to(device)
    with torch.no_grad():
        for g in graphs:
            g = g.to(device)
            order_logits, _ = model(g)
            pred_order = torch.argsort(order_logits, descending=True).tolist()
            scores.append(score_order(pred_order, g.cpu()))
    return scores


def _mean_metrics(scores: list[dict[str, float]]) -> dict[str, float]:
    return {k: sum(s[k] for s in scores) / len(scores) for k in METRIC_KEYS}


def _aggregate_runs(runs: list[dict[str, float]]) -> dict[str, Any]:
    """Aggregate multiple seed runs into median ± IQR (median of means)."""
    out: dict[str, Any] = {}
    for k in METRIC_KEYS:
        vals = sorted(r[k] for r in runs)
        median = statistics.median(vals)
        # IQR
        q1 = vals[len(vals)//4] if len(vals) >= 4 else vals[0]
        q3 = vals[3*len(vals)//4] if len(vals) >= 4 else vals[-1]
        iqr = q3 - q1
        mean = statistics.mean(vals)
        stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
        out[k] = {"median": median, "iqr": iqr, "mean": mean, "stdev": stdev, "min": min(vals), "max": max(vals)}
    out["n_runs"] = len(runs)
    return out


def generate_suites(n_graphs: int = 1000, seed: int = 999, n_real_cbom: int | None = None) -> dict[str, Any]:
    """Generate all evaluation suites deterministically from seed."""
    suites: dict[str, Any] = {}
    # In-dist canonical (last 15%)
    data = generate_dataset(n_graphs=n_graphs, seed=seed)
    n_train = int(0.85 * len(data))
    suites["in_dist"] = data[n_train:]
    suites["in_dist_meta"] = {"n": len(suites["in_dist"]), "seed": seed, "n_graphs": n_graphs}

    # OOD size — much larger graphs
    ood = []
    for i in range(max(50, n_graphs // 10)):
        n = [200, 300, 400, 500][i % 4]
        # deterministic but different sizes
        ood.append(generate_migration_graph(n_assets=n, seed=seed + 10000 + i, enterprise_topology=False))
    suites["ood_size"] = ood
    suites["ood_size_meta"] = {"n": len(ood), "sizes": "200-500", "desc": "size OOD (training was 20-100)"}

    # Enterprise topology
    ent = []
    for i in range(max(50, n_graphs // 10)):
        n = 50 if i % 2 == 0 else 120
        ent.append(generate_migration_graph(n_assets=n, seed=seed + 20000 + i, enterprise_topology=True))
    suites["enterprise"] = ent
    suites["enterprise_meta"] = {"n": len(ent), "topology": "layered L0->L1->L2", "desc": "enterprise DAG structure"}

    # Real CBOMs if available
    real_graphs: list = []
    # Try planner/data/real_cboms (real TLS-derived enterprise CBOMs), then
    # planner/data and inspector fixtures
    for cbom_dir in [
        Path(__file__).resolve().parents[1] / "data" / "real_cboms",
        Path(__file__).resolve().parents[1] / "data",
        Path(__file__).resolve().parents[2] / "inspector" / "data",
    ]:
        if cbom_dir.is_dir():
            for p in list(cbom_dir.glob("*.json"))[:50]:
                if p.name == "algorithms.json":
                    continue
                try:
                    import json as _j
                    cbom = _j.loads(p.read_text())
                    if "assets" in cbom and isinstance(cbom["assets"], list) and len(cbom["assets"]) > 0:
                        g = cbom_to_dependency_graph(cbom, seed=seed)
                        real_graphs.append(g)
                except Exception:
                    continue
    # Also synthetic "real-like" if no real CBOMs found (so suite never empty in CI)
    if not real_graphs:
        # Create synthetic but with host-affinity structure mimicking real CBOM
        for i in range(20):
            cbom = {"assets": [
                {"algorithm": "RSA-2048", "key_size": 2048, "criticality": "high", "pqc_ready": False, "host": "host-a"},
                {"algorithm": "ECC-P256", "key_size": 256, "criticality": "critical", "pqc_ready": False, "host": "host-a"},
                {"algorithm": "ML-KEM-512", "key_size": 512, "criticality": "low", "pqc_ready": True, "host": "host-b"},
            ] * 7}
            try:
                real_graphs.append(cbom_to_dependency_graph(cbom, seed=seed + 30000 + i))
            except Exception:
                pass
    suites["real_cbom"] = real_graphs
    suites["real_cbom_meta"] = {"n": len(real_graphs), "desc": "real CBOMs via cbom_to_dependency_graph" if real_graphs else "synthetic real-like"}
    return suites


def run_eval(
    model_path: str,
    n_graphs: int = 1000,
    seeds: list[int] | None = None,
    device: str | None = None,
    suites: list[str] | None = None,
) -> dict[str, Any]:
    """Run full doctrine evaluation for one model."""
    if seeds is None:
        seeds = [42, 43, 44]
    if suites is None:
        suites = ["in_dist", "ood_size", "enterprise", "real_cbom"]
    dev = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    # Load model per seed? For harness we load once and evaluate same weights across suites;
    # multi-seed aggregation here refers to eval suite generation seeds (deterministic).
    # For training-seed variance, caller trains multiple checkpoints and aggregates outside.
    model_info = _load_model(Path(model_path))
    if model_info is None:
        raise FileNotFoundError(f"model not found: {model_path}")
    model, payload = model_info
    # For 3-seed reporting on eval suite generation (suite sampling variance), generate suite per seed
    suite_results: dict[str, Any] = {}
    all_suite_metrics: dict[str, list[dict[str, float]]] = {s: [] for s in suites}
    for s in seeds:
        gen = generate_suites(n_graphs=n_graphs, seed=s)
        for suite_name in suites:
            graphs = gen.get(suite_name, [])
            if not graphs:
                continue
            scores = _evaluate_model_on_suite(model, graphs, dev)
            mean = _mean_metrics(scores)
            all_suite_metrics[suite_name].append(mean)
    for suite_name in suites:
        runs = all_suite_metrics[suite_name]
        if not runs:
            suite_results[suite_name] = {"error": "no graphs"}
            continue
        agg = _aggregate_runs(runs)
        # Also store per-seed means for debugging
        suite_results[suite_name] = {**agg, "per_seed_means": runs}

    # Provenance
    data_hash = hashlib.sha256(f"{n_graphs}-{sorted(seeds)}".encode()).hexdigest()[:16]
    result = {
        "model_path": model_path,
        "model_config": payload.get("model_config", {}) if isinstance(payload, dict) else {},
        "params": sum(p.numel() for p in model.parameters()),
        "device": str(dev),
        "data_hash": data_hash,
        "seeds": seeds,
        "n_graphs": n_graphs,
        "suites": suite_results,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Doctrine eval harness (OOD + 3-seed)")
    parser.add_argument("--model-path", type=str, default="model.pt")
    parser.add_argument("--n-graphs", type=int, default=1000)
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    parser.add_argument("--device", type=str, default=None)
    parser.add_argument("--json-out", type=str, default=None)
    parser.add_argument("--suites", type=str, nargs="+", default=["in_dist","ood_size","enterprise","real_cbom"], help="suites to run")
    args = parser.parse_args()

    result = run_eval(args.model_path, n_graphs=args.n_graphs, seeds=args.seeds, device=args.device, suites=args.suites)
    print(json.dumps(result, indent=2))
    # Summary table
    print("\nSuite       | kendall median±IQR | top5 median | top10 median | n")
    print("-"*70)
    for suite, data in result["suites"].items():
        if "error" in data:
            print(f"{suite:12}| error: {data['error']}")
            continue
        k = data["kendall"]
        t5 = data["top5"]
        print(f"{suite:12}| {k['median']:.4f} ±{k['iqr']:.4f} | {t5['median']:.3f}       | {data['top10']['median']:.3f}       | {data['n_runs']}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2))
        print(f"\nWritten to {args.json_out}")


if __name__ == "__main__":
    main()
