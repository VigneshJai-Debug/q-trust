#!/usr/bin/env python3
"""Leave-one-out real-CBOM evaluation — the honest out-of-sample protocol.

Why this exists (audit finding, 2026-08-29):

The previous flagship real-CBOM number (τ-b 0.807) was **in-sample**: the
model was fine-tuned on all 39 real CBOMs and benchmarked on the same 39.
Worse, every scanned host appeared in two different CBOMs, so even a
train/eval split over CBOMs leaked hosts across folds. This harness
implements the protocol a senior ML reviewer would demand:

  1. **Host-disjoint corpus** — every host lives in exactly one CBOM
     (built by ``scripts/build_real_cboms.py``), so no host is shared
     between the train and eval folds.
  2. **Leave-one-out** — for each real CBOM, fine-tune a fresh model on
     the other N-1 real CBOMs (+ a synthetic mix to retain doctrine
     fidelity) and evaluate on the *held-out* CBOM only. Every reported
     number is a genuinely unseen-estate generalization figure.
  3. **Honest baselines on the same folds** — the priority heuristic
     ("ceiling") and a random baseline are scored on the identical
     held-out CBOMs, so the model's τ-b is directly comparable.

Result JSON schema (written to ``planner/results/real_cbom_loo.json``):

    {
      "protocol": "leave-one-out (host-disjoint CBOMs)",
      "n_cboms": 37,
      "n_hosts": 277,
      "fold_metrics": { "<cbom>": {kendall/top5/top10/exact_rank/...} },
      "aggregate": {
         "model":  {mean/std/median of each metric across folds},
         "heuristic": {...}, "random": {...}
      },
      "model_vs_heuristic": 0.0123,   # mean Δτ-b (positive = model wins)
      "config": {init, epochs, n_synthetic, batch_size, lr, seed},
      "device": "NVIDIA A100-SXM4-80GB",
      "generated_at": "..."
    }

GPU-parallel execution (8×A100 class):

    # shard 1..K — each trains a fold slice on its own CUDA device
    CUDA_VISIBLE_DEVICES=0 python scripts/eval_real_cbom_loo.py --fold-start 0  --fold-end 10
    CUDA_VISIBLE_DEVICES=1 python scripts/eval_real_cbom_loo.py --fold-start 10 --fold-end 20
    CUDA_VISIBLE_DEVICES=2 python scripts/eval_real_cbom_loo.py --fold-start 20 --fold-end 30
    CUDA_VISIBLE_DEVICES=3 python scripts/eval_real_cbom_loo.py --fold-start 30 --fold-end 40

    # merge the shard artifacts into the canonical report
    python scripts/eval_real_cbom_loo.py --merge-shards

Fold seeds are derived from the full graph list BEFORE slicing, so every
shard reproduces exactly the seeds a monolithic run would use — the merged
report is bit-identical to a single-process run with the same config.

Usage:
    python scripts/eval_real_cbom_loo.py                     # defaults below
    python scripts/eval_real_cbom_loo.py --epochs 8 --n-synthetic 2000 --seed 42
    python scripts/eval_real_cbom_loo.py --quick             # 3 folds (smoke)
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "planner"))

from qtrust_planner._device import resolve_device  # noqa: E402
from qtrust_planner.benchmark import heuristic_order, random_order, score_order  # noqa: E402
from qtrust_planner.data_generator import cbom_to_dependency_graph  # noqa: E402
from qtrust_planner.train_gpu import train_gpu  # noqa: E402

CBOM_DIR = REPO_ROOT / "planner" / "data" / "real_cboms"
RESULT_PATH = REPO_ROOT / "planner" / "results" / "real_cbom_loo.json"
BASE_MODEL = REPO_ROOT / "planner" / "model_gpu_v3.pt"


def load_real_graphs(cbom_dir: Path, seed: int):
    """Load all real CBOMs as PyG graphs (host-disjoint by construction)."""
    graphs = []
    for p in sorted(cbom_dir.glob("*.json")):
        import json as _j
        cbom = _j.loads(p.read_text())
        graphs.append((p.name, cbom_to_dependency_graph(cbom, seed=seed)))
    return graphs


def eval_graph(model, g, device):
    import torch
    g = g.to(device)
    with torch.no_grad():
        order_logits, _ = model(g)
    pred_order = torch.argsort(order_logits, descending=True).tolist()
    return score_order(pred_order, g.cpu())


def run_loo(
    cbom_dir: Path = CBOM_DIR,
    epochs: int = 6,
    n_synthetic: int = 2000,
    batch_size: int = 64,
    learning_rate: float = 5e-4,
    seed: int = 42,
    device_name: str | None = None,
    quick: bool = False,
    out_path: Path = RESULT_PATH,
    fold_start: int = 0,
    fold_end: int | None = None,
) -> dict:
    """Run leave-one-out real-CBOM evaluation. Returns the full report dict.

    ``fold_start`` / ``fold_end`` (exclusive) select a contiguous fold slice
    so the LOO can be sharded across GPUs; each shard writes a partial
    artifact that ``merge_shards`` combines into the canonical report.
    """
    import torch

    # Probe-based resolution: a reported-but-unusable CUDA device (contended
    # or absent driver) must not silently mislabel results as GPU-measured.
    device = resolve_device(device_name)
    all_graphs = load_real_graphs(cbom_dir, seed=seed)
    # Deterministic per-fold seeds over the FULL corpus BEFORE slicing, so
    # every shard uses exactly the seeds a monolithic run would use.
    rng = __import__("random").Random(seed)
    all_seeds = [rng.randint(0, 1_000_000) for _ in all_graphs]
    if quick:
        all_graphs, all_seeds = all_graphs[:3], all_seeds[:3]
    if fold_end is None:
        fold_end = len(all_graphs)
    graphs = all_graphs[fold_start:fold_end]
    fold_seeds = all_seeds[fold_start:fold_end]
    print(f"Device: {torch.cuda.get_device_name(0) if device.type == 'cuda' else 'cpu'}")
    print(f"LOO over {len(graphs)} real CBOMs (folds {fold_start}..{fold_end - 1}, "
          f"corpus {len(all_graphs)}) (host-disjoint corpus)")

    fold_metrics: dict[str, dict] = {}
    model_scores_all: list[dict] = []
    heur_scores_all: list[dict] = []
    rand_scores_all: list[dict] = []
    t0 = time.time()

    for fold, (name, held_out) in enumerate(graphs):
        gi = fold_start + fold  # global fold index (stable across shards)
        train_real = [g for n, g in all_graphs if n != name]
        ft_path = REPO_ROOT / "planner" / f"_loo_fold{gi}.pt"
        train_gpu(
            n_graphs=n_synthetic,
            epochs=epochs,
            batch_size=batch_size,
            learning_rate=learning_rate,
            seed=fold_seeds[fold],
            norm="layer",
            init_path=str(BASE_MODEL),
            model_path=str(ft_path),
            device_name=str(device),
            extra_graphs=train_real,
        )
        # nosemgrep — torch.load with weights_only=True: safe deserialization
        payload = torch.load(ft_path, map_location="cpu", weights_only=True)
        from qtrust_planner.model_v3 import MigrationGNNv3
        cfg = payload.get("model_config", {})
        model = MigrationGNNv3(
            input_features=cfg.get("input_features", 6),
            hidden_dim=cfg.get("hidden_dim", 256),
            embedding_dim=cfg.get("embedding_dim", 128),
            heads=cfg.get("heads", 8),
            dropout=cfg.get("dropout", 0.15),
            use_centrality=cfg.get("use_centrality", True),
            variant=cfg.get("variant", "hybrid"),
            norm=cfg.get("norm", "layer"),
        )
        model.load_state_dict(payload["state_dict"])
        model.to(device).eval()
        ft_path.unlink(missing_ok=True)

        m = eval_graph(model, held_out, device)
        h = score_order(heuristic_order(held_out), held_out.cpu())
        r = score_order(random_order(held_out), held_out.cpu())
        fold_metrics[name] = {
            "model": {k: round(float(v), 6) for k, v in m.items()},
            "heuristic": {k: round(float(v), 6) for k, v in h.items()},
            "random": {k: round(float(v), 6) for k, v in r.items()},
            "n_assets": int(held_out.n_assets),
        }
        model_scores_all.append(m)
        heur_scores_all.append(h)
        rand_scores_all.append(r)
        print(f"  fold {fold+1:>2}/{len(graphs)} {name}: "
              f"model τ-b={m['kendall']:.4f} | heuristic={h['kendall']:.4f} | "
              f"random={r['kendall']:.4f} | n={held_out.n_assets} | "
              f"{time.time()-t0:.0f}s elapsed")

    def _agg(runs: list[dict]) -> dict:
        out = {}
        for k in ("exact_rank", "top5", "top10", "kendall", "node_rank"):
            vals = [r[k] for r in runs]
            out[k] = {
                "mean": round(statistics.mean(vals), 6),
                "median": round(statistics.median(vals), 6),
                "stdev": round(statistics.stdev(vals), 6) if len(vals) > 1 else 0.0,
                "min": round(min(vals), 6),
                "max": round(max(vals), 6),
            }
        return out

    agg = {
        "model": _agg(model_scores_all),
        "heuristic": _agg(heur_scores_all),
        "random": _agg(rand_scores_all),
    }
    config = {
        "init": str(BASE_MODEL.relative_to(REPO_ROOT)),
        "epochs": epochs,
        "n_synthetic": n_synthetic,
        "batch_size": batch_size,
        "learning_rate": learning_rate,
        "seed": seed,
    }
    device_label = torch.cuda.get_device_name(0) if device.type == "cuda" else "cpu"

    if len(graphs) != len(all_graphs):
        # Fold-slice (shard) mode: persist the partial artifact; a later
        # --merge-shards pass assembles the canonical report from all shards.
        shard = {
            "protocol": "leave-one-out (host-disjoint CBOMs, real TLS scan)",
            "shard": [fold_start, fold_end],
            "n_cboms_total": len(all_graphs),
            "n_hosts_total": sum(int(g.n_assets) for _, g in all_graphs),
            "fold_metrics": fold_metrics,
            "config": config,
            "device": device_label,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        shard_path = out_path.with_name(
            f"{out_path.stem}_shard{fold_start}_{fold_end}.json"
        )
        shard_path.parent.mkdir(parents=True, exist_ok=True)
        shard_path.write_text(json.dumps(shard, indent=2))
        n_ties = sum(1 for m in fold_metrics.values()
                     if abs(m["model"]["kendall"] - m["heuristic"]["kendall"]) < 1e-9)
        print(f"\nWrote shard {shard_path} "
              f"({len(fold_metrics)} folds, model-heuristic ties {n_ties})")
        return shard

    report = {
        "protocol": "leave-one-out (host-disjoint CBOMs, real TLS scan)",
        "n_cboms": len(graphs),
        "n_hosts": sum(int(g.n_assets) for _, g in graphs),
        "fold_metrics": fold_metrics,
        "aggregate": agg,
        "model_vs_heuristic_tau_b": round(
            agg["model"]["kendall"]["mean"] - agg["heuristic"]["kendall"]["mean"], 6
        ),
        "model_vs_random_tau_b": round(
            agg["model"]["kendall"]["mean"] - agg["random"]["kendall"]["mean"], 6
        ),
        "config": config,
        "device": device_label,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\nWrote {out_path}")
    print(f"Out-of-sample real-CBOM τ-b: model {agg['model']['kendall']['mean']:.4f} "
          f"vs heuristic {agg['heuristic']['kendall']['mean']:.4f} "
          f"(Δ {report['model_vs_heuristic_tau_b']:+.4f})")
    return report


def merge_shards(out_path: Path) -> dict:
    """Combine all ``<stem>_shard<start>_<end>.json`` artifacts next to
    ``out_path`` into the canonical LOO report (single-GPU-equivalent)."""
    shard_files = sorted(out_path.parent.glob(f"{out_path.stem}_shard*.json"))
    if not shard_files:
        raise FileNotFoundError(
            f"no shard artifacts found for {out_path.name} — run fold slices first"
        )
    fold_metrics: dict[str, dict] = {}
    config: dict | None = None
    devices: list[str] = []
    n_cboms_total = -1
    n_hosts_total = -1
    for sf in shard_files:
        data = json.loads(sf.read_text())
        overlap = set(fold_metrics) & set(data["fold_metrics"])
        if overlap:
            raise ValueError(f"duplicate folds across shards: {sorted(overlap)}")
        fold_metrics.update(data["fold_metrics"])
        config = config or data.get("config")
        devices.append(str(data.get("device")))
        n_cboms_total = max(n_cboms_total, int(data.get("n_cboms_total", 0)))
        n_hosts_total = max(n_hosts_total, int(data.get("n_hosts_total", 0)))

    def _agg(runs: list[dict]) -> dict:
        out = {}
        for k in ("exact_rank", "top5", "top10", "kendall", "node_rank"):
            vals = [r[k] for r in runs]
            out[k] = {
                "mean": round(statistics.mean(vals), 6),
                "median": round(statistics.median(vals), 6),
                "stdev": round(statistics.stdev(vals), 6) if len(vals) > 1 else 0.0,
                "min": round(min(vals), 6),
                "max": round(max(vals), 6),
            }
        return out

    model_runs = [m["model"] for m in fold_metrics.values()]
    heur_runs = [m["heuristic"] for m in fold_metrics.values()]
    rand_runs = [m["random"] for m in fold_metrics.values()]
    agg = {"model": _agg(model_runs), "heuristic": _agg(heur_runs), "random": _agg(rand_runs)}
    report = {
        "protocol": "leave-one-out (host-disjoint CBOMs, real TLS scan)",
        "n_cboms": len(fold_metrics),
        "n_hosts": n_hosts_total,
        "fold_metrics": dict(sorted(fold_metrics.items())),
        "aggregate": agg,
        "model_vs_heuristic_tau_b": round(
            agg["model"]["kendall"]["mean"] - agg["heuristic"]["kendall"]["mean"], 6
        ),
        "model_vs_random_tau_b": round(
            agg["model"]["kendall"]["mean"] - agg["random"]["kendall"]["mean"], 6
        ),
        "config": config,
        "device": devices[0] if len(set(devices)) == 1 else devices,
        "shard_files": [str(sf.name) for sf in shard_files],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(f"Merged {len(shard_files)} shards -> {out_path} "
          f"({report['n_cboms']} folds)")
    print(f"Out-of-sample real-CBOM τ-b: model {agg['model']['kendall']['mean']:.4f} "
          f"vs heuristic {agg['heuristic']['kendall']['mean']:.4f} "
          f"(Δ {report['model_vs_heuristic_tau_b']:+.4f})")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LOO real-CBOM evaluation")
    parser.add_argument("--epochs", type=int, default=6)
    parser.add_argument("--n-synthetic", type=int, default=2000)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=5e-4)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--device", type=str, default=None)
    parser.add_argument("--out", type=Path, default=RESULT_PATH)
    parser.add_argument("--quick", action="store_true", help="3 folds (smoke test)")
    parser.add_argument("--fold-start", type=int, default=0,
                        help="first fold index for this shard (GPU-parallel LOO)")
    parser.add_argument("--fold-end", type=int, default=None,
                        help="exclusive last fold index for this shard")
    parser.add_argument("--merge-shards", action="store_true",
                        help="merge *_shard*.json artifacts into the canonical report")
    args = parser.parse_args()
    if args.merge_shards:
        merge_shards(args.out)
        raise SystemExit(0)
    run_loo(
        epochs=args.epochs,
        n_synthetic=args.n_synthetic,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        seed=args.seed,
        device_name=args.device,
        quick=args.quick,
        out_path=args.out,
        fold_start=args.fold_start,
        fold_end=args.fold_end,
    )
