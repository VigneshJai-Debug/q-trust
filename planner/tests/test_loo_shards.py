"""Regression tests for the GPU-parallel LOO fold sharding in
``scripts/eval_real_cbom_loo.py``.

Guards the 4-GPU 40-fold campaign protocol: folds must be mergeable into a
canonical report identical to a single-process run, and duplicate folds
across shards (a config mistake that would double-count a held-out CBOM)
must fail loudly instead of silently biasing the aggregate.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load_loo_script():
    path = REPO / "scripts" / "eval_real_cbom_loo.py"
    spec = importlib.util.spec_from_file_location("eval_real_cbom_loo", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fold_metrics(n: int, seed: float = 0.5, start: int = 0) -> dict:
    out = {}
    for i in range(n):
        tau = (seed + i * 0.01) % 1.0
        out[f"cbom_{start + i}.json"] = {
            "model": {"exact_rank": 0.0, "top5": 0.0, "top10": 1.0,
                      "kendall": tau, "node_rank": 0.5},
            "heuristic": {"exact_rank": 1.0, "top5": 1.0, "top10": 1.0,
                          "kendall": 0.7, "node_rank": 1.0},
            "random": {"exact_rank": 0.0, "top5": 0.0, "top10": 1.0,
                       "kendall": 0.2, "node_rank": 0.1},
            "n_assets": 8,
        }
    return out


@pytest.fixture()
def merged_dir(tmp_path):
    loo = _load_loo_script()
    shards = [
        {"shard": [0, 2], "n_cboms_total": 4, "n_hosts_total": 32,
         "fold_metrics": _fold_metrics(2, 0.50, start=0), "config": {"epochs": 30, "seed": 42},
         "device": "NVIDIA A100-SXM4-80GB"},
        {"shard": [2, 4], "n_cboms_total": 4, "n_hosts_total": 32,
         "fold_metrics": _fold_metrics(2, 0.60, start=2), "config": {"epochs": 30, "seed": 42},
         "device": "NVIDIA A100-SXM4-80GB"},
    ]
    for s in shards:
        lo, hi = s["shard"]
        p = tmp_path / f"real_cbom_loo_40_shard{lo}_{hi}.json"
        p.write_text(json.dumps(s))
    return loo, tmp_path / "real_cbom_loo_40.json"


def test_merge_reports_all_folds_and_aggregates(merged_dir):
    loo, out_path = merged_dir
    report = loo.merge_shards(out_path)
    assert report["n_cboms"] == 4
    assert report["config"] == {"epochs": 30, "seed": 42}
    assert report["device"] == "NVIDIA A100-SXM4-80GB"
    assert report["n_hosts"] == 32
    assert len(report["fold_metrics"]) == 4
    # Aggregate must equal a direct single-corpus computation.
    import statistics
    taus = [m["model"]["kendall"] for m in report["fold_metrics"].values()]
    assert report["aggregate"]["model"]["kendall"]["mean"] == round(statistics.mean(taus), 6)
    heur = statistics.mean(m["heuristic"]["kendall"] for m in report["fold_metrics"].values())
    assert report["model_vs_heuristic_tau_b"] == round(
        report["aggregate"]["model"]["kendall"]["mean"] - heur, 6)
    assert report["generated_at"], "canonical report must carry a timestamp"


def test_merge_order_is_irrelevant(tmp_path):
    loo = _load_loo_script()
    shard_a = {"shard": [0, 2], "n_cboms_total": 4, "n_hosts_total": 32,
               "fold_metrics": _fold_metrics(2, 0.55, start=0), "config": {"epochs": 30, "seed": 42},
               "device": "gpu-a"}
    shard_b = {"shard": [2, 4], "n_cboms_total": 4, "n_hosts_total": 32,
               "fold_metrics": _fold_metrics(2, 0.65, start=2), "config": {"epochs": 30, "seed": 42},
               "device": "gpu-b"}
    dir1, dir2 = tmp_path / "d1", tmp_path / "d2"
    dir1.mkdir()
    dir2.mkdir()
    for d in (dir1, dir2):
        (d / "real_cbom_loo_40_shard0_2.json").write_text(json.dumps(shard_a))
        (d / "real_cbom_loo_40_shard2_4.json").write_text(json.dumps(shard_b))
    # Same shards, different filename ordering -> identical aggregates.
    (dir1 / "real_cbom_loo_40_shard0_2.json").rename(dir1 / "real_cbom_loo_40_shardZ_9.json")
    first = loo.merge_shards(dir1 / "real_cbom_loo_40.json")
    second = loo.merge_shards(dir2 / "real_cbom_loo_40.json")
    for key in ("kendall", "top5", "top10", "exact_rank"):
        assert second["aggregate"]["model"][key]["mean"] == first["aggregate"]["model"][key]["mean"]
    assert second["model_vs_heuristic_tau_b"] == first["model_vs_heuristic_tau_b"]
    assert second["n_cboms"] == first["n_cboms"] == 4


def test_duplicate_folds_across_shards_are_rejected(tmp_path):
    loo = _load_loo_script()
    dup_a = {"shard": [0, 2], "n_cboms_total": 4, "n_hosts_total": 32,
             "fold_metrics": _fold_metrics(2, start=0), "config": {"epochs": 30, "seed": 42},
             "device": "gpu"}
    dup_b = {"shard": [0, 2], "n_cboms_total": 4, "n_hosts_total": 32,
             "fold_metrics": _fold_metrics(2, start=0), "config": {"epochs": 30, "seed": 42},
             "device": "gpu"}
    for i, d in enumerate((dup_a, dup_b)):
        (tmp_path / f"real_cbom_loo_40_shard{i}.json").write_text(json.dumps(d))
    with pytest.raises(ValueError, match="duplicate folds"):
        loo.merge_shards(tmp_path / "real_cbom_loo_40.json")


def test_merge_without_shards_fails_loudly(tmp_path):
    loo = _load_loo_script()
    with pytest.raises(FileNotFoundError, match="no shard artifacts"):
        loo.merge_shards(tmp_path / "real_cbom_loo_40.json")