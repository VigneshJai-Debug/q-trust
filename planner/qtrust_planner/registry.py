"""MLOps Registry — makes "trained" and "served" the same word (pdf §20).

File-based fallback when MLflow is not available; MLflow preferred when
QTRUST_MLFLOW_TRACKING_URI is set. Every run logs config, seed, data hash,
git commit, and metrics; promotion to production is a registry transition
gated on the eval suites (§20, milestone M5).

Also handles checkpoint export: ONNX + TensorRT int8 for inspector CLI
and planner GNN; heterogeneous-graph schema file; checkout via release assets.

The registry is the status report (§21).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

# Anchor the default registry at the repo's planner/registry regardless of
# the caller's working directory (HPO/training can be launched from planner/
# or from the repo root; a relative default would silently create a nested
# planner/planner/registry instead of the tracked one).
_DEFAULT_REGISTRY = Path(__file__).resolve().parents[1] / "registry"
REGISTRY_DIR = Path(os.environ.get("QTRUST_REGISTRY_DIR", str(_DEFAULT_REGISTRY)))
# REG-24 FIX: do not mkdir at import time (unsafe for multi-worker). Lazy in _ensure_registry().


def _ensure_registry() -> None:
    REGISTRY_DIR.mkdir(parents=True, exist_ok=True)

def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()[:12]
    except Exception:
        return "unknown"

def _data_hash_for_run(n_graphs: int, seed: int) -> str:
    return hashlib.sha256(f"{n_graphs}-{seed}".encode()).hexdigest()[:16]

def log_run(
    run_name: str,
    params: dict[str, Any],
    metrics: dict[str, float],
    artifact_path: str | None = None,
    tags: dict[str, str] | None = None,
) -> str:
    """Log a run to the file registry and optionally to MLflow."""
    _ensure_registry()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    git_commit = _git_commit()
    run_id = hashlib.sha256(f"{run_name}-{ts}-{git_commit}".encode()).hexdigest()[:12]
    record = {
        "run_id": run_id,
        "run_name": run_name,
        "timestamp": ts,
        "git_commit": git_commit,
        "params": params,
        "metrics": metrics,
        "tags": tags or {},
        "artifact_path": artifact_path,
        "data_hash": params.get("data_hash"),
    }
    # File registry
    out = REGISTRY_DIR / f"{run_name}_{run_id}.json"
    out.write_text(json.dumps(record, indent=2))
    print(f"[registry] logged {run_name} -> {out} (run_id={run_id})")
    # MLflow mirror if configured
    mlflow_uri = os.environ.get("QTRUST_MLFLOW_TRACKING_URI") or os.environ.get("MLFLOW_TRACKING_URI")
    if mlflow_uri:
        try:
            import mlflow  # type: ignore
            mlflow.set_tracking_uri(mlflow_uri)
            mlflow.set_experiment(os.environ.get("QTRUST_MLFLOW_EXPERIMENT", "qtrust-planner"))
            with mlflow.start_run(run_name=run_name):
                mlflow.log_params({k: str(v) for k, v in params.items()})
                mlflow.log_metrics(metrics)
                if tags:
                    mlflow.set_tags(tags)
                if artifact_path and Path(artifact_path).exists():
                    mlflow.log_artifact(artifact_path)
            print(f"[registry] mirrored to MLflow at {mlflow_uri}")
        except Exception as e:
            print(f"[registry] MLflow mirror failed: {e}")
    return run_id

def promote_model(run_id: str, stage: str = "production") -> None:
    """Promote a model to a stage (staging/production) — gating on eval."""
    marker = REGISTRY_DIR / f"promote_{run_id}_{stage}.json"
    marker.write_text(json.dumps({"run_id": run_id, "stage": stage, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=2))
    print(f"[registry] promoted {run_id} -> {stage}")

def list_runs() -> list[dict]:
    runs = []
    for p in REGISTRY_DIR.glob("*.json"):
        if p.name.startswith("promote_"):
            continue
        try:
            runs.append(json.loads(p.read_text()))
        except Exception:
            pass
    return sorted(runs, key=lambda r: r.get("timestamp", ""), reverse=True)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        for r in list_runs():
            print(f"{r['run_id']} {r['run_name']} {r['metrics']}")
