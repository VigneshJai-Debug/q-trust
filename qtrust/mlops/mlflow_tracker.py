"""
MLflow tracking — §51 (§25 pipeline).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


def log_run(params: Dict[str, Any], metrics: Dict[str, Any], artifact_path: Path | None = None) -> str:
    try:
        import mlflow

        with mlflow.start_run():
            mlflow.log_params(params)
            mlflow.log_metrics(metrics)
            if artifact_path and artifact_path.exists():
                mlflow.log_artifact(str(artifact_path))
            return mlflow.active_run().info.run_id if mlflow.active_run() else "no-run"
    except Exception:
        # Fallback: local JSON log when MLflow not installed (CI without GPU)
        log_path = Path("qtrust/mlops/mlflow_runs.json")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        import json

        runs = json.loads(log_path.read_text()) if log_path.exists() else []
        runs.append({"params": params, "metrics": metrics, "artifact": str(artifact_path) if artifact_path else None})
        log_path.write_text(json.dumps(runs, indent=2))
        return "local-fallback"
