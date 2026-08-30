"""
Model registry — §49, §53-54 shadow mode, gates.

Never overwrite models. Versioned: risk-v1, risk-v2. Each prediction stores
model, dataset, feature_schema, policy hashes anchored to Merkle root → blockchain (§50).

Gates: Precision, Recall, Critical Recall ≥97%, ECE ≤0.05, AUPRC ≥ baseline+10%.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


@dataclass
class ModelVersion:
    name: str  # risk-v3.2
    dataset: str  # riskbench-2026-08
    dataset_hash: str
    feature_schema: str  # v5
    policy: str  # policy-v2.1
    metrics: Dict[str, Any]
    artifact_path: str
    promoted: bool = False


REGISTRY = Path("qtrust/mlops/registry.json")


def register(version: ModelVersion) -> None:
    data: Dict[str, Any] = {}
    if REGISTRY.exists():
        data = json.loads(REGISTRY.read_text())
    data[version.name] = {
        "dataset": version.dataset,
        "dataset_hash": version.dataset_hash,
        "feature_schema": version.feature_schema,
        "policy": version.policy,
        "metrics": version.metrics,
        "artifact": version.artifact_path,
        "promoted": version.promoted,
    }
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY.write_text(json.dumps(data, indent=2))


def gate_check(metrics: Dict[str, Any], baseline_auprc: float = 0.6) -> Dict[str, Any]:
    checks = {
        "critical_recall": metrics.get("critical_recall", 0) >= 0.97,
        "ece": metrics.get("ece", 1) <= 0.05,
        "auprc_gain": metrics.get("auprc", 0) >= baseline_auprc + 0.10,
        "precision": metrics.get("precision", 0) >= 0.85,
        "recall": metrics.get("recall", 0) >= 0.80,
    }
    passed = all(checks.values())
    return {"passed": passed, "checks": checks, "shadow": not passed}


def shadow_predict(rule_pred: Any, ml_pred: Any) -> Dict[str, Any]:
    # Rule engine → production, ML → shadow (§53) for 30-60 days
    return {"production": rule_pred, "shadow": ml_pred, "compare": rule_pred == ml_pred}
