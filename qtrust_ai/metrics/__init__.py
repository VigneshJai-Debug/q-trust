"""
qtrust_ai.metrics — Killer metric suite package (Phase 5).

Per ``qtrust_ai/README.md`` §27 (Killer metrics):

* :mod:`qtrust_ai.metrics.core` — pure-Python implementations of every metric
  (precision/recall/F1/FNR/coverage, AUROC/AUPRC/Brier/ECE, Kendall τ /
  Spearman ρ / NDCG@K / P@K / R@K, MAE/RMSE/MAPE, accuracy). No heavy deps —
  runs in CI anywhere.
* :mod:`qtrust_ai.metrics.suite` — :class:`QTrustMetricSuite` composes the six
  domain reports:

    Discovery P/R/F1/FN/coverage | Risk AUROC/AUPRC/Brier/ECE |
    Ranking τ/ρ/NDCG@K/P@K/R@K | Migration cost MAE + failure AUROC |
    Interop compat acc + latency error | Planner risk/$ + risk/hour +
    downtime + completion time

Usage::

    from qtrust_ai.metrics.suite import QTrustMetricSuite

    suite = QTrustMetricSuite()
    report = suite.full_report(
        discovery=([1, 0, 1], [1, 0, 1]),
        risk=([1, 0, 1], [0.9, 0.1, 0.8]),
        ranking=([3.0, 2.0, 0.0], [0.9, 0.5, 0.1], 3),
    )
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

try:
    from .core import (
        precision_recall_f1,
        false_negative_rate,
        coverage,
        brier_score,
        expected_calibration_error,
        auroc,
        auprc,
        kendall_tau,
        spearman_rho,
        ndcg_at_k,
        precision_at_k,
        recall_at_k,
        mae,
        rmse,
        mape,
        accuracy,
    )
except ImportError:  # pragma: no cover
    precision_recall_f1 = None  # type: ignore
    false_negative_rate = None  # type: ignore
    coverage = None  # type: ignore
    brier_score = None  # type: ignore
    expected_calibration_error = None  # type: ignore
    auroc = None  # type: ignore
    auprc = None  # type: ignore
    kendall_tau = None  # type: ignore
    spearman_rho = None  # type: ignore
    ndcg_at_k = None  # type: ignore
    precision_at_k = None  # type: ignore
    recall_at_k = None  # type: ignore
    mae = None  # type: ignore
    rmse = None  # type: ignore
    mape = None  # type: ignore
    accuracy = None  # type: ignore

try:
    from .suite import QTrustMetricSuite
except ImportError:  # pragma: no cover
    QTrustMetricSuite = None  # type: ignore

__all__ = [
    "precision_recall_f1", "false_negative_rate", "coverage",
    "brier_score", "expected_calibration_error", "auroc", "auprc",
    "kendall_tau", "spearman_rho", "ndcg_at_k", "precision_at_k", "recall_at_k",
    "mae", "rmse", "mape", "accuracy",
    "QTrustMetricSuite",
]

__version__: str = "5.0.0-metrics"
METRICS_MODULES: List[str] = [
    "qtrust_ai.metrics.core",
    "qtrust_ai.metrics.suite",
]

# §27 metric domains
METRIC_DOMAINS: Dict[str, List[str]] = {
    "discovery": ["precision", "recall", "f1", "false_negative_rate", "coverage"],
    "risk": ["auroc", "auprc", "brier", "ece"],
    "ranking": ["kendall_tau", "spearman_rho", "ndcg@k", "precision@k", "recall@k"],
    "migration": ["cost_mae", "duration_mae", "failure_auroc"],
    "interop": ["compat_accuracy", "latency_error"],
    "planner": ["risk_per_usd", "risk_per_engineer_hour", "downtime", "completion_days"],
}


def get_metrics_info() -> Dict[str, Any]:
    """Return package metadata for health checks."""
    return {
        "package": "qtrust_ai.metrics",
        "version": __version__,
        "phase": "5 Interface",
        "modules": METRICS_MODULES,
        "domains": METRIC_DOMAINS,
        "architecture_doc": "qtrust_ai/README.md",
        "pure_python": True,
        "has_suite": QTrustMetricSuite is not None,
    }


if __name__ == "__main__":
    print("=== qtrust_ai.metrics package demo ===")
    print(json.dumps(get_metrics_info(), indent=2))
    if QTrustMetricSuite is not None and auroc is not None:
        suite = QTrustMetricSuite()  # type: ignore
        report = suite.full_report(  # type: ignore
            discovery=([1, 0, 1, 1], [1, 0, 1, 0]),
            risk=([1, 0, 1, 1], [0.9, 0.1, 0.8, 0.4]),
            ranking=([3.0, 2.0, 3.0, 0.0], [0.9, 0.5, 0.95, 0.1], 3),
        )
        print(json.dumps(report, indent=2))
        assert report["discovery"]["f1"] > 0.5
        assert report["risk"]["auroc"] > 0.5
        assert report["ranking"]["kendall_tau"] > 0.5
        print("\n✓ metrics package demo passed")
    else:
        print("metrics not importable")
