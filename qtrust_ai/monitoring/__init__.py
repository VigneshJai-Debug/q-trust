"""
qtrust_ai.monitoring — Continuous & Regression monitoring package.

Phase 4 Enterprise per ``qtrust_ai/README.md`` § Continuous Monitoring:

* :mod:`qtrust_ai.monitoring.anomaly` — Continuous crypto anomaly detection:
  unexpected crypto usage, new algorithm appearance, sudden RSA increase,
  and crypto regression (classical re-introduction). Extends
  :mod:`inspector.qtrust_inspector.anomaly_detector` with streaming,
  windowed baselining, and quantum-aware checks.
* :mod:`qtrust_ai.monitoring.regression` — Crypto Regression detector for
  CI/CD: blocks pipelines when ``ML-KEM → RSA`` or any PQC → classical
  regression is detected, distinguishes intentional rollback vs incident.

NIST alignment: ongoing crypto-agility & continuous inventory
[CSRC 2025-26] — migration is not one-shot; drift must be detected live.

Usage::

    from qtrust_ai.monitoring.anomaly import CryptoAnomalyDetector, CryptoSnapshot
    from qtrust_ai.monitoring.regression import CryptoRegressionDetector

    mon = CryptoAnomalyDetector(seed=42)
    mon.train(baseline_snapshots)
    alerts = mon.detect(current_snapshot)

    reg = CryptoRegressionDetector()
    verdict = reg.check_ci_gate(baseline_cbom, candidate_cbom)
    assert not verdict.blocked or verdict.severity == "CRITICAL"

All models are CPU-friendly with deterministic fallbacks when
``torch`` / ``sklearn`` are absent.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

try:
    from .anomaly import (
        CryptoAnomalyDetector,
        CryptoSnapshot,
        AnomalyAlert,
        MonitoringConfig,
    )
except ImportError:  # pragma: no cover
    CryptoAnomalyDetector = None  # type: ignore
    CryptoSnapshot = None  # type: ignore
    AnomalyAlert = None  # type: ignore
    MonitoringConfig = None  # type: ignore

try:
    from .regression import (
        CryptoRegressionDetector,
        RegressionResult,
        RegressionFinding,
        RegressionGateVerdict,
    )
except ImportError:  # pragma: no cover
    CryptoRegressionDetector = None  # type: ignore
    RegressionResult = None  # type: ignore
    RegressionFinding = None  # type: ignore
    RegressionGateVerdict = None  # type: ignore

__all__ = [
    "CryptoAnomalyDetector",
    "CryptoSnapshot",
    "AnomalyAlert",
    "MonitoringConfig",
    "CryptoRegressionDetector",
    "RegressionResult",
    "RegressionFinding",
    "RegressionGateVerdict",
]

__version__: str = "4.0.0-monitoring"
MONITORING_MODULES: List[str] = [
    "qtrust_ai.monitoring.anomaly",
    "qtrust_ai.monitoring.regression",
]


def get_monitoring_info() -> Dict[str, Any]:
    """Return package metadata for health checks."""
    return {
        "package": "qtrust_ai.monitoring",
        "version": __version__,
        "phase": "4 Enterprise",
        "models": [
            "CryptoAnomalyDetector (continuous: new algo, RSA spike, regression)",
            "CryptoRegressionDetector (CI/CD gate: ML-KEM→RSA blocked)",
        ],
        "architecture_doc": "qtrust_ai/README.md",
        "has_anomaly": CryptoAnomalyDetector is not None,
        "has_regression": CryptoRegressionDetector is not None,
        "extends": "inspector/qtrust_inspector/anomaly_detector.py",
    }


if __name__ == "__main__":
    print("=== qtrust_ai.monitoring package demo ===")
    print(json.dumps(get_monitoring_info(), indent=2))
    if CryptoAnomalyDetector is not None:
        det = CryptoAnomalyDetector(seed=42)  # type: ignore
        det.train()  # type: ignore
        # Simulate baseline vs current with RSA spike + new algo
        from qtrust_ai.monitoring.anomaly import CryptoSnapshot  # type: ignore
        baseline = CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "ECDSA-P256": 10, "AES-256": 30}, total_assets=80)  # type: ignore
        current = CryptoSnapshot(algorithm_counts={"RSA-2048": 65, "ECDSA-P256": 10, "AES-256": 30, "DES": 2}, total_assets=107)  # type: ignore
        det.establish_baseline([baseline])  # type: ignore
        alerts = det.detect(current)  # type: ignore
        print(f"\n[CryptoAnomalyDetector] {len(alerts)} alerts")
        for a in alerts:  # type: ignore
            print(f"  {a.alert_type:18s} {a.severity:8s} {a.message}")
    if CryptoRegressionDetector is not None:
        reg = CryptoRegressionDetector()  # type: ignore
        baseline_cbom = {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]}  # type: ignore
        regressed_cbom = {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ML-DSA-65"}]}  # type: ignore
        verdict = reg.check_ci_gate(baseline_cbom, regressed_cbom)  # type: ignore
        print(f"\n[CryptoRegressionDetector] blocked={verdict.blocked} severity={verdict.severity} findings={len(verdict.findings)}")
        for f in verdict.findings:  # type: ignore
            print(f"  {f.regression_type:20s} {f.severity:8s} {f.message}")
