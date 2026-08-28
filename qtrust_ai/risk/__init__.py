"""
qtrust_ai.risk — Risk & HNDL intelligence package.

Phase 1 Foundation per ``qtrust_ai/README.md`` § The intelligence stack:

* :mod:`qtrust_ai.risk.quantum_exposure` — Quantum Exposure Score:
  ``vuln × sensitivity × lifetime × exposure × attractiveness × lead_time``
  plus HNDL risk, calibration (temperature scaling, conformal), and alignment
  with ``inspector/qtrust_inspector/risk_engine.py`` and NIST migration
  guidance (SP 800-131A, CNSA 2.0).

See ``qtrust_ai/README.md`` § Risk and docs/WHITEPAPER.md § 4.3-4.4
(HNDL Exposure Scoring, Overall Risk). The 6-factor product is the primary
migration-urgency signal; HNDL is the harvest-now specific sub-score.

NIST alignment:
* 2030 disallow RSA-2048 / ECDSA-P256 for key establishment (SP 800-131A)
* 2035 disallow all classical asymmetric (CNSA 2.0)
* Harvest-now-decrypt-later horizon drives ``lifetime`` and ``exposure``.

Usage::

    from qtrust_ai.risk.quantum_exposure import QuantumExposureModel, ExposureFactors

    model = QuantumExposureModel()
    factors = ExposureFactors(
        algorithm="RSA-2048", sensitivity=5, lifetime_years=10,
        exposure_years=3.0, attractiveness=4, lead_time_years=2,
    )
    result = model.predict(factors)
    print(result.score, result.hndl_risk, result.level)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from .quantum_exposure import (
        QuantumExposureModel,
        ExposureFactors,
        QuantumExposureScore,
        Vulnerability,
    )
except ImportError:  # pragma: no cover
    QuantumExposureModel = None  # type: ignore
    ExposureFactors = None  # type: ignore
    QuantumExposureScore = None  # type: ignore
    Vulnerability = None  # type: ignore

__all__ = [
    "QuantumExposureModel",
    "ExposureFactors",
    "QuantumExposureScore",
    "Vulnerability",
]

__version__: str = "1.0.0-risk"
FACTOR_NAMES: List[str] = ["vuln", "sensitivity", "lifetime", "exposure", "attractiveness", "lead_time"]
RISK_LEVELS: List[str] = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

@dataclass
class RiskHealth:
    """Health summary for risk scoring."""

    factors: List[str] = None  # type: ignore
    levels: List[str] = None  # type: ignore
    has_model: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "factors": self.factors or FACTOR_NAMES,
            "levels": self.levels or RISK_LEVELS,
            "has_model": self.has_model,
        }


def get_risk_info() -> Dict[str, Any]:
    """Return package metadata for health checks / benchmarking."""
    return {
        "package": "qtrust_ai.risk",
        "version": __version__,
        "phase": "1 Foundation",
        "models": ["QuantumExposureModel (6-factor + HNDL)"],
        "factors": FACTOR_NAMES,
        "levels": RISK_LEVELS,
        "architecture_doc": "qtrust_ai/README.md",
        "nist_alignment": ["SP 800-131A", "CNSA 2.0", "HNDL"],
        "has_model": QuantumExposureModel is not None,
    }


if __name__ == "__main__":
    print("=== qtrust_ai.risk package demo ===")
    print(json.dumps(get_risk_info(), indent=2))
    if QuantumExposureModel is not None:
        model = QuantumExposureModel()  # type: ignore
        model.train(epochs=1)  # type: ignore
        cases = [
            {"algorithm": "RSA-2048", "sensitivity": 5, "lifetime_years": 5, "exposure_years": 5, "attractiveness": 5, "lead_time_years": 5},
            {"algorithm": "ML-KEM-768", "sensitivity": 5, "lifetime_years": 5, "exposure_years": 5, "attractiveness": 5, "lead_time_years": 5},
            {"algorithm": "AES-256", "sensitivity": 2, "lifetime_years": 2, "exposure_years": 1, "attractiveness": 2, "lead_time_years": 1},
        ]
        for c in cases:
            f = ExposureFactors(**c)  # type: ignore
            r = model.predict(f)  # type: ignore
            print(f"[QuantumExposure] {c['algorithm']:12s} -> score={r.score:5.1f} hndl={r.hndl_risk:5.1f} level={r.level}")
            print(f"  {r.explanation}")
    else:
        print("Risk model not importable")
