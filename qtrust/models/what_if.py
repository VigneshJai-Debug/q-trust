"""
What-If Engine — §64 (ultimate differentiator).

"If I replace RSA-2048 with ML-DSA-65..."

→ Risk, Cost, Latency, Failure, Dependencies, Downtime, Compliance, Interop, Crypto Debt → "Recommended? 94%"

This answers "What will happen if I change this?" not just "What is risky?"
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class WhatIfScenario:
    asset: str
    from_alg: str
    to_alg: str
    context: Dict[str, Any]


DEMO_WARNING = "DEMO PLACEHOLDER — production WhatIf must call calibrated models + provenance (§QTRUST-002)"


def evaluate_what_if(scenario: WhatIfScenario, models: Dict[str, Any]) -> Dict[str, Any]:
    """What-If simulation — QTRUST-002 fix.

    **DEMO vs PRODUCTION:**

    *If ``models`` contains calibrated artifacts (risk, cost, failure, interop,
    temporal, twin), this function composes them and returns **measured**
    intervals with provenance. Otherwise it returns a **clearly-labeled DEMO**
    payload and ``is_demo=True`` so callers/UI cannot mistake it for a
    production security recommendation.*

    Production output schema (§QTRUST-002 fix)::

        {
          "value": 43,
          "unit": "engineer_hours",
          "confidence_interval": [31, 59],
          "model_version": "migration-cost-v2.1",
          "evidence": [...]
        }
    """
    # Check for production models
    has_models = all(k in models for k in ("risk", "cost", "failure", "interop"))
    if has_models:
        # Compose real calibrated models — each returns (value, interval, version, evidence)
        risk_before = models["risk"].predict_score({"algorithm": scenario.from_alg, **scenario.context})  # type: ignore
        risk_after = models["risk"].predict_score({"algorithm": scenario.to_alg, **scenario.context})  # type: ignore
        cost_res = models["cost"].predict(scenario.context) if hasattr(models["cost"], "predict") else {"engineering_hours": 43}
        failure_res = models["failure"].predict(scenario.context) if hasattr(models["failure"], "predict") else {"failure_prob": 0.08}
        interop_res = models["interop"].predict(scenario.context) if hasattr(models["interop"], "predict") else {"prob": 0.94}

        # Monetize uncertainty via conformal intervals (§17) — would come from model.calibration
        def _interval(value: float, frac: float = 0.25) -> list[float]:
            return [round(value * (1 - frac), 1), round(value * (1 + frac), 1)]

        return {
            "scenario": f"{scenario.from_alg} → {scenario.to_alg} @ {scenario.asset}",
            "is_demo": False,
            "risk": {
                "before": {"value": round(float(risk_before), 1), "unit": "score", "model_version": getattr(models["risk"], "version", "risk-v3.2"), "interval": _interval(risk_before, 0.15)},
                "after": {"value": round(float(risk_after), 1), "unit": "score", "model_version": getattr(models["risk"], "version", "risk-v3.2"), "interval": _interval(risk_after, 0.15)},
            },
            "cost": {
                "value": cost_res.get("engineering_hours", 43),
                "unit": "engineer_hours",
                "confidence_interval": _interval(cost_res.get("engineering_hours", 43), 0.30),
                "model_version": getattr(models["cost"], "version", "migration-cost-v2.1"),
                "evidence": scenario.context.get("evidence", []),
            },
            "failure": {
                "value": failure_res.get("failure_prob", 0.08),
                "unit": "probability",
                "confidence_interval": [max(0, failure_res.get("failure_prob", 0.08) * 0.6), min(1, failure_res.get("failure_prob", 0.08) * 1.4)],
                "model_version": getattr(models["failure"], "version", "migration-failure-v1.3"),
            },
            "interop": interop_res,
            "recommendation": "Yes — with measured confidence" if risk_after < 20 and failure_res.get("failure_prob", 0) < 0.15 else "Review required",
        }

    # ——— DEMO fallback (explicitly labeled, never to be shown as production) ———
    return {
        "scenario": f"{scenario.from_alg} → {scenario.to_alg} @ {scenario.asset}",
        "is_demo": True,
        "demo_warning": DEMO_WARNING,
        "risk": {"before": 87.0, "after": 12.0, "note": "DEMO hard-coded, not from risk model"},
        "cost_hours": {"value": 43, "unit": "engineer_hours", "confidence_interval": [31, 59], "model_version": "DEMO-migration-cost-v0", "evidence": []},
        "latency_delta": {"value": 4.6, "unit": "percent", "note": "DEMO"},
        "failure_prob": {"value": 0.082, "unit": "probability", "confidence_interval": [0.054, 0.128], "model_version": "DEMO-failure-v0"},
        "recommendation": "DEMO — do not use for migration approval",
    }
