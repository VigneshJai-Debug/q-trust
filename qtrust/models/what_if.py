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


def evaluate_what_if(scenario: WhatIfScenario, models: Dict[str, Any]) -> Dict[str, Any]:
    # In production, calls risk, cost, failure, interop, temporal models + digital twin
    risk_before = 87.0 if "RSA" in scenario.from_alg else 40.0
    risk_after = 12.0 if "ML-DSA" in scenario.to_alg or "ML-KEM" in scenario.to_alg else 50.0
    cost = 43.0  # hours
    latency = 4.6  # %
    failure = 0.082
    return {
        "scenario": f"{scenario.from_alg} → {scenario.to_alg} @ {scenario.asset}",
        "risk": {"before": risk_before, "after": risk_after, "delta": risk_after - risk_before},
        "cost_hours": cost,
        "latency_delta": latency,
        "failure_prob": failure,
        "crypto_debt_future": {"30d": 1.9, "90d": 0.9, "180d": 0.5},
        "recommendation": "Yes — with 94% confidence" if risk_after < 20 and failure < 0.15 else "Review required",
        "confidence": 0.94,
    }
