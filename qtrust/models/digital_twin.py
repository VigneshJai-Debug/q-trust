"""
Digital Twin — §47-48.

Scenario generation → migration simulation → expected vs actual → model correction.

Stores every scan (§45 temporal data lake), predicts future crypto debt, simulates plans.

Becomes testbed for what-if engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class TwinState:
    timestamp: str
    assets: List[Dict[str, Any]]
    risk_score: float
    crypto_debt_m: float


class DigitalTwin:
    def __init__(self):
        self.history: List[TwinState] = []

    def ingest_scan(self, state: TwinState) -> None:
        self.history.append(state)

    def simulate_migration(self, plan: List[str]) -> Dict[str, Any]:
        # Apply plan to last state
        last = self.history[-1] if self.history else TwinState("now", [], 70, 1.8)
        predicted = max(10, last.risk_score * 0.6)
        cost = len(plan) * 8.5  # hours
        return {"predicted_risk": predicted, "predicted_cost_hours": cost, "plan": plan}

    def record_actual(self, predicted: Dict[str, Any], actual: Dict[str, Any]) -> Dict[str, Any]:
        error = actual["cost_hours"] - predicted["predicted_cost_hours"]
        # Feed back into training data (§48)
        return {"error": error, "needs_retrain": abs(error) > 5}

    def forecast_debt(self, days: int = 180) -> float:
        last = self.history[-1].crypto_debt_m if self.history else 1.8
        return last * (1 + days * 0.002)
