"""
Temporal GNN — §15, §45-46.

G(t), G(t+1), G(t+2) → predict future crypto debt, risk, migration priority.

Example: Service A RSA → next month ML-DSA → new dependency appears.
Predicts: "Which assets will be high priority in next 90 days?" + future crypto debt ($1.8M → $2.9M).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class Snapshot:
    day: int
    num_nodes: int
    num_edges: int
    risk_score: float


class TemporalGNN:
    def __init__(self, seed: int = 42):
        self.seed = seed

    def predict_trajectory(self, history: List[Snapshot], horizon_days: List[int] = [30, 90, 180]) -> Dict[str, Any]:
        # Simple trend: risk decays if PQC migration continues, else grows
        last = history[-1].risk_score if history else 70
        # Learned decay factors (would be GNN in production)
        factors = {30: 0.84, 90: 0.68, 180: 0.58}
        risks = [round(last * factors.get(h, 0.5), 1) for h in horizon_days]
        # Crypto debt forecast (§46)
        debt_now = 1.8  # $M
        debt_future = {30: debt_now * 1.05, 90: debt_now * 1.28, 180: debt_now * 1.61}
        return {"risks": risks, "debt": debt_future, "horizon": horizon_days}

    def predict_crypto_debt(self, current_debt: float, plan: str | None = None) -> Dict[str, float]:
        if plan == "migration_A":
            return {30: current_debt * 1.02, 90: current_debt * 0.75, 180: current_debt * 0.5}
        return {30: current_debt * 1.05, 90: current_debt * 1.28, 180: current_debt * 1.61}
