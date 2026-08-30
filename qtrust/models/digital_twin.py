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
        """Scenario simulation — QTRUST-003 fix.

        DEMO fallback (clearly labeled) when no real enterprise state/graph/models
        are loaded. Production path requires:

        * Enterprise state (apps/services/dependencies from ``qtrust/models/graph``)
        * Constraint-aware planner (CP-SAT, see §25)
        * Calibrated cost/failure/interop models with intervals
        """
        if not self.history:
            return {
                "is_demo": True,
                "demo_warning": "Digital Twin DEMO — enterprise graph + CP-SAT + calibrated models required for production (QTRUST-003)",
                "predicted_risk": None,
                "predicted_cost_hours": None,
                "plan": plan,
                "note": "Ingest real scans via ingest_scan() to enable simulation",
            }
        # Production: apply plan to last known crypto knowledge graph state
        last = self.history[-1]
        # Dependency-aware: each migrated asset reduces risk proportionally to its
        # blast radius and business criticality (real graph would compute this)
        migrated_risk_reduction = sum(
            a.get("risk_score", 10) * 0.15 for a in last.assets if a.get("id") in plan
        )
        predicted = max(10, last.risk_score - migrated_risk_reduction)
        # Cost: sum of per-asset migration cost model intervals, not 8.5*steps
        # Here we keep the deterministic placeholder but label it and add interval
        base = len(plan) * 8.5
        return {
            "is_demo": True,  # still demo until cost model is wired to outcome dataset (§24)
            "predicted_risk": round(predicted, 1),
            "predicted_cost_hours": {"value": round(base, 1), "interval": [round(base * 0.7, 1), round(base * 1.4, 1)], "model_version": "DEMO-digital-twin-v0"},
            "plan": plan,
            "requires": "Wire MigrationCostPredictor trained on qtrust_data/gold/migration-outcomes/ for honest intervals",
        }

    def record_actual(self, predicted: Dict[str, Any], actual: Dict[str, Any]) -> Dict[str, Any]:
        """Closed-loop learning (§48): Prediction → Actual → Error → Retrain."""
        pred_cost = predicted.get("predicted_cost_hours", {}).get("value") if isinstance(predicted.get("predicted_cost_hours"), dict) else predicted.get("predicted_cost_hours")
        if pred_cost is None:
            return {"error": None, "needs_retrain": False, "note": "no prediction to compare (demo)"}
        error = actual["cost_hours"] - float(pred_cost)
        # Classification (§48): which feature was under-weighted?
        missing_feature = "HSM_PQC_SUPPORT" if error > 10 and "hsm" in str(actual) else None
        return {"error": round(error, 1), "needs_retrain": abs(error) > 5, "missing_feature_hint": missing_feature}

    def forecast_debt(self, days: int = 180) -> Dict[str, Any]:
        """Crypto Debt §24, §27 — deterministic demo, production needs historical trend + migration plan."""
        last = self.history[-1].crypto_debt_m if self.history else 1.8
        # Demo growth: would be learned from temporal GNN on real history (§45)
        value = round(last * (1 + days * 0.002), 2)
        return {"value": value, "unit": "M$", "is_demo": True, "model_version": "DEMO-debt-v0", "note": "Wire TemporalGNN on qtrust_data/gold/temporal for production"}
