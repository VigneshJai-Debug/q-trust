"""
QTrustMetricSuite — the killer metric suite (spec §27).

Composes :mod:`qtrust_ai.metrics.core` into the six domain reports the
README promises, so Q-Trust is evaluated like a research system, not a demo:

    Discovery   P/R/F1/FN-rate/coverage
    Risk        AUROC / AUPRC / Brier / ECE
    Ranking     Kendall τ / Spearman ρ / NDCG@K / P@K / R@K
    Migration   cost MAE / duration MAE / failure AUROC
    Interop     compatibility accuracy / latency error
    Planner     risk-reduction/$ , risk-reduction/engineer-hour, downtime,
                completion time

Each report is a JSON-serialisable dict; :meth:`full_report` returns them all
plus the source count so dashboards / CI gates can consume one object.

Example:
    from qtrust_ai.metrics.suite import QTrustMetricSuite

    suite = QTrustMetricSuite()
    report = suite.full_report(
        discovery=(y_true, y_pred), risk=(y_true, y_prob),
        ranking=(relevance, scores, 10), migration=(cost_actual, cost_pred,
        duration_actual, duration_pred, fail_true, fail_score),
        interop=(compat_true, compat_pred, latency_actual, latency_pred),
        planner=[{"risk_reduction": 12.0, "cost_usd": 10000, "eng_hours": 60,
                  "downtime_minutes": 30, "duration_days": 12}],
    )
    assert "ranking" in report and report["ranking"]["kendall_tau"] > 0
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Sequence, Tuple

from qtrust_ai.metrics.core import (
    accuracy,
    auprc,
    auroc,
    brier_score,
    coverage,
    expected_calibration_error,
    false_negative_rate,
    kendall_tau,
    mae,
    mape,
    ndcg_at_k,
    precision_at_k,
    precision_recall_f1,
    recall_at_k,
    rmse,
    spearman_rho,
)


class QTrustMetricSuite:
    """Composable metric reports per the §27 evaluation framework."""

    # -- discovery ----------------------------------------------------------

    def discovery_report(
        self,
        y_true: Sequence[int],
        y_pred: Sequence[int],
        total_inventory: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Precision / Recall / F1 / FNR / Coverage (spec §27 discovery)."""
        p, r, f = precision_recall_f1(y_true, y_pred)
        cov = coverage(sum(1 for t in y_true if t == 1), total_inventory or len(y_true))
        return {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f), 4),
            "false_negative_rate": round(float(false_negative_rate(y_true, y_pred)), 4),
            "coverage": round(float(cov), 4),
            "n": len(y_true),
        }

    # -- risk ---------------------------------------------------------------

    def risk_report(self, y_true: Sequence[int], y_prob: Sequence[float]) -> Dict[str, Any]:
        """AUROC / AUPRC / Brier / ECE (spec §27 risk)."""
        return {
            "auroc": round(float(auroc(y_true, y_prob)), 4),
            "auprc": round(float(auprc(y_true, y_prob)), 4),
            "brier": round(float(brier_score([float(t) for t in y_true], [float(p) for p in y_prob])), 4),
            "ece": round(float(expected_calibration_error(y_true, y_prob)), 4),
            "n": len(y_true),
        }

    # -- ranking ------------------------------------------------------------

    def ranking_report(
        self,
        ground_truth: Sequence[float],
        predicted_scores: Sequence[float],
        k: int = 10,
        relevance: Optional[Sequence[int]] = None,
    ) -> Dict[str, Any]:
        """Kendall τ / Spearman ρ / NDCG@K / P@K / R@K (spec §27 ranking)."""
        rel = list(relevance) if relevance is not None else [1 if g > 0 else 0 for g in ground_truth]
        return {
            "kendall_tau": round(float(kendall_tau(ground_truth, predicted_scores)), 4),
            "spearman_rho": round(float(spearman_rho(ground_truth, predicted_scores)), 4),
            f"ndcg@{k}": round(float(ndcg_at_k(ground_truth, predicted_scores, k)), 4),
            f"precision@{k}": round(float(precision_at_k(rel, predicted_scores, k)), 4),
            f"recall@{k}": round(float(recall_at_k(rel, predicted_scores, k)), 4),
            "k": k,
            "n": len(ground_truth),
        }

    # -- migration ----------------------------------------------------------

    def migration_report(
        self,
        cost_actual: Sequence[float],
        cost_pred: Sequence[float],
        duration_actual: Sequence[float],
        duration_pred: Sequence[float],
        failure_true: Sequence[int],
        failure_score: Sequence[float],
    ) -> Dict[str, Any]:
        """Cost MAE / duration MAE / failure AUROC (spec §27 migration)."""
        return {
            "cost_mae_hours": round(float(mae(cost_actual, cost_pred)), 3),
            "cost_rmse_hours": round(float(rmse(cost_actual, cost_pred)), 3),
            "duration_mae_days": round(float(mae(duration_actual, duration_pred)), 3),
            "failure_auroc": round(float(auroc(failure_true, failure_score)), 4),
            "failure_auprc": round(float(auprc(failure_true, failure_score)), 4),
            "n": len(cost_actual),
        }

    # -- interop ------------------------------------------------------------

    def interop_report(
        self,
        compat_true: Sequence[int],
        compat_pred: Sequence[int],
        latency_actual: Sequence[float],
        latency_pred: Sequence[float],
    ) -> Dict[str, Any]:
        """Compatibility accuracy + latency prediction error (§27 interop)."""
        return {
            "compat_accuracy": round(float(accuracy(compat_true, compat_pred)), 4),
            "latency_mae_percent": round(float(mae(latency_actual, latency_pred)), 3),
            "latency_mape_percent": round(float(mape(latency_actual, latency_pred) * 100), 3),
            "n": len(compat_true),
        }

    # -- planner ------------------------------------------------------------

    def planner_report(self, plans: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        """Risk-reduction efficiency + downtime + completion (spec §27 planner).

        Each plan: ``{"risk_reduction": float, "cost_usd": float,
        "eng_hours": float, "downtime_minutes": float, "duration_days": float}``.
        """
        if not plans:
            return {"plans": 0, "risk_reduction_per_usd": 0.0, "risk_reduction_per_hour": 0.0,
                    "total_downtime_minutes": 0.0, "completion_days": 0.0, "n": 0}
        total_cost = sum(float(p.get("cost_usd", 0)) for p in plans)
        total_hours = sum(float(p.get("eng_hours", 0)) for p in plans)
        total_risk = sum(float(p.get("risk_reduction", 0)) for p in plans)
        return {
            "risk_reduction_per_usd": round(total_risk / total_cost, 6) if total_cost else 0.0,
            "risk_reduction_per_engineer_hour": round(total_risk / total_hours, 6) if total_hours else 0.0,
            "total_downtime_minutes": round(float(sum(p.get("downtime_minutes", 0) for p in plans)), 2),
            "completion_days": round(float(max(p.get("duration_days", 0) for p in plans)), 2),
            "n": len(plans),
        }

    # -- combined -----------------------------------------------------------

    def full_report(
        self,
        discovery: Optional[Tuple[Sequence[int], Sequence[int]]] = None,
        risk: Optional[Tuple[Sequence[int], Sequence[float]]] = None,
        ranking: Optional[Tuple[Sequence[float], Sequence[float], int]] = None,
        migration: Optional[Tuple[Sequence[float], Sequence[float], Sequence[float], Sequence[float], Sequence[int], Sequence[float]]] = None,
        interop: Optional[Tuple[Sequence[int], Sequence[int], Sequence[float], Sequence[float]]] = None,
        planner: Optional[Sequence[Dict[str, Any]]] = None,
        discovery_total_inventory: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Compute every domain report and return one combined JSON object."""
        report: Dict[str, Any] = {}
        if discovery is not None:
            report["discovery"] = self.discovery_report(discovery[0], discovery[1], discovery_total_inventory)
        if risk is not None:
            report["risk"] = self.risk_report(risk[0], risk[1])
        if ranking is not None:
            report["ranking"] = self.ranking_report(ranking[0], ranking[1], ranking[2] if len(ranking) > 2 else 10)
        if migration is not None:
            report["migration"] = self.migration_report(*migration)
        if interop is not None:
            report["interop"] = self.interop_report(*interop)
        if planner is not None:
            report["planner"] = self.planner_report(planner)
        report["n_reports"] = len(report)
        return report

    def report_json(self, **kwargs: Any) -> str:
        """JSON string of :meth:`full_report`."""
        return json.dumps(self.full_report(**kwargs), indent=2)


if __name__ == "__main__":
    print("=== QTrustMetricSuite demo — killer metric suite (§27) ===\n")
    suite = QTrustMetricSuite()
    report = suite.full_report(
        discovery=([1, 0, 1, 1, 0, 1], [1, 0, 1, 0, 0, 1]),
        risk=([1, 0, 1, 1, 0, 1], [0.9, 0.1, 0.8, 0.4, 0.2, 0.7]),
        ranking=([3.0, 2.0, 3.0, 0.0, 1.0, 2.0], [0.9, 0.5, 0.95, 0.1, 0.3, 0.6], 3),
        migration=([84.0, 31.0, 12.0], [80.0, 33.0, 11.0], [12.0, 6.0, 4.0], [11.0, 6.0, 5.0],
                   [1, 0, 1], [0.8, 0.2, 0.7]),
        interop=([1, 1, 0], [1, 1, 0], [4.8, 3.2, 9.0], [4.9, 3.0, 8.5]),
        planner=[
            {"risk_reduction": 12.0, "cost_usd": 10000, "eng_hours": 60, "downtime_minutes": 30, "duration_days": 12},
            {"risk_reduction": 8.0, "cost_usd": 6000, "eng_hours": 40, "downtime_minutes": 15, "duration_days": 8},
        ],
    )
    print(json.dumps(report, indent=2))
    assert report["discovery"]["f1"] > 0.5
    assert report["risk"]["auroc"] > 0.5
    assert report["ranking"]["kendall_tau"] > 0.5
    assert report["migration"]["failure_auroc"] > 0.5
    assert report["interop"]["compat_accuracy"] >= 0.9
    assert report["planner"]["risk_reduction_per_usd"] > 0.0
    print("\n✓ all six §27 metric domains computed")
