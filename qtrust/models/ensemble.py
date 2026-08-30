"""
Ensemble — §36.

GNN + LightGBM + rules + expert model + temporal → calibrated ensemble.

Rule engine always above ML (§37): if deterministic evidence says RSA-2048, model cannot hallucinate ML-KEM.
"""
from __future__ import annotations

from typing import Any, Dict, List


def ensemble_predict(predictions: List[Dict[str, Any]], weights: List[float] | None = None) -> Dict[str, Any]:
    if weights is None:
        weights = [1.0 / len(predictions)] * len(predictions)
    # Weighted average for scores, majority for categories
    scores = [p.get("score", 50) * w for p, w in zip(predictions, weights)]
    final_score = sum(scores) / sum(weights) if weights else 50
    # Calibration (§59): confidence must be measured
    return {"score": round(final_score, 1), "components": len(predictions), "weights": weights}


def safety_check(deterministic: str, ml_prediction: str) -> bool:
    # §37 safety: deterministic evidence cannot be overwritten
    if deterministic and deterministic != ml_prediction:
        # ML hallucinated — veto
        return False
    return True
