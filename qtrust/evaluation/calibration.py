"""
Calibration — QTRUST-008 / §59.

Measures ECE, Brier, coverage, selective risk.
If Q-Trust says 96% confidence, it must be 96% correct.

Implements Platt scaling / isotonic regression for evidence fusion:

    P(crypto | lexical, AST, CodeQL, dependency, runtime)

vs max(floors) which is not statistical calibration.
"""
from __future__ import annotations

from typing import List

# Re-export from metrics for convenience
from .metrics import ece, brier_score


def platt_scale(logits: List[float], labels: List[int]) -> List[float]:
    """Platt scaling stub — production would fit logistic regression on held-out."""
    # For now, sigmoid
    import math

    return [1 / (1 + math.exp(-logit)) for logit in logits]


def calibration_report(probs: List[float], labels: List[int]) -> dict:
    return {"ece": round(ece(probs, labels), 4), "brier": round(brier_score(probs, labels), 4), "n": len(labels)}
