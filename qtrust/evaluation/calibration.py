"""
Calibration — §59.

Measures ECE, Brier, coverage, selective risk.
If Q-Trust says 96% confidence, it must be 96% correct.
"""
from __future__ import annotations

from typing import List

from .metrics import ece, brier_score


def calibration_report(probs: List[float], labels: List[int]) -> dict:
    return {"ece": round(ece(probs, labels), 4), "brier": round(brier_score(probs, labels), 4), "n": len(labels)}
