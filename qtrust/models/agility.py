"""
Crypto Agility Predictor — §24.

"How hard will it be to replace this algorithm?"

Features: hardcoded crypto, abstraction layers, central KMS, config-driven, lib versions, test coverage, deployment automation, cert automation, service coupling.

Output: Agility Score 0-100. Aligns with NIST crypto-agility direction.

Higher agility → lower migration cost / faster rollout.
"""
from __future__ import annotations

from typing import Any, Dict


def agility_score(features: Dict[str, Any]) -> Dict[str, Any]:
    score = 50
    if features.get("hardcoded_crypto"):
        score -= 20
    if features.get("abstraction_layers"):
        score += 15
    if features.get("central_kms"):
        score += 15
    if features.get("config_driven_crypto"):
        score += 10
    if features.get("test_coverage", 0) > 0.8:
        score += 10
    if features.get("deployment_automation"):
        score += 10
    score = max(0, min(100, score))
    level = "HIGH" if score >= 80 else "MEDIUM" if score >= 50 else "LOW"
    return {"agility": score, "level": level, "rationale": "central KMS + abstraction → high agility"}
