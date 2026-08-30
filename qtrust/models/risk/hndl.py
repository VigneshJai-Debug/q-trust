"""
HNDL Risk — §23.

"How valuable is this encrypted data to an attacker if harvested today?"

Features: data classification, lifetime, encryption alg, key lifetime, storage, network exposure, attacker attractiveness, legal impact.
Output: CRITICAL etc.

NIST frames PQC migration around protecting data from future quantum attacks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class HNDLFeatures:
    data_classification: str  # public/internal/confidential/regulated
    data_lifetime_years: int  # 0-30
    algorithm: str
    key_lifetime_days: int
    storage_duration_years: float
    network_exposed: bool
    attacker_attractiveness: int  # 1-5


def hndl_risk(f: HNDLFeatures) -> Dict[str, Any]:
    score = 0
    if f.data_classification in ("regulated", "confidential"):
        score += 40
    if f.data_lifetime_years > 10:
        score += 30
    if "RSA" in f.algorithm or "ECDSA" in f.algorithm:
        score += 20
    if f.network_exposed:
        score += 10
    score = min(100, score + f.attacker_attractiveness * 3)
    level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW"
    return {"hndl_score": score, "level": level, "reason": f"{f.algorithm} + {f.data_lifetime_years}y lifetime + {f.data_classification}"}
