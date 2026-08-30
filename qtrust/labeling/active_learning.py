"""
Active learning loop — §27-28.

Model → uncertain samples → human labels → retrain → repeat.
Stores explanations for future training.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class ActiveSample:
    code: str
    language: str
    model_confidence: float
    entropy: float
    priority: float  # low confidence = high priority


def uncertainty_priority(confidence: float) -> float:
    # confidence 0.5 → priority 1.0, 0.99→0.02
    return 1.0 - abs(confidence - 0.5) * 2


def select_for_labeling(
    predictions: List[Dict[str, Any]], budget: int = 100
) -> List[Dict[str, Any]]:
    scored: List[Dict[str, Any]] = []
    for p in predictions:
        conf = float(p.get("confidence", 0.5))
        # Custom crypto near 51% or dynamic reflection 53% → human review
        priority = uncertainty_priority(conf)
        # Boost vendored/dynamic cases
        if any(kw in p.get("code", "") for kw in ("importlib", "my_crypto", "Wrapper")):
            priority = min(1.0, priority + 0.3)
        scored.append({**p, "priority": priority})
    scored.sort(key=lambda x: x["priority"], reverse=True)
    return scored[:budget]


def record_human_label(
    sample: Dict[str, Any], label: str, explanation: str, expert_id: str
) -> Dict[str, Any]:
    return {
        "sample_hash": hashlib.sha256(sample.get("code", "").encode()).hexdigest()[:16],
        "label": label,  # TRUE_POSITIVE | FALSE_POSITIVE | UNCERTAIN
        "explanation": explanation,
        "expert": expert_id,
        "language": sample.get("language"),
        "algorithm": sample.get("algorithm"),
    }
