"""
Expert labeling — §10, §12.

QTrust-RiskBench: Assets 100k+, Comparisons 1M+, Experts 20-50+, Domains finance/healthcare/gov/cloud.

Each sample: asset_a, asset_b, preference, expert_confidence, domain.

Pairwise preference data beats predicting risk=87.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class ExpertPreference:
    asset_a: str
    asset_b: str
    preference: str  # asset_a or asset_b
    expert_confidence: float
    domain: str
    expert_id: str
    rationale: str = ""


def load_expert_bench(path: Path) -> List[ExpertPreference]:
    data = json.loads(path.read_text())
    return [ExpertPreference(**d) for d in data]


def write_expert_bench(prefs: List[ExpertPreference], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([asdict(p) for p in prefs], indent=2))
