"""
Weak supervision — §26.

Labeling Functions (LFs) combine CodeQL, Semgrep, AST, dependency, rules.
Weak labels → training data. Human labels → validation/gold.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass
class LabelingFunction:
    name: str
    fn: Callable[[Dict[str, Any]], int]  # 1=crypto, 0=non-crypto, -1=abstain
    description: str


def lf_rsa_api(ctx: Dict[str, Any]) -> int:
    if "RSA.generate" in ctx.get("code", ""):
        return 1
    return -1


def lf_dependency_pycryptodome(ctx: Dict[str, Any]) -> int:
    if "pycryptodome" in ctx.get("dependencies", ""):
        return 1
    return -1


def lf_codeql_sink(ctx: Dict[str, Any]) -> int:
    if ctx.get("codeql_sink"):
        return 1
    return -1


def lf_readme_only(ctx: Dict[str, Any]) -> int:
    if ctx.get("file", "").endswith("README.md") and "RSA" in ctx.get("code", ""):
        return 0
    return -1


def lf_dead_code(ctx: Dict[str, Any]) -> int:
    if ctx.get("reachable") is False:
        return -1  # abstain, high uncertainty
    return -1


LABELS: List[LabelingFunction] = [
    LabelingFunction("LF_001_RSA_API", lf_rsa_api, "AST contains RSA.generate() → crypto"),
    LabelingFunction("LF_002_PYCRYPTODOME", lf_dependency_pycryptodome, "dependency=pycryptodome"),
    LabelingFunction("LF_003_CODEQL_SINK", lf_codeql_sink, "CodeQL sink"),
    LabelingFunction("LF_004_README", lf_readme_only, "RSA in README → non-crypto"),
    LabelingFunction("LF_005_DEAD_CODE", lf_dead_code, "dead code → abstain"),
]


def apply_lfs(candidate: Dict[str, Any]) -> Dict[str, Any]:
    votes: List[int] = []
    fired: List[str] = []
    for lf in LABELS:
        v = lf.fn(candidate)
        if v != -1:
            votes.append(v)
            fired.append(lf.name)
    # Majority vote; abstain if tie/empty
    if not votes:
        label = -1
        confidence = 0.0
    else:
        label = 1 if sum(votes) / len(votes) > 0.5 else 0
        confidence = max(votes.count(0), votes.count(1)) / len(votes)
    return {"weak_label": label, "confidence": confidence, "fired": fired, "votes": votes}


def is_weak_training_candidate(candidate: Dict[str, Any]) -> bool:
    """Only high-confidence weak labels go to training; low-confidence → active learning."""
    res = apply_lfs(candidate)
    return res["confidence"] >= 0.75 and res["weak_label"] != -1
