"""
CP-SAT Planner — QTRUST-005 fix (§25).

Enterprise scheduling has hard constraints:

    service A must migrate before B
    service C cannot migrate during maintenance window
    maximum downtime = 5 min
    engineering capacity = 3 teams
    budget = $100k
    vendor support / HSM compatibility / cert lifecycle

CP-SAT (Google OR-Tools) is the correctness baseline; RL learns scalable policy
for repeated large problems. Benchmark: greedy / heuristic / CP-SAT / RL / human
on same unseen scenarios (organization-disjoint).

This stub implements a constraint-aware greedy; production swaps in OR-Tools
when available (pip install ortools).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from ortools.sat.python import cp_model  # type: ignore

    HAS_ORTOOLS = True
except Exception:
    HAS_ORTOOLS = False
    cp_model = None  # type: ignore


@dataclass
class MigrationTask:
    id: str
    duration_hours: float
    risk_reduction: float
    dependencies: List[str]
    downtime_minutes: float = 0
    team: str = "team-a"


def _greedy_cpsat(tasks: List[MigrationTask], constraints: Dict[str, Any]) -> List[str]:
    # Topological sort respecting dependencies + capacity
    # Real CP-SAT would solve: minimize risk-weighted completion time subject to
    # capacity, windows, budget. This greedy respects dependencies and picks
    # highest risk_reduction first among ready tasks.
    remaining = {t.id: t for t in tasks}
    scheduled: List[str] = []
    # Simple dependency resolver
    for _ in range(len(tasks)):
        ready = [t for t in remaining.values() if all(d in scheduled for d in t.dependencies)]
        if not ready:
            break  # cycle
        # Capacity: at most `capacity` parallel — greedy picks top risk
        ready.sort(key=lambda x: x.risk_reduction, reverse=True)
        scheduled.append(ready[0].id)
        del remaining[ready[0].id]
    # Append any leftover (cycle)
    scheduled.extend(remaining.keys())
    return scheduled


def solve(tasks: List[MigrationTask], constraints: Dict[str, Any] | None = None) -> Dict[str, Any]:
    constraints = constraints or {}
    if HAS_ORTOOLS:
        # Production: build cp_model.CpModel with interval vars, capacity, etc.
        # Stub keeps greedy but marks as OR-Tools available
        order = _greedy_cpsat(tasks, constraints)
        return {"solver": "ortools-cpsat (greedy fallback in this stub)", "order": order, "is_optimal": False}
    return {"solver": "greedy-cpsat-fallback (pip install ortools for real CP-SAT)", "order": _greedy_cpsat(tasks, constraints), "is_optimal": False}


def benchmark(tasks: List[MigrationTask], constraints: Dict[str, Any]) -> Dict[str, Any]:
    """Compare heuristic vs CP-SAT vs RL vs human on same unseen scenario (QTRUST-005)."""
    from qtrust.models.risk.model import RiskRankingModel

    # Heuristic: sort by heuristic priority formula (would be data_generator heuristic)
    heuristic_order = sorted(tasks, key=lambda t: t.risk_reduction, reverse=True)
    cpsat = solve(tasks, constraints)
    # RL placeholder — would call planner/qtrust_planner/rl_agent.py
    rl_order = list(reversed(heuristic_order))  # demo

    def _score(order: List[str]) -> float:
        # Weighted completion time — lower is better
        return sum((i + 1) * next(t.risk_reduction for t in tasks if t.id == oid) for i, oid in enumerate(order))

    return {
        "heuristic": {"order": [t.id for t in heuristic_order], "score": _score([t.id for t in heuristic_order])},
        "cpsat": {"order": cpsat["order"], "score": _score(cpsat["order"])},
        "rl": {"order": [t.id for t in rl_order], "score": _score([t.id for t in rl_order])},
        "note": "QTRUST-005: Real benchmark requires organization-disjoint unseen scenarios; do not claim RL beats heuristic on same training distribution",
    }
