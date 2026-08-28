"""
qtrust_ai.policy — Policy Reasoning package (Phase 5 Interface).

Per ``qtrust_ai/README.md`` §22 (Policy Reasoning):

* :mod:`qtrust_ai.policy.constraints` — machine-checkable constraint schema
  (``PolicyConstraint`` / ``ConstraintSet``): maintenance windows, downtime
  limits, max-concurrent, vendor restrictions, ordering, FIPS-only, mandatory
  deadlines, algorithm blocklists, approvals. JSON-serialisable for crossing
  the trust boundary into the planner.
* :mod:`qtrust_ai.policy.parser` — deterministic natural-language parser:
  ``"Payment API cannot be down > 5 minutes"`` →
  ``downtime_limit {max_minutes: 5, scope: payment}``.
* :mod:`qtrust_ai.policy.engine` — :class:`PolicyEngine` enforces constraints
  on the planner: maps onto ``ConstrainedOptimizer.OptimizerConfig``,
  validates asset lists and produced schedules, and reports violations.

Pipeline (spec §22):

    natural-language policy → PolicyParser → ConstraintSet
        → PolicyEngine.apply_to_optimizer → OptimizerConfig (hard constraints)
        → PolicyEngine.check_assets / check_schedule → PolicyReport

Usage::

    from qtrust_ai.policy.engine import PolicyEngine

    engine = PolicyEngine(seed=42)
    cs = engine.parse("Payment API cannot be down > 5 minutes. "
                      "Production migration only Saturday 02:00-04:00.")
    config = engine.apply_to_optimizer(cs)   # planner now operates under policy
    report = engine.check_schedule(schedule, cs)

All parsing/checking is deterministic and CPU-friendly; the optimiser backend
(``ortools`` / ``pulp``) is optional with a heuristic fallback.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

try:
    from .constraints import PolicyConstraint, ConstraintSet, CONSTRAINT_TYPES
except ImportError:  # pragma: no cover
    PolicyConstraint = None  # type: ignore
    ConstraintSet = None  # type: ignore
    CONSTRAINT_TYPES = []  # type: ignore

try:
    from .parser import PolicyParser
except ImportError:  # pragma: no cover
    PolicyParser = None  # type: ignore

try:
    from .engine import PolicyEngine, PolicyReport, PolicyViolation
except ImportError:  # pragma: no cover
    PolicyEngine = None  # type: ignore
    PolicyReport = None  # type: ignore
    PolicyViolation = None  # type: ignore

__all__ = [
    "PolicyConstraint",
    "ConstraintSet",
    "CONSTRAINT_TYPES",
    "PolicyParser",
    "PolicyEngine",
    "PolicyReport",
    "PolicyViolation",
]

__version__: str = "5.0.0-policy"
POLICY_MODULES: List[str] = [
    "qtrust_ai.policy.constraints",
    "qtrust_ai.policy.parser",
    "qtrust_ai.policy.engine",
]

# Spec §22 example policies (used in docs / evaluation)
EXAMPLE_POLICIES: List[str] = [
    "Critical systems must migrate before non-critical systems.",
    "No production migration during business hours.",
    "Only FIPS-approved implementations.",
    "Payment API cannot be down > 5 minutes.",
    "Vendor X PQC support unavailable until Q3.",
]


def get_policy_info() -> Dict[str, Any]:
    """Return package metadata for health checks."""
    return {
        "package": "qtrust_ai.policy",
        "version": __version__,
        "phase": "5 Interface",
        "modules": POLICY_MODULES,
        "constraint_types": list(CONSTRAINT_TYPES or []),
        "example_policies": EXAMPLE_POLICIES,
        "architecture_doc": "qtrust_ai/README.md",
        "has_parser": PolicyParser is not None,
        "has_engine": PolicyEngine is not None,
    }


if __name__ == "__main__":
    print("=== qtrust_ai.policy package demo ===")
    print(json.dumps(get_policy_info(), indent=2))
    if PolicyEngine is not None and PolicyParser is not None:
        engine = PolicyEngine(seed=42)  # type: ignore
        cs = engine.parse("Payment API cannot be down more than 5 minutes. "
                          "Critical systems: maximum 2 simultaneous migrations.")  # type: ignore
        print(f"\nparsed {len(cs.constraints)} constraints:")
        for c in cs.constraints:
            print(f"  [{c.constraint_type:18s}] {c.description}")
        if engine.apply_to_optimizer is not None:
            try:
                cfg = engine.apply_to_optimizer(cs)  # type: ignore
                print(f"\noptimizer config: max_simultaneous={cfg.max_simultaneous}, payment≤{cfg.payment_api_max_downtime_minutes}m")
            except RuntimeError as e:
                print(f"\noptimizer config unavailable: {e}")
    else:
        print("policy not importable (missing dependencies)")
