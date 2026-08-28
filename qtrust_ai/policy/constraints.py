"""
Policy constraints — machine-checkable, JSON-serialisable constraint schema.

Architecture reference: ``qtrust_ai/README.md`` §22 (Policy Reasoning).

Natural-language policies are parsed into :class:`PolicyConstraint` objects
(``qtrust_ai.policy.parser``) which the planner (``ConstrainedOptimizer``,
``MultiObjectiveRLAgent``) must respect. A constraint is deliberately simple
and JSON-serialisable so it can cross the trust boundary between the policy
engine and the optimiser:

    natural-language policy
        → PolicyConstraint (this module)   [machine-checkable]
        → OptimizerConfig / planner inputs [enforced]

Constraint types (spec §22 examples):

* ``maintenance_window`` — "No production migration during business hours"
  → allowed maintenance window (e.g. Sat 02:00-04:00).
* ``downtime_limit`` — "Payment API cannot be down > 5 minutes"
  → max downtime for an asset class.
* ``max_concurrent`` — "Critical systems: maximum 2 simultaneous migrations".
* ``vendor_restriction`` — "Vendor X PQC support unavailable until Q3".
* ``ordering`` — "Critical systems must migrate before non-critical systems".
* ``fips_only`` — "Only FIPS-approved implementations".
* ``mandatory_by`` — "Migrate <scope> by <year>" (e.g. CNSA 2.0 2030 / 2035).
* ``blocklist_algorithm`` — "No <algorithm> in new deployments".
* ``require_approval`` — "Requires <role> approval before migration".

Each constraint carries ``severity`` (hard = infeasible if violated,
soft = advisory / weighted in the RL reward) and the original ``source_text``
for auditability.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List

# Canonical constraint types
CONSTRAINT_TYPES: List[str] = [
    "maintenance_window",
    "downtime_limit",
    "max_concurrent",
    "vendor_restriction",
    "ordering",
    "fips_only",
    "mandatory_by",
    "blocklist_algorithm",
    "require_approval",
]


@dataclass
class PolicyConstraint:
    """One machine-checkable constraint derived from a policy statement.

    Attributes:
        constraint_type: One of :data:`CONSTRAINT_TYPES`.
        description: Short canonical description (e.g. ``payment ≤5m downtime``).
        params: Type-specific parameters (see ``param_schema`` below).
        severity: ``hard`` (violation → infeasible) or ``soft`` (weighted).
        source_text: Original natural-language statement (audit trail).
        id: Deterministic hash id.
    """

    constraint_type: str
    description: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    severity: str = "hard"
    source_text: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        if self.constraint_type not in CONSTRAINT_TYPES:
            # tolerate unknown types by keeping them soft (never silently block)
            self.severity = "soft"
        if not self.id:
            raw = f"{self.constraint_type}:{self.description}:{json.dumps(self.params, sort_keys=True)}"
            self.id = "pol-" + hashlib.sha256(raw.encode()).hexdigest()[:10]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PolicyConstraint":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# Human-readable param schema per type (documentation + validation)
PARAM_SCHEMA: Dict[str, Dict[str, str]] = {
    "maintenance_window": {
        "weekday": "int 0-6 (5 = Saturday)",
        "start_hour": "int 0-23",
        "end_hour": "int 0-23 (exclusive)",
    },
    "downtime_limit": {
        "max_minutes": "float — hard ceiling",
        "scope": "asset class or regex (e.g. 'payment')",
    },
    "max_concurrent": {
        "max": "int — simultaneous migrations",
        "scope": "asset class or 'all'",
    },
    "vendor_restriction": {
        "vendor": "vendor key (e.g. 'vendorA')",
        "available_from_month": "int 1-12 (7 = Q3)",
        "available_from_year": "optional int",
    },
    "ordering": {
        "first": "criticality/class that must go first (e.g. 'critical')",
        "second": "criticality/class that must follow (e.g. 'non-critical')",
    },
    "fips_only": {"mode": "'fips' | 'cnsa2' | 'cnsa1'"},
    "mandatory_by": {
        "scope": "asset class or 'all'",
        "year": "int deadline",
    },
    "blocklist_algorithm": {
        "algorithms": "list[str] — algorithms banned in new deployments",
        "scope": "asset class or 'all'",
    },
    "require_approval": {
        "role": "approver role (e.g. 'CISO')",
        "scope": "asset class or 'all'",
    },
}


@dataclass
class ConstraintSet:
    """A parsed policy: ordered, deduplicated constraints + stats.

    Attributes:
        constraints: Deduplicated constraints (by id).
        source_text: Original policy text.
        parse_warnings: Statements that matched no rule (for review).
    """

    constraints: List[PolicyConstraint] = field(default_factory=list)
    source_text: str = ""
    parse_warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._dedupe()

    def _dedupe(self) -> None:
        seen: set[str] = set()
        unique: List[PolicyConstraint] = []
        for c in self.constraints:
            if c.id not in seen:
                seen.add(c.id)
                unique.append(c)
        self.constraints = unique

    def by_type(self, constraint_type: str) -> List[PolicyConstraint]:
        return [c for c in self.constraints if c.constraint_type == constraint_type]

    def hard(self) -> List[PolicyConstraint]:
        return [c for c in self.constraints if c.severity == "hard"]

    def soft(self) -> List[PolicyConstraint]:
        return [c for c in self.constraints if c.severity == "soft"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "constraints": [c.to_dict() for c in self.constraints],
            "count": len(self.constraints),
            "hard": len(self.hard()),
            "soft": len(self.soft()),
            "parse_warnings": self.parse_warnings,
        }


if __name__ == "__main__":
    print("=== Policy constraints demo — machine-checkable JSON schema ===\n")
    cs = ConstraintSet(constraints=[
        PolicyConstraint(
            constraint_type="downtime_limit",
            description="payment ≤5m downtime",
            params={"max_minutes": 5.0, "scope": "payment"},
            source_text="Payment API cannot be down > 5 minutes",
        ),
        PolicyConstraint(
            constraint_type="maintenance_window",
            description="Sat 02:00-04:00 only",
            params={"weekday": 5, "start_hour": 2, "end_hour": 4},
            source_text="Production migration only Saturday 02:00-04:00",
        ),
    ])
    print(json.dumps(cs.to_dict(), indent=2))
    print(f"hard={len(cs.hard())} soft={len(cs.soft())}")
    assert cs.constraints[0].id.startswith("pol-")
    # round-trip
    back = ConstraintSet(constraints=[PolicyConstraint.from_dict(c.to_dict()) for c in cs.constraints])
    assert [c.id for c in back.constraints] == [c.id for c in cs.constraints]
    print("✓ constraint round-trip passed")
