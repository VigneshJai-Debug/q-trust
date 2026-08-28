"""
Policy engine — enforce policy constraints on the migration planner.

Architecture reference: ``qtrust_ai/README.md`` §22 (Policy Reasoning).

The engine converts a parsed :class:`ConstraintSet` into what the planner
actually consumes:

* :meth:`PolicyEngine.apply_to_optimizer` — map constraints onto
  :class:`qtrust_ai.migration.constrained_optimizer.OptimizerConfig`
  (window, downtime limit, max concurrent, vendor Q3).
* :meth:`PolicyEngine.check_assets` — validate a migration asset list against
  ordering / downtime / vendor / blocklist / approval constraints *before*
  scheduling.
* :meth:`PolicyEngine.check_schedule` — validate a produced schedule
  (``ScheduleResult``) and report violations.

Pipeline:

    policy text → PolicyParser → ConstraintSet
        → PolicyEngine.apply_to_optimizer → OptimizerConfig (hard constraints)
        → PolicyEngine.check_assets / check_schedule → PolicyReport

The RL planner's reward also consumes soft constraints (``severity == "soft"``)
as penalties — see :mod:`qtrust_ai.migration.multi_objective_rl`.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from qtrust_ai.policy.constraints import ConstraintSet
from qtrust_ai.policy.parser import PolicyParser

try:
    from qtrust_ai.migration.constrained_optimizer import (  # type: ignore
        MigrationAsset,
        OptimizerConfig,
        ScheduleResult,
    )
    HAS_OPTIMIZER = True
except Exception:  # pragma: no cover
    MigrationAsset = None  # type: ignore
    OptimizerConfig = None  # type: ignore
    ScheduleResult = None  # type: ignore
    HAS_OPTIMIZER = False


@dataclass
class PolicyViolation:
    """One policy violation found during checking."""

    constraint_type: str
    message: str
    asset_id: str = ""
    severity: str = "hard"
    constraint_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyReport:
    """Result of checking assets / schedule against a constraint set."""

    compliant: bool
    violations: List[PolicyViolation] = field(default_factory=list)
    checked: int = 0
    constraint_count: int = 0
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compliant": self.compliant,
            "violations": [v.to_dict() for v in self.violations],
            "checked": self.checked,
            "constraint_count": self.constraint_count,
            "warnings": self.warnings,
        }


class PolicyEngine:
    """Enforce parsed policy constraints on the migration planner.

    Attributes:
        parser: :class:`PolicyParser` used by :meth:`parse`.
        seed: Random seed (deterministic checks; no randomness used).

    Example:
        >>> engine = PolicyEngine(seed=0)
        >>> cs = engine.parse("Payment API cannot be down > 5 minutes. "
        ...                   "Critical systems: maximum 2 simultaneous migrations.")
        >>> assets = [MigrationAsset(id="payment-api", downtime_minutes=3, criticality="critical"),
        ...           MigrationAsset(id="analytics", downtime_minutes=9)]
        >>> report = engine.check_assets(assets, cs)
        >>> report.violations  # payment-api ok, analytics blocked? no — analytics not in scope
        []
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self.parser = PolicyParser(seed=seed)
        random.seed(seed)
        self.is_trained = False

    # -- parsing ------------------------------------------------------------

    def parse(self, policy_text: str) -> ConstraintSet:
        """Parse policy text into a constraint set (delegates to parser)."""
        return self.parser.parse(policy_text)

    # -- optimizer integration ----------------------------------------------

    def apply_to_optimizer(self, cs: ConstraintSet, config: Optional[Any] = None) -> Any:
        """Map constraints onto an :class:`OptimizerConfig`.

        Args:
            cs: Parsed constraints.
            config: Existing :class:`OptimizerConfig` to mutate (or ``None``
                to start from defaults).

        Returns:
            :class:`OptimizerConfig` with constraint-derived fields set.
        """
        if not HAS_OPTIMIZER or OptimizerConfig is None:
            raise RuntimeError("qtrust_ai.migration.constrained_optimizer not importable")
        cfg = config or OptimizerConfig(seed=self.seed)
        for c in cs.constraints:
            if c.severity != "hard":
                continue
            p = c.params
            if c.constraint_type == "maintenance_window":
                cfg.allowed_window_weekday = int(p.get("weekday", 5))
                cfg.allowed_window_start_hour = int(p.get("start_hour", 2))
                cfg.allowed_window_end_hour = int(p.get("end_hour", 4))
            elif c.constraint_type == "downtime_limit":
                if "payment" in str(p.get("scope", "")).lower():
                    cfg.payment_api_max_downtime_minutes = float(p.get("max_minutes", 5.0))
            elif c.constraint_type == "max_concurrent":
                cfg.max_simultaneous = max(1, int(p.get("max", 2)))
            elif c.constraint_type == "vendor_restriction":
                cfg.vendor_unavailable_until_month = int(p.get("available_from_month", 7))
                cfg.vendor_unavailable_until_year = int(p["available_from_year"]) if p.get("available_from_year") else None
        return cfg

    # -- asset / schedule checking ------------------------------------------

    def check_assets(self, assets: List[Any], cs: ConstraintSet) -> PolicyReport:
        """Check a migration asset list against constraints (pre-scheduling).

        Checks (per constraint type):

        * ``downtime_limit`` — scope-matched assets exceeding ``max_minutes``.
        * ``vendor_restriction`` — vendor assets flagged for Q3 gate.
        * ``ordering`` — critical assets must appear before non-critical in the
          input order (planner will re-order; this validates the *input* list).
        * ``blocklist_algorithm`` — asset algorithm in the banned set.
        * ``require_approval`` — scope assets must carry ``approved_by``.

        Args:
            assets: List of :class:`MigrationAsset`-compatible objects.
            cs: Constraint set.

        Returns:
            :class:`PolicyReport` with violations.
        """
        violations: List[PolicyViolation] = []
        hard = cs.hard()
        for c in hard:
            p = c.params
            if c.constraint_type == "downtime_limit":
                scope = str(p.get("scope", "all")).lower()
                limit = float(p.get("max_minutes", 5.0))
                for a in assets:
                    if scope != "all" and scope not in str(a.id).lower():
                        continue
                    dt = float(getattr(a, "downtime_minutes", 0) or 0)
                    if dt > limit + 1e-9:
                        violations.append(PolicyViolation(
                            "downtime_limit",
                            f"{a.id} downtime {dt:.1f}m > policy limit {limit:.1f}m",
                            asset_id=str(a.id), severity="hard", constraint_id=c.id,
                        ))
            elif c.constraint_type == "vendor_restriction":
                vendor = str(p.get("vendor", "vendorX")).lower()
                for a in assets:
                    if vendor in str(getattr(a, "vendor", "")).lower():
                        violations.append(PolicyViolation(
                            "vendor_restriction",
                            f"{a.id} depends on {vendor} (PQC unavailable until Q{p.get('available_from_month', 7) // 3 + 1})",
                            asset_id=str(a.id), severity="hard", constraint_id=c.id,
                        ))
            elif c.constraint_type == "blocklist_algorithm":
                banned = [str(x).upper() for x in p.get("algorithms", [])]
                for a in assets:
                    algo = str(getattr(a, "algorithm", "") or "").upper()
                    if any(b in algo for b in banned):
                        violations.append(PolicyViolation(
                            "blocklist_algorithm",
                            f"{a.id} uses banned algorithm {algo}",
                            asset_id=str(a.id), severity="hard", constraint_id=c.id,
                        ))
            elif c.constraint_type == "require_approval":
                scope = str(p.get("scope", "all")).lower()
                for a in assets:
                    if scope != "all" and scope not in str(a.id).lower():
                        continue
                    approved = getattr(a, "approved_by", None)
                    if not approved:
                        violations.append(PolicyViolation(
                            "require_approval",
                            f"{a.id} lacks {p.get('role', 'CISO')} approval",
                            asset_id=str(a.id), severity="hard", constraint_id=c.id,
                        ))

        if any(c.constraint_type == "ordering" for c in hard):
            crit_seen = False
            for a in assets:
                crit = str(getattr(a, "criticality", "medium")).lower() in ("high", "critical")
                if crit:
                    crit_seen = True
                elif crit_seen and str(getattr(a, "criticality", "medium")).lower() in ("low", "medium"):
                    violations.append(PolicyViolation(
                        "ordering",
                        f"non-critical {a.id} scheduled before critical assets complete",
                        asset_id=str(a.id), severity="hard",
                        constraint_id=next((c.id for c in hard if c.constraint_type == "ordering"), ""),
                    ))

        return PolicyReport(
            compliant=not violations,
            violations=violations,
            checked=len(assets),
            constraint_count=len(cs.constraints),
            warnings=list(cs.parse_warnings),
        )

    def check_schedule(self, schedule: Any, cs: ConstraintSet) -> PolicyReport:
        """Check a produced :class:`ScheduleResult` against constraints.

        Verifies the schedule entries respect the maintenance window and the
        max-concurrent limit (the two constraints a schedule must satisfy).

        Args:
            schedule: :class:`ScheduleResult` from the constrained optimizer.
            cs: Constraint set.

        Returns:
            :class:`PolicyReport`.
        """
        violations: List[PolicyViolation] = []
        entries = getattr(schedule, "schedule", []) or []
        for c in cs.hard():
            p = c.params
            if c.constraint_type == "maintenance_window":
                weekday = int(p.get("weekday", 5))
                sh = int(p.get("start_hour", 2))
                eh = int(p.get("end_hour", 4))
                for e in entries:
                    start = getattr(e, "start", None)
                    if start is None:
                        continue
                    if start.weekday() != weekday or not (sh <= start.hour < eh):
                        violations.append(PolicyViolation(
                            "maintenance_window",
                            f"{e.asset_id} starts {start.isoformat()} outside window "
                            f"weekday={weekday} {sh:02d}:00-{eh:02d}:00",
                            asset_id=str(e.asset_id), severity="hard", constraint_id=c.id,
                        ))
            elif c.constraint_type == "max_concurrent":
                mx = int(p.get("max", 2))
                starts: Dict[str, int] = {}
                for e in entries:
                    key = str(getattr(getattr(e, "start", None), "date", lambda: "")()) if hasattr(getattr(e, "start", None), "date") else str(e.asset_id)
                    starts[key] = starts.get(key, 0) + 1
                for key, n in starts.items():
                    if n > mx:
                        violations.append(PolicyViolation(
                            "max_concurrent",
                            f"{n} migrations on {key} > policy limit {mx}",
                            asset_id=key, severity="hard", constraint_id=c.id,
                        ))
            elif c.constraint_type == "downtime_limit":
                scope = str(p.get("scope", "all")).lower()
                limit = float(p.get("max_minutes", 5.0))
                for e in entries:
                    if scope != "all" and scope not in str(e.asset_id).lower():
                        continue
                    dt = float(getattr(e, "downtime_minutes", 0) or 0)
                    if dt > limit + 1e-9:
                        violations.append(PolicyViolation(
                            "downtime_limit",
                            f"{e.asset_id} downtime {dt:.1f}m > policy limit {limit:.1f}m",
                            asset_id=str(e.asset_id), severity="hard", constraint_id=c.id,
                        ))

        return PolicyReport(
            compliant=not violations,
            violations=violations,
            checked=len(entries),
            constraint_count=len(cs.constraints),
            warnings=list(cs.parse_warnings),
        )

    # -- API-consistency stubs ----------------------------------------------

    def train(self, dataset: Optional[List[Dict[str, Any]]] = None, epochs: int = 3) -> Dict[str, Any]:
        """No-op training — the engine is deterministic rules.

        Reports the rule table size and whether the optimizer backend loaded.
        """
        self.is_trained = True
        from qtrust_ai.policy.parser import _RULES  # type: ignore
        return {
            "mode": "deterministic-rules",
            "rules": len(_RULES),
            "constraint_types": sorted({r.constraint_type for r in _RULES}),
            "optimizer_backend": bool(HAS_OPTIMIZER),
        }

    def evaluate(self, dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Evaluate parser accuracy on labelled NL→constraint-type pairs.

        Args:
            dataset: List of ``{"text": str, "expect": [constraint_type, ...]}``.
                If ``None`` a built-in anchor set (spec §22 examples) is used.

        Returns:
            Dict with ``passed``, ``total``, ``accuracy``, ``expected_types``.
        """
        if dataset is None:
            dataset = [
                {"text": "Payment API cannot be down more than 5 minutes.", "expect": ["downtime_limit"]},
                {"text": "Production migration only Saturday 02:00-04:00.", "expect": ["maintenance_window"]},
                {"text": "Critical systems: maximum 2 simultaneous migrations.", "expect": ["max_concurrent"]},
                {"text": "Vendor X PQC support unavailable until Q3.", "expect": ["vendor_restriction"]},
                {"text": "Critical systems must migrate before non-critical systems.", "expect": ["ordering"]},
                {"text": "Only FIPS-approved implementations.", "expect": ["fips_only"]},
                {"text": "Migrate all production systems by 2030.", "expect": ["mandatory_by"]},
                {"text": "No RSA in new deployments.", "expect": ["blocklist_algorithm"]},
                {"text": "Requires CISO approval before migration.", "expect": ["require_approval"]},
            ]
        passed = 0
        expected_types = sorted({t for ex in dataset for t in ex["expect"]})
        for ex in dataset:
            cs = self.parse(ex["text"])
            got = {c.constraint_type for c in cs.constraints}
            if set(ex["expect"]) <= got:
                passed += 1
        total = len(dataset)
        return {
            "passed": passed,
            "total": total,
            "accuracy": round(passed / total, 3) if total else 0.0,
            "expected_types": expected_types,
        }


if __name__ == "__main__":
    print("=== PolicyEngine demo — enforce policy on the constrained planner ===\n")
    engine = PolicyEngine(seed=42)
    print(f"[train] {json.dumps(engine.train(), indent=2)}\n")

    policy = (
        "Payment API cannot be down more than 5 minutes. "
        "Production migration only Saturday 02:00-04:00. "
        "Critical systems: maximum 2 simultaneous migrations. "
        "Vendor X PQC support unavailable until Q3."
    )
    cs = engine.parse(policy)
    print(f"[parse] {len(cs.constraints)} constraints")
    for c in cs.constraints:
        print(f"  {c.description}")

    # Map onto the constrained optimizer config (hard constraints per §13/§22)
    if HAS_OPTIMIZER and OptimizerConfig is not None:
        cfg = engine.apply_to_optimizer(cs)
        print(f"\n[optimizer config] window Sat {cfg.allowed_window_start_hour:02d}-{cfg.allowed_window_end_hour:02d}, "
              f"max_simultaneous={cfg.max_simultaneous}, payment≤{cfg.payment_api_max_downtime_minutes}m, "
              f"vendor Q{cfg.vendor_unavailable_until_month // 3 + 1}")
        assert cfg.allowed_window_weekday == 5 and cfg.max_simultaneous == 2
        assert abs(cfg.payment_api_max_downtime_minutes - 5.0) < 1e-9
        assert cfg.vendor_unavailable_until_month == 7

        # End-to-end: parse → config → optimize → check
        from qtrust_ai.migration.constrained_optimizer import ConstrainedOptimizer, MigrationAsset
        from datetime import datetime
        opt = ConstrainedOptimizer(config=cfg, seed=42)
        assets = [
            MigrationAsset(id="payment-api", priority=0.95, duration_hours=2, downtime_minutes=3, criticality="critical"),
            MigrationAsset(id="auth-service", priority=0.90, duration_hours=3, downtime_minutes=4, criticality="high"),
            MigrationAsset(id="analytics", priority=0.40, duration_hours=2, downtime_minutes=6, criticality="low"),
            MigrationAsset(id="vendor-hsm", priority=0.70, duration_hours=4, downtime_minutes=4, vendor="vendorX"),
        ]
        res = opt.optimize(assets, start_date=datetime(2026, 5, 9, 10, 0, 0))
        report = engine.check_schedule(res, cs)
        print(f"\n[schedule] feasible={res.feasible} entries={len(res.schedule)}")
        print(f"[policy]   compliant={report.compliant} violations={len(report.violations)}")
        for v in report.violations:
            print(f"  ✗ {v.message}")
        # All Sat 02-04
        assert all(e.start.weekday() == 5 and 2 <= e.start.hour < 4 for e in res.schedule)
        print("✓ policy-constrained schedule satisfies maintenance window")

    eval_res = engine.evaluate()
    print(f"\n[evaluate] {json.dumps(eval_res, indent=2)}")
    assert eval_res["accuracy"] == 1.0
    print("✓ policy engine anchor evaluation passed")
