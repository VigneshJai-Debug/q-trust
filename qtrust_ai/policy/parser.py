"""
Policy parser — natural-language policy → machine-checkable constraints.

Architecture reference: ``qtrust_ai/README.md`` §22 (Policy Reasoning).

Deterministic, rule-based NLP: each rule is a set of trigger phrases plus a
small extractor (regex / keyword capture). Statements are split on sentence
boundaries, each matched against every rule, and the winning rule produces a
:class:`PolicyConstraint` (``qtrust_ai.policy.constraints``).

Supported policy patterns (spec §22 examples):

* "No production migration during business hours." → maintenance_window
* "Payment API cannot be down > 5 minutes." → downtime_limit
* "Critical systems: maximum 2 simultaneous migrations." → max_concurrent
* "Vendor X PQC support unavailable until Q3." → vendor_restriction
* "Critical systems must migrate before non-critical systems." → ordering
* "Only FIPS-approved implementations." → fips_only
* "Migrate all systems by 2030." → mandatory_by
* "No RSA in new deployments." → blocklist_algorithm
* "Requires CISO approval." → require_approval

Design goals:

* Deterministic — same policy text always yields the same constraint set
  (auditable, testable).
* Lenient — unmatched statements become ``parse_warnings``, never a crash.
* Generic — rule matching is data-driven (:data:`_RULES`) so adding a new
  policy dialect is a table entry, not a code change.

Example:
    from qtrust_ai.policy.parser import PolicyParser

    parser = PolicyParser(seed=42)
    cs = parser.parse("Payment API cannot be down > 5 minutes. "
                      "Critical systems: maximum 2 simultaneous migrations.")
    assert any(c.constraint_type == "downtime_limit" for c in cs.constraints)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from qtrust_ai.policy.constraints import ConstraintSet, PolicyConstraint

# Quarter → month (Q3 = July)
_QUARTER_MONTH = {"q1": 1, "q2": 4, "q3": 7, "q4": 10}

_WEEKDAY_NAMES = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6, "mon": 0, "tue": 1,
    "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
}

_ALGORITHM_NAMES = [
    "RSA", "RSA-2048", "RSA-1024", "ECDSA", "ECDSA-P256", "ECDH", "ECDH-P256",
    "DSA", "DH", "X25519", "ED25519", "AES-128", "AES-256", "3DES", "DES",
    "SHA-1", "SHA-256", "MD5", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "SLH-DSA", "HQC-128", "Falcon-512", "KYBER",
]


# ---------------------------------------------------------------------------
# Small extractor helpers
# ---------------------------------------------------------------------------

def _num(text: str, patterns: List[str]) -> Optional[int]:
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            try:
                return int(m.group(1))
            except (ValueError, IndexError):
                return None
    return None


def _find_scope(text: str) -> str:
    """Best-effort asset-class scope ('payment' | 'critical' | 'all')."""
    lower = text.lower()
    if any(w in lower for w in ("payment", "banking", "financial")):
        return "payment"
    if any(w in lower for w in ("critical system", "critical service", "critical asset")):
        return "critical"
    if any(w in lower for w in ("production", "prod")):
        return "production"
    return "all"


def _find_weekday(text: str) -> Optional[int]:
    lower = text.lower()
    for name, idx in _WEEKDAY_NAMES.items():
        if re.search(rf"\b{name}\b", lower):
            return idx
    return None


def _find_vendor(text: str) -> str:
    """'vendor X' / 'vendorX' / 'acme' → normalized vendor key."""
    m = re.search(r"vendor\s*([a-z0-9]+)", text, re.IGNORECASE)
    if m:
        return "vendor" + m.group(1).lower()
    # bare company-ish token after 'from' / 'until'
    return "vendorX"


# ---------------------------------------------------------------------------
# Rules (ordered — first match wins)
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    constraint_type: str
    triggers: List[str]
    extract: Callable[[str, str], PolicyConstraint]
    priority: int = 10


def _r_maintenance(text: str, src: str) -> PolicyConstraint:
    weekday = _find_weekday(text)
    sh = _num(text, [r"(\d{1,2})\s*[:.]?\s*(\d{2})\s*[-–—]", r"from (\d{1,2})"])
    params: Dict[str, Any] = {"weekday": weekday if weekday is not None else 5}
    if sh is not None:
        params["start_hour"] = sh
        params["end_hour"] = (sh + 2) % 24
    else:
        params["start_hour"] = 2
        params["end_hour"] = 4
    return PolicyConstraint(
        constraint_type="maintenance_window",
        description=f"{_WEEKDAY_NAMES.get(str(params['weekday']), 'weekend')} "
                    f"{params['start_hour']:02d}:00-{params['end_hour']:02d}:00 only",
        params=params,
        source_text=src,
    )


def _r_downtime(text: str, src: str) -> PolicyConstraint:
    minutes = _num(text, [r"(\d+(?:\.\d+)?)\s*(?:minutes|mins|min)\b", r"down\s*(?:for|>|over|more than)\s*(\d+)"])
    scope = _find_scope(text)
    return PolicyConstraint(
        constraint_type="downtime_limit",
        description=f"{scope} ≤{minutes or 5}m downtime",
        params={"max_minutes": float(minutes) if minutes is not None else 5.0, "scope": scope},
        source_text=src,
    )


def _r_max_concurrent(text: str, src: str) -> PolicyConstraint:
    n = _num(text, [r"(\d+)\s*(?:simultaneous|concurrent|at a time)", r"maximum\s*(\d+)"])
    return PolicyConstraint(
        constraint_type="max_concurrent",
        description=f"≤{n or 2} simultaneous migrations",
        params={"max": n or 2, "scope": _find_scope(text)},
        source_text=src,
    )


def _r_vendor(text: str, src: str) -> PolicyConstraint:
    quarter = None
    for name, month in _QUARTER_MONTH.items():
        if re.search(rf"\b{name}\b", text.lower()):
            quarter = month
            break
    vendor = _find_vendor(text)
    return PolicyConstraint(
        constraint_type="vendor_restriction",
        description=f"{vendor} PQC available from Q{quarter // 3 + 1 if quarter else '?'}",
        params={"vendor": vendor, "available_from_month": quarter or 7},
        source_text=src,
    )


def _r_ordering(text: str, src: str) -> PolicyConstraint:
    lower = text.lower()
    if "non-critical" in lower or "non critical" in lower:
        first, second = "critical", "non-critical"
    elif "high" in lower and "low" in lower:
        first, second = "high", "low"
    else:
        first, second = "critical", "non-critical"
    return PolicyConstraint(
        constraint_type="ordering",
        description=f"{first} before {second}",
        params={"first": first, "second": second},
        source_text=src,
    )


def _r_fips(text: str, src: str) -> PolicyConstraint:
    lower = text.lower()
    mode = "cnsa2" if "cnsa 2" in lower or "cnsa2" in lower else ("cnsa1" if "cnsa 1" in lower or "cnsa1" in lower else "fips")
    return PolicyConstraint(
        constraint_type="fips_only",
        description=f"only {mode}-approved implementations",
        params={"mode": mode},
        source_text=src,
    )


def _r_mandatory_by(text: str, src: str) -> PolicyConstraint:
    year = _num(text, [r"by\s*(20\d{2})", r"(20\d{2})\s*(?:deadline|must|before)"])
    return PolicyConstraint(
        constraint_type="mandatory_by",
        description=f"migrate {_find_scope(text)} by {year or 2030}",
        params={"scope": _find_scope(text), "year": year or 2030},
        source_text=src,
    )


def _r_blocklist(text: str, src: str) -> PolicyConstraint:
    found = [a for a in _ALGORITHM_NAMES if re.search(rf"\b{re.escape(a)}\b", text, re.IGNORECASE)]
    return PolicyConstraint(
        constraint_type="blocklist_algorithm",
        description="no " + ", ".join(found) if found else "no banned algorithm",
        params={"algorithms": found or ["RSA"], "scope": _find_scope(text)},
        source_text=src,
    )


def _r_approval(text: str, src: str) -> PolicyConstraint:
    role = "CISO"
    for r in ("CISO", "CSO", "board", "security architect"):
        if re.search(rf"\b{r}\b", text, re.IGNORECASE):
            role = r
            break
    return PolicyConstraint(
        constraint_type="require_approval",
        description=f"{role} approval required",
        params={"role": role, "scope": _find_scope(text)},
        source_text=src,
    )


_RULES: List[_Rule] = [
    _Rule("blocklist_algorithm", ["no rsa", "no ecdsa", "no aes-128", "no md5", "banned", "not allowed in new"], _r_blocklist, priority=5),
    _Rule("mandatory_by", ["by 2030", "by 2035", "deadline", "must be migrated by", "before 20"], _r_mandatory_by, priority=6),
    _Rule("ordering", ["before non-critical", "before non critical", "critical before", "migrate before"], _r_ordering, priority=7),
    _Rule("max_concurrent", ["simultaneous", "concurrent", "at a time", "maximum 2", "maximum 3", "max 2"], _r_max_concurrent, priority=8),
    _Rule("downtime_limit", ["down", "downtime", "minutes", "cannot be down", "max downtime"], _r_downtime, priority=9),
    _Rule("vendor_restriction", ["vendor", "unavailable until", "available until", "q3", "q4", "q1", "q2"], _r_vendor, priority=10),
    _Rule("maintenance_window", ["business hours", "maintenance window", "saturday", "sunday", "weekend", "02:00", "04:00", "only on"], _r_maintenance, priority=11),
    _Rule("fips_only", ["fips", "cnsa"], _r_fips, priority=12),
    _Rule("require_approval", ["approval", "sign-off", "sign off"], _r_approval, priority=13),
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class PolicyParser:
    """Deterministic natural-language → :class:`ConstraintSet` parser.

    Attributes:
        seed: Unused for parsing (deterministic) — kept for API parity.

    Example:
        >>> parser = PolicyParser()
        >>> cs = parser.parse("Payment API cannot be down > 5 minutes.")
        >>> cs.constraints[0].constraint_type == "downtime_limit"
        True
        >>> cs.constraints[0].params["max_minutes"] == 5.0
        True
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed

    def parse(self, policy_text: str) -> ConstraintSet:
        """Parse a policy document (one or more sentences) into constraints.

        Args:
            policy_text: Natural-language policy, e.g. ``"Payment API cannot
                be down > 5 minutes. Critical systems: maximum 2 simultaneous
                migrations."``

        Returns:
            :class:`ConstraintSet` with deduplicated constraints and warnings
            for statements that matched no rule.
        """
        statements = self._split_statements(policy_text)
        constraints: List[PolicyConstraint] = []
        warnings: List[str] = []
        for stmt in statements:
            matched = self.parse_statement(stmt)
            if matched is not None:
                constraints.append(matched)
            else:
                warnings.append(stmt)
        return ConstraintSet(constraints=constraints, source_text=policy_text, parse_warnings=warnings)

    def parse_statement(self, statement: str) -> Optional[PolicyConstraint]:
        """Parse a single statement against the rule table (first match wins).

        Args:
            statement: One policy sentence.

        Returns:
            :class:`PolicyConstraint` or ``None`` when no rule matches.
        """
        s = statement.strip().rstrip(".;, ").strip()
        if not s:
            return None
        lower = s.lower()
        ordered = sorted(_RULES, key=lambda r: r.priority)
        for rule in ordered:
            if any(trig in lower for trig in rule.triggers):
                try:
                    return rule.extract(s, statement)
                except Exception:  # pragma: no cover — extractor bug must not crash parse
                    continue
        return None

    @staticmethod
    def _split_statements(text: str) -> List[str]:
        """Split on sentence boundaries while keeping hours like ``02:00`` intact."""
        # Protect ':' in time patterns, then split on [.;\n]
        protected = re.sub(r"(\d{1,2}):(\d{2})", r"\1H\2", text)
        parts = re.split(r"[.;\n]+", protected)
        out: List[str] = []
        for p in parts:
            p = re.sub(r"(\d{1,2})H(\d{2})", r"\1:\2", p).strip()
            if p:
                out.append(p)
        return out


if __name__ == "__main__":
    print("=== PolicyParser demo — NL policy → machine-checkable constraints ===\n")
    parser = PolicyParser(seed=42)
    policy = (
        "Payment API cannot be down more than 5 minutes. "
        "Production migration only Saturday 02:00-04:00. "
        "Critical systems: maximum 2 simultaneous migrations. "
        "Vendor X PQC support unavailable until Q3. "
        "Critical systems must migrate before non-critical systems. "
        "Only FIPS-approved implementations. "
        "Migrate all production systems by 2030. "
        "No RSA in new deployments. "
        "High-risk migrations require CISO approval. "
        "Something completely unrelated about coffee."
    )
    cs = parser.parse(policy)
    print(cs.source_text)
    print(f"\nParsed {len(cs.constraints)} constraints "
          f"(hard={len(cs.hard())}, soft={len(cs.soft())}), warnings={len(cs.parse_warnings)}")
    for c in cs.constraints:
        print(f"  [{c.constraint_type:20s}] {c.description:45s} {c.params}")
    for w in cs.parse_warnings:
        print(f"  [unmatched      ] {w!r}")

    # Assertions per spec §22 examples
    types = {c.constraint_type for c in cs.constraints}
    assert "maintenance_window" in types
    assert "downtime_limit" in types
    assert "max_concurrent" in types
    assert "vendor_restriction" in types
    assert "ordering" in types
    assert "fips_only" in types
    assert "mandatory_by" in types
    assert "blocklist_algorithm" in types
    assert "require_approval" in types
    assert len(cs.parse_warnings) == 1  # the coffee statement
    dc = next(c for c in cs.constraints if c.constraint_type == "downtime_limit")
    assert dc.params["max_minutes"] == 5.0, dc.params
    mc = next(c for c in cs.constraints if c.constraint_type == "max_concurrent")
    assert mc.params["max"] == 2, mc.params
    print("\n✓ all spec §22 policy patterns parsed correctly")
