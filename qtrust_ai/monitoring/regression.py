"""
Crypto Regression — CI/CD gate that blocks quantum regressions.

Architecture reference: ``qtrust_ai/README.md`` Phase 4 Enterprise
``monitoring/regression.py`` blocks CI/CD on ``ML-KEM → RSA regression``:

    baseline CBOM (main)          candidate CBOM (PR)
         ML-KEM-768 ──────►           RSA-2048        ✗ BLOCK  (quantum regression)
         ML-DSA-65  ──────►           ECDSA-P256      ✗ BLOCK
         RSA-2048   ──────►           ML-KEM-768      ✓ PASS   (upgrade)
         AES-128    ──────►           AES-128         ⚠ WARN   (stale, not regression)

The detector compares two inventories (CBOMs / snapshots / dependency
graphs) and classifies each delta:

* **quantum_regression** — PQC → classical (CRITICAL, blocks)
* **downgrade** — larger key → smaller, or P-384 → P-256 (HIGH, blocks)
* **reintroduction** — classical algo reappears after removal (MEDIUM)
* **upgrade** — classical → PQC or key-size increase (INFO, pass)

It exposes a CI/CD-friendly gate verdict ``blocked / pass / warn`` and a
human-readable report for PR comments / SARIF.

Example:

    from qtrust_ai.monitoring.regression import CryptoRegressionDetector

    det = CryptoRegressionDetector()
    verdict = det.check_ci_gate(baseline_cbom, candidate_cbom)
    if verdict.blocked:
        print(f"BLOCKED: {verdict.findings[0].message}")
        raise SystemExit(1)
"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Knowledge base — algorithm hierarchy
# ---------------------------------------------------------------------------

# PQC families that must never regress to classical
_PQC_FAMILIES: Set[str] = {"ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FALCON", "FN-DSA", "MAYO"}

_CLASSICAL_FAMILIES: Set[str] = {"RSA", "ECDSA", "ECDH", "DSA", "DH", "ED25519", "ED448", "X25519", "X448", "3DES", "DES", "SHA-1", "MD5"}

# Key size ordering within family (larger = stronger)
_KEY_SIZE_ORDER: Dict[str, List[int]] = {
    "RSA": [1024, 2048, 3072, 4096],
    "ECDSA": [224, 256, 384, 521],
    "ECDH": [224, 256, 384, 521],
    "DSA": [1024, 2048, 3072],
    "DH": [1024, 2048, 3072, 4096],
    "ML-KEM": [512, 768, 1024],
    "ML-DSA": [44, 65, 87],
}

# Family strength ranking (for cross-family comparison within classical)
_FAMILY_STRENGTH: Dict[str, int] = {
    "RSA-1024": 10, "DES": 10, "MD5": 10, "SHA-1": 15, "3DES": 20,
    "RSA-2048": 40, "ECDSA-P256": 40, "ECDH-P256": 40, "DSA-2048": 40,
    "RSA-3072": 60, "ECDSA-P384": 60, "AES-128": 50, "SHA-256": 50,
    "RSA-4096": 80, "ECDSA-P521": 80, "AES-256": 80, "SHA-384": 70, "SHA-512": 75,
    "ML-KEM-512": 85, "ML-KEM-768": 90, "ML-KEM-1024": 95,
    "ML-DSA-44": 85, "ML-DSA-65": 90, "ML-DSA-87": 95,
    "SLH-DSA": 95, "HQC-128": 85, "FALCON": 85,
}

_PQC_FAMILY_SET = {k.upper() for k in _PQC_FAMILIES}
_CLASSICAL_SET = {k.upper() for k in _CLASSICAL_FAMILIES}


def _family(algo: str) -> str:
    upper = algo.upper().replace("_", "-").strip()
    for fam in ["ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FALCON", "FN-DSA", "MAYO", "ECDSA", "ECDH", "ED25519", "ED448", "X25519", "X448", "3DES", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "AES-", "RSA", "DSA", "DH", "MD5", "SHA"]:
        if fam in upper:
            return fam.replace("-", "").replace("AES-", "AES") if "AES" in fam else fam
    return upper.split("-")[0].split("_")[0]


def _is_pqc(algo: str) -> bool:
    upper = algo.upper()
    return any(fam in upper for fam in _PQC_FAMILY_SET)


def _is_classical(algo: str) -> bool:
    upper = algo.upper()
    if any(fam in upper for fam in _PQC_FAMILY_SET):
        return False
    return any(fam in upper for fam in _CLASSICAL_SET) or "RSA" in upper or "ECDSA" in upper or "ECDH" in upper


def _strength(algo: str) -> int:
    upper = algo.upper()
    for key, val in _FAMILY_STRENGTH.items():
        if key in upper:
            return val
    # Heuristic by key size
    import re
    m = re.search(r"(\d{3,4})\s*$", upper)
    if m:
        try:
            ks = int(m.group(1))
            if ks >= 4096:
                return 85
            if ks >= 3072:
                return 65
            if ks >= 2048:
                return 40
            if ks >= 1024:
                return 15
        except Exception:
            pass
    if "AES-256" in upper or "SHA-384" in upper or "SHA-512" in upper:
        return 75
    if "AES-128" in upper or "SHA-256" in upper:
        return 50
    return 30


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RegressionFinding:
    """Single regression finding (one algorithm delta)."""

    regression_type: str  # quantum_regression | downgrade | reintroduction | upgrade | new_classical | removed_pqc
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    message: str
    from_algo: Optional[str] = None
    to_algo: Optional[str] = None
    location: Optional[str] = None
    blocked: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RegressionResult:
    """Detailed comparison of two inventories."""

    baseline_algos: Dict[str, int] = field(default_factory=dict)
    candidate_algos: Dict[str, int] = field(default_factory=dict)
    added: Dict[str, int] = field(default_factory=dict)
    removed: Dict[str, int] = field(default_factory=dict)
    findings: List[RegressionFinding] = field(default_factory=list)
    has_regression: bool = False
    has_quantum_regression: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


@dataclass
class RegressionGateVerdict:
    """CI/CD gate verdict."""

    blocked: bool  # True → fail the pipeline
    severity: str  # CRITICAL | HIGH | MEDIUM | PASS
    findings: List[RegressionFinding] = field(default_factory=list)
    result: Optional[RegressionResult] = None
    report: str = ""
    sarif_hint: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        if self.result:
            d["result"] = self.result.to_dict()
        return d


@dataclass
class RegressionConfig:
    block_on_quantum_regression: bool = True
    block_on_downgrade: bool = True
    warn_on_reintroduction: bool = True
    allow_list: List[str] = field(default_factory=lambda: ["AES-128", "SHA-256"])  # classical that may be new without blocking
    seed: int = 42


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class CryptoRegressionDetector:
    """Detects crypto regressions & enforces CI/CD gate.

    The core check is **quantum regression**: any PQC primitive that existed
    in the baseline but is replaced by (or accompanied by a new) classical
    primitive in the candidate. This blocks ``ML-KEM → RSA`` even if RSA
    already existed elsewhere — the *delta* matters.

    Additional checks:
    * **downgrade** — key size or family strength decrease
    * **reintroduction** — classical algo that was removed returns
    * **new_classical** — new classical algo not in baseline
    * **upgrade** — classical → PQC (pass, reported as INFO)

    Attributes:
        config: :class:`RegressionConfig`.

    Example:
        >>> det = CryptoRegressionDetector()
        >>> baseline = {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]}
        >>> candidate = {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ML-DSA-65"}]}
        >>> verdict = det.check_ci_gate(baseline, candidate)
        >>> verdict.blocked and verdict.severity == "CRITICAL"
        True
        >>> # Pure PQC upgrade passes
        >>> det.check_ci_gate({"assets": [{"algorithm": "RSA-2048"}]}, {"assets": [{"algorithm": "ML-KEM-768"}]}).blocked
        False
    """

    def __init__(self, config: Optional[RegressionConfig] = None, seed: int = 42) -> None:
        self.config = config or RegressionConfig(seed=seed)
        self.config.seed = seed
        random.seed(seed)
        self.is_trained = False
        self._history: List[Dict[str, Any]] = []

    # ---- training (stub) --------------------------------------------------

    def train(self, dataset: Optional[List[Dict[str, Any]]] = None, epochs: int = 3) -> Dict[str, Any]:
        """Train detector thresholds (stub: heuristic is rule-based).

        Args:
            dataset: List of ``{"baseline": CBOM|dict, "candidate": CBOM|dict,
                "blocked": bool}``. If ``None`` synthetic history is generated.

        Returns:
            Dict with ``examples``, ``accuracy``, ``note``.
        """
        random.seed(self.config.seed)
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=200, seed=self.config.seed)
        correct = 0
        for ex in dataset:
            baseline = ex.get("baseline", ex.get("before", {}))
            candidate = ex.get("candidate", ex.get("after", {}))
            expected = bool(ex.get("blocked", ex.get("is_regression", False)))
            verdict = self.check_ci_gate(baseline, candidate)
            if verdict.blocked == expected:
                correct += 1
            self._history.append({"baseline": baseline, "candidate": candidate, "expected": expected, "got": verdict.blocked})
        self.is_trained = True
        acc = correct / len(dataset) if dataset else 0.0
        return {"examples": len(dataset), "accuracy": round(acc, 4), "correct": correct, "n": len(dataset), "note": "rule-based detector; train() validates thresholds on synthetic history"}

    # ---- core: compare two inventories ------------------------------------

    def _extract_algo_counts(self, inventory: Any) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
        """Extract ``{algo: count}`` and ``{algo: [locations]}`` from inventory."""
        if inventory is None:
            return {}, {}
        # Dict CBOM {"assets": [{"algorithm": ..., "location": ...}]}
        if isinstance(inventory, dict) and "assets" in inventory:
            assets = inventory.get("assets", [])
            counts: Counter = Counter()
            locs: Dict[str, List[str]] = {}
            for asset in assets:
                if isinstance(asset, dict):
                    algo = str(asset.get("algorithm", asset.get("algo", "UNKNOWN")))
                    loc = str(asset.get("location", asset.get("file", asset.get("path", "unknown"))))
                else:
                    algo = str(getattr(asset, "algorithm", "UNKNOWN"))
                    loc = str(getattr(asset, "location", "unknown"))
                counts[algo] += 1
                locs.setdefault(algo, []).append(loc)
            return dict(counts), locs
        # Direct mapping {algo: count}
        if isinstance(inventory, dict):
            # Could be {"RSA-2048": 3, "ML-KEM-768": 2}
            counts2: Dict[str, int] = {}
            locs2: Dict[str, List[str]] = {}
            for k, v in inventory.items():
                if isinstance(v, int):
                    counts2[str(k)] = v
                elif isinstance(v, dict) and "count" in v:
                    counts2[str(k)] = int(v["count"])
            return counts2, locs2
        # List of algos
        if isinstance(inventory, list):
            counts3: Counter = Counter()
            locs3: Dict[str, List[str]] = {}
            for item in inventory:
                if isinstance(item, str):
                    counts3[item] += 1
                elif isinstance(item, dict) and "algorithm" in item:
                    counts3[str(item["algorithm"])] += 1
            return dict(counts3), locs3
        return {}, {}

    def compare(self, baseline: Any, candidate: Any) -> RegressionResult:
        """Compare two inventories and return detailed :class:`RegressionResult`.

        Args:
            baseline: Baseline inventory (CBOM dict, algo->count, or list).
            candidate: Candidate inventory (same formats).

        Returns:
            :class:`RegressionResult` with added/removed and findings.
        """
        b_counts, b_locs = self._extract_algo_counts(baseline)
        c_counts, c_locs = self._extract_algo_counts(candidate)

        added: Dict[str, int] = {}
        removed: Dict[str, int] = {}
        findings: List[RegressionFinding] = []

        # Compute added / removed deltas
        all_algos = set(b_counts) | set(c_counts)
        for algo in all_algos:
            bc = b_counts.get(algo, 0)
            cc = c_counts.get(algo, 0)
            if cc > bc:
                added[algo] = cc - bc
            if bc > cc:
                removed[algo] = bc - cc

        # --- Quantum regression: PQC removed + classical added ---------------
        pqc_removed = {algo: cnt for algo, cnt in removed.items() if _is_pqc(algo)}
        classical_added = {algo: cnt for algo, cnt in added.items() if _is_classical(algo)}
        # Also: PQC family count drop (even if same algo count unchanged but classical spike)
        pqc_baseline_total = sum(cnt for algo, cnt in b_counts.items() if _is_pqc(algo))
        pqc_candidate_total = sum(cnt for algo, cnt in c_counts.items() if _is_pqc(algo))
        classical_baseline_total = sum(cnt for algo, cnt in b_counts.items() if _is_classical(algo))
        classical_candidate_total = sum(cnt for algo, cnt in c_counts.items() if _is_classical(algo))

        has_quantum_regression = False
        # Case 1: direct PQC count drop + classical rise
        if pqc_candidate_total < pqc_baseline_total and classical_candidate_total > classical_baseline_total:
            # Check if delta is material (>=1 PQC lost and >=1 classical gained)
            if pqc_baseline_total - pqc_candidate_total >= 1 and classical_candidate_total - classical_baseline_total >= 1:
                has_quantum_regression = True
                # Emit per-PQC-removed finding, linking to classical added
                for pqc_algo, removed_cnt in pqc_removed.items():
                    # Find strongest classical added to pair as "to"
                    to_algo = max(classical_added, key=lambda k: classical_added[k]) if classical_added else None
                    findings.append(RegressionFinding(
                        regression_type="quantum_regression",
                        severity="CRITICAL",
                        message=f"Quantum regression: {pqc_algo} (×{removed_cnt} removed) → classical {to_algo or 'classical'} (×{classical_added.get(to_algo, '?')} added) — PQC → classical rollback blocks CI/CD",
                        from_algo=pqc_algo,
                        to_algo=to_algo,
                        location=(c_locs.get(to_algo, ["unknown"])[0] if to_algo and c_locs.get(to_algo) else None),
                        blocked=True,
                        details={"pqc_removed": dict(pqc_removed), "classical_added": dict(classical_added), "pqc_total_drop": pqc_baseline_total - pqc_candidate_total, "classical_total_rise": classical_candidate_total - classical_baseline_total},
                    ))
                if not pqc_removed and classical_added:
                    # PQC total dropped but no single PQC algo fully removed (partial)
                    findings.append(RegressionFinding(
                        regression_type="quantum_regression",
                        severity="CRITICAL",
                        message=f"Quantum regression: PQC total {pqc_candidate_total} < baseline {pqc_baseline_total} while classical {classical_candidate_total} > baseline {classical_baseline_total} — net PQC loss",
                        from_algo="PQC:total",
                        to_algo="classical:total",
                        blocked=True,
                        details={"pqc_baseline": pqc_baseline_total, "pqc_candidate": pqc_candidate_total, "classical_baseline": classical_baseline_total, "classical_candidate": classical_candidate_total},
                    ))
        # Case 2: ML-KEM → RSA specific (strongest signal even if totals ambiguous)
        for pqc_algo in list(pqc_removed.keys()):
            if "ML-KEM" in pqc_algo.upper():
                for classical_algo in classical_added:
                    if "RSA" in classical_algo.upper():
                        # Ensure we didn't already emit for this pqc
                        if not any(f.from_algo == pqc_algo and f.to_algo == classical_algo for f in findings):
                            findings.append(RegressionFinding(
                                regression_type="quantum_regression",
                                severity="CRITICAL",
                                message=f"ML-KEM → RSA regression: {pqc_algo} removed and {classical_algo} added — blocks CI/CD per PQC policy",
                                from_algo=pqc_algo,
                                to_algo=classical_algo,
                                blocked=True,
                                details={"rule": "ML-KEM→RSA"},
                            ))
                            has_quantum_regression = True
        # Case 3: any classical added when PQC existed and candidate has no PQC at all (full rollback)
        if pqc_baseline_total > 0 and pqc_candidate_total == 0 and classical_candidate_total > 0:
            if not has_quantum_regression:
                findings.append(RegressionFinding(
                    regression_type="quantum_regression",
                    severity="CRITICAL",
                    message=f"Full PQC rollback: baseline had {pqc_baseline_total} PQC assets, candidate has 0 — all quantum-safe removed",
                    from_algo="PQC:*",
                    to_algo=list(classical_added.keys())[0] if classical_added else "classical",
                    blocked=True,
                    details={"pqc_baseline_total": pqc_baseline_total},
                ))
                has_quantum_regression = True

        # --- Downgrade: key size / strength decrease --------------------------
        for algo in added:
            if algo in self.config.allow_list:
                continue
            # If same family existed in baseline with larger key: check
            fam = _family(algo)
            # Find baseline counterpart same family with higher strength
            baseline_same_fam = {k: v for k, v in b_counts.items() if _family(k) == fam}
            if baseline_same_fam:
                # Added algo is weaker than some removed/baseline algo of same family
                for b_algo in baseline_same_fam:
                    if _strength(algo) < _strength(b_algo) and removed.get(b_algo, 0) > 0:
                        findings.append(RegressionFinding(
                            regression_type="downgrade",
                            severity="HIGH",
                            message=f"Downgrade: {b_algo} (strength {_strength(b_algo)}) → {algo} (strength {_strength(algo)})",
                            from_algo=b_algo,
                            to_algo=algo,
                            blocked=self.config.block_on_downgrade,
                            details={"from_strength": _strength(b_algo), "to_strength": _strength(algo)},
                        ))
                        break

        # --- Reintroduction: classical algo that was removed returns --------
        # For CI gate we consider reintroduction as MEDIUM unless it's PQC→classical
        # Already flagged as quantum_regression if PQC existed; otherwise standalone:
        for algo, cnt in added.items():
            if _is_classical(algo) and algo not in b_counts:
                # Truly new classical
                if algo not in self.config.allow_list:
                    # Only flag if not already flagged as quantum_regression
                    if not any(f.to_algo == algo and f.regression_type == "quantum_regression" for f in findings):
                        findings.append(RegressionFinding(
                            regression_type="new_classical" if pqc_baseline_total == 0 else "reintroduction",
                            severity="MEDIUM" if pqc_baseline_total > 0 else "LOW",
                            message=f"New classical algorithm '{algo}' introduced (×{cnt}) — was not in baseline",
                            from_algo=None,
                            to_algo=algo,
                            blocked=False,
                            details={"count": cnt, "pqc_baseline_total": pqc_baseline_total},
                        ))

        # --- Upgrade: classical → PQC (positive, INFO) ---------------------
        pqc_added = {algo: cnt for algo, cnt in added.items() if _is_pqc(algo)}
        classical_removed = {algo: cnt for algo, cnt in removed.items() if _is_classical(algo)}
        if pqc_added and classical_removed:
            for pqc_algo in pqc_added:
                for classical_algo in classical_removed:
                    findings.append(RegressionFinding(
                        regression_type="upgrade",
                        severity="INFO",
                        message=f"PQC upgrade: {classical_algo} (×{classical_removed[classical_algo]} removed) → {pqc_algo} (×{pqc_added[pqc_algo]} added) — migration progress",
                        from_algo=classical_algo,
                        to_algo=pqc_algo,
                        blocked=False,
                        details={"upgrade": True},
                    ))
                    break
                break

        has_regression = any(f.regression_type in ("quantum_regression", "downgrade", "reintroduction") for f in findings)
        # Ensure quantum_regression flag authoritative
        has_qr = any(f.regression_type == "quantum_regression" for f in findings) or has_quantum_regression

        return RegressionResult(
            baseline_algos=dict(b_counts),
            candidate_algos=dict(c_counts),
            added=dict(added),
            removed=dict(removed),
            findings=findings,
            has_regression=has_regression or has_qr,
            has_quantum_regression=has_qr,
        )

    # ---- CI/CD gate -------------------------------------------------------

    def check_ci_gate(self, baseline: Any, candidate: Any) -> RegressionGateVerdict:
        """Evaluate CI/CD gate: should the pipeline be blocked?

        Args:
            baseline: Baseline inventory (main branch CBOM / snapshot / graph).
            candidate: Candidate inventory (PR branch).

        Returns:
            :class:`RegressionGateVerdict` with ``blocked``, ``severity``,
            ``findings``, and a markdown ``report`` for PR comments.
        """
        result = self.compare(baseline, candidate)
        block_findings = [f for f in result.findings if f.blocked]
        # Quantum regression always blocks regardless of config override? spec says block ML-KEM→RSA
        quantum = [f for f in result.findings if f.regression_type == "quantum_regression"]
        should_block = False
        severity = "PASS"
        if quantum and self.config.block_on_quantum_regression:
            should_block = True
            severity = "CRITICAL"
        elif block_findings:
            # Check if any HIGH downgrade that is configured to block
            if any(f.severity in ("CRITICAL", "HIGH") for f in block_findings):
                should_block = True
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        # Build report
        if should_block:
            title = f"⛔ BLOCKED ({severity}): crypto regression detected"
        elif result.has_regression:
            title = "⚠️ WARNING: crypto drift detected (not blocking)"
            severity = "MEDIUM" if severity == "PASS" else severity
        else:
            title = "✅ PASS: no crypto regression"

        lines: List[str] = [f"### {title}", ""]
        lines.append(f"Baseline: {sum(result.baseline_algos.values())} assets → Candidate: {sum(result.candidate_algos.values())} assets")
        if result.added:
            lines.append(f"Added: {result.added}")
        if result.removed:
            lines.append(f"Removed: {result.removed}")
        if result.findings:
            lines.append("")
            lines.append("| Type | Severity | From → To | Message | Block |")
            lines.append("|---|---|---|---|---|")
            for f in result.findings:
                to_s = f.to_algo or "-"
                from_s = f.from_algo or "-"
                lines.append(f"| {f.regression_type} | {f.severity} | {from_s} → {to_s} | {f.message[:80]} | {'⛔' if f.blocked else '✓'} |")
        else:
            lines.append("No findings — candidate is clean vs baseline.")
        # Guidance
        if should_block:
            lines.append("")
            lines.append("**Action:** revert the PQC→classical change or request exception from security. See `qtrust_ai/monitoring/regression.py`.")
        report = "\n".join(lines)

        sarif_hint = {
            "tool": "qtrust-crypto-regression",
            "blocked": should_block,
            "severity": severity,
            "findings": len(result.findings),
            "quantum_regression": result.has_quantum_regression,
        }

        return RegressionGateVerdict(
            blocked=should_block,
            severity=severity,
            findings=result.findings,
            result=result,
            report=report,
            sarif_hint=sarif_hint,
        )

    # ---- evaluate ---------------------------------------------------------

    def evaluate(self, dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Evaluate on labelled regression dataset.

        Args:
            dataset: List of ``{"baseline": ..., "candidate": ..., "blocked": bool}``.
                If ``None`` synthetic eval set.

        Returns:
            Dict with ``accuracy``, ``precision``, ``recall``, ``n``.
        """
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=200, seed=self.config.seed + 101)
        y_true: List[int] = []
        y_pred: List[int] = []
        per_type: Dict[str, Dict[str, int]] = {}
        for ex in dataset:
            baseline = ex.get("baseline", ex.get("before", {}))
            candidate = ex.get("candidate", ex.get("after", {}))
            true = 1 if ex.get("blocked", ex.get("is_regression", False)) else 0
            pred = 1 if self.check_ci_gate(baseline, candidate).blocked else 0
            y_true.append(true)
            y_pred.append(pred)
            rtype = ex.get("regression_type", "unknown")
            per_type.setdefault(rtype, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            if true == 1 and pred == 1:
                per_type[rtype]["tp"] += 1
            elif true == 0 and pred == 1:
                per_type[rtype]["fp"] += 1
            elif true == 1 and pred == 0:
                per_type[rtype]["fn"] += 1
            else:
                per_type[rtype]["tn"] += 1
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
        acc = (tp + tn) / len(y_true) if y_true else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        return {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "n": len(dataset),
            "per_type": per_type,
        }

    # ---- synthetic dataset ------------------------------------------------

    def _generate_synthetic_dataset(self, n: int = 200, seed: int = 42) -> List[Dict[str, Any]]:
        rnd = random.Random(seed)
        templates = [
            # quantum regression: ML-KEM → RSA
            ({"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}, {"algorithm": "AES-256"}]}, {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ML-DSA-65"}, {"algorithm": "AES-256"}]}, True, "quantum_regression"),
            ({"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "AES-256"}]}, {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "AES-256"}]}, True, "quantum_regression"),
            ({"assets": [{"algorithm": "ML-DSA-65"}]}, {"assets": [{"algorithm": "ECDSA-P256"}]}, True, "quantum_regression"),
            # downgrade
            ({"assets": [{"algorithm": "RSA-4096"}]}, {"assets": [{"algorithm": "RSA-2048"}]}, True, "downgrade"),
            ({"assets": [{"algorithm": "ECDSA-P384"}]}, {"assets": [{"algorithm": "ECDSA-P256"}]}, True, "downgrade"),
            # upgrade (pass)
            ({"assets": [{"algorithm": "RSA-2048"}]}, {"assets": [{"algorithm": "ML-KEM-768"}]}, False, "upgrade"),
            ({"assets": [{"algorithm": "ECDSA-P256"}]}, {"assets": [{"algorithm": "ML-DSA-65"}]}, False, "upgrade"),
            ({"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "AES-128"}]}, {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ML-KEM-768"}]}, False, "upgrade"),
            # benign (no change, new pqc, unrelated)
            ({"assets": [{"algorithm": "ML-KEM-768"}]}, {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "AES-256"}]}, False, "benign"),
            ({"assets": [{"algorithm": "AES-256"}]}, {"assets": [{"algorithm": "AES-256"}]}, False, "benign"),
        ]
        data: List[Dict[str, Any]] = []
        for i in range(n):
            baseline, candidate, blocked, rtype = rnd.choice(templates)
            # Clone to avoid mutation
            b = json.loads(json.dumps(baseline))
            c = json.loads(json.dumps(candidate))
            # Add jitter: sometimes add extra benign assets
            if rnd.random() < 0.20:
                extra_algo = rnd.choice(["AES-256", "SHA-256", "SHA-384"])
                b["assets"].append({"algorithm": extra_algo})
                c["assets"].append({"algorithm": extra_algo})
            data.append({"baseline": b, "candidate": c, "blocked": blocked, "regression_type": rtype, "id": i})
        return data


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== CryptoRegressionDetector demo — CI/CD gate (ML-KEM→RSA blocks) ===")
    det = CryptoRegressionDetector(seed=42)
    train_res = det.train(epochs=1)
    print(f"[train] {json.dumps(train_res, indent=2)}")

    cases = [
        ("ML-KEM → RSA (BLOCK)", {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]}, {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ML-DSA-65"}]}, True),
        ("ML-DSA → ECDSA (BLOCK)", {"assets": [{"algorithm": "ML-DSA-65"}]}, {"assets": [{"algorithm": "ECDSA-P256"}]}, True),
        ("RSA-4096 → RSA-2048 (downgrade BLOCK)", {"assets": [{"algorithm": "RSA-4096"}]}, {"assets": [{"algorithm": "RSA-2048"}]}, True),
        ("RSA → ML-KEM (upgrade PASS)", {"assets": [{"algorithm": "RSA-2048"}]}, {"assets": [{"algorithm": "ML-KEM-768"}]}, False),
        ("ECDSA → ML-DSA (upgrade PASS)", {"assets": [{"algorithm": "ECDSA-P256"}]}, {"assets": [{"algorithm": "ML-DSA-65"}]}, False),
        ("no change (PASS)", {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "AES-256"}]}, {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "AES-256"}]}, False),
        ("full PQC rollback (BLOCK)", {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]}, {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ECDSA-P256"}]}, True),
        ("AES benign (PASS)", {"assets": [{"algorithm": "AES-256"}]}, {"assets": [{"algorithm": "AES-256"}, {"algorithm": "SHA-384"}]}, False),
    ]
    for label, baseline, candidate, expect_block in cases:
        verdict = det.check_ci_gate(baseline, candidate)
        status = "⛔ BLOCK" if verdict.blocked else "✅ PASS"
        print(f"\n[{label:38s}] {status} severity={verdict.severity} expected_block={expect_block} -> {'OK' if verdict.blocked==expect_block else 'MISMATCH'}")
        if verdict.findings:
            for f in verdict.findings:
                print(f"  - {f.regression_type:18s} {f.severity:8s} blocked={f.blocked} {f.message}")
        print(f"  Report headline: {verdict.report.split(chr(10))[0]}")

    # Inventory dict format
    print("\n--- dict inventory format ---")
    verdict = det.check_ci_gate({"ML-KEM-768": 2, "AES-256": 5}, {"RSA-2048": 2, "AES-256": 5})
    print(f"dict ML-KEM→RSA blocked={verdict.blocked} findings={len(verdict.findings)}")

    # Detailed compare
    print("\n--- detailed compare ---")
    result = det.compare({"assets": [{"algorithm": "ML-KEM-768"}]}, {"assets": [{"algorithm": "RSA-2048"}]})
    print(f"added={result.added} removed={result.removed} has_qr={result.has_quantum_regression}")
    for f in result.findings:
        print(f"  {f.regression_type} {f.severity} {f.message}")

    eval_res = det.evaluate()
    print(f"\n[evaluate] acc={eval_res['accuracy']} P={eval_res['precision']} R={eval_res['recall']} F1={eval_res['f1']} n={eval_res['n']}")
    for rtype, m in eval_res["per_type"].items():
        print(f"  {rtype:20s} {m}")

    # Anchor assertions per spec
    assert det.check_ci_gate({"assets": [{"algorithm": "ML-KEM-768"}]}, {"assets": [{"algorithm": "RSA-2048"}]}).blocked, "ML-KEM→RSA must block"
    assert not det.check_ci_gate({"assets": [{"algorithm": "RSA-2048"}]}, {"assets": [{"algorithm": "ML-KEM-768"}]}).blocked, "RSA→ML-KEM must pass"
    assert det.check_ci_gate({"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]}, {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ECDSA-P256"}]}).blocked, "full PQC→classical must block"
    print("\n✓ regression anchor assertions passed — ML-KEM→RSA blocks, quantum regression detected, CI/CD gate enforced")
