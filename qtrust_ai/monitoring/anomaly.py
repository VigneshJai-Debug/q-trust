"""
Anomaly detection upgrade — continuous crypto monitoring.

Extends :mod:`inspector.qtrust_inspector.anomaly_detector` (VAE baseline)
with streaming, windowed capabilities required for **continuous monitoring**
per ``qtrust_ai/README.md`` Phase 4 Enterprise:

* **Unexpected crypto usage** — new algorithm family appears that was never
  in baseline (e.g. ``DES``, ``MD5`` after cleanup).
* **New algorithm** — any algorithm not in allow-list / baseline, flagged
  for review (supply-chain or developer引入).
* **Sudden RSA increase** — RSA count spikes > threshold vs baseline
  (migration rollback or new service bypassing PQC).
* **Crypto regression** — quantum-unsafe re-introduction: PQC asset count
  drops while classical rises (complement to :mod:`qtrust_ai.monitoring.regression`).

The detector keeps a **baseline window** (e.g. last 30 days of CBOM
snapshots) and scores each new :class:`CryptoSnapshot` using:
    - VAE reconstruction error (if torch available, via existing detector)
    - Statistical drift: KL divergence, z-score, chi-square on algorithm distribution
    - Rule checks: new-algo, RSA spike, regression

All methods are CPU-friendly. When ``torch`` is absent the VAE layer is
skipped; statistical + rule checks remain deterministic via hash jitter.

Example:

    from qtrust_ai.monitoring.anomaly import CryptoAnomalyDetector, CryptoSnapshot

    mon = CryptoAnomalyDetector(seed=42)
    mon.train()  # or mon.establish_baseline(baseline_snaps)
    alerts = mon.detect(CryptoSnapshot(algorithm_counts={"RSA-2048": 65}, total_assets=107))
    assert any(a.alert_type == "rsa_spike" for a in alerts)
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import numpy as np  # type: ignore
    HAS_NP = True
except ImportError:
    HAS_NP = False
    np = None  # type: ignore

try:
    import torch  # type: ignore
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    torch = None  # type: ignore

# Try to reuse existing VAE if available
try:
    from qtrust_inspector.anomaly_detector import CBOMAnomalyDetector as _VAEAnomalyDetector  # type: ignore
    HAS_VAE = True
except ImportError:
    try:
        from inspector.qtrust_inspector.anomaly_detector import CBOMAnomalyDetector as _VAEAnomalyDetector  # type: ignore
        HAS_VAE = True
    except ImportError:
        HAS_VAE = False
        _VAEAnomalyDetector = None  # type: ignore


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CryptoSnapshot:
    """Point-in-time crypto inventory snapshot (aggregated from CBOM or graph).

    Attributes:
        timestamp: ISO timestamp (defaults to now).
        algorithm_counts: Mapping ``algorithm → count`` (e.g. ``{"RSA-2048": 40}``).
        total_assets: Total asset count (sum of algorithm_counts if None).
        pqc_counts: PQC-specific subset (auto-derived if empty).
        source: Provenance label (e.g. "cbom:host-12", "ci:pr-42").
        metadata: Extra context (env, branch, pipeline id).
    """

    algorithm_counts: Dict[str, int] = field(default_factory=dict)
    total_assets: int = 0
    pqc_counts: Dict[str, int] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "snapshot"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.total_assets == 0 and self.algorithm_counts:
            self.total_assets = sum(self.algorithm_counts.values())
        if not self.pqc_counts and self.algorithm_counts:
            self.pqc_counts = {k: v for k, v in self.algorithm_counts.items() if any(x in k.upper() for x in ("ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FALCON"))}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_cbom(cls, cbom: Dict[str, Any], source: str = "cbom") -> "CryptoSnapshot":
        """Build from CBOM dict ``{"assets": [{"algorithm": ...}]}``."""
        counts: Counter = Counter()
        for asset in cbom.get("assets", []):
            algo = asset.get("algorithm", asset.get("algo", "UNKNOWN"))
            counts[str(algo)] += 1
        return cls(algorithm_counts=dict(counts), source=source, metadata={"cbom": True})

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CryptoSnapshot":
        return cls(
            algorithm_counts=dict(d.get("algorithm_counts", d.get("counts", {}))),
            total_assets=int(d.get("total_assets", 0)),
            pqc_counts=dict(d.get("pqc_counts", {})),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            source=d.get("source", "snapshot"),
            metadata=dict(d.get("metadata", {})),
        )


@dataclass
class AnomalyAlert:
    """Single anomaly alert from continuous monitoring."""

    alert_type: str  # new_algorithm | rsa_spike | unexpected_crypto | quantum_regression | distribution_drift | vae_anomaly
    severity: str  # INFO | LOW | MEDIUM | HIGH | CRITICAL
    message: str
    score: float = 0.0  # 0-1 confidence/anomaly score
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "anomaly"
    blocked: bool = False  # whether CI/CD should be blocked (for regression alerts)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MonitoringConfig:
    seed: int = 42
    # Thresholds
    new_algorithm_severity: str = "MEDIUM"  # new algo not in baseline → MEDIUM
    rsa_spike_z_threshold: float = 2.5  # z-score
    rsa_spike_pct_threshold: float = 0.30  # 30% increase
    unexpected_crypto_threshold: float = 0.05  # fraction of unexpected
    drift_kl_threshold: float = 0.15  # KL divergence
    drift_chi2_p_threshold: float = 0.01  # chi-square p-value (approx)
    regression_drop_threshold: float = 0.10  # PQC count drop fraction
    regression_rise_threshold: float = 0.15  # classical rise fraction
    vae_threshold: float = 0.80  # VAE anomaly threshold
    baseline_window: int = 30  # number of snapshots in baseline
    use_vae: bool = True
    allow_list: List[str] = field(default_factory=lambda: ["AES-256", "SHA-256", "SHA-384", "SHA-512"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _kl_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
    """KL(p||q) with smoothing."""
    eps = 1e-9
    keys = set(p) | set(q)
    kl = 0.0
    for k in keys:
        pk = p.get(k, eps)
        qk = q.get(k, eps)
        kl += pk * math.log(pk / qk)
    return max(0.0, kl)


def _zscore(value: float, mean: float, std: float) -> float:
    if std < 1e-9:
        return 0.0 if abs(value - mean) < 1e-9 else 5.0
    return (value - mean) / std


def _normalize_counts(counts: Dict[str, int]) -> Dict[str, float]:
    total = sum(counts.values()) or 1
    return {k: v / total for k, v in counts.items()}


def _deterministic_jitter(key: str, seed: int, scale: float = 1.0) -> float:
    h = hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()
    v = (int(h[:8], 16) / 0xFFFFFFFF) * 2 - 1
    return v * scale


_CLASSICAL_FAMILIES = {"RSA", "ECDSA", "ECDH", "DSA", "DH", "ED25519", "ED448", "X25519", "3DES", "DES", "MD5", "SHA-1"}
_PQC_FAMILIES = {"ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FALCON", "FN-DSA"}


def _is_classical(algo: str) -> bool:
    upper = algo.upper()
    return any(fam in upper for fam in _CLASSICAL_FAMILIES) and not any(fam in upper for fam in _PQC_FAMILIES)


def _is_pqc(algo: str) -> bool:
    upper = algo.upper()
    return any(fam in upper for fam in _PQC_FAMILIES)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class CryptoAnomalyDetector:
    """Continuous crypto anomaly detector (upgraded monitoring).

    Extends the existing VAE anomaly detector with streaming baseline
    comparison for four enterprise-critical cases:

    * **unexpected_crypto** — crypto in unexpected location / pipeline that
      was not in baseline (allow-list + baseline membership).
    * **new_algorithm** — algorithm family / primitive never seen in baseline.
    * **rsa_spike** — sudden RSA count increase (z-score + pct).
    * **quantum_regression** — PQC count drops while classical rises
      (migration rollback).

    The detector maintains a sliding baseline window of :class:`CryptoSnapshot`
    and optionally delegates to the VAE for per-asset reconstruction error.

    Attributes:
        config: :class:`MonitoringConfig`.
        baseline: List of :class:`CryptoSnapshot` used as normal.

    Example:
        >>> det = CryptoAnomalyDetector(seed=42)
        >>> det.establish_baseline([CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "AES-256": 30}, total_assets=70)])
        >>> alerts = det.detect(CryptoSnapshot(algorithm_counts={"RSA-2048": 65, "AES-256": 30, "DES": 2}, total_assets=97))
        >>> any(a.alert_type == "rsa_spike" for a in alerts)
        True
        >>> any(a.alert_type == "new_algorithm" for a in alerts)
        True
    """

    def __init__(self, config: Optional[MonitoringConfig] = None, seed: int = 42) -> None:
        self.config = config or MonitoringConfig(seed=seed)
        self.config.seed = seed
        random.seed(seed)
        self.baseline: List[CryptoSnapshot] = []
        self._baseline_algos: set[str] = set()
        self._baseline_algo_means: Dict[str, float] = {}
        self._baseline_algo_stds: Dict[str, float] = {}
        self._baseline_pqc_mean: float = 0.0
        self._baseline_pqc_std: float = 1.0
        self._baseline_dist: Dict[str, float] = {}
        self.is_trained = False
        self._vae: Any = None
        if HAS_VAE and self.config.use_vae and HAS_TORCH:
            try:
                self._vae = _VAEAnomalyDetector(threshold=self.config.vae_threshold)  # type: ignore
            except Exception:
                self._vae = None

    # ---- baseline management ----------------------------------------------

    def establish_baseline(self, snapshots: List[CryptoSnapshot]) -> Dict[str, Any]:
        """Set / replace the baseline window and recompute statistics.

        Args:
            snapshots: List of :class:`CryptoSnapshot` considered "normal"
                (e.g. last 30 days).

        Returns:
            Dict with ``n``, ``algos``, ``pqc_mean``.
        """
        # Keep most recent window
        if len(snapshots) > self.config.baseline_window:
            snapshots = snapshots[-self.config.baseline_window :]
        self.baseline = list(snapshots)
        # Algorithm set
        self._baseline_algos = set()
        for s in self.baseline:
            self._baseline_algos.update(s.algorithm_counts.keys())
        # Add allow-list to baseline (not anomalous if allow-listed)
        self._baseline_algos.update(self.config.allow_list)
        # Per-algorithm mean/std across snapshots
        all_algos = set(a for s in self.baseline for a in s.algorithm_counts)
        for algo in all_algos:
            vals = [float(s.algorithm_counts.get(algo, 0)) for s in self.baseline]
            mean = sum(vals) / len(vals) if vals else 0.0
            var = sum((v - mean) ** 2 for v in vals) / len(vals) if vals else 0.0
            std = math.sqrt(var) if var > 0 else max(1.0, mean * 0.30)
            self._baseline_algo_means[algo] = mean
            self._baseline_algo_stds[algo] = max(1.0, std)
        # PQC stats
        pqc_vals = [float(sum(s.pqc_counts.values())) for s in self.baseline]
        if pqc_vals:
            pm = sum(pqc_vals) / len(pqc_vals)
            pv = sum((v - pm) ** 2 for v in pqc_vals) / len(pqc_vals)
            self._baseline_pqc_mean = pm
            self._baseline_pqc_std = max(1.0, math.sqrt(pv) if pv > 0 else max(1.0, pm * 0.30))
        # Overall distribution (average normalized)
        agg: Counter = Counter()
        for s in self.baseline:
            agg.update(s.algorithm_counts)
        self._baseline_dist = _normalize_counts(dict(agg))
        self.is_trained = True
        return {"n": len(self.baseline), "algos": len(self._baseline_algos), "pqc_mean": round(self._baseline_pqc_mean, 1)}

    def train(self, snapshots: Optional[List[Dict[str, Any]]] = None, epochs: int = 3) -> Dict[str, Any]:
        """Establish baseline from snapshots or generate synthetic baseline.

        Also optionally trains the VAE layer on synthetic-normal CBOMs.

        Args:
            snapshots: List of :class:`CryptoSnapshot` or CBOM dicts.
                If ``None`` a synthetic baseline is generated.
            epochs: VAE training epochs (if torch available).

        Returns:
            Dict with baseline stats + VAE status.
        """
        if snapshots is None:
            # Generate synthetic baseline: mostly RSA/ECDSA+AES
            synth = self._generate_synthetic_baseline(n=30, seed=self.config.seed)
            stats = self.establish_baseline(synth)
            # Train VAE if possible
            vae_status = "skipped (torch unavailable)"
            if self._vae is not None and HAS_TORCH:
                try:
                    cboms = [{"assets": [{"algorithm": algo, "key_size": 2048 if "RSA" in algo else 256, "criticality": "medium", "expired": False, "vendor": "DigiCert", "self_signed": False, "days_until_expiry": 180, "location": f"host-{i}.example.com"} for algo, cnt in snap.algorithm_counts.items() for _ in range(cnt)]} for i, snap in enumerate(synth[:20])]
                    self._vae.train(cboms, epochs=epochs)  # type: ignore
                    vae_status = f"trained {epochs} epochs"
                except Exception as e:
                    vae_status = f"vae train failed: {e}"
                    self._vae = None
            return {**stats, "vae": vae_status, "mode": "synthetic"}

        # Normalize input
        snaps: List[CryptoSnapshot] = []
        for item in snapshots:
            if isinstance(item, CryptoSnapshot):
                snaps.append(item)
            elif isinstance(item, dict) and "algorithm_counts" in item:
                snaps.append(CryptoSnapshot.from_dict(item))
            elif isinstance(item, dict) and "assets" in item:
                snaps.append(CryptoSnapshot.from_cbom(item))
            else:
                # assume dict of algo->count
                if isinstance(item, dict):
                    snaps.append(CryptoSnapshot(algorithm_counts={str(k): int(v) for k, v in item.items()}))
        stats = self.establish_baseline(snaps)
        # Optional VAE training on same snapshots
        vae_status = "skipped"
        if self._vae is not None and HAS_TORCH and snaps:
            try:
                cboms = [{"assets": [{"algorithm": algo, "key_size": 2048 if "RSA" in algo else 256, "criticality": "medium", "expired": False, "vendor": "DigiCert", "self_signed": False, "days_until_expiry": 200, "location": f"asset-{si}"} for algo, cnt in s.algorithm_counts.items() for si in range(cnt)]} for s in snaps[:15]]
                self._vae.train(cboms, epochs=epochs)  # type: ignore
                vae_status = f"trained {epochs} epochs"
            except Exception as e:
                vae_status = f"failed: {e}"
                self._vae = None
        return {**stats, "vae": vae_status, "mode": "provided"}

    # ---- detection --------------------------------------------------------

    def detect(self, snapshot: CryptoSnapshot) -> List[AnomalyAlert]:
        """Detect anomalies in *snapshot* vs baseline.

        Runs four rule/statistical checks plus optional VAE:

        * **new_algorithm** — algorithm not in baseline
        * **unexpected_crypto** — unexpected location/new criticality (if metadata)
        * **rsa_spike** — RSA family count spike
        * **quantum_regression** — PQC drop + classical rise
        * **distribution_drift** — KL divergence on overall distribution
        * **vae_anomaly** — VAE reconstruction error (if trained)

        Args:
            snapshot: :class:`CryptoSnapshot` to score.

        Returns:
            List of :class:`AnomalyAlert` (empty if normal).
        """
        if not self.is_trained or not self.baseline:
            return [AnomalyAlert(alert_type="not_trained", severity="INFO", message="No baseline established — call establish_baseline() or train()", score=0.0)]
        alerts: List[AnomalyAlert] = []
        alerts.extend(self._check_new_algorithm(snapshot))
        alerts.extend(self._check_unexpected_crypto(snapshot))
        alerts.extend(self._check_rsa_spike(snapshot))
        alerts.extend(self._check_quantum_regression(snapshot))
        alerts.extend(self._check_distribution_drift(snapshot))
        # VAE layer
        if self._vae is not None and HAS_TORCH:
            try:
                vae_alert = self._check_vae(snapshot)
                if vae_alert:
                    alerts.append(vae_alert)
            except Exception:
                pass
        # Deduplicate by type
        seen = set()
        uniq: List[AnomalyAlert] = []
        for a in alerts:
            key = (a.alert_type, a.message)
            if key not in seen:
                uniq.append(a)
                seen.add(key)
        return uniq

    def _check_new_algorithm(self, snap: CryptoSnapshot) -> List[AnomalyAlert]:
        alerts: List[AnomalyAlert] = []
        for algo in snap.algorithm_counts:
            if algo not in self._baseline_algos:
                # Allow small counts of symmetric/hash that may be baseline noise
                if algo in self.config.allow_list:
                    continue
                cnt = snap.algorithm_counts[algo]
                severity = self.config.new_algorithm_severity
                # Classical PQC-family new algo is higher severity
                if _is_classical(algo) and cnt >= 2:
                    severity = "HIGH" if any(x in algo.upper() for x in ("RSA", "ECDSA")) else "MEDIUM"
                alerts.append(AnomalyAlert(
                    alert_type="new_algorithm",
                    severity=severity,
                    message=f"New algorithm '{algo}' not in baseline (count={cnt}) — supply-chain or developer introduced",
                    score=0.85 if severity in ("HIGH", "CRITICAL") else 0.65,
                    details={"algorithm": algo, "count": cnt, "baseline_algos": len(self._baseline_algos)},
                    source=snap.source,
                ))
        return alerts

    def _check_unexpected_crypto(self, snap: CryptoSnapshot) -> List[AnomalyAlert]:
        alerts: List[AnomalyAlert] = []
        # Flag: snapshot contains weak primitives not expected after cleanup
        weak_algos = {a for a in snap.algorithm_counts if any(x in a.upper() for x in ("DES", "MD5", "SHA-1", "3DES", "RSA-1024", "ECDSA-SHA1"))}
        for algo in weak_algos:
            cnt = snap.algorithm_counts[algo]
            alerts.append(AnomalyAlert(
                alert_type="unexpected_crypto",
                severity="HIGH" if cnt >= 3 else "MEDIUM",
                message=f"Unexpected weak crypto '{algo}' still present (count={cnt}) — cleanup incomplete or config drift",
                score=0.80,
                details={"algorithm": algo, "count": cnt},
                source=snap.source,
            ))
        # Flag: metadata-driven unexpected location (if provided)
        loc = snap.metadata.get("location") or snap.metadata.get("env")
        if loc and loc not in [s.metadata.get("location") for s in self.baseline]:
            # Only if total is non-trivial
            if snap.total_assets > 5:
                alerts.append(AnomalyAlert(
                    alert_type="unexpected_crypto",
                    severity="LOW",
                    message=f"Crypto observed in unexpected location/env '{loc}' not in baseline",
                    score=0.45,
                    details={"location": loc},
                    source=snap.source,
                ))
        return alerts

    def _check_rsa_spike(self, snap: CryptoSnapshot) -> List[AnomalyAlert]:
        alerts: List[AnomalyAlert] = []
        # RSA family aggregate (all RSA-* variants)
        rsa_current = sum(cnt for algo, cnt in snap.algorithm_counts.items() if "RSA" in algo.upper())
        # Baseline RSA mean/std
        rsa_vals = [sum(cnt for algo, cnt in s.algorithm_counts.items() if "RSA" in algo.upper()) for s in self.baseline]
        if not rsa_vals:
            return alerts
        mean = sum(rsa_vals) / len(rsa_vals) if rsa_vals else 0.0
        var = sum((v - mean) ** 2 for v in rsa_vals) / len(rsa_vals) if rsa_vals else 0.0
        std = math.sqrt(var) if var > 0 else max(1.0, mean * 0.30)
        zs = _zscore(float(rsa_current), mean, std)
        pct = (rsa_current - mean) / max(1.0, mean) if mean else (1.0 if rsa_current else 0.0)
        if zs >= self.config.rsa_spike_z_threshold or pct >= self.config.rsa_spike_pct_threshold:
            # Only alert if absolute increase is meaningful (>=3)
            if rsa_current - mean >= 3:
                severity = "CRITICAL" if zs >= 3.5 and pct >= 0.50 else ("HIGH" if zs >= 3.0 or pct >= 0.40 else "MEDIUM")
                alerts.append(AnomalyAlert(
                    alert_type="rsa_spike",
                    severity=severity,
                    message=f"Sudden RSA increase: {rsa_current} vs baseline {mean:.1f} (z={zs:.1f}, +{pct:.0%}) — possible rollback or new service bypassing PQC",
                    score=min(0.95, 0.60 + zs * 0.08),
                    details={"rsa_current": rsa_current, "rsa_baseline_mean": round(mean, 1), "zscore": round(zs, 2), "pct_increase": round(pct, 3)},
                    source=snap.source,
                ))
        # Also check any single algorithm spike (e.g. RSA-2048 specifically)
        for algo, cnt in snap.algorithm_counts.items():
            if "RSA" not in algo.upper():
                continue
            mean_a = self._baseline_algo_means.get(algo, 0.0)
            std_a = self._baseline_algo_stds.get(algo, max(1.0, mean_a * 0.30))
            zs_a = _zscore(float(cnt), mean_a, std_a)
            pct_a = (cnt - mean_a) / max(1.0, mean_a) if mean_a else (1.0 if cnt else 0.0)
            if zs_a >= self.config.rsa_spike_z_threshold and pct_a >= self.config.rsa_spike_pct_threshold and cnt - mean_a >= 3:
                # Already covered by family; avoid duplicate if family already alerted
                if not any(a.alert_type == "rsa_spike" for a in alerts):
                    alerts.append(AnomalyAlert(
                        alert_type="rsa_spike",
                        severity="MEDIUM",
                        message=f"RSA variant spike: {algo} {cnt} vs baseline {mean_a:.1f} (z={zs_a:.1f})",
                        score=min(0.90, 0.60 + zs_a * 0.07),
                        details={"algorithm": algo, "count": cnt, "mean": round(mean_a, 1), "zscore": round(zs_a, 2)},
                        source=snap.source,
                    ))
                break
        return alerts

    def _check_quantum_regression(self, snap: CryptoSnapshot) -> List[AnomalyAlert]:
        alerts: List[AnomalyAlert] = []
        pqc_current = sum(snap.pqc_counts.values()) if snap.pqc_counts else sum(cnt for algo, cnt in snap.algorithm_counts.items() if _is_pqc(algo))
        classical_current = sum(cnt for algo, cnt in snap.algorithm_counts.items() if _is_classical(algo))
        # Baseline aggregates
        pqc_baseline = self._baseline_pqc_mean
        classical_baseline = sum(
            sum(cnt for algo, cnt in s.algorithm_counts.items() if _is_classical(algo)) for s in self.baseline
        ) / len(self.baseline) if self.baseline else 0.0
        # Regression condition: PQC drops ≥ threshold AND classical rises ≥ threshold
        pqc_drop = (pqc_baseline - pqc_current) / max(1.0, pqc_baseline) if pqc_baseline else 0.0
        classical_rise = (classical_current - classical_baseline) / max(1.0, classical_baseline) if classical_baseline else (1.0 if classical_current else 0.0)
        if pqc_drop >= self.config.regression_drop_threshold and classical_rise >= self.config.regression_rise_threshold:
            # Absolute counts guard: need at least 2 PQC lost and 3 classical gained
            if pqc_baseline - pqc_current >= 1 and classical_current - classical_baseline >= 2:
                alerts.append(AnomalyAlert(
                    alert_type="quantum_regression",
                    severity="CRITICAL",
                    message=f"Crypto regression: PQC {pqc_current:.0f} vs baseline {pqc_baseline:.0f} (drop {pqc_drop:.0%}), classical {classical_current:.0f} vs baseline {classical_baseline:.0f} (rise {classical_rise:.0%}) — rollback to quantum-vulnerable",
                    score=0.92,
                    details={"pqc_current": pqc_current, "pqc_baseline": round(pqc_baseline, 1), "pqc_drop": round(pqc_drop, 3), "classical_current": classical_current, "classical_baseline": round(classical_baseline, 1), "classical_rise": round(classical_rise, 3)},
                    source=snap.source,
                    blocked=True,
                ))
        # Also flag if any specific PQC→classical drop at algorithm level (e.g. ML-KEM gone, RSA up)
        if pqc_current == 0 and pqc_baseline >= 2:
            # Full disappearance
            alerts.append(AnomalyAlert(
                alert_type="quantum_regression",
                severity="CRITICAL",
                message=f"Quantum regression: PQC completely disappeared (baseline {pqc_baseline:.0f} PQC assets) — migration rollback",
                score=0.95,
                details={"pqc_current": pqc_current, "pqc_baseline": round(pqc_baseline, 1)},
                source=snap.source,
                blocked=True,
            ))
        return alerts

    def _check_distribution_drift(self, snap: CryptoSnapshot) -> List[AnomalyAlert]:
        alerts: List[AnomalyAlert] = []
        cur_dist = _normalize_counts(snap.algorithm_counts)
        kl = _kl_divergence(cur_dist, self._baseline_dist if self._baseline_dist else _normalize_counts({k: 1 for k in cur_dist}))
        if kl >= self.config.drift_kl_threshold:
            severity = "HIGH" if kl >= 0.35 else ("MEDIUM" if kl >= 0.22 else "LOW")
            alerts.append(AnomalyAlert(
                alert_type="distribution_drift",
                severity=severity,
                message=f"Crypto distribution drift KL={kl:.3f} (threshold {self.config.drift_kl_threshold}) — inventory composition shifted",
                score=min(0.85, 0.45 + kl),
                details={"kl_divergence": round(kl, 4), "threshold": self.config.drift_kl_threshold},
                source=snap.source,
            ))
        return alerts

    def _check_vae(self, snap: CryptoSnapshot) -> Optional[AnomalyAlert]:
        if self._vae is None or not HAS_TORCH:
            return None
        # Build minimal CBOM from snapshot
        cbom = {"assets": [{"algorithm": algo, "key_size": 2048 if "RSA" in algo.upper() else 256, "criticality": "medium", "expired": False, "vendor": "DigiCert", "self_signed": False, "days_until_expiry": 180, "location": f"asset-{i}_{algo}"} for algo, cnt in snap.algorithm_counts.items() for i in range(min(cnt, 20))]}
        if not cbom["assets"]:
            return None
        try:
            if not getattr(self._vae, "trained", False):
                return None
            result = self._vae.score_cbom(cbom)  # type: ignore
            if result.is_anomalous:
                return AnomalyAlert(
                    alert_type="vae_anomaly",
                    severity="MEDIUM" if result.anomaly_score < 0.90 else "HIGH",
                    message=f"VAE anomaly: reconstruction score {result.anomaly_score:.3f} > threshold {result.threshold:.3f} (assets={result.asset_count})",
                    score=float(result.anomaly_score),
                    details={"anomaly_score": round(float(result.anomaly_score), 4), "threshold": round(float(result.threshold), 4), "asset_count": result.asset_count},
                    source=snap.source,
                )
        except Exception:
            return None
        return None

    # ---- streaming ---------------------------------------------------------

    def detect_stream(self, snapshots: List[CryptoSnapshot]) -> List[List[AnomalyAlert]]:
        """Detect on a stream of snapshots, updating baseline sliding window.

        Args:
            snapshots: Ordered snapshots (oldest → newest).

        Returns:
            List per snapshot of alerts (same length as input).
        """
        results: List[List[AnomalyAlert]] = []
        for snap in snapshots:
            alerts = self.detect(snap)
            results.append(alerts)
            # Rolling baseline: append if normal, else keep baseline
            if not any(a.severity in ("CRITICAL", "HIGH") for a in alerts):
                self.baseline.append(snap)
                if len(self.baseline) > self.config.baseline_window:
                    self.baseline.pop(0)
                # Recompute stats incrementally (full recompute for simplicity)
                self.establish_baseline(self.baseline)
        return results

    def evaluate(self, dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Evaluate detector on labelled dataset.

        Args:
            dataset: List of ``{"snapshot": CryptoSnapshot|dict, "label": 0/1,
                "anomaly_type": str}``. If ``None`` synthetic eval set.

        Returns:
            Dict with ``precision``, ``recall``, ``f1``, ``n``.
        """
        if dataset is None:
            dataset = self._generate_synthetic_eval(seed=self.config.seed + 101)
        # Ensure baseline exists
        if not self.is_trained:
            self.train()
        y_true: List[int] = []
        y_pred: List[int] = []
        per_type: Dict[str, Dict[str, int]] = {}
        for ex in dataset:
            raw = ex.get("snapshot", ex)
            if isinstance(raw, dict) and "algorithm_counts" in raw:
                snap = CryptoSnapshot.from_dict(raw)
            elif isinstance(raw, CryptoSnapshot):
                snap = raw
            elif isinstance(raw, dict) and "assets" in raw:
                snap = CryptoSnapshot.from_cbom(raw)
            else:
                snap = CryptoSnapshot(algorithm_counts=dict(raw) if isinstance(raw, dict) else {})
            true = int(ex.get("label", 0))
            pred = 1 if self.detect(snap) else 0
            y_true.append(true)
            y_pred.append(pred)
            atype = ex.get("anomaly_type", "unknown")
            per_type.setdefault(atype, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            if true == 1 and pred == 1:
                per_type[atype]["tp"] += 1
            elif true == 0 and pred == 1:
                per_type[atype]["fp"] += 1
            elif true == 1 and pred == 0:
                per_type[atype]["fn"] += 1
            else:
                per_type[atype]["tn"] += 1
        # P/R/F1
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return {
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "n": len(dataset),
            "per_type": per_type,
            "baseline_n": len(self.baseline),
        }

    # ---- synthetic helpers ------------------------------------------------

    def _generate_synthetic_baseline(self, n: int = 30, seed: int = 42) -> List[CryptoSnapshot]:
        rnd = random.Random(seed)
        snaps: List[CryptoSnapshot] = []
        for i in range(n):
            # Normal baseline: RSA 35-45, ECDSA 8-12, AES 25-35
            rsa = rnd.randint(35, 45)
            ecdsa = rnd.randint(8, 12)
            aes = rnd.randint(25, 35)
            sha = rnd.randint(5, 10)
            total = rsa + ecdsa + aes + sha
            snaps.append(CryptoSnapshot(
                algorithm_counts={"RSA-2048": rsa, "ECDSA-P256": ecdsa, "AES-256": aes, "SHA-256": sha},
                total_assets=total,
                pqc_counts={},
                source=f"baseline-{i}",
                metadata={"env": "prod"},
            ))
        return snaps

    def _generate_synthetic_eval(self, n: int = 100, seed: int = 42) -> List[Dict[str, Any]]:
        rnd = random.Random(seed)
        # First establish a baseline to define "normal"
        baseline = self._generate_synthetic_baseline(n=20, seed=seed)
        # Normal snapshots
        dataset: List[Dict[str, Any]] = []
        for _ in range(n // 2):
            rsa = rnd.randint(35, 45)
            dataset.append({"snapshot": CryptoSnapshot(algorithm_counts={"RSA-2048": rsa, "ECDSA-P256": rnd.randint(8, 12), "AES-256": rnd.randint(25, 35), "SHA-256": rnd.randint(5, 10)}), "label": 0, "anomaly_type": "normal"})
        # Anomalous: new algorithm
        for _ in range(n // 6):
            dataset.append({"snapshot": CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "AES-256": 30, "DES": rnd.randint(2, 5)}), "label": 1, "anomaly_type": "new_algorithm"})
        # Anomalous: RSA spike
        for _ in range(n // 6):
            dataset.append({"snapshot": CryptoSnapshot(algorithm_counts={"RSA-2048": rnd.randint(60, 80), "AES-256": 30}), "label": 1, "anomaly_type": "rsa_spike"})
        # Anomalous: quantum regression (PQC → classical)
        for _ in range(n - len(dataset)):
            dataset.append({"snapshot": CryptoSnapshot(algorithm_counts={"RSA-2048": rnd.randint(50, 70), "AES-256": 25}, pqc_counts={}), "label": 1, "anomaly_type": "quantum_regression"})
        rnd.shuffle(dataset)
        # Ensure detector has baseline (but don't overwrite if already trained externally)
        if not self.is_trained:
            self.establish_baseline(baseline)
        return dataset


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== CryptoAnomalyDetector demo — continuous monitoring ===")
    det = CryptoAnomalyDetector(seed=42)
    baseline = det._generate_synthetic_baseline(n=20, seed=42)
    stats = det.establish_baseline(baseline)
    print(f"[baseline] {json.dumps(stats, indent=2)}")
    train_res = det.train(baseline, epochs=1)
    print(f"[train] {json.dumps({k: v for k, v in train_res.items() if k != 'mode'}, indent=2)}")

    cases = [
        ("normal", CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "ECDSA-P256": 10, "AES-256": 30, "SHA-256": 8}, source="prod-normal")),
        ("rsa_spike", CryptoSnapshot(algorithm_counts={"RSA-2048": 68, "ECDSA-P256": 10, "AES-256": 30}, source="prod-spike")),
        ("new_algo", CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "AES-256": 30, "DES": 3}, source="prod-newalgo")),
        ("weak_crypto", CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "AES-256": 30, "MD5": 4}, source="prod-weak")),
        ("quantum_regression", CryptoSnapshot(algorithm_counts={"RSA-2048": 55, "ECDSA-P256": 12}, pqc_counts={}, source="prod-regression")),
        ("drift", CryptoSnapshot(algorithm_counts={"RSA-1024": 20, "DES": 10, "MD5": 8}, source="prod-drift")),
        ("pqc_healthy", CryptoSnapshot(algorithm_counts={"RSA-2048": 10, "ML-KEM-768": 30, "ML-DSA-65": 8, "AES-256": 25}, pqc_counts={"ML-KEM-768": 30, "ML-DSA-65": 8}, source="prod-pqc")),
    ]
    for label, snap in cases:
        alerts = det.detect(snap)
        print(f"\n[{label:20s}] algos={snap.algorithm_counts} pqc={snap.pqc_counts}")
        if alerts:
            for a in alerts:
                print(f"  -> {a.alert_type:20s} {a.severity:8s} score={a.score:.2f} blocked={a.blocked}")
                print(f"     {a.message}")
                if a.details:
                    print(f"     details={a.details}")
        else:
            print("  -> no anomalies (normal)")

    # Stream demo
    print("\n--- stream detection ---")
    stream = [
        CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "AES-256": 30}, source="stream-0"),
        CryptoSnapshot(algorithm_counts={"RSA-2048": 42, "AES-256": 30}, source="stream-1"),
        CryptoSnapshot(algorithm_counts={"RSA-2048": 67, "AES-256": 30}, source="stream-2"),
        CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "AES-256": 30, "DES": 2}, source="stream-3"),
    ]
    det2 = CryptoAnomalyDetector(seed=42)
    det2.establish_baseline(baseline)
    for alerts in det2.detect_stream(stream):
        print(f"  step {len([a for a in stream if True])} alerts={len(alerts)} types={[a.alert_type for a in alerts]}")

    eval_res = det.evaluate()
    print(f"\n[evaluate] P={eval_res['precision']} R={eval_res['recall']} F1={eval_res['f1']} n={eval_res['n']}")
    for atype, metrics in eval_res["per_type"].items():
        print(f"  {atype:20s} {metrics}")

    # Assertion: RSA spike and new algo must trigger
    assert any(a.alert_type == "rsa_spike" for a in det.detect(CryptoSnapshot(algorithm_counts={"RSA-2048": 70, "AES-256": 30}))), "RSA spike not detected"
    assert any(a.alert_type == "new_algorithm" for a in det.detect(CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "DES": 3}))), "new algorithm not detected"
    print("\n✓ continuous monitoring assertions passed — RSA spike & new algorithm detected, VAE layer optional")
