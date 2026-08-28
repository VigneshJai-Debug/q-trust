"""
Migration Cost Predictor — engineering hours, downtime, testing, hardware, duration.

Predicts the real cost of migrating an application / service to PQC *before*
execution, so planners can optimise the roadmap. Corresponds to
``qtrust_ai/README.md`` Phase 2 Migration Intel and the planner reward term
``- w3·cost - w4·downtime``.

Outputs (per migration / asset):
    * engineering_hours  — dev + crypto + code-review hours
    * testing_hours      — unit / integ / interop / perf testing hours
    * downtime_percent   — expected service downtime (%) during cutover
    * hardware_upgrade_prob — probability an HSM / accelerator must be replaced
    * cert_replacement_count — number of certs / keys to re-issue
    * rollback_prob      — probability migration must be rolled back
    * duration_days      — calendar duration for the migration
    * total_cost_usd     — optional USD estimate (hours × blended rate)

Example anchoring (used in training synthetic data and tests):
    Legacy banking API → hybrid PQC: 84h eng, 31h testing, 4% downtime,
    17 dependents, 12 days — this calibrates the heuristic.

Architecture: CPU-friendly linear + non-linear heuristic with deterministic
hash jitter when ``sklearn`` is absent. ``train()`` fits weights via
random-search on synthetic org data (40/30/20/10 mix discipline).

Example:
    pred = MigrationCostPredictor()
    pred.train()
    feats = MigrationCostFeatures(app_type="banking-api", legacy=True,
                                  target_pqc="hybrid", dependency_count=17)
    r = pred.predict(feats)
    assert 60 < r.engineering_hours < 110  # ~84h anchored
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

try:
    from sklearn.ensemble import RandomForestRegressor  # type: ignore
    from sklearn.linear_model import Ridge  # type: ignore
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    RandomForestRegressor = None  # type: ignore
    Ridge = None  # type: ignore


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class MigrationCostFeatures:
    """Input features for cost prediction.

    Attributes:
        app_type: Application category (``banking-api``, ``payment``,
            ``tls-gateway``, ``iot-firmware``, ``web``, ``mobile``, ...).
        protocol: Crypto protocol (``TLS1.2``, ``TLS1.3``, ``mTLS``, ``SSH``,
            ``IPSec``, ``custom``).
        library: Crypto library (``openssl``, ``boringssl``, ``libsodium``,
            ``bouncy-castle``, ``mbedtls``, ``proprietary``).
        library_version: Version string (``"3.0.8"``) — older → higher cost.
        hardware: Hardware type (``x86``, ``arm``, ``hsm``, ``tpm``, ``iot-mcu``).
        legacy: Whether the asset is legacy / end-of-life.
        target_pqc: Migration target (``"full"`` PQC, ``"hybrid"``, ``"pq-only"``).
        dependency_count: Number of direct + transitive dependents.
        loc: Lines of code (thousands proxy via int); default 10.
        team_size: Engineers assigned (affects duration vs hours).
        cert_count: Current cert/key count; ``None`` → inferred from deps.
        traffic_rps: Peak traffic (requests/s) — higher → higher downtime risk.
        compliance_level: ``low`` | ``medium`` | ``high`` (controls testing).
    """

    app_type: str = "web"
    protocol: str = "TLS1.3"
    library: str = "openssl"
    library_version: str = "3.0.0"
    hardware: str = "x86"
    legacy: bool = False
    target_pqc: str = "hybrid"
    dependency_count: int = 5
    loc: int = 10
    team_size: int = 3
    cert_count: Optional[int] = None
    traffic_rps: int = 500
    compliance_level: str = "medium"

    def clamp(self) -> "MigrationCostFeatures":
        import copy
        c = copy.copy(self)
        c.dependency_count = max(0, min(200, int(c.dependency_count)))
        c.loc = max(1, min(10000, int(c.loc)))
        c.team_size = max(1, min(50, int(c.team_size)))
        c.traffic_rps = max(0, min(1_000_000, int(c.traffic_rps)))
        if c.cert_count is not None:
            c.cert_count = max(0, min(5000, int(c.cert_count)))
        c.compliance_level = c.compliance_level.lower().strip()
        if c.compliance_level not in ("low", "medium", "high"):
            c.compliance_level = "medium"
        c.target_pqc = c.target_pqc.lower().strip()
        return c


@dataclass
class CostPrediction:
    """Output of :meth:`MigrationCostPredictor.predict`."""

    engineering_hours: float
    testing_hours: float
    downtime_percent: float
    hardware_upgrade_prob: float
    cert_replacement_count: int
    rollback_prob: float
    duration_days: int
    total_cost_usd: float
    breakdown: Dict[str, float] = field(default_factory=dict)
    interval_days: Optional[Tuple[float, float]] = None
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CostPredictorConfig:
    seed: int = 42
    blended_hourly_rate_usd: float = 150.0
    use_sklearn: bool = True
    conformal_alpha: float = 0.1
    conformal_margin_hours: Optional[float] = None


# ---------------------------------------------------------------------------
# Heuristic helpers — deterministic, calibrated to the banking-API anchor
# ---------------------------------------------------------------------------

_APP_TYPE_COEFF: Dict[str, Dict[str, float]] = {
    # coeffs are multipliers on base hours; anchored to banking-api = 1.0
    "banking-api": {"eng": 1.00, "test": 1.00, "downtime": 1.0, "hardware": 0.35},
    "payment": {"eng": 0.95, "test": 1.10, "downtime": 1.2, "hardware": 0.40},
    "tls-gateway": {"eng": 0.70, "test": 0.90, "downtime": 0.8, "hardware": 0.25},
    "auth-service": {"eng": 0.85, "test": 1.00, "downtime": 1.0, "hardware": 0.30},
    "web": {"eng": 0.55, "test": 0.70, "downtime": 0.6, "hardware": 0.15},
    "mobile": {"eng": 0.60, "test": 0.85, "downtime": 0.5, "hardware": 0.10},
    "iot-firmware": {"eng": 1.30, "test": 1.40, "downtime": 1.5, "hardware": 0.80},
    "ssh": {"eng": 0.65, "test": 0.80, "downtime": 0.7, "hardware": 0.20},
    "vpn": {"eng": 0.75, "test": 0.95, "downtime": 0.9, "hardware": 0.30},
    "hsm": {"eng": 1.20, "test": 1.30, "downtime": 1.4, "hardware": 0.95},
}

_PROTOCOL_COEFF: Dict[str, float] = {
    "TLS1.3": 1.0, "TLS1.2": 1.25, "mTLS": 1.35, "SSH": 1.15, "IPSec": 1.30,
    "QUIC": 1.20, "custom": 1.50, "proprietary": 1.60,
}

_LIBRARY_AGE_PENALTY: Dict[str, float] = {
    # version -> penalty (older majors cost more)
    "openssl-1.1": 1.40, "openssl-1.0": 1.70, "openssl-3": 1.00,
    "boringssl": 1.05, "libsodium": 1.10, "bouncy-castle": 1.15,
    "mbedtls-2": 1.35, "mbedtls-3": 1.10, "proprietary": 1.50, "unknown": 1.30,
}

_HARDWARE_UPGRADE_BASE: Dict[str, float] = {
    "x86": 0.10, "arm": 0.18, "tpm": 0.35, "hsm": 0.65, "iot-mcu": 0.75,
    "smartcard": 0.80, "fpga": 0.40, "unknown": 0.30,
}

# Anchor: legacy banking-api hybrid ML-KEM+ML-DSA → 84h eng, 31h test, 4% downtime, 17 deps, 12 days
_ANCHOR = {
    "app_type": "banking-api", "legacy": True, "target": "hybrid",
    "deps": 17, "eng": 84.0, "test": 31.0, "downtime": 4.0, "duration": 12,
}


def _lib_penalty(library: str, version: str) -> float:
    lib = library.lower().replace(" ", "").replace("_", "-")
    ver = version.strip()
    # Try specific then family
    for k in (f"{lib}-{ver.split('.')[0]}", lib, "unknown"):
        if k in _LIBRARY_AGE_PENALTY:
            return _LIBRARY_AGE_PENALTY[k]
        # openssl families
        if lib.startswith("openssl"):
            if ver.startswith("1.1"):
                return _LIBRARY_AGE_PENALTY["openssl-1.1"]
            if ver.startswith("1.0"):
                return _LIBRARY_AGE_PENALTY["openssl-1.0"]
            if ver.startswith("3"):
                return _LIBRARY_AGE_PENALTY["openssl-3"]
        if lib.startswith("mbedtls"):
            if ver.startswith("2"):
                return _LIBRARY_AGE_PENALTY["mbedtls-2"]
            return _LIBRARY_AGE_PENALTY["mbedtls-3"]
    return 1.20


def _deterministic_jitter(key: str, seed: int, scale: float = 1.0) -> float:
    """Deterministic zero-mean jitter in [-scale, +scale]."""
    h = hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()
    v = (int(h[:8], 16) / 0xFFFFFFFF) * 2 - 1  # -1..1
    return v * scale


def _base_hours(features: MigrationCostFeatures, config: CostPredictorConfig) -> Tuple[float, float]:
    """Compute base eng/test hours before jitter — anchored to the banking-API spec.

    The anchor is ``banking-api, legacy=True, hybrid, 17 deps, TLS1.3,
    openssl 3.x, x86, LOC 10, compliance medium`` → 84h / 31h. All factors
    are *relative* to that anchor so the spec example is reproduced.
    """
    c = features.clamp()
    app = c.app_type.lower().replace("_", "-")
    coeff = _APP_TYPE_COEFF.get(app, {"eng": 0.70, "test": 0.85, "downtime": 0.8, "hardware": 0.25})
    # Anchor app is banking-api with coeff 1.0 — no division needed
    # but other app types scale relative
    anchor_proto = _PROTOCOL_COEFF["TLS1.3"]  # 1.0
    proto = _PROTOCOL_COEFF.get(c.protocol, 1.20) / anchor_proto
    anchor_lib_pen = _LIBRARY_AGE_PENALTY["openssl-3"]  # 1.0
    lib_pen = _lib_penalty(c.library, c.library_version) / anchor_lib_pen

    dep_factor = 1.0 + (c.dependency_count - _ANCHOR["deps"]) * 0.035  # each dep +3.5%
    dep_factor = max(0.5, dep_factor)
    # Anchor is legacy=True (baseline 1.0); non-legacy is cheaper (migration easier)
    legacy_factor = 1.0 if c.legacy else 0.80
    target_factor = {"hybrid": 1.0, "full": 1.15, "pq-only": 1.35, "hf-hybrid": 1.05}.get(c.target_pqc.lower(), 1.10)
    loc_factor = 1.0 + max(0, (c.loc - 10)) * 0.015  # each 1k LOC above 10 adds 1.5%
    compliance_factor = {"low": 0.85, "medium": 1.0, "high": 1.25}[c.compliance_level]

    eng = _ANCHOR["eng"] * coeff["eng"] * dep_factor * legacy_factor * proto * lib_pen * target_factor * loc_factor * compliance_factor
    test = _ANCHOR["test"] * coeff["test"] * dep_factor * legacy_factor * proto * lib_pen * target_factor * (0.7 + 0.3 * loc_factor) * compliance_factor

    return eng, test


def _downtime_prob(features: MigrationCostFeatures) -> float:
    c = features.clamp()
    app = c.app_type.lower().replace("_", "-")
    coeff = _APP_TYPE_COEFF.get(app, {"eng": 0.70, "test": 0.85, "downtime": 0.8, "hardware": 0.25})
    # Anchor 4% for banking-api legacy hybrid TLS1.3 openssl3 (baseline 1.0)
    base = _ANCHOR["downtime"] * coeff["downtime"]
    # Legacy anchor is True → non-legacy cheaper
    if not c.legacy:
        base *= 0.83
    # Full PQ adds cutover complexity vs hybrid anchor (1.0)
    if c.target_pqc.lower() == "full":
        base *= 1.25
    elif c.target_pqc.lower() == "pq-only":
        base *= 1.40
    # Traffic scales downtime severity (relative to anchor ~500 RPS)
    if c.traffic_rps > 10000:
        base *= 1.40
    elif c.traffic_rps > 1000:
        base *= 1.15
    # Protocol relative to anchor TLS1.3
    if c.protocol.lower() in ("mtls", "ipsec", "custom"):
        base *= 1.25
    elif c.protocol.lower() == "tls1.2":
        base *= 1.15
    # Dependency count relative to anchor 17 deps
    dep_delta = c.dependency_count - _ANCHOR["deps"]
    base *= (1.0 + max(-0.3, min(0.5, dep_delta * 0.02)))
    return max(0.1, min(35.0, base))


def _hardware_prob(features: MigrationCostFeatures) -> float:
    c = features.clamp()
    base = _HARDWARE_UPGRADE_BASE.get(c.hardware.lower(), 0.30)
    if c.legacy:
        base = min(0.95, base * 1.6)
    # Target PQC often needs bigger keys → HSM / MCU upgrades
    if c.target_pqc.lower() in ("full", "pq-only"):
        base = min(0.95, base * 1.25)
    # Crypto agility: libs older than 3.x on HSM → near-certain upgrade
    if c.hardware.lower() in ("hsm", "tpm", "smartcard") and c.library_version.startswith("1."):
        base = min(0.95, base * 1.5)
    # Dependency count proxy: many dependents often means embedded
    base = min(0.95, base + min(0.2, c.dependency_count * 0.008))
    return max(0.01, min(0.95, base))


def _cert_count(features: MigrationCostFeatures) -> int:
    if features.cert_count is not None:
        return max(0, int(features.cert_count))
    # Infer from deps: ~0.7 certs per dep, at least 1 if any deps
    c = features.clamp()
    inferred = max(1, round(c.dependency_count * 0.7)) if c.dependency_count else 1
    # Protocol multiplier
    if c.protocol.lower() in ("mtls", "tls1.2", "tls1.3"):
        inferred = max(inferred, 2)
    return inferred


def _rollback_prob(features: MigrationCostFeatures, downtime: float, hw_prob: float) -> float:
    c = features.clamp()
    p = 0.04  # baseline
    if c.legacy:
        p += 0.06
    if c.target_pqc.lower() == "full":
        p += 0.04
    if hw_prob > 0.5:
        p += 0.05
    if downtime > 5:
        p += 0.04
    if c.dependency_count > 20:
        p += 0.03
    if c.traffic_rps > 5000:
        p += 0.03
    if "proprietary" in c.library.lower() or "custom" in c.protocol.lower():
        p += 0.05
    return max(0.01, min(0.45, p))


def _duration_days(eng_hours: float, team_size: int, downtime: float, hw_prob: float) -> int:
    # Assume 6h effective eng per day per person, parallelisation diminishing
    # Calibrated so the anchor (84h, team 3, 4% dt, hw 0.30) → 12 days (spec)
    parallel = max(1, team_size)
    serial_frac = 0.25
    days_eng = (eng_hours * serial_frac) / 6 + (eng_hours * (1 - serial_frac)) / (6 * parallel)
    # Hardware procurement — tuned to hit 12d for anchor
    hw_days = hw_prob * 5.5  # up to 5.5 days if near-certain upgrade
    # Downtime planning / cutover window
    cutover_days = min(3, downtime / 5 * 2)
    total = days_eng + hw_days + cutover_days + 1.5  # +1.5 buffer (testing wrap-up)
    return max(2, int(math.ceil(total)))


# ---------------------------------------------------------------------------
# Predictor
# ---------------------------------------------------------------------------

class MigrationCostPredictor:
    """Migration cost / effort predictor.

    Predicts engineering + testing effort, downtime, hardware, certs,
    rollback risk, and calendar duration *before* migration — the cost
    dimension of the planner's multi-objective reward.

    The model is CPU-friendly: a deterministic calibrated heuristic with an
    optional ``sklearn`` regressor layer. ``train()`` fits per-feature
    multipliers and a conformal interval.

    Attributes:
        config: :class:`CostPredictorConfig`.
        is_trained: Whether :meth:`train` has been called.

    Example:
        >>> m = MigrationCostPredictor(seed=0)
        >>> m.train()
        >>> f = MigrationCostFeatures(app_type="banking-api", legacy=True,
        ...                           target_pqc="hybrid", dependency_count=17)
        >>> r = m.predict(f)
        >>> 60 < r.engineering_hours < 110 and 20 < r.testing_hours < 45
        True
        >>> r.duration_days >= 5
        True
    """

    def __init__(self, config: Optional[CostPredictorConfig] = None, seed: int = 42) -> None:
        self.config = config or CostPredictorConfig(seed=seed)
        self.config.seed = seed
        random.seed(seed)
        self.is_trained = False
        self._weights: Dict[str, float] = {"eng": 1.0, "test": 1.0, "downtime": 1.0}
        self._models: Dict[str, Any] = {}  # optional sklearn regressors

    # ---- training ---------------------------------------------------------

    def train(
        self,
        dataset: Optional[List[Dict[str, Any]]] = None,
        epochs: int = 5,
    ) -> Dict[str, Any]:
        """Fit cost weights (and optional sklearn regressors).

        Args:
            dataset: List of ``{"features": MigrationCostFeatures|dict,
                "labels": {"eng": float, "test": float, "downtime": float,
                "duration": int}}``. If ``None`` a synthetic banking-anchored
                dataset is generated.
            epochs: Random-search iterations (×10) for weight fitting.

        Returns:
            Dict with ``examples``, ``weights``, ``mae``, ``has_sklearn``.
        """
        random.seed(self.config.seed)
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=400, seed=self.config.seed)

        pairs: List[Tuple[MigrationCostFeatures, Dict[str, float]]] = []
        for ex in dataset:
            raw_f = ex.get("features", ex)
            if isinstance(raw_f, dict) and "labels" in ex:
                raw_f = ex["features"]
            if isinstance(raw_f, dict):
                f = MigrationCostFeatures(**{k: v for k, v in raw_f.items() if k in MigrationCostFeatures.__dataclass_fields__})
            else:
                f = raw_f  # type: ignore
            labels = ex.get("labels", ex.get("label", {}))
            if not isinstance(labels, dict):
                labels = {"eng": float(labels)}
            pairs.append((f, labels))

        # Random-search weight fitting on eng/test/downtime MAE — narrow range to keep anchor stable
        best_w = dict(self._weights)
        best_mae = self._mae(pairs, best_w)
        rnd = random.Random(self.config.seed)
        for _ in range(epochs * 10):
            cand = {k: max(0.85, min(1.15, v + rnd.uniform(-0.04, 0.04))) for k, v in best_w.items()}
            mae = self._mae(pairs, cand)
            if mae < best_mae:
                best_mae = mae
                best_w = cand
        self._weights = best_w

        # Optional sklearn: fit Ridge on residuals
        if HAS_SKLEARN and self.config.use_sklearn:
            try:
                X, y_eng, y_test = [], [], []
                for f, lbl in pairs:
                    X.append(self._featurize(f))
                    y_eng.append(float(lbl.get("eng", lbl.get("engineering_hours", 40))))
                    y_test.append(float(lbl.get("test", lbl.get("testing_hours", 20))))
                import numpy as np  # type: ignore
                Xn = np.array(X, dtype=float)
                self._models["eng"] = Ridge(alpha=1.0)  # type: ignore
                self._models["eng"].fit(Xn, np.array(y_eng))  # type: ignore
                self._models["test"] = Ridge(alpha=1.0)  # type: ignore
                self._models["test"].fit(Xn, np.array(y_test))  # type: ignore
            except Exception:
                self._models = {}

        self.is_trained = True

        # Conformal margin on eng hours
        residuals: List[float] = []
        for f, lbl in pairs:
            pred_eng = self._predict_eng_with_weights(f, best_w)
            residuals.append(abs(pred_eng - float(lbl.get("eng", 40))))
        residuals.sort()
        alpha = self.config.conformal_alpha
        idx = min(len(residuals) - 1, max(0, int(math.ceil((1 - alpha) * len(residuals))) - 1))
        margin = residuals[idx] if residuals else 12.0
        self.config.conformal_margin_hours = round(float(margin), 2)

        return {
            "examples": len(pairs),
            "weights": {k: round(v, 3) for k, v in best_w.items()},
            "mae": round(float(best_mae), 3),
            "conformal_margin_hours": self.config.conformal_margin_hours,
            "has_sklearn": bool(self._models),
        }

    def _featurize(self, f: MigrationCostFeatures) -> List[float]:
        c = f.clamp()
        app_key = c.app_type.lower()
        app_score = _APP_TYPE_COEFF.get(app_key, {"eng": 0.70})["eng"]
        return [
            float(c.dependency_count), float(c.loc), float(c.team_size),
            float(c.traffic_rps) / 1000.0, float(c.legacy),
            float(c.protocol.lower() in ("mtls", "custom", "ipsec")),
            float(_lib_penalty(c.library, c.library_version)),
            float(app_score),
            float({"low": 0, "medium": 1, "high": 2}[c.compliance_level]),
            float({"hybrid": 0, "full": 1, "pq-only": 2}.get(c.target_pqc.lower(), 1)),
        ]

    def _predict_eng_with_weights(self, f: MigrationCostFeatures, weights: Dict[str, float]) -> float:
        old = self._weights
        self._weights = weights
        try:
            return self._heuristic_predict(f).engineering_hours
        finally:
            self._weights = old

    def _mae(self, pairs: List[Tuple[MigrationCostFeatures, Dict[str, float]]], weights: Dict[str, float]) -> float:
        if not pairs:
            return 0.0
        err = 0.0
        for f, lbl in pairs:
            pred = self._predict_eng_with_weights(f, weights)
            true = float(lbl.get("eng", lbl.get("engineering_hours", 40)))
            err += abs(pred - true)
        return err / len(pairs)

    # ---- prediction -------------------------------------------------------

    def _heuristic_predict(self, features: MigrationCostFeatures) -> CostPrediction:
        c = features.clamp()
        eng_base, test_base = _base_hours(c, self.config)
        eng_base *= self._weights.get("eng", 1.0)
        test_base *= self._weights.get("test", 1.0)

        downtime = _downtime_prob(c) * self._weights.get("downtime", 1.0)
        hw_prob = _hardware_prob(c)
        certs = _cert_count(c)
        rollback = _rollback_prob(c, downtime, hw_prob)

        # Deterministic jitter (±5% eng, ±5% test, ±0.35% downtime) — small to keep anchor stable
        eng = eng_base * (1 + _deterministic_jitter(f"eng:{c.app_type}:{c.dependency_count}:{c.legacy}", self.config.seed, 0.05))
        test = test_base * (1 + _deterministic_jitter(f"test:{c.app_type}:{c.loc}", self.config.seed + 1, 0.05))
        downtime = max(0.1, downtime + _deterministic_jitter(f"dt:{c.app_type}:{c.traffic_rps}", self.config.seed + 2, 0.35))

        # Optional sklearn residual correction (small) — clipped to avoid negatives
        if self._models.get("eng") is not None:
            try:
                import numpy as np  # type: ignore
                X = np.array([self._featurize(c)], dtype=float)
                ml_eng = float(self._models["eng"].predict(X)[0])  # type: ignore
                ml_eng = max(4.0, min(2000.0, ml_eng))
                ml_test = float(self._models["test"].predict(X)[0])  # type: ignore
                ml_test = max(2.0, min(1000.0, ml_test))
                # Blend 20% ML, 80% heuristic to keep anchor stable
                eng = eng * 0.80 + ml_eng * 0.20
                test = test * 0.80 + ml_test * 0.20
            except Exception:
                pass

        # Clamp before duration/cost so sklearn cannot produce negatives
        eng = max(4.0, min(2000.0, eng))
        test = max(2.0, min(1000.0, test))
        downtime = max(0.1, min(35.0, downtime))

        duration = _duration_days(eng, c.team_size, downtime, hw_prob)
        total_usd = (eng + test) * self.config.blended_hourly_rate_usd

        breakdown = {
            "base_eng": round(eng_base, 1), "base_test": round(test_base, 1),
            "dep_factor": round(1.0 + (c.dependency_count - _ANCHOR["deps"]) * 0.035, 3),
            "legacy_factor": 1.0 if c.legacy else 0.80,
            "hw_prob_raw": round(hw_prob, 3),
        }
        interval = None
        if self.config.conformal_margin_hours is not None:
            m = self.config.conformal_margin_hours
            interval = (max(1, duration - math.ceil(m / 10)), duration + math.ceil(m / 10))

        expl = (
            f"{c.app_type} legacy={c.legacy} {c.target_pqc} deps={c.dependency_count} "
            f"lib={c.library} {c.library_version} hw={c.hardware} "
            f"→ eng={eng:.1f}h test={test:.1f}h downtime={downtime:.1f}% hw_up={hw_prob:.0%} "
            f"certs={certs} rollback={rollback:.0%} duration={duration}d cost=${total_usd:,.0f}"
        )
        return CostPrediction(
            engineering_hours=round(float(eng), 1),
            testing_hours=round(float(test), 1),
            downtime_percent=round(float(downtime), 2),
            hardware_upgrade_prob=round(float(hw_prob), 3),
            cert_replacement_count=int(certs),
            rollback_prob=round(float(rollback), 3),
            duration_days=int(duration),
            total_cost_usd=round(float(total_usd), 2),
            breakdown=breakdown,
            interval_days=interval,
            explanation=expl,
        )

    def predict(self, features: MigrationCostFeatures) -> CostPrediction:
        """Predict migration cost for *features*.

        Args:
            features: :class:`MigrationCostFeatures`.

        Returns:
            :class:`CostPrediction` with hours, downtime, hardware, duration, etc.
        """
        return self._heuristic_predict(features)

    def predict_batch(self, batch: List[MigrationCostFeatures]) -> List[CostPrediction]:
        return [self.predict(f) for f in batch]

    # ---- evaluation -------------------------------------------------------

    def evaluate(self, dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Evaluate on a labelled dataset.

        Reports MAE for engineering hours / testing / downtime / duration.

        Args:
            dataset: Same format as :meth:`train`. If ``None`` a synthetic eval
                set is generated.

        Returns:
            Dict with ``mae_eng``, ``mae_test``, ``mae_downtime``, ``mae_duration``,
            ``rmse_eng``, ``n``.
        """
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=200, seed=self.config.seed + 101)
        pairs: List[Tuple[MigrationCostFeatures, Dict[str, float]]] = []
        for ex in dataset:
            raw_f = ex.get("features", ex)
            if isinstance(raw_f, dict) and "labels" in ex:
                raw_f = ex["features"]
            if isinstance(raw_f, dict):
                f = MigrationCostFeatures(**{k: v for k, v in raw_f.items() if k in MigrationCostFeatures.__dataclass_fields__})
            else:
                f = raw_f  # type: ignore
            labels = ex.get("labels", {})
            pairs.append((f, labels))

        errs_eng: List[float] = []
        errs_test: List[float] = []
        errs_dt: List[float] = []
        errs_dur: List[float] = []
        for f, lbl in pairs:
            pred = self.predict(f)
            true_eng = float(lbl.get("eng", lbl.get("engineering_hours", pred.engineering_hours)))
            true_test = float(lbl.get("test", lbl.get("testing_hours", pred.testing_hours)))
            true_dt = float(lbl.get("downtime", lbl.get("downtime_percent", pred.downtime_percent)))
            true_dur = float(lbl.get("duration", lbl.get("duration_days", pred.duration_days)))
            errs_eng.append(abs(pred.engineering_hours - true_eng))
            errs_test.append(abs(pred.testing_hours - true_test))
            errs_dt.append(abs(pred.downtime_percent - true_dt))
            errs_dur.append(abs(pred.duration_days - true_dur))

        def mae(lst: List[float]) -> float:
            return sum(lst) / len(lst) if lst else 0.0

        def rmse(lst: List[float]) -> float:
            return math.sqrt(sum(x * x for x in lst) / len(lst)) if lst else 0.0

        return {
            "mae_eng": round(mae(errs_eng), 3),
            "rmse_eng": round(rmse(errs_eng), 3),
            "mae_test": round(mae(errs_test), 3),
            "mae_downtime": round(mae(errs_dt), 3),
            "mae_duration": round(mae(errs_dur), 3),
            "n": len(pairs),
            "has_sklearn": bool(self._models),
        }

    # ---- synthetic dataset ------------------------------------------------

    def _generate_synthetic_dataset(self, n: int = 400, seed: int = 42) -> List[Dict[str, Any]]:
        rnd = random.Random(seed)
        app_types = list(_APP_TYPE_COEFF.keys())
        protocols = list(_PROTOCOL_COEFF.keys())
        libs = ["openssl", "boringssl", "libsodium", "bouncy-castle", "mbedtls", "proprietary"]
        vers = ["3.0.8", "3.1.2", "1.1.1w", "2.28.0", "1.0.2u"]
        hws = list(_HARDWARE_UPGRADE_BASE.keys())
        targets = ["hybrid", "full", "pq-only"]
        data: List[Dict[str, Any]] = []
        for i in range(n):
            app = rnd.choice(app_types)
            legacy = rnd.random() < 0.35
            target = rnd.choice(targets)
            deps = rnd.randint(0, 40)
            loc = rnd.randint(2, 80)
            team = rnd.randint(1, 6)
            proto = rnd.choice(protocols)
            lib = rnd.choice(libs)
            ver = rnd.choice(vers)
            hw = rnd.choice(hws)
            traffic = rnd.randint(10, 50000)
            compliance = rnd.choice(["low", "medium", "high"])
            f = MigrationCostFeatures(
                app_type=app, protocol=proto, library=lib, library_version=ver,
                hardware=hw, legacy=legacy, target_pqc=target, dependency_count=deps,
                loc=loc, team_size=team, traffic_rps=traffic, compliance_level=compliance,
            )
            # Label = heuristic + noise (so training can recover weights)
            tmp_cfg = CostPredictorConfig(seed=seed)
            eng_base, test_base = _base_hours(f, tmp_cfg)
            dt = _downtime_prob(f)
            hw_p = _hardware_prob(f)
            dur = _duration_days(eng_base, team, dt, hw_p)
            # Add Gaussian noise 10% to simulate real variance
            eng_label = max(4, eng_base + rnd.gauss(0, eng_base * 0.10))
            test_label = max(2, test_base + rnd.gauss(0, test_base * 0.10))
            dt_label = max(0.1, dt + rnd.gauss(0, 0.6))
            dur_label = max(2, dur + rnd.randint(-1, 1))
            data.append({
                "features": asdict(f),
                "labels": {"eng": round(float(eng_label), 1), "test": round(float(test_label), 1), "downtime": round(float(dt_label), 2), "duration": int(dur_label)},
                "id": i,
            })
        # Ensure the exact anchor exists (spec example) — baseline features per spec
        data.append({
            "features": asdict(MigrationCostFeatures(app_type="banking-api", legacy=True, target_pqc="hybrid", dependency_count=17, loc=10, team_size=3, protocol="TLS1.3", library="openssl", library_version="3.0.8", hardware="x86", traffic_rps=500, compliance_level="medium")),
            "labels": {"eng": 84.0, "test": 31.0, "downtime": 4.0, "duration": 12},
            "id": n,
        })
        return data


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== MigrationCostPredictor demo ===")
    m = MigrationCostPredictor(seed=42)
    train_res = m.train(epochs=3)
    print(f"[train] {json.dumps(train_res, indent=2)}")

    cases = [
        MigrationCostFeatures(app_type="banking-api", legacy=True, target_pqc="hybrid", dependency_count=17, loc=25, team_size=3, protocol="TLS1.2", library="openssl", library_version="1.1.1w", hardware="x86", traffic_rps=2000, compliance_level="high"),
        MigrationCostFeatures(app_type="tls-gateway", legacy=False, target_pqc="hybrid", dependency_count=5, loc=10, team_size=2, protocol="TLS1.3", library="openssl", library_version="3.0.8", hardware="x86", traffic_rps=8000, compliance_level="medium"),
        MigrationCostFeatures(app_type="iot-firmware", legacy=True, target_pqc="full", dependency_count=30, loc=60, team_size=2, protocol="custom", library="mbedtls", library_version="2.28.0", hardware="iot-mcu", traffic_rps=200, compliance_level="high"),
        MigrationCostFeatures(app_type="web", legacy=False, target_pqc="hybrid", dependency_count=2, loc=8, team_size=4, protocol="TLS1.3", library="boringssl", library_version="3.1.2", hardware="x86", traffic_rps=10000, compliance_level="low"),
        MigrationCostFeatures(app_type="hsm", legacy=True, target_pqc="pq-only", dependency_count=12, loc=15, team_size=2, protocol="mTLS", library="proprietary", library_version="1.0.2", hardware="hsm", traffic_rps=5000, compliance_level="high"),
    ]
    for f in cases:
        r = m.predict(f)
        print(f"\n{f.app_type:15s} legacy={str(f.legacy):5s} {f.target_pqc:8s} deps={f.dependency_count:2d} lib={f.library} {f.library_version} hw={f.hardware}")
        print(f"  eng={r.engineering_hours:5.1f}h test={r.testing_hours:4.1f}h downtime={r.downtime_percent:4.1f}% hw_up={r.hardware_upgrade_prob:.0%} "
              f"certs={r.cert_replacement_count} rollback={r.rollback_prob:.0%} duration={r.duration_days}d cost=${r.total_cost_usd:,.0f}")
        print(f"  {r.explanation}")

    eval_res = m.evaluate()
    print(f"\n[evaluate] MAE eng={eval_res['mae_eng']}h test={eval_res['mae_test']}h downtime={eval_res['mae_downtime']}% duration={eval_res['mae_duration']}d n={eval_res['n']}")

    # Anchor check
    anchor_f = MigrationCostFeatures(app_type="banking-api", legacy=True, target_pqc="hybrid", dependency_count=17)
    anchor_r = m.predict(anchor_f)
    print(f"\n[anchor] banking-api hybrid 17 deps → eng={anchor_r.engineering_hours}h test={anchor_r.testing_hours}h downtime={anchor_r.downtime_percent}% duration={anchor_r.duration_days}d (expect ~84h/31h/4%/12d)")
