"""
Quantum Exposure Score — vuln × sensitivity × lifetime × exposure × attractiveness × lead_time + HNDL

Architecture reference: ``qtrust_ai/README.md`` Phase 1 Foundation (Risk).

This module implements the **Quantum Exposure Score** and **HNDL (Harvest-Now-
Decrypt-Later) risk** model described in the spec and whitepaper:

    Quantum Exposure = vuln × sensitivity × lifetime × exposure × attractiveness × lead_time

Each factor is 0-5 (or normalized 0-1) so the raw product is 0-15625, then
mapped to 0-100 via a calibrated squash (log / sigmoid with temperature).

Alignment:
* **risk_engine.py**: reuses ``ALGORITHM_VULNERABILITY_DB`` semantics
  (BROKEN / WEAKENED / SAFE / PQC_READY) and NIST 800-131A / CNSA 2.0 logic.
  See ``inspector/qtrust_inspector/risk_engine.py:calculate_risk_score``.
* **NIST migration guidance**: deadlines 2030 (RSA-2048 disallow) / 2035
  (all classical disallow) feed ``lead_time`` and HNDL horizon.
  See docs/WHITEPAPER.md § 1.2-1.3 and ``risk_engine.py:NIST_800_131A_DEPRECATION``.
* **qtrust_common/heuristics.py**: ``pqc_risk`` is a simpler 0-1 heuristic;
  this model is the learned counterpart with 6 factors + calibration.

Features:
* CPU-friendly, deterministic, no GPU required.
* Calibration via temperature scaling + conformal prediction intervals.
* ``train`` / ``predict`` / ``evaluate`` (AUROC/AUPRC/Brier/ECE per README § Killer metrics).

Example:
    from qtrust_ai.risk.quantum_exposure import QuantumExposureModel, ExposureFactors

    model = QuantumExposureModel()
    factors = ExposureFactors(
        algorithm="RSA-2048", key_size=2048, sensitivity=5,
        lifetime_years=10, exposure_years=4.0, attractiveness=5, lead_time_years=3,
    )
    result = model.predict(factors)
    print(result.score, result.hndl_risk, result.level)
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field, asdict
from datetime import date
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# Optional deps
try:
    from sklearn.metrics import roc_auc_score, average_precision_score  # type: ignore
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Import canonical risk engine for alignment (fallback if not on path)
try:
    from inspector.qtrust_inspector.risk_engine import (  # type: ignore
        QuantumVulnerability as _QV,
        ALGORITHM_VULNERABILITY_DB as _VULN_DB,
        NIST_800_131A_DEPRECATION as _NIST_DEP,
    )
    HAS_RISK_ENGINE = True
except Exception:
    HAS_RISK_ENGINE = False
    _QV = None  # type: ignore
    _VULN_DB = {}  # type: ignore
    _NIST_DEP = {}  # type: ignore


# ---------------------------------------------------------------------------
# Vulnerability — mirrors risk_engine.QuantumVulnerability
# ---------------------------------------------------------------------------

class Vulnerability(str, Enum):
    """Quantum vulnerability tier — mirrors ``risk_engine.QuantumVulnerability``."""

    BROKEN = "broken"       # Shor breaks (RSA, ECDSA, ECDH, DH, EdDSA)
    WEAKENED = "weakened"   # Grover halves margin (AES-128, 3DES, SHA-1)
    SAFE = "safe"           # Quantum-safe symmetric/hash (AES-256, SHA-384)
    PQC_READY = "pqc_ready" # NIST PQC (ML-KEM, ML-DSA, SLH-DSA, HQC)


# Vulnerability weight for the product (1-5 scale; PQC_READY=0 kills product)
_VULN_WEIGHT: Dict[Vulnerability, int] = {
    Vulnerability.BROKEN: 5,
    Vulnerability.WEAKENED: 3,
    Vulnerability.SAFE: 1,
    Vulnerability.PQC_READY: 0,
}

# Algorithm -> Vulnerability (subset; full DB in risk_engine.py)
_ALGO_VULN: Dict[str, Vulnerability] = {
    "RSA": Vulnerability.BROKEN, "RSA-1024": Vulnerability.BROKEN, "RSA-2048": Vulnerability.BROKEN,
    "RSA-4096": Vulnerability.BROKEN, "ECDSA": Vulnerability.BROKEN, "ECDSA-P256": Vulnerability.BROKEN,
    "ECDSA-P384": Vulnerability.BROKEN, "ECDH": Vulnerability.BROKEN, "ECDH-P256": Vulnerability.BROKEN,
    "DSA": Vulnerability.BROKEN, "ED25519": Vulnerability.BROKEN, "ED448": Vulnerability.BROKEN,
    "DH": Vulnerability.BROKEN, "DH-2048": Vulnerability.BROKEN, "X25519": Vulnerability.BROKEN,
    "X448": Vulnerability.BROKEN,
    "AES-128": Vulnerability.WEAKENED, "3DES": Vulnerability.WEAKENED, "DES": Vulnerability.WEAKENED,
    "AES-256": Vulnerability.SAFE, "AES-192": Vulnerability.SAFE, "CHACHA20-POLY1305": Vulnerability.SAFE,
    "SHA-256": Vulnerability.SAFE, "SHA-384": Vulnerability.SAFE, "SHA-512": Vulnerability.SAFE,
    "SHA3-256": Vulnerability.SAFE, "HMAC-SHA256": Vulnerability.SAFE,
    "ML-KEM-512": Vulnerability.PQC_READY, "ML-KEM-768": Vulnerability.PQC_READY, "ML-KEM-1024": Vulnerability.PQC_READY,
    "ML-DSA-44": Vulnerability.PQC_READY, "ML-DSA-65": Vulnerability.PQC_READY, "ML-DSA-87": Vulnerability.PQC_READY,
    "SLH-DSA-SHA2-128S": Vulnerability.PQC_READY, "SLH-DSA-SHA3-128S": Vulnerability.PQC_READY,
    "HQC-128": Vulnerability.PQC_READY, "HQC-192": Vulnerability.PQC_READY,
}

_NIST_DEADLINES: Dict[str, int] = {
    "RSA-1024": 2030, "RSA-2048": 2030, "ECDSA-P256": 2030, "ECDSA-P384": 2030,
    "SHA-1": 2030, "3DES": 2030, "RSA": 2035, "ECDSA": 2035, "DSA": 2035,
}

_CNSA2_ALLOWED = frozenset({"ML-KEM-1024", "ML-DSA-87", "SLH-DSA-SHA2-256S", "AES-256", "SHA-384", "SHA-512"})


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ExposureFactors:
    """Input factors for quantum exposure scoring.

    All factors are clamped to their valid ranges internally.

    Attributes:
        algorithm: Algorithm name (e.g. ``"RSA-2048"``, ``"ML-KEM-768"``).
        key_size: Key size in bits (optional; affects vuln for symmetric).
        sensitivity: Data sensitivity 0-5 (0=public, 5=restricted / crown jewels).
        lifetime_years: Required confidentiality horizon 0-5 mapped (0=ephemeral,
            5=20+ years). Raw years are bucketed.
        exposure_years: How long the asset has been exposed to harvesting (0-10).
        attractiveness: Adversary attractiveness 0-5 (0=low value, 5=nation-state target).
        lead_time_years: Migration lead time 0-5 (0=already PQC, 5=3+ years to migrate).
        purpose: Optional purpose hint (``key-establishment`` / ``signature`` …)
            for HNDL relevance.
        data_classification: Human label (``public`` / ``internal`` / ``confidential`` / ``restricted``).
        first_seen: ISO date string for exposure calculation (overrides ``exposure_years`` if present).
    """

    algorithm: str = "RSA-2048"
    key_size: Optional[int] = None
    sensitivity: int = 3
    lifetime_years: int = 2
    exposure_years: float = 0.0
    attractiveness: int = 3
    lead_time_years: int = 2
    purpose: Optional[str] = None
    data_classification: str = "confidential"
    first_seen: Optional[str] = None

    def clamp(self) -> "ExposureFactors":
        """Return a clamped copy."""
        import copy
        c = copy.copy(self)
        c.sensitivity = max(0, min(5, int(c.sensitivity)))
        # lifetime bucket: map raw years 0-30 -> 0-5
        if c.lifetime_years > 5:
            # treat as raw years
            raw = int(c.lifetime_years)
            if raw <= 1:
                c.lifetime_years = 1
            elif raw <= 3:
                c.lifetime_years = 2
            elif raw <= 7:
                c.lifetime_years = 3
            elif raw <= 15:
                c.lifetime_years = 4
            else:
                c.lifetime_years = 5
        else:
            c.lifetime_years = max(0, min(5, int(c.lifetime_years)))
        c.exposure_years = max(0.0, min(10.0, float(c.exposure_years)))
        c.attractiveness = max(0, min(5, int(c.attractiveness)))
        c.lead_time_years = max(0, min(5, int(c.lead_time_years)))
        # first_seen -> exposure_years
        if c.first_seen:
            try:
                fs = date.fromisoformat(c.first_seen)
                c.exposure_years = max(c.exposure_years, (date.today() - fs).days / 365.25)
                c.exposure_years = min(10.0, c.exposure_years)
            except Exception:
                pass
        return c


@dataclass
class QuantumExposureScore:
    """Output of :meth:`QuantumExposureModel.predict`.

    Attributes:
        score: Quantum Exposure Score 0-100 (product squash).
        hndl_risk: HNDL risk 0-100 (harvest-now-decrypt-later specific).
        level: ``NONE`` | ``LOW`` | ``MEDIUM`` | ``HIGH`` | ``CRITICAL``.
        vulnerability: :class:`Vulnerability` tier.
        factors: Normalized factor dict (v, s, l, e, a, lt) used in the product.
        raw_product: Raw 0-15625 product before squash.
        explanation: Human-readable breakdown for copilot / dashboard.
        calibrated: Whether temperature scaling was applied.
        interval: Optional conformal interval ``(low, high)`` 0-100.
    """

    score: float
    hndl_risk: float
    level: str
    vulnerability: Vulnerability
    factors: Dict[str, float] = field(default_factory=dict)
    raw_product: float = 0.0
    explanation: str = ""
    calibrated: bool = False
    interval: Optional[Tuple[float, float]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["vulnerability"] = self.vulnerability.value if isinstance(self.vulnerability, Enum) else self.vulnerability
        return d


@dataclass
class QuantumExposureConfig:
    """Hyper-parameters for :class:`QuantumExposureModel`."""

    seed: int = 42
    temperature: float = 1.0  # 1.0 = no scaling; <1 sharpens, >1 softens
    use_log_squash: bool = True  # log(1+product) / log(1+15625) vs linear
    hndl_weight: float = 1.0  # weight of HNDL component inside overall score
    conformal_alpha: float = 0.1  # 90% interval when conformal is fit
    conformal_margin: Optional[float] = None  # fitted margin (None = not fit)


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _normalize_algo(algorithm: str) -> str:
    return algorithm.upper().replace(" ", "").replace("_", "-")


def _lookup_vulnerability(algorithm: str, key_size: Optional[int] = None) -> Vulnerability:
    """Mirror ``risk_engine._lookup_vulnerability`` semantics."""
    algo_upper = _normalize_algo(algorithm)
    # Direct hit
    if algo_upper in _ALGO_VULN:
        vuln = _ALGO_VULN[algo_upper]
    else:
        # Substring fallback (fail closed → BROKEN)
        vuln = Vulnerability.BROKEN
        for key, val in _ALGO_VULN.items():
            if key in algo_upper or algo_upper in key:
                vuln = val
                break
    # Symmetric key-size refinement (Grover: <256 weakened)
    if key_size is not None and any(m in algo_upper for m in ("AES", "CHACHA20")):
        if key_size < 256:
            return Vulnerability.WEAKENED
        return Vulnerability.SAFE
    # Asymmetric: Shor breaks at any size (never soften)
    if any(m in algo_upper for m in ("RSA", "ECDSA", "ECDH", "ED25519", "ED448", "X25519", "X448", "DSA", "DH")):
        return vuln
    return vuln


def _hndl_risk(
    vulnerability: Vulnerability,
    sensitivity: int,
    lifetime_years: int,
    exposure_years: float,
    purpose: Optional[str] = None,
) -> float:
    """HNDL risk 0-100.

    Mirrors ``risk_engine._calculate_hndl_score`` but extended with purpose
    sensitivity (KEM / encryption is HNDL-relevant; signature-only is less).

    HNDL matters when: broken vuln + long lifetime + high sensitivity + prior
    exposure + confidentiality purpose.
    """
    weights = {
        Vulnerability.BROKEN: 5,
        Vulnerability.WEAKENED: 3,
        Vulnerability.SAFE: 0,
        Vulnerability.PQC_READY: 0,
    }
    v = weights.get(vulnerability, 0)
    s = max(0, min(5, sensitivity))
    # lifetime already 0-5 bucket
    ell = max(0, min(5, lifetime_years))
    e = max(0.0, exposure_years)
    # Purpose modifier: signature-only data is less HNDL-sensitive
    purpose_mult = 1.0
    if purpose:
        pl = purpose.lower()
        if pl in ("signature", "signing"):
            purpose_mult = 0.3  # signatures are not confidentiality
        elif pl in ("key-establishment", "kem", "key_exchange", "encryption"):
            purpose_mult = 1.0
        elif pl in ("hashing", "randomness"):
            purpose_mult = 0.1
    # Base formula: V * S * L * (1 + E/10) scaled to 0-100
    raw = v * s * ell * (1 + e / 10) * purpose_mult
    # Scale: max raw = 5*5*5*2 = 250 -> 100
    return min(100.0, raw * (100 / 125))


def _squash_product(product: float, temperature: float = 1.0, use_log: bool = True) -> float:
    """Map raw 0-15625 product to 0-100."""
    if product <= 0:
        return 0.0
    if use_log:
        # log squash: log(1+product)/log(1+15625) * 100, then temperature
        base = math.log1p(product) / math.log1p(15625) * 100.0
    else:
        base = min(product / 15625, 1.0) * 100.0
    if temperature != 1.0 and temperature > 0:
        # Temperature scaling in logit space for smoother calibration
        # Map 0-100 -> 0-1 -> logit -> /T -> sigmoid -> 0-100
        p = max(1e-6, min(1 - 1e-6, base / 100.0))
        logit = math.log(p / (1 - p))
        p_scaled = 1 / (1 + math.exp(-logit / temperature))
        return max(0.0, min(100.0, p_scaled * 100.0))
    return max(0.0, min(100.0, base))


def _level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class QuantumExposureModel:
    """Quantum Exposure Score model.

    Computes ``vuln × sensitivity × lifetime × exposure × attractiveness × lead_time``
    per spec, plus an HNDL sub-score, with calibration (temperature scaling +
    conformal intervals).

    The 6-factor product is the primary score; HNDL is reported alongside and
    blended into the explanation so that CISOs see both the *overall migration
    urgency* and the *harvest-now* specific risk.

    Aligns with ``risk_engine.py`` vulnerability DB and NIST deadlines so that
    scores are consistent whether produced here or via the inspector.

    Args:
        config: Model hyper-parameters.

    Example:
        >>> m = QuantumExposureModel()
        >>> f = ExposureFactors(algorithm="RSA-2048", sensitivity=5, lifetime_years=5,
        ...                     exposure_years=4, attractiveness=5, lead_time_years=4)
        >>> r = m.predict(f)
        >>> r.level in ("HIGH", "CRITICAL")
        True
        >>> r.hndl_risk > 50
        True
    """

    def __init__(self, config: Optional[QuantumExposureConfig] = None) -> None:
        self.config = config or QuantumExposureConfig()
        random.seed(self.config.seed)
        self.is_trained = False
        self._factor_weights: Dict[str, float] = {
            "vuln": 1.0, "sensitivity": 1.0, "lifetime": 1.0,
            "exposure": 1.0, "attractiveness": 1.0, "lead_time": 1.0,
        }

    # -- prediction ---------------------------------------------------------

    def predict(self, factors: ExposureFactors) -> QuantumExposureScore:
        """Score a single asset's quantum exposure.

        Args:
            factors: :class:`ExposureFactors` (clamped internally).

        Returns:
            :class:`QuantumExposureScore` with 0-100 ``score``, ``hndl_risk``,
            ``level``, and calibration interval if fitted.
        """
        f = factors.clamp()
        vuln = _lookup_vulnerability(f.algorithm, f.key_size)

        # Factor values 0-5 (vuln 0-5, others 0-5)
        v = _VULN_WEIGHT[vuln]
        s = f.sensitivity
        # lifetime already bucketed 0-5
        ell = f.lifetime_years
        # exposure: map years 0-10 -> 0-5 (1 point per 2 years)
        e_score = min(5, max(0, int(math.ceil(f.exposure_years / 2)))) if f.exposure_years > 0 else 0
        # keep continuous for HNDL but bucket for product
        if f.exposure_years == 0:
            e_score = 0
        elif f.exposure_years < 0.5:
            e_score = 1
        a = f.attractiveness
        lt = f.lead_time_years

        # Apply learned factor weights (train() may adjust)
        w = self._factor_weights
        # Weighted product: (v*wv) * (s*ws) * ... — weights act as exponents-ish
        # We implement as (value * weight) so weight 1.2 boosts that factor
        pv = max(0, v * w["vuln"])
        ps = max(0, s * w["sensitivity"])
        pl = max(0, ell * w["lifetime"])
        pe = max(0, max(1, e_score) * w["exposure"]) if v > 0 else 0  # if PQC_READY, product 0
        pa = max(0, a * w["attractiveness"])
        plt = max(0, lt * w["lead_time"])

        # If any confidentiality factor is 0 and vuln is BROKEN, still expose risk
        # So we floor non-zero factors at 0.5 to avoid zeroing the product when data is short-lived but sensitive
        raw_product = pv * max(0.5, ps) * max(0.5, pl) * max(0.5, pe) * max(0.5, pa) * max(0.5, plt)
        if v == 0:
            raw_product = 0.0

        score = _squash_product(raw_product, temperature=self.config.temperature, use_log=self.config.use_log_squash)

        # HNDL sub-score (uses continuous exposure_years)
        hndl = _hndl_risk(vuln, s, ell, f.exposure_years, purpose=f.purpose)

        # Blend HNDL into explanation; do not double-count in score unless configured
        if self.config.hndl_weight != 0 and vuln == Vulnerability.BROKEN:
            # Optional: lightly blend HNDL so KEM assets score higher than signature-only
            score = max(score, hndl * 0.6 + score * 0.4)
            score = min(100.0, score)

        level = _level(score)

        factors_dict = {
            "vuln": pv, "sensitivity": ps, "lifetime": pl,
            "exposure": pe, "attractiveness": pa, "lead_time": plt,
        }

        # Conformal interval
        interval: Optional[Tuple[float, float]] = None
        if self.config.conformal_margin is not None:
            m = self.config.conformal_margin
            interval = (max(0.0, score - m), min(100.0, score + m))

        # NIST deadline awareness for explanation
        deadline = _NIST_DEADLINES.get(_normalize_algo(f.algorithm), _NIST_DEADLINES.get(f.algorithm.split("-")[0].upper(), None))
        deadline_str = f" NIST deadline {deadline}" if deadline else ""
        purpose_str = f" purpose={f.purpose}" if f.purpose else ""
        expl = (
            f"vuln={vuln.value}({pv:.1f}) × sens={s} × life={ell} × exp={e_score}({f.exposure_years:.1f}y)"
            f" × attract={a} × lead={lt} = raw {raw_product:.1f} → {score:.1f}/100"
            f" HNDL={hndl:.1f}{deadline_str}{purpose_str} [{level}]"
        )

        return QuantumExposureScore(
            score=round(float(score), 2),
            hndl_risk=round(float(hndl), 2),
            level=level,
            vulnerability=vuln,
            factors={k: round(float(v), 2) for k, v in factors_dict.items()},
            raw_product=round(float(raw_product), 2),
            explanation=expl,
            calibrated=self.config.temperature != 1.0,
            interval=(round(interval[0], 2), round(interval[1], 2)) if interval else None,
        )

    def predict_batch(self, batch: List[ExposureFactors]) -> List[QuantumExposureScore]:
        """Batch predict."""
        return [self.predict(f) for f in batch]

    # -- training (CPU stub + weight learning) ------------------------------

    def train(
        self,
        dataset: Optional[List[Dict[str, Any]]] = None,
        epochs: int = 3,
        lr: float = 0.05,
    ) -> Dict[str, Any]:
        """Fit factor weights and calibration (CPU-friendly).

        In production this would train a small MLP / gradient-boosted model on
        expert-labelled 0-100 exposure scores (40/30/20/10 mix per README).
        The stub does deterministic heuristic weight fitting plus temperature
        search.

        Args:
            dataset: List of ``{"factors": ExposureFactors|dict, "label": float 0-100}``
                or ``{"algorithm": str, ..., "label": float}``. If ``None``
                a synthetic dataset is generated.
            epochs: Iterations of weight search.
            lr: Step size for weight updates.

        Returns:
            Dict with ``examples``, ``factor_weights``, ``temperature``,
            ``mae``, ``note``.
        """
        random.seed(self.config.seed)
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=400, seed=self.config.seed)

        # Normalize dataset entries to (ExposureFactors, label)
        pairs: List[Tuple[ExposureFactors, float]] = []
        for ex in dataset:
            if "factors" in ex:
                raw_f = ex["factors"]
                if isinstance(raw_f, dict):
                    f = ExposureFactors(**{k: v for k, v in raw_f.items() if k in ExposureFactors.__dataclass_fields__})
                else:
                    f = raw_f  # type: ignore
                label = float(ex.get("label", ex.get("score", 50)))
            else:
                # flat dict
                f = ExposureFactors(
                    algorithm=str(ex.get("algorithm", "RSA-2048")),
                    key_size=ex.get("key_size"),
                    sensitivity=int(ex.get("sensitivity", 3)),
                    lifetime_years=int(ex.get("lifetime_years", ex.get("lifetime", 2))),
                    exposure_years=float(ex.get("exposure_years", ex.get("exposure", 0))),
                    attractiveness=int(ex.get("attractiveness", 3)),
                    lead_time_years=int(ex.get("lead_time_years", ex.get("lead_time", 2))),
                    purpose=ex.get("purpose"),
                )
                label = float(ex.get("label", ex.get("score", 50)))
            pairs.append((f, max(0, min(100, label))))

        # Simple heuristic weight fitting: correlate each factor with residual
        # Start from uniform and do a few random-search steps (deterministic)
        best_weights = dict(self._factor_weights)
        best_mae = self._mae(pairs, best_weights, self.config.temperature)

        rnd = random.Random(self.config.seed)
        for _ in range(epochs * 10):
            cand = {k: max(0.5, min(1.5, v + rnd.uniform(-lr, lr))) for k, v in best_weights.items()}
            mae = self._mae(pairs, cand, self.config.temperature)
            if mae < best_mae:
                best_mae = mae
                best_weights = cand

        self._factor_weights = best_weights

        # Temperature search
        best_temp = self.config.temperature
        for t in [0.7, 0.85, 1.0, 1.15, 1.3, 1.5]:
            mae_t = self._mae(pairs, best_weights, t)
            if mae_t < best_mae:
                best_mae = mae_t
                best_temp = t
        self.config.temperature = best_temp
        self.is_trained = True

        # Fit conformal margin on residuals
        residuals: List[float] = []
        for f, label in pairs:
            pred = self._predict_with_weights(f, best_weights, best_temp)
            residuals.append(abs(pred - label))
        residuals.sort()
        alpha = self.config.conformal_alpha
        idx = min(len(residuals) - 1, max(0, int(math.ceil((1 - alpha) * len(residuals))) - 1))
        margin = residuals[idx] if residuals else 10.0
        self.config.conformal_margin = round(float(margin), 2)

        return {
            "examples": len(pairs),
            "factor_weights": {k: round(float(v), 3) for k, v in best_weights.items()},
            "temperature": best_temp,
            "mae": round(float(best_mae), 3),
            "conformal_margin": self.config.conformal_margin,
            "conformal_alpha": alpha,
            "has_sklearn": HAS_SKLEARN,
            "note": "stub does random-search weight fitting + temp scaling + conformal; real training would use MLP/GBM",
        }

    def _predict_with_weights(
        self, factors: ExposureFactors, weights: Dict[str, float], temperature: float
    ) -> float:
        """Internal predict with explicit weights/temperature (for training)."""
        old_w, old_t = self._factor_weights, self.config.temperature
        self._factor_weights, self.config.temperature = weights, temperature
        try:
            return self.predict(factors).score
        finally:
            self._factor_weights, self.config.temperature = old_w, old_t

    def _mae(
        self, pairs: List[Tuple[ExposureFactors, float]], weights: Dict[str, float], temperature: float
    ) -> float:
        if not pairs:
            return 0.0
        err = 0.0
        for f, label in pairs:
            pred = self._predict_with_weights(f, weights, temperature)
            err += abs(pred - label)
        return err / len(pairs)

    # -- evaluation ---------------------------------------------------------

    def evaluate(
        self, dataset: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Evaluate on a labelled dataset.

        Reports per README § Killer metrics — Risk: AUROC / AUPRC / Brier / ECE.

        Args:
            dataset: Same format as :meth:`train`. If ``None`` a synthetic eval
                set is generated.

        Returns:
            Dict with ``mae``, ``rmse``, ``brier``, ``ece``, ``auroc``,
            ``auprc``, ``n``, ``by_level``.
        """
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=200, seed=self.config.seed + 101)

        pairs: List[Tuple[ExposureFactors, float]] = []
        for ex in dataset:
            if "factors" in ex:
                raw_f = ex["factors"]
                if isinstance(raw_f, dict):
                    f = ExposureFactors(**{k: v for k, v in raw_f.items() if k in ExposureFactors.__dataclass_fields__})
                else:
                    f = raw_f  # type: ignore
                label = float(ex.get("label", 50))
            else:
                f = ExposureFactors(
                    algorithm=str(ex.get("algorithm", "RSA-2048")),
                    key_size=ex.get("key_size"),
                    sensitivity=int(ex.get("sensitivity", 3)),
                    lifetime_years=int(ex.get("lifetime_years", 2)),
                    exposure_years=float(ex.get("exposure_years", 0)),
                    attractiveness=int(ex.get("attractiveness", 3)),
                    lead_time_years=int(ex.get("lead_time_years", 2)),
                    purpose=ex.get("purpose"),
                )
                label = float(ex.get("label", 50))
            pairs.append((f, max(0, min(100, label))))

        preds: List[float] = []
        labels: List[float] = []
        abs_errs: List[float] = []
        by_level: Dict[str, List[float]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "NONE": []}
        for f, label in pairs:
            p = self.predict(f).score
            preds.append(p)
            labels.append(label)
            abs_errs.append(abs(p - label))
            # bucket by true level
            true_level = _level(label)
            by_level[true_level].append(abs(p - label))

        n = len(pairs)
        mae = sum(abs_errs) / n if n else 0.0
        rmse = math.sqrt(sum(e * e for e in abs_errs) / n) if n else 0.0

        # Brier: treat normalized label/100 as prob, pred/100 as prob of "high exposure"
        brier: Optional[float] = None
        if HAS_SKLEARN:
            try:
                y_prob = [p / 100.0 for p in preds]
                y_true01 = [lv / 100.0 for lv in labels]
                # Brier for regression: mean squared error normalized
                brier = float(sum((a - b) ** 2 for a, b in zip(y_prob, y_true01)) / n) if n else 0.0
            except Exception:
                brier = None
        if brier is None:
            brier = float(sum((p / 100 - lv / 100) ** 2 for p, lv in zip(preds, labels)) / n) if n else 0.0

        # ECE: Expected Calibration Error — bin preds 0-100 into 10 bins
        ece = 0.0
        num_bins = 10
        for b in range(num_bins):
            lo, hi = b * 10, (b + 1) * 10
            bin_idx = [i for i, p in enumerate(preds) if lo <= p < hi or (b == num_bins - 1 and p == 100)]
            if not bin_idx:
                continue
            acc = sum(labels[i] for i in bin_idx) / len(bin_idx)
            conf = sum(preds[i] for i in bin_idx) / len(bin_idx)
            ece += abs(acc - conf) * len(bin_idx) / n
        ece = ece / 100.0  # normalize to 0-1

        # AUROC/AUPRC: binarize labels at >=60 (HIGH/CRITICAL threshold)
        auroc: Optional[float] = None
        auprc: Optional[float] = None
        if HAS_SKLEARN and n >= 4:
            try:
                y_true_bin = [1 if lv >= 60 else 0 for lv in labels]
                if len(set(y_true_bin)) == 2:
                    y_score = [p / 100.0 for p in preds]
                    auroc = float(roc_auc_score(y_true_bin, y_score))  # type: ignore
                    auprc = float(average_precision_score(y_true_bin, y_score))  # type: ignore
            except Exception:
                pass
        # Fallback AUROC via ranking if sklearn absent or failed
        if auroc is None and n >= 4:
            y_true_bin = [1 if lv >= 60 else 0 for lv in labels]
            if len(set(y_true_bin)) == 2:
                # Mann-Whitney U approximation
                pairs_sorted = sorted(zip(preds, y_true_bin), key=lambda x: x[0])
                # simple rank correlation as proxy
                try:
                    n_pos = sum(y_true_bin)
                    n_neg = n - n_pos
                    # count concordant
                    conc = 0
                    for i in range(n):
                        for j in range(i + 1, n):
                            if pairs_sorted[i][1] == 0 and pairs_sorted[j][1] == 1:
                                conc += 1
                            elif pairs_sorted[i][1] == 1 and pairs_sorted[j][1] == 0:
                                conc -= 1
                    auroc = 0.5 + conc / (n_pos * n_neg) / 2 if n_pos * n_neg else 0.5
                    auroc = max(0.0, min(1.0, auroc))
                except Exception:
                    auroc = None

        by_level_mae = {
            lvl: round(sum(v) / len(v), 2) if v else None
            for lvl, v in by_level.items()
        }

        return {
            "mae": round(float(mae), 3),
            "rmse": round(float(rmse), 3),
            "brier": round(float(brier), 4),
            "ece": round(float(ece), 4),
            "auroc": round(float(auroc), 4) if auroc is not None else None,
            "auprc": round(float(auprc), 4) if auprc is not None else None,
            "n": n,
            "by_level_mae": by_level_mae,
            "has_sklearn": HAS_SKLEARN,
            "temperature": self.config.temperature,
            "conformal_margin": self.config.conformal_margin,
        }

    # -- calibration helpers ------------------------------------------------

    def calibrate(
        self, dataset: Optional[List[Dict[str, Any]]] = None, method: str = "temperature"
    ) -> Dict[str, Any]:
        """Standalone calibration (re-fits temperature + conformal).

        Args:
            dataset: Calibration set. If ``None`` a synthetic set is generated.
            method: ``"temperature"`` or ``"none"``.

        Returns:
            Dict with ``temperature``, ``mae_before``, ``mae_after``, ``margin``.
        """
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=200, seed=self.config.seed + 202)
        if method == "none":
            return {"temperature": self.config.temperature, "mae_before": None, "mae_after": None, "margin": self.config.conformal_margin}
        # Delegate to train's temperature search
        before = self.evaluate(dataset)
        mae_before = before["mae"]
        self.train(dataset, epochs=2)
        after = self.evaluate(dataset)
        return {
            "temperature": self.config.temperature,
            "mae_before": mae_before,
            "mae_after": after["mae"],
            "margin": self.config.conformal_margin,
            "brier_after": after["brier"],
            "ece_after": after["ece"],
        }

    # -- synthetic dataset --------------------------------------------------

    def _generate_synthetic_dataset(
        self, n: int = 400, seed: int = 42
    ) -> List[Dict[str, Any]]:
        """Generate deterministic synthetic (factors, label) pairs.

        Labels are heuristic 0-100 scores that reflect the product logic, so
        that training can recover sensible weights.
        """
        rnd = random.Random(seed)
        algos = ["RSA-2048", "RSA-4096", "ECDSA-P256", "ECDH-P256", "AES-256", "SHA-256", "ML-KEM-768", "ML-DSA-65", "HQC-128"]
        purposes = [None, "key-establishment", "signature", "encryption", "hashing", "certificate_handling"]
        data: List[Dict[str, Any]] = []
        for i in range(n):
            algo = rnd.choice(algos)
            vuln = _lookup_vulnerability(algo)
            sens = rnd.randint(0, 5)
            life = rnd.randint(0, 5)
            exp = round(rnd.uniform(0, 8), 1)
            attr = rnd.randint(0, 5)
            lead = rnd.randint(0, 5)
            purpose = rnd.choice(purposes)
            f = ExposureFactors(
                algorithm=algo, sensitivity=sens, lifetime_years=life,
                exposure_years=exp, attractiveness=attr, lead_time_years=lead,
                purpose=purpose,
            )
            # Heuristic label: squash product + HNDL blend (no temperature)
            v = _VULN_WEIGHT[vuln]
            e_score = min(5, max(0, int(math.ceil(exp / 2)))) if exp > 0 else 0
            raw = v * max(0.5, sens) * max(0.5, life) * max(0.5, e_score or 1) * max(0.5, attr) * max(0.5, lead)
            if v == 0:
                raw = 0
            score = _squash_product(raw, temperature=1.0, use_log=True)
            hndl = _hndl_risk(vuln, sens, life, exp, purpose=purpose)
            if vuln == Vulnerability.BROKEN:
                score = max(score, hndl * 0.6 + score * 0.4)
            # Add small noise
            score = max(0, min(100, score + rnd.gauss(0, 4)))
            data.append({"factors": asdict(f), "label": round(float(score), 2), "id": i})
        return data


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== QuantumExposureModel demo ===")
    model = QuantumExposureModel()
    train_res = model.train(epochs=2)
    print(f"[train] {json.dumps(train_res, indent=2)}")

    cases = [
        ExposureFactors(algorithm="RSA-2048", sensitivity=5, lifetime_years=5, exposure_years=5.0, attractiveness=5, lead_time_years=5, purpose="key-establishment"),
        ExposureFactors(algorithm="RSA-2048", sensitivity=5, lifetime_years=5, exposure_years=5.0, attractiveness=5, lead_time_years=5, purpose="signature"),
        ExposureFactors(algorithm="ECDSA-P256", sensitivity=4, lifetime_years=4, exposure_years=3.0, attractiveness=4, lead_time_years=3, purpose="signature"),
        ExposureFactors(algorithm="AES-256", sensitivity=3, lifetime_years=3, exposure_years=2.0, attractiveness=2, lead_time_years=2),
        ExposureFactors(algorithm="ML-KEM-768", sensitivity=5, lifetime_years=5, exposure_years=5.0, attractiveness=5, lead_time_years=5),
        ExposureFactors(algorithm="SHA-256", sensitivity=1, lifetime_years=1, exposure_years=0.2, attractiveness=1, lead_time_years=1, purpose="hashing"),
        ExposureFactors(algorithm="RSA-1024", sensitivity=5, lifetime_years=5, exposure_years=8.0, attractiveness=5, lead_time_years=5, first_seen="2019-01-15"),
    ]
    for f in cases:
        r = model.predict(f)
        print(f"\n{f.algorithm:15s} sens={f.sensitivity} life={f.lifetime_years} exp={f.exposure_years:.1f} "
              f"attr={f.attractiveness} lead={f.lead_time_years} purpose={f.purpose or '-':20s}")
        print(f"  vuln={r.vulnerability.value:10s} raw={r.raw_product:7.1f} score={r.score:5.1f} "
              f"hndl={r.hndl_risk:5.1f} level={r.level:8s} interval={r.interval}")
        print(f"  {r.explanation}")

    eval_res = model.evaluate()
    print(f"\n[evaluate] MAE={eval_res['mae']} RMSE={eval_res['rmse']} Brier={eval_res['brier']} "
          f"ECE={eval_res['ece']} AUROC={eval_res['auroc']} AUPRC={eval_res['auprc']} n={eval_res['n']}")
    print(f"  by_level_mae={eval_res['by_level_mae']}")

    # Alignment check: risk_engine vs this model for same finding
    try:
        from inspector.qtrust_inspector.models import AssetFinding  # type: ignore
        from inspector.qtrust_inspector.risk_engine import calculate_risk_score  # type: ignore
        af = AssetFinding(asset_type="file_key", host="src/auth.py", algorithm="RSA-2048", key_size=2048, criticality="critical", first_seen="2020-06-01")
        re_score = calculate_risk_score(af, data_sensitivity=5, data_lifetime_years=5)
        qe = model.predict(ExposureFactors(algorithm="RSA-2048", key_size=2048, sensitivity=5, lifetime_years=5, exposure_years=5.0, attractiveness=5, lead_time_years=4))
        print(f"\n[alignment] risk_engine overall={re_score.overall_risk_score} hndl={re_score.hndl_exposure_score} level={re_score.risk_level}")
        print(f"           quantum_exposure score={qe.score} hndl={qe.hndl_risk} level={qe.level}")
        print(f"           both CRITICAL/HIGH? risk_engine={re_score.risk_level.value} vs qe={qe.level} -> "
              f"{'ALIGNED' if re_score.risk_level.value == qe.level or {re_score.risk_level.value, qe.level} <= {'CRITICAL','HIGH'} else 'check'}")
    except Exception as e:
        print(f"[alignment] skipped: {e}")

    # Calibration demo
    print("\n--- calibrate ---")
    cal = model.calibrate(method="temperature")
    print(json.dumps(cal, indent=2))
