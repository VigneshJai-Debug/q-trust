"""
Migration Failure Predictor — will migration break prod?

Predicts whether a PQC migration will cause a production incident *before*
cutover, and explains the top likely reasons. Sits between the Cost
Predictor and the Digital Twin in the migration intelligence stack:

    PQC Recommender → Cost Predictor → Failure Predictor → Interoperability
                                      → Constrained Optimizer → Twin

Features (10) per spec:
    library_version, protocol, cert chain depth, PQC impl (ml-kem/ml-dsa/hqc),
    hardware, latency_ms, packet_size_bytes, dependency_count, app_type, traffic

Outputs:
    * failure_prob 0..1 (calibrated)
    * predicted class (``will_break`` at threshold 0.5)
    * top_reasons: list of (reason, contribution %) sorted — e.g.
      ``legacy incompatibility 61%``, ``cert chain 18%``, ``packet overflow 9%``

Architecture: logistic-style linear model over engineered features
(CPU-friendly) + deterministic hash jitter. ``train()`` fits weights via
random-search on synthetic incident data; ``evaluate()`` reports AUROC /
AUPRC / Brier / accuracy.

Example:
    pred = MigrationFailurePredictor()
    pred.train()
    feats = FailureFeatures(library="openssl", library_version="1.1.1w",
                            protocol="TLS1.2", hardware="hsm", pqc_impl="ML-KEM-768")
    r = pred.predict(feats)
    assert 0 <= r.failure_prob <= 1
    print(r.top_reasons)  # [("legacy incompatibility", 0.61), ...]
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

try:
    from sklearn.metrics import roc_auc_score, average_precision_score  # type: ignore
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    from sklearn.linear_model import LogisticRegression  # type: ignore
    HAS_LR = True
except ImportError:
    HAS_LR = False
    LogisticRegression = None  # type: ignore


# ---------------------------------------------------------------------------
# Failure reason taxonomy
# ---------------------------------------------------------------------------

REASON_LABELS: List[str] = [
    "legacy incompatibility",
    "library outdated / unsupported PQC",
    "cert chain incompatibility",
    "hardware unsupported (HSM/TPM/MCU)",
    "packet size / MTU overflow",
    "latency / timeout exceeded",
    "high dependency ripple",
    "protocol mismatch / downgrade",
    "traffic surge amplifies failure",
    "app type fragile (firmware / HSM / banking)",
]

# Each reason's raw weight depends on features — mapped below


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FailureFeatures:
    """Input features for failure prediction.

    Attributes:
        library: Crypto library (``openssl``, ``boringssl``, ``libsodium``,
            ``bouncy-castle``, ``mbedtls``, ``proprietary``).
        library_version: Version string — ``"1.1.1w"`` is high-risk.
        protocol: ``TLS1.2`` / ``TLS1.3`` / ``mTLS`` / ``SSH`` / ``QUIC`` / ``IPSec`` / ``custom``.
        cert_chain_depth: Depth of the certificate chain (1-5; deeper → more fragile).
        pqc_impl: Target PQC implementation (``ML-KEM-768``, ``ML-DSA-65``, ``HQC-128``, ``hybrid``).
        hardware: ``x86`` / ``arm`` / ``hsm`` / ``tpm`` / ``iot-mcu`` / ``smartcard``.
        latency_ms: Baseline service p95 latency in ms.
        packet_size_bytes: Typical handshake / packet size (bytes).
        dependency_count: Number of dependents that must all migrate.
        app_type: ``banking-api`` / ``payment`` / ``iot-firmware`` / ``web`` / etc.
        traffic_rps: Peak traffic (requests/s).
    """

    library: str = "openssl"
    library_version: str = "3.0.8"
    protocol: str = "TLS1.3"
    cert_chain_depth: int = 2
    pqc_impl: str = "ML-KEM-768"
    hardware: str = "x86"
    latency_ms: float = 80.0
    packet_size_bytes: int = 1500
    dependency_count: int = 5
    app_type: str = "web"
    traffic_rps: int = 500

    def clamp(self) -> "FailureFeatures":
        import copy
        c = copy.copy(self)
        c.cert_chain_depth = max(1, min(10, int(c.cert_chain_depth)))
        c.latency_ms = max(1.0, min(5000.0, float(c.latency_ms)))
        c.packet_size_bytes = max(64, min(100_000, int(c.packet_size_bytes)))
        c.dependency_count = max(0, min(200, int(c.dependency_count)))
        c.traffic_rps = max(0, min(1_000_000, int(c.traffic_rps)))
        return c


@dataclass
class FailurePrediction:
    """Output of :meth:`MigrationFailurePredictor.predict`."""

    failure_prob: float               # 0..1
    will_break: bool                  # prob >= threshold
    threshold: float = 0.5
    top_reasons: List[Tuple[str, float]] = field(default_factory=list)  # (reason, share 0..1) sums ~1
    all_reason_scores: Dict[str, float] = field(default_factory=dict)   # raw 0..1 per reason
    latency_risk: float = 0.0
    packet_risk: float = 0.0
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # tuples → lists for JSON
        d["top_reasons"] = [[k, round(v, 3)] for k, v in self.top_reasons]
        return d


@dataclass
class FailurePredictorConfig:
    seed: int = 42
    threshold: float = 0.5
    use_sklearn: bool = True
    temperature: float = 1.0  # Platt scaling temperature
    conformal_alpha: float = 0.1


# ---------------------------------------------------------------------------
# Feature engineering → per-reason raw scores 0..1
# ---------------------------------------------------------------------------

def _lib_age_score(library: str, version: str) -> float:
    lib = library.lower()
    ver = version.strip().lower()
    if lib.startswith("openssl"):
        if ver.startswith("1.0"):
            return 0.95
        if ver.startswith("1.1"):
            return 0.80
        if ver.startswith("3.0"):
            return 0.20
        if ver.startswith("3.1") or ver.startswith("3.2") or ver.startswith("3.3"):
            return 0.10
    if lib.startswith("mbedtls") and ver.startswith("2."):
        return 0.75
    if "proprietary" in lib or "custom" in lib:
        return 0.65
    if lib in ("boringssl", "aws-lc"):
        return 0.25
    return 0.30


def _protocol_risk(protocol: str) -> float:
    p = protocol.lower()
    table = {"tls1.3": 0.15, "tls1.2": 0.55, "mtls": 0.60, "quic": 0.45, "ssh": 0.35, "ipsec": 0.50, "custom": 0.85, "proprietary": 0.90}
    return table.get(p, 0.50)


def _hardware_risk(hardware: str) -> float:
    h = hardware.lower()
    table = {"x86": 0.10, "arm": 0.25, "tpm": 0.55, "hsm": 0.70, "iot-mcu": 0.80, "smartcard": 0.85, "fpga": 0.40}
    return table.get(h, 0.30)


def _pqc_risk(pqc_impl: str) -> float:
    impl = pqc_impl.lower()
    if "hqc" in impl:
        return 0.45  # larger keys/ciphertexts → higher overflow risk
    if "slh-dsa" in impl:
        return 0.50  # large signatures
    if "falcon" in impl:
        return 0.30
    if "ml-kem" in impl or "ml-dsa" in impl:
        return 0.20
    if "hybrid" in impl:
        return 0.25
    return 0.35


def _packet_risk(packet_size: int) -> float:
    # ML-KEM-768 ct ≈ 1088, SLH-DSA sig ≈ 7856-29792; MTU 1500 overflow matters
    if packet_size > 8000:
        return 0.85
    if packet_size > 4000:
        return 0.60
    if packet_size > 1500:
        return 0.35
    return 0.10


def _latency_risk(latency_ms: float) -> float:
    if latency_ms > 500:
        return 0.75
    if latency_ms > 200:
        return 0.45
    if latency_ms > 100:
        return 0.25
    return 0.10


def _per_reason_scores(f: FailureFeatures) -> Dict[str, float]:
    """Compute raw 0..1 risk per reason."""
    c = f.clamp()
    lib_age = _lib_age_score(c.library, c.library_version)
    proto = _protocol_risk(c.protocol)
    hw = _hardware_risk(c.hardware)
    pqc = _pqc_risk(c.pqc_impl)
    pkt = _packet_risk(c.packet_size_bytes)
    lat = _latency_risk(c.latency_ms)
    dep = min(1.0, c.dependency_count / 30.0)  # 30 deps → 1.0
    traffic = min(1.0, math.log1p(c.traffic_rps) / math.log1p(50000))  # log scale
    app_fragile = {"iot-firmware": 0.85, "hsm": 0.80, "banking-api": 0.60, "payment": 0.55, "tls-gateway": 0.40, "web": 0.15, "mobile": 0.25}.get(c.app_type.lower(), 0.30)
    chain = min(1.0, (c.cert_chain_depth - 1) / 4.0)  # depth 1→0, 5→1

    return {
        "legacy incompatibility": max(lib_age, proto * 0.8, pqc * 0.6) * (0.7 + dep * 0.3),
        "library outdated / unsupported PQC": lib_age,
        "cert chain incompatibility": max(chain, lib_age * 0.5) * (0.6 + proto * 0.4),
        "hardware unsupported (HSM/TPM/MCU)": hw * (0.6 + pqc * 0.4),
        "packet size / MTU overflow": max(pkt, pqc * 0.7) * (0.5 + hw * 0.3),
        "latency / timeout exceeded": max(lat, hw * 0.4) * (0.5 + pqc * 0.5),
        "high dependency ripple": dep * (0.6 + traffic * 0.4),
        "protocol mismatch / downgrade": proto * (0.7 + lib_age * 0.3),
        "traffic surge amplifies failure": traffic * (0.6 + dep * 0.4),
        "app type fragile (firmware / HSM / banking)": app_fragile * (0.7 + hw * 0.3),
    }


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-30, min(30, x))))


def _deterministic_jitter_features(f: FailureFeatures, seed: int) -> float:
    key = f"{f.library}:{f.library_version}:{f.protocol}:{f.hardware}:{f.pqc_impl}:{f.app_type}:{f.dependency_count}"
    h = hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()
    v = (int(h[:4], 16) % 200) / 1000.0 - 0.10  # -0.10..+0.10
    return v


# ---------------------------------------------------------------------------
# Predictor
# ---------------------------------------------------------------------------

class MigrationFailurePredictor:
    """Migration failure (prod break) predictor.

    Answers: *will this migration break production?* and *why?*.

    The model is a lightweight logistic over 10 engineered risk signals,
    CPU-friendly and deterministic. ``train()`` fits per-reason weights
    (global) plus an optional ``sklearn`` LogisticRegression on the same
    10-D feature vector.

    Attributes:
        config: :class:`FailurePredictorConfig`.
        is_trained: Whether :meth:`train` has been called.

    Example:
        >>> m = MigrationFailurePredictor(seed=0)
        >>> m.train()
        >>> f = FailureFeatures(library="openssl", library_version="1.1.1w",
        ...                     protocol="TLS1.2", hardware="hsm",
        ...                     pqc_impl="ML-KEM-768", dependency_count=25,
        ...                     latency_ms=300, packet_size_bytes=8000)
        >>> r = m.predict(f)
        >>> 0 <= r.failure_prob <= 1
        True
        >>> len(r.top_reasons) >= 1
        True
    """

    def __init__(self, config: Optional[FailurePredictorConfig] = None, seed: int = 42) -> None:
        self.config = config or FailurePredictorConfig(seed=seed)
        self.config.seed = seed
        random.seed(seed)
        self.is_trained = False
        self._weights: Dict[str, float] = {label: 1.0 for label in REASON_LABELS}
        self._bias: float = -1.2  # calibrated so median case ~ 0.25
        self._lr_model: Any = None

    # ---- training ---------------------------------------------------------

    def train(
        self,
        dataset: Optional[List[Dict[str, Any]]] = None,
        epochs: int = 8,
    ) -> Dict[str, Any]:
        """Fit per-reason weights (and optional sklearn LR).

        Args:
            dataset: List of ``{"features": FailureFeatures|dict, "label": 0/1}``
                or ``{"library": ..., "label": 0}`` flat dicts. If ``None``
                a synthetic incident dataset is generated.
            epochs: Random-search iterations (×12) for weight fitting.

        Returns:
            Dict with ``examples``, ``weights``, ``bias``, ``auroc``,
            ``has_sklearn``.
        """
        random.seed(self.config.seed)
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=600, seed=self.config.seed)

        pairs: List[Tuple[FailureFeatures, int]] = []
        for ex in dataset:
            if "features" in ex:
                raw = ex["features"]
                if isinstance(raw, dict):
                    f = FailureFeatures(**{k: v for k, v in raw.items() if k in FailureFeatures.__dataclass_fields__})
                else:
                    f = raw  # type: ignore
                label = int(ex.get("label", 0))
            else:
                f = FailureFeatures(**{k: v for k, v in ex.items() if k in FailureFeatures.__dataclass_fields__})
                label = int(ex.get("label", 0))
            pairs.append((f, max(0, min(1, label))))

        # Random-search to maximise AUROC proxy (accuracy here) on eng scores
        best_w = dict(self._weights)
        best_b = self._bias
        best_acc = self._accuracy(pairs, best_w, best_b)
        rnd = random.Random(self.config.seed)
        for _ in range(epochs * 12):
            cand_w = {k: max(0.5, min(2.0, v + rnd.uniform(-0.12, 0.12))) for k, v in best_w.items()}
            cand_b = max(-3.0, min(1.0, best_b + rnd.uniform(-0.15, 0.15)))
            acc = self._accuracy(pairs, cand_w, cand_b)
            if acc > best_acc:
                best_acc = acc
                best_w, best_b = cand_w, cand_b

        self._weights = best_w
        self._bias = best_b

        # Optional sklearn LogisticRegression on 10-D engineered features
        if HAS_LR and self.config.use_sklearn:
            try:
                X = [self._featurize_vec(f) for f, _ in pairs]
                y = [lbl for _, lbl in pairs]
                import numpy as np  # type: ignore
                Xn = np.array(X, dtype=float)
                yn = np.array(y, dtype=int)
                # Only fit if both classes present
                if len(set(y)) == 2:
                    self._lr_model = LogisticRegression(max_iter=400, random_state=self.config.seed)  # type: ignore
                    self._lr_model.fit(Xn, yn)  # type: ignore
            except Exception:
                self._lr_model = None

        self.is_trained = True

        # Quick AUROC estimate on training set
        auroc = self._auroc_fallback(pairs)
        return {
            "examples": len(pairs),
            "weights": {k: round(v, 3) for k, v in best_w.items()},
            "bias": round(float(best_b), 3),
            "train_accuracy": round(float(best_acc), 4),
            "train_auroc": round(float(auroc), 4) if auroc is not None else None,
            "has_sklearn": self._lr_model is not None,
        }

    def _featurize_vec(self, f: FailureFeatures) -> List[float]:
        scores = _per_reason_scores(f)
        return [scores[label] for label in REASON_LABELS]

    def _logit(self, f: FailureFeatures, weights: Dict[str, float], bias: float) -> float:
        scores = _per_reason_scores(f)
        # Weighted sum
        s = bias
        for label in REASON_LABELS:
            s += scores[label] * weights.get(label, 1.0) * 0.55  # 0.55 scales sum to logit range
        # legacy bump: if 3+ high risks (>0.6), push logit up
        high = sum(1 for label in REASON_LABELS if scores[label] > 0.6)
        if high >= 3:
            s += 0.6
        s += _deterministic_jitter_features(f, self.config.seed) * 0.5
        return s

    def _prob(self, f: FailureFeatures, weights: Dict[str, float], bias: float) -> float:
        logit = self._logit(f, weights, bias)
        # Temperature scaling
        if self.config.temperature != 1.0:
            logit = logit / max(0.2, self.config.temperature)
        return _sigmoid(logit)

    def _accuracy(self, pairs: List[Tuple[FailureFeatures, int]], weights: Dict[str, float], bias: float) -> float:
        if not pairs:
            return 0.0
        correct = 0
        for f, lbl in pairs:
            p = self._prob(f, weights, bias)
            pred = 1 if p >= self.config.threshold else 0
            if pred == lbl:
                correct += 1
        return correct / len(pairs)

    def _auroc_fallback(self, pairs: List[Tuple[FailureFeatures, int]]) -> Optional[float]:
        if not pairs or len(set(lbl for _, lbl in pairs)) < 2:
            return None
        if HAS_SKLEARN:
            try:
                y_true = [lbl for _, lbl in pairs]
                y_score = [self._prob(f, self._weights, self._bias) for f, _ in pairs]
                return float(roc_auc_score(y_true, y_score))  # type: ignore
            except Exception:
                pass
        # Mann-Whitney fallback
        try:
            y_true = [lbl for _, lbl in pairs]
            y_score = [self._prob(f, self._weights, self._bias) for f, _ in pairs]
            pairs_sorted = sorted(zip(y_score, y_true), key=lambda x: x[0])
            n_pos = sum(y_true)
            n_neg = len(y_true) - n_pos
            conc = 0
            for i in range(len(pairs_sorted)):
                for j in range(i + 1, len(pairs_sorted)):
                    if pairs_sorted[i][1] == 0 and pairs_sorted[j][1] == 1:
                        conc += 1
                    elif pairs_sorted[i][1] == 1 and pairs_sorted[j][1] == 0:
                        conc -= 1
            return max(0.0, min(1.0, 0.5 + conc / (n_pos * n_neg) / 2 if n_pos * n_neg else 0.5))
        except Exception:
            return None

    # ---- prediction -------------------------------------------------------

    def predict(self, features: FailureFeatures) -> FailurePrediction:
        """Predict failure probability and top reasons for *features*.

        Args:
            features: :class:`FailureFeatures`.

        Returns:
            :class:`FailurePrediction` with ``failure_prob``, ``will_break``,
            and ranked ``top_reasons``.
        """
        c = features.clamp()
        raw_scores = _per_reason_scores(c)

        # Heuristic probability
        heuristic_prob = self._prob(c, self._weights, self._bias)

        # Optional sklearn blend
        prob = heuristic_prob
        if self._lr_model is not None:
            try:
                import numpy as np  # type: ignore
                X = np.array([self._featurize_vec(c)], dtype=float)
                ml_prob = float(self._lr_model.predict_proba(X)[0][1])  # type: ignore
                prob = heuristic_prob * 0.55 + ml_prob * 0.45
            except Exception:
                pass

        prob = max(0.01, min(0.99, prob))
        will_break = prob >= self.config.threshold

        # Rank reasons by weighted contribution
        weighted = {label: raw_scores[label] * self._weights.get(label, 1.0) for label in REASON_LABELS}
        total = sum(weighted.values()) or 1.0
        shares = {k: v / total for k, v in weighted.items()}
        ranked = sorted(shares.items(), key=lambda x: -x[1])

        # Top 3-4 reasons that sum to ~80%
        top: List[Tuple[str, float]] = []
        cum = 0.0
        for label, share in ranked:
            if cum >= 0.85 and len(top) >= 3:
                break
            top.append((label, round(float(share), 3)))
            cum += share
            if len(top) >= 4 and cum >= 0.6:
                break

        # All reason scores (raw)
        all_scores = {k: round(float(v), 3) for k, v in raw_scores.items()}

        # Latency / packet sub-risks
        lat_risk = all_scores.get("latency / timeout exceeded", 0.0)
        pkt_risk = all_scores.get("packet size / MTU overflow", 0.0)

        # Explanation
        top_str = ", ".join(f"{label} {share:.0%}" for label, share in top[:3])
        expl = (
            f"p={prob:.1%} ({'BREAK' if will_break else 'ok'} @ {self.config.threshold:.0%}) "
            f"top: {top_str}; hw={c.hardware} lib={c.library} {c.library_version} "
            f"proto={c.protocol} pqc={c.pqc_impl} deps={c.dependency_count} "
            f"lat={c.latency_ms:.0f}ms pkt={c.packet_size_bytes}B"
        )

        return FailurePrediction(
            failure_prob=round(float(prob), 4),
            will_break=will_break,
            threshold=self.config.threshold,
            top_reasons=top,
            all_reason_scores=all_scores,
            latency_risk=lat_risk,
            packet_risk=pkt_risk,
            explanation=expl,
        )

    def predict_batch(self, batch: List[FailureFeatures]) -> List[FailurePrediction]:
        return [self.predict(f) for f in batch]

    # ---- evaluation -------------------------------------------------------

    def evaluate(self, dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Evaluate on a labelled incident dataset.

        Reports accuracy, AUROC, AUPRC, Brier, ECE-style.

        Args:
            dataset: Same format as :meth:`train`. If ``None`` a synthetic eval
                set is generated.

        Returns:
            Dict with ``accuracy``, ``auroc``, ``auprc``, ``brier``, ``ece``,
            ``n``.
        """
        if dataset is None:
            dataset = self._generate_synthetic_dataset(n=300, seed=self.config.seed + 101)

        pairs: List[Tuple[FailureFeatures, int]] = []
        for ex in dataset:
            if "features" in ex:
                raw = ex["features"]
                if isinstance(raw, dict):
                    f = FailureFeatures(**{k: v for k, v in raw.items() if k in FailureFeatures.__dataclass_fields__})
                else:
                    f = raw  # type: ignore
                label = int(ex.get("label", 0))
            else:
                f = FailureFeatures(**{k: v for k, v in ex.items() if k in FailureFeatures.__dataclass_fields__})
                label = int(ex.get("label", 0))
            pairs.append((f, label))

        y_true: List[int] = []
        y_score: List[float] = []
        y_pred: List[int] = []
        for f, lbl in pairs:
            p = self.predict(f).failure_prob
            y_true.append(lbl)
            y_score.append(p)
            y_pred.append(1 if p >= self.config.threshold else 0)

        # Accuracy
        acc = sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true) if y_true else 0.0

        # Brier
        brier = sum((s - t) ** 2 for s, t in zip(y_score, y_true)) / len(y_true) if y_true else 0.0

        # ECE (10 bins)
        ece = 0.0
        num_bins = 10
        for b in range(num_bins):
            lo, hi = b / 10, (b + 1) / 10
            idx = [i for i, s in enumerate(y_score) if lo <= s < hi or (b == num_bins - 1 and s == 1.0)]
            if not idx:
                continue
            acc_bin = sum(y_true[i] for i in idx) / len(idx)
            conf_bin = sum(y_score[i] for i in idx) / len(idx)
            ece += abs(acc_bin - conf_bin) * len(idx) / len(y_true)

        auroc: Optional[float] = None
        auprc: Optional[float] = None
        if HAS_SKLEARN and len(set(y_true)) == 2:
            try:
                auroc = float(roc_auc_score(y_true, y_score))  # type: ignore
                auprc = float(average_precision_score(y_true, y_score))  # type: ignore
            except Exception:
                pass
        if auroc is None and len(set(y_true)) == 2:
            # fallback via _auroc_fallback but need y_score already
            try:
                pairs_sorted = sorted(zip(y_score, y_true), key=lambda x: x[0])
                n_pos = sum(y_true)
                n_neg = len(y_true) - n_pos
                conc = 0
                for i in range(len(pairs_sorted)):
                    for j in range(i + 1, len(pairs_sorted)):
                        if pairs_sorted[i][1] == 0 and pairs_sorted[j][1] == 1:
                            conc += 1
                        elif pairs_sorted[i][1] == 1 and pairs_sorted[j][1] == 0:
                            conc -= 1
                auroc = max(0.0, min(1.0, 0.5 + conc / (n_pos * n_neg) / 2 if n_pos * n_neg else 0.5))
            except Exception:
                auroc = None

        return {
            "accuracy": round(float(acc), 4),
            "auroc": round(float(auroc), 4) if auroc is not None else None,
            "auprc": round(float(auprc), 4) if auprc is not None else None,
            "brier": round(float(brier), 4),
            "ece": round(float(ece), 4),
            "n": len(pairs),
            "has_sklearn": HAS_SKLEARN,
            "threshold": self.config.threshold,
        }

    # ---- synthetic dataset ------------------------------------------------

    def _generate_synthetic_dataset(self, n: int = 600, seed: int = 42) -> List[Dict[str, Any]]:
        rnd = random.Random(seed)
        libs = ["openssl", "boringssl", "mbedtls", "libsodium", "proprietary"]
        vers_map = {"openssl": ["3.0.8", "3.1.2", "1.1.1w", "1.0.2u"], "mbedtls": ["3.4.0", "2.28.0"], "boringssl": ["head"], "libsodium": ["1.0.18"], "proprietary": ["2.1.0", "1.0.0"]}
        protocols = ["TLS1.3", "TLS1.2", "mTLS", "SSH", "QUIC", "custom"]
        hws = ["x86", "arm", "hsm", "tpm", "iot-mcu"]
        pqcs = ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "SLH-DSA-SHA2-128s", "HQC-128", "hybrid"]
        apps = ["web", "banking-api", "payment", "iot-firmware", "tls-gateway", "hsm", "auth-service"]
        data: List[Dict[str, Any]] = []
        for i in range(n):
            lib = rnd.choice(libs)
            ver = rnd.choice(vers_map.get(lib, ["1.0.0"]))
            proto = rnd.choice(protocols)
            hw = rnd.choice(hws)
            pqc = rnd.choice(pqcs)
            app = rnd.choice(apps)
            f = FailureFeatures(
                library=lib, library_version=ver, protocol=proto,
                cert_chain_depth=rnd.randint(1, 4), pqc_impl=pqc, hardware=hw,
                latency_ms=round(rnd.uniform(20, 600), 1),
                packet_size_bytes=rnd.choice([1200, 1500, 2000, 4000, 8000, 15000]),
                dependency_count=rnd.randint(0, 50),
                app_type=app, traffic_rps=rnd.randint(10, 50000),
            )
            # Label: heuristic prob > 0.5 → 1 else 0, with noise
            # Use temporary weights (uniform) to generate ground truth
            raw = _per_reason_scores(f)
            logit = -1.2 + sum(raw[r] * 0.55 for r in REASON_LABELS)
            if sum(1 for r in REASON_LABELS if raw[r] > 0.6) >= 3:
                logit += 0.6
            true_prob = _sigmoid(logit)
            # Inject some high-risk forced labels
            if lib == "openssl" and ver.startswith("1.1") and proto in ("TLS1.2", "mTLS") and hw in ("hsm", "iot-mcu"):
                true_prob = min(0.95, true_prob + 0.35)
            label = 1 if rnd.random() < true_prob else 0
            # Add 5% label noise
            if rnd.random() < 0.05:
                label = 1 - label
            data.append({"features": asdict(f), "label": label, "id": i})
        return data


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== MigrationFailurePredictor demo ===")
    m = MigrationFailurePredictor(seed=42)
    train_res = m.train(epochs=5)
    print(f"[train] {json.dumps(train_res, indent=2)}")

    cases = [
        FailureFeatures(library="openssl", library_version="3.1.2", protocol="TLS1.3", hardware="x86", pqc_impl="ML-KEM-768", latency_ms=45, packet_size_bytes=1300, dependency_count=3, app_type="web", traffic_rps=1000, cert_chain_depth=2),
        FailureFeatures(library="openssl", library_version="1.1.1w", protocol="TLS1.2", hardware="hsm", pqc_impl="ML-KEM-768", latency_ms=300, packet_size_bytes=8000, dependency_count=25, app_type="banking-api", traffic_rps=5000, cert_chain_depth=4),
        FailureFeatures(library="mbedtls", library_version="2.28.0", protocol="custom", hardware="iot-mcu", pqc_impl="SLH-DSA-SHA2-128s", latency_ms=600, packet_size_bytes=15000, dependency_count=35, app_type="iot-firmware", traffic_rps=200, cert_chain_depth=3),
        FailureFeatures(library="boringssl", library_version="head", protocol="TLS1.3", hardware="x86", pqc_impl="ML-DSA-65", latency_ms=60, packet_size_bytes=1500, dependency_count=8, app_type="payment", traffic_rps=12000, cert_chain_depth=3),
        FailureFeatures(library="proprietary", library_version="1.0.0", protocol="custom", hardware="smartcard", pqc_impl="HQC-128", latency_ms=800, packet_size_bytes=9000, dependency_count=40, app_type="hsm", traffic_rps=8000, cert_chain_depth=5),
    ]
    for f in cases:
        r = m.predict(f)
        print(f"\n{f.library} {f.library_version} {f.protocol} {f.hardware} {f.pqc_impl} deps={f.dependency_count} lat={f.latency_ms:.0f}ms pkt={f.packet_size_bytes}B")
        print(f"  failure_prob={r.failure_prob:.1%} will_break={r.will_break} (thr {r.threshold:.0%})")
        print(f"  top_reasons: {', '.join(f'{lbl} {share:.0%}' for lbl, share in r.top_reasons)}")
        print(f"  explanation: {r.explanation}")

    print("\n--- batch ---")
    batch = [
        FailureFeatures(library="openssl", library_version="3.1.2", protocol="TLS1.3", hardware="x86", pqc_impl="ML-KEM-768"),
        FailureFeatures(library="openssl", library_version="1.1.1w", protocol="TLS1.2", hardware="hsm", pqc_impl="ML-KEM-1024"),
    ]
    for r in m.predict_batch(batch):
        print(f"  p={r.failure_prob:.1%} break={r.will_break} top={r.top_reasons[0]}")

    eval_res = m.evaluate()
    print(f"\n[evaluate] acc={eval_res['accuracy']} auroc={eval_res['auroc']} auprc={eval_res['auprc']} brier={eval_res['brier']} ece={eval_res['ece']} n={eval_res['n']}")

    # Sanity: modern stack should be low risk, legacy HSM should be high
    low = m.predict(FailureFeatures(library="openssl", library_version="3.1.2", protocol="TLS1.3", hardware="x86", pqc_impl="ML-KEM-768", latency_ms=50, packet_size_bytes=1200, dependency_count=2, app_type="web"))
    high = m.predict(FailureFeatures(library="openssl", library_version="1.1.1w", protocol="TLS1.2", hardware="hsm", pqc_impl="ML-KEM-768", latency_ms=400, packet_size_bytes=9000, dependency_count=30, app_type="iot-firmware"))
    print(f"\n[sanity] modern low={low.failure_prob:.1%} vs legacy high={high.failure_prob:.1%} -> {'PASS' if low.failure_prob < high.failure_prob else 'FAIL'}")
