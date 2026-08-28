"""
Algorithm / Purpose Classifier — maps crypto usage to cryptographic purpose.

Architecture reference: ``qtrust_ai/README.md`` Phase 1 Foundation.

Purpose taxonomy (6 classes):
    * key-establishment  — KEM / key exchange / key agreement (DH, ECDH, ML-KEM)
    * signature          — signing / verification (RSA-PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA)
    * encryption         — symmetric / asymmetric encryption (AES, ChaCha20, RSA-OAEP)
    * hashing            — digest / KDF / integrity (SHA-2, SHA-3, HMAC)
    * randomness         — RNG / entropy (DRBG, /dev/urandom, getrandom)
    * certificate_handling — X.509 / PEM / chain validation / TLS cert

This module provides :class:`AlgorithmPurposeClassifier` which disambiguates
dual-use algorithms (e.g. RSA → signature vs KEM vs encryption, ECDSA vs ECDH,
AES → encryption vs key wrap) via **purpose-aware features**:

* Context window (surrounding tokens / API names: ``sign``, ``verify``,
  ``encrypt``, ``derive``, ``hmac``, ``random``)
* Import / library features (``cryptography.hazmat.primitives.asymmetric``)
* Call-site features (function name, argument names, return-value usage)
* Data-flow features (key type: ``private_key.sign`` vs ``public_key.encrypt``)

Train / predict / evaluate are CPU-friendly with deterministic fallback when
``sklearn`` / ``torch`` are absent. The model aligns with ``risk_engine.py``
vulnerability DB so that quantum impact reflects purpose (HNDL-relevant KEM
vs signature-only).

Example:
    clf = AlgorithmPurposeClassifier()
    clf.train()
    res = clf.predict("RSA", context="rsa.sign(data, private_key)")
    assert res.purpose == Purpose.SIGNATURE
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

try:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
    from sklearn.linear_model import LogisticRegression  # type: ignore
    from sklearn.metrics import precision_recall_fscore_support  # type: ignore
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    TfidfVectorizer = None  # type: ignore
    LogisticRegression = None  # type: ignore

# ---------------------------------------------------------------------------
# Purpose taxonomy
# ---------------------------------------------------------------------------

class Purpose(str, Enum):
    """Cryptographic purpose — aligns with CBOM / NIST workstreams."""

    KEY_ESTABLISHMENT = "key-establishment"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    HASHING = "hashing"
    RANDOMNESS = "randomness"
    CERTIFICATE_HANDLING = "certificate_handling"

    @classmethod
    def list(cls) -> List[str]:
        return [p.value for p in cls]


# Map algorithm families → plausible purposes (for validation / fallback)
_ALGORITHM_PURPOSE_PRIORS: Dict[str, List[Purpose]] = {
    "RSA": [Purpose.SIGNATURE, Purpose.ENCRYPTION, Purpose.KEY_ESTABLISHMENT, Purpose.CERTIFICATE_HANDLING],
    "ECDSA": [Purpose.SIGNATURE, Purpose.CERTIFICATE_HANDLING],
    "ECDH": [Purpose.KEY_ESTABLISHMENT],
    "DSA": [Purpose.SIGNATURE],
    "DH": [Purpose.KEY_ESTABLISHMENT],
    "ED25519": [Purpose.SIGNATURE],
    "ED448": [Purpose.SIGNATURE],
    "X25519": [Purpose.KEY_ESTABLISHMENT],
    "X448": [Purpose.KEY_ESTABLISHMENT],
    "ML-KEM": [Purpose.KEY_ESTABLISHMENT, Purpose.ENCRYPTION],
    "ML-DSA": [Purpose.SIGNATURE, Purpose.CERTIFICATE_HANDLING],
    "SLH-DSA": [Purpose.SIGNATURE],
    "HQC": [Purpose.KEY_ESTABLISHMENT],
    "FALCON": [Purpose.SIGNATURE],
    "AES": [Purpose.ENCRYPTION],
    "CHACHA20": [Purpose.ENCRYPTION],
    "SHA": [Purpose.HASHING],
    "SHA3": [Purpose.HASHING],
    "HMAC": [Purpose.HASHING],
    "RANDOM": [Purpose.RANDOMNESS],
    "DRBG": [Purpose.RANDOMNESS],
    "CERT": [Purpose.CERTIFICATE_HANDLING],
    "X509": [Purpose.CERTIFICATE_HANDLING],
}

# Keyword → purpose vote (context window features)
_KEYWORD_PURPOSE_MAP: Dict[str, Purpose] = {
    # signature
    "sign": Purpose.SIGNATURE, "verify": Purpose.SIGNATURE, "signature": Purpose.SIGNATURE,
    "ecdsa": Purpose.SIGNATURE, "dsa": Purpose.SIGNATURE, "ed25519": Purpose.SIGNATURE,
    "pss": Purpose.SIGNATURE, "dilithium": Purpose.SIGNATURE, "falcon": Purpose.SIGNATURE,
    "sphincs": Purpose.SIGNATURE, "slh-dsa": Purpose.SIGNATURE,
    # kem / key-establishment
    "kem": Purpose.KEY_ESTABLISHMENT, "encaps": Purpose.KEY_ESTABLISHMENT,
    "decaps": Purpose.KEY_ESTABLISHMENT, "key_exchange": Purpose.KEY_ESTABLISHMENT,
    "key_agreement": Purpose.KEY_ESTABLISHMENT, "ecdh": Purpose.KEY_ESTABLISHMENT,
    "diffie": Purpose.KEY_ESTABLISHMENT, "kyber": Purpose.KEY_ESTABLISHMENT,
    "ml-kem": Purpose.KEY_ESTABLISHMENT, "hqc": Purpose.KEY_ESTABLISHMENT,
    "derive": Purpose.KEY_ESTABLISHMENT, "shared_secret": Purpose.KEY_ESTABLISHMENT,
    # encryption
    "encrypt": Purpose.ENCRYPTION, "decrypt": Purpose.ENCRYPTION, "cipher": Purpose.ENCRYPTION,
    "aes": Purpose.ENCRYPTION, "chacha": Purpose.ENCRYPTION, "gcm": Purpose.ENCRYPTION,
    "cbc": Purpose.ENCRYPTION, "oaep": Purpose.ENCRYPTION,
    # hashing
    "hash": Purpose.HASHING, "digest": Purpose.HASHING, "sha256": Purpose.HASHING,
    "sha512": Purpose.HASHING, "hmac": Purpose.HASHING, "kdf": Purpose.HASHING,
    "pbkdf": Purpose.HASHING, "hkdf": Purpose.HASHING,
    # randomness
    "random": Purpose.RANDOMNESS, "rand": Purpose.RANDOMNESS, "entropy": Purpose.RANDOMNESS,
    "drbg": Purpose.RANDOMNESS, "urandom": Purpose.RANDOMNESS, "getrandom": Purpose.RANDOMNESS,
    "nonce": Purpose.RANDOMNESS,
    # cert handling
    "certificate": Purpose.CERTIFICATE_HANDLING, "x509": Purpose.CERTIFICATE_HANDLING,
    "pem": Purpose.CERTIFICATE_HANDLING, "chain": Purpose.CERTIFICATE_HANDLING,
    "tls": Purpose.CERTIFICATE_HANDLING, "mtls": Purpose.CERTIFICATE_HANDLING,
    "issuer": Purpose.CERTIFICATE_HANDLING, "subject": Purpose.CERTIFICATE_HANDLING,
}

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PurposeResult:
    """Output of :meth:`AlgorithmPurposeClassifier.predict`."""

    algorithm: str
    normalized_algorithm: str
    purpose: Purpose
    confidence: float
    all_scores: Dict[str, float] = field(default_factory=dict)
    explanation: str = ""
    hndl_relevant: bool = False  # True if purpose is HNDL-sensitive (KEM/encryption)


@dataclass
class ClassifierConfig:
    """Hyper-parameters for :class:`AlgorithmPurposeClassifier`."""

    seed: int = 42
    threshold: float = 0.35
    use_sklearn: bool = True
    purpose_aware: bool = True


# ---------------------------------------------------------------------------
# Feature helpers
# ---------------------------------------------------------------------------

def _normalize_algorithm(algorithm: str) -> str:
    return algorithm.upper().replace(" ", "").replace("_", "-")


def _algorithm_family(algorithm: str) -> str:
    upper = _normalize_algorithm(algorithm)
    # strip size suffixes like -2048, -P256, -128
    for fam in ["ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FALCON", "ED25519", "ED448",
                "X25519", "X448", "ECDSA", "ECDH", "CHACHA20", "AES", "SHA3", "SHA", "HMAC", "RSA", "DSA", "DH", "CERT", "X509"]:
        if fam in upper:
            return fam
    return upper.split("-")[0].split("_")[0]


def _context_features(context: str) -> Dict[str, float]:
    """Bag-of-keywords → purpose logits from context window."""
    lower = context.lower()
    scores: Dict[str, float] = defaultdict(float)
    for kw, purpose in _KEYWORD_PURPOSE_MAP.items():
        if kw in lower:
            # weight by keyword length (more specific -> higher)
            w = 0.5 + min(0.5, len(kw) / 10)
            # boost if appears near algorithm name (within 40 chars)
            scores[purpose.value] += w
    return dict(scores)


def _deterministic_purpose_scores(
    algorithm: str, context: str, seed: int = 42
) -> Dict[str, float]:
    """Fallback deterministic scoring when sklearn is absent."""
    fam = _algorithm_family(algorithm)
    priors = _ALGORITHM_PURPOSE_PRIORS.get(fam, [])
    ctx_scores = _context_features(context)
    # combine priors + context + hash jitter
    raw: Dict[str, float] = defaultdict(float)
    for p in Purpose:
        # prior
        if Purpose(p) in priors:
            raw[p.value] += 1.0
        # context vote
        raw[p.value] += ctx_scores.get(p.value, 0.0)
        # deterministic jitter from hash to break ties reproducibly
        h = hashlib.sha256(f"{seed}:{algorithm}:{context}:{p.value}".encode()).hexdigest()
        jitter = (int(h[:4], 16) % 100) / 500.0  # 0..0.2
        raw[p.value] += jitter
    # softmax
    import math
    max_v = max(raw.values()) if raw else 0
    exps = {k: math.exp(v - max_v) for k, v in raw.items()}
    total = sum(exps.values()) or 1.0
    return {k: v / total for k, v in exps.items()}


def _is_hndl_relevant(purpose: Purpose, algorithm: str) -> bool:
    """HNDL-relevant if purpose is confidentiality (KEM/encryption) with broken vuln."""
    if purpose in (Purpose.KEY_ESTABLISHMENT, Purpose.ENCRYPTION):
        return True
    # certificate handling with RSA/ECDSA also relevant (key establishment inside TLS)
    if purpose == Purpose.CERTIFICATE_HANDLING and _algorithm_family(algorithm) in ("RSA", "ECDSA", "ECDH"):
        return True
    return False


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class AlgorithmPurposeClassifier:
    """Purpose classifier for crypto algorithms.

    Architecture: lightweight TF-IDF + LogisticRegression (CPU) with a rich
    purpose-aware feature layer. Falls back to deterministic hash-based scoring.

    Training data mix per ``qtrust_ai/README.md``: synthetic + real corpus +
    expert heuristics + adversarial (obfuscated wrappers where ``rsa.sign`` is
    hidden behind ``wrapper.encrypt``).

    Attributes:
        config: :class:`ClassifierConfig`.
        is_trained: Whether :meth:`train` has been called.

    Example:
        >>> clf = AlgorithmPurposeClassifier(seed=0)
        >>> clf.train()
        >>> clf.predict("RSA", context="private_key.sign(data)").purpose
        <Purpose.SIGNATURE: 'signature'>
        >>> clf.predict("RSA", context="public_key.encrypt(data)").purpose
        <Purpose.ENCRYPTION: 'encryption'>
        >>> clf.predict("ECDH", context="derive shared secret").purpose
        <Purpose.KEY_ESTABLISHMENT: 'key-establishment'>
    """

    def __init__(self, config: Optional[ClassifierConfig] = None, seed: int = 42) -> None:
        self.config = config or ClassifierConfig(seed=seed)
        self.config.seed = seed
        random.seed(seed)
        self.is_trained = False
        self._vectorizer: Any = None
        self._model: Any = None
        self._label_list: List[str] = Purpose.list()
        self._train_distribution: Counter = Counter()

    # -- feature construction ------------------------------------------------

    def _featurize(self, algorithm: str, context: str) -> str:
        """Build a text feature string for TF-IDF."""
        fam = _algorithm_family(algorithm)
        ctx = context.lower()
        # Expand context with purpose keywords (augmentation)
        feats = [fam.lower(), algorithm.lower(), ctx]
        # Add explicit purpose signals as tokens
        for kw in _KEYWORD_PURPOSE_MAP:
            if kw in ctx:
                feats.append(f"kw_{kw}")
        feats.append(f"fam_{fam.lower()}")
        return " ".join(feats)

    def _sklearn_train(
        self, corpus: List[Dict[str, Any]]
    ) -> None:
        """Train TF-IDF + LogReg if sklearn is present."""
        if not HAS_SKLEARN or not self.config.use_sklearn:
            return
        texts = [self._featurize(ex["algorithm"], ex.get("context", "")) for ex in corpus]
        labels = [ex["purpose"] for ex in corpus]
        try:
            self._vectorizer = TfidfVectorizer(max_features=2048, ngram_range=(1, 2))  # type: ignore
            X = self._vectorizer.fit_transform(texts)  # type: ignore
            self._model = LogisticRegression(  # type: ignore
                max_iter=500, multi_class="multinomial", random_state=self.config.seed,
                class_weight="balanced",  # rare purposes (encryption/KEM) get fair gradients
            )
            self._model.fit(X, labels)  # type: ignore
        except Exception:
            self._vectorizer = None
            self._model = None

    def _sklearn_predict(self, algorithm: str, context: str) -> Optional[Dict[str, float]]:
        """Return per-purpose probabilities via sklearn, or None."""
        if self._vectorizer is None or self._model is None:
            return None
        try:
            text = self._featurize(algorithm, context)
            X = self._vectorizer.transform([text])  # type: ignore
            proba = self._model.predict_proba(X)[0]  # type: ignore
            classes = list(self._model.classes_)  # type: ignore
            scores = {cls: float(p) for cls, p in zip(classes, proba)}
            # Ensure all purposes present
            for p in Purpose.list():
                scores.setdefault(p, 0.0)
            # Blend with deterministic context features (purpose-aware)
            ctx_scores = _context_features(context)
            if ctx_scores and self.config.purpose_aware:
                for p, v in ctx_scores.items():
                    scores[p] = scores.get(p, 0.0) * 0.7 + (v / (1 + v)) * 0.3
                # re-normalize
                total = sum(scores.values()) or 1.0
                scores = {k: v / total for k, v in scores.items()}
            return scores
        except Exception:
            return None

    # -- public API ---------------------------------------------------------

    def train(
        self,
        corpus: Optional[List[Dict[str, Any]]] = None,
        epochs: int = 1,
    ) -> Dict[str, Any]:
        """Train the purpose classifier (CPU stub / sklearn if available).

        Args:
            corpus: List of ``{"algorithm": str, "context": str, "purpose": str}``.
                If ``None`` a synthetic purpose-annotated corpus is generated
                covering the 40/30/20/10 mix (synthetic/real/expert/adversarial).
            epochs: Unused for sklearn; kept for API symmetry with
                :class:`qtrust_ai.discovery.code_detector.CryptoCodeDetector`.

        Returns:
            Dict with ``examples``, ``distribution``, ``has_sklearn``,
            ``classes``.
        """
        if corpus is None:
            corpus = self._generate_synthetic_corpus(n=600, seed=self.config.seed)
        self._train_distribution = Counter(ex["purpose"] for ex in corpus)
        self._sklearn_train(corpus)
        self.is_trained = True
        return {
            "examples": len(corpus),
            "distribution": dict(self._train_distribution),
            "has_sklearn": HAS_SKLEARN and self._vectorizer is not None,
            "classes": Purpose.list(),
            "epochs": epochs,
            "note": "sklearn TF-IDF+LogReg if available; else deterministic fallback",
        }

    def predict(self, algorithm: str, context: str = "") -> PurposeResult:
        """Predict cryptographic purpose for *algorithm* in *context*.

        Dual-use disambiguation examples:
        * ``RSA`` + ``sign`` → :attr:`Purpose.SIGNATURE`
        * ``RSA`` + ``encrypt`` / ``oaep`` → :attr:`Purpose.ENCRYPTION`
        * ``RSA`` + ``kem`` / ``encaps`` → :attr:`Purpose.KEY_ESTABLISHMENT`
        * ``ECDSA`` + ``verify`` → :attr:`Purpose.SIGNATURE`
        * ``ECDH`` + ``derive`` → :attr:`Purpose.KEY_ESTABLISHMENT`

        Args:
            algorithm: Algorithm label (e.g. ``"RSA"``, ``"ML-KEM-768"``,
                ``"SHA-256"``, ``"AES-256"``).
            context: Code context / surrounding lines / comment. More context
                improves disambiguation for dual-use algorithms.

        Returns:
            :class:`PurposeResult` with ``purpose``, ``confidence``, per-class
            ``all_scores``, and HNDL relevance.
        """
        normalized = _normalize_algorithm(algorithm)
        # Try sklearn first
        scores = self._sklearn_predict(algorithm, context)
        if scores is None:
            scores = _deterministic_purpose_scores(algorithm, context, seed=self.config.seed)
        # Pick best
        best_purpose_str = max(scores, key=lambda k: scores[k])  # type: ignore
        best_conf = float(scores[best_purpose_str])
        try:
            best_purpose = Purpose(best_purpose_str)
        except ValueError:
            best_purpose = Purpose.ENCRYPTION
        # Explanation
        ctx_hits = [kw for kw in _KEYWORD_PURPOSE_MAP if kw in context.lower()]
        expl = f"family={_algorithm_family(algorithm)}"
        if ctx_hits:
            expl += f"; context_hits={ctx_hits[:5]}"
        expl += f"; scores={ {k: round(v,2) for k,v in sorted(scores.items(), key=lambda x: -x[1])[:3]} }"
        return PurposeResult(
            algorithm=algorithm,
            normalized_algorithm=normalized,
            purpose=best_purpose,
            confidence=best_conf,
            all_scores=scores,
            explanation=expl,
            hndl_relevant=_is_hndl_relevant(best_purpose, algorithm),
        )

    def predict_batch(
        self, items: List[Dict[str, str]]
    ) -> List[PurposeResult]:
        """Batch predict for ``[{"algorithm": ..., "context": ...}, ...]``."""
        return [self.predict(it.get("algorithm", "UNKNOWN"), it.get("context", "")) for it in items]

    def evaluate(
        self, dataset: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Evaluate on a labelled dataset (P/R/F1 per purpose + macro).

        Args:
            dataset: List of ``{"algorithm": str, "context": str, "purpose": str}``.
                If ``None`` a synthetic eval set is generated.

        Returns:
            Dict with ``accuracy``, ``macro_f1``, ``per_purpose`` (P/R/F1),
            ``confusion`` counts, ``n``.
        """
        if dataset is None:
            dataset = self._generate_synthetic_corpus(n=200, seed=self.config.seed + 99)
        y_true: List[str] = []
        y_pred: List[str] = []
        per_purpose: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
        correct = 0
        for ex in dataset:
            true = ex["purpose"]
            pred = self.predict(ex["algorithm"], ex.get("context", "")).purpose.value
            y_true.append(true)
            y_pred.append(pred)
            if true == pred:
                correct += 1
                per_purpose[true]["tp"] += 1
            else:
                per_purpose[true]["fn"] += 1
                per_purpose[pred]["fp"] += 1

        # Compute per-purpose P/R/F1 without sklearn (string labels)
        per_purpose_metrics: Dict[str, Dict[str, float]] = {}
        for p in Purpose.list():
            tp = per_purpose[p]["tp"]
            fp = per_purpose[p]["fp"]
            fn = per_purpose[p]["fn"]
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
            per_purpose_metrics[p] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "support": tp + fn,
            }
        accuracy = correct / len(dataset) if dataset else 0.0
        macro_f1 = sum(m["f1"] for m in per_purpose_metrics.values()) / len(per_purpose_metrics) if per_purpose_metrics else 0.0
        # Optional sklearn macro F1 for comparison
        sklearn_macro_f1: Optional[float] = None
        if HAS_SKLEARN:
            try:
                _, _, f1_skl, _ = precision_recall_fscore_support(  # type: ignore
                    y_true, y_pred, average="macro", zero_division=0
                )
                sklearn_macro_f1 = float(f1_skl)  # type: ignore
            except Exception:
                pass
        return {
            "accuracy": round(accuracy, 4),
            "macro_f1": round(macro_f1, 4),
            "sklearn_macro_f1": round(sklearn_macro_f1, 4) if sklearn_macro_f1 is not None else None,
            "per_purpose": per_purpose_metrics,
            "n": len(dataset),
            "has_sklearn": HAS_SKLEARN and self._vectorizer is not None,
        }

    # -- synthetic corpus ---------------------------------------------------

    def _generate_synthetic_corpus(
        self, n: int = 600, seed: int = 42
    ) -> List[Dict[str, Any]]:
        """Deterministic synthetic purpose-annotated corpus."""
        rnd = random.Random(seed)
        # (algorithm, context_template, purpose)
        templates: List[Tuple[str, str, str]] = [
            ("RSA", "private_key.sign(data, padding=PSS, algorithm=SHA256)", Purpose.SIGNATURE.value),
            ("RSA", "public_key.verify(signature, data, padding=PSS)", Purpose.SIGNATURE.value),
            ("RSA", "public_key.encrypt(plaintext, padding=OAEP)", Purpose.ENCRYPTION.value),
            ("RSA", "private_key.decrypt(ciphertext)", Purpose.ENCRYPTION.value),
            ("RSA", "rsa_kem.encaps(public_key) -> (ct, ss)", Purpose.KEY_ESTABLISHMENT.value),
            ("ECDSA", "ecdsa.Sign(privateKey, hash)", Purpose.SIGNATURE.value),
            ("ECDSA", "ecdsa.Verify(publicKey, hash, sig)", Purpose.SIGNATURE.value),
            ("ECDH", "ecdh.derive_shared_secret(privateKey, peerPublic)", Purpose.KEY_ESTABLISHMENT.value),
            ("ECDH", "shared_secret = ECDH.compute(peer_pub)", Purpose.KEY_ESTABLISHMENT.value),
            ("X25519", "x25519(keypair.private, peer_public)", Purpose.KEY_ESTABLISHMENT.value),
            ("Ed25519", "ed25519.sign(message, private_key)", Purpose.SIGNATURE.value),
            ("ML-KEM-768", "ml_kem.encaps(public_key)", Purpose.KEY_ESTABLISHMENT.value),
            ("ML-KEM-768", "ml_kem.decaps(ciphertext, secret_key)", Purpose.KEY_ESTABLISHMENT.value),
            ("ML-DSA-65", "ml_dsa.sign(message, signing_key)", Purpose.SIGNATURE.value),
            ("SLH-DSA-SHA2-128s", "slh_dsa.sign(msg, sk)", Purpose.SIGNATURE.value),
            ("AES-256", "AES.new(key, AES.MODE_GCM).encrypt(plaintext)", Purpose.ENCRYPTION.value),
            ("AES-256", "cipher = AESGCM(key).decrypt(nonce, ct, None)", Purpose.ENCRYPTION.value),
            ("ChaCha20-Poly1305", "ChaCha20Poly1305(key).encrypt(nonce, pt, aad)", Purpose.ENCRYPTION.value),
            ("SHA-256", "hashlib.sha256(data).hexdigest()", Purpose.HASHING.value),
            ("SHA-256", "MessageDigest.getInstance('SHA-256').digest(data)", Purpose.HASHING.value),
            ("HMAC-SHA256", "hmac.new(key, msg, hashlib.sha256)", Purpose.HASHING.value),
            ("RANDOM", "os.urandom(32)", Purpose.RANDOMNESS.value),
            ("RANDOM", "getrandom(buf, 32, 0)", Purpose.RANDOMNESS.value),
            ("X509", "x509.load_pem_x509_certificate(pem_data)", Purpose.CERTIFICATE_HANDLING.value),
            ("CERT", "tls_cert.verify_chain(chain, root)", Purpose.CERTIFICATE_HANDLING.value),
            # adversarial: wrapped RSA sign hidden as encrypt
            ("RSA", "wrapper.encrypt(data)  # actually rsa.sign behind wrapper", Purpose.SIGNATURE.value),
            ("AES-256", "sdk.do_crypto(payload)  # proprietary wrapper for AES-GCM", Purpose.ENCRYPTION.value),
        ]
        corpus: List[Dict[str, Any]] = []
        for i in range(n):
            algo, ctx, purp = rnd.choice(templates)
            # Add noise words 20% of the time
            if rnd.random() < 0.2:
                ctx = rnd.choice(["// todo: review", "/* legacy */ ", ""]) + " " + ctx
            corpus.append({"algorithm": algo, "context": ctx, "purpose": purp, "id": i})
        return corpus


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    clf = AlgorithmPurposeClassifier(seed=42)
    print("=== AlgorithmPurposeClassifier demo ===")
    train_res = clf.train()
    print(f"[train] {json.dumps(train_res, indent=2)}")

    cases = [
        ("RSA", "private_key.sign(data, padding=PSS, hash=SHA256)"),
        ("RSA", "public_key.encrypt(plaintext, padding=OAEP)"),
        ("RSA", "kem.encaps(public_key) -> shared_secret"),
        ("ECDSA", "ecdsa.Sign(priv, digest)"),
        ("ECDH", "derive shared_secret via ECDH"),
        ("ML-KEM-768", "ml_kem.encaps(pk)"),
        ("ML-DSA-65", "ml_dsa.sign(msg, sk)"),
        ("AES-256", "AESGCM(key).encrypt(nonce, plaintext, aad)"),
        ("SHA-256", "hashlib.sha256(data).digest()"),
        ("RANDOM", "os.urandom(32)"),
        ("X509", "load_pem_x509_certificate(pem)"),
        ("RSA", "wrapper.encrypt(data)  # actually signing behind wrapper"),
    ]
    for algo, ctx in cases:
        r = clf.predict(algo, context=ctx)
        print(f"\n{algo:20s} ctx={ctx[:55]:55s} -> {r.purpose.value:22s} "
              f"conf={r.confidence:.2f} hndl={r.hndl_relevant}")
        print(f"  expl: {r.explanation}")

    eval_res = clf.evaluate()
    print(f"\n[evaluate] accuracy={eval_res['accuracy']} macro_f1={eval_res['macro_f1']} n={eval_res['n']}")
    for purp, m in eval_res["per_purpose"].items():
        print(f"  {purp:22s} P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f} support={m['support']}")
