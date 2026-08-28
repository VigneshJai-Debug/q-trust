"""
qtrust_ai.discovery — Discovery AI package.

Phase 1 Foundation per ``qtrust_ai/README.md`` § Phase 1:

* :mod:`qtrust_ai.discovery.code_detector` — CryptoCodeBERT / CryptoTransformer
  code model (``CryptoCodeDetector``): AST + data-flow + ML ensemble for
  crypto / non-crypto → algorithm / purpose classification across 12 languages
  with obfuscated / wrapped handling.
* :mod:`qtrust_ai.discovery.algorithm_classifier` — purpose classifier
  (key-establishment, signature, encryption, hashing, randomness, certificate
  handling) with RSA/ECDSA → signature vs KEM disambiguation.

See ``qtrust_ai/README.md`` for the 32-point transformation and training order
(Phase1 1-4 → Phase2 → …). All models are CPU-friendly with deterministic
fallbacks when ``torch`` / ``transformers`` / ``sklearn`` are absent.

NIST alignment: comprehensive inventory/discovery [NIST NCCoE PQC migration].

Usage::

    from qtrust_ai.discovery.code_detector import CryptoCodeDetector
    from qtrust_ai.discovery.algorithm_classifier import AlgorithmPurposeClassifier

    det = CryptoCodeDetector()
    findings = det.scan_repo("./src")
    clf = AlgorithmPurposeClassifier()
    purpose = clf.predict("RSA", context="signing X.509 cert")
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from .code_detector import CryptoCodeDetector, CryptoFinding, DetectionResult
except ImportError:  # pragma: no cover
    CryptoCodeDetector = None  # type: ignore
    CryptoFinding = None  # type: ignore
    DetectionResult = None  # type: ignore

try:
    from .algorithm_classifier import AlgorithmPurposeClassifier, Purpose, PurposeResult
except ImportError:  # pragma: no cover
    AlgorithmPurposeClassifier = None  # type: ignore
    Purpose = None  # type: ignore
    PurposeResult = None  # type: ignore

__all__ = [
    "CryptoCodeDetector",
    "CryptoFinding",
    "DetectionResult",
    "AlgorithmPurposeClassifier",
    "Purpose",
    "PurposeResult",
]

__version__: str = "1.0.0-discovery"
SUPPORTED_LANGUAGES: List[str] = [
    "python", "java", "c", "cpp", "rust", "go",
    "javascript", "typescript", "csharp", "kotlin",
    "swift", "php", "solidity", "shell",
]

@dataclass
class DiscoveryStats:
    """Aggregated stats for a discovery run."""

    files_scanned: int = 0
    findings: int = 0
    crypto_files: int = 0
    languages: Dict[str, int] = None  # type: ignore
    algorithms: Dict[str, int] = None  # type: ignore

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "findings": self.findings,
            "crypto_files": self.crypto_files,
            "languages": self.languages or {},
            "algorithms": self.algorithms or {},
        }


def get_discovery_info() -> Dict[str, Any]:
    """Return package metadata for health checks / benchmarking."""
    return {
        "package": "qtrust_ai.discovery",
        "version": __version__,
        "phase": "1 Foundation",
        "models": ["CryptoCodeDetector (CryptoCodeBERT)", "AlgorithmPurposeClassifier"],
        "languages": SUPPORTED_LANGUAGES,
        "architecture_doc": "qtrust_ai/README.md",
        "has_detector": CryptoCodeDetector is not None,
        "has_classifier": AlgorithmPurposeClassifier is not None,
    }


if __name__ == "__main__":
    print("=== qtrust_ai.discovery package demo ===")
    print(json.dumps(get_discovery_info(), indent=2))
    # Quick end-to-end demo if models are importable
    if CryptoCodeDetector is not None:
        det = CryptoCodeDetector(seed=42)  # type: ignore
        snippet = "import hashlib; hashlib.sha256(b'demo')"
        res = det.predict(snippet, language="python")  # type: ignore
        print(f"\n[CryptoCodeDetector] snippet -> is_crypto={res.is_crypto} algo={res.algorithm} conf={res.confidence:.2f}")
        print(f"  explanation: {res.explanation}")
    if AlgorithmPurposeClassifier is not None:
        clf = AlgorithmPurposeClassifier(seed=42)  # type: ignore
        clf.train()  # type: ignore
        for algo, ctx in [("RSA", "private_key.sign(data)"), ("ECDH", "derive shared secret"), ("AES-256", "encrypt plaintext")]:
            pr = clf.predict(algo, context=ctx)  # type: ignore
            print(f"[AlgorithmPurposeClassifier] {algo:12s} ctx={ctx:25s} -> {pr.purpose.value} conf={pr.confidence:.2f}")
