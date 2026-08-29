"""
CryptoCodeBERT / CryptoTransformer — code model for crypto discovery.

Architecture reference: ``qtrust_ai/README.md`` Phase 1 Foundation.

This module implements ``CryptoCodeDetector`` as described in the spec:

* **Static rules** — regex / keyword heuristics per language.
* **AST analysis** — Python ``ast`` + approximate AST for other languages.
* **Data-flow** — taint tracking of crypto objects through assignments / wrappers.
* **ML code model** — ``CryptoCodeBERT`` / ``CryptoTransformer`` stub that
  falls back deterministically when ``torch``/``transformers`` are absent.
* **Ensemble** — weighted voting (static 0.3 + AST 0.3 + data-flow 0.2 + ML 0.2),
  with static-rule hits decisive: the trusted deterministic layer cannot be
  vetoed by the ML fallback.

Covers 12 languages: Python, Java, C/C++, Rust, Go, JS/TS, C#, Kotlin, Swift,
PHP, Solidity, shell. Handles obfuscated / wrapped / renamed / proprietary SDK
cases that defeat pure rules (see ``benchmark/dataset.py`` adversarial 10%).

All methods are CPU-friendly, deterministic (seeded), and importable without
GPU or heavy deps.

NIST alignment: comprehensive inventory/discovery [NIST NCCoE PQC migration].

Example:
    detector = CryptoCodeDetector()
    findings = detector.scan_file("example.py")
    results = detector.predict("RSA_sign(data, key)", language="python")
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional heavy deps — deterministic fallbacks when absent
# ---------------------------------------------------------------------------
try:
    import torch  # type: ignore
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    torch = None  # type: ignore

try:
    from transformers import AutoTokenizer, AutoModel  # type: ignore
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False
    AutoTokenizer = None  # type: ignore
    AutoModel = None  # type: ignore

try:
    from sklearn.metrics import accuracy_score  # type: ignore
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SUPPORTED_LANGUAGES: List[str] = [
    "python", "java", "c", "cpp", "c/c++", "rust", "go",
    "javascript", "typescript", "js", "ts", "csharp", "c#",
    "kotlin", "swift", "php", "solidity", "shell", "bash", "sh",
]

# Normalise language aliases -> canonical
_LANGUAGE_ALIASES: Dict[str, str] = {
    "c++": "cpp", "c/c++": "cpp", "js": "javascript", "ts": "typescript",
    "c#": "csharp", "csharp": "csharp", "sh": "shell", "bash": "shell",
    "py": "python",
}

ALGORITHM_LABELS: List[str] = [
    "RSA", "ECDSA", "ECDH", "DSA", "DH", "Ed25519", "Ed448", "X25519", "X448",
    "AES-128", "AES-256", "ChaCha20-Poly1305", "3DES", "DES",
    "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "MD5",
    "HMAC-SHA256", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128s", "HQC-128", "UNKNOWN",
]

# File extensions -> language
_EXTENSION_MAP: Dict[str, str] = {
    ".py": "python", ".java": "java", ".c": "c", ".h": "c", ".cpp": "cpp",
    ".cc": "cpp", ".hpp": "cpp", ".rs": "rust", ".go": "go",
    ".js": "javascript", ".ts": "typescript", ".cs": "csharp",
    ".kt": "kotlin", ".swift": "swift", ".php": "php", ".sol": "solidity",
    ".sh": "shell", ".bash": "shell",
}

# ---------------------------------------------------------------------------
# Regex patterns per language — static rules layer
# ---------------------------------------------------------------------------
# Each entry: list of (pattern, algorithm_hint)
STATIC_PATTERNS: Dict[str, List[Tuple[str, str]]] = {
    "python": [
        (r"from\s+cryptography", "RSA"),
        (r"_lib\.(RSA|EVP|X509|EC_KEY|HMAC|BN_|ASN1_|BIO_)\w*", "RSA"),
        (r"#include\s*<openssl/", "RSA"),
        (r"import\s+hashlib", "SHA-256"),
        (r"hashlib\.(sha256|sha512|md5)", "HASH"),
        (r"Crypto\.Cipher\.(AES|DES|ChaCha20)", "AES-256"),
        (r"rsa\.(generate|encrypt|decrypt|sign|verify)", "RSA"),
        (r"ecdsa\.", "ECDSA"),
        (r"ecdh\.", "ECDH"),
        (r"nacl\.", "Ed25519"),
        (r"fips.*aes|AES", "AES-256"),
        (r"hmac\.", "HMAC-SHA256"),
        (r"ml_kem|ML_KEM|kyber", "ML-KEM-768"),
        (r"ml_dsa|dilithium", "ML-DSA-65"),
    ],
    "java": [
        (r"javax\.crypto", "AES-256"),
        (r"java\.security\.(MessageDigest|Signature|KeyPairGenerator)", "RSA"),
        (r"Cipher\.getInstance\(\s*\"AES", "AES-256"),
        (r"Cipher\.getInstance\(\s*\"RSA", "RSA"),
        (r"Signature\.getInstance\(\s*\"SHA.*ECDSA", "ECDSA"),
        (r"KeyPairGenerator\.getInstance\(\s*\"(RSA|EC)", "RSA"),
        (r"BouncyCastle|BC", "RSA"),
        (r"MessageDigest\.getInstance\(\s*\"SHA-256", "SHA-256"),
    ],
    "cpp": [
        (r"EVP_(Encrypt|Decrypt|Digest|PKEY)", "AES-256"),
        (r"RSA_(generate|encrypt|decrypt|sign)", "RSA"),
        (r"EC_KEY_new|ECDSA_sign|ECDH_compute", "ECDSA"),
        (r"AES_set_encrypt_key|AES_encrypt", "AES-256"),
        (r"SHA256|SHA384|SHA512", "SHA-256"),
        (r"libsodium|sodium_", "Ed25519"),
        (r"mbedtls_", "RSA"),
    ],
    "c": [
        (r"EVP_(Encrypt|Decrypt|Digest|PKEY)", "AES-256"),
        (r"RSA_", "RSA"),
        (r"EC_KEY|ECDSA|ECDH", "ECDSA"),
        (r"crypto_[a-z0-9_]+", "LIBSODIUM"),
        (r"sodium_(init|crypto|malloc|free)", "Ed25519"),
        (r"\bOQS_[A-Z0-9_]+", "PQC"),
        (r"\b(kyber|dilithium|ml-kem|ml-dsa|sphincs|falcon|hqc)\b", "PQC"),
        (r"SHA256|MD5", "SHA-256"),
    ],
    "rust": [
        (r"use\s+ring::", "SHA-256"),
        (r"use\s+rustls", "RSA"),
        (r"openssl::(rsa|ec|hash|symm)", "RSA"),
        (r"aes_gcm|chacha20", "AES-256"),
        (r"ed25519_dalek", "Ed25519"),
        (r"pqcrypto\-(kyber|dilithium|sphincs)", "ML-KEM-768"),
        (r"aws_lc_rs|aws-lc-rs", "RSA"),
        (r"openssl::[a-z0-9_]+", "RSA"),
        (r"\b(pkcs12|pkcs7|ocsp|crl|x509)\b", "CERT"),
        (r"webpki|zeroize|subtle::", "CERT"),
    ],
    "go": [
        (r"crypto/(rsa|ecdsa|ecdh|ed25519|elliptic)", "RSA"),
        (r"crypto/(aes|cipher|chacha20poly1305)", "AES-256"),
        (r"crypto/(sha1|sha256|sha384|sha512|sha3|md5)", "SHA-256"),
        (r"crypto/(hmac|subtle)", "HMAC-SHA256"),
        (r"crypto/(rand|x509)", "CERT"),
        (r"golang\.org/x/crypto", "Ed25519"),
        (r"crypto/tls", "RSA"),
        (r"cipher\.NewGCM", "AES-256"),
        (r"circl/(kem|pke)", "ML-KEM-768"),
        (r"circl/sign", "ML-DSA-65"),
        (r"\b(kyber|dilithium|sphincs|falcon|ml-kem|ml-dsa|hqc)\b", "PQC"),
        (r"\b(sha3|sha256|sha512|sha1|md5)\b", "SHA-256"),
    ],
    "javascript": [
        (r"require\(\s*['\"]crypto['\"]\)", "AES-256"),
        (r"crypto\.(createCipher|createHash|subtle)", "SHA-256"),
        (r"subtle\.(encrypt|decrypt|sign|verify|digest)", "RSA"),
        (r"ethers\.(utils|Wallet)", "ECDSA"),
        (r"tweetnacl|nacl\.", "Ed25519"),
        (r"node:crypto", "AES-256"),
        (r"\bsjcl\b", "AES-256"),
    ],
    "typescript": [
        (r"from\s+['\"]crypto['\"]", "AES-256"),
        (r"crypto\.(createCipher|subtle)", "SHA-256"),
        (r"subtle\.", "RSA"),
    ],
    "csharp": [
        (r"System\.Security\.Cryptography", "RSA"),
        (r"AesManaged|RSA signing|ECDsa", "AES-256"),
        (r"BouncyCastle", "RSA"),
        (r"SHA256Managed|SHA512", "SHA-256"),
    ],
    "kotlin": [
        (r"javax\.crypto|java\.security", "RSA"),
        (r"Cipher\.getInstance", "AES-256"),
        (r"MessageDigest", "SHA-256"),
    ],
    "swift": [
        (r"import\s+CryptoKit", "SHA-256"),
        (r"import\s+Security", "RSA"),
        (r"P256|P384|Curve25519", "ECDSA"),
        (r"AES\.GCM|ChaChaPoly", "AES-256"),
        (r"\bAES\(", "AES-256"),
        (r"\b(ChaCha20|Poly1305|Rabbit|Blowfish|RC4)\b", "ChaCha20-Poly1305"),
        (r"\b(CBC|GCM|CCM|XTS)\b", "AES-256"),
        (r"\bDigest\b", "SHA-256"),
        (r"\bHMAC\b", "HMAC-SHA256"),
        (r"\b(SHA1|SHA256|SHA384|SHA512|MD5)\b", "SHA-256"),
    ],
    "php": [
        (r"openssl_(encrypt|decrypt|sign|verify|pkey|public|private|seal|open|error)", "RSA"),
        (r"\bopenssl_[a-z_]+", "RSA"),
        (r"sodium_crypto", "Ed25519"),
        (r"hash\(\s*['\"]sha256", "SHA-256"),
        (r"\brsa\b", "RSA"),
        (r"\bdes(-ede3|-ede|-cbc|-ecb)?\b", "DES"),
        (r"\b(sha1|sha256|sha384|sha512|md5|hmac)\b", "SHA-256"),
        (r"\b(aes|chacha20|blowfish|twofish)\b", "AES-256"),
        (r"\b(ml-kem|mlkem|ml-dsa|kyber|dilithium|sphincs)\b", "PQC"),
    ],
    "solidity": [
        (r"ecrecover\(", "ECDSA"),
        (r"\bECDSA\.\w+", "ECDSA"),
        (r"\bMessageHashUtils\.", "ECDSA"),
        (r"isValidSignature", "ECDSA"),
        (r"eip712Domain|_hashTypedData|_domainSeparatorV4", "SHA3-256"),
        (r"keccak256\(", "SHA3-256"),
        (r"sha256\(", "SHA-256"),
        (r"ripemd160", "HASH"),
    ],
    "shell": [
        (r"openssl\s+(enc|dgst|req|genrsa|ecparam)", "RSA"),
        (r"gpg\s+--", "RSA"),
        (r"ssh-keygen", "RSA"),
        (r"hashcat|sha256sum|md5sum", "SHA-256"),
    ],
}

# Obfuscated / wrapped indicators
OBFUSCATION_PATTERNS: List[Tuple[str, str]] = [
    (r"base64\.(b64decode|decode)", "base64_obfuscation"),
    (r"eval\s*\(", "dynamic_eval"),
    (r"exec\s*\(", "dynamic_exec"),
    (r"__import__\s*\(", "dynamic_import"),
    (r"getattr\s*\(.*crypto", "reflection"),
    (r"from\s+.*import\s+\*\s", "wildcard_import"),
    (r"chr\s*\(\s*\d+\s*\)", "char_obfuscation"),
    (r"\\x[0-9a-fA-F]{2}", "hex_obfuscation"),
    (r"wrapper|Wrapper|WRAPPER", "wrapper_class"),
    (r"proprietary|Proprietary|SDK|sdk", "proprietary_sdk"),
    (r"ctypes|ffi|cffi", "ffi_wrapper"),
]

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CryptoFinding:
    """Single crypto finding from source scan.

    Attributes:
        file: Source file path (or '<snippet>' for inline predict).
        line: 1-based line number.
        language: Canonical language key.
        algorithm: Detected algorithm label (e.g. 'RSA', 'SHA-256').
        category: 'crypto' | 'non-crypto'.
        confidence: Ensemble confidence in [0, 1].
        method: Which layer fired ('static', 'ast', 'dataflow', 'ml', 'ensemble').
        context: Code snippet / surrounding lines.
        obfuscated: Whether obfuscation indicators were present.
        purpose_hint: Optional purpose hint (e.g. 'signature', 'encryption').
    """

    file: str
    line: int
    language: str
    algorithm: str
    category: str = "crypto"
    confidence: float = 0.0
    method: str = "ensemble"
    context: str = ""
    obfuscated: bool = False
    purpose_hint: Optional[str] = None
    column: Optional[int] = None


@dataclass
class DetectionResult:
    """Result of :meth:`CryptoCodeDetector.predict` for a snippet."""

    is_crypto: bool
    algorithm: str
    confidence: float
    language: str
    findings: List[CryptoFinding] = field(default_factory=list)
    obfuscated: bool = False
    explanation: str = ""


@dataclass
class DetectorConfig:
    """Hyper-parameters for :class:`CryptoCodeDetector`."""

    model_name: str = "CryptoCodeBERT"
    use_transformer: bool = True
    static_weight: float = 0.30
    ast_weight: float = 0.30
    dataflow_weight: float = 0.20
    ml_weight: float = 0.20
    threshold: float = 0.5
    seed: int = 42
    max_file_size_bytes: int = 2_000_000
    context_lines: int = 2


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _canonical_language(lang: str) -> str:
    lang = lang.lower().strip()
    return _LANGUAGE_ALIASES.get(lang, lang)


def _detect_language_from_path(path: Path) -> str:
    ext = path.suffix.lower()
    return _EXTENSION_MAP.get(ext, "python")


def _deterministic_score(text: str, seed: int = 42) -> float:
    """Deterministic pseudo-ML score in [0,1] derived from hash."""
    h = hashlib.sha256(f"{seed}:{text}".encode()).hexdigest()
    # use first 8 hex chars -> int -> [0,1)
    val = int(h[:8], 16) / 0xFFFFFFFF
    # bias: crypto keywords push score up
    crypto_kw = ["encrypt", "decrypt", "sign", "verify", "hash", "cipher",
                 "rsa", "ecdsa", "aes", "hmac", "crypto", "key", "cert"]
    lower = text.lower()
    bonus = sum(0.07 for kw in crypto_kw if kw in lower)
    return min(1.0, val * 0.6 + bonus)


def _is_obfuscated(code: str) -> Tuple[bool, List[str]]:
    hits: List[str] = []
    for pat, label in OBFUSCATION_PATTERNS:
        if re.search(pat, code):
            hits.append(label)
    return (len(hits) > 0, hits)


def _precision_recall_f1_fallback(
    y_true: List[int], y_pred: List[int]
) -> Tuple[float, float, float]:
    """Compute P/R/F1 without sklearn."""
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

class CryptoCodeDetector:
    """CryptoCodeBERT / CryptoTransformer ensemble detector.

    Implements the Phase 1 Discovery AI described in ``qtrust_ai/README.md``:

    * Multi-language static rules + AST + data-flow + ML ensemble.
    * Two-stage classification: crypto / non-crypto → algorithm / purpose.
    * Adversarial robustness: explicit obfuscated / wrapped / renamed detection.

    The ML layer (``CryptoCodeBERT``) is a fine-tuned code transformer. When
    ``torch``/``transformers`` are unavailable the detector falls back to a
    deterministic hash-based pseudo-model so that ``train``/``predict``/
    ``evaluate`` remain importable and testable on CPU-only CI.

    Args:
        config: Detector hyper-parameters. If ``None`` defaults are used.
        model_name: Override for ``config.model_name`` (``CryptoCodeBERT``
            or ``CryptoTransformer``).
        seed: Random seed for determinism.

    Example:
        >>> det = CryptoCodeDetector(seed=0)
        >>> r = det.predict("import hashlib; hashlib.sha256(b'hi')", language="python")
        >>> r.is_crypto
        True
    """

    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        model_name: Optional[str] = None,
        seed: int = 42,
    ) -> None:
        self.config = config or DetectorConfig()
        if model_name is not None:
            self.config.model_name = model_name
        self.config.seed = seed
        random.seed(seed)
        self._trained = False
        self._label_counts: Counter = Counter()
        self._ml_bias: Dict[str, float] = {}
        self._hf_model: Any = None
        self._hf_tokenizer: Any = None
        self._hf_device: Any = None
        self._hf_max_len: int = 256

    # -- internal layers ---------------------------------------------------

    def _static_layer(self, code: str, language: str) -> List[CryptoFinding]:
        """Apply regex static rules for *language*."""
        lang = _canonical_language(language)
        # map aliases like 'c' -> 'cpp' patterns
        patterns = STATIC_PATTERNS.get(lang, [])
        if not patterns and lang in ("c",):
            patterns = STATIC_PATTERNS.get("c", [])
        findings: List[CryptoFinding] = []
        obf, _ = _is_obfuscated(code)
        lines = code.splitlines()
        for idx, line in enumerate(lines, start=1):
            for pat, algo in patterns:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(CryptoFinding(
                        file="<snippet>",
                        line=idx,
                        language=lang,
                        algorithm=algo,
                        category="crypto",
                        confidence=0.85,
                        method="static",
                        context=line.strip()[:200],
                        obfuscated=obf,
                    ))
        return findings

    def _ast_layer(self, code: str, language: str) -> List[CryptoFinding]:
        """AST analysis.

        For Python we parse ``ast``; for other languages we do an approximate
        AST via brace / import scanning that still catches wrapped classes.
        """
        lang = _canonical_language(language)
        findings: List[CryptoFinding] = []
        obf, obf_hits = _is_obfuscated(code)
        if lang == "python":
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    # Import detection
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        names = []
                        if isinstance(node, ast.Import):
                            names = [a.name for a in node.names]
                        else:
                            names = [a.name for a in node.names] + [node.module or ""]
                        blob = " ".join(names).lower()
                        if any(kw in blob for kw in ("crypto", "hashlib", "rsa", "ecdsa", "nacl")):
                            findings.append(CryptoFinding(
                                file="<snippet>",
                                line=getattr(node, "lineno", 1),
                                language=lang,
                                algorithm="RSA" if "rsa" in blob else "SHA-256",
                                category="crypto",
                                confidence=0.80,
                                method="ast",
                                context=blob[:200],
                                obfuscated=obf,
                            ))
                    # Call detection
                    if isinstance(node, ast.Call):
                        func_name = ""
                        if isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        elif isinstance(node.func, ast.Name):
                            func_name = node.func.id
                        if func_name.lower() in ("encrypt", "decrypt", "sign", "verify", "hash", "digest"):
                            findings.append(CryptoFinding(
                                file="<snippet>",
                                line=getattr(node, "lineno", 1),
                                language=lang,
                                algorithm=func_name,
                                category="crypto",
                                confidence=0.75,
                                method="ast",
                                context=func_name,
                                obfuscated=obf,
                            ))
                    # Class wrapper detection
                    if isinstance(node, ast.ClassDef):
                        if any(kw in node.name.lower() for kw in ("crypto", "cipher", "wrapper", "sdk")):
                            findings.append(CryptoFinding(
                                file="<snippet>",
                                line=getattr(node, "lineno", 1),
                                language=lang,
                                algorithm="WRAPPER",
                                category="crypto",
                                confidence=0.60,
                                method="ast",
                                context=f"class {node.name}",
                                obfuscated=True,
                            ))
            except SyntaxError:
                pass
        else:
            # Approximate AST for non-Python: detect wrapper classes / obfuscation
            # via regex for class / function definitions containing crypto keywords.
            # NB: bare ``wrapper`` is excluded — ``Wrapper``/``wrapped`` are
            # common names in non-crypto code (e.g. gson's wrapper classes) and
            # would be a false-positive source. Only crypto-signalling names
            # count as class-level evidence.
            wrapper_pat = re.compile(
                r"(class|struct|interface|func|function)\s+\w*(crypto|cipher|sdk|ksm|kem)\w*",
                re.IGNORECASE,
            )
            for idx, line in enumerate(code.splitlines(), start=1):
                if wrapper_pat.search(line):
                    findings.append(CryptoFinding(
                        file="<snippet>",
                        line=idx,
                        language=lang,
                        algorithm="WRAPPER",
                        category="crypto",
                        confidence=0.55,
                        method="ast",
                        context=line.strip()[:200],
                        obfuscated=True,
                    ))
            # Obfuscation indicators are *amplifiers*, not detectors: they only
            # surface as findings when the file already shows real crypto
            # evidence. A lone base64/`eval`/`ffi` occurrence in non-crypto
            # code (JSON parsers, CLI tools) must not become a crypto finding.
            if obf and any(f.category == "crypto" for f in findings):
                for hit in obf_hits:
                    findings.append(CryptoFinding(
                        file="<snippet>",
                        line=1,
                        language=lang,
                        algorithm="OBFUSCATED",
                        category="crypto",
                        confidence=0.65,
                        method="ast",
                        context=hit,
                        obfuscated=True,
                    ))
        return findings

    def _dataflow_layer(self, code: str, language: str) -> List[CryptoFinding]:
        """Lightweight taint tracking: variable assigned from crypto API then reused."""
        lang = _canonical_language(language)
        findings: List[CryptoFinding] = []
        # Track assignments like:  x = Cipher.getInstance("AES")  or  key = rsa.generate(...)
        assign_pat = re.compile(
            r"(\w+)\s*=\s*.*(Cipher|KeyPair|hashlib|Crypto|rsa|ecdsa|hmac|crypto|subtle)",
            re.IGNORECASE,
        )
        tainted: Dict[str, int] = {}  # var -> line
        lines = code.splitlines()
        for idx, line in enumerate(lines, start=1):
            m = assign_pat.search(line)
            if m:
                var = m.group(1)
                tainted[var] = idx
            # Reuse of tainted variable
            for var, src_line in list(tainted.items()):
                if var in line and idx != src_line:
                    # avoid double-counting the assignment line itself
                    if re.search(rf"\b{re.escape(var)}\b\s*\.", line):
                        findings.append(CryptoFinding(
                            file="<snippet>",
                            line=idx,
                            language=lang,
                            algorithm="DATAFLOW",
                            category="crypto",
                            confidence=0.70,
                            method="dataflow",
                            context=line.strip()[:200],
                            obfuscated=False,
                        ))
                        break
        return findings

    def _ml_layer(self, code: str, language: str) -> Tuple[bool, str, float]:
        """ML code model — real fine-tuned transformer when available.

        Returns ``(is_crypto, algorithm, confidence)``. If a checkpoint was
        fine-tuned via :meth:`fine_tune`, a real forward pass runs on GPU/CPU.
        Otherwise a deterministic hash-based score is used.
        """
        if self._hf_model is not None and self._hf_tokenizer is not None:
            try:
                enc = self._hf_tokenizer(
                    code, truncation=True, max_length=self._hf_max_len, return_tensors="pt"
                )
                enc = {k: v.to(self._hf_device) for k, v in enc.items()}
                self._hf_model.eval()
                with torch.no_grad():
                    logits = self._hf_model(**enc).logits  # type: ignore
                    probs = torch.softmax(logits, dim=-1)[0]
                p_crypto = float(probs[1])
                is_crypto = p_crypto >= self.config.threshold
                algo = "UNKNOWN"
                if is_crypto:
                    if self._label_counts:
                        algo = self._label_counts.most_common(1)[0][0]
                    else:
                        algo = "AES-256"
                return is_crypto, algo, p_crypto
            except Exception:
                pass  # fall through to deterministic stub
        score = _deterministic_score(code, seed=self.config.seed)
        # Apply learned bias if train() was called
        bias = self._ml_bias.get(language, 0.0)
        score = max(0.0, min(1.0, score + bias))
        is_crypto = score >= self.config.threshold
        # Algorithm from most frequent training label or heuristic
        algo = "UNKNOWN"
        if is_crypto:
            if self._label_counts:
                algo = self._label_counts.most_common(1)[0][0]
            else:
                lower = code.lower()
                for cand in ["rsa", "ecdsa", "aes", "sha", "hmac", "ml-kem", "chacha"]:
                    if cand in lower:
                        algo = cand.upper()
                        break
                if algo == "UNKNOWN" and any(kw in lower for kw in ("cipher", "crypto", "hash")):
                    algo = "AES-256"
        return is_crypto, algo, score

    def _ensemble(
        self, code: str, language: str
    ) -> Tuple[bool, str, float, List[CryptoFinding]]:
        """Combine layers via weighted voting."""
        static = self._static_layer(code, language)
        ast_f = self._ast_layer(code, language)
        dflow = self._dataflow_layer(code, language)
        ml_is_crypto, ml_algo, ml_score = self._ml_layer(code, language)

        # Aggregate evidence
        cfg = self.config
        # layer presence as 0/1 * weight; the ML layer's weight is scaled by
        # its confidence so a *confident* learned signal carries proportional
        # weight rather than being capped at a flat 0.2 (which previously
        # discarded otherwise-decisive ML-only detections).
        w_static = cfg.static_weight if static else 0.0
        w_ast = cfg.ast_weight if ast_f else 0.0
        w_dflow = cfg.dataflow_weight if dflow else 0.0
        # ML confidence-scaled in [0, ml_weight]: low score -> low/no weight,
        # high score -> full ml_weight instead of a hard 0/1 gate.
        w_ml = cfg.ml_weight * ml_score

        total_positive_weight = w_static + w_ast + w_dflow + w_ml
        # Static rules are the trusted deterministic layer — a single real
        # crypto API/import hit is decisive evidence (ML can never veto it).
        # Without this, a lone import like ``crypto/rand`` (w_static 0.3 <
        # threshold 0.5) would be silently missed.
        is_crypto = total_positive_weight >= cfg.threshold or bool(static)

        # If any layer fired but ensemble below threshold, still flag if 2+ layers
        layers_fired = sum(bool(x) for x in [static, ast_f, dflow]) + (1 if ml_is_crypto else 0)
        if layers_fired >= 2:
            is_crypto = True

        # Decisive high-confidence ML hit: when the fine-tuned transformer is
        # confidently crypto AND *no* deterministic layer fired, the learned
        # signal alone should flag the file. This is what recovers obfuscated /
        # renamed / cross-language crypto that static+AST miss (and previously
        # fell through because a flat ml_weight < threshold). The high bar
        # (0.85) keeps precision: weak ML evidence never overrides the ensemble.
        if ml_is_crypto and not static and not ast_f and not dflow and ml_score >= 0.85:
            is_crypto = True

        # Choose algorithm: prefer static > ast > ml
        algo = "UNKNOWN"
        confidence = total_positive_weight  # already 0-1
        all_findings = static + ast_f + dflow
        if all_findings:
            # most common non-UNKNOWN/WRAPPER/DATAFLOW algorithm
            c = Counter(f.algorithm for f in all_findings if f.algorithm not in ("WRAPPER", "DATAFLOW", "OBFUSCATED"))
            if c:
                algo = c.most_common(1)[0][0]
            else:
                algo = all_findings[0].algorithm
        elif ml_is_crypto:
            algo = ml_algo
            confidence = ml_score

        # Add ML as finding if it fired
        if ml_is_crypto:
            all_findings.append(CryptoFinding(
                file="<snippet>", line=1, language=_canonical_language(language),
                algorithm=ml_algo, category="crypto", confidence=ml_score,
                method="ml", context=code[:200],
                obfuscated=_is_obfuscated(code)[0],
            ))
        confidence = max(0.0, min(1.0, confidence))
        return is_crypto, algo, confidence, all_findings

    # -- public API ---------------------------------------------------------

    def predict(self, code: str, language: str = "python") -> DetectionResult:
        """Classify *code* as crypto / non-crypto and label the algorithm.

        This is the two-stage classifier: stage-1 (crypto vs non-crypto) then
        stage-2 (algorithm / purpose). For purpose disambiguation see
        :mod:`qtrust_ai.discovery.algorithm_classifier`.

        Args:
            code: Source snippet.
            language: Language hint (e.g. ``"python"``, ``"java"``).

        Returns:
            :class:`DetectionResult` with ``is_crypto``, ``algorithm``,
            ``confidence``, and per-layer :class:`CryptoFinding` list.
        """
        lang = _canonical_language(language)
        is_crypto, algo, conf, findings = self._ensemble(code, lang)
        obf, _ = _is_obfuscated(code)
        expl_parts: List[str] = []
        if findings:
            methods = Counter(f.method for f in findings)
            expl_parts.append(f"layers={dict(methods)}")
        expl_parts.append(f"ensemble_conf={conf:.2f}")
        if obf:
            expl_parts.append("obfuscated=True (rule+AST flagged)")
        explanation = "; ".join(expl_parts) if is_crypto else f"no crypto signals (conf={conf:.2f})"
        return DetectionResult(
            is_crypto=is_crypto, algorithm=algo if is_crypto else "UNKNOWN",
            confidence=conf, language=lang, findings=findings,
            obfuscated=obf, explanation=explanation,
        )

    def scan_file(self, path: str | Path) -> List[CryptoFinding]:
        """Scan a single file for crypto usage.

        Handles large files by truncation at ``config.max_file_size_bytes``,
        skips binary files, and detects language from extension.

        Args:
            path: File system path.

        Returns:
            List of :class:`CryptoFinding` (empty if non-crypto or unreadable).
        """
        p = Path(path)
        if not p.is_file():
            return []
        try:
            if p.stat().st_size > self.config.max_file_size_bytes:
                # sample first N bytes
                text = p.read_text(encoding="utf-8", errors="ignore")[: self.config.max_file_size_bytes]
            else:
                text = p.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return []
        # Quick binary check
        if "\x00" in text[:4096]:
            return []
        lang = _detect_language_from_path(p)
        is_crypto, algo, conf, findings = self._ensemble(text, lang)
        # Patch file path into findings
        for f in findings:
            f.file = str(p)
        # If ensemble says non-crypto but findings exist, keep them with low conf
        if not is_crypto and not findings:
            return []
        return findings

    def scan_repo(self, root: str | Path, exclude_dirs: Optional[List[str]] = None) -> List[CryptoFinding]:
        """Recursively scan a repository.

        Args:
            root: Repository root directory.
            exclude_dirs: Directory names to skip (defaults to common ignores).

        Returns:
            Flat list of all :class:`CryptoFinding` across the repo.
        """
        root_p = Path(root)
        if not root_p.is_dir():
            return []
        exclude = set(exclude_dirs or [".git", "__pycache__", "node_modules", ".venv", "venv", "target", "build", ".idea", ".vscode"])
        all_findings: List[CryptoFinding] = []
        for dirpath, dirnames, filenames in os.walk(root_p):
            # prune excluded dirs in-place
            dirnames[:] = [d for d in dirnames if d not in exclude and not d.startswith(".")]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() not in _EXTENSION_MAP:
                    continue
                all_findings.extend(self.scan_file(fpath))
        return all_findings

    # -- real transformer fine-tuning (GPU) --------------------------------

    def fine_tune(
        self,
        corpus: List[Dict[str, Any]],
        epochs: int = 3,
        lr: float = 2e-5,
        model_name: str = "huggingface/CodeBERTa-small-v1",
        device: Optional[str] = None,
        batch_size: int = 24,
        max_len: int = 256,
        save_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Real transformer fine-tune on labelled code (GPU when available).

        Fine-tunes a small code model (default ``CodeBERTa-small-v1``) on the
        ``(code, is_crypto)`` corpus so the ML layer of the ensemble is a real
        classifier instead of a deterministic hash stub. Runs on CUDA when
        available. Skips gracefully (returns ``status=skipped``) when torch /
        transformers are missing or the model download fails — the detector
        keeps working with its deterministic fallback.
        """
        if not HAS_TORCH or not HAS_TRANSFORMERS or torch is None:
            return {"status": "skipped", "reason": "torch/transformers unavailable"}
        if not corpus:
            return {"status": "skipped", "reason": "empty corpus"}
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer  # type: ignore
        except Exception as exc:
            return {"status": "skipped", "reason": f"import failed: {exc}"}

        dev = device or ("cuda" if torch.cuda.is_available() else "cpu")
        # Deterministic training: seed all RNGs and pin cuDNN so repeated
        # runs produce bit-identical checkpoints. Without this the headline
        # held-out F1 changes run-to-run (observed 0.812?0.899), which makes
        # the benchmark non-reproducible and defeats the measured-results
        # claims.
        torch.manual_seed(self.config.seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.config.seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
        try:
            tok = AutoTokenizer.from_pretrained(model_name)  # type: ignore
            model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)  # type: ignore
        except Exception as exc:
            return {"status": "skipped", "reason": f"model download failed: {exc}"}
        model = model.to(dev)
        self._hf_tokenizer = tok
        self._hf_model = model
        self._hf_device = dev
        self._hf_max_len = max_len

        labels = [1 if c.get("is_crypto") else 0 for c in corpus]
        encs = tok(
            [c.get("code", "")[: max_len * 8] for c in corpus],
            truncation=True, max_length=max_len, padding=True, return_tensors="pt",
        )
        inputs = encs["input_ids"].to(dev)
        masks = encs["attention_mask"].to(dev)
        targets = torch.tensor(labels, dtype=torch.long).to(dev)
        opt = torch.optim.AdamW(model.parameters(), lr=lr)
        loss_fn = torch.nn.CrossEntropyLoss()
        n = len(corpus)
        # Shuffle each epoch — source-grouped corpora otherwise train on
        # long homogeneous runs (all-crypto then all-benign) and converge
        # to a degenerate classifier. Use a SEEDED local RNG so repeated
        # training runs produce identical orderings and a reproducible
        # checkpoint (the global ``random`` must not be consumed; other
        # layers share that stream).
        epoch_order = list(range(n))
        epoch_rng = random.Random(self.config.seed)
        train_acc: Optional[float] = None
        final_loss = 0.0
        for _ in range(epochs):
            epoch_rng.shuffle(epoch_order)
            model.train()
            total_loss, correct, seen = 0.0, 0, 0
            for i in range(0, n, batch_size):
                idx = epoch_order[i : i + batch_size]
                b_in = inputs[idx]
                b_m = masks[idx]
                b_t = targets[idx]
                out = model(input_ids=b_in, attention_mask=b_m)
                loss = loss_fn(out.logits, b_t)
                opt.zero_grad()
                loss.backward()
                opt.step()
                total_loss += float(loss.detach()) * len(b_t)
                correct += int((out.logits.argmax(-1) == b_t).sum())
                seen += len(b_t)
            train_acc = round(correct / seen, 4)
            final_loss = round(total_loss / seen, 4)

        # Persist label priors so predict() can name the algorithm
        self._label_counts = Counter(
            str(c.get("label", c.get("algorithm", "UNKNOWN"))) for c in corpus if c.get("is_crypto")
        )
        self._trained = True
        result: Dict[str, Any] = {
            "status": "trained", "model": model_name, "device": dev,
            "epochs": epochs, "examples": n, "batch_size": batch_size,
            "train_accuracy": train_acc, "final_loss": final_loss,
            "gpus_visible": torch.cuda.device_count(),
        }
        if save_dir:
            try:
                import os
                os.makedirs(save_dir, exist_ok=True)
                model.save_pretrained(save_dir)  # type: ignore
                tok.save_pretrained(save_dir)  # type: ignore
                result["saved_to"] = save_dir
            except Exception as exc:
                result["save_error"] = str(exc)
        return result

    def load_fine_tuned(self, save_dir: str) -> bool:
        """Load a checkpoint previously saved by :meth:`fine_tune`."""
        if not HAS_TORCH or not HAS_TRANSFORMERS or torch is None:
            return False
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer  # type: ignore
            self._hf_tokenizer = AutoTokenizer.from_pretrained(save_dir)  # type: ignore
            self._hf_model = AutoModelForSequenceClassification.from_pretrained(save_dir)  # type: ignore
            self._hf_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self._hf_model = self._hf_model.to(self._hf_device)
            return True
        except Exception:
            return False

    # -- training / evaluation (CPU stubs) ----------------------------------

    def train(
        self,
        corpus: Optional[List[Dict[str, Any]]] = None,
        synthetic_ratio: float = 0.4,
        epochs: int = 3,
        lr: float = 2e-5,
    ) -> Dict[str, Any]:
        """Train / fine-tune the code model.

        The **real** transformer path is :meth:`fine_tune` (CodeBERTa on the
        labelled corpus, GPU when available — this is what
        ``scripts/train_qtrust_all.py --real`` calls). ``train()`` is the
        lightweight fallback for CPU-only / no-transformers environments: it
        populates deterministic label priors and per-language bias from the
        corpus so ``predict`` still improves after ``train``. See
        ``qtrust_ai/README.md`` § Dataset discipline (40/30/20/10 mix of
        synthetic / real / expert / adversarial) for the production recipe.

        Args:
            corpus: List of ``{"code": str, "language": str, "label": str,
                "is_crypto": bool}``. If ``None`` a synthetic corpus is generated.
            synthetic_ratio: Fraction of synthetic examples when generating.
            epochs: Training epochs (fallback: controls bias magnitude).
            lr: Learning rate (fallback: scales bias).

        Returns:
            Dict with ``epochs``, ``examples``, ``label_distribution``,
            ``per_language_bias``, and ``note``.
        """
        random.seed(self.config.seed)
        if corpus is None:
            corpus = self._generate_synthetic_corpus(n=500, synthetic_ratio=synthetic_ratio)
        # Count labels
        self._label_counts = Counter(
            ex.get("label", ex.get("algorithm", "UNKNOWN")) for ex in corpus if ex.get("is_crypto", True)
        )
        # Simulate per-language bias learning: languages with more crypto examples get positive bias
        lang_crypto = Counter(ex["language"] for ex in corpus if ex.get("is_crypto"))
        lang_total = Counter(ex["language"] for ex in corpus)
        self._ml_bias = {}
        for lang in lang_total:
            ratio = lang_crypto[lang] / lang_total[lang] if lang_total[lang] else 0.5
            # bias in [-0.05, +0.10] scaled by epochs/lr
            self._ml_bias[_canonical_language(lang)] = (ratio - 0.5) * 0.2 * (epochs / 3)

        self._trained = True
        result: Dict[str, Any] = {
            "epochs": epochs,
            "examples": len(corpus),
            "label_distribution": dict(self._label_counts),
            "per_language_bias": dict(self._ml_bias),
            "has_torch": HAS_TORCH,
            "has_transformers": HAS_TRANSFORMERS,
            "note": "fallback path (no transformers/GPU); priors populated deterministically — "
                   "use fine_tune() for the real CodeBERTa fine-tune",
        }
        # If torch available, simulate a training loop log
        if HAS_TORCH:
            result["torch_available"] = True
            result["simulated_loss"] = round(0.9 - 0.08 * epochs + random.random() * 0.05, 4)
        return result

    def evaluate(self, dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Evaluate detector on a labelled dataset.

        Reports Precision / Recall / F1 / coverage (and accuracy) per
        ``qtrust_ai/README.md`` Killer metrics § Discovery: P/R/F1/FN/coverage.

        Args:
            dataset: List of ``{"code": str, "language": str, "is_crypto": bool,
                "label": str}``. If ``None`` a synthetic eval set is generated.

        Returns:
            Dict with ``precision``, ``recall``, ``f1``, ``accuracy``,
            ``false_negatives``, ``coverage``, ``n``, ``per_language`` breakdown.
        """
        if dataset is None:
            dataset = self._generate_synthetic_corpus(n=200, synthetic_ratio=0.5, seed=self.config.seed + 1)
        y_true: List[int] = []
        y_pred: List[int] = []
        per_lang: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        fns: List[Dict[str, Any]] = []
        for ex in dataset:
            code = ex.get("code", "")
            lang = ex.get("language", "python")
            true = 1 if ex.get("is_crypto", False) else 0
            pred = 1 if self.predict(code, language=lang).is_crypto else 0
            y_true.append(true)
            y_pred.append(pred)
            # per-language
            key = _canonical_language(lang)
            if true == 1 and pred == 1:
                per_lang[key]["tp"] += 1
            elif true == 0 and pred == 1:
                per_lang[key]["fp"] += 1
            elif true == 1 and pred == 0:
                per_lang[key]["fn"] += 1
                fns.append({"code": code[:80], "language": lang, "label": ex.get("label")})
            else:
                per_lang[key]["tn"] += 1

        if HAS_SKLEARN and y_true:
            try:
                from sklearn.metrics import precision_recall_fscore_support as prfs  # type: ignore
                p, r, f1, _ = prfs(y_true, y_pred, average="binary", zero_division=0)  # type: ignore
                acc = accuracy_score(y_true, y_pred)  # type: ignore
            except Exception:
                p, r, f1 = _precision_recall_f1_fallback(y_true, y_pred)
                acc = sum(1 for t, p_ in zip(y_true, y_pred) if t == p_) / len(y_true) if y_true else 0.0
        else:
            p, r, f1 = _precision_recall_f1_fallback(y_true, y_pred)
            acc = sum(1 for t, p_ in zip(y_true, y_pred) if t == p_) / len(y_true) if y_true else 0.0

        # coverage = fraction of inputs the model attempted (always 1.0 here)
        coverage = 1.0
        # FN rate
        total_pos = sum(y_true)
        fn_count = len(fns)
        fn_rate = fn_count / total_pos if total_pos else 0.0
        return {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f1), 4),
            "accuracy": round(float(acc), 4),
            "false_negatives": fn_count,
            "fn_rate": round(fn_rate, 4),
            "coverage": coverage,
            "n": len(dataset),
            "per_language": {k: dict(v) for k, v in per_lang.items()},
        }

    # -- synthetic corpus helper -------------------------------------------

    def _generate_synthetic_corpus(
        self, n: int = 500, synthetic_ratio: float = 0.4, seed: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Generate a deterministic synthetic corpus for training / eval."""
        rnd = random.Random(seed if seed is not None else self.config.seed)
        templates_crypto = [
            ("python", "import hashlib\nhashlib.sha256(b'{msg}')", "SHA-256", True),
            ("python", "from Crypto.Cipher import AES\nAES.new(key, AES.MODE_GCM)", "AES-256", True),
            ("java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");', "AES-256", True),
            ("java", 'KeyPairGenerator.getInstance("RSA")', "RSA", True),
            ("go", 'import "crypto/rsa"\nrsa.GenerateKey(rand.Reader, 2048)', "RSA", True),
            ("javascript", "crypto.createHash('sha256').update(data)", "SHA-256", True),
            ("rust", "use ring::digest; digest::digest(&digest::SHA256, data)", "SHA-256", True),
            ("solidity", "keccak256(abi.encodePacked(data))", "SHA3-256", True),
            ("shell", "openssl enc -aes-256-cbc -in file.txt", "AES-256", True),
            ("python", "rsa.sign(data, priv_key, 'SHA-256')", "RSA", True),
            ("python", "base64.b64decode('Y3J5cHRv'); eval(code)", "OBFUSCATED", True),  # adversarial
            ("python", "class CryptoWrapper:\n    def encrypt(self, d): pass", "WRAPPER", True),
        ]
        templates_benign = [
            ("python", "def add(a, b): return a + b", "UNKNOWN", False),
            ("java", "public class Foo { int x = 1; }", "UNKNOWN", False),
            ("javascript", "console.log('hello')", "UNKNOWN", False),
            ("go", 'fmt.Println("hi")', "UNKNOWN", False),
            ("rust", "fn main() { println!(\"hi\"); }", "UNKNOWN", False),
            ("shell", "ls -la /tmp", "UNKNOWN", False),
            ("python", "import os\nos.listdir('.')", "UNKNOWN", False),
        ]
        corpus: List[Dict[str, Any]] = []
        for i in range(n):
            if rnd.random() < synthetic_ratio + 0.1:  # slightly crypto-heavy
                lang, code, label, is_crypto = rnd.choice(templates_crypto)
                msg = rnd.choice(["hello", "data", "secret", "payload"])
                code = code.format(msg=msg)
            else:
                lang, code, label, is_crypto = rnd.choice(templates_benign)
            # adversarial wrapper variant 10% of the time
            if rnd.random() < 0.10 and is_crypto:
                code = f"# wrapped\n{code}\n# end"
            corpus.append({"code": code, "language": lang, "label": label, "is_crypto": is_crypto, "id": i})
        return corpus


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    det = CryptoCodeDetector(seed=42)
    print("=== CryptoCodeDetector demo ===")
    print(f"Model: {det.config.model_name} | languages: {len(SUPPORTED_LANGUAGES)} | torch={HAS_TORCH}")
    # Train stub
    train_res = det.train(epochs=2)
    print(f"\n[train] {json.dumps(train_res, indent=2)}")

    snippets = [
        ("import hashlib; hashlib.sha256(b'hello')", "python"),
        ("Cipher c = Cipher.getInstance(\"RSA/ECB/PKCS1Padding\");", "java"),
        ("def add(a,b): return a+b", "python"),
        ("base64.b64decode('abcd'); eval(__import__('os').system('x'))", "python"),
        ("openssl enc -aes-256-cbc -in secret.txt", "shell"),
        ("keccak256(abi.encodePacked(msg))", "solidity"),
    ]
    for code, lang in snippets:
        r = det.predict(code, language=lang)
        print(f"\n[{lang:10s}] crypto={r.is_crypto} algo={r.algorithm} conf={r.confidence:.2f} obf={r.obfuscated}")
        print(f"  code: {code[:70]}")
        print(f"  expl: {r.explanation}")
        if r.findings:
            for f in r.findings[:2]:
                print(f"    - {f.method}:{f.algorithm} @L{f.line} conf={f.confidence:.2f}")

    # scan_file demo via temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tf:
        tf.write("from Crypto.Cipher import AES\nkey = b'0'*32\ncipher = AES.new(key, AES.MODE_GCM)\n")
        tf_path = tf.name
    findings = det.scan_file(tf_path)
    print(f"\n[scan_file] {tf_path} -> {len(findings)} findings")
    for f in findings:
        print(f"  {f.language}:{f.algorithm} L{f.line} {f.method} conf={f.confidence:.2f} -> {f.context[:60]}")
    os.unlink(tf_path)

    # evaluate
    eval_res = det.evaluate()
    print(f"\n[evaluate] P={eval_res['precision']} R={eval_res['recall']} F1={eval_res['f1']} "
          f"acc={eval_res['accuracy']} FN={eval_res['false_negatives']}/{eval_res['n']}")

    # scan_repo demo on a temp repo
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "app.py").write_text("import hashlib\nimport rsa\nrsa.newkeys(2048)\n")
        Path(tmpdir, "util.go").write_text('package main\nimport "crypto/rsa"\n')
        Path(tmpdir, "README.md").write_text("# no crypto here\n")
        repo_findings = det.scan_repo(tmpdir)
        print(f"\n[scan_repo] {tmpdir} -> {len(repo_findings)} total findings")
        for f in repo_findings:
            print(f"  {Path(f.file).name}:{f.line} {f.algorithm} ({f.method})")
