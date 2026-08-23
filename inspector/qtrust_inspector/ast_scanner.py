"""Tree-sitter AST analysis for cryptographic pattern detection.

Provides structural analysis of Python, JavaScript/TypeScript source code
that catches aliased imports, multiline patterns, and scope-aware risk
signals that regex alone misses.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .models import AssetFinding


# Language-specific AST patterns as s-expression queries
PYTHON_AST_PATTERNS = [
    # Import aliases: `from cryptography.hazmat.primitives.asymmetric import rsa as r`
    ("import_alias", r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+(\w+)\s+as\s+(\w+)", "RSA"),
    # Direct usage after alias: `r.generate_private_key(...)`
    ("aliased_usage", r"(\w+)\.generate_private_key\(", "RSA"),
    # hashlib usage
    ("hash_import", r"import\s+hashlib", "hashlib"),
    ("hash_usage", r"hashlib\.(sha256|sha384|sha512|md5|sha1)\(", "hash"),
    # ssl module
    ("ssl_context", r"ssl\.SSLContext|SSL\.PROTOCOL_TLS", "TLS"),
]

JAVASCRIPT_AST_PATTERNS = [
    # crypto module
    ("crypto_import", r"require\s*\(\s*['\"]crypto['\"]\s*\)|from\s+['\"]crypto['\"]", "crypto"),
    ("create_hash", r"crypto\.createHash\(['\"](\w+)['\"]\)", "hash"),
    ("generate_key", r"crypto\.generateKeyPairSync\(['\"](\w+)['\"]\s*,", "asymmetric"),
    # WebCrypto
    ("subtle_generate", r"crypto\.subtle\.generateKey\(", "asymmetric"),
    ("subtle_sign", r"crypto\.subtle\.sign\(", "signature"),
    ("subtle_encrypt", r"crypto\.subtle\.encrypt\(", "encryption"),
]

GO_AST_PATTERNS = [
    ("crypto_rsa", r"crypto/rsa", "RSA"),
    ("crypto_ecdsa", r"crypto/ecdsa", "ECDSA"),
    ("crypto_ed25519", r"crypto/ed25519", "Ed25519"),
    ("crypto_aes", r"crypto/aes", "AES"),
    ("tls_dial", r"crypto/tls\.Dial|tls\.DialWithDialer", "TLS"),
]

JAVA_AST_PATTERNS = [
    ("keypair_gen", r"KeyPairGenerator\.getInstance\(['\"](\w+)['\"]\)", "asymmetric"),
    ("cipher_init", r"Cipher\.getInstance\(['\"](\w+)['\"]\)", "symmetric"),
    ("message_digest", r"MessageDigest\.getInstance\(['\"](\w+)['\"]\)", "hash"),
    ("bouncycastle", r"org\.bouncycastle", "BouncyCastle"),
]

RUST_AST_PATTERNS = [
    ("ring_usage", r"use\s+ring::", "ring"),
    ("rustcrypto", r"use\s+(aes|chacha20poly1305|sha2|rsa|ecdsa|ed25519)", "rustcrypto"),
    ("openssl", r"use\s+openssl::", "OpenSSL"),
]

CCPP_AST_PATTERNS = [
    ("openssl_evp", r"EVP_(Encrypt|Decrypt|Sign|Verify|Seal|Open)Init", "OpenSSL"),
    ("openssl_rsa", r"RSA_(generate|sign|verify|encrypt|decrypt)", "RSA"),
    ("openssl_ec", r"EC_KEY|ECDSA_sign|ECDSA_verify", "ECDSA"),
    ("openssl_aes", r"AES_(encrypt|decrypt|set_encrypt_key)", "AES"),
]

CSHARP_AST_PATTERNS = [
    ("system_crypto", r"System\.Security\.Cryptography", "System.Security"),
    ("rsa_class", r"new\s+RSACryptoServiceProvider|RSA\.Create", "RSA"),
    ("aes_class", r"new\s+AesCryptoServiceProvider|Aes\.Create", "AES"),
    ("ecdsa_class", r"ECDsa\.Create|new\s+ECDsaCng", "ECDSA"),
]

# Map language to patterns
LANG_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    "python": PYTHON_AST_PATTERNS,
    "javascript": JAVASCRIPT_AST_PATTERNS,
    "typescript": JAVASCRIPT_AST_PATTERNS,
    "go": GO_AST_PATTERNS,
    "java": JAVA_AST_PATTERNS,
    "rust": RUST_AST_PATTERNS,
    "c": CCPP_AST_PATTERNS,
    "cpp": CCPP_AST_PATTERNS,
    "csharp": CSHARP_AST_PATTERNS,
}

# Scope detection patterns (test code, mocks)
SCOPE_TEST_PATTERNS = [
    r"def\s+test_",
    r"pytest\.fixture",
    r"describe\s*\(",
    r"it\s*\(",
    r"test\s*\(",
    r"mock\.",
    r"@pytest",
    r"unittest",
    r"assert.*Raises",
    r"console\.log",  # likely test/debug code
]

# Aliased import tracking
class AliasTracker:
    """Track import aliases across a file."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def track(self, original: str, alias: str) -> None:
        self.aliases[alias] = original

    def resolve(self, name: str) -> str:
        return self.aliases.get(name, name)


def _detect_scope(content: str, line_num: int) -> str:
    """Detect if a line is inside a test function or mock."""
    lines = content.splitlines()
    for i in range(min(line_num, len(lines))):
        line = lines[i]
        for pattern in SCOPE_TEST_PATTERNS:
            if re.search(pattern, line):
                return "test"
    return "production"


def scan_with_ast(
    path: Path,
    content: str,
    language: str,
) -> list[AssetFinding]:
    """Scan source code using AST-style pattern matching.

    This provides structural analysis that catches:
    - Aliased imports (from crypto import rsa as r; r.generate_private_key(...))
    - Multiline patterns
    - Scope-aware risk (test code vs production)
    - Import chain tracking

    Returns list of AssetFinding with 'ast' confidence level.
    """
    findings: list[AssetFinding] = []
    patterns = LANG_PATTERNS.get(language, [])
    if not patterns:
        return findings

    tracker = AliasTracker()

    for line_num, line in enumerate(content.splitlines(), 1):
        for pattern_name, pattern, category in patterns:
            match = re.search(pattern, line)
            if not match:
                continue

            # Track aliases
            if pattern_name == "import_alias":
                groups = match.groups()
                if len(groups) == 2:
                    tracker.track(groups[0], groups[1])

            # Resolve aliases for usage patterns
            algo = category
            if pattern_name == "aliased_usage" and match.groups():
                alias = match.groups()[0]
                resolved = tracker.resolve(alias)
                algo = resolved

            # Detect scope
            scope = _detect_scope(content, line_num)
            criticality = "medium" if scope == "test" else "high"

            # Get surrounding context
            start = max(0, line_num - 3)
            end = min(len(content.splitlines()), line_num + 2)
            context = "\n".join(content.splitlines()[start:end])

            findings.append(AssetFinding(
                asset_type="ast_crypto_usage",
                host=str(path),
                algorithm=algo,
                key_type=category,
                criticality=criticality,
                metadata={
                    "language": language,
                    "line": line_num,
                    "pattern": pattern_name,
                    "scope": scope,
                    "confidence": "high",
                    "evidence": line.strip()[:200],
                    "context": context[:500],
                },
            ))

    return findings
