"""Multi-language source code scanner for cryptographic API usage.

Scans Python, Java, Go, JavaScript/TypeScript, Rust, C/C++, Ruby, PHP, Swift, C#
source files for cryptographic API calls, key material, and algorithm usage.

Detects:
- OpenSSL/EVP API usage (C/C++/Python/Java)
- java.security / javax.crypto usage (Java)
- crypto/ecdsa/ed25519 usage (Go)
- crypto module usage (Node.js)
- cryptography/pyca usage (Python)
- ring/rustcrypto usage (Rust)
- Net::SSH / OpenSSL usage (Ruby)
- openssl_* usage (PHP)
- CryptoKit usage (Swift)
- System.Security.Cryptography (C#)
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import AssetFinding

# Language detection by extension
EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c_header",
    ".hpp": "cpp_header",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".cs": "csharp",
}

# Crypto API patterns per language
CRYPTO_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    "python": [
        (r"cryptography\.hazmat\.primitives\.asymmetric\.rsa", "RSA", "asymmetric"),
        (r"cryptography\.hazmat\.primitives\.asymmetric\.ec", "ECDSA", "asymmetric"),
        (r"cryptography\.hazmat\.primitives\.asymmetric\.ed25519", "Ed25519", "asymmetric"),
        (r"cryptography\.hazmat\.primitives\.asymmetric\.ed448", "Ed448", "asymmetric"),
        (r"cryptography\.hazmat\.primitives\.asymmetric\.dsa", "DSA", "asymmetric"),
        (r"cryptography\.hazmat\.primitives\.asymmetric\.dh", "DH", "asymmetric"),
        (r"cryptography\.hazmat\.primitives\.ciphers\.algorithms\.AES", "AES", "symmetric"),
        (r"cryptography\.hazmat\.primitives\.hashes\.SHA256", "SHA-256", "hash"),
        (r"cryptography\.hazmat\.primitives\.hashes\.SHA384", "SHA-384", "hash"),
        (r"cryptography\.hazmat\.primitives\.hashes\.SHA512", "SHA-512", "hash"),
        (r"cryptography\.hazmat\.primitives\.hashes\.MD5", "MD5", "hash"),
        (r"cryptography\.hazmat\.primitives\.hashes\.SHA1", "SHA-1", "hash"),
        (r"from\s+hashlib\s+import", "hashlib", "hash"),
        (r"import\s+nacl", "NaCl", "asymmetric"),
        (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa", "RSA", "asymmetric"),
        (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec", "ECDSA", "asymmetric"),
        (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ed25519", "Ed25519", "asymmetric"),
        (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dsa", "DSA", "asymmetric"),
        (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dh", "DH", "asymmetric"),
        (r"from\s+cryptography\.hazmat\.primitives\.hashes\s+import\s+SHA256", "SHA-256", "hash"),
        (r"from\s+cryptography\.hazmat\.primitives\.hashes\s+import\s+SHA384", "SHA-384", "hash"),
        (r"from\s+cryptography\.hazmat\.primitives\.hashes\s+import\s+SHA512", "SHA-512", "hash"),
        (r"from\s+cryptography\.hazmat\.primitives\.hashes\s+import\s+MD5", "MD5", "hash"),
        (r"from\s+cryptography\.hazmat\.primitives\.hashes\s+import\s+SHA1", "SHA-1", "hash"),
        (r"from\s+cryptography\.hazmat\.primitives\.ciphers\s+import\s+AES", "AES", "symmetric"),
        (r"from\s+cryptography\.hazmat", "hazmat", "crypto"),
        (r"ssl\.SSLContext", "TLS", "protocol"),
        (r"SSL\.PROTOCOL_TLS", "TLS", "protocol"),
    ],
    "java": [
        (r"java\.security\.KeyPairGenerator.*RSA", "RSA", "asymmetric"),
        (r"java\.security\.KeyPairGenerator.*EC", "ECDSA", "asymmetric"),
        (r"java\.security\.KeyPairGenerator.*DSA", "DSA", "asymmetric"),
        (r"javax\.crypto\.Cipher.*AES", "AES", "symmetric"),
        (r"javax\.crypto\.Cipher.*DES", "DES", "symmetric"),
        (r"javax\.crypto\.Cipher.*RC4", "RC4", "symmetric"),
        (r"MessageDigest\.getInstance.*SHA-?256", "SHA-256", "hash"),
        (r"MessageDigest\.getInstance.*SHA-?512", "SHA-512", "hash"),
        (r"MessageDigest\.getInstance.*MD5", "MD5", "hash"),
        (r"MessageDigest\.getInstance.*SHA-?1", "SHA-1", "hash"),
        (r"org\.bouncycastle", "BouncyCastle", "crypto"),
        (r"java\.security\.Signature.*SHA256withECDSA", "ECDSA", "asymmetric"),
        (r"java\.security\.Signature.*SHA256withRSA", "RSA", "asymmetric"),
    ],
    "go": [
        (r"crypto/rsa", "RSA", "asymmetric"),
        (r"crypto/ecdsa", "ECDSA", "asymmetric"),
        (r"crypto/ed25519", "Ed25519", "asymmetric"),
        (r"crypto/dsa", "DSA", "asymmetric"),
        (r"crypto/aes", "AES", "symmetric"),
        (r"crypto/des", "DES", "symmetric"),
        (r"crypto/sha256", "SHA-256", "hash"),
        (r"crypto/sha512", "SHA-512", "hash"),
        (r"crypto/md5", "MD5", "hash"),
        (r"crypto/sha1", "SHA-1", "hash"),
        (r"crypto/tls", "TLS", "protocol"),
        (r"golang\.org/x/crypto", "x/crypto", "crypto"),
        (r"golang\.org/x/crypto/nacl", "NaCl", "crypto"),
    ],
    "javascript": [
        (r"crypto\.createCipheriv.*aes", "AES", "symmetric"),
        (r"crypto\.createCipheriv.*des", "DES", "symmetric"),
        (r"crypto\.createCipheriv.*rc4", "RC4", "symmetric"),
        (r"crypto\.createHash.*sha256", "SHA-256", "hash"),
        (r"crypto\.createHash.*sha512", "SHA-512", "hash"),
        (r"crypto\.createHash.*md5", "MD5", "hash"),
        (r"crypto\.createHash.*sha1", "SHA-1", "hash"),
        (r"crypto\.createSign.*SHA256", "ECDSA/RSA", "asymmetric"),
        (r"crypto\.generateKeyPairSync.*rsa", "RSA", "asymmetric"),
        (r"crypto\.generateKeyPairSync.*ec", "ECDSA", "asymmetric"),
        (r"crypto\.scrypt", "scrypt", "kdf"),
        (r"require\(['\"]crypto['\"]", "crypto", "crypto"),
        (r"ethers\.Wallet", "ECDSA", "asymmetric"),
        (r"web3.*sign", "ECDSA", "asymmetric"),
    ],
    "typescript": [
        (r"crypto\.createCipheriv.*aes", "AES", "symmetric"),
        (r"crypto\.createHash.*sha256", "SHA-256", "hash"),
        (r"crypto\.createHash.*md5", "MD5", "hash"),
        (r"crypto\.createSign.*SHA256", "ECDSA/RSA", "asymmetric"),
        (r"ethers\.Wallet", "ECDSA", "asymmetric"),
        (r"viem.*sign", "ECDSA", "asymmetric"),
    ],
    "rust": [
        (r"ring::signature", "Ring", "asymmetric"),
        (r"ring::agreement", "ECDH", "asymmetric"),
        (r"rustCrypto", "RustCrypto", "crypto"),
        (r"aes::Aes", "AES", "symmetric"),
        (r"sha2::Sha256", "SHA-256", "hash"),
        (r"sha2::Sha512", "SHA-512", "hash"),
        (r"sha1::Sha1", "SHA-1", "hash"),
        (r"md-5::Md5", "MD5", "hash"),
        (r"rsa::Rsa", "RSA", "asymmetric"),
        (r"ecdsa::", "ECDSA", "asymmetric"),
        (r"ed25519_dalek", "Ed25519", "asymmetric"),
        (r"p256::", "ECC-P256", "asymmetric"),
        (r"p384::", "ECC-P384", "asymmetric"),
        (r"x25519_dalek", "X25519", "asymmetric"),
        (r"chacha20poly1305", "ChaCha20-Poly1305", "symmetric"),
        (r"crypto_box", "NaCl", "crypto"),
    ],
    "c": [
        (r"EVP_EncryptInit.*AES", "AES", "symmetric"),
        (r"EVP_DigestInit.*SHA256", "SHA-256", "hash"),
        (r"EVP_DigestInit.*MD5", "MD5", "hash"),
        (r"EVP_PKey.*RSA", "RSA", "asymmetric"),
        (r"EVP_PKey.*EC", "ECDSA", "asymmetric"),
        (r"RSA_generate_key", "RSA", "asymmetric"),
        (r"DES_*", "DES", "symmetric"),
        (r"AES_*", "AES", "symmetric"),
        (r"HMAC_CTX", "HMAC", "mac"),
        (r"SSL_CTX", "TLS", "protocol"),
        (r"OPENSSL_init_ssl", "OpenSSL", "crypto"),
    ],
    "cpp": [
        (r"EVP_EncryptInit.*AES", "AES", "symmetric"),
        (r"EVP_DigestInit.*SHA256", "SHA-256", "hash"),
        (r"EVP_PKey.*RSA", "RSA", "asymmetric"),
        (r"BOTAN", "Botan", "crypto"),
        (r"CRYPTOPP", "Crypto++", "crypto"),
        (r"OpenSSL::", "OpenSSL", "crypto"),
    ],
    "ruby": [
        (r"OpenSSL::Cipher.*AES", "AES", "symmetric"),
        (r"OpenSSL::Digest.*SHA256", "SHA-256", "hash"),
        (r"OpenSSL::Digest.*MD5", "MD5", "hash"),
        (r"OpenSSL::PKey::RSA", "RSA", "asymmetric"),
        (r"OpenSSL::PKey::EC", "ECDSA", "asymmetric"),
        (r"Net::SSH", "SSH", "protocol"),
    ],
    "php": [
        (r"openssl_pkey_new.*RSA", "RSA", "asymmetric"),
        (r"openssl_pkey_new.*EC", "ECDSA", "asymmetric"),
        (r"openssl_encrypt.*aes", "AES", "symmetric"),
        (r"openssl_digest.*sha256", "SHA-256", "hash"),
        (r"openssl_digest.*md5", "MD5", "hash"),
        (r"sodium_", "libsodium", "crypto"),
    ],
    "swift": [
        (r"CryptoKit\.AES\.GCM", "AES-GCM", "symmetric"),
        (r"CryptoKit\.ChaChaPoly", "ChaCha20-Poly1305", "symmetric"),
        (r"CryptoKit\.SHA256", "SHA-256", "hash"),
        (r"CryptoKit\.SHA384", "SHA-384", "hash"),
        (r"CryptoKit\.SHA512", "SHA-512", "hash"),
        (r"CryptoKit\.P256\.Signing", "ECDSA-P256", "asymmetric"),
        (r"CryptoKit\.P384\.Signing", "ECDSA-P384", "asymmetric"),
        (r"CryptoKit\.Curve25519", "X25519", "asymmetric"),
        (r"SecKeyCreateRandomKey.*kSecAttrKeyTypeRSA", "RSA", "asymmetric"),
    ],
    "csharp": [
        (r"System\.Security\.Cryptography\.RSA", "RSA", "asymmetric"),
        (r"System\.Security\.Cryptography\.ECDsa", "ECDSA", "asymmetric"),
        (r"System\.Security\.Cryptography\.Aes", "AES", "symmetric"),
        (r"System\.Security\.Cryptography\.SHA256", "SHA-256", "hash"),
        (r"System\.Security\.Cryptography\.SHA512", "SHA-512", "hash"),
        (r"System\.Security\.Cryptography\.MD5", "MD5", "hash"),
        (r"System\.Security\.Cryptography\.HMACSHA256", "HMAC-SHA256", "mac"),
        (r"BouncyCastle", "BouncyCastle", "crypto"),
    ],
}

# Hardcoded key patterns (regex, algorithm, type)
HARDCODED_KEY_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?:private[_\-]?key|secret[_\-]?key|api[_\-]?key)\s*[:=]\s*['\"][A-Za-z0-9+/=]{20,}['\"]", "hardcoded_key", "secret"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "RSA-private-key", "key_material"),
    (r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", "EC-private-key", "key_material"),
    (r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----", "DSA-private-key", "key_material"),
    (r"-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----", "encrypted-private-key", "key_material"),
    (r"-----BEGIN\s+CERTIFICATE-----", "x509-certificate", "key_material"),
]

# File patterns to skip
SKIP_PATTERNS = {
    "__pycache__", "node_modules", ".git", "vendor", "dist", "build",
    ".venv", "venv", "env", ".tox", ".mypy_cache", ".ruff_cache",
    "target", "debug", "release", ".next", ".nuxt",
}

SKIP_EXTENSIONS = {
    ".min.js", ".map", ".lock", ".sum", ".wasm", ".so", ".dll",
    ".exe", ".bin", ".o", ".obj", ".pyc", ".pyo", ".class",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar",
    ".gz", ".rar", ".7z", ".pdf", ".doc", ".docx",
}


def scan_source_file(
    path_or_code: Path | str,
    max_file_size: int = 5_000_000,
    language: str | None = None,
) -> list[AssetFinding]:
    """Scan a single source code file or code string for cryptographic API usage.

    Args:
        path_or_code: Path to the source file, or raw code string.
        max_file_size: Skip files larger than this (bytes).
        language: Force language detection (e.g., "python", "javascript").

    Returns:
        List of AssetFinding for each cryptographic API usage detected.
    """
    findings: list[AssetFinding] = []

    if isinstance(path_or_code, str) and not Path(path_or_code).exists():
        content = path_or_code
        lang = language
        host = "<inline>"
        if lang is None:
            return findings
    else:
        path = Path(path_or_code)
        if path.suffix.lower() in SKIP_EXTENSIONS:
            return findings
        lang = language or EXTENSION_MAP.get(path.suffix.lower())
        if lang is None:
            return findings
        try:
            size = path.stat().st_size
            if size > max_file_size or size == 0:
                return findings
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return findings
        host = str(path)

    patterns = CRYPTO_PATTERNS.get(lang, [])
    if not patterns:
        return findings

    file_findings: dict[str, set[str]] = {}

    for line_num, line in enumerate(content.splitlines(), 1):
        line_stripped = line.strip()
        if line_stripped.startswith("//") or line_stripped.startswith("#"):
            continue

        for pattern, algorithm, cat in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                key = f"{algorithm}:{cat}"
                if key not in file_findings:
                    file_findings[key] = set()
                file_findings[key].add(str(line_num))

        for pattern, algorithm, key_type in HARDCODED_KEY_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Audit I-5: never echo the secret material back into reports
                # (reports get attached to CBOMs, SARIF uploads, tickets...).
                redacted = re.sub(
                    r"""(['"])[A-Za-z0-9+/=_\-]{16,}\1""",
                    r"\1[REDACTED]\1",
                    line_stripped,
                )
                findings.append(AssetFinding(
                    asset_type="hardcoded_key",
                    host=host,
                    algorithm=algorithm,
                    key_type=key_type,
                    criticality="critical",
                    metadata={
                        "language": lang,
                        "line": line_num,
                        "evidence": redacted[:200],
                    },
                ))

    for key, lines in file_findings.items():
        algorithm, cat = key.split(":", 1)
        findings.append(AssetFinding(
            asset_type="source_crypto_usage",
            host=host,
            algorithm=algorithm,
            key_type=cat,
            criticality="medium",
            metadata={
                "language": lang,
                "lines": sorted(lines, key=int)[:10],
                "total_matches": len(lines),
            },
        ))

    return findings


def scan_source_directory(
    directory: str,
    extensions: set[str] | None = None,
    max_file_size: int = 5_000_000,
) -> list[AssetFinding]:
    """Recursively scan a directory for cryptographic usage in source code.

    Args:
        directory: Root directory to scan.
        extensions: Optional set of extensions to scan (default: all known).
        max_file_size: Skip files larger than this.

    Returns:
        List of AssetFinding for each detection.
    """
    root = Path(directory)
    if not root.exists():
        return []

    if extensions is None:
        extensions = set(EXTENSION_MAP.keys())

    findings: list[AssetFinding] = []
    for path in root.rglob("*"):
        if any(skip in path.parts for skip in SKIP_PATTERNS):
            continue
        if path.is_symlink():
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in extensions:
            continue
        findings.extend(scan_source_file(path, max_file_size))
    return findings
