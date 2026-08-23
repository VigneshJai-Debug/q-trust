"""Binary/crypto-artifact scanner.

Detects embedded cryptographic libraries and artifacts inside compiled binaries
(ELF, PE, Mach-O) and archive formats (JAR/WAR/APK/wheels/gems), plus PEM blobs
embedded in arbitrary binaries. Produces AssetFinding records compatible with
the risk-engine vocabulary.
"""
from __future__ import annotations

import io
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from .models import AssetFinding
from .source_scanner import SKIP_PATTERNS

MAX_FILE_SIZE_DEFAULT = 100 * 1024 * 1024
STRING_SCAN_LIMIT = 64 * 1024 * 1024
MAX_MATCHES_PER_PATTERN = 8

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = (
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
)
ZIP_MAGIC = b"PK\x03\x04"

LIBRARY_VERSION_PATTERNS: list[tuple[bytes, str]] = [
    (rb"OpenSSL[ /](\d+\.\d+\.\d+[0-9a-z]*)", "OpenSSL"),
    (rb"BoringSSL", "BoringSSL"),
    (rb"[Ll]ibgcrypt[ -](\d+\.\d+\.\d+)", "libgcrypt"),
    (rb"wolfSSL[ /](\d+\.\d+\.\d+[a-z]*)", "wolfSSL"),
    (rb"mbed[Tt][Ll][Ss][ /](\d+\.\d+\.\d+)", "mbedTLS"),
    (rb"PolarSSL[ /](\d+\.\d+\.\d+)", "mbedTLS"),
    (rb"liboqs[ -](\d+\.\d+\.\d+)", "liboqs"),
    (rb"GnuTLS[ -](\d+\.\d+\.\d+)", "GnuTLS"),
    (rb"Crypto\+\+[ /](\d+\.\d+(\.\d+)?)", "Crypto++"),
    (rb"pqcrypto[ /-](\d+\.\d+(\.\d+)?)", "pqcrypto"),
]

KNOWN_SYMBOLS: list[tuple[bytes, str]] = [
    (b"EVP_CIPHER_CTX_new", "OpenSSL"),
    (b"SSL_CTX_new", "OpenSSL"),
    (b"RSA_generate_key_ex", "OpenSSL"),
    (b"aesni_ecb_encrypt", "BoringSSL"),
    (b"CRYPTO_chacha_20", "BoringSSL"),
    (b"gcry_check_version", "libgcrypt"),
    (b"wolfSSL_Init", "wolfSSL"),
    (b"mbedtls_aes_init", "mbedTLS"),
    (b"OQS_KEM_new", "liboqs"),
    (b"oqs_kem_ml_kem_768", "liboqs"),
]

DLL_HINT_PATTERNS: list[tuple[bytes, str]] = [
    (rb"(?i)\blibcrypto[\w\-]*\.dll", "OpenSSL"),
    (rb"(?i)\blibssl[\w\-]*\.dll", "OpenSSL"),
    (rb"(?i)\blibeay32\.dll", "OpenSSL"),
    (rb"(?i)\bssleay32\.dll", "OpenSSL"),
    (rb"(?i)\bwolfssl\.dll", "wolfSSL"),
    (rb"(?i)\bmbedtls\.dll", "mbedTLS"),
    (rb"(?i)\blibgcrypt[\w\-]*\.dll", "libgcrypt"),
    (rb"(?i)\bliboqs\.dll", "liboqs"),
]

JAVA_CRYPTO_PACKAGES: list[tuple[str, str]] = [
    ("org/bouncycastle/", "BouncyCastle"),
    ("javax/crypto/", "javax.crypto"),
    ("com/sun/crypto/provider/", "SunJCE"),
]

KEYSTORE_EXTENSIONS = {".jks", ".keystore", ".bks"}

NATIVE_LIB_NAMES = {
    "libcrypto.so": "OpenSSL",
    "libssl.so": "OpenSSL",
    "libconscrypt_jni.so": "Conscrypt",
    "libgmp.so": "libgcrypt",
    "libwolfssl.so": "wolfSSL",
    "libmbedtls.so": "mbedTLS",
    "liboqs.so": "liboqs",
}

WHEEL_CRYPTO_DEPS: dict[str, str] = {
    "cryptography": "pyca-cryptography",
    "pycryptodome": "pycryptodome",
    "pycrypto": "pycrypto",
    "pynacl": "pynacl",
    "pyopenssl": "pyopenssl",
}

PEM_MARKER_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]{3,40})-----")

PEM_LABEL_ALGORITHMS: dict[str, str] = {
    "CERTIFICATE": "x509-certificate",
    "TRUSTED CERTIFICATE": "x509-certificate",
    "PRIVATE KEY": "private-key",
    "ENCRYPTED PRIVATE KEY": "private-key",
    "RSA PRIVATE KEY": "RSA",
    "EC PRIVATE KEY": "EC",
    "DSA PRIVATE KEY": "DSA",
    "OPENSSH PRIVATE KEY": "private-key",
    "PGP PRIVATE KEY BLOCK": "private-key",
    "PUBLIC KEY": "public-key",
    "CERTIFICATE REQUEST": "csr",
}


def _detect_format(data: bytes, suffix: str) -> str:
    if data[:4] == ELF_MAGIC:
        return "ELF"
    if data[:2] == PE_MAGIC:
        return "PE"
    if data[:4] in MACHO_MAGICS:
        return "Mach-O"
    if data[:4] == ZIP_MAGIC or suffix in (".jar", ".war", ".apk", ".whl", ".zip"):
        return "ZIP"
    if suffix == ".gem":
        return "GEM"
    return "raw"


def _library_criticality(library: str, version: str | None) -> str:
    if library == "OpenSSL" and version:
        major = version.split(".")[0]
        if major in ("0", "1"):
            return "high"
        try:
            minor = int(version.split(".")[1]) if len(version.split(".")) > 1 else 0
        except ValueError:
            minor = 99
        if major == "3" and minor < 5:
            return "medium"
        return "low"
    if library in ("BoringSSL", "liboqs"):
        return "medium"
    return "medium"


def _library_metadata(
    fmt: str,
    library: str,
    version: str | None,
    offset: int,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "format": fmt,
        "library": library,
        "offset": offset,
    }
    if version:
        metadata["version"] = version
    supports_pqc = library == "liboqs" or (
        library == "OpenSSL" and _openssl_supports_pqc(version)
    ) or library == "BoringSSL"
    metadata["supports_pqc"] = supports_pqc
    if not supports_pqc:
        metadata["note"] = f"{library} supports only classical algorithms; no PQC (ML-KEM/ML-DSA)"
    if extra:
        metadata.update(extra)
    return metadata


def _openssl_supports_pqc(version: str | None) -> bool:
    if not version:
        return False
    try:
        parts = [int(p) for p in re.findall(r"\d+", version)[:2]]
    except ValueError:
        return False
    if len(parts) < 2:
        return False
    return parts[0] > 3 or (parts[0] == 3 and parts[1] >= 5)


def _scan_library_strings(fmt: str, host: str, data: bytes) -> list[AssetFinding]:
    region = data[:STRING_SCAN_LIMIT]
    findings: list[AssetFinding] = []
    seen_libraries: set[str] = set()

    for pattern, library in LIBRARY_VERSION_PATTERNS:
        count = 0
        for match in re.finditer(pattern, region):
            groups = [g for g in match.groups() if g]
            version = groups[0].decode("ascii", errors="replace") if groups else None
            if any(f.vendor == library and f.metadata.get("version") == version for f in findings):
                continue
            findings.append(AssetFinding(
                asset_type="binary_crypto_artifact",
                host=host,
                algorithm=library,
                vendor=library,
                criticality=_library_criticality(library, version),
                metadata=_library_metadata(fmt, library, version, match.start()),
            ))
            seen_libraries.add(library)
            count += 1
            if count >= MAX_MATCHES_PER_PATTERN:
                break

    for symbol, library in KNOWN_SYMBOLS:
        if library in seen_libraries:
            continue
        pos = region.find(symbol)
        if pos >= 0:
            findings.append(AssetFinding(
                asset_type="binary_crypto_artifact",
                host=host,
                algorithm=library,
                vendor=library,
                criticality=_library_criticality(library, None),
                metadata=_library_metadata(fmt, library, None, pos, {"evidence": symbol.decode("ascii")}),
            ))
            seen_libraries.add(library)

    if fmt == "PE":
        for pattern, library in DLL_HINT_PATTERNS:
            match = re.search(pattern, region)
            if match:
                dll_name = match.group(0).decode("ascii", errors="replace")
                findings.append(AssetFinding(
                    asset_type="binary_crypto_artifact",
                    host=host,
                    algorithm=library,
                    vendor=library,
                    criticality=_library_criticality(library, None),
                    metadata=_library_metadata(fmt, library, None, match.start(), {"import_hint": dll_name}),
                ))

    return findings


def _scan_pem_blobs(host: str, data: bytes) -> list[AssetFinding]:
    region = data[:STRING_SCAN_LIMIT]
    findings: list[AssetFinding] = []
    seen_labels: set[str] = set()
    for match in PEM_MARKER_RE.finditer(region):
        label = match.group(1).decode("ascii", errors="replace").strip()
        algorithm = PEM_LABEL_ALGORITHMS.get(label, "unknown-pem")
        dedupe_key = f"{algorithm}:{label}"
        if dedupe_key in seen_labels:
            continue
        seen_labels.add(dedupe_key)
        is_private = "PRIVATE KEY" in label
        findings.append(AssetFinding(
            asset_type="binary_crypto_artifact",
            host=host,
            algorithm=algorithm,
            vendor="embedded-pem",
            criticality="critical" if is_private else "medium",
            metadata={
                "format": "PEM-blob",
                "library": label,
                "offset": match.start(),
                "supports_pqc": False,
                "note": "Embedded PEM blob inside binary",
            },
        ))
        if len(seen_labels) >= 16:
            break
    return findings


def _zip_member_bytes(zf: zipfile.ZipFile, name: str, limit: int = 16 * 1024 * 1024) -> bytes | None:
    try:
        info = zf.getinfo(name)
        if info.file_size > limit:
            return None
        return zf.read(name)
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
        return None


def _scan_zip_container(host: str, data: bytes, fmt: str) -> list[AssetFinding]:
    findings: list[AssetFinding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return findings

    bc_version: str | None = None
    for name in names:
        if name.startswith("META-INF/maven/org.bouncycastle/") and name.endswith("pom.properties"):
            blob = _zip_member_bytes(zf, name)
            if blob:
                m = re.search(rb"^version=(.+)$", blob, re.MULTILINE)
                if m:
                    bc_version = m.group(1).decode("ascii", errors="replace").strip()
                    break

    detected_packages: dict[str, str] = {}
    signing_entries: list[str] = []
    keystores: list[str] = []
    native_libs: list[str] = []

    for name in names:
        normalized = name.replace("\\", "/")
        if normalized.startswith("META-INF/") and normalized.upper().endswith((".RSA", ".SF", ".DSA", ".EC")):
            signing_entries.append(normalized)
        lower = normalized.lower()
        if lower.endswith(tuple(KEYSTORE_EXTENSIONS)):
            keystores.append(normalized)
        base = normalized.rsplit("/", 1)[-1]
        if base in NATIVE_LIB_NAMES and ("/lib/" in normalized or normalized.startswith("lib/")):
            native_libs.append(normalized)
        for prefix, library in JAVA_CRYPTO_PACKAGES:
            if normalized.startswith(prefix):
                detected_packages.setdefault(library, normalized)

    for library, example in detected_packages.items():
        findings.append(AssetFinding(
            asset_type="binary_crypto_artifact",
            host=host,
            algorithm=library,
            vendor=library,
            criticality="medium",
            metadata={
                "format": fmt,
                "library": library,
                "version": bc_version if library == "BouncyCastle" else None,
                "offset": 0,
                "entry_example": example,
                "supports_pqc": library == "BouncyCastle" and bool(bc_version),
            },
        ))

    for entry in signing_entries[:4]:
        findings.append(AssetFinding(
            asset_type="binary_crypto_artifact",
            host=host,
            algorithm="jar-signature",
            vendor="JAR-signing",
            criticality="medium",
            metadata={
                "format": fmt,
                "library": "signed-jar",
                "entry": entry,
                "offset": 0,
                "supports_pqc": False,
            },
        ))

    for entry in keystores[:4]:
        findings.append(AssetFinding(
            asset_type="binary_crypto_artifact",
            host=host,
            algorithm="java-keystore",
            vendor="JavaKeyStore",
            criticality="high",
            metadata={
                "format": fmt,
                "library": "keystore",
                "entry": entry,
                "offset": 0,
                "supports_pqc": False,
                "note": "KeyStore archive entry contains key material",
            },
        ))

    for entry in native_libs[:4]:
        lib_name = entry.rsplit("/", 1)[-1]
        library = NATIVE_LIB_NAMES.get(lib_name, "native-crypto")
        findings.append(AssetFinding(
            asset_type="binary_crypto_artifact",
            host=host,
            algorithm=library,
            vendor=library,
            criticality="medium",
            metadata={
                "format": fmt,
                "library": library,
                "entry": entry,
                "offset": 0,
                "supports_pqc": False,
            },
        ))

    for name in names:
        if name.endswith(".dist-info/METADATA"):
            blob = _zip_member_bytes(zf, name, limit=4 * 1024 * 1024)
            if not blob:
                continue
            text = blob.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if not line.startswith("Requires-Dist:"):
                    continue
                spec = line.split(":", 1)[1].strip()
                dep_name = re.split(r"[\s<>=!~;\[]", spec, maxsplit=1)[0].strip().lower()
                if dep_name in WHEEL_CRYPTO_DEPS:
                    version_match = re.search(r"[<>=!~]+\s*([\d][\w.]*)", spec)
                    findings.append(AssetFinding(
                        asset_type="binary_crypto_artifact",
                        host=host,
                        algorithm=WHEEL_CRYPTO_DEPS[dep_name],
                        vendor=WHEEL_CRYPTO_DEPS[dep_name],
                        criticality="medium",
                        metadata={
                            "format": fmt,
                            "library": dep_name,
                            "version": version_match.group(1) if version_match else None,
                            "offset": 0,
                            "metadata_entry": name,
                            "requirement": spec,
                            "supports_pqc": dep_name == "cryptography",
                        },
                    ))

    return findings


def _scan_gem_archive(host: str, data: bytes) -> list[AssetFinding]:
    findings: list[AssetFinding] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as outer:
            inner_member = None
            for member in outer.getmembers():
                if member.name == "data.tar.gz" or member.name.endswith("data.tar.gz"):
                    inner_member = member
                    break
            if inner_member is None:
                return findings
            inner_bytes = outer.extractfile(inner_member).read(MAX_FILE_SIZE_DEFAULT)
        with tarfile.open(fileobj=io.BytesIO(inner_bytes), mode="r:*") as inner:
            for member in inner.getmembers():
                if member.name.endswith(".gemspec"):
                    blob = inner.extractfile(member).read(2 * 1024 * 1024) if inner.extractfile(member) else b""
                    text = blob.decode("utf-8", errors="replace")
                    if re.search(r"\b(crypto|openssl|rsa|ecdsa|bcrypt)\b", text, re.IGNORECASE):
                        name_match = re.search(r"name\s*=\s*[\"']([^\"']+)", text)
                        findings.append(AssetFinding(
                            asset_type="binary_crypto_artifact",
                            host=host,
                            algorithm=name_match.group(1) if name_match else "gem-crypto",
                            vendor=name_match.group(1) if name_match else "ruby-gem",
                            criticality="medium",
                            metadata={
                                "format": "GEM",
                                "library": name_match.group(1) if name_match else member.name,
                                "offset": 0,
                                "supports_pqc": False,
                            },
                        ))
    except (tarfile.TarError, OSError):
        return findings
    return findings


def scan_binary(path: str | Path, max_file_size: int = MAX_FILE_SIZE_DEFAULT) -> list[AssetFinding]:
    """Scan a single binary/archive file for embedded crypto libraries/artifacts."""
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
        if size <= 0 or size > max_file_size:
            return []
        data = file_path.read_bytes()
    except OSError:
        return []

    host = str(file_path)
    suffix = file_path.suffix.lower()
    fmt = _detect_format(data, suffix)

    findings: list[AssetFinding] = []

    if fmt == "ZIP":
        findings.extend(_scan_zip_container(host, data, suffix.lstrip(".").upper() or "ZIP"))
    elif fmt == "GEM":
        findings.extend(_scan_gem_archive(host, data))

    findings.extend(_scan_library_strings(fmt, host, data))
    findings.extend(_scan_pem_blobs(host, data))

    return findings


def scan_binaries_in_directory(
    root: str | Path,
    max_file_size: int = MAX_FILE_SIZE_DEFAULT,
) -> list[AssetFinding]:
    """Recursively scan a directory tree for embedded crypto artifacts in binaries.

    Honors SKIP_PATTERNS-style excludes (.git, node_modules, target, __pycache__, ...)
    and skips symbolic links.
    """
    root_path = Path(root)
    if not root_path.exists():
        return []

    skip = set(SKIP_PATTERNS) | {".pytest_cache", ".mypy_cache", ".ruff_cache"}
    findings: list[AssetFinding] = []
    for path in sorted(root_path.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if any(part in skip for part in path.parts[:-1]):
            continue
        try:
            if path.stat().st_size > max_file_size:
                continue
        except OSError:
            continue
        findings.extend(scan_binary(path, max_file_size=max_file_size))
    return findings
