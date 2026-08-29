from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from .models import AssetFinding


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    NIST_SP_800_131A = "NIST_SP_800_131A"
    CNSA_2_0 = "CNSA_2_0"
    FIPS_140_3 = "FIPS_140_3"
    EU_NIS2 = "EU_NIS2"
    FISMA = "FISMA"
    FEDRAMP = "FEDRAMP"
    CMMC = "CMMC"
    PCI_DSS_4_0 = "PCI_DSS_4_0"
    BSI_TR_02102 = "BSI_TR_02102"
    NCSC_UK = "NCSC_UK"
    ASD_ISM = "ASD_ISM"


class ComplianceStatus(str, Enum):
    """Result status for a compliance rule."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    """Severity of a compliance finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceRule(BaseModel):
    """A single compliance rule evaluation."""
    framework: ComplianceFramework
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    status: ComplianceStatus
    evidence: str = ""
    recommendation: str = ""


class ComplianceResult(BaseModel):
    """Aggregated compliance evaluation result for one framework."""
    framework: ComplianceFramework
    total_rules: int
    compliant_count: int
    non_compliant_count: int
    partial_count: int
    score: float = Field(..., ge=0, le=100, description="Compliance score 0-100")
    rules: list[ComplianceRule] = Field(default_factory=list)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FORBIDDEN_SYMMETRIC = {"des", "3des", "triple_des", "rc4"}
_FORBIDDEN_HASH = {"md5", "sha1"}
_KEY_SIZE_RE = re.compile(r"(\d+)")

_CIPHERSUITE_RANK: dict[str, int] = {
    "aes_256_gcm": 100,
    "aes_128_gcm": 90,
    "chacha20_poly1305": 90,
    "aes_256_cbc": 70,
    "aes_128_cbc": 60,
    "3des_cbc": 10,
    "rc4": 0,
}


def _normalise_alg(name: str | None) -> str:
    """Lower-case, strip whitespace, collapse underscores and dashes."""
    if not name:
        return ""
    normalized = re.sub(r"[\s_]+", "_", name.strip().lower())
    normalized = re.sub(r"[-]+", "_", normalized)
    return normalized


def _extract_key_size(finding: AssetFinding) -> int | None:
    if finding.key_size is not None:
        return finding.key_size
    m = _KEY_SIZE_RE.search(finding.algorithm or "")
    if m:
        return int(m.group(1))
    m = _KEY_SIZE_RE.search(finding.key_type or "")
    if m:
        return int(m.group(1))
    return None


def _is_asymmetric(finding: AssetFinding) -> bool:
    alg = _normalise_alg(finding.algorithm)
    ktype = _normalise_alg(finding.key_type)
    return any(k in alg or k in ktype for k in ("rsa", "ecdsa", "dsa", "ed25519", "ed448", "ec", "ml_dsa", "slh_dsa"))


def _is_symmetric(finding: AssetFinding) -> bool:
    alg = _normalise_alg(finding.algorithm)
    return any(k in alg for k in ("aes", "des", "3des", "rc4", "chacha"))


def _is_hash(finding: AssetFinding) -> bool:
    alg = _normalise_alg(finding.algorithm)
    return any(k in alg for k in ("sha", "md5", "blake", "shake", "digest", "hmac"))


def _is_key_exchange(finding: AssetFinding) -> bool:
    alg = _normalise_alg(finding.algorithm)
    return any(k in alg for k in ("kem", "x25519", "x448", "dh", "ecdh", "ml_kem"))


def _is_tls(finding: AssetFinding) -> bool:
    return finding.asset_type in ("tls_certificate", "tls_cipher_suite", "tls_connection")


def _cipher_strength(cipher: str) -> int:
    return _CIPHERSUITE_RANK.get(_normalise_alg(cipher), 50)


# ---------------------------------------------------------------------------
# Rule evaluators – one per framework
# ---------------------------------------------------------------------------


def _nist_800_131a_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)
    ksize = _extract_key_size(finding)

    # RSA minimum key sizes
    if "rsa" in alg or _normalise_alg(finding.key_type) == "rsa":
        # Encryption
        if ksize is not None:
            ok = ksize >= 2048
            rules.append(ComplianceRule(
                framework=ComplianceFramework.NIST_SP_800_131A,
                rule_id="NIST-800-131A-RSA-ENCRYPT",
                rule_name="RSA encryption key size >= 2048 bits",
                description="NIST SP 800-131A requires RSA keys used for encryption to be at least 2048 bits.",
                severity=Severity.HIGH,
                status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
                evidence=f"RSA key size {ksize} bits",
                recommendation="Upgrade to RSA-2048 or larger for encryption." if not ok else "",
            ))
            # Signing
            ok_sign = ksize >= 3072
            rules.append(ComplianceRule(
                framework=ComplianceFramework.NIST_SP_800_131A,
                rule_id="NIST-800-131A-RSA-SIGN",
                rule_name="RSA signing key size >= 3072 bits",
                description="NIST SP 800-131A requires RSA keys used for digital signatures to be at least 3072 bits.",
                severity=Severity.CRITICAL,
                status=ComplianceStatus.COMPLIANT if ok_sign else ComplianceStatus.NON_COMPLIANT,
                evidence=f"RSA key size {ksize} bits",
                recommendation="Upgrade to RSA-3072 or larger for digital signatures." if not ok_sign else "",
            ))

    # ECDSA
    if "ecdsa" in alg or "ec" in _normalise_alg(finding.key_type or ""):
        weak_curves = {"p_192", "p192", "secp192r1", "sect163", "sect163r2"}
        is_weak = any(w in alg for w in weak_curves)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.NIST_SP_800_131A,
            rule_id="NIST-800-131A-ECDSA",
            rule_name="ECDSA key size >= P-256",
            description="NIST SP 800-131A requires ECDSA keys to be at least P-256.",
            severity=Severity.HIGH,
            status=ComplianceStatus.NON_COMPLIANT if is_weak else ComplianceStatus.COMPLIANT,
            evidence=f"ECDSA curve detected: {finding.algorithm}",
            recommendation="Upgrade to P-256 or stronger curve." if is_weak else "",
        ))

    # Hash algorithms
    if _is_hash(finding):
        strong = {"sha256", "sha_256", "sha384", "sha_384", "sha512", "sha_512", "sha3_256", "sha3_512", "blake2b", "blake2s", "blake3"}
        weak = _FORBIDDEN_HASH
        is_strong = any(s in alg for s in strong)
        is_weak = any(w in alg for w in weak)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.NIST_SP_800_131A,
            rule_id="NIST-800-131A-HASH",
            rule_name="Hash algorithm >= SHA-256",
            description="NIST SP 800-131A requires SHA-256 or stronger for hashing.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if is_strong else (ComplianceStatus.NON_COMPLIANT if is_weak else ComplianceStatus.PARTIAL),
            evidence=f"Hash algorithm: {finding.algorithm}",
            recommendation="Migrate to SHA-256 or stronger." if not is_strong else "",
        ))

    # Symmetric encryption
    if _is_symmetric(finding):
        is_forbidden = any(f in alg for f in _FORBIDDEN_SYMMETRIC)
        ok_size = ksize is not None and ksize >= 128
        rules.append(ComplianceRule(
            framework=ComplianceFramework.NIST_SP_800_131A,
            rule_id="NIST-800-131A-SYMM",
            rule_name="Symmetric encryption >= AES-128",
            description="NIST SP 800-131A requires AES-128 or stronger for symmetric encryption.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if (ok_size and not is_forbidden) else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Symmetric algorithm: {finding.algorithm}, key size: {ksize}",
            recommendation="Migrate to AES-128 or AES-256." if is_forbidden or not ok_size else "",
        ))

    # Deprecated algorithm check (catch-all)
    all_forbidden = _FORBIDDEN_SYMMETRIC | _FORBIDDEN_HASH
    if any(f in alg for f in all_forbidden):
        rules.append(ComplianceRule(
            framework=ComplianceFramework.NIST_SP_800_131A,
            rule_id="NIST-800-131A-DEPRECATED",
            rule_name="No deprecated algorithms",
            description="NIST SP 800-131A prohibits MD5, SHA-1, DES, 3DES, and RC4.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"Deprecated algorithm detected: {finding.algorithm}",
            recommendation="Replace with a NIST-approved algorithm.",
        ))

    return rules


def _cnsa_2_0_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)

    # Key establishment – ML-KEM-1024
    if _is_key_exchange(finding) or _is_asymmetric(finding):
        ok_kem = "ml_kem_1024" in alg or "mlkem1024" in alg
        rules.append(ComplianceRule(
            framework=ComplianceFramework.CNSA_2_0,
            rule_id="CNSA2-KEM",
            rule_name="ML-KEM-1024 for key establishment",
            description="CNSA 2.0 requires ML-KEM-1024 for post-quantum key establishment.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if ok_kem else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Key exchange algorithm: {finding.algorithm}",
            recommendation="Migrate to ML-KEM-1024 for key establishment." if not ok_kem else "",
        ))

    # Digital signatures – ML-DSA-87
    if _is_asymmetric(finding):
        alg_l = alg
        ok_sig = "ml_dsa_87" in alg_l or "mldsa87" in alg_l
        rules.append(ComplianceRule(
            framework=ComplianceFramework.CNSA_2_0,
            rule_id="CNSA2-SIG",
            rule_name="ML-DSA-87 for digital signatures",
            description="CNSA 2.0 requires ML-DSA-87 for post-quantum digital signatures.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if ok_sig else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Signature algorithm: {finding.algorithm}",
            recommendation="Migrate to ML-DSA-87 for digital signatures." if not ok_sig else "",
        ))

    # Backup signature – SLH-DSA-SHA2-256s
    if _is_asymmetric(finding):
        ok_backup = "slh_dsa_sha2_256s" in alg or "slhdsa_sha2_256s" in alg
        rules.append(ComplianceRule(
            framework=ComplianceFramework.CNSA_2_0,
            rule_id="CNSA2-BACKUP-SIG",
            rule_name="SLH-DSA-SHA2-256s backup signature",
            description="CNSA 2.0 designates SLH-DSA-SHA2-256s as the backup signature algorithm.",
            severity=Severity.MEDIUM,
            status=ComplianceStatus.COMPLIANT if ok_backup else ComplianceStatus.PARTIAL,
            evidence=f"Signature algorithm: {finding.algorithm}",
            recommendation="Add SLH-DSA-SHA2-256s as a backup signature algorithm." if not ok_backup else "",
        ))

    # Symmetric – AES-256
    if _is_symmetric(finding):
        ok_aes = "aes_256" in alg
        rules.append(ComplianceRule(
            framework=ComplianceFramework.CNSA_2_0,
            rule_id="CNSA2-SYMM",
            rule_name="AES-256 for symmetric encryption",
            description="CNSA 2.0 requires AES-256 for symmetric encryption.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if ok_aes else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Symmetric algorithm: {finding.algorithm}",
            recommendation="Migrate to AES-256." if not ok_aes else "",
        ))

    # Hash – SHA-384 / SHA-512
    if _is_hash(finding):
        ok_hash = any(h in alg for h in ("sha384", "sha_384", "sha512", "sha_512"))
        rules.append(ComplianceRule(
            framework=ComplianceFramework.CNSA_2_0,
            rule_id="CNSA2-HASH",
            rule_name="SHA-384 or SHA-512 for hashing",
            description="CNSA 2.0 requires SHA-384 or SHA-512 for hashing.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if ok_hash else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Hash algorithm: {finding.algorithm}",
            recommendation="Migrate to SHA-384 or SHA-512." if not ok_hash else "",
        ))

    # Key exchange – X25519 (transitional)
    if _is_key_exchange(finding):
        ok_x25519 = "x25519" in alg
        rules.append(ComplianceRule(
            framework=ComplianceFramework.CNSA_2_0,
            rule_id="CNSA2-KEX",
            rule_name="X25519 for key exchange (transitional)",
            description="CNSA 2.0 allows X25519 as a transitional key exchange algorithm.",
            severity=Severity.MEDIUM,
            status=ComplianceStatus.COMPLIANT if ok_x25519 else ComplianceStatus.PARTIAL,
            evidence=f"Key exchange algorithm: {finding.algorithm}",
            recommendation="Use X25519 or ML-KEM-1024 for key exchange." if not ok_x25519 else "",
        ))

    return rules


def _fips_140_3_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)
    ksize = _extract_key_size(finding)

    fips_algorithms = {
        "aes_128", "aes_192", "aes_256",
        "sha256", "sha_256", "sha384", "sha_384", "sha512", "sha_512",
        "sha3_256", "sha3_384", "sha3_512",
        "rsa", "ecdsa", "ecdh",
        "hmac", "cmac", "gcm",
    }

    # FIPS-approved algorithms
    alg_family = alg.split("_")[0] if alg else ""
    is_fips_approved = any(f in alg for f in fips_algorithms) or alg_family in fips_algorithms
    rules.append(ComplianceRule(
        framework=ComplianceFramework.FIPS_140_3,
        rule_id="FIPS-ALG-APPROVED",
        rule_name="FIPS-approved algorithms only",
        description="FIPS 140-3 requires the use of FIPS-approved cryptographic algorithms.",
        severity=Severity.CRITICAL,
        status=ComplianceStatus.COMPLIANT if is_fips_approved else ComplianceStatus.NON_COMPLIANT,
        evidence=f"Algorithm: {finding.algorithm}",
        recommendation="Use only FIPS-approved algorithms." if not is_fips_approved else "",
    ))

    # Minimum key sizes for FIPS
    if _is_asymmetric(finding) and ksize is not None:
        if "rsa" in alg:
            ok = ksize >= 2048
            rules.append(ComplianceRule(
                framework=ComplianceFramework.FIPS_140_3,
                rule_id="FIPS-RSA-SIZE",
                rule_name="RSA key size >= 2048 bits",
                description="FIPS 140-3 requires RSA keys of at least 2048 bits.",
                severity=Severity.HIGH,
                status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
                evidence=f"RSA key size {ksize} bits",
                recommendation="Upgrade to RSA-2048 or larger." if not ok else "",
            ))

    if _is_symmetric(finding) and ksize is not None:
        ok = ksize >= 128
        rules.append(ComplianceRule(
            framework=ComplianceFramework.FIPS_140_3,
            rule_id="FIPS-SYMM-SIZE",
            rule_name="Symmetric key size >= 128 bits",
            description="FIPS 140-3 requires symmetric keys of at least 128 bits.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Symmetric key size {ksize} bits",
            recommendation="Upgrade to AES-128 or larger." if not ok else "",
        ))

    # Approved modes of operation
    if _is_symmetric(finding):
        alg_l = alg
        ok_mode = any(m in alg_l for m in ("gcm", "ctr", "cbc", "ccm"))
        rules.append(ComplianceRule(
            framework=ComplianceFramework.FIPS_140_3,
            rule_id="FIPS-MODE",
            rule_name="Approved modes of operation",
            description="FIPS 140-3 requires approved modes of operation (GCM, CTR, CBC, CCM).",
            severity=Severity.MEDIUM,
            status=ComplianceStatus.COMPLIANT if ok_mode else ComplianceStatus.PARTIAL,
            evidence=f"Cipher: {finding.algorithm}",
            recommendation="Use an approved mode of operation (GCM, CTR, CBC, CCM)." if not ok_mode else "",
        ))

    # No deprecated algorithms
    deprecated = {"des", "3des", "md5", "sha1", "rc4", "rc2"}
    is_deprecated = any(d in alg for d in deprecated)
    rules.append(ComplianceRule(
        framework=ComplianceFramework.FIPS_140_3,
        rule_id="FIPS-NO-DEPRECATED",
        rule_name="No deprecated algorithms",
        description="FIPS 140-3 prohibits DES, 3DES, MD5, SHA-1, and RC4.",
        severity=Severity.CRITICAL,
        status=ComplianceStatus.NON_COMPLIANT if is_deprecated else ComplianceStatus.COMPLIANT,
        evidence=f"Algorithm: {finding.algorithm}",
        recommendation="Replace deprecated algorithm with a FIPS-approved alternative." if is_deprecated else "",
    ))

    return rules


def _eu_nis2_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []

    alg = _normalise_alg(finding.algorithm)
    ksize = _extract_key_size(finding)

    # Cryptographic measures for essential entities
    has_crypto = bool(alg)
    rules.append(ComplianceRule(
        framework=ComplianceFramework.EU_NIS2,
        rule_id="NIS2-CRYPTO-MEASURES",
        rule_name="Cryptographic measures for essential entities",
        description="EU NIS2 requires essential entities to implement cryptographic measures.",
        severity=Severity.HIGH,
        status=ComplianceStatus.COMPLIANT if has_crypto else ComplianceStatus.PARTIAL,
        evidence=f"Cryptography detected: {finding.algorithm}" if has_crypto else "No cryptographic algorithm detected",
        recommendation="Implement cryptographic controls for all assets." if not has_crypto else "",
    ))

    # State-of-the-art encryption
    weak_algorithms = {"des", "3des", "rc4", "md5", "sha1"}
    is_weak = any(w in alg for w in weak_algorithms)
    strong_algorithms = {"aes_256", "aes_192", "aes_128", "chacha20", "x25519", "x448"}
    is_strong = any(s in alg for s in strong_algorithms) or (ksize is not None and ksize >= 256)
    rules.append(ComplianceRule(
        framework=ComplianceFramework.EU_NIS2,
        rule_id="NIS2-STATE-OF-ART",
        rule_name="State-of-the-art encryption",
        description="EU NIS2 requires state-of-the-art encryption methods.",
        severity=Severity.HIGH,
        status=ComplianceStatus.COMPLIANT if (is_strong and not is_weak) else ComplianceStatus.NON_COMPLIANT,
        evidence=f"Algorithm: {finding.algorithm}, key size: {ksize}",
        recommendation="Use state-of-the-art encryption (AES-256, ChaCha20, etc.)." if is_weak or not is_strong else "",
    ))

    # Risk assessment for quantum threats
    quantum_safe = {"ml_kem", "ml_dsa", "slh_dsa", "falcon", "x25519", "x448", "ed25519", "ed448", "cshake", "kyber"}
    is_pq_safe = any(q in alg for q in quantum_safe)
    rules.append(ComplianceRule(
        framework=ComplianceFramework.EU_NIS2,
        rule_id="NIS2-QUANTUM",
        rule_name="Risk assessment for quantum threats",
        description="EU NIS2 mandates risk assessment and migration planning for quantum computing threats.",
        severity=Severity.MEDIUM,
        status=ComplianceStatus.COMPLIANT if is_pq_safe else ComplianceStatus.PARTIAL,
        evidence=f"Algorithm: {finding.algorithm}",
        recommendation="Conduct quantum threat risk assessment and plan migration to PQC." if not is_pq_safe else "",
    ))

    # Incident reporting for crypto failures
    rules.append(ComplianceRule(
        framework=ComplianceFramework.EU_NIS2,
        rule_id="NIS2-INCIDENT-REPORT",
        rule_name="Incident reporting for crypto failures",
        description="EU NIS2 requires timely reporting of significant cybersecurity incidents including crypto failures.",
        severity=Severity.LOW,
        status=ComplianceStatus.NOT_APPLICABLE,
        evidence="Incident reporting is an organisational control, not verifiable via automated scanning.",
        recommendation="Establish incident reporting procedures for cryptographic failures.",
    ))

    return rules


def _fisma_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)

    # FIPS 140-3 validated modules
    rules.append(ComplianceRule(
        framework=ComplianceFramework.FISMA,
        rule_id="FISMA-FIPS-MODULE",
        rule_name="FIPS 140-3 validated modules",
        description="FISMA requires the use of FIPS 140-3 validated cryptographic modules.",
        severity=Severity.CRITICAL,
        status=ComplianceStatus.PARTIAL,
        evidence="FIPS module validation status cannot be determined from algorithm metadata alone.",
        recommendation="Verify that the cryptographic module used has a current FIPS 140-3 certificate.",
    ))

    # NIST-recommended algorithms
    nist_approved = {
        "aes_128", "aes_192", "aes_256",
        "sha256", "sha384", "sha512",
        "rsa", "ecdsa", "ecdh",
    }
    is_approved = any(a in alg for a in nist_approved)
    rules.append(ComplianceRule(
        framework=ComplianceFramework.FISMA,
        rule_id="FISMA-NIST-ALG",
        rule_name="NIST-recommended algorithms",
        description="FISMA mandates the use of NIST-recommended cryptographic algorithms.",
        severity=Severity.HIGH,
        status=ComplianceStatus.COMPLIANT if is_approved else ComplianceStatus.NON_COMPLIANT,
        evidence=f"Algorithm: {finding.algorithm}",
        recommendation="Use only NIST-recommended algorithms." if not is_approved else "",
    ))

    # Key management procedures
    rules.append(ComplianceRule(
        framework=ComplianceFramework.FISMA,
        rule_id="FISMA-KEY-MGMT",
        rule_name="Key management procedures",
        description="FISMA requires documented key management procedures including generation, distribution, storage, and destruction.",
        severity=Severity.HIGH,
        status=ComplianceStatus.PARTIAL,
        evidence="Key management procedures require manual verification.",
        recommendation="Document and implement key lifecycle management procedures.",
    ))

    return rules


def _fedramp_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)
    ksize = _extract_key_size(finding)

    # FIPS 140-2/3 validated crypto modules
    rules.append(ComplianceRule(
        framework=ComplianceFramework.FEDRAMP,
        rule_id="FEDRAMP-FIPS-MODULE",
        rule_name="FIPS 140-2/3 validated crypto modules",
        description="FedRAMP requires FIPS 140-2 or FIPS 140-3 validated cryptographic modules.",
        severity=Severity.CRITICAL,
        status=ComplianceStatus.PARTIAL,
        evidence="FIPS module validation status cannot be determined from algorithm metadata alone.",
        recommendation="Verify FIPS 140-2/3 validation of the cryptographic module in use.",
    ))

    # NSA CNSA Suite algorithms
    cnsa_algorithms = {"aes_256", "sha_384", "sha384", "sha_512", "sha512", "rsa", "ecdsa"}
    is_cnsa = any(a in alg for a in cnsa_algorithms) or (ksize is not None and ksize >= 256)
    rules.append(ComplianceRule(
        framework=ComplianceFramework.FEDRAMP,
        rule_id="FEDRAMP-CNSA",
        rule_name="NSA CNSA Suite algorithms",
        description="FedRAMP recommends NSA CNSA Suite algorithms for high-impact systems.",
        severity=Severity.HIGH,
        status=ComplianceStatus.COMPLIANT if is_cnsa else ComplianceStatus.NON_COMPLIANT,
        evidence=f"Algorithm: {finding.algorithm}",
        recommendation="Use NSA CNSA Suite algorithms (AES-256, SHA-384/512)." if not is_cnsa else "",
    ))

    # TLS 1.2+ with approved cipher suites
    if _is_tls(finding):
        tls_ok = any(t in alg for t in ("tls_1_3", "tls_1_2", "tlsv13", "tlsv12"))
        rules.append(ComplianceRule(
            framework=ComplianceFramework.FEDRAMP,
            rule_id="FEDRAMP-TLS",
            rule_name="TLS 1.2+ with approved cipher suites",
            description="FedRAMP requires TLS 1.2 or higher with FIPS-approved cipher suites.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if tls_ok else ComplianceStatus.NON_COMPLIANT,
            evidence=f"TLS protocol: {finding.algorithm}",
            recommendation="Upgrade to TLS 1.2 or 1.3." if not tls_ok else "",
        ))

    return rules


def _cmmc_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)

    # CUI protection with approved algorithms
    approved_algorithms = {"aes_128", "aes_192", "aes_256", "sha256", "sha384", "sha512", "rsa", "ecdsa", "ecdh"}
    is_approved = any(a in alg for a in approved_algorithms)
    rules.append(ComplianceRule(
        framework=ComplianceFramework.CMMC,
        rule_id="CMMC-CUI-ALG",
        rule_name="CUI protection with approved algorithms",
        description="CMMC requires CUI to be protected using NIST-approved cryptographic algorithms.",
        severity=Severity.HIGH,
        status=ComplianceStatus.COMPLIANT if is_approved else ComplianceStatus.NON_COMPLIANT,
        evidence=f"Algorithm: {finding.algorithm}",
        recommendation="Use NIST-approved algorithms for CUI protection." if not is_approved else "",
    ))

    # Key management requirements
    rules.append(ComplianceRule(
        framework=ComplianceFramework.CMMC,
        rule_id="CMMC-KEY-MGMT",
        rule_name="Key management requirements",
        description="CMMC requires formal key management including secure generation, storage, and rotation.",
        severity=Severity.HIGH,
        status=ComplianceStatus.PARTIAL,
        evidence="Key management practices require manual verification.",
        recommendation="Implement and document key management lifecycle procedures.",
    ))

    # Audit trail for crypto operations
    rules.append(ComplianceRule(
        framework=ComplianceFramework.CMMC,
        rule_id="CMMC-AUDIT",
        rule_name="Audit trail for crypto operations",
        description="CMMC requires audit trails for cryptographic operations.",
        severity=Severity.MEDIUM,
        status=ComplianceStatus.PARTIAL,
        evidence="Audit trail verification requires organisational review.",
        recommendation="Enable and maintain audit logging for all cryptographic operations.",
    ))

    return rules


def _pci_dss_4_0_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)
    ksize = _extract_key_size(finding)

    # Req 12.3.3: Cryptographic inventory mandatory
    rules.append(ComplianceRule(
        framework=ComplianceFramework.PCI_DSS_4_0,
        rule_id="PCI-DSS-12.3.3",
        rule_name="Cryptographic inventory mandatory",
        description="PCI DSS 4.0 Req 12.3.3 requires maintaining an inventory of all cryptographic algorithms and keys (effective 2025-03).",
        severity=Severity.HIGH,
        status=ComplianceStatus.PARTIAL,
        evidence=f"Algorithm detected: {finding.algorithm}",
        recommendation="Maintain a documented cryptographic inventory covering all algorithms, keys, and their locations.",
    ))

    # RSA >= 2048 for encryption
    if "rsa" in alg or _normalise_alg(finding.key_type) == "rsa":
        if ksize is not None:
            ok = ksize >= 2048
            rules.append(ComplianceRule(
                framework=ComplianceFramework.PCI_DSS_4_0,
                rule_id="PCI-DSS-RSA-ENCRYPT",
                rule_name="RSA encryption key size >= 2048 bits",
                description="PCI DSS 4.0 requires RSA keys for encryption to be at least 2048 bits.",
                severity=Severity.HIGH,
                status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
                evidence=f"RSA key size {ksize} bits",
                recommendation="Upgrade to RSA-2048 or larger." if not ok else "",
            ))

    # No MD5, SHA-1 for digital signatures
    if _is_hash(finding):
        forbidden = {"md5", "sha1"}
        is_forbidden = any(f in alg for f in forbidden)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.PCI_DSS_4_0,
            rule_id="PCI-DSS-SIG-HASH",
            rule_name="No MD5 or SHA-1 for digital signatures",
            description="PCI DSS 4.0 prohibits MD5 and SHA-1 for digital signatures.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.NON_COMPLIANT if is_forbidden else ComplianceStatus.COMPLIANT,
            evidence=f"Hash algorithm: {finding.algorithm}",
            recommendation="Replace MD5/SHA-1 with SHA-256 or stronger for signatures." if is_forbidden else "",
        ))

    # AES-128+ or 3DES minimum for symmetric
    if _is_symmetric(finding):
        is_aes_ok = "aes_128" in alg or "aes_192" in alg or "aes_256" in alg
        is_3des = "3des" in alg or "triple_des" in alg
        is_forbidden = any(f in alg for f in ("des", "rc4"))
        ok = is_aes_ok or (is_3des and not is_forbidden)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.PCI_DSS_4_0,
            rule_id="PCI-DSS-SYMM",
            rule_name="AES-128+ or 3DES minimum for symmetric encryption",
            description="PCI DSS 4.0 requires AES-128 or stronger, or 3DES as a minimum for symmetric encryption.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Symmetric algorithm: {finding.algorithm}, key size: {ksize}",
            recommendation="Migrate to AES-128 or AES-256." if not ok else "",
        ))

    # TLS 1.2+ required
    if _is_tls(finding):
        tls_ok = any(t in alg for t in ("tls_1_3", "tls_1_2", "tlsv13", "tlsv12"))
        rules.append(ComplianceRule(
            framework=ComplianceFramework.PCI_DSS_4_0,
            rule_id="PCI-DSS-TLS",
            rule_name="TLS 1.2 or higher required",
            description="PCI DSS 4.0 requires TLS 1.2 or higher for all cardholder data transmissions.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if tls_ok else ComplianceStatus.NON_COMPLIANT,
            evidence=f"TLS protocol: {finding.algorithm}",
            recommendation="Upgrade to TLS 1.2 or 1.3." if not tls_ok else "",
        ))

    return rules


def _bsi_tr_02102_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)
    ksize = _extract_key_size(finding)

    # RSA >= 2048 or ECDSA >= P-256
    if "rsa" in alg or _normalise_alg(finding.key_type) == "rsa":
        if ksize is not None:
            ok = ksize >= 2048
            rules.append(ComplianceRule(
                framework=ComplianceFramework.BSI_TR_02102,
                rule_id="BSI-RSA-SIZE",
                rule_name="RSA key size >= 2048 bits",
                description="BSI TR-02102-1 requires RSA keys of at least 2048 bits.",
                severity=Severity.HIGH,
                status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
                evidence=f"RSA key size {ksize} bits",
                recommendation="Upgrade to RSA-2048 or larger." if not ok else "",
            ))

    if "ecdsa" in alg or "ec" in _normalise_alg(finding.key_type or ""):
        weak_curves = {"p_192", "p192", "secp192r1", "sect163"}
        is_weak = any(w in alg for w in weak_curves)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.BSI_TR_02102,
            rule_id="BSI-ECDSA-SIZE",
            rule_name="ECDSA key size >= P-256",
            description="BSI TR-02102-1 requires ECDSA keys to be at least P-256.",
            severity=Severity.HIGH,
            status=ComplianceStatus.NON_COMPLIANT if is_weak else ComplianceStatus.COMPLIANT,
            evidence=f"ECDSA curve: {finding.algorithm}",
            recommendation="Upgrade to P-256 or stronger curve." if is_weak else "",
        ))

    # SHA-256+ for signatures
    if _is_hash(finding):
        ok = any(s in alg for s in ("sha256", "sha_256", "sha384", "sha_384", "sha512", "sha_512", "sha3_256", "sha3_512"))
        weak = any(f in alg for f in ("md5", "sha1"))
        rules.append(ComplianceRule(
            framework=ComplianceFramework.BSI_TR_02102,
            rule_id="BSI-HASH",
            rule_name="SHA-256 or stronger for signatures",
            description="BSI TR-02102-1 requires SHA-256 or stronger for hashing and digital signatures.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if ok else (ComplianceStatus.NON_COMPLIANT if weak else ComplianceStatus.PARTIAL),
            evidence=f"Hash algorithm: {finding.algorithm}",
            recommendation="Migrate to SHA-256 or stronger." if not ok else "",
        ))

    # AES-128+ or ChaCha20-Poly1305
    if _is_symmetric(finding):
        is_aes_ok = "aes_128" in alg or "aes_192" in alg or "aes_256" in alg
        is_chacha = "chacha20" in alg or "chacha" in alg
        ok = is_aes_ok or is_chacha
        rules.append(ComplianceRule(
            framework=ComplianceFramework.BSI_TR_02102,
            rule_id="BSI-SYMM",
            rule_name="AES-128+ or ChaCha20-Poly1305 for symmetric encryption",
            description="BSI TR-02102-1 requires AES-128 or stronger, or ChaCha20-Poly1305.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Symmetric algorithm: {finding.algorithm}, key size: {ksize}",
            recommendation="Migrate to AES-128/256 or ChaCha20-Poly1305." if not ok else "",
        ))

    # Post-quantum alternatives (FrodoKEM, Classic McEliece, HQC)
    if _is_key_exchange(finding):
        pq_approved = {"frodo", "classic_mceliece", "mceliece", "hqc"}
        is_pq_approved = any(p in alg for p in pq_approved)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.BSI_TR_02102,
            rule_id="BSI-PQ-ALTS",
            rule_name="Post-quantum key exchange alternatives",
            description="BSI TR-02102-1 approves FrodoKEM, Classic McEliece, and HQC as post-quantum key exchange alternatives.",
            severity=Severity.MEDIUM,
            status=ComplianceStatus.COMPLIANT if is_pq_approved else ComplianceStatus.PARTIAL,
            evidence=f"Key exchange algorithm: {finding.algorithm}",
            recommendation="Consider FrodoKEM, Classic McEliece, or HQC for post-quantum key exchange." if not is_pq_approved else "",
        ))

    # TLS 1.2+ required
    if _is_tls(finding):
        tls_ok = any(t in alg for t in ("tls_1_3", "tls_1_2", "tlsv13", "tlsv12"))
        rules.append(ComplianceRule(
            framework=ComplianceFramework.BSI_TR_02102,
            rule_id="BSI-TLS",
            rule_name="TLS 1.2 or higher required",
            description="BSI TR-02102-1 requires TLS 1.2 or higher.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if tls_ok else ComplianceStatus.NON_COMPLIANT,
            evidence=f"TLS protocol: {finding.algorithm}",
            recommendation="Upgrade to TLS 1.2 or 1.3." if not tls_ok else "",
        ))

    return rules


def _ncsc_uk_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)
    ksize = _extract_key_size(finding)

    # All NIST PQC approved (ML-KEM, ML-DSA, SLH-DSA)
    if _is_key_exchange(finding) or _is_asymmetric(finding):
        pq_approved = {"ml_kem", "ml_dsa", "slh_dsa"}
        is_pq_approved = any(p in alg for p in pq_approved)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.NCSC_UK,
            rule_id="NCSC-PQ-ALG",
            rule_name="NIST PQC algorithms approved (ML-KEM, ML-DSA, SLH-DSA)",
            description="NCSC UK approves NIST PQC algorithms: ML-KEM, ML-DSA, and SLH-DSA.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if is_pq_approved else ComplianceStatus.PARTIAL,
            evidence=f"Algorithm: {finding.algorithm}",
            recommendation="Plan migration to ML-KEM, ML-DSA, or SLH-DSA per NCSC guidance." if not is_pq_approved else "",
        ))

    # Phased deadlines: 2028/2031/2035
    rules.append(ComplianceRule(
        framework=ComplianceFramework.NCSC_UK,
        rule_id="NCSC-PHASED-DEADLINE",
        rule_name="PQC migration phased deadlines (2028/2031/2035)",
        description="NCSC UK mandates PQC migration in phases: TLS/web by 2028, critical infrastructure by 2031, all systems by 2035.",
        severity=Severity.MEDIUM,
        status=ComplianceStatus.PARTIAL,
        evidence="Timeline compliance requires organisational planning assessment.",
        recommendation="Develop a phased PQC migration plan aligned with NCSC UK deadlines.",
    ))

    # RSA >= 3072 or ECDSA >= P-384 for signatures
    if "rsa" in alg or _normalise_alg(finding.key_type) == "rsa":
        if ksize is not None:
            ok = ksize >= 3072
            rules.append(ComplianceRule(
                framework=ComplianceFramework.NCSC_UK,
                rule_id="NCSC-RSA-SIGN",
                rule_name="RSA signature key size >= 3072 bits",
                description="NCSC UK requires RSA keys for signatures to be at least 3072 bits.",
                severity=Severity.HIGH,
                status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
                evidence=f"RSA key size {ksize} bits",
                recommendation="Upgrade to RSA-3072 or larger for digital signatures." if not ok else "",
            ))

    if "ecdsa" in alg or "ec" in _normalise_alg(finding.key_type or ""):
        weak_curves = {"p_192", "p192", "secp192r1", "p_256", "p256"}
        is_weak = any(w in alg for w in weak_curves)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.NCSC_UK,
            rule_id="NCSC-ECDSA-SIGN",
            rule_name="ECDSA signature key size >= P-384",
            description="NCSC UK requires ECDSA keys for signatures to be at least P-384.",
            severity=Severity.HIGH,
            status=ComplianceStatus.NON_COMPLIANT if is_weak else ComplianceStatus.COMPLIANT,
            evidence=f"ECDSA curve: {finding.algorithm}",
            recommendation="Upgrade to P-384 or stronger curve for digital signatures." if is_weak else "",
        ))

    # No MD5, SHA-1
    if _is_hash(finding):
        weak = {"md5", "sha1"}
        is_weak = any(w in alg for w in weak)
        rules.append(ComplianceRule(
            framework=ComplianceFramework.NCSC_UK,
            rule_id="NCSC-NO-WEAK-HASH",
            rule_name="No MD5 or SHA-1 allowed",
            description="NCSC UK prohibits MD5 and SHA-1 for all cryptographic uses.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.NON_COMPLIANT if is_weak else ComplianceStatus.COMPLIANT,
            evidence=f"Hash algorithm: {finding.algorithm}",
            recommendation="Replace MD5/SHA-1 with SHA-256 or stronger." if is_weak else "",
        ))

    return rules


def _asd_ism_rules(finding: AssetFinding) -> list[ComplianceRule]:
    rules: list[ComplianceRule] = []
    alg = _normalise_alg(finding.algorithm)

    # ML-KEM-1024 + ML-DSA-87 only (strictest)
    if _is_key_exchange(finding) or _is_asymmetric(finding):
        ok_kem = "ml_kem_1024" in alg or "mlkem1024" in alg
        rules.append(ComplianceRule(
            framework=ComplianceFramework.ASD_ISM,
            rule_id="ASD-KEM",
            rule_name="ML-KEM-1024 required for key exchange",
            description="ASD ISM requires ML-KEM-1024 as the sole post-quantum key encapsulation mechanism.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if ok_kem else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Key exchange algorithm: {finding.algorithm}",
            recommendation="Migrate to ML-KEM-1024 for key encapsulation." if not ok_kem else "",
        ))

        ok_sig = "ml_dsa_87" in alg or "mldsa87" in alg
        rules.append(ComplianceRule(
            framework=ComplianceFramework.ASD_ISM,
            rule_id="ASD-SIG",
            rule_name="ML-DSA-87 required for digital signatures",
            description="ASD ISM requires ML-DSA-87 as the sole post-quantum digital signature algorithm.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if ok_sig else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Signature algorithm: {finding.algorithm}",
            recommendation="Migrate to ML-DSA-87 for digital signatures." if not ok_sig else "",
        ))

    # Classical asymmetric cease 2030
    classical_asymmetric = {"rsa", "ecdsa", "dsa", "ed25519", "ed448"}
    is_classical = any(c in alg for c in classical_asymmetric)
    if is_classical:
        rules.append(ComplianceRule(
            framework=ComplianceFramework.ASD_ISM,
            rule_id="ASD-CLASSICAL-CEASE",
            rule_name="Classical asymmetric algorithms cease 2030",
            description="ASD ISM mandates ceasing use of classical asymmetric algorithms (RSA, ECDSA, etc.) by 2030.",
            severity=Severity.HIGH,
            status=ComplianceStatus.PARTIAL,
            evidence=f"Classical algorithm detected: {finding.algorithm}",
            recommendation="Plan migration to ML-KEM-1024 and ML-DSA-87 before 2030 deadline.",
        ))

    # AES-256 only
    if _is_symmetric(finding):
        ok = "aes_256" in alg
        rules.append(ComplianceRule(
            framework=ComplianceFramework.ASD_ISM,
            rule_id="ASD-SYMM",
            rule_name="AES-256 only for symmetric encryption",
            description="ASD ISM requires AES-256 exclusively for symmetric encryption.",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.COMPLIANT if ok else ComplianceStatus.NON_COMPLIANT,
            evidence=f"Symmetric algorithm: {finding.algorithm}",
            recommendation="Migrate to AES-256 for all symmetric encryption." if not ok else "",
        ))

    # SHA-256+ only
    if _is_hash(finding):
        ok = any(s in alg for s in ("sha256", "sha_256", "sha384", "sha_384", "sha512", "sha_512", "sha3_256", "sha3_512"))
        weak = any(f in alg for f in ("md5", "sha1"))
        rules.append(ComplianceRule(
            framework=ComplianceFramework.ASD_ISM,
            rule_id="ASD-HASH",
            rule_name="SHA-256 or stronger only",
            description="ASD ISM requires SHA-256 or stronger hashing algorithms.",
            severity=Severity.HIGH,
            status=ComplianceStatus.COMPLIANT if ok else (ComplianceStatus.NON_COMPLIANT if weak else ComplianceStatus.PARTIAL),
            evidence=f"Hash algorithm: {finding.algorithm}",
            recommendation="Migrate to SHA-256 or stronger." if not ok else "",
        ))

    return rules


_FRAMEWORK_RULE_MAP: dict[
    ComplianceFramework,
    tuple[ComplianceFramework, ...],
] = {}


# ---------------------------------------------------------------------------
# ComplianceEngine
# ---------------------------------------------------------------------------


class ComplianceReport(BaseModel):
    """Simplified compliance report returned by ComplianceEngine.check()."""
    framework: ComplianceFramework
    is_compliant: bool
    violations: list[str] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0, le=100)
    rules: list[ComplianceRule] = Field(default_factory=list)


class ComplianceEngine:
    """Evaluates a single AssetFinding against a compliance framework."""

    _evaluators = {
        ComplianceFramework.NIST_SP_800_131A: _nist_800_131a_rules,
        ComplianceFramework.CNSA_2_0: _cnsa_2_0_rules,
        ComplianceFramework.FIPS_140_3: _fips_140_3_rules,
        ComplianceFramework.EU_NIS2: _eu_nis2_rules,
        ComplianceFramework.FISMA: _fisma_rules,
        ComplianceFramework.FEDRAMP: _fedramp_rules,
        ComplianceFramework.CMMC: _cmmc_rules,
        ComplianceFramework.PCI_DSS_4_0: _pci_dss_4_0_rules,
        ComplianceFramework.BSI_TR_02102: _bsi_tr_02102_rules,
        ComplianceFramework.NCSC_UK: _ncsc_uk_rules,
        ComplianceFramework.ASD_ISM: _asd_ism_rules,
    }

    def __init__(self, frameworks: list[ComplianceFramework] | None = None):
        self.frameworks = frameworks or list(self._evaluators.keys())

    def evaluate(self, finding: AssetFinding, framework: ComplianceFramework) -> ComplianceResult:
        """Evaluate *finding* against *framework* and return a ComplianceResult."""
        evaluator = self._evaluators.get(framework)
        if evaluator is None:
            raise ValueError(f"Unsupported compliance framework: {framework}")

        rules = evaluator(finding)

        total = len(rules)
        compliant = sum(1 for r in rules if r.status == ComplianceStatus.COMPLIANT)
        non_compliant = sum(1 for r in rules if r.status == ComplianceStatus.NON_COMPLIANT)
        partial = sum(1 for r in rules if r.status == ComplianceStatus.PARTIAL)
        not_applicable = sum(1 for r in rules if r.status == ComplianceStatus.NOT_APPLICABLE)

        scoreable = total - not_applicable
        if scoreable > 0:
            score = round(
                (compliant * 100 + partial * 50) / scoreable,
                2,
            )
        else:
            score = 100.0

        return ComplianceResult(
            framework=framework,
            total_rules=total,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            partial_count=partial,
            score=min(score, 100.0),
            rules=rules,
        )

    def check(self, finding: AssetFinding) -> ComplianceReport:
        """Check finding against all configured frameworks. Returns simplified report."""
        all_violations: list[str] = []
        all_rules: list[ComplianceRule] = []
        any_compliant = True
        total_score = 0.0

        for framework in self.frameworks:
            result = self.evaluate(finding, framework)
            for rule in result.rules:
                all_rules.append(rule)
                if rule.status == ComplianceStatus.NON_COMPLIANT:
                    all_violations.append(f"[{framework.value}] {rule.rule_name}: {rule.evidence}")
                    any_compliant = False
            total_score += result.score

        avg_score = total_score / len(self.frameworks) if self.frameworks else 100.0

        return ComplianceReport(
            framework=self.frameworks[0] if self.frameworks else ComplianceFramework.NIST_SP_800_131A,
            is_compliant=any_compliant and len(all_violations) == 0,
            violations=all_violations,
            score=avg_score,
            rules=all_rules,
        )
