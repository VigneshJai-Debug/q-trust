from __future__ import annotations

from datetime import date, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from .models import AssetFinding


class QuantumVulnerability(str, Enum):
    BROKEN = "broken"
    WEAKENED = "weakened"
    SAFE = "safe"
    PQC_READY = "pqc_ready"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


ALGORITHM_VULNERABILITY_DB: Dict[str, QuantumVulnerability] = {
    # Broken by Shor's algorithm
    "RSA": QuantumVulnerability.BROKEN,
    "RSA-1024": QuantumVulnerability.BROKEN,
    "RSA-2048": QuantumVulnerability.BROKEN,
    "RSA-4096": QuantumVulnerability.BROKEN,
    "ECDSA": QuantumVulnerability.BROKEN,
    "ECDSA-P256": QuantumVulnerability.BROKEN,
    "ECDSA-P384": QuantumVulnerability.BROKEN,
    "ECDSA-P521": QuantumVulnerability.BROKEN,
    "ECDH": QuantumVulnerability.BROKEN,
    "ECDH-P256": QuantumVulnerability.BROKEN,
    "ECDH-P384": QuantumVulnerability.BROKEN,
    "ECDH-P521": QuantumVulnerability.BROKEN,
    "DSA": QuantumVulnerability.BROKEN,
    "Ed25519": QuantumVulnerability.BROKEN,
    "Ed448": QuantumVulnerability.BROKEN,
    "DH": QuantumVulnerability.BROKEN,
    "DH-2048": QuantumVulnerability.BROKEN,
    "DH-4096": QuantumVulnerability.BROKEN,
    "X25519": QuantumVulnerability.BROKEN,
    "X448": QuantumVulnerability.BROKEN,
    # Weakened by Grover's algorithm
    "AES-128": QuantumVulnerability.WEAKENED,
    "3DES": QuantumVulnerability.WEAKENED,
    "DES": QuantumVulnerability.WEAKENED,
    "HMAC-MD5": QuantumVulnerability.WEAKENED,
    # Safe symmetric and hashing algorithms
    "AES-256": QuantumVulnerability.SAFE,
    "AES-192": QuantumVulnerability.SAFE,
    "ChaCha20-Poly1305": QuantumVulnerability.SAFE,
    "SHA-256": QuantumVulnerability.SAFE,
    "SHA-384": QuantumVulnerability.SAFE,
    "SHA-512": QuantumVulnerability.SAFE,
    "SHA3-256": QuantumVulnerability.SAFE,
    "SHA3-384": QuantumVulnerability.SAFE,
    "SHA3-512": QuantumVulnerability.SAFE,
    "HMAC-SHA256": QuantumVulnerability.SAFE,
    "HMAC-SHA384": QuantumVulnerability.SAFE,
    "HMAC-SHA512": QuantumVulnerability.SAFE,
    # Post-quantum cryptography ready
    "ML-KEM-512": QuantumVulnerability.PQC_READY,
    "ML-KEM-768": QuantumVulnerability.PQC_READY,
    "ML-KEM-1024": QuantumVulnerability.PQC_READY,
    "ML-DSA-44": QuantumVulnerability.PQC_READY,
    "ML-DSA-65": QuantumVulnerability.PQC_READY,
    "ML-DSA-87": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA2-128s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA2-128f": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA2-192s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA2-192f": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA2-256s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA2-256f": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA3-128s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA3-128f": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA3-192s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA3-192f": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA3-256s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-SHA3-256f": QuantumVulnerability.PQC_READY,
    "HQC-128": QuantumVulnerability.PQC_READY,
    "HQC-192": QuantumVulnerability.PQC_READY,
    "HQC-256": QuantumVulnerability.PQC_READY,
    "FALCON-512": QuantumVulnerability.PQC_READY,
    "FALCON-1024": QuantumVulnerability.PQC_READY,
    "CRYSTALS-DILITHIUM": QuantumVulnerability.PQC_READY,
    "CRYSTALS-KYBER": QuantumVulnerability.PQC_READY,
}

NIST_800_131A_DEPRECATION: Dict[str, int] = {
    "RSA-1024": 2030,
    "RSA-2048": 2030,
    "ECDSA-P256": 2030,
    "ECDSA-P384": 2030,
    "SHA-1": 2030,
    "3DES": 2030,
    "DES": 2030,
    "RC4": 2030,
    "RSA": 2035,
    "RSA-4096": 2035,
    "ECDSA": 2035,
    "ECDSA-P521": 2035,
    "DSA": 2035,
}

CNSA2_ALLOWED_ALGORITHMS: set[str] = {
    "ML-KEM-1024",
    "ML-DSA-87",
    "SLH-DSA-SHA2-256s",
    "AES-256",
    "SHA-384",
    "SHA-512",
    "SHA3-384",
    "SHA3-512",
    "HMAC-SHA384",
    "HMAC-SHA512",
}

# Case-normalized view of CNSA2_ALLOWED_ALGORITHMS so lookups are uppercase-safe
# regardless of how the caller spells the algorithm.
_CNSA2_ALLOWED_UPPER: frozenset[str] = frozenset(
    algo.upper() for algo in CNSA2_ALLOWED_ALGORITHMS
)

# Algorithm families that are broken by Shor's algorithm regardless of key size.
_ASYMMETRIC_FAMILY_MARKERS: tuple[str, ...] = (
    "RSA",
    "ECDSA",
    "ECDH",
    "ED25519",
    "ED448",
    "X25519",
    "X448",
    "DSA",
    "DH",
)

# Symmetric algorithm markers where key size does affect post-quantum strength
# (Grover's algorithm halves the effective security bits).
_SYMMETRIC_KEYSIZE_MARKERS: tuple[str, ...] = ("AES", "CHACHA20")


def _normalize_algorithm_name(algorithm: str) -> str:
    return algorithm.upper().replace(" ", "").replace("_", "-")


class RiskScore(BaseModel):
    quantum_vulnerability: QuantumVulnerability
    nist_800_131a_compliant: bool
    cnsa2_compliant: bool
    hndl_exposure_score: float = Field(ge=0, le=100)
    overall_risk_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    recommended_action: str
    recommended_replacement: str

    @property
    def value(self) -> float:
        return self.overall_risk_score / 100.0


_NORMALIZED_VULNERABILITY_DB: Dict[str, QuantumVulnerability] = {
    _normalize_algorithm_name(k): v for k, v in ALGORITHM_VULNERABILITY_DB.items()
}


def _is_asymmetric(algo_upper: str) -> bool:
    return any(marker in algo_upper for marker in _ASYMMETRIC_FAMILY_MARKERS)


def _apply_symmetric_key_size(
    vuln: QuantumVulnerability, algo_upper: str, key_size: int | None
) -> QuantumVulnerability:
    """Apply key-size based adjustment for symmetric algorithms only.

    Quantum vulnerability of asymmetric algorithms (RSA, ECDSA, ECDH, DH, DSA,
    Ed*, X*) depends ONLY on the algorithm family -- Shor's algorithm breaks
    them at any key size -- so no size-based downgrade is ever applied there.
    """
    if key_size is None:
        return vuln
    if any(marker in algo_upper for marker in _SYMMETRIC_KEYSIZE_MARKERS):
        if key_size < 256:
            return QuantumVulnerability.WEAKENED
        return QuantumVulnerability.SAFE
    return vuln


def _lookup_vulnerability(algorithm: str, key_size: int | None = None) -> QuantumVulnerability:
    algo_upper = _normalize_algorithm_name(algorithm)

    if algo_upper in _NORMALIZED_VULNERABILITY_DB:
        vuln = _NORMALIZED_VULNERABILITY_DB[algo_upper]
    else:
        vuln = QuantumVulnerability.SAFE
        for key, value in ALGORITHM_VULNERABILITY_DB.items():
            normalized_key = _normalize_algorithm_name(key)
            if normalized_key in algo_upper or algo_upper in normalized_key:
                vuln = value
                break

    if _is_asymmetric(algo_upper):
        # Shor's algorithm breaks these regardless of key size; never soften.
        return vuln
    return _apply_symmetric_key_size(vuln, algo_upper, key_size)


def _check_nist_800_131a(algorithm: str, key_size: Optional[int] = None) -> Tuple[bool, Optional[int]]:
    algo_upper = algorithm.upper().replace(" ", "")
    current_year = date.today().year
    if algo_upper in NIST_800_131A_DEPRECATION:
        deadline = NIST_800_131A_DEPRECATION[algo_upper]
        return current_year < deadline, deadline
    if key_size is not None:
        if "RSA" in algo_upper and key_size < 2048:
            return current_year < 2030, 2030
        if "ECDSA" in algo_upper and key_size < 384:
            return current_year < 2030, 2030
    return True, None


def _check_cnsa2(algorithm: str) -> bool:
    # Uppercase-safe lookup on both sides so caller casing never matters.
    return _normalize_algorithm_name(algorithm) in _CNSA2_ALLOWED_UPPER


def _calculate_hndl_score(
    vulnerability: QuantumVulnerability,
    sensitivity: int = 3,
    lifetime_years: int = 2,
    exposure_years: float = 0.0,
) -> float:
    vuln_weights = {
        QuantumVulnerability.BROKEN: 5,
        QuantumVulnerability.WEAKENED: 3,
        QuantumVulnerability.SAFE: 0,
        QuantumVulnerability.PQC_READY: 0,
    }
    v = vuln_weights.get(vulnerability, 0)
    s = max(0, min(5, sensitivity))
    l = max(0, min(5, lifetime_years))
    e = max(0.0, exposure_years)
    score = v * s * l * (1 + e / 10)
    return min(100.0, score * (100 / 125))


def _determine_risk_level(score: float) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    elif score >= 60:
        return RiskLevel.HIGH
    elif score >= 40:
        return RiskLevel.MEDIUM
    elif score > 0:
        return RiskLevel.LOW
    return RiskLevel.NONE


def _get_recommended_action(
    vulnerability: QuantumVulnerability,
    nist_compliant: bool,
    cnsa2_compliant: bool,
    risk_level: RiskLevel,
) -> str:
    if vulnerability == QuantumVulnerability.PQC_READY:
        return "No action required - algorithm is post-quantum secure"
    if vulnerability == QuantumVulnerability.SAFE and nist_compliant and cnsa2_compliant:
        return "Monitor for future deprecation updates"
    actions = []
    if vulnerability == QuantumVulnerability.BROKEN:
        actions.append("URGENT: Replace with PQC algorithm before quantum computers arrive")
    elif vulnerability == QuantumVulnerability.WEAKENED:
        actions.append("Upgrade to larger key size or equivalent PQC algorithm")
    if not nist_compliant:
        actions.append("Update to meet NIST SP 800-131A compliance deadline")
    if not cnsa2_compliant:
        actions.append("Migrate to CNSA 2.0 approved algorithm suite")
    return "; ".join(actions) if actions else "Review and update algorithm"


def _get_recommended_replacement(algorithm: str, vulnerability: QuantumVulnerability) -> str:
    algo_upper = algorithm.upper()
    if vulnerability == QuantumVulnerability.BROKEN:
        if "RSA" in algo_upper or "DSA" in algo_upper:
            return "ML-DSA-87 or ML-KEM-1024"
        if "ECDSA" in algo_upper or "ECDH" in algo_upper or "X25519" in algo_upper or "X448" in algo_upper:
            return "ML-KEM-1024 for key exchange, ML-DSA-87 for signatures"
        if "ED25519" in algo_upper or "ED448" in algo_upper:
            return "ML-DSA-87"
        return "ML-KEM-1024 + ML-DSA-87"
    if vulnerability == QuantumVulnerability.WEAKENED:
        if "AES-128" in algo_upper:
            return "AES-256"
        if "3DES" in algo_upper or "DES" in algo_upper:
            return "AES-256-GCM"
        return "AES-256"
    return "No replacement needed"


def calculate_risk_score(
    finding: AssetFinding,
    data_sensitivity: int = 3,
    data_lifetime_years: int = 2,
) -> RiskScore:
    algorithm = finding.algorithm or "unknown"
    key_size = finding.key_size

    vulnerability = _lookup_vulnerability(algorithm, key_size)
    nist_compliant, nist_deadline = _check_nist_800_131a(algorithm, key_size)
    cnsa2_compliant = _check_cnsa2(algorithm)

    exposure_years = 0.0
    if finding.first_seen:
        try:
            first_seen_date = date.fromisoformat(finding.first_seen)
            exposure_years = (date.today() - first_seen_date).days / 365.25
        except (ValueError, TypeError):
            pass

    hndl_score = _calculate_hndl_score(
        vulnerability, data_sensitivity, data_lifetime_years, exposure_years
    )

    vuln_penalties = {
        QuantumVulnerability.BROKEN: 50,
        QuantumVulnerability.WEAKENED: 25,
        QuantumVulnerability.SAFE: 5,
        QuantumVulnerability.PQC_READY: 0,
    }
    penalty = vuln_penalties.get(vulnerability, 5)
    if not nist_compliant:
        penalty += 15
    if not cnsa2_compliant:
        penalty += 10
    overall_score = min(100.0, hndl_score + penalty)

    risk_level = _determine_risk_level(overall_score)
    recommended_action = _get_recommended_action(vulnerability, nist_compliant, cnsa2_compliant, risk_level)
    recommended_replacement = _get_recommended_replacement(algorithm, vulnerability)

    return RiskScore(
        quantum_vulnerability=vulnerability,
        nist_800_131a_compliant=nist_compliant,
        cnsa2_compliant=cnsa2_compliant,
        hndl_exposure_score=round(hndl_score, 2),
        overall_risk_score=round(overall_score, 2),
        risk_level=risk_level,
        recommended_action=recommended_action,
        recommended_replacement=recommended_replacement,
    )
