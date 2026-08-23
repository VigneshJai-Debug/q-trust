"""Risk scoring and compliance checking for quantum-safe migration."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class QuantumVulnerability(str, Enum):
    """Quantum vulnerability status of a cryptographic algorithm."""
    BROKEN = "BROKEN"
    WEAKENED = "WEAKENED"
    SAFE = "SAFE"
    PQC_READY = "PQC_READY"


class RiskScore(BaseModel):
    """Risk assessment result for a single cryptographic finding."""
    quantum_vulnerability: QuantumVulnerability
    nist_800_131a_compliant: bool
    cnsa2_compliant: bool
    hndl_exposure_score: float = Field(ge=0.0, le=1.0)
    overall_risk_score: float = Field(ge=0.0, le=10.0)
    risk_level: str = Field(pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW|NONE)$")
    recommended_action: str
    recommended_replacement: str | None = None


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    NIST_SP_800_131A = "NIST_SP_800_131A"
    CNSA_2_0 = "CNSA_2_0"
    FIPS_140_3 = "FIPS_140_3"
    EU_NIS2 = "EU_NIS2"
    FISMA = "FISMA"
    FEDRAMP = "FEDRAMP"
    CMMC = "CMMC"


class ComplianceRule(BaseModel):
    """Individual compliance rule check result."""
    framework: ComplianceFramework
    rule_id: str
    rule_name: str
    description: str
    severity: str
    status: str
    evidence: str
    recommendation: str


class ComplianceResult(BaseModel):
    """Aggregated compliance evaluation result for a framework."""
    framework: ComplianceFramework
    total_rules: int
    compliant_count: int
    non_compliant_count: int
    partial_count: int
    score: float = Field(ge=0.0, le=100.0)
    rules: list[ComplianceRule]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


_ALGORITHM_VULNERABILITY_DB: dict[str, QuantumVulnerability] = {
    "RSA": QuantumVulnerability.BROKEN,
    "RSA-2048": QuantumVulnerability.BROKEN,
    "RSA-3072": QuantumVulnerability.BROKEN,
    "RSA-4096": QuantumVulnerability.BROKEN,
    "ECDSA": QuantumVulnerability.BROKEN,
    "ECDSA-P256": QuantumVulnerability.BROKEN,
    "ECDSA-P384": QuantumVulnerability.BROKEN,
    "Ed25519": QuantumVulnerability.WEAKENED,
    "Ed448": QuantumVulnerability.WEAKENED,
    "DH": QuantumVulnerability.BROKEN,
    "DH-2048": QuantumVulnerability.BROKEN,
    "ECDH": QuantumVulnerability.BROKEN,
    "ECDH-P256": QuantumVulnerability.BROKEN,
    "ECDH-P384": QuantumVulnerability.BROKEN,
    "AES-128": QuantumVulnerability.WEAKENED,
    "AES-192": QuantumVulnerability.SAFE,
    "AES-256": QuantumVulnerability.SAFE,
    "ChaCha20-Poly1305": QuantumVulnerability.SAFE,
    "SHA-256": QuantumVulnerability.WEAKENED,
    "SHA-384": QuantumVulnerability.SAFE,
    "SHA-512": QuantumVulnerability.SAFE,
    "SHA3-256": QuantumVulnerability.SAFE,
    "SHA3-512": QuantumVulnerability.SAFE,
    "ML-KEM-512": QuantumVulnerability.PQC_READY,
    "ML-KEM-768": QuantumVulnerability.PQC_READY,
    "ML-KEM-1024": QuantumVulnerability.PQC_READY,
    "ML-DSA-44": QuantumVulnerability.PQC_READY,
    "ML-DSA-65": QuantumVulnerability.PQC_READY,
    "ML-DSA-87": QuantumVulnerability.PQC_READY,
    "SLH-DSA-128s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-128f": QuantumVulnerability.PQC_READY,
    "SLH-DSA-192s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-192f": QuantumVulnerability.PQC_READY,
    "SLH-DSA-256s": QuantumVulnerability.PQC_READY,
    "SLH-DSA-256f": QuantumVulnerability.PQC_READY,
    "FrodoKEM-640": QuantumVulnerability.PQC_READY,
    "FrodoKEM-976": QuantumVulnerability.PQC_READY,
    "FrodoKEM-1344": QuantumVulnerability.PQC_READY,
    "Kyber-512": QuantumVulnerability.PQC_READY,
    "Kyber-768": QuantumVulnerability.PQC_READY,
    "Kyber-1024": QuantumVulnerability.PQC_READY,
    "SPHINCS+-128s": QuantumVulnerability.PQC_READY,
    "SPHINCS+-128f": QuantumVulnerability.PQC_READY,
    "SPHINCS+-192s": QuantumVulnerability.PQC_READY,
    "SPHINCS+-192f": QuantumVulnerability.PQC_READY,
    "SPHINCS+-256s": QuantumVulnerability.PQC_READY,
    "SPHINCS+-256f": QuantumVulnerability.PQC_READY,
}

_VULNERABILITY_WEIGHTS: dict[QuantumVulnerability, float] = {
    QuantumVulnerability.BROKEN: 1.0,
    QuantumVulnerability.WEAKENED: 0.6,
    QuantumVulnerability.SAFE: 0.1,
    QuantumVulnerability.PQC_READY: 0.0,
}

_NIST_800_131A_DISALLOWED: set[str] = {"RSA", "DH", "ECDSA", "ECDH"}
_CNSA2_DISALLOWED: set[str] = {
    "RSA", "DH", "ECDSA", "ECDH",
    "AES-128", "SHA-256", "Ed25519", "Ed448",
}

_REPLACEMENT_MAP: dict[QuantumVulnerability, str | None] = {
    QuantumVulnerability.BROKEN: "ML-KEM-768 or ML-DSA-65",
    QuantumVulnerability.WEAKENED: "ML-KEM-768 or AES-256",
    QuantumVulnerability.SAFE: None,
    QuantumVulnerability.PQC_READY: None,
}


def _determine_risk_level(score: float) -> str:
    if score >= 8.0:
        return "CRITICAL"
    elif score >= 6.0:
        return "HIGH"
    elif score >= 3.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "NONE"


def _recommended_action(vuln: QuantumVulnerability) -> str:
    if vuln == QuantumVulnerability.BROKEN:
        return "Migrate immediately to NIST-approved PQC algorithm"
    elif vuln == QuantumVulnerability.WEAKENED:
        return "Plan migration to PQC within 12 months"
    elif vuln == QuantumVulnerability.SAFE:
        return "No action required; continue monitoring"
    return "Algorithm is quantum-ready; no migration needed"


class RiskScoringEngine:
    """Calculates quantum-risk scores for cryptographic findings."""

    def calculate(self, finding_data: dict[str, Any]) -> RiskScore:
        algorithm = finding_data.get("algorithm", "UNKNOWN")
        vuln = _ALGORITHM_VULNERABILITY_DB.get(algorithm, QuantumVulnerability.BROKEN)

        hndl_exposure = float(finding_data.get("hndl_exposure_score", 0.0))
        hndl_exposure = max(0.0, min(1.0, hndl_exposure))

        vuln_weight = _VULNERABILITY_WEIGHTS[vuln]
        overall = vuln_weight * 7.0 + hndl_exposure * 3.0

        nist_ok = algorithm not in _NIST_800_131A_DISALLOWED
        cnsa2_ok = algorithm not in _CNSA2_DISALLOWED

        return RiskScore(
            quantum_vulnerability=vuln,
            nist_800_131a_compliant=nist_ok,
            cnsa2_compliant=cnsa2_ok,
            hndl_exposure_score=hndl_exposure,
            overall_risk_score=round(overall, 2),
            risk_level=_determine_risk_level(overall),
            recommended_action=_recommended_action(vuln),
            recommended_replacement=_REPLACEMENT_MAP[vuln],
        )

    def batch_calculate(self, findings: list[dict[str, Any]]) -> list[RiskScore]:
        return [self.calculate(f) for f in findings]


_NIST_RULES: dict[str, dict[str, str]] = {
    "NIST-800-131A-01": {
        "rule_name": "No RSA key transport",
        "description": "RSA key establishment is disallowed after 2030.",
        "severity": "CRITICAL",
    },
    "NIST-800-131A-02": {
        "rule_name": "No DH key exchange",
        "description": "Finite-field Diffie-Hellman is disallowed.",
        "severity": "CRITICAL",
    },
    "NIST-800-131A-03": {
        "rule_name": "Minimum symmetric key size",
        "description": "AES-128 is allowed; AES-256 recommended.",
        "severity": "MEDIUM",
    },
    "NIST-800-131A-04": {
        "rule_name": "No ECDSA for digital signatures",
        "description": "ECDSA is disallowed for new deployments.",
        "severity": "HIGH",
    },
}

_CNSA2_RULES: dict[str, dict[str, str]] = {
    "CNSA2-01": {
        "rule_name": "AES-256 required",
        "description": "Only AES-256 is allowed for symmetric encryption.",
        "severity": "CRITICAL",
    },
    "CNSA2-02": {
        "rule_name": "No RSA",
        "description": "RSA is completely disallowed under CNSA 2.0.",
        "severity": "CRITICAL",
    },
    "CNSA2-03": {
        "rule_name": "SHA-384 or SHA-512 required",
        "description": "SHA-256 is disallowed under CNSA 2.0.",
        "severity": "HIGH",
    },
    "CNSA2-04": {
        "rule_name": "ML-KEM / ML-DSA required",
        "description": "PQC algorithms must be used for key exchange and signatures.",
        "severity": "CRITICAL",
    },
}

_FIPS140_3_RULES: dict[str, dict[str, str]] = {
    "FIPS-140-3-01": {
        "rule_name": "FIPS-validated modules",
        "description": "Cryptographic modules must be FIPS 140-3 validated.",
        "severity": "CRITICAL",
    },
    "FIPS-140-3-02": {
        "rule_name": "Approved algorithms only",
        "description": "Only NIST-approved algorithms are permitted.",
        "severity": "HIGH",
    },
}

_EU_NIS2_RULES: dict[str, dict[str, str]] = {
    "NIS2-01": {
        "rule_name": "Risk management measures",
        "description": "Organizations must implement cybersecurity risk-management measures.",
        "severity": "HIGH",
    },
    "NIS2-02": {
        "rule_name": "Incident reporting",
        "description": "Significant incidents must be reported within 24 hours.",
        "severity": "MEDIUM",
    },
}

_FISMA_RULES: dict[str, dict[str, str]] = {
    "FISMA-01": {
        "rule_name": "Information system categorization",
        "description": "Systems must be categorized per FIPS 199.",
        "severity": "HIGH",
    },
}

_FEDRAMP_RULES: dict[str, dict[str, str]] = {
    "FEDRAMP-01": {
        "rule_name": "Boundary protection",
        "description": "Agencies must implement boundary protection controls.",
        "severity": "HIGH",
    },
}

_CMMC_RULES: dict[str, dict[str, str]] = {
    "CMMC-01": {
        "rule_name": "Access control",
        "description": "Limit information system access to authorized users.",
        "severity": "MEDIUM",
    },
}

_FRAMEWORK_RULES: dict[ComplianceFramework, dict[str, dict[str, str]]] = {
    ComplianceFramework.NIST_SP_800_131A: _NIST_RULES,
    ComplianceFramework.CNSA_2_0: _CNSA2_RULES,
    ComplianceFramework.FIPS_140_3: _FIPS140_3_RULES,
    ComplianceFramework.EU_NIS2: _EU_NIS2_RULES,
    ComplianceFramework.FISMA: _FISMA_RULES,
    ComplianceFramework.FEDRAMP: _FEDRAMP_RULES,
    ComplianceFramework.CMMC: _CMMC_RULES,
}


class ComplianceEngine:
    """Evaluates findings against compliance frameworks."""

    def evaluate(
        self, finding_data: dict[str, Any], framework: ComplianceFramework
    ) -> ComplianceResult:
        algorithm = finding_data.get("algorithm", "UNKNOWN")
        vuln = _ALGORITHM_VULNERABILITY_DB.get(algorithm, QuantumVulnerability.BROKEN)
        rules_db = _FRAMEWORK_RULES[framework]

        rules: list[ComplianceRule] = []
        for rule_id, meta in rules_db.items():
            status = "COMPLIANT"
            evidence = f"Algorithm {algorithm} is {vuln.value}"

            if framework == ComplianceFramework.NIST_SP_800_131A:
                if algorithm in _NIST_800_131A_DISALLOWED:
                    status = "NON_COMPLIANT"
                    evidence = f"Algorithm {algorithm} is disallowed by NIST SP 800-131A"
            elif framework == ComplianceFramework.CNSA_2_0:
                if algorithm in _CNSA2_DISALLOWED:
                    status = "NON_COMPLIANT"
                    evidence = f"Algorithm {algorithm} is disallowed by CNSA 2.0"
            elif framework == ComplianceFramework.FIPS_140_3:
                if vuln == QuantumVulnerability.BROKEN:
                    status = "NON_COMPLIANT"
                    evidence = f"Algorithm {algorithm} is not FIPS-approved"

            rules.append(
                ComplianceRule(
                    framework=framework,
                    rule_id=rule_id,
                    rule_name=meta["rule_name"],
                    description=meta["description"],
                    severity=meta["severity"],
                    status=status,
                    evidence=evidence,
                    recommendation=_recommended_action(vuln),
                )
            )

        compliant = sum(1 for r in rules if r.status == "COMPLIANT")
        non_compliant = sum(1 for r in rules if r.status == "NON_COMPLIANT")
        partial = sum(1 for r in rules if r.status == "PARTIAL")
        total = len(rules)
        score = (compliant / total * 100.0) if total else 0.0

        return ComplianceResult(
            framework=framework,
            total_rules=total,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            partial_count=partial,
            score=round(score, 2),
            rules=rules,
        )

    def batch_evaluate(
        self, findings: list[dict[str, Any]], framework: ComplianceFramework
    ) -> ComplianceResult:
        all_rules: list[ComplianceRule] = []
        compliant = non_compliant = partial = 0

        for finding in findings:
            result = self.evaluate(finding, framework)
            all_rules.extend(result.rules)
            compliant += result.compliant_count
            non_compliant += result.non_compliant_count
            partial += result.partial_count

        total = len(all_rules)
        score = (compliant / total * 100.0) if total else 0.0

        return ComplianceResult(
            framework=framework,
            total_rules=total,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            partial_count=partial,
            score=round(score, 2),
            rules=all_rules,
        )

    def full_report(self, findings: list[dict[str, Any]]) -> dict[str, ComplianceResult]:
        report: dict[str, ComplianceResult] = {}
        for framework in ComplianceFramework:
            report[framework.value] = self.batch_evaluate(findings, framework)
        return report


__all__ = [
    "QuantumVulnerability",
    "RiskScore",
    "ComplianceFramework",
    "ComplianceRule",
    "ComplianceResult",
    "RiskScoringEngine",
    "ComplianceEngine",
]
