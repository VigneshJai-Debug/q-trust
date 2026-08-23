from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from pydantic import BaseModel, Field


class MigrationPhase(BaseModel):
    phase_number: int
    name: str
    description: str
    duration_months: float
    effort_days: float
    assets: list[dict[str, Any]] = Field(default_factory=list)
    risk_reduction: float = Field(ge=0.0, le=1.0)
    compliance_frameworks: list[str] = Field(default_factory=list)


class CostEstimate(BaseModel):
    daily_rate_usd: float = 1500.0
    total_effort_days: float
    total_cost_usd: float
    fte_required: float
    timeline_months: float
    phases: list[MigrationPhase]


PHASE_TEMPLATES = [
    {
        "name": "Emergency: Critical Vulnerabilities",
        "description": "Immediate remediation of critical quantum-vulnerable assets and exposed keys",
        "risk_reduction": 0.3,
        "compliance_frameworks": ["NIST SP 800-131A", "CNSA 2.0"],
    },
    {
        "name": "Quick Wins: Low-Hanging Fruit",
        "description": "Migrate easily-replaceable assets and upgrade deprecated algorithms",
        "risk_reduction": 0.25,
        "compliance_frameworks": ["NIST SP 800-131A"],
    },
    {
        "name": "Core Migration: High-Value Systems",
        "description": "Migrate critical infrastructure, databases, and primary TLS endpoints",
        "risk_reduction": 0.25,
        "compliance_frameworks": ["CNSA 2.0", "FIPS 140-3", "EU NIS2"],
    },
    {
        "name": "Full PQC: Complete Transition",
        "description": "Complete migration to post-quantum algorithms across all systems",
        "risk_reduction": 0.15,
        "compliance_frameworks": ["CNSA 2.0", "FIPS 140-3", "EU NIS2", "FISMA", "FedRAMP", "CMMC"],
    },
    {
        "name": "Verification & Hardening",
        "description": "Audit, verify compliance, and establish continuous monitoring",
        "risk_reduction": 0.05,
        "compliance_frameworks": ["All frameworks"],
    },
]


def _estimate_asset_effort(algorithm: str, key_size: int) -> float:
    algo_upper = algorithm.upper()
    effort_map = {
        "RSA-1024": 1.0, "RSA-2048": 1.5, "RSA-3072": 2.0, "RSA-4096": 2.5,
        "ECC-P256": 1.5, "ECC-P384": 2.0, "ECC-P521": 2.5,
        "DSA-1024": 1.0, "DSA-2048": 1.5,
        "DH-2048": 1.5, "ECDH-P256": 1.5, "ECDSA-P256": 1.5,
        "ED25519": 1.5, "ED448": 2.0,
        "AES-128": 0.5, "AES-256": 0.0,
        "SHA-256": 0.0, "SHA-384": 0.0, "SHA-512": 0.0,
        "MD5": 0.5, "SHA-1": 0.5, "DES": 0.5, "3DES": 0.5, "RC4": 0.5,
    }
    for key, val in effort_map.items():
        if algo_upper.startswith(key):
            return val
    return 1.0


def _classify_asset_phase(algorithm: str, key_size: int, criticality: str) -> int:
    algo_upper = algorithm.upper()
    pqc_prefixes = ("ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FALCON", "CRYSTALS")
    if any(algo_upper.startswith(p) for p in pqc_prefixes):
        return -1
    broken = ("RSA", "ECC", "DSA", "DH", "ECDH", "ECDSA", "ED25519", "ED448")
    weak = ("MD5", "SHA-1", "DES", "3DES", "RC4", "BLOWFISH")
    if any(algo_upper.startswith(w) for w in weak):
        return 0
    if criticality in ("critical", "Critical") and any(algo_upper.startswith(b) for b in broken):
        return 0
    if any(algo_upper.startswith(b) for b in broken):
        if key_size and key_size >= 4096:
            return 2
        return 1
    return 3


def generate_roadmap(
    findings: list[dict[str, Any]] | Any,
    daily_rate_usd: float = 1500.0,
    target_date: date | None = None,
) -> dict[str, Any]:
    if hasattr(findings, "findings"):
        finding_list = [f.model_dump() if hasattr(f, "model_dump") else f.__dict__ for f in findings.findings]
    else:
        finding_list = list(findings)

    phase_assets: dict[int, list[dict[str, Any]]] = {i: [] for i in range(5)}
    pqc_ready = []
    total_effort = 0.0

    for finding in finding_list:
        algorithm = finding.get("algorithm", "unknown")
        key_size = finding.get("key_size", 0) or 0
        criticality = finding.get("criticality", "medium")
        phase_idx = _classify_asset_phase(algorithm, key_size, criticality)
        if phase_idx == -1:
            pqc_ready.append(finding)
            continue
        effort = _estimate_asset_effort(algorithm, key_size)
        total_effort += effort
        finding_with_effort = {**finding, "effort_days": effort}
        phase_assets[phase_idx].append(finding_with_effort)

    cumulative_risk = 0.0
    phases: list[MigrationPhase] = []
    for i, template in enumerate(PHASE_TEMPLATES):
        assets = sorted(phase_assets[i], key=lambda a: -a.get("effort_days", 0))
        cumulative_risk += template["risk_reduction"]
        phases.append(
            MigrationPhase(
                phase_number=i + 1,
                name=template["name"],
                description=template["description"],
                duration_months=max(1.0, sum(a["effort_days"] for a in assets) / 22.0),
                effort_days=sum(a["effort_days"] for a in assets),
                assets=assets,
                risk_reduction=min(cumulative_risk, 1.0),
                compliance_frameworks=template["compliance_frameworks"],
            )
        )

    timeline_months = max(p.duration_months for p in phases) if phases else 1.0
    fte_required = total_effort / (timeline_months * 22.0) if timeline_months > 0 else 1.0
    total_cost = total_effort * daily_rate_usd

    return {
        "phases": [
            {
                "name": p.name,
                "description": p.description,
                "phase_number": p.phase_number,
                "duration_months": p.duration_months,
                "effort_days": p.effort_days,
                "tasks": [
                    {"algorithm": a.get("algorithm", "unknown"), "effort_days": a.get("effort_days", 0)}
                    for a in p.assets
                ],
                "risk_reduction": p.risk_reduction,
                "compliance_frameworks": p.compliance_frameworks,
                "asset_count": len(p.assets),
            }
            for p in phases
        ],
        "estimated_cost": total_cost,
        "total_effort_days": total_effort,
        "timeline_months": timeline_months,
        "fte_required": fte_required,
        "daily_rate_usd": daily_rate_usd,
    }
