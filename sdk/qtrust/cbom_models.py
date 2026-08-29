"""CycloneDX 1.7 and advanced CBOM models for the SDK."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CycloneDXComponent",
    "CycloneDXBOM",
    "EvidenceEntry",
    "EvidenceLedger",
    "MigrationPhase",
    "CostEstimate",
    "convert_to_cyclonedx",
    "generate_evidence_ledger",
    "generate_migration_roadmap",
]


class CycloneDXComponent(BaseModel):
    """A CycloneDX 1.7 component representing a cryptographic asset."""

    bom_ref: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str = "cryptographic-asset"
    name: str
    version: str = "1.0.0"
    description: str = ""
    crypto_properties: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True)


class CycloneDXBOM(BaseModel):
    """A CycloneDX 1.7 Bill of Materials."""

    bom_format: str = "CycloneDX"
    spec_version: str = "1.7"
    serial_number: str = Field(
        default_factory=lambda: f"urn:uuid:{uuid.uuid4()}"
    )
    version: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)
    components: list[CycloneDXComponent] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the BOM to a dictionary."""
        return {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "serialNumber": self.serial_number,
            "version": self.version,
            "metadata": self.metadata,
            "components": [c.model_dump() for c in self.components],
            **({"vulnerabilities": self.vulnerabilities} if self.vulnerabilities else {}),
        }

    def to_json(self) -> str:
        """Serialize the BOM to a JSON string."""
        import json

        return json.dumps(self.to_dict(), indent=2, default=str)


class EvidenceEntry(BaseModel):
    """A single entry in the evidence ledger."""

    entry_hash: str
    prev_hash: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scan_result_hash: str
    scan_target: str
    findings_count: int = 0
    risk_summary: dict[str, Any] = Field(default_factory=dict)


class EvidenceLedger(BaseModel):
    """An immutable evidence ledger with hash-chain integrity."""

    batch_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entries: list[EvidenceEntry] = Field(default_factory=list)
    entry_count: int = 0

    def verify(self) -> bool:
        """Verify hash-chain integrity of the ledger."""
        if not self.entries:
            return True

        prev = "0" * 64
        for entry in self.entries:
            if entry.prev_hash != prev:
                return False
            expected = hashlib.sha256(
                f"{entry.prev_hash}{entry.scan_result_hash}{entry.timestamp}".encode()
            ).hexdigest()
            if entry.entry_hash != expected:
                return False
            prev = entry.entry_hash
        return True


class MigrationPhase(BaseModel):
    """A single phase in a quantum-safe migration roadmap."""

    phase_number: int
    name: str
    description: str
    duration_months: float
    effort_days: float
    assets: list[str] = Field(default_factory=list)
    risk_reduction: float = 0.0
    compliance_frameworks: list[str] = Field(default_factory=list)


class CostEstimate(BaseModel):
    """Cost estimate for a quantum-safe migration."""

    daily_rate_usd: float
    total_effort_days: float
    total_cost_usd: float
    fte_required: float
    timeline_months: float
    phases: list[MigrationPhase] = Field(default_factory=list)


def convert_to_cyclonedx(scan_result: dict[str, Any]) -> CycloneDXBOM:
    """Convert a scan result dictionary to a CycloneDX BOM."""
    metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": [
            {
                "vendor": "qtrust",
                "name": "qtrust-scanner",
                "version": scan_result.get("scanner_version", "1.0.0"),
            }
        ],
        "manufacturer": {"name": "qtrust"},
    }

    components: list[CycloneDXComponent] = []
    for finding in scan_result.get("findings", []):
        crypto_props: dict[str, Any] = {
            "asset_type": finding.get("asset_type", "unknown"),
            "algorithm_properties": {
                "algorithm": finding.get("algorithm", "unknown"),
                "key_size": finding.get("key_size"),
            },
            "quantum_safe": finding.get("quantum_safe", False),
        }
        components.append(
            CycloneDXComponent(
                name=finding.get("name", "unknown"),
                version=finding.get("version", "1.0.0"),
                description=finding.get("description", ""),
                crypto_properties=crypto_props,
            )
        )

    return CycloneDXBOM(
        metadata=metadata,
        components=components,
        vulnerabilities=scan_result.get("vulnerabilities"),
    )


def generate_evidence_ledger(
    scan_results: list[dict[str, Any]],
) -> EvidenceLedger:
    """Generate an evidence ledger from a list of scan results."""
    entries: list[EvidenceEntry] = []
    prev_hash = "0" * 64

    for result in scan_results:
        scan_target = result.get("target", "unknown")
        findings = result.get("findings", [])
        findings_count = len(findings)

        risk_summary: dict[str, Any] = {}
        for f in findings:
            severity = f.get("severity", "unknown")
            risk_summary[severity] = risk_summary.get(severity, 0) + 1

        scan_result_hash = hashlib.sha256(
            str(result).encode()
        ).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        entry_hash = hashlib.sha256(
            f"{prev_hash}{scan_result_hash}{timestamp}".encode()
        ).hexdigest()

        entry = EvidenceEntry(
            entry_hash=entry_hash,
            prev_hash=prev_hash,
            timestamp=timestamp,
            scan_result_hash=scan_result_hash,
            scan_target=scan_target,
            findings_count=findings_count,
            risk_summary=risk_summary,
        )
        entries.append(entry)
        prev_hash = entry_hash

    return EvidenceLedger(
        entries=entries,
        entry_count=len(entries),
    )


def generate_migration_roadmap(
    findings: list[dict[str, Any]],
    daily_rate: float = 1500.0,
) -> CostEstimate:
    """Generate a quantum-safe migration roadmap and cost estimate."""
    algo_counts: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        algo = finding.get("algorithm", "unknown")
        algo_counts.setdefault(algo, []).append(finding)

    phases: list[MigrationPhase] = []
    phase_num = 1
    total_effort = 0.0

    priority_order = {
        "RSA": 1, "ECDSA": 2, "DSA": 3,
        "AES": 4, "SHA": 5, "HMAC": 6, "unknown": 99,
    }
    sorted_algos = sorted(
        algo_counts.keys(),
        key=lambda a: priority_order.get(a, 50),
    )

    for algo in sorted_algos:
        items = algo_counts[algo]
        asset_count = len(items)
        effort = max(15, asset_count * 10)
        duration = max(1.0, effort / 22 / 3)

        quantum_safe_count = sum(
            1 for i in items if i.get("quantum_safe", False)
        )
        risk_reduction = (
            (quantum_safe_count / asset_count) if asset_count else 0.0
        )

        phase = MigrationPhase(
            phase_number=phase_num,
            name=f"Migrate {algo}",
            description=f"Transition {algo} implementations to quantum-safe alternatives",
            duration_months=round(duration, 1),
            effort_days=effort,
            assets=[i.get("name", "unknown") for i in items],
            risk_reduction=round(risk_reduction, 2),
            compliance_frameworks=["NIST", "FIPS 140-3"],
        )
        phases.append(phase)
        total_effort += effort
        phase_num += 1

    timeline = max(p.duration_months for p in phases) if phases else 1.0
    total_cost = total_effort * daily_rate
    fte = round(total_effort / (timeline * 22), 1) if timeline > 0 else 0.0

    return CostEstimate(
        daily_rate_usd=daily_rate,
        total_effort_days=total_effort,
        total_cost_usd=round(total_cost, 2),
        fte_required=fte,
        timeline_months=round(timeline, 1),
        phases=phases,
    )
