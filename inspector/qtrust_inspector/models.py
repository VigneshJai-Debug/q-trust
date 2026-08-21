from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class AssetFinding(BaseModel):
    """A single cryptographic asset finding."""
    asset_type: str = Field(..., description="e.g., tls_certificate, ssh_host_key, file_key")
    host: str = Field(..., description="The host or path of the asset")
    port: int | None = None
    algorithm: str | None = None
    key_type: str | None = None
    key_size: int | None = None
    vendor: str | None = None
    criticality: str = Field("medium", description="low, medium, high, or critical")
    fingerprint_sha256: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Optional TLS details (populated by the TLS scanner)
    issuer: str | None = None
    subject: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    expired: bool | None = None
    cipher: str | None = None

    @property
    def location(self) -> str:
        """Human-readable location (host:port)."""
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host


class ScanResult(BaseModel):
    """The result of a scan."""
    target: str
    scanner: str = "qtrust-inspector"
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: int | None = None
    completed_at: int | None = None
    findings: list[AssetFinding] = Field(default_factory=list)
    error: str | None = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def by_algorithm(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            alg = f.algorithm or "unknown"
            counts[alg] = counts.get(alg, 0) + 1
        return counts

    @property
    def by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.asset_type] = counts.get(f.asset_type, 0) + 1
        return counts

    def to_cbom(self) -> dict[str, Any]:
        """Convert this scan result into a CBOM-style JSON document."""
        assets = []
        for f in self.findings:
            assets.append({
                "type": f.asset_type,
                "host": f.host,
                "port": f.port,
                "algorithm": f.algorithm,
                "key_type": f.key_type,
                "key_size": f.key_size,
                "vendor": f.vendor,
                "criticality": f.criticality,
                "fingerprint_sha256": f.fingerprint_sha256,
                "expired": f.expired,
                "not_after": f.not_after,
                "metadata": f.metadata,
            })
        return {
            "schema_version": "qtrust.cbom.v1",
            "scan_timestamp": self.scan_timestamp,
            "target": self.target,
            "scanner": self.scanner,
            "assets": assets,
            "asset_count": len(assets),
        }
