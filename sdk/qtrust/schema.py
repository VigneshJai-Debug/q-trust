# sdk/qtrust/schema.py
"""Pydantic models for Q-Trust attestation objects."""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _validate_hash(v: str) -> str:
    """Ensure a hash is a 0x-prefixed 64-char hex string."""
    if not v.startswith("0x"):
        raise ValueError("hash must start with 0x")
    if len(v) != 66:
        raise ValueError(f"hash must be 32 bytes (66 chars), got {len(v)}")
    try:
        bytes.fromhex(v[2:])
    except ValueError as e:
        raise ValueError(f"hash is not valid hex: {e}")
    return v.lower()


class CBOMEntry(BaseModel):
    """A single cryptographic asset in a CBOM."""
    asset_type: str = Field(..., description="tls_cert | ssh_key | code_signing | hsm | jwt")
    algorithm: str = Field(..., description="e.g., RSA-2048, ECC-P256, ML-DSA-44")
    location: str = Field(..., description="Hostname, file path, or service identifier")
    vendor: str | None = Field(None, description="Vendor if known (e.g., DigiCert)")
    product: str | None = Field(None, description="Product ID if known")
    version: str | None = Field(None, description="Product version")
    criticality: str = Field("medium", description="low | medium | high | critical")
    expires_at: int | None = Field(None, description="Unix timestamp of expiry, if applicable")


class CBOM(BaseModel):
    """A Cryptographic Bill of Materials."""
    schema_version: str = Field(default="cbom.v1")
    org_did: str = Field(..., description="Organization DID")
    generated_at: int = Field(..., description="Unix timestamp of CBOM generation")
    scanner_version: str = Field(..., description="Version of the scanner that produced this CBOM")
    assets: list[CBOMEntry] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict, description="Summary stats")


class AssetRecord(BaseModel):
    """An asset record as returned by the on-chain AssetRegistry."""
    asset_id: str
    org_did: str
    cbom_hash: str
    metadata_uri: str
    registered_at: int
    last_updated: int
    active: bool

    @property
    def datetime(self) -> datetime:
        return datetime.fromtimestamp(self.registered_at, tz=timezone.utc)


class VendorInfo(BaseModel):
    """Vendor information."""
    name: str
    metadata_uri: str
    registered_at: int
    active: bool


class ProductAttestation(BaseModel):
    """A vendor product attestation."""
    attestation_id: str
    vendor_did: str
    product_id: str
    version: str
    algorithm: str
    supported: bool
    evidence_uri: str
    timestamp: int
    revoked: bool


class MigrationRecord(BaseModel):
    """A record of a migration step."""
    migration_id: str
    asset_id: str
    org_did: str
    from_algorithm: str
    to_algorithm: str
    evidence_hash: str
    evidence_uri: str
    timestamp: int
    verified: bool
