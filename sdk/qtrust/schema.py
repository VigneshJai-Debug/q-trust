# sdk/qtrust/schema.py
"""Pydantic models for Q-Trust attestation objects."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator

# REG-05: canonical algorithm names. FIPS 203/204 define ML-KEM-{512,768,1024}
# and ML-DSA-{44,65,87}; earlier builds emitted malformed names such as
# "ML-DSA-441" (parameter counts concatenated with the variant). Everything
# entering a CBOM is normalized through this table.
_CANONICAL_ALGORITHMS = {
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "FALCON-512", "FALCON-1024", "HQC-128", "HQC-192", "HQC-256",
    "RSA-1024", "RSA-2048", "RSA-3072", "RSA-4096",
    "ECC-P256", "ECC-P384", "ECC-P521",
    "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
    "ECDH-P256", "ECDH-P384", "ECDH-P521",
    "DSA-1024", "DSA-2048", "DH-2048", "DH-4096",
    "Ed25519", "Ed448", "X25519", "X448",
    "SHA-1", "SHA-256", "SHA-384", "SHA-512",
    "SHA3-256", "SHA3-384", "SHA3-512",
    "AES-128", "AES-192", "AES-256", "3DES", "DES", "RC4",
    "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "HMAC-MD5",
    "ChaCha20-Poly1305",
}

# Common malformed variants -> canonical name (e.g. parameter count
# concatenated with the variant: ML-DSA-441 -> ML-DSA-44).
_MALFORMED_ALGORITHM_MAP = {
    "ML-DSA-441": "ML-DSA-44",
    "ML-DSA-659": "ML-DSA-65",
    "ML-DSA-877": "ML-DSA-87",
}


def canonicalize_algorithm(name: str) -> str:
    """Normalize an algorithm name to its canonical form (REG-05).

    Fixes known malformed variants (e.g. ML-DSA-441 -> ML-DSA-44) and
    normalizes whitespace/underscores/case for lookup.
    """
    if not name or not name.strip():
        raise ValueError("algorithm name must be non-empty")
    cleaned = re.sub(r"[\s_]+", "-", name.strip())
    if cleaned in _MALFORMED_ALGORITHM_MAP:
        return _MALFORMED_ALGORITHM_MAP[cleaned]
    upper = cleaned.upper()
    for canonical in _CANONICAL_ALGORITHMS:
        if upper == canonical.upper():
            return canonical
    return cleaned


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

    @field_validator("algorithm")
    @classmethod
    def _canonical_algorithm(cls, v: str) -> str:
        """REG-05: normalize every algorithm name to its canonical form at ingress."""
        return canonicalize_algorithm(v)


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
