"""
Cryptography Taxonomy — QTRUST-009 (§9, CycloneDX registry).

CycloneDX 1.7 registry models: family, primitive, mode, parameter set, curve,
key size, security category, standard, implementation, protocol, usage.

Instead of coarse ``RSA`` vs ``ECDSA``, normalize to:

    RSA-PKCS1-1.5-SHA-256-2048 / ECDSA-P256-SHA256 / ML-KEM-768 / etc.

This enables fine-grained compliance (NIST, CNSA 2.0) and precise migration targets.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class CryptoTaxonomy:
    family: str  # RSA, ECDSA, ECDH, ML-KEM, etc.
    primitive: str  # signature, kem, encryption, hashing
    mode: Optional[str] = None  # PKCS1, GCM, etc.
    parameter_set: Optional[str] = None  # P-256, 768, etc.
    key_size: Optional[int] = None
    curve: Optional[str] = None
    security_category: Optional[str] = None  # NIST category 1-5
    standard: Optional[str] = None  # FIPS 203, etc.
    protocol: Optional[str] = None  # TLS 1.3, etc.
    usage: Optional[str] = None  # at-rest, in-transit


# CycloneDX registry inspired patterns
PATTERNS = [
    (re.compile(r"RSA.*PKCS1.*SHA-256.*2048", re.I), {"family": "RSA", "mode": "PKCS1-1.5", "primitive": "signature", "key_size": 2048}),
    (re.compile(r"ECDSA.*P-256", re.I), {"family": "ECDSA", "curve": "P-256", "primitive": "signature"}),
    (re.compile(r"ML-KEM-768", re.I), {"family": "ML-KEM", "parameter_set": "768", "primitive": "kem", "standard": "FIPS 203"}),
    (re.compile(r"AES-256-GCM", re.I), {"family": "AES", "mode": "GCM", "primitive": "encryption", "key_size": 256}),
]


def normalize(algorithm: str, key_size: Optional[int] = None) -> CryptoTaxonomy:
    alg = (algorithm or "").strip()
    for pat, meta in PATTERNS:
        if pat.search(alg):
            return CryptoTaxonomy(**{**meta, "key_size": key_size or meta.get("key_size")})
    # Fallback coarse
    family = alg.split("-")[0].upper() if alg else "Unknown"
    primitive = "signature" if family in ("RSA", "ECDSA") else "kem" if family in ("ML-KEM", "ECDH") else "encryption"
    return CryptoTaxonomy(family=family, primitive=primitive, key_size=key_size)
