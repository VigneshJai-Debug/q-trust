from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


from .models import AssetFinding, ScanResult

ASSET_TYPE_MAP: dict[str, str] = {
    "tls_certificate": "certificate",
    "ssh_host_key": "key",
    "file_key": "key",
    "ssh_private_key": "key",
    "algorithm": "algorithm",
    "protocol": "protocol",
    "library": "library",
}

ALGORITHM_PROPERTIES: dict[str, dict[str, Any]] = {
    "RSA": {"name": "RSA", "scheme": "RSA-PKCS1-v1_5"},
    "ECDSA": {"name": "ECDSA", "scheme": "ECDSA"},
    "Ed25519": {"name": "Ed25519", "scheme": "EdDSA"},
    "AES": {"name": "AES", "scheme": "AES-GCM"},
    "ChaCha20-Poly1305": {"name": "ChaCha20-Poly1305", "scheme": "ChaCha20"},
    "SHA256": {"name": "SHA-256", "scheme": "SHA-2"},
    "SHA384": {"name": "SHA-384", "scheme": "SHA-2"},
    "SHA512": {"name": "SHA-512", "scheme": "SHA-2"},
    "MD5": {"name": "MD5", "scheme": "MD5"},
    "SHA1": {"name": "SHA-1", "scheme": "SHA-1"},
}

WEAK_ALGORITHMS = {
    "MD5", "SHA1", "DES", "3DES", "RC4", "Blowfish", "IDEA",
    "RSA", "ECDSA", "ECDH", "DSA", "Ed25519", "Ed448", "DH",
    "HMAC-SHA1", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512",
}


def _finding_to_component(
    finding: AssetFinding,
    risk_scores: dict[str, int] | None = None,
) -> dict[str, Any]:
    asset_type = ASSET_TYPE_MAP.get(finding.asset_type, "library")
    alg = finding.algorithm or "unknown"
    props = ALGORITHM_PROPERTIES.get(alg, {"name": alg, "scheme": alg})
    alg_lower = alg.lower()
    quantum_safe = not any(
        weak.lower() in alg_lower or alg_lower.startswith(weak.lower())
        for weak in WEAK_ALGORITHMS
    )

    cdx_component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "name": f"{finding.asset_type}:{finding.host}",
        "quantumSafe": quantum_safe,
        "cryptoProperties": {
            "assetType": asset_type,
            "algorithmProperties": {
                "name": props["name"],
                "oid": props.get("oid"),
                "scheme": props["scheme"],
                "strength": str(finding.key_size) if finding.key_size else None,
                "version": None,
                "mode": None,
            },
            "quantumSafe": quantum_safe,
        },
        "properties": [],
    }

    if finding.fingerprint_sha256:
        cdx_component["hashes"] = [
            {"alg": "SHA-256", "content": finding.fingerprint_sha256}
        ]

    if finding.issuer:
        cdx_component["cryptoProperties"]["certificates"] = [
            {
                "issuer": finding.issuer,
                "subject": finding.subject or "",
                "serialNumber": finding.serial_number or "",
                "notBefore": finding.not_before or "",
                "notAfter": finding.not_after or "",
                "expired": finding.expired,
            }
        ]

    if risk_scores and finding.host in risk_scores:
        score = risk_scores[finding.host]
        cdx_component["properties"].append(
            {"name": "qtrust:risk_score", "value": str(score)}
        )

    cdx_component["properties"].append(
        {"name": "qtrust:criticality", "value": finding.criticality}
    )

    return cdx_component


def generate_cyclonedx(
    scan_result: ScanResult,
    risk_scores: dict[str, int] | None = None,
) -> dict[str, Any]:
    components = [_finding_to_component(f, risk_scores) for f in scan_result.findings]

    vulns: list[dict[str, Any]] = []
    if risk_scores:
        for host, score in risk_scores.items():
            if score >= 7:
                vulns.append(
                    {
                        "id": f"qtrust-{host}",
                        "source": {"name": "qtrust-inspector"},
                        "ratings": [
                            {
                                "score": float(score),
                                "severity": "critical" if score >= 9 else "high",
                            }
                        ],
                        "description": f"High risk score ({score}) for {host}",
                    }
                )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "componentCount": len(components),
            "tools": [
                {
                    "vendor": "qtrust",
                    "name": "qtrust-inspector",
                    "version": "0.1.0",
                }
            ],
            "manufacturer": {"name": "qtrust"},
        },
        "components": components,
        "vulnerabilities": vulns if vulns else None,
    }


def save_cyclonedx(cdx_dict: dict[str, Any], path: str) -> str:
    import json

    with open(path, "w") as f:
        json.dump(cdx_dict, f, indent=2, default=str)
    return path
