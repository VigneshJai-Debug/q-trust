from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .models import ScanResult

RULES: list[dict[str, Any]] = [
    {
        "id": "QC-CRYPTO-001",
        "name": "WeakAlgorithm",
        "shortDescription": {"text": "Weak cryptographic algorithm detected"},
        "fullDescription": {
            "text": "A weak or insecure cryptographic algorithm was found that may be vulnerable to attack."
        },
        "helpUri": "https://qtrust.dev/rules/QC-CRYPTO-001",
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "QC-CRYPTO-002",
        "name": "ExpiredCertificate",
        "shortDescription": {"text": "Expired certificate detected"},
        "fullDescription": {
            "text": "An expired TLS/SSL certificate was found which may cause connection failures or security risks."
        },
        "helpUri": "https://qtrust.dev/rules/QC-CRYPTO-002",
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "QC-CRYPTO-003",
        "name": "HardcodedKey",
        "shortDescription": {"text": "Hardcoded cryptographic key detected"},
        "fullDescription": {
            "text": "A hardcoded cryptographic key was found which compromises security if the source is exposed."
        },
        "helpUri": "https://qtrust.dev/rules/QC-CRYPTO-003",
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "QC-CRYPTO-004",
        "name": "DeprecatedAlgorithm",
        "shortDescription": {"text": "Deprecated algorithm detected"},
        "fullDescription": {
            "text": "A deprecated cryptographic algorithm was found and should be replaced with a modern alternative."
        },
        "helpUri": "https://qtrust.dev/rules/QC-CRYPTO-004",
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "QC-CRYPTO-005",
        "name": "PQCMigrationNeeded",
        "shortDescription": {"text": "Post-quantum cryptography migration needed"},
        "fullDescription": {
            "text": "The cryptographic asset uses an algorithm vulnerable to quantum computing attacks and should be migrated to a post-quantum algorithm."
        },
        "helpUri": "https://qtrust.dev/rules/QC-CRYPTO-005",
        "defaultConfiguration": {"level": "note"},
    },
    {
        "id": "QC-CRYPTO-006",
        "name": "VulnerableLibrary",
        "shortDescription": {"text": "Vulnerable cryptographic library detected"},
        "fullDescription": {
            "text": "A cryptographic library with known vulnerabilities was detected."
        },
        "helpUri": "https://qtrust.dev/rules/QC-CRYPTO-006",
        "defaultConfiguration": {"level": "error"},
    },
]

CRITICALITY_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

WEAK_ALGORITHMS = {"MD5", "SHA1", "DES", "3DES", "RC4", "Blowfish", "IDEA"}
DEPRECATED_ALGORITHMS = {"MD5", "SHA1", "DES", "3DES", "RC4"}


def _map_level(criticality: str) -> str:
    return CRITICALITY_LEVEL.get(criticality, "warning")


def _finding_to_rule_id(finding: Any) -> str:
    alg = (finding.algorithm or "").upper()
    if finding.expired:
        return "QC-CRYPTO-002"
    if alg in WEAK_ALGORITHMS:
        return "QC-CRYPTO-001"
    if alg in DEPRECATED_ALGORITHMS:
        return "QC-CRYPTO-004"
    if finding.asset_type in ("ssh_private_key", "file_key"):
        return "QC-CRYPTO-003"
    return "QC-CRYPTO-005"


def _finding_to_result(finding: Any, target: str) -> dict[str, Any]:
    rule_id = _finding_to_rule_id(finding)
    level = _map_level(finding.criticality)
    location = finding.location
    message = f"[{rule_id}] {finding.asset_type} on {location}"
    if finding.algorithm:
        message += f" using {finding.algorithm}"

    physical_location: dict[str, Any] = {
        "artifactLocation": {
            "uri": target,
            "uriBaseId": "%SRCROOT%",
        },
        "region": {
            "startLine": 1,
            "startColumn": 1,
        },
    }

    if finding.host:
        physical_location["address"] = {"name": finding.host}

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{"physicalLocation": physical_location}],
        "properties": {
            "criticality": finding.criticality,
            "asset_type": finding.asset_type,
        },
    }

    if finding.algorithm:
        result["properties"]["algorithm"] = finding.algorithm
    if finding.fingerprint_sha256:
        result["fingerprints"] = [{"algorithm": "SHA-256", "value": finding.fingerprint_sha256}]

    return result


def generate_sarif(scan_results: list[ScanResult] | ScanResult) -> dict[str, Any]:
    if isinstance(scan_results, ScanResult):
        scan_results = [scan_results]

    results: list[dict[str, Any]] = []
    for sr in scan_results:
        for finding in sr.findings:
            results.append(_finding_to_result(finding, sr.target))

    rules_by_id = {r["id"]: r for r in RULES}
    used_ids = {r["ruleId"] for r in results}
    tool_rules = [rules_by_id[rid] for rid in sorted(used_ids) if rid in rules_by_id]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "qtrust-inspector",
                        "version": "0.1.0",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://qtrust.dev",
                        "rules": tool_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def save_sarif(sarif_dict: dict[str, Any], path: str) -> str:
    import json

    with open(path, "w") as f:
        json.dump(sarif_dict, f, indent=2, default=str)
    return path
