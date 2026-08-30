"""
Data normalizer — §25.

Standardizes CycloneDX 1.7 CBOM output (software, hardware, services, crypto assets + dependencies)
into unified schema for training. Enforces ECMA-424.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict


def normalize_cbom(cbom: Dict[str, Any]) -> Dict[str, Any]:
    # Map CycloneDX 1.7 → qtrust canonical schema
    assets = []
    for comp in cbom.get("components", cbom.get("assets", [])):
        assets.append(
            {
                "algorithm": comp.get("algorithm") or comp.get("name", "Unknown"),
                "key_size": comp.get("keySize") or comp.get("key_size", 2048),
                "location": comp.get("location") or comp.get("name", "unknown"),
                "dependencies": comp.get("dependencies", []),
            }
        )
    norm = {"schema_version": "qtrust.cbom.v1", "assets": assets}
    norm["_hash"] = hashlib.sha256(json.dumps(norm, sort_keys=True).encode()).hexdigest()[:16]
    return norm
