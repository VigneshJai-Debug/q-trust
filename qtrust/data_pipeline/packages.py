"""
Package ecosystem mining — §42 (§2).

Sources: PyPI, npm, crates.io, Go modules, Debian, Maven, etc.
Builds dependency knowledge graph: package → version → crypto library → algorithm → vuln → PQC support.

This learns: "App doesn't directly call RSA, but its dependency embeds OpenSSL with this behavior."
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


def fetch_pypi_metadata(package: str) -> Dict[str, Any]:
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{package}/json", timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


def build_dependency_graph(manifest_path: Path) -> Dict[str, Any]:
    # Parses requirements.txt, package.json, Cargo.toml, go.mod, pom.xml
    # Stub: real would use cyclonedx/cdxgen or importlib.metadata
    if not manifest_path.exists():
        return {"nodes": [], "edges": []}
    text = manifest_path.read_text(errors="ignore")
    nodes = []
    if "cryptography" in text:
        nodes.append({"package": "cryptography", "crypto": "RSA", "pqc": False})
    if "openssl" in text.lower():
        nodes.append({"package": "openssl", "crypto": "ECDSA", "pqc": True})
    return {"manifest": str(manifest_path), "nodes": nodes}
