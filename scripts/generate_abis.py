#!/usr/bin/env python3
"""Regenerate backend/src/lib/abis.ts from the compiled Forge artifacts."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_DIR = ROOT / "contracts" / "out"
OUT = ROOT / "backend" / "src" / "lib" / "abis.ts"

CONTRACTS = [
    ("AssetRegistryAbi", "AssetRegistry"),
    ("VendorRegistryAbi", "VendorRegistry"),
    ("MigrationRegistryAbi", "MigrationRegistry"),
    ("AuditRegistryAbi", "AuditRegistry"),
]


def ts_value(value):
    """Convert a Python value to a TS literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        if not value:
            return "[]"
        return "[\n" + ",\n".join("      " + ts_value(v).replace("\n", "\n      ") for v in value) + ",\n    ]"
    if isinstance(value, dict):
        return "{\n" + ",\n".join(f"      {k}: {ts_value(v).replace(chr(10), chr(10)+'      ')}" for k, v in value.items()) + ",\n    }"
    raise TypeError(type(value))


lines = [
    "// ABI definitions for the Q-Trust contracts (generated from Forge artifacts).",
    "// Regenerate with: python3 scripts/generate_abis.py",
    "",
]

for const_name, contract in CONTRACTS:
    artifact = json.loads((ARTIFACT_DIR / f"{contract}.sol" / f"{contract}.json").read_text())
    entries = []
    for item in artifact["abi"]:
        body = ",\n".join(f"      {k}: {ts_value(v).replace(chr(10), chr(10)+'      ')}" for k, v in item.items())
        entries.append(f"    {{\n{body},\n    }}")
    lines.append(f"export const {const_name} = [")
    lines.append(",\n".join(entries))
    lines.append("] as const;")
    lines.append("")

OUT.write_text("\n".join(lines))
print(f"Wrote {OUT}")