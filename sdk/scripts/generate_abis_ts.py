#!/usr/bin/env python3
"""Regenerate backend/src/lib/abis.ts from the compiled Forge artifacts."""
import json
from pathlib import Path

CONTRACTS = {
    "AssetRegistryAbi": "AssetRegistry",
    "VendorRegistryAbi": "VendorRegistry",
    "MigrationRegistryAbi": "MigrationRegistry",
    "AuditRegistryAbi": "AuditRegistry",
    "QTrustGovernanceAbi": "QTrustGovernance",
    "TimelockControllerAbi": "TimelockController",
}

OUT_FILE = Path(__file__).resolve().parent.parent.parent / "backend" / "src" / "lib" / "abis.ts"
ARTIFACT_DIR = Path(__file__).resolve().parent.parent.parent / "contracts" / "out"

lines = [
    "// ABI definitions for the Q-Trust contracts (generated from Forge artifacts).",
    "// Regenerate with: python3 scripts/generate_abis.py",
    "",
]
for const_name, contract in CONTRACTS.items():
    artifact = json.loads((ARTIFACT_DIR / f"{contract}.sol" / f"{contract}.json").read_text())
    abi = json.dumps(artifact["abi"], indent=4)
    lines.append(f"export const {const_name} = {abi} as const;")
    lines.append("")

# AuditResult enum name mapping helper.
lines.append(
    """export function auditResultName(code: number): string {
  switch (code) {
    case 0: return "Pending";
    case 1: return "Passed";
    case 2: return "Failed";
    case 3: return "Conditional";
    default: return "Unknown";
  }
}
"""
)
OUT_FILE.write_text("\n".join(lines))
print(f"Wrote {len(lines)} lines to {OUT_FILE}")