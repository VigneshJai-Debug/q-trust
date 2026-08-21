#!/usr/bin/env python3
"""Regenerate sdk/qtrust/contracts.py from the compiled Forge artifacts."""
import json
from pathlib import Path

CONTRACTS = {
    "ASSET_REGISTRY_ABI": "AssetRegistry",
    "VENDOR_REGISTRY_ABI": "VendorRegistry",
    "MIGRATION_REGISTRY_ABI": "MigrationRegistry",
    "AUDIT_REGISTRY_ABI": "AuditRegistry",
    "GOVERNANCE_ABI": "QTrustGovernance",
    "TIMELOCK_ABI": "TimelockController",
}

OUT_DIR = Path(__file__).resolve().parent.parent
ARTIFACT_DIR = Path(__file__).resolve().parent.parent.parent / "contracts" / "out"

lines = ['"""ABI definitions for Q-Trust smart contracts (generated from Forge artifacts)."""', ""]

for const_name, contract in CONTRACTS.items():
    artifact = json.loads((ARTIFACT_DIR / f"{contract}.sol" / f"{contract}.json").read_text())
    abi = json.dumps(artifact["abi"], indent=2)
    abi = abi.replace(": true", ": True").replace(": false", ": False").replace(": null", ": None")
    lines.append(f"{const_name} = {abi}")
    lines.append("")

lines.append("ABI_REGISTRY = {")
for const_name in CONTRACTS:
    lines.append(f'    "{const_name}": {const_name},')
lines.append("}")
lines.append("")

(OUT_DIR / "qtrust" / "contracts.py").write_text("\n".join(lines))
print(f"Wrote {len(lines)} lines to {OUT_DIR / 'qtrust' / 'contracts.py'}")
