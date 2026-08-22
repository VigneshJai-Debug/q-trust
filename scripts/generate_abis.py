#!/usr/bin/env python3
"""Regenerate ABI bindings from compiled Forge artifacts.

Usage:
    python3 scripts/generate_abis.py              # regenerate both TS + Python
    python3 scripts/generate_abis.py --target ts   # backend/src/lib/abis.ts only
    python3 scripts/generate_abis.py --target py   # sdk/qtrust/contracts.py only
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_DIR = ROOT / "contracts" / "out"

# ── Contract sets ────────────────────────────────────────────────────────────

CORE_REGISTRIES = {
    "AssetRegistry": "AssetRegistry",
    "VendorRegistry": "VendorRegistry",
    "MigrationRegistry": "MigrationRegistry",
    "AuditRegistry": "AuditRegistry",
}

GOVERNANCE_CONTRACTS = {
    "QTrustGovernance": "QTrustGovernance",
    "TimelockController": "TimelockController",
}

ALL_CONTRACTS = {**CORE_REGISTRIES, **GOVERNANCE_CONTRACTS}


# ── TypeScript generation ────────────────────────────────────────────────────

def _ts_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        if not value:
            return "[]"
        items = ",\n".join("      " + _ts_value(v).replace("\n", "\n      ") for v in value)
        return f"[\n{items},\n    ]"
    if isinstance(value, dict):
        items = ",\n".join(
            f"      {k}: {_ts_value(v).replace(chr(10), chr(10)+'      ')}" for k, v in value.items()
        )
        return f"{{\n{items},\n    }}"
    raise TypeError(f"unsupported type: {type(value)}")


def generate_ts():
    out = ROOT / "backend" / "src" / "lib" / "abis.ts"
    lines = [
        "// ABI definitions for Q-Trust contracts (generated from Forge artifacts).",
        "// Regenerate: python3 scripts/generate_abis.py --target ts",
        "",
    ]

    for name, contract in ALL_CONTRACTS.items():
        artifact_path = ARTIFACT_DIR / f"{contract}.sol" / f"{contract}.json"
        if not artifact_path.exists():
            print(f"  SKIP {contract} (artifact not found)", file=sys.stderr)
            continue
        artifact = json.loads(artifact_path.read_text())
        const_name = name[0].upper() + name[1:] + "Abi"
        entries = []
        for item in artifact["abi"]:
            body = ",\n".join(
                f"      {k}: {_ts_value(v).replace(chr(10), chr(10)+'      ')}" for k, v in item.items()
            )
            entries.append(f"    {{\n{body},\n    }}")
        lines.append(f"export const {const_name} = [")
        lines.append(",\n".join(entries))
        lines.append("] as const;")
        lines.append("")

    # AuditResult helper
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

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    print(f"  TS  -> {out.relative_to(ROOT)}  ({len(ALL_CONTRACTS)} contracts)")


# ── Python generation ────────────────────────────────────────────────────────

def generate_py():
    out = ROOT / "sdk" / "qtrust" / "contracts.py"
    lines = [
        '"""ABI definitions for Q-Trust smart contracts (generated from Forge artifacts)."""',
        "# Regenerate: python3 scripts/generate_abis.py --target py",
        "",
    ]

    py_names = {}
    for name, contract in ALL_CONTRACTS.items():
        artifact_path = ARTIFACT_DIR / f"{contract}.sol" / f"{contract}.json"
        if not artifact_path.exists():
            print(f"  SKIP {contract} (artifact not found)", file=sys.stderr)
            continue
        artifact = json.loads(artifact_path.read_text())
        const_name = name.upper() + "_ABI" if name.isupper() else "_".join(
            c.upper() if c.isupper() else c.lower() for c in name
        ).upper() + "_ABI"
        # Simpler naming: just uppercase with underscores
        const_name = "".join(f"_{c}" if c.isupper() and i > 0 else c.upper() for i, c in enumerate(name)).lstrip("_") + "_ABI"
        abi = json.dumps(artifact["abi"], indent=2)
        abi = abi.replace(": true", ": True").replace(": false", ": False").replace(": null", ": None")
        lines.append(f"{const_name} = {abi}")
        lines.append("")
        py_names[const_name] = name

    lines.append("ABI_REGISTRY = {")
    for const_name in py_names:
        lines.append(f'    "{const_name}": {const_name},')
    lines.append("}")
    lines.append("")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    print(f"  PY  -> {out.relative_to(ROOT)}  ({len(py_names)} contracts)")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Regenerate ABI bindings from Forge artifacts")
    parser.add_argument("--target", choices=["ts", "py", "all"], default="all")
    args = parser.parse_args()

    if not ARTIFACT_DIR.exists():
        print(f"ERROR: {ARTIFACT_DIR} not found — run 'forge build' first", file=sys.stderr)
        sys.exit(1)

    print("Generating ABIs...")
    if args.target in ("ts", "all"):
        generate_ts()
    if args.target in ("py", "all"):
        generate_py()
    print("Done.")


if __name__ == "__main__":
    main()
