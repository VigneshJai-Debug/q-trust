#!/usr/bin/env python3
"""Run qtrust_inspector scans and print findings as JSON to stdout.

Used by the backend scanner routes to execute real cryptographic scans
instead of returning fabricated data.

Usage:
    python3 run_inspector.py --scan-type source|manifests|full --path <directory>

Output (single JSON object on stdout):
    {"findings": [ {...}, ... ]}
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make the repo-local inspector package importable without pip install.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_INSPECTOR_DIR = _REPO_ROOT / "inspector"
for _p in (str(_INSPECTOR_DIR), str(_REPO_ROOT / "sdk")):
    if Path(_p).is_dir() and _p not in sys.path:
        sys.path.insert(0, _p)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a Q-Trust inspector scan and emit JSON.")
    parser.add_argument(
        "--scan-type",
        choices=["source", "manifests", "full"],
        required=True,
        help="Which scanners to run",
    )
    parser.add_argument("--path", required=True, help="Absolute directory path to scan")
    args = parser.parse_args()

    scan_root = Path(args.path)
    if not scan_root.is_absolute():
        print(json.dumps({"error": "--path must be an absolute directory"}))
        return 2
    if not scan_root.is_dir():
        print(json.dumps({"error": f"path does not exist or is not a directory: {args.path}"}))
        return 2

    try:
        from qtrust_inspector.manifest_scanner import scan_manifest
        from qtrust_inspector.source_scanner import scan_source_directory
    except ImportError as exc:
        print(json.dumps({"error": f"qtrust_inspector unavailable: {exc}"}))
        return 3

    findings: list[dict] = []
    try:
        if args.scan_type in ("source", "full"):
            for finding in scan_source_directory(str(scan_root)):
                findings.append(finding.model_dump())
        if args.scan_type in ("manifests", "full"):
            for finding in scan_manifest(str(scan_root)):
                findings.append(finding.model_dump())
    except Exception as exc:  # noqa: BLE001 - surface any scan failure as JSON
        print(json.dumps({"error": f"scan failed: {exc}"}))
        return 4

    json.dump({"findings": findings}, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
