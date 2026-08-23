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
import os
import sys
from pathlib import Path


def _ensure_qtrust_inspector_importable() -> None:
    """Make qtrust_inspector importable without pip install.

    Prefers an already-installed (pip) package; on ImportError appends candidate
    repo-checkout paths — QTRUST_INSPECTOR_PATH entries first (os.pathsep-
    separated), then the conventional <repo>/inspector layout derived from this
    script's location. Callers retry the import afterwards.
    """
    try:
        import qtrust_inspector  # noqa: F401

        return
    except ImportError:
        pass

    candidates: list[str] = []
    raw = os.environ.get("QTRUST_INSPECTOR_PATH")
    if raw:
        candidates.extend(p.strip() for p in raw.split(os.pathsep) if p.strip())
    repo_root = Path(__file__).resolve().parents[2]
    candidates.append(str(repo_root / "inspector"))
    candidates.append(str(repo_root / "sdk"))
    for cand in candidates:
        if Path(cand).is_dir() and cand not in sys.path:
            sys.path.insert(0, cand)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a Q-Trust inspector scan and emit JSON.")
    parser.add_argument(
        "--scan-type",
        choices=["source", "manifests", "full"],
        required=True,
        help="Which scanners to run",
    )
    parser.add_argument("--path", required=True, help="Absolute directory path to scan")
    parser.add_argument(
        "--binaries",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include binary/archive crypto-artifact scan (full scan type only)",
    )
    parser.add_argument(
        "--ast",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable AST-based crypto API detection (merged and deduped with regex results)",
    )
    args = parser.parse_args()

    scan_root = Path(args.path)
    if not scan_root.is_absolute():
        print(json.dumps({"error": "--path must be an absolute directory"}))
        return 2
    if not scan_root.is_dir():
        print(json.dumps({"error": f"path does not exist or is not a directory: {args.path}"}))
        return 2

    try:
        _ensure_qtrust_inspector_importable()
        from qtrust_inspector.manifest_scanner import scan_manifest
        from qtrust_inspector.source_scanner import scan_source_directory
    except ImportError as exc:
        print(json.dumps({"error": f"qtrust_inspector unavailable: {exc}"}))
        return 3

    findings: list[dict] = []
    detector_capabilities: dict[str, str] | None = None
    try:
        if args.scan_type in ("source", "full"):
            source_findings = list(scan_source_directory(str(scan_root)))
            if args.ast:
                from qtrust_inspector.ast_scanner import (
                    DETECTOR_CAPABILITIES,
                    merge_findings_dedupe,
                    scan_source_directory_ast,
                )

                source_findings = merge_findings_dedupe(
                    source_findings,
                    scan_source_directory_ast(str(scan_root)),
                )
                detector_capabilities = dict(DETECTOR_CAPABILITIES)
            for finding in source_findings:
                findings.append(finding.model_dump())
        if args.scan_type in ("manifests", "full"):
            for finding in scan_manifest(str(scan_root)):
                findings.append(finding.model_dump())
        if args.scan_type == "full" and args.binaries:
            from qtrust_inspector.binary_scanner import scan_binaries_in_directory
            for finding in scan_binaries_in_directory(str(scan_root)):
                findings.append(finding.model_dump())
    except Exception as exc:  # noqa: BLE001 - surface any scan failure as JSON
        print(json.dumps({"error": f"scan failed: {exc}"}))
        return 4

    payload: dict = {"findings": findings}
    if detector_capabilities is not None:
        payload["detector"] = detector_capabilities
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
