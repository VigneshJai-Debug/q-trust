#!/usr/bin/env python3
"""
Expand real CBOM dataset — QTRUST-006.

Target: 1,000+ orgs, 10,000+ CBOM snapshots, 100k+ services, 1M+ crypto assets.

Current: 277 hosts → 37 CBOMs (prototype). This script:

1. Extends CURATED_HOSTS to 1k+ via Tranco top 1k + cloud provider host discovery
2. Scans with host-disjoint, org-disjoint splits (no host in >1 split)
3. Validates via near-duplicate embedding dedup (hash of cert chains)
4. Writes to qtrust_data/gold/cboms/ with lineage

Usage:
    python scripts/expand_real_cbom.py --target 1000 --workers 32 --out qtrust_data/gold/cboms
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from build_real_datasets import CURATED_HOSTS

def main():
    ap = argparse.ArgumentParser(description="Expand real CBOM to 1k orgs (QTRUST-006)")
    ap.add_argument("--target", type=int, default=1000, help="Target orgs/hosts")
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--out", type=str, default="qtrust_data/gold/cboms")
    args = ap.parse_args()
    print(f"QTRUST-006: Current {len(CURATED_HOSTS)} curated hosts → target {args.target}")
    print("Plan: Tranco 1k + AWS/Azure/GCP host discovery + certificate transparency logs")
    print("Splits: host-disjoint, org-disjoint, temporal (see qtrust/data/splits.py)")
    print(f"Out: {args.out} (DVC-tracked, not git)")
    # In production, this would invoke scan_hosts.py with extended host list
    # For now, emit manifest
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "MANIFEST.json").write_text(json.dumps({"current": len(CURATED_HOSTS), "target": args.target, "status": "planned", "note": "Run build_real_datasets.py --parts tls --hosts 1000 to populate"}, indent=2))
    print("Manifest written. See docs/TRUTH_AUDIT.md: current 39 CBOMs is REAL but prototype — not enterprise AI claim.")

if __name__ == "__main__":
    main()
