"""
Unified evaluation — §31 5 levels, §63 report structure.

Runs synthetic / open_source / expert / temporal / adversarial / migration_outcomes
and writes results/discovery.md etc.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


LEVELS = ["synthetic", "open_source", "expert", "temporal", "adversarial", "migration_outcomes"]


def run_all(splits_dir: Path, out_path: Path) -> Dict[str, Any]:
    """Run 5-level evaluation — honest: no fabricated metrics (REG-08 fix).

    If splits are missing, returns ``is_demo: true`` and does NOT claim τ values.
    This prevents README_FACTORY from quoting placeholder numbers as benchmark output.
    """
    import sys

    if not splits_dir.exists() or not any(splits_dir.iterdir()):
        msg = f"splits_dir {splits_dir} missing — run `python -m qtrust.data.splits` first. No metrics fabricated."
        print(f"::warning::{msg}", file=sys.stderr)
        report: Dict[str, Any] = {"levels": LEVELS, "results": {}, "is_demo": True, "warning": msg}
        for lvl in LEVELS:
            report["results"][lvl] = {"status": "not_available", "note": "splits missing — see docs/TRUTH_AUDIT.md"}
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2))
        return report

    report = {"levels": LEVELS, "results": {}, "is_demo": False}
    # In production, each level would call its real harness:
    #   synthetic: planner/qtrust_planner/benchmark.py
    #   expert: qtrust_data/gold/riskbench-v1 with QTrustRiskBench.load_real()
    # For this audit fix, we mark all as not_available until harnesses are wired,
    # rather than returning hardcoded tau 0.971/0.807 that README quoted as real.
    for lvl in LEVELS:
        report["results"][lvl] = {"status": "not_available", "note": "harness not yet wired — see docs/TRUTH_AUDIT.md for real values"}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--splits", type=str, default="qtrust/data/splits")
    p.add_argument("--out", type=str, default="qtrust_bench/evaluation/report.json")
    args = p.parse_args()
    run_all(Path(args.splits), Path(args.out))
    print(f"Report → {args.out}")
