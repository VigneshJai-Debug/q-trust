"""
Synthetic benchmark — Level 1 (§31).

Uses data_generator synthetic graphs (heuristic labels allowed ONLY for Level 1).
Higher levels must use real/expert labels.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "planner"))
from qtrust_planner.data_generator import generate_dataset


def run_synthetic(n_graphs: int = 1000, seed: int = 999) -> dict:
    ds = generate_dataset(n_graphs=n_graphs, seed=seed)
    return {
        "level": "synthetic",
        "n": n_graphs,
        "graphs": len(ds),
        "note": "synthetic only — not proof of superiority (§31)",
    }
