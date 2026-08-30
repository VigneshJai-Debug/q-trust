"""
Real-world benchmark — Level 2/3 (§31).

Unseen repositories / organizations. Repository-split, org-split, temporal.
"""
from __future__ import annotations

from pathlib import Path
import json
from qtrust.data.splits import repository_split


def run_real_world(gold_path: Path) -> dict:
    samples = json.loads(gold_path.read_text())
    split = repository_split(samples, key="repo", seed=42)
    # Evaluate discovery/risk on held-out repos
    return {"level": "real_world", "train": len(split["train"]), "test": len(split["test"]), "repos_test": split["test_repos"][:5]}
