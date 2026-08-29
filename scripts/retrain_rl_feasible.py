#!/usr/bin/env python3
"""Fine-tune the RL migration agent on the SAME feasible distribution used by
scripts/eval_rl_agent.py (20-50 assets, 365-day deadline).

Motivation: the previously committed `planner/rl_agent.pt` was trained over
20-100 asset envs, many of which are infeasible under the 365-day deadline.
On the feasible distribution that the eval harness measures, that policy lags
even a criticality-priority heuristic. Retraining (or fine-tuning) on feasible
envs teaches the agent to capture the criticality / vulnerability-first signal.

Usage:
    python scripts/retrain_rl_feasible.py [episodes] [out.pt] [seed] [init.pt]
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "planner"))

from qtrust_planner.rl_agent import MigrationEnvironment, train_agent_ppo  # noqa: E402

FEASIBLE_MIN = 20
FEASIBLE_MAX = 50

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "planner" / "rl_agent.pt"


def make_feasible_factory(seed: int):
    """env_factory: regenerate a feasible-size env each call with per-env rng."""

    def factory() -> MigrationEnvironment:
        n_assets = random.randint(FEASIBLE_MIN, FEASIBLE_MAX)
        return MigrationEnvironment(n_assets=n_assets, seed=random.randint(0, 1_000_000))

    return factory


if __name__ == "__main__":
    episodes = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    out = sys.argv[2] if len(sys.argv) > 2 else str(DEFAULT_OUT)
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 2024
    init = sys.argv[4] if len(sys.argv) > 4 else str(DEFAULT_OUT)
    random.seed(seed)

    train_agent_ppo(
        n_episodes=episodes,
        n_envs=64,
        save_path=out,
        seed=seed,
        learning_rate=3e-4,
        ppo_epochs=5,
        entropy_coef=0.01,
        env_factory=make_feasible_factory(seed),
        init_path=init,
    )
    print(f"\nFine-tuned feasible-distribution agent -> {out}")