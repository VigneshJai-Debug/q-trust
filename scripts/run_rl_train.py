#!/usr/bin/env python3
"""Rigorous RL PPO retrain: python scripts/run_rl_train.py <episodes> <out.pt> [seed]"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "planner"))

from qtrust_planner.rl_agent import train_agent_ppo  # noqa: E402

episodes = int(sys.argv[1])
out = sys.argv[2]
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 42

train_agent_ppo(
    n_episodes=episodes,
    n_envs=64,
    save_path=out,
    seed=seed,
    learning_rate=3e-4,
    ppo_epochs=4,
    entropy_coef=0.01,
)
