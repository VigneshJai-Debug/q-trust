#!/usr/bin/env python3
"""Evaluate the trained RL migration agent on held-out environments.

Rigorous, reproducible protocol:

- Environments are drawn with *feasible* sizes (20-50 assets) so that a good
  policy can actually complete the migration before the 365-day deadline. At
  larger sizes the total serial migration effort alone exceeds the deadline,
  so no policy — optimal or otherwise — can finish, and rewards are dominated
  by an unwinnable deadline rather than by sequencing skill.

- Three policies are compared on identical environments:
    1. The trained RL agent (greedy argmax rollouts).
    2. A criticality-priority heuristic (migrate highest-value assets first),
       the standard deterministic baseline for scheduling problems.
    3. A random baseline.

- Reported metrics: total mean reward (the RM-reward objective the agent is
  trained to maximize) **and**, crucially, the fraction of assets migrated
  (completion), because on feasible problems an informative reward must
  coincide with actually finishing the migration.

Usage:
    python scripts/eval_rl_agent.py                        # planner/rl_agent.pt, 20 envs
    python scripts/eval_rl_agent.py --model-path /tmp/rl.pt --n-envs 30 --seed 7
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent.parent
import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "planner"))

from qtrust_planner.rl_agent import (  # noqa: E402
    MigrationAgent,
    MigrationEnvironment,
    state_to_tensors,
)

# Feasible problem sizes: total serial migration effort stays well under the
# 365-day deadline so completing the migration is always possible.
FEASIBLE_MIN = 20
FEASIBLE_MAX = 50

_CRIT_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _greedy_rollout(agent: MigrationAgent, env: MigrationEnvironment, device: str) -> tuple[float, int, bool]:
    state = env.reset()
    total_r = 0.0
    steps = 0
    done = False
    while state.available:
        x, edge_index = state_to_tensors(state, device)
        with torch.no_grad():
            logits, _ = agent(x, edge_index)
        mask = torch.full_like(logits, float("-inf"))
        for a in state.available:
            mask[a] = 0.0
        action = int((logits + mask).argmax().item())
        state, reward, done, _ = env.step(action)
        total_r += reward
        steps += 1
        if done:
            break
    n_migrated = sum(env.migrated)
    return total_r, n_migrated, done


def _criticality_heuristic(env: MigrationEnvironment) -> tuple[float, int, bool]:
    """Deterministic baseline: migrate highest-criticality available asset first."""
    state = env.reset()
    total_r = 0.0
    steps = 0
    done = False
    while state.available:
        action = max(
            state.available,
            key=lambda i: _CRIT_WEIGHT.get(state.assets[i]["criticality"], 2),
        )
        state, reward, done, _ = env.step(action)
        total_r += reward
        steps += 1
        if done:
            break
    n_migrated = sum(env.migrated)
    return total_r, n_migrated, done


def _random_baseline(env: MigrationEnvironment) -> tuple[float, int, bool]:
    state = env.reset()
    total_r = 0.0
    steps = 0
    done = False
    while state.available:
        action = random.choice(state.available)
        state, reward, done, _ = env.step(action)
        total_r += reward
        steps += 1
        if done:
            break
    n_migrated = sum(env.migrated)
    return total_r, n_migrated, done


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", type=str, default=str(ROOT / "planner" / "rl_agent.pt"))
    parser.add_argument("--n-envs", type=int, default=20)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--json-out", type=str, default=None)
    args = parser.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    agent = MigrationAgent(n_features=6, hidden_dim=128)
    sd = torch.load(args.model_path, map_location="cpu", weights_only=True)
    agent.load_state_dict(sd)
    agent.to(device)
    agent.eval()

    random.seed(args.seed)
    torch.manual_seed(args.seed)
    envs = [
        MigrationEnvironment(n_assets=random.randint(FEASIBLE_MIN, FEASIBLE_MAX), seed=args.seed * 1000 + i)
        for i in range(args.n_envs)
    ]

    agent_rewards, agent_migrated, agent_total = [], 0, 0
    heur_rewards, heur_migrated, heur_total = [], 0, 0
    random_rewards, random_migrated, random_total = [], 0, 0
    for env in envs:
        n_assets = env.n_assets
        r, n_m, _ = _greedy_rollout(agent, env, device)
        agent_rewards.append(r)
        agent_migrated += n_m
        agent_total += n_assets
        r2, n_m2, _ = _criticality_heuristic(env)
        heur_rewards.append(r2)
        heur_migrated += n_m2
        heur_total += n_assets
        r3, n_m3, _ = _random_baseline(env)
        random_rewards.append(r3)
        random_migrated += n_m3
        random_total += n_assets

    n = len(agent_rewards)
    mean_agent = sum(agent_rewards) / n
    mean_heur = sum(heur_rewards) / n
    mean_random = sum(random_rewards) / n
    report = {
        "model_path": str(args.model_path),
        "n_envs": args.n_envs,
        "asset_range": [FEASIBLE_MIN, FEASIBLE_MAX],
        "seed": args.seed,
        "device": device,
        "agent_mean_reward": round(mean_agent, 3),
        "agent_completion_rate": round(agent_migrated / agent_total, 4),
        "heuristic_mean_reward": round(mean_heur, 3),
        "heuristic_completion_rate": round(heur_migrated / heur_total, 4),
        "random_baseline_mean_reward": round(mean_random, 3),
        "random_completion_rate": round(random_migrated / random_total, 4),
        "agent_vs_random": round(mean_agent - mean_random, 3),
        "agent_vs_heuristic": round(mean_agent - mean_heur, 3),
    }
    print(json.dumps(report, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2))
        print(f"Written to {args.json_out}")


if __name__ == "__main__":
    main()