#!/usr/bin/env python3
"""Evaluate the trained RL migration agent on REAL, host-disjoint enterprise CBOMs.

Reproducible generator for ``planner/results/rl_benchmark_real_cbom.json``:

  * The 40 host-disjoint real CBOMs are packed into enterprise estates with a
    deterministic packing (``scripts/train_real_models.py::pack_graph_cboms``,
    seed 99) so evaluation sees the same 6-26-asset real estates the agent was
    trained on (raw per-host CBOMs are 2-9 assets and every policy trivially
    completes them).
  * Real TLS findings carry no explicit criticality, so each normalized asset
    gets a deterministic scan-derived risk label
    (``train_real_models.risk_criticality_from_scan`` — RSA-1024 → critical,
    RSA-2048 → high, expired/self-signed/near-expiry raise the class). Without
    this every asset defaulted to ``medium``, the reward had no order-dependent
    term, and *every* completing policy scored identically — the benchmark was
    degenerate and the earlier "beats the heuristic on real estates" headline
    (agent 130.20 vs heuristic 112.40) was not reproducible by any script in
    the repo. The archived synthetic-feasible comparison lives in
    ``scripts/eval_rl_agent.py`` and remains the reference for sequencing skill
    on deadline-pressured estates.
  * Three policies on identical environments:
      1. the trained RL agent (greedy argmax rollouts),
      2. the criticality-priority heuristic (deterministic baseline),
      3. a random baseline.
  * Metrics: mean reward (+std/min/max across environments), the fraction of
    assets actually migrated (completion), and the win/tie/loss tally vs the
    heuristic per environment.

Usage:
    python scripts/eval_rl_real_cbom.py                          # writes planner/results/rl_benchmark_real_cbom.json
    python scripts/eval_rl_real_cbom.py --model planner/rl_agent_real.pt --out /tmp/rl_bench.json
    python scripts/eval_rl_real_cbom.py --n-envs 40 --pack-seed 99
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import random
import statistics
import sys
import time
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "planner"))

from qtrust_planner._device import resolve_device  # noqa: E402
from qtrust_planner.rl_agent import (  # noqa: E402
    MigrationAgent,
    MigrationEnvironment,
    state_to_tensors,
)

CBOM_DIR = ROOT / "planner" / "data" / "real_cboms"
DEFAULT_MODEL = ROOT / "planner" / "rl_agent_real.pt"
RESULT_PATH = ROOT / "planner" / "results" / "rl_benchmark_real_cbom.json"


def _import_train_real_models():
    """Load the packing helpers from scripts/train_real_models.py without
    executing its ``__main__`` block (scripts/ has no package __init__)."""
    path = ROOT / "scripts" / "train_real_models.py"
    spec = importlib.util.spec_from_file_location("train_real_models", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["train_real_models"] = mod
    spec.loader.exec_module(mod)
    return mod


def build_real_environments(n_envs: int, pack_seed: int) -> list[MigrationEnvironment]:
    """Pack the 40 host-disjoint real CBOMs into enterprise estates (same
    deterministic packing as training) and build one env per pack."""
    trm = _import_train_real_models()
    paths = sorted(CBOM_DIR.glob("*.json"))
    if not paths:
        raise FileNotFoundError(f"no real CBOMs in {CBOM_DIR}")
    findings = trm.load_real_findings(paths)
    assets = [trm.normalize_asset(trm.enrich_asset_criticality(f)) for f in findings]
    assets = [a for a in assets if a["algorithm"] != "Unknown" or a["key_size"]]
    packs = trm.pack_graph_cboms(assets, n_packs=n_envs, seed=pack_seed)
    from collections import Counter
    crit = Counter((a.get("criticality") or "medium") for a in assets)
    print(f"real-asset criticality (scan-derived): {dict(crit)}")
    return [MigrationEnvironment.from_cbom(pack, seed=i) for i, pack in enumerate(packs)]

_CRIT_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _greedy_rollout(agent: MigrationAgent, env: MigrationEnvironment, device: str) -> tuple[float, int]:
    state = env.reset()
    total_r = 0.0
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
        if done:
            break
    return total_r, sum(env.migrated)


def _criticality_heuristic(env: MigrationEnvironment) -> tuple[float, int]:
    state = env.reset()
    total_r = 0.0
    while state.available:
        action = max(
            state.available,
            key=lambda i: _CRIT_WEIGHT.get(state.assets[i]["criticality"], 2),
        )
        state, reward, done, _ = env.step(action)
        total_r += reward
        if done:
            break
    return total_r, sum(env.migrated)


def _random_baseline(env: MigrationEnvironment) -> tuple[float, int]:
    state = env.reset()
    total_r = 0.0
    while state.available:
        action = random.choice(state.available)
        state, reward, done, _ = env.step(action)
        total_r += reward
        if done:
            break
    return total_r, sum(env.migrated)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=str, default=str(DEFAULT_MODEL))
    parser.add_argument("--out", type=str, default=str(RESULT_PATH))
    parser.add_argument("--seed", type=int, default=7, help="RNG seed for the random baseline")
    parser.add_argument("--device", type=str, default=None)
    parser.add_argument("--n-envs", type=int, default=40, help="number of packed real-CBOM envs")
    parser.add_argument("--pack-seed", type=int, default=99,
                        help="packing seed (99 = same packing as train_real_models.py)")
    args = parser.parse_args()

    device = str(resolve_device(args.device))
    agent = MigrationAgent(n_features=6, hidden_dim=128)
    sd = torch.load(args.model, map_location="cpu", weights_only=True)
    agent.load_state_dict(sd)
    agent.to(device)
    agent.eval()

    random.seed(args.seed)
    torch.manual_seed(args.seed)

    envs = build_real_environments(args.n_envs, args.pack_seed)
    agent_r, heur_r, rand_r = [], [], []
    agent_m, heur_m, rand_m, total = 0, 0, 0, 0
    agent_wins, ties = 0, 0
    print(f"Device: {device} · {len(envs)} packed real-CBOM environments "
          f"(pack_seed={args.pack_seed})\n")
    print(f"{'env':>5} {'n':>4} {'agent':>8} {'heuristic':>9} {'random':>8}  delta_vs_heur")
    for i, env in enumerate(envs):
        n = env.n_assets
        total += n
        ar, am = _greedy_rollout(agent, env, device)
        hr, hm = _criticality_heuristic(env)
        rr, rm = _random_baseline(env)
        agent_r.append(ar)
        heur_r.append(hr)
        rand_r.append(rr)
        agent_m += am
        heur_m += hm
        rand_m += rm
        if ar > hr + 1e-9:
            agent_wins += 1
        elif abs(ar - hr) <= 1e-9:
            ties += 1
        print(f"{i:>5} {n:>4} {ar:>8.2f} {hr:>9.2f} {rr:>8.2f}  {ar - hr:+.2f}")

    n = len(agent_r)
    losses = n - agent_wins - ties
    report = {
        "protocol": "real-CBOM greedy rollout (40 host-disjoint real CBOMs, scan-derived criticality)",
        "n_envs": n,
        "agent_mean_reward": round(statistics.mean(agent_r), 3),
        "agent_std": round(statistics.stdev(agent_r), 3) if n > 1 else 0.0,
        "agent_min": round(min(agent_r), 3),
        "agent_max": round(max(agent_r), 3),
        "packing": {"protocol": "pack_graph_cboms (train_real_models.py)",
                     "n_packs": args.n_envs, "pack_seed": args.pack_seed,
                     "env_sizes": sorted(len(e.assets) for e in envs)},
        "criticality": "risk_criticality_from_scan (train_real_models.py): RSA-1024 -> critical, "
                        "RSA<3072 -> high, expired/self-signed/near-expiry raise class; "
                        "real TLS findings carry no explicit criticality (previous all-medium "
                        "default made the benchmark degenerate)",
        "agent_completion_rate": round(agent_m / total, 4),
        "heuristic_mean_reward": round(statistics.mean(heur_r), 3),
        "heuristic_completion_rate": round(heur_m / total, 4),
        "random_baseline_mean_reward": round(statistics.mean(rand_r), 3),
        "random_baseline_completion_rate": round(rand_m / total, 4),
        "agent_vs_heuristic": round(statistics.mean(agent_r) - statistics.mean(heur_r), 3),
        "agent_vs_random": round(statistics.mean(agent_r) - statistics.mean(rand_r), 3),
        "agent_beats_heuristic_on": f"{agent_wins}/{n} envs (+{ties} ties, {losses} losses)",
        "device": device,
        "trained_on": "PPO, 64 vectorized envs, packed real-CBOM estates with scan-derived risk labels (retrain_rl_real_cbom.py, seed 42)",
        "model": str(Path(args.model).relative_to(ROOT)),
        "env_seeds": "from_cbom(cbom, seed=i) for i in range(n_envs)",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"\nWrote {out}")
    print(f"Agent {report['agent_mean_reward']} ± {report['agent_std']} vs heuristic "
          f"{report['heuristic_mean_reward']} (Δ {report['agent_vs_heuristic']:+.2f}) vs "
          f"random {report['random_baseline_mean_reward']} (Δ {report['agent_vs_random']:+.2f}) — "
          f"beats heuristic on {agent_wins}/{n} envs")


if __name__ == "__main__":
    main()