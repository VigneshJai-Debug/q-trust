#!/usr/bin/env python3
"""Retrain the RL migration agent on REAL, host-disjoint enterprise CBOMs.

Reproducible generator for ``planner/rl_agent_real.pt`` and the config behind
``planner/results/rl_benchmark_real_cbom.json``:

  * The 40 real CBOMs (280 hosts) are packed into 100 enterprise estates with
    the same deterministic packing used by ``scripts/train_real_models.py``
    (``pack_graph_cboms``, seed 99) so training sees real 6-26-asset estates
    rather than the raw 2-9-asset per-host CBOMs.
  * Real TLS findings are stamped with a blanket ``criticality: medium`` by
    the CBOM builder, which would flatten every asset to one class and leave
    the reward with no order-dependent term (no gradient). Each finding is
    therefore re-labelled with ``risk_criticality_from_scan``
    (``train_real_models.py``) before packing — a deterministic function of
    the real certificate attributes (RSA-1024 → critical, RSA-2048 → high,
    expired/self-signed/near-expiry raise the class).
  * PPO with 64 vectorized envs, 4 PPO epochs, entropy bonus 0.01,
    deterministic kernels (same seed → same agent). NOTE: one rollout costs
    ~2.9 s on an A100, so 4,000 episodes is ~3 hours; the canonical committed
    agent was trained for 190 episodes (a ~10-minute run) — its reward had
    converged (8.86 @ 100 → 8.82 @ 190, best 8.86) and it matches the doctrine
    heuristic on the real-CBOM benchmark (see ``eval_rl_real_cbom.py``). Run
    the full 4,000 for a longer-horizon agent: it costs ~3 h of A100 time.

Usage:
    python scripts/retrain_rl_real_cbom.py                        # 4000 episodes -> planner/rl_agent_real.pt
    python scripts/retrain_rl_real_cbom.py 190 /tmp/rl.pt 42      # ~10-min CI-sized run
"""
from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "planner"))

from qtrust_planner.rl_agent import train_agent_ppo  # noqa: E402

CBOM_DIR = ROOT / "planner" / "data" / "real_cboms"
DEFAULT_OUT = ROOT / "planner" / "rl_agent_real.pt"


def _import_train_real_models():
    path = ROOT / "scripts" / "train_real_models.py"
    spec = importlib.util.spec_from_file_location("train_real_models", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["train_real_models"] = mod
    spec.loader.exec_module(mod)
    return mod


def build_real_pack_factory(n_packs: int = 100, pack_seed: int = 99):
    """env_factory cycling real-CBOM packs (from_cbom, per-env seed)."""
    trm = _import_train_real_models()
    paths = sorted(CBOM_DIR.glob("*.json"))
    if not paths:
        raise FileNotFoundError(f"no real CBOMs in {CBOM_DIR}")
    findings = trm.load_real_findings(paths)
    assets = [trm.normalize_asset(trm.enrich_asset_criticality(f)) for f in findings]
    assets = [a for a in assets if a["algorithm"] != "Unknown" or a["key_size"]]
    packs = trm.pack_graph_cboms(assets, n_packs=n_packs, seed=pack_seed)
    print(f"Built {len(packs)} packed real-CBOM environments "
          f"(size {min(len(p['assets']) for p in packs)}-{max(len(p['assets']) for p in packs)})")

    from qtrust_planner.rl_agent import MigrationEnvironment  # noqa: PLC0415

    cycle: dict[str, int] = {"i": 0}

    def factory() -> MigrationEnvironment:
        i = cycle["i"]
        cycle["i"] += 1
        return MigrationEnvironment.from_cbom(packs[i % len(packs)], seed=i)

    return factory


if __name__ == "__main__":
    episodes = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    out = sys.argv[2] if len(sys.argv) > 2 else str(DEFAULT_OUT)
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 42

    random.seed(seed)
    train_agent_ppo(
        n_episodes=episodes,
        n_envs=64,
        save_path=out,
        seed=seed,
        learning_rate=3e-4,
        ppo_epochs=4,
        entropy_coef=0.01,
        value_coef=0.5,
        env_factory=build_real_pack_factory(),
    )
    print(f"\nRetrained real-CBOM PPO agent -> {out}")