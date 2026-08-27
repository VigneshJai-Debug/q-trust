"""Hyperparameter protocol — Optuna + ASHA (§18), 15% GPU-hours budget.

Per §18, each track has a small declared search space; everything outside is fixed and logged.
Reporting is uniform: median of 3 seeds ± IQR, retrain winner from scratch.

Tracks:
  QTrace-FM: depth/width, patch len, mask ratio, peak lr, warmup frac
  QPlan-GT: layer count, heads, edge-type dim, PPO clip/entropy
  QScan-Code: LoRA rank/modules, data mix, lr
  QRisk: tree depth, lr, calibration temp

Usage:
    python -m qtrust_planner.hpo --track trace --n-trials 20
    python -m qtrust_planner.hpo --track plan --n-trials 10 --quick
Requires optuna; falls back to random search if not installed.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from pathlib import Path

SEARCH_SPACES = {
    "trace": {  # QTrace-FM (§13)
        "depth": [12, 16, 24],
        "width": [384, 512, 768],
        "patch_len": [16, 32, 64],
        "mask_ratio": [0.6, 0.65, 0.75],
        "peak_lr": [1e-4, 3e-4, 5e-4],
        "warmup_frac": [0.01, 0.03, 0.06],
    },
    "plan": {  # QPlan-GT (§14)
        "n_layers": [3, 4, 6],
        "n_heads": [4, 8, 12],
        "edge_type_dim": [16, 32, 64],
        "ppo_clip": [0.1, 0.2, 0.3],
        "entropy_coef": [0.01, 0.02, 0.05],
        "lr": [1e-4, 3e-4, 1e-3],
    },
    "code": {  # QScan-Code (§15)
        "lora_rank": [8, 16, 32],
        "lora_alpha": [16, 32],
        "data_mix_weight": [0.3, 0.5, 0.7],
        "lr": [1e-4, 2e-4, 5e-4],
    },
    "risk": {  # QRisk (§16)
        "tree_depth": [4, 6, 8],
        "lr": [0.01, 0.05, 0.1],
        "calibration_temp": [0.5, 1.0, 1.5, 2.0],
    },
}

def _sample_random(space: dict) -> dict:
    return {k: random.choice(v) for k, v in space.items()}

def _objective_dummy(params: dict, track: str) -> float:
    """Placeholder objective — replace with real training + eval_harness().

    Returns a fake score so HPO plumbing is testable on CPU without A100.
    In production, this calls train_gpu/train_ddp and eval_harness.
    """
    # Simulate 0-1 score where better params trend higher
    score = 0.5 + random.uniform(-0.1, 0.1)
    # A few params have small systematic effects so HPO finds something
    if track == "trace" and params.get("mask_ratio", 0.6) == 0.6:
        score += 0.05
    if track == "plan" and params.get("ppo_clip", 0.2) == 0.2:
        score += 0.04
    return max(0.0, min(1.0, score))

def run_hpo(track: str, n_trials: int = 20, seed: int = 42, out_path: str | None = None) -> dict:
    if track not in SEARCH_SPACES:
        raise ValueError(f"unknown track {track!r} (choose from {list(SEARCH_SPACES)})")
    space = SEARCH_SPACES[track]
    random.seed(seed)
    # Prefer Optuna if available
    try:
        import optuna  # type: ignore
        from optuna.pruners import SuccessiveHalvingPruner
        from optuna.samplers import TPESampler
        study = optuna.create_study(direction="maximize", sampler=TPESampler(seed=seed), pruner=SuccessiveHalvingPruner())
        def _optuna_objective(trial):
            params = {k: trial.suggest_categorical(k, v) for k, v in space.items()}
            score = _objective_dummy(params, track)
            # Simulate pruning
            trial.report(score, step=1)
            if trial.should_prune():
                raise optuna.TrialPruned()
            return score
        study.optimize(_optuna_objective, n_trials=n_trials)
        best = study.best_params
        best_value = study.best_value
        trials = [{"params": t.params, "value": t.value, "state": t.state.name} for t in study.trials]
        print(f"[hpo] {track}: best {best} => {best_value:.4f} ({n_trials} trials, Optuna)")
    except ImportError:
        # Fallback: random search with manual early-stopping simulation (ASHA-like)
        print("[hpo] optuna not installed — falling back to random search (install optuna for TPE+ASHA)")
        trials = []
        best = None
        best_value = -1
        for i in range(n_trials):
            params = _sample_random(space)
            value = _objective_dummy(params, track)
            trials.append({"params": params, "value": value, "state": "COMPLETE"})
            if value > best_value:
                best_value = value
                best = params
            # ASHA early stopping simulation: stop bad trials early (no compute saved in dummy, but logged)
            if i >= n_trials * 0.5 and value < best_value * 0.8:
                trials[-1]["state"] = "PRUNED"
        print(f"[hpo] {track}: best {best} => {best_value:.4f} ({n_trials} trials, random)")

    result = {
        "track": track,
        "n_trials": n_trials,
        "seed": seed,
        "best_params": best,
        "best_value": best_value,
        "trials": trials,
        "space": space,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if out_path:
        Path(out_path).write_text(json.dumps(result, indent=2))
        print(f"[hpo] written to {out_path}")
    # Also log to registry
    try:
        from .registry import log_run
        log_run(f"hpo-{track}", {"track": track, "n_trials": n_trials}, {"best_value": best_value})
    except Exception:
        pass
    return result

def main():
    parser = argparse.ArgumentParser(description="HPO with Optuna+ASHA (or random fallback)")
    parser.add_argument("--track", type=str, required=True, choices=list(SEARCH_SPACES.keys()), help="trace|plan|code|risk")
    parser.add_argument("--n-trials", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quick", action="store_true", help="quick test: 3 trials")
    parser.add_argument("--out", type=str, default=None)
    args = parser.parse_args()
    if args.quick:
        args.n_trials = 3
    out = args.out or f"planner/results/hpo_{args.track}.json"
    run_hpo(args.track, n_trials=args.n_trials, seed=args.seed, out_path=out)

if __name__ == "__main__":
    main()
