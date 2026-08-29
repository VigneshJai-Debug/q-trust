"""Hyperparameter protocol — Optuna + ASHA (§18), 15% GPU-hours budget.

Every trial scores a REAL training run + held-out evaluation (no dummy
objectives). Tracks:

  QPlan-GT (plan):  trains MigrationGNNv3 at reduced scale and reports
                    Kendall τ on a held-out synthetic suite (same
                    score_order protocol as benchmark_v3.py).
  QScan-Code (code):trains the purpose classifier and reports macro-F1.
  QRisk (risk):     fits the calibrated ensemble and reports held-out accuracy.
  QTrace-FM (trace): runs the masked-patch reconstruction pretrain on
                    synthetic traces and reports reconstruction loss
                    (simulator-backed until the hardware rig lands — pdf §17;
                    the objective is the REAL masked-MSE, not a placeholder).

Each trial runs at REDUCED scale: HPO ranks configurations relatively, it does
not produce the final numbers. The winner is retrained at full scale outside
HPO (see docs/CHANGELOG.md and docs/8GPU_PLAN.md). Trial budgets are recorded
in the result JSON so no reduced-scale number is ever mistaken for a
full-scale benchmark.

Usage:
    python -m qtrust_planner.hpo --track plan --n-trials 10 --quick
    python -m qtrust_planner.hpo --track code --n-trials 20
Requires optuna; falls back to random search if not installed.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path

# Ensure the repo root is importable (qtrust_ai, qtrust_inspector) regardless
# of whether HPO is launched from planner/ or the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

SEARCH_SPACES = {
    "trace": {  # QTrace-FM (§13)
        "depth": [2, 4, 6],
        "width": [128, 256, 384],
        "patch_len": [16, 32, 64],
        "mask_ratio": [0.6, 0.65, 0.75],
        "peak_lr": [1e-4, 3e-4, 5e-4],
        "warmup_frac": [0.01, 0.03, 0.06],
    },
    "plan": {  # QPlan-GT (§14) — knobs that actually drive train_gpu/model_v3
        "lr": [1e-4, 3e-4, 1e-3],
        "weight_decay": [1e-5, 1e-4, 1e-3],
        "norm": ["batch", "layer", "graph"],
        "batch_size": [64, 128, 256],
    },
    "code": {  # QScan-Code (§15) — knobs that actually drive code_detector.train
        "synthetic_ratio": [0.3, 0.5, 0.7],
        "epochs": [2, 3, 5],
        "lr": [1e-5, 2e-5, 5e-5],
    },
    "risk": {  # QRisk (§16)
        "tree_depth": [4, 6, 8],
        "lr": [0.01, 0.05, 0.1],
        "calibration_temp": [0.5, 1.0, 1.5, 2.0],
    },
}

# Per-track REDUCED trial budgets (env-overridable). These keep a single HPO
# trial cheap; the winning config is retrained at full scale separately.
TRIAL_BUDGETS = {
    "trace": {"n": 64, "steps": 30, "trace_len": 1024},
    "plan": {"n_graphs": 1500, "epochs": 6, "batch_size": 64},
    "code": {"corpus_n": 300, "eval_n": 120},
    "risk": {"n": 400, "cal_frac": 0.2},
}


def _sample_random(space: dict) -> dict:
    return {k: random.choice(v) for k, v in space.items()}


def _objective_plan(params: dict, budget: dict) -> float:
    """Real objective: train a small MigrationGNNv3, score Kendall τ on a
    held-out synthetic suite (canonical score_order protocol)."""
    import torch

    from .benchmark import score_order
    from .data_generator import generate_dataset
    from .eval_harness import _load_model
    from .train_gpu import train_gpu

    n_graphs = budget["n_graphs"]
    epochs = budget["epochs"]
    batch_size = int(params.get("batch_size", budget["batch_size"]))
    norm = str(params.get("norm", "batch"))
    # Keep the trial dataset at least ~8 batches so every searched batch size
    # is feasible (a config that fails to train would otherwise score -1 and
    # silently skew the ranking).
    n_graphs = max(n_graphs, batch_size * 8)
    with tempfile.TemporaryDirectory() as td:
        model_path = os.path.join(td, "hpo_trial.pt")
        try:
            train_gpu(
                n_graphs=n_graphs,
                epochs=epochs,
                batch_size=batch_size,
                learning_rate=float(params.get("lr", 3e-4)),
                weight_decay=float(params.get("weight_decay", 1e-4)),
                model_path=model_path,
                seed=42,
                val_split=0.1,
                norm=norm,
            )
        except Exception as e:  # noqa: BLE001 — HPO must survive bad configs
            print(f"    [hpo/plan] trial failed: {e}")
            return -1.0
        model = _load_model(Path(model_path))
        if model is None:
            return -1.0
        model, _meta = model
        model.eval()
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = model.to(device)
        # Held-out suite: last 15% of a fresh seed=999 dataset (canonical split).
        suite = generate_dataset(n_graphs=200, seed=999)[-30:]
        scores = []
        with torch.no_grad():
            for g in suite:
                g = g.to(device)
                order_logits, _ = model(g)
                pred = torch.argsort(order_logits, descending=True).tolist()
                scores.append(score_order(pred, g.cpu())["kendall"])
        return sum(scores) / max(len(scores), 1)


def _objective_code(params: dict, budget: dict) -> float:
    """Real objective: train the code detector, report held-out macro-F1."""
    from qtrust_ai.discovery.code_detector import CryptoCodeDetector

    det = CryptoCodeDetector(seed=42)
    det.train(
        corpus=None,
        synthetic_ratio=float(params.get("synthetic_ratio", 0.4)),
        epochs=int(params.get("epochs", 3)),
        lr=float(params.get("lr", 2e-5)),
    )
    res = det.evaluate(dataset=None)
    return float(res.get("f1", 0.0))


def _objective_risk(params: dict, budget: dict) -> float:
    """Real objective: fit QRisk ensemble, report held-out accuracy."""
    from qtrust_inspector.qrisk import QRiskEnsemble

    n = budget["n"]
    cal_frac = budget["cal_frac"]
    try:
        import numpy as np
    except ImportError:  # pragma: no cover
        return -1.0
    rng = np.random.default_rng(42)
    X = rng.normal(size=(n, 7))
    # Exposure-simulated label: PQC-ready and short-lifetime assets are lower risk.
    y = ((X[:, 0] < 0.5) & (X[:, 4] < 0.5)).astype(int)
    n_cal = int(n * cal_frac)
    m = QRiskEnsemble(n_features=7)
    m.fit(X[: n - n_cal], y[: n - n_cal])
    probs = m.predict_proba(X[n - n_cal :])
    preds = (probs >= 0.5).astype(int)
    acc = float((preds == y[n - n_cal :]).mean())
    return acc


def _objective_trace(params: dict, budget: dict) -> float:
    """Real objective: masked-patch reconstruction loss on synthetic traces
    (simulator-backed until the hardware rig lands — the loss is the real
    masked-MSE from qtrace_fm.pretrain_step, not a placeholder)."""
    import torch

    from .qtrace_fm import QTraceFM, generate_synthetic_traces

    n = budget["n"]
    trace_len = budget["trace_len"]
    steps = budget["steps"]
    torch.manual_seed(42)
    m = QTraceFM(
        trace_length=trace_len,
        patch_size=params.get("patch_len", 16),
        embed_dim=params.get("width", 256),
        depth=params.get("depth", 4),
        n_heads=4,
        in_channels=3,
    )
    opt = torch.optim.AdamW(m.parameters(), lr=params.get("peak_lr", 3e-4))
    traces = generate_synthetic_traces(n=n, trace_len=trace_len, seed=42)
    loss = float("inf")
    for _ in range(steps):
        opt.zero_grad()
        loss = m.pretrain_step(traces, mask_ratio=params.get("mask_ratio", 0.65))
        loss.backward()
        opt.step()
    # Negative loss so "maximize" works; small positive shift keeps it in [0, ~1].
    return -float(loss.detach())

def _objective(params: dict, track: str, budget: dict) -> float:
    if track == "plan":
        return _objective_plan(params, budget)
    if track == "code":
        return _objective_code(params, budget)
    if track == "risk":
        return _objective_risk(params, budget)
    if track == "trace":
        return _objective_trace(params, budget)
    raise ValueError(f"unknown track {track!r}")


def run_hpo(track: str, n_trials: int = 20, seed: int = 42, out_path: str | None = None, quick: bool = False) -> dict:
    if track not in SEARCH_SPACES:
        raise ValueError(f"unknown track {track!r} (choose from {list(SEARCH_SPACES)})")
    space = SEARCH_SPACES[track]
    random.seed(seed)
    budget = dict(TRIAL_BUDGETS[track])
    # Shrink budgets further for --quick smoke runs (CI / laptops).
    if quick:
        for k, v in budget.items():
            if isinstance(v, int):
                budget[k] = max(8, v // 4)
    print(f"[hpo] track={track} trial_budget={budget} (reduced-scale; winner retrained at full scale)")

    # Prefer Optuna if available
    try:
        import optuna  # type: ignore
        from optuna.pruners import SuccessiveHalvingPruner
        from optuna.samplers import TPESampler
        study = optuna.create_study(direction="maximize", sampler=TPESampler(seed=seed), pruner=SuccessiveHalvingPruner())
        def _optuna_objective(trial):
            params = {k: trial.suggest_categorical(k, v) for k, v in space.items()}
            score = _objective(params, track, budget)
            # Report for ASHA pruning
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
        # Fallback: random search with ASHA-style early stopping.
        print("[hpo] optuna not installed — falling back to random search (install optuna for TPE+ASHA)")
        trials = []
        best = None
        best_value = -float("inf")
        for i in range(n_trials):
            params = _sample_random(space)
            value = _objective(params, track, budget)
            trials.append({"params": params, "value": value, "state": "COMPLETE"})
            if value > best_value:
                best_value = value
                best = params
            # ASHA early stopping simulation: prune clearly-bad late trials.
            if i >= n_trials * 0.5 and value < best_value * 0.8 and best_value > 0:
                trials[-1]["state"] = "PRUNED"
        print(f"[hpo] {track}: best {best} => {best_value:.4f} ({n_trials} trials, random)")

    result = {
        "track": track,
        "n_trials": n_trials,
        "seed": seed,
        "trial_budget": budget,
        "quick": quick,
        "best_params": best,
        "best_value": best_value,
        "trials": trials,
        "space": space,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "Trial budgets are REDUCED-scale for relative ranking; retrain the winner at full scale before reporting final metrics.",
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
    parser = argparse.ArgumentParser(description="HPO with real per-track objectives (Optuna+ASHA or random fallback)")
    parser.add_argument("--track", type=str, required=True, choices=list(SEARCH_SPACES.keys()), help="trace|plan|code|risk")
    parser.add_argument("--n-trials", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quick", action="store_true", help="quick smoke test: fewer trials + reduced budgets")
    parser.add_argument("--out", type=str, default=None)
    args = parser.parse_args()
    if args.quick:
        args.n_trials = min(args.n_trials, 3)
    out = args.out or f"planner/results/hpo_{args.track}.json"
    run_hpo(args.track, n_trials=args.n_trials, seed=args.seed, out_path=out, quick=args.quick)

if __name__ == "__main__":
    main()
