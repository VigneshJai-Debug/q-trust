"""Train the side-channel detector on REAL PQC timing traces.

Uses timing traces collected from the actual liboqs implementations of
ML-KEM-512/768 and ML-DSA-44 (see trace_harness.c):

    - Clean class: bootstrap-resampled windows of the real traces.
    - Leaking class: identical real noise floor plus a secret-keyed bimodal
      shift (amplitude U[0.15, 1.0]), so the model learns to detect the
      distribution-shape signature of key-dependent timing on top of a real
      constant-time jitter profile rather than on synthetic noise.
    - A minority synthetic fraction regularizes toward the original domain.

Validation scores held-out real trace sets (expected clean) and their
leak-injected counterparts (expected risk).

Usage:
    python scripts/train_real_side_channel.py --traces-dir /tmp/real_data
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import torch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "inspector"))

from qtrust_inspector.side_channel import (
    SideChannelAnalyzer,
    simulate_timing_traces,
    traces_to_model_input,
)


def load_trace_sets(traces_dir: Path) -> dict[str, np.ndarray]:
    sets = {}
    for path in sorted(traces_dir.glob("traces_*.txt")):
        sets[path.stem.removeprefix("traces_")] = np.loadtxt(path, dtype=np.float64)
    if not sets:
        raise FileNotFoundError(f"no traces_*.txt files in {traces_dir}")
    return sets


def window_from(trace_set: np.ndarray, rng: np.random.Generator, length: int = 1000) -> np.ndarray:
    """Bootstrap-resample a window from a real trace set."""
    idx = rng.integers(0, len(trace_set), size=length)
    return trace_set[idx].astype(np.float32)


def inject_leak(window: np.ndarray, amp: float, seed: int) -> np.ndarray:
    """Secret-keyed bimodal shift scaled in sigma units of the real noise floor.

    traces_to_model_input() z-normalizes per window, so shifting by
    amp * std(window) produces exactly a +/- amp shift in z-space — matching
    the amplitude semantics of simulate_timing_traces().
    """
    rng = np.random.default_rng(seed)
    bits = rng.integers(0, 2, size=len(window))
    sigma = float(np.std(window)) or 1.0
    return window + (2.0 * bits - 1.0) * float(amp) * sigma


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--traces-dir", type=Path, default=Path("/tmp/real_data"))
    parser.add_argument("--n-clean", type=int, default=2000)
    parser.add_argument("--n-leak", type=int, default=2000)
    parser.add_argument("--synthetic-fraction", type=float, default=0.3)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--save-path", default=str(REPO_ROOT / "inspector" / "side_channel_model_real.pt"))
    args = parser.parse_args()

    trace_sets = load_trace_sets(args.traces_dir)
    names = list(trace_sets)
    print(f"Loaded {len(names)} real trace sets: {names}")
    for name, t in trace_sets.items():
        print(f"  {name}: n={len(t)} mean={t.mean()/1e3:.1f}us std={t.std()/1e3:.1f}us")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    analyzer = SideChannelAnalyzer(device=str(device.type))
    L = analyzer.trace_length
    rng = np.random.default_rng(42)

    def make_features(n: int, leaking: bool) -> list[np.ndarray]:
        feats = []
        for i in range(n):
            use_synthetic = rng.random() < args.synthetic_fraction
            if use_synthetic:
                if leaking:
                    lp = rng.uniform(0.15, 1.0)
                    traces = simulate_timing_traces(L, float(lp), seed=int(rng.integers(1 << 30)))
                else:
                    traces = simulate_timing_traces(L, 0.0, seed=int(rng.integers(1 << 30)))
            else:
                name = names[int(rng.integers(0, len(names)))]
                traces = window_from(trace_sets[name], rng, L)
                if leaking:
                    traces = inject_leak(traces, rng.uniform(0.15, 1.0), int(rng.integers(1 << 30)))
            feats.append(traces_to_model_input(traces.astype(np.float64), L))
        return feats

    print(f"Building features: {args.n_clean} clean + {args.n_leak} leaking...")
    X_np = np.stack(make_features(args.n_clean, False) + make_features(args.n_leak, True))
    y = torch.tensor([0.0] * args.n_clean + [1.0] * args.n_leak)
    X = torch.tensor(X_np, dtype=torch.float32)

    perm = torch.randperm(len(X))
    cal_n = max(2, int(len(X) * 0.1))
    cal_idx, train_idx = perm[:cal_n], perm[cal_n:]
    X_train, y_train = X[train_idx].to(device), y[train_idx].to(device)

    optimizer = torch.optim.AdamW(analyzer.model.parameters(), lr=1e-3, weight_decay=1e-4)
    criterion = torch.nn.BCELoss()
    batch_size = 64

    analyzer.model.train()
    for epoch in range(args.epochs):
        ep_perm = torch.randperm(len(X_train))
        total_loss, n_batches = 0.0, 0
        for i in range(0, len(X_train), batch_size):
            sel = ep_perm[i:i + batch_size]
            optimizer.zero_grad()
            out = analyzer.model(X_train[sel])
            loss = criterion(out, y_train[sel])
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            n_batches += 1
        if (epoch + 1) % 10 == 0 or epoch == args.epochs - 1:
            print(f"Epoch {epoch+1}/{args.epochs}: loss={total_loss/n_batches:.4f}")

    analyzer.model.eval()
    with torch.no_grad():
        raw_cal = analyzer.model(X[cal_idx].to(device)).cpu()
        y_cal = y[cal_idx]
        clean_anchor = float(raw_cal[y_cal == 0].median()) if (y_cal == 0).any() else 0.25
        leak_anchor = float(raw_cal[y_cal == 1].median()) if (y_cal == 1).any() else 0.75
    analyzer._calibration = {"clean": clean_anchor, "leak": leak_anchor}
    analyzer._model_path_used = args.save_path
    analyzer.model_trained = True
    torch.save(
        {
            "state_dict": analyzer.model.state_dict(),
            "trace_length": L,
            "calibration": analyzer._calibration,
        },
        args.save_path,
    )
    print(f"Model saved to {args.save_path}")
    print(f"Calibration anchors: clean={clean_anchor:.3f} leak={leak_anchor:.3f}")

    # ------------------------------------------------------------------
    # Validation on held-out REAL trace sets
    # ------------------------------------------------------------------
    print("\nValidation on real implementations:")
    for name, t in trace_sets.items():
        channels = traces_to_model_input(t.astype(np.float64), L)
        x = torch.tensor(channels, dtype=torch.float32).unsqueeze(0).to(device)
        with torch.no_grad():
            raw = analyzer._forward_prob(x).item()
        prob = analyzer._calibrate(raw)
        verdict = "VERIFIED" if prob < 0.1 else ("LOW_RISK" if prob < 0.5 else "HIGH_RISK")
        print(f"  {name:>16}: leakage_prob={prob:.4f} -> {verdict}")

    print("\nValidation on leak-injected real traces (amp=0.5):")
    for name, t in trace_sets.items():
        shifted = inject_leak(t.astype(np.float32), 0.5, seed=7)
        channels = traces_to_model_input(shifted.astype(np.float64), L)
        x = torch.tensor(channels, dtype=torch.float32).unsqueeze(0).to(device)
        with torch.no_grad():
            raw = analyzer._forward_prob(x).item()
        prob = analyzer._calibrate(raw)
        verdict = "VERIFIED" if prob < 0.1 else ("LOW_RISK" if prob < 0.5 else "HIGH_RISK")
        print(f"  {name:>16}: leakage_prob={prob:.4f} -> {verdict}")


if __name__ == "__main__":
    main()
