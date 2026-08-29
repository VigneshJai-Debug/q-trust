#!/usr/bin/env python3
"""Retrain canonical inspector models: python scripts/run_inspector_train.py [side_channel|anomaly]"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "inspector"))

which = sys.argv[1] if len(sys.argv) > 1 else "both"

if which in ("side_channel", "both"):
    from qtrust_inspector.side_channel import SideChannelAnalyzer

    print("=== Training canonical side-channel detector (10K clean / 10K leak, 80 ep) ===", flush=True)
    a = SideChannelAnalyzer()
    a.train_detector(
        n_clean=10_000, n_leaking=10_000, epochs=80,
        save_path=str(ROOT / "inspector" / "side_channel_model.pt"),
    )
    print("side-channel done", flush=True)

if which in ("anomaly", "both"):
    from qtrust_inspector.anomaly_detector import CBOMAnomalyDetector

    print("=== Training canonical anomaly detector (80 ep) ===", flush=True)
    det = CBOMAnomalyDetector()
    # Same protocol as scripts/train_real_models.train_anomaly but on the
    # canonical tracked checkpoint path with a deterministic seed.
    import random

    rng = random.Random(123)
    cboms = det.generate_synthetic_training_data(n_cboms=400, seed=42)
    rng.shuffle(cboms)
    cut = int(len(cboms) * 0.8)
    det.train(cboms[:cut], epochs=80, save_path=str(ROOT / "inspector" / "anomaly_model.pt"))
    print("anomaly done", flush=True)
