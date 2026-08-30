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

    print("=== Training canonical anomaly detector (80 ep, real+synth mix) ===", flush=True)
    det = CBOMAnomalyDetector()
    import json
    import random

    # Train on the REAL host-disjoint enterprise CBOMs (live TLS scan) mixed
    # with synthetic diversity so the VAE learns real certificate
    # distributions (RSA-2048/ECDSA-P256 certs, Let's Encrypt/DigiCert
    # issuers) rather than only the synthetic generator's shape.
    real_cboms = []
    real_dir = ROOT / "planner" / "data" / "real_cboms"
    if real_dir.is_dir():
        for p in sorted(real_dir.glob("*.json")):
            try:
                cbom = json.loads(p.read_text())
                if cbom.get("assets"):
                    real_cboms.append(cbom)
            except Exception:
                continue
    if not real_cboms:
        print("  ! no real CBOMs found — falling back to synthetic-only", flush=True)

    rng = random.Random(123)
    synth = det.generate_synthetic_training_data(n_cboms=400, seed=42)
    cboms = real_cboms + synth
    rng.shuffle(cboms)
    cut = max(1, int(len(cboms) * 0.8))
    print(f"  training on {len(cboms)} CBOMs ({len(real_cboms)} real TLS-derived)", flush=True)
    det.train(cboms[:cut], epochs=80, save_path=str(ROOT / "inspector" / "anomaly_model.pt"))
    print("anomaly done", flush=True)
