#!/usr/bin/env python3
"""Single-run wrapper: python scripts/run_gnn_train.py <n_graphs> <epochs> <lr> <wd> <seed> <out.pt>"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "planner"))

from qtrust_planner.train_gpu import train_gpu  # noqa: E402

n_graphs, epochs, lr, wd, seed, out = (
    int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]),
    float(sys.argv[4]), int(sys.argv[5]), sys.argv[6],
)
train_gpu(
    n_graphs=n_graphs, epochs=epochs, batch_size=256,
    learning_rate=lr, weight_decay=wd, seed=seed,
    norm="layer", model_path=out, device_name="cuda",
)
