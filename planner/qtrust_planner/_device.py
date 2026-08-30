"""Honest device resolution for planner training/eval scripts.

``torch.cuda.is_available()`` can report True while the device is shared,
busy, or otherwise unusable at the moment of use (e.g. a contended A100 or a
container without driver access), so a naive auto-select picks CUDA and then
either crashes mid-training or silently runs degraded. This helper performs a
real allocation probe and falls back to CPU when CUDA cannot actually be
used right now. Benchmark artifacts that record ``device`` therefore report
where the numbers were actually produced.
"""
from __future__ import annotations

from typing import Optional

import torch


def resolve_device(preferred: Optional[str] = None) -> torch.device:
    """Return a usable ``torch.device``.

    ``preferred`` wins when given. Otherwise CUDA is used only if it is both
    reported available *and* a probe allocation succeeds; any failure falls
    back to CPU.
    """
    if preferred:
        return torch.device(preferred)
    if torch.cuda.is_available():
        try:
            torch.zeros(1, device="cuda")
            return torch.device("cuda")
        except Exception:
            pass
    return torch.device("cpu")
