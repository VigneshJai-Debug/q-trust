"""Robust CUDA-vs-CPU device resolution for the inspector's ML modules.

``torch.cuda.is_available()`` can return True even when the reported device is
not actually usable in the current environment (e.g. a container with no
accessible driver), so a naive auto-select picks CUDA and then fails on the
first operation. This helper performs a real allocation probe and falls back
to CPU when CUDA cannot actually be used.
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