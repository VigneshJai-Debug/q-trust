"""Repo-wide pytest normalization.

Some environments report a CUDA device via ``torch.cuda.is_available()`` that
cannot actually be used (e.g. a container without driver access). That breaks
CPU-safe training tests because torch 2.13's ``optimizer.step()`` consults the
accelerator API even for CPU tensors. CI uses CPU-only torch wheels and never
sees this.

The probe runs in a *subprocess* so the decision cannot be poisoned by
``torch.cuda.is_available()`` already being cached in this process. When the
device is unusable we hide it via ``CUDA_VISIBLE_DEVICES`` *before* any torch
import here, so the first in-process import sees CPU-only, exactly like CI.
Healthy GPU machines are untouched (probe succeeds, env var not set).
"""
import os
import subprocess
import sys


def _cuda_is_actually_usable() -> bool:
    """Return True only if a real CUDA allocation succeeds in a fresh process."""
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import torch; torch.zeros(1, device='cuda')"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        return result.returncode == 0
    except Exception:
        return False


if not _cuda_is_actually_usable():
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
