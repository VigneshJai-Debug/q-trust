"""
DVC manager — §51, §25 pipeline versioning.
"""
from __future__ import annotations

import subprocess


def dvc_repro(target: str = "evaluate") -> None:
    subprocess.run(["dvc", "repro", target], check=False)


def dvc_push() -> None:
    subprocess.run(["dvc", "push"], check=False)
