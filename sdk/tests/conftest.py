"""Make the SDK ``qtrust`` package importable under pytest in any invocation.

This repo also ships a top-level ``qtrust/`` ML-factory package that shares the
``qtrust`` name and shadows ``sdk/qtrust`` whenever the repository root is on
``sys.path`` (e.g. running pytest from the project root, or from ``sdk/`` where
pytest walks up to the root ``conftest.py``). End-users of
``pip install qtrust-sdk`` never hit this — it only affects monorepo-internal
test runs.

A plain ``sys.path.insert`` is not enough: pytest prepends per-test basedirs
and conftest directories *after* conftests run, so the ordering is not stable
across invocations. Instead we eagerly import ``qtrust`` here, which registers
``sdk/qtrust`` in ``sys.modules``; every later ``from qtrust import ...`` in
the tests then resolves to the SDK regardless of sys.path order.
"""
import sys
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parent.parent
# Unconditional: an editable install may already put sdk/ on sys.path but at a
# later position than the repo root — the eager import below must win.
sys.path.insert(0, str(SDK_ROOT))

# Prefer the SDK's own package over any other ``qtrust`` on sys.path. If this
# ever fails, the SDK install/checkout is broken and tests should fail loudly.
import qtrust  # noqa: E402,F401
