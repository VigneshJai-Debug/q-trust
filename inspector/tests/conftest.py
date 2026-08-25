"""Make repo-root-relative imports work under pytest from any CWD.

``tests/test_benchmark.py`` imports ``benchmarks.score``, which lives in the
inspector root next to (not inside) the ``qtrust_inspector`` package. Adding
the inspector root to sys.path mirrors how developers run these tests locally.
"""
import sys
from pathlib import Path

INSPECTOR_ROOT = Path(__file__).resolve().parent.parent
if str(INSPECTOR_ROOT) not in sys.path:
    sys.path.insert(0, str(INSPECTOR_ROOT))
