"""Make qtrust_planner importable regardless of the pytest invocation CWD.

The planner is not pip-installed (no pyproject); tests import the package
directly from this directory.
"""
import sys
from pathlib import Path

PLANNER_ROOT = Path(__file__).resolve().parent.parent
if str(PLANNER_ROOT) not in sys.path:
    sys.path.insert(0, str(PLANNER_ROOT))
