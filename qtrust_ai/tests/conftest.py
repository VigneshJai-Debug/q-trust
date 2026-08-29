"""Make qtrust_ai importable regardless of the pytest invocation CWD.

The qtrust_ai package is not pip-installed (no pyproject); tests import it
directly from the repo root.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
