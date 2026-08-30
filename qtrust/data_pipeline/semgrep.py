"""
Semgrep + dependency analysis — §4 complement to CodeQL.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict


SEMGREP_RULES = {
    "rsa-usage": {"pattern": "RSA.generate", "lang": "python", "severity": "high"},
    "ecdsa-sign": {"pattern": "ecdsa.Sign", "lang": "go", "severity": "high"},
    "aes-gcm": {"pattern": "AES.new", "lang": "python", "severity": "medium"},
    "tls-config": {"pattern": "tls.Config", "lang": "go", "severity": "high"},
}


def semgrep_available() -> bool:
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


def run_semgrep(repo_path: Path, out_path: Path) -> Dict[str, Any]:
    if semgrep_available():
        subprocess.run(
            ["semgrep", "--config=auto", "--json", f"--output={out_path / 'semgrep.json'}", str(repo_path)],
            check=False,
        )
        return {"engine": "semgrep", "repo": str(repo_path)}
    return {"engine": "heuristic", "rules": list(SEMGREP_RULES.keys())}
