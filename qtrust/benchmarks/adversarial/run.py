"""
Adversarial benchmark — §40.

Obfuscation, aliases, wrappers, dynamic imports, vendored deps, dead code, etc.
Differentiation from competitors.
"""
from __future__ import annotations

from typing import Any, Dict, List

import random

ADVERSARIAL_TEMPLATES = [
    ("python", 'r + "s" + "a"  # obfuscated RSA', True),
    ("python", "from crypto import RSA as R; R.generate()", True),
    ("python", "importlib.import_module('cryptography')", True),
    ("python", "my_crypto.sign()  # wrapper → RSA.sign()", True),
    ("python", "def _dead():\n    RSA.generate()  # dead code", False),
    ("python", "# RSA in comment only", False),
]


def generate_adversarial(n: int = 1000, seed: int = 42) -> List[Dict[str, Any]]:
    rnd = random.Random(seed)
    out: List[Dict[str, Any]] = []
    for i in range(n):
        lang, code, is_crypto = rnd.choice(ADVERSARIAL_TEMPLATES)
        # Add misleading comment 10%
        if rnd.random() < 0.1:
            code = "# not crypto\n" + code
        out.append({"code": code, "language": lang, "is_crypto": is_crypto, "id": i, "adversarial": True})
    return out
