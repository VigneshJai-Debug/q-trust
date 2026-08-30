"""
Robustness — §40 adversarial.

Tests model on obfuscated, aliased, wrapped, dynamic import samples.
"""
from __future__ import annotations

from typing import Any, Dict, List

from qtrust.benchmarks.adversarial.run import generate_adversarial


def robustness_report(model: Any, n: int = 500) -> Dict[str, Any]:
    adv = generate_adversarial(n=n)
    # Evaluate
    correct = 0
    for ex in adv:
        try:
            pred = model.predict(ex["code"], ex["language"])
            is_crypto = pred.is_crypto if hasattr(pred, "is_crypto") else bool(pred)
        except Exception:
            is_crypto = False
        if is_crypto == ex["is_crypto"]:
            correct += 1
    return {"adversarial_accuracy": correct / n, "n": n}
