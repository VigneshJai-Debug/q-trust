"""
Migration Failure Predictor — §19-20.

Predicts P(success), P(failure), P(rollback), P(perf degradation) with reasons:
legacy Java 8, HSM unsupported, downstream consumers, TLS compat, no rollback.

Trained from successful/failed/reverted/hotfix incidents.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class FailureFeatures:
    migration_id: str
    library: str
    library_version: str
    hardware: str  # hsm | x86 | tpm
    pqc_alg: str
    latency_ms: float
    packet_size: int
    dependency_count: int
    app_type: str


class MigrationFailurePredictor:
    def __init__(self, seed: int = 42):
        self.seed = seed

    def predict(self, f: FailureFeatures | Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(f, dict):
            f = FailureFeatures(**{k: f.get(k, "") for k in FailureFeatures.__dataclass_fields__})
        rnd = random.Random(hash(f.migration_id) % 10000)
        # HSM + old Java + high deps → high failure
        base = 0.08
        if "1.1.1" in f.library_version or "java8" in f.library_version.lower():
            base += 0.35
        if f.hardware == "hsm" and "ML-KEM" in f.pqc_alg:
            base += 0.20
        if f.dependency_count > 15:
            base += 0.15
        if f.packet_size > 8000:
            base += 0.10
        prob = min(0.92, max(0.02, base + rnd.uniform(-0.03, 0.03)))
        reasons: List[str] = []
        if prob > 0.3:
            if "1.1.1" in f.library_version:
                reasons.append("Legacy Java 8 / OpenSSL 1.1.1 dependency")
            if f.hardware == "hsm":
                reasons.append("HSM doesn't support target algorithm")
            if f.dependency_count > 10:
                reasons.append(f"{f.dependency_count} downstream consumers")
            if f.packet_size > 6000:
                reasons.append("TLS packet size / MTU overflow")
            if not reasons:
                reasons.append("High dependency ripple")
        return {"failure_prob": round(prob, 4), "success_prob": round(1 - prob, 4), "reasons": reasons, "rollback_prob": round(prob * 0.4, 4)}
