"""
Migration Intelligence — Phase 2

Exports the four PQC migration models that sit between the Intelligence AI
and the Planner (per ``qtrust_ai/README.md`` and ``qtrust_ai/__init__.py``):

    Crypto Graph → PQC Recommender + Cost + Failure + Interoperability
               → Constrained Optimizer → RL Planner → Digital Twin

Each sub-module is CPU-friendly with deterministic fallbacks so that the
package is importable without ``torch`` / ``sklearn`` on CI.

Modules:
    * :mod:`qtrust_ai.migration.replacement_recommender` — purpose-aware
      PQC mapping (RSA sig→ML-DSA vs KEM→ML-KEM, version/level/CNSA).
    * :mod:`qtrust_ai.migration.cost_predictor` — engineering/testing/
      downtime/hardware/duration regression (anchored to banking-API 84h/31h).
    * :mod:`qtrust_ai.migration.failure_predictor` — prod-break probability
      + top reasons (legacy 61% etc).
    * :mod:`qtrust_ai.migration.interoperability` — client/server/PQC
      compatibility, latency, handshake, memory, bandwidth.

All models expose ``train() / predict() / evaluate()`` and are deterministic
when ``sklearn`` is absent (hash jitter).
"""

from __future__ import annotations

from typing import Dict, List

from qtrust_ai.migration.replacement_recommender import (
    PQCRecommender,
    PQCRecommendation,
    Purpose as RecommenderPurpose,
    SecurityLevel,
    StandardStatus,
)
from qtrust_ai.migration.cost_predictor import (
    CostPrediction,
    CostPredictorConfig,
    MigrationCostFeatures,
    MigrationCostPredictor,
)
from qtrust_ai.migration.failure_predictor import (
    FailureFeatures,
    FailurePrediction,
    FailurePredictorConfig,
    MigrationFailurePredictor,
)
from qtrust_ai.migration.interoperability import (
    InteropConfig,
    InteropFeatures,
    InteropResult,
    InteroperabilityPredictor,
)

__all__ = [
    "PQCRecommender",
    "PQCRecommendation",
    "RecommenderPurpose",
    "SecurityLevel",
    "StandardStatus",
    "MigrationCostPredictor",
    "MigrationCostFeatures",
    "CostPrediction",
    "CostPredictorConfig",
    "MigrationFailurePredictor",
    "FailureFeatures",
    "FailurePrediction",
    "FailurePredictorConfig",
    "InteroperabilityPredictor",
    "InteropFeatures",
    "InteropResult",
    "InteropConfig",
    "get_migration_models",
    "MIGRATION_MODULES",
]

__version__ = "2.0.0-migration-intelligence"

MIGRATION_MODULES: List[str] = [
    "qtrust_ai.migration.replacement_recommender",
    "qtrust_ai.migration.cost_predictor",
    "qtrust_ai.migration.failure_predictor",
    "qtrust_ai.migration.interoperability",
]


def get_migration_models(seed: int = 42) -> Dict[str, object]:
    """Instantiate all four migration intelligence models.

    Args:
        seed: Random seed for deterministic fallbacks.

    Returns:
        Dict ``{name: model_instance}`` with keys ``recommender``,
        ``cost``, ``failure``, ``interop``.

    Example:
        >>> models = get_migration_models(seed=0)
        >>> models["recommender"].recommend("RSA-2048", purpose="signature")
    """
    return {
        "recommender": PQCRecommender(seed=seed),
        "cost": MigrationCostPredictor(seed=seed),
        "failure": MigrationFailurePredictor(seed=seed),
        "interop": InteroperabilityPredictor(seed=seed),
    }


if __name__ == "__main__":
    print("=== qtrust_ai.migration package ===")
    print(f"version: {__version__}")
    print(f"modules: {MIGRATION_MODULES}")
    models = get_migration_models(seed=42)
    for name, model in models.items():
        print(f"  {name:15s} {model.__class__.__name__} (seed=42)")
    # Quick smoke: purpose-aware recommender
    rec = models["recommender"]  # type: ignore
    r1 = rec.recommend("RSA-2048", purpose="signature")  # type: ignore
    r2 = rec.recommend("RSA-2048", purpose="key-establishment")  # type: ignore
    print(f"\nRSA-2048 sig  -> {r1.primary_pqc} (hybrid {r1.hybrid})")
    print(f"RSA-2048 kem  -> {r2.primary_pqc} (hybrid {r2.hybrid})")
    assert r1.primary_pqc.startswith("ML-DSA") or r1.primary_pqc.startswith("SLH")
    assert r2.primary_pqc.startswith("ML-KEM") or r2.primary_pqc.startswith("HQC")
    print("✓ migration package smoke passed")
