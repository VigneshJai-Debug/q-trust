"""
qtrust_ai.vendor — Vendor & Supply Chain intelligence package.

Phase 4 Enterprise per ``qtrust_ai/README.md`` § Enterprise Intelligence:

* :mod:`qtrust_ai.vendor.supply_chain_risk` — Crypto Supply Chain Risk:
  ``Vendor → Product → Library → Crypto → PQC readiness``. Quantifies
  transitive supply-chain exposure (e.g. Vendor A 91/100 vs Vendor C 34/100)
  and pinpoints which product / library / primitive blocks PQC migration.
* :mod:`qtrust_ai.vendor.readiness_model` — Vendor PQC Readiness for
  procurement: predicts vendor ability to deliver PQC on time from
  library dependencies, known vulns, certification, lifecycle, and
  future compatibility.

NIST alignment: supply-chain risk management [NIST SP 800-161] + PQC
migration-discovery [NIST NCCoE] — procurement must vet vendor crypto
before purchase, not after.

Usage::

    from qtrust_ai.vendor.supply_chain_risk import SupplyChainRiskModel, Vendor
    from qtrust_ai.vendor.readiness_model import VendorReadinessModel, VendorFeatures

    scm = SupplyChainRiskModel(seed=42)
    scm.train()
    score = scm.score_vendor(vendor_a)   # 91/100
    readiness = VendorReadinessModel().predict(vendor_features)

All models are CPU-friendly with deterministic fallbacks when ``torch`` /
``sklearn`` are absent and reproducible vendor scores (seeded).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

try:
    from .supply_chain_risk import (
        SupplyChainRiskModel,
        SupplyChainRiskResult,
        Vendor,
        Product,
        Library,
        CryptoUsage,
    )
except ImportError:  # pragma: no cover
    SupplyChainRiskModel = None  # type: ignore
    SupplyChainRiskResult = None  # type: ignore
    Vendor = None  # type: ignore
    Product = None  # type: ignore
    Library = None  # type: ignore
    CryptoUsage = None  # type: ignore

try:
    from .readiness_model import (
        VendorReadinessModel,
        VendorReadinessFeatures,
        VendorReadinessPrediction,
        ReadinessLevel,
    )
except ImportError:  # pragma: no cover
    VendorReadinessModel = None  # type: ignore
    VendorReadinessFeatures = None  # type: ignore
    VendorReadinessPrediction = None  # type: ignore
    ReadinessLevel = None  # type: ignore

__all__ = [
    "SupplyChainRiskModel",
    "SupplyChainRiskResult",
    "Vendor",
    "Product",
    "Library",
    "CryptoUsage",
    "VendorReadinessModel",
    "VendorReadinessFeatures",
    "VendorReadinessPrediction",
    "ReadinessLevel",
]

__version__: str = "4.0.0-vendor-intelligence"
VENDOR_MODULES: List[str] = [
    "qtrust_ai.vendor.supply_chain_risk",
    "qtrust_ai.vendor.readiness_model",
]

# Canonical enterprise benchmark (spec: Vendor A 91/100 etc)
BENCHMARK_SCORES: Dict[str, int] = {
    "Vendor A": 91,
    "Vendor B": 67,
    "Vendor C": 34,
    "Vendor D": 78,
    "Internal": 85,
}


def get_vendor_info() -> Dict[str, Any]:
    """Return package metadata for health checks / benchmarking."""
    return {
        "package": "qtrust_ai.vendor",
        "version": __version__,
        "phase": "4 Enterprise",
        "models": [
            "SupplyChainRiskModel (Vendor→Product→Library→Crypto→PQC)",
            "VendorReadinessModel (procurement PQC readiness)",
        ],
        "benchmark_scores": BENCHMARK_SCORES,
        "architecture_doc": "qtrust_ai/README.md",
        "has_supply_chain": SupplyChainRiskModel is not None,
        "has_readiness": VendorReadinessModel is not None,
    }


if __name__ == "__main__":
    print("=== qtrust_ai.vendor package demo ===")
    print(json.dumps(get_vendor_info(), indent=2))
    if SupplyChainRiskModel is not None:
        m = SupplyChainRiskModel(seed=42)  # type: ignore
        m.train()  # type: ignore
        # Demo Vendor A 91/100 anchor
        demo_vendor = Vendor(  # type: ignore
            name="Vendor A",
            products=[
                Product(  # type: ignore
                    name="VendorA-Gateway-3.2",
                    libraries=[
                        Library(name="openssl", version="3.2.1", crypto_algorithms=["ML-KEM-768", "ML-DSA-65"], pqc_support=True),  # type: ignore
                    ],
                )
            ],
        )
        r = m.score_vendor(demo_vendor)  # type: ignore
        print(f"\n[SupplyChainRiskModel] {demo_vendor.name} -> {r.score}/100 {r.level} {r.breakdown}")
    if VendorReadinessModel is not None:
        rm = VendorReadinessModel(seed=42)  # type: ignore
        rm.train()  # type: ignore
        feats = VendorReadinessFeatures(vendor_name="Vendor A")  # type: ignore
        pr = rm.predict(feats)  # type: ignore
        print(f"\n[VendorReadinessModel] {feats.vendor_name} -> {pr.readiness_score}/100 {pr.level.value} {pr.recommendation}")
