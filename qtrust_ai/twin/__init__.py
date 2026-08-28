"""
qtrust_ai.twin — Enterprise Cryptographic Digital Twin package.

Phase 4 Enterprise per ``qtrust_ai/README.md`` § Digital Twin:

* :mod:`qtrust_ai.twin.digital_twin` — Enterprise Cryptographic Digital Twin:
  a simulated environment of servers, apps, networks, certificates, keys,
  libraries, protocols, dependencies, data, and vendors. Answers
  **what-if** migration questions for 500 assets *before* touching
  production:

      cost / downtime / latency / compatibility / risk / failure

  Sits at the end of the intelligence pipeline per ``qtrust_ai/__init__.py``:

      Temporal GNN → Planner → Migration Engine → **Digital Twin**
      → Safe Simulation → Execution → Continuous Monitor

  The twin consumes the crypto dependency graph and migration roadmap
  (or a synthetic enterprise inventory) and simulates each asset's
  migration outcome without side effects.

NIST alignment: PQC performance & interoperability workstream
[NCCoE Applied Cryptography — Migration to PQC].

Usage::

    from qtrust_ai.twin.digital_twin import DigitalTwin, TwinInventory, WhatIfScenario

    twin = DigitalTwin(seed=42)
    twin.build_from_inventory(inventory)  # or twin.generate_enterprise(n=500)
    result = twin.simulate(scenario="aggressive", assets_to_migrate=500)
    print(result.total_cost_usd, result.compatibility_rate, result.risk_reduction)

All simulations are CPU-friendly, deterministic (seeded), and importable
without ``torch`` / ``sklearn``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

try:
    from .digital_twin import (
        DigitalTwin,
        TwinInventory,
        TwinAsset,
        TwinServer,
        WhatIfScenario,
        SimulationResult,
        TwinConfig,
    )
except ImportError:  # pragma: no cover
    DigitalTwin = None  # type: ignore
    TwinInventory = None  # type: ignore
    TwinAsset = None  # type: ignore
    TwinServer = None  # type: ignore
    WhatIfScenario = None  # type: ignore
    SimulationResult = None  # type: ignore
    TwinConfig = None  # type: ignore

__all__ = [
    "DigitalTwin",
    "TwinInventory",
    "TwinAsset",
    "TwinServer",
    "WhatIfScenario",
    "SimulationResult",
    "TwinConfig",
]

__version__: str = "4.0.0-twin"
TWIN_MODULES: List[str] = [
    "qtrust_ai.twin.digital_twin",
]


def get_twin_info() -> Dict[str, Any]:
    """Return package metadata for health checks."""
    return {
        "package": "qtrust_ai.twin",
        "version": __version__,
        "phase": "4 Enterprise",
        "models": ["DigitalTwin (what-if migration, 500 assets → cost/downtime/latency/compat/risk/failure)"],
        "architecture_doc": "qtrust_ai/README.md",
        "has_digital_twin": DigitalTwin is not None,
        "layers": ["servers", "apps", "networks", "certs", "keys", "libs", "protocols", "deps", "data", "vendors"],
    }


if __name__ == "__main__":
    print("=== qtrust_ai.twin package demo ===")
    print(json.dumps(get_twin_info(), indent=2))
    if DigitalTwin is not None:
        twin = DigitalTwin(seed=42)  # type: ignore
        twin.generate_enterprise(n=50, seed=42)  # type: ignore
        print(f"\n[DigitalTwin] inventory: {len(twin.inventory.assets)} assets, {len(twin.inventory.servers)} servers")
        result = twin.simulate(scenario="hybrid-migration", assets_to_migrate=20)  # type: ignore
        print(f"[simulate] cost=${result.total_cost_usd:,.0f} downtime={result.total_downtime_hours:.1f}h compat={result.compatibility_rate:.1%} risk {result.risk_before:.0f}→{result.risk_after:.0f} failure={result.failure_prob:.1%}")
        print(f"  {result.explanation[:160]}")
