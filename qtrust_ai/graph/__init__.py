"""
qtrust_ai.graph — Graph intelligence package.

Phase 1 Foundation per ``qtrust_ai/README.md`` § The intelligence stack:

* :mod:`qtrust_ai.graph.dependency_graph` — builds the 6-layer crypto
  dependency graph ``Application → Library → Crypto primitive → Protocol →
  Certificate/key → Data`` from discovery findings.
* :mod:`qtrust_ai.graph.blast_radius` — Crypto Blast Radius model:
  ``direct + indirect + critical services + datasets`` → score 0-100.

See also ``qtrust_ai/README.md`` § How it beats the heuristic (Graph) and
§ Usage::

    from qtrust_ai.discovery.code_detector import CryptoCodeDetector
    from qtrust_ai.graph.dependency_graph import DependencyGraph
    from qtrust_ai.graph.blast_radius import BlastRadius

    findings = CryptoCodeDetector().scan_repo("./src")
    graph = DependencyGraph().build_from_findings(findings)
    radius = BlastRadius(graph).compute("RSA-2048")

All graph models are CPU-friendly with pure-Python fallbacks when
``networkx`` is absent and deterministic node IDs for reproducibility.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from .dependency_graph import DependencyGraph, GraphNode, GraphEdge, NodeType
except ImportError:  # pragma: no cover
    DependencyGraph = None  # type: ignore
    GraphNode = None  # type: ignore
    GraphEdge = None  # type: ignore
    NodeType = None  # type: ignore

try:
    from .blast_radius import BlastRadius, BlastRadiusResult
except ImportError:  # pragma: no cover
    BlastRadius = None  # type: ignore
    BlastRadiusResult = None  # type: ignore

__all__ = [
    "DependencyGraph",
    "GraphNode",
    "GraphEdge",
    "NodeType",
    "BlastRadius",
    "BlastRadiusResult",
]

__version__: str = "1.0.0-graph"
LAYER_ORDER: List[str] = [
    "application", "library", "crypto_primitive", "protocol", "certificate", "key", "data"
]

@dataclass
class GraphHealth:
    """Health summary for a graph build."""

    nodes: int = 0
    edges: int = 0
    layers_present: List[str] = None  # type: ignore
    has_networkx: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "layers_present": self.layers_present or [],
            "has_networkx": self.has_networkx,
        }


def get_graph_info() -> Dict[str, Any]:
    """Return package metadata for health checks."""
    return {
        "package": "qtrust_ai.graph",
        "version": __version__,
        "phase": "1 Foundation",
        "models": ["DependencyGraph (6-layer)", "BlastRadius (direct+indirect+critical+datasets)"],
        "layers": LAYER_ORDER,
        "architecture_doc": "qtrust_ai/README.md",
        "has_dependency_graph": DependencyGraph is not None,
        "has_blast_radius": BlastRadius is not None,
    }


if __name__ == "__main__":
    print("=== qtrust_ai.graph package demo ===")
    print(json.dumps(get_graph_info(), indent=2))
    if DependencyGraph is not None and BlastRadius is not None:
        g = DependencyGraph()  # type: ignore
        g.build_from_findings(  # type: ignore
            [
                {"algorithm": "RSA-2048", "file": "services/payment/api.py", "criticality": "critical"},
                {"algorithm": "ECDSA-P256", "file": "services/auth/tls.go", "criticality": "high"},
                {"algorithm": "AES-256", "file": "services/crypto/util.py", "criticality": "high"},
            ],
            app_name="demo-platform",
        )
        print(f"\n[DependencyGraph] stats={json.dumps(g.stats(), indent=2)}")  # type: ignore
        br = BlastRadius(g)  # type: ignore
        for prim in ["RSA-2048", "ECDSA-P256", "AES-256"]:
            r = br.compute(prim)  # type: ignore
            print(f"[BlastRadius] {prim:12s} -> {r.level:8s} {r.score:5.1f} {r.breakdown}")
    else:
        print("Graph models not importable (missing dependencies)")
