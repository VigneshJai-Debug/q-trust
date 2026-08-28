"""
Dependency Graph — Application → Library → Crypto primitive → Protocol → Certificate/key → Data

Architecture reference: ``qtrust_ai/README.md`` Phase 1 Foundation (Graph).

This module builds the typed crypto dependency graph that is the backbone for
all downstream intelligence:

    Application
        → Library (e.g. ``openssl``, ``cryptography``, `` boringssl``)
            → Crypto primitive (e.g. ``RSA-2048``, ``AES-256``, ``ECDSA-P256``)
                → Protocol (e.g. ``TLS 1.3``, ``SSH``, ``mTLS``, ``JWT``)
                    → Certificate / Key (e.g. ``RSA-2048 cert #a3f1``)
                        → Data (e.g. ``payment_records``, ``PII``)

The graph is constructed from :class:`qtrust_ai.discovery.code_detector.CryptoFinding`
and/or :class:`inspector.qtrust_inspector.models.AssetFinding` objects, with
heuristic inference when edges are not explicit (e.g. ``RSA`` found in a Python
file that imports ``ssl`` → protocol ``TLS``).

Design goals:
* Importable without ``networkx`` (pure-Python fallback adjacency).
* Deterministic node IDs (hash of type+name) so that repeated builds are stable.
* Blast-radius preparation: pre-computed reverse index + criticality annotations
  used by :mod:`qtrust_ai.graph.blast_radius`.

See ``qtrust_ai/README.md`` § Migration Engine and § Digital Twin for how the
graph feeds temporal GNN, cost predictor, and twin simulation.

Example:
    from qtrust_ai.graph.dependency_graph import DependencyGraph
    from qtrust_ai.discovery.code_detector import CryptoFinding

    g = DependencyGraph()
    g.add_node("app:payment-api", type="application", criticality="critical")
    g.add_node("lib:openssl", type="library")
    g.add_edge("app:payment-api", "lib:openssl", relation="depends_on")
    print(g.stats())
    print(g.to_dict())
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional networkx — fallback to dict adjacency
try:
    import networkx as nx  # type: ignore
    HAS_NX = True
except ImportError:
    HAS_NX = False
    nx = None  # type: ignore


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    """6-layer node taxonomy per architecture doc."""

    APPLICATION = "application"
    LIBRARY = "library"
    CRYPTO_PRIMITIVE = "crypto_primitive"
    PROTOCOL = "protocol"
    CERTIFICATE = "certificate"
    KEY = "key"
    DATA = "data"


class EdgeType(str, Enum):
    """Typed edge relations."""

    DEPENDS_ON = "depends_on"
    IMPLEMENTS = "implements"
    USES = "uses"
    NEGOTIATES = "negotiates"
    SECURES = "secures"
    ISSUED_BY = "issued_by"
    PROTECTS = "protects"
    CONTAINS = "contains"


# Heuristic mappings for graph enrichment
_CRYPTO_TO_PROTOCOL: Dict[str, str] = {
    "RSA": "TLS", "RSA-2048": "TLS", "RSA-4096": "TLS",
    "ECDSA": "TLS", "ECDSA-P256": "TLS", "ECDH": "TLS",
    "X25519": "TLS", "Ed25519": "SSH",
    "AES-256": "TLS", "AES-128": "TLS", "ChaCha20-Poly1305": "TLS",
    "ML-KEM-768": "TLS-PQC", "ML-KEM-1024": "TLS-PQC",
    "ML-DSA-65": "mTLS-PQC", "ML-DSA-87": "mTLS-PQC",
}

_CRYPTO_TO_DATA_SENSITIVITY: Dict[str, int] = {
    "RSA": 4, "ECDSA": 4, "ECDH": 4, "ML-KEM-768": 2, "AES-256": 3,
    "SHA-256": 1, "HMAC-SHA256": 2,
}

_LIBRARY_HINTS: Dict[str, str] = {
    "cryptography": "python-cryptography", "Crypto": "pycryptodome",
    "openssl": "openssl", "boringssl": "boringssl", "ring": "ring",
    "rustls": "rustls", "golang.org/x/crypto": "go-x-crypto",
    "BouncyCastle": "bouncycastle", "CryptoKit": "cryptokit",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """Typed node in the crypto dependency graph."""

    id: str
    type: NodeType
    name: str
    criticality: str = "medium"  # low|medium|high|critical
    metadata: Dict[str, Any] = field(default_factory=dict)
    sensitivity: int = 1  # 1-5 for DATA nodes
    algorithm: Optional[str] = None
    key_size: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value if isinstance(self.type, Enum) else self.type
        return d


@dataclass
class GraphEdge:
    """Directed edge with relation type."""

    src: str
    dst: str
    relation: EdgeType = EdgeType.DEPENDS_ON
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["relation"] = self.relation.value if isinstance(self.relation, Enum) else self.relation
        return d


def _node_id(node_type: str, name: str) -> str:
    """Deterministic node ID."""
    raw = f"{node_type}:{name}"
    # short hash suffix for uniqueness when names collide
    h = hashlib.sha256(raw.encode()).hexdigest()[:6]
    safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in name)[:48]
    return f"{node_type}:{safe}#{h}"


# ---------------------------------------------------------------------------
# DependencyGraph
# ---------------------------------------------------------------------------

class DependencyGraph:
    """Crypto dependency graph (6-layer model).

    Wraps either ``networkx.DiGraph`` (if available) or a pure-Python
    adjacency dict, exposing a unified API used by :mod:`qtrust_ai.graph.blast_radius`
    and the temporal GNN.

    The graph is directed: ``Application → Library → Primitive → Protocol →
    Certificate/Key → Data``. Reverse edges are indexed for blast-radius traversal.

    Example:
        >>> g = DependencyGraph()
        >>> g.add_node("payment-api", NodeType.APPLICATION, criticality="critical")
        >>> g.add_node("RSA-2048", NodeType.CRYPTO_PRIMITIVE, algorithm="RSA-2048")
        >>> g.add_edge("payment-api", "RSA-2048", EdgeType.DEPENDS_ON)
        >>> g.stats()["nodes"] >= 2
        True
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.adj: Dict[str, List[str]] = defaultdict(list)  # src -> [dst]
        self.rev_adj: Dict[str, List[str]] = defaultdict(list)  # dst -> [src]
        # optional networkx mirror
        self._nx: Any = None
        if HAS_NX:
            self._nx = nx.DiGraph()  # type: ignore

    # -- mutation ----------------------------------------------------------

    def add_node(
        self,
        name: str,
        type: NodeType | str = NodeType.APPLICATION,  # noqa: A002
        node_id: Optional[str] = None,
        criticality: str = "medium",
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        """Add (or upsert) a node.

        Args:
            name: Human-readable name (e.g. ``"payment-api"``, ``"RSA-2048"``).
            type: :class:`NodeType` or string.
            node_id: Explicit ID; if ``None`` a deterministic ID is derived.
            criticality: ``low`` | ``medium`` | ``high`` | ``critical``.
            metadata: Extra attributes.
            **kwargs: Forwarded to :class:`GraphNode` (e.g. ``algorithm``,
                ``key_size``, ``sensitivity``).

        Returns:
            The node ID.
        """
        if isinstance(type, str):
            try:
                type = NodeType(type)  # type: ignore
            except ValueError:
                type = NodeType.APPLICATION  # type: ignore
        # pyright: ignore[reportAssignmentType]
        nid = node_id or _node_id(type.value, name)  # type: ignore
        if nid in self.nodes:
            # merge metadata
            if metadata:
                self.nodes[nid].metadata.update(metadata)
            return nid
        node = GraphNode(
            id=nid, type=type, name=name,  # type: ignore
            criticality=criticality, metadata=metadata or {}, **kwargs  # type: ignore
        )
        self.nodes[nid] = node
        if self._nx is not None:
            self._nx.add_node(nid, **node.to_dict())  # type: ignore
        return nid

    def add_edge(
        self,
        src: str,
        dst: str,
        relation: EdgeType | str = EdgeType.DEPENDS_ON,
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a directed edge ``src → dst``.

        ``src`` and ``dst`` may be node IDs or names (resolved to IDs if a node
        with that name exists). If either endpoint is missing it is auto-created
        as an ``APPLICATION`` / ``DATA`` placeholder.

        Args:
            src: Source node ID or name.
            dst: Destination node ID or name.
            relation: :class:`EdgeType` or string.
            weight: Edge weight (default 1.0).
            metadata: Extra attributes.
        """
        if isinstance(relation, str):
            try:
                relation = EdgeType(relation)  # type: ignore
            except ValueError:
                relation = EdgeType.DEPENDS_ON  # type: ignore
        # Resolve names to IDs when possible (lookup by name)
        src_id = self._resolve_or_create(src, default_type=NodeType.APPLICATION)
        dst_id = self._resolve_or_create(dst, default_type=NodeType.DATA)
        # Deduplicate
        for e in self.edges:
            if e.src == src_id and e.dst == dst_id and e.relation == relation:
                return
        edge = GraphEdge(src=src_id, dst=dst_id, relation=relation, weight=weight, metadata=metadata or {})  # type: ignore
        self.edges.append(edge)
        self.adj[src_id].append(dst_id)
        self.rev_adj[dst_id].append(src_id)
        if self._nx is not None:
            self._nx.add_edge(src_id, dst_id, relation=relation.value, weight=weight)  # type: ignore

    def _resolve_or_create(self, ref: str, default_type: NodeType) -> str:
        """Resolve *ref* as node ID if present, else as name -> ID, else create."""
        if ref in self.nodes:
            return ref
        # Search by name
        for nid, node in self.nodes.items():
            if node.name == ref:
                return nid
        # Auto-create placeholder
        return self.add_node(ref, type=default_type)

    # -- building from findings --------------------------------------------

    def build_from_findings(
        self,
        findings: List[Any],
        app_name: str = "enterprise-app",
        app_criticality: str = "high",
    ) -> "DependencyGraph":
        """Populate the graph from discovery findings.

        Accepts :class:`qtrust_ai.discovery.code_detector.CryptoFinding`,
        :class:`inspector.qtrust_inspector.models.AssetFinding`, or plain
        ``dict`` objects with ``algorithm`` / ``file`` / ``criticality`` keys.

        Heuristics:
        * Each unique ``algorithm`` → ``CRYPTO_PRIMITIVE`` node.
        * ``file`` path → ``LIBRARY`` node (inferred from import hints) +
          ``APPLICATION`` node (directory / service).
        * Primitive → ``PROTOCOL`` edge via :data:`_CRYPTO_TO_PROTOCOL`.
        * Primitive → synthetic ``DATA`` node when no explicit data asset is present.

        Args:
            findings: List of finding objects / dicts.
            app_name: Default application node name.
            app_criticality: Default criticality for the application node.

        Returns:
            ``self`` for chaining.
        """
        # Ensure app node
        app_id = self.add_node(app_name, type=NodeType.APPLICATION, criticality=app_criticality)

        for f in findings:
            # Normalize to dict
            if isinstance(f, dict):
                algo = f.get("algorithm") or f.get("algo") or "UNKNOWN"
                file_path = f.get("file") or f.get("host") or f.get("path") or "unknown"
                crit = f.get("criticality", "medium")
                key_size = f.get("key_size")
            else:
                algo = getattr(f, "algorithm", None) or getattr(f, "algo", None) or "UNKNOWN"
                file_path = getattr(f, "file", None) or getattr(f, "host", None) or getattr(f, "host", "unknown")
                crit = getattr(f, "criticality", "medium")
                key_size = getattr(f, "key_size", None)

            algo_norm = str(algo).strip() or "UNKNOWN"
            if algo_norm.upper() in ("UNKNOWN", "WRAPPER", "DATAFLOW", "OBFUSCATED"):
                continue

            # Library node inferred from file path / algorithm
            lib_name = self._infer_library(file_path, algo_norm)
            lib_id = self.add_node(lib_name, type=NodeType.LIBRARY)

            # Crypto primitive
            prim_id = self.add_node(
                algo_norm, type=NodeType.CRYPTO_PRIMITIVE,
                algorithm=algo_norm, key_size=key_size, criticality=crit,
            )

            # Protocol
            proto_name = _CRYPTO_TO_PROTOCOL.get(algo_norm, _CRYPTO_TO_PROTOCOL.get(algo_norm.split("-")[0], "TLS"))
            proto_id = self.add_node(proto_name, type=NodeType.PROTOCOL)

            # Certificate / Key synthetic
            cert_name = f"{algo_norm}-cert"
            cert_id = self.add_node(cert_name, type=NodeType.CERTIFICATE, algorithm=algo_norm, key_size=key_size)

            # Data asset synthetic
            data_sens = _CRYPTO_TO_DATA_SENSITIVITY.get(algo_norm, _CRYPTO_TO_DATA_SENSITIVITY.get(algo_norm.split("-")[0], 2))
            data_name = f"data:{algo_norm.lower()}"
            data_id = self.add_node(data_name, type=NodeType.DATA, sensitivity=data_sens, criticality=crit)

            # Edges: App → Lib → Primitive → Protocol → Cert → Data
            self.add_edge(app_id, lib_id, EdgeType.DEPENDS_ON)
            self.add_edge(lib_id, prim_id, EdgeType.IMPLEMENTS)
            self.add_edge(prim_id, proto_id, EdgeType.NEGOTIATES)
            self.add_edge(proto_id, cert_id, EdgeType.USES)
            self.add_edge(cert_id, data_id, EdgeType.PROTECTS)

            # Also direct primitive → data for blast-radius shortcuts
            self.add_edge(prim_id, data_id, EdgeType.PROTECTS, weight=0.5)

        return self

    def _infer_library(self, file_path: str, algorithm: str) -> str:
        """Infer library name from file path and algorithm."""
        lower = file_path.lower()
        for hint, lib in _LIBRARY_HINTS.items():
            if hint.lower() in lower:
                return lib
        # fallback by language extension
        ext = Path(file_path).suffix.lower()
        ext_lib = {
            ".py": "python-cryptography", ".java": "bouncycastle",
            ".go": "go-x-crypto", ".rs": "ring", ".js": "node-crypto",
            ".ts": "node-crypto", ".cs": "dotnet-crypto", ".php": "php-openssl",
        }.get(ext)
        if ext_lib:
            return ext_lib
        return "openssl"

    # -- queries -----------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return graph statistics."""
        by_type = Counter(n.type.value for n in self.nodes.values())
        by_relation = Counter(e.relation.value for e in self.edges)
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "by_type": dict(by_type),
            "by_relation": dict(by_relation),
            "has_networkx": HAS_NX,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON-serializable dict."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "stats": self.stats(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def find_nodes(
        self, type: Optional[NodeType | str] = None, algorithm: Optional[str] = None  # noqa: A002
    ) -> List[GraphNode]:
        """Find nodes by type and/or algorithm."""
        result: List[GraphNode] = []
        for n in self.nodes.values():
            if type is not None:
                tval = type.value if isinstance(type, Enum) else str(type)
                if n.type.value != tval:
                    continue
            if algorithm is not None and n.algorithm != algorithm:
                continue
            result.append(n)
        return result

    def downstream(self, node_id: str, max_hops: int = 6) -> Set[str]:
        """BFS downstream (dependents) from *node_id*."""
        visited: Set[str] = set()
        queue: deque[Tuple[str, int]] = deque([(node_id, 0)])
        while queue:
            cur, hops = queue.popleft()
            if cur in visited or hops > max_hops:
                continue
            visited.add(cur)
            for nxt in self.adj.get(cur, []):
                if nxt not in visited:
                    queue.append((nxt, hops + 1))
        visited.discard(node_id)
        return visited

    def upstream(self, node_id: str, max_hops: int = 6) -> Set[str]:
        """BFS upstream (dependencies) of *node_id*."""
        visited: Set[str] = set()
        queue: deque[Tuple[str, int]] = deque([(node_id, 0)])
        while queue:
            cur, hops = queue.popleft()
            if cur in visited or hops > max_hops:
                continue
            visited.add(cur)
            for prev in self.rev_adj.get(cur, []):
                if prev not in visited:
                    queue.append((prev, hops + 1))
        visited.discard(node_id)
        return visited

    def blast_radius_inputs(self, primitive_algo: str) -> Dict[str, Any]:
        """Prepare inputs for :class:`qtrust_ai.graph.blast_radius.BlastRadius`.

        Collects direct & indirect dependents, critical services, and datasets
        reachable from all primitive nodes matching *primitive_algo*.

        Args:
            primitive_algo: Algorithm name (e.g. ``"RSA-2048"``, ``"RSA"``).

        Returns:
            Dict with ``primitive_nodes``, ``direct``, ``indirect``,
            ``critical_services``, ``datasets``.
        """
        prim_nodes = [
            n for n in self.nodes.values()
            if n.type == NodeType.CRYPTO_PRIMITIVE and (
                n.algorithm == primitive_algo or n.algorithm and primitive_algo in n.algorithm
            )
        ]
        if not prim_nodes and primitive_algo.upper() == "RSA":
            # broaden: any RSA variant
            prim_nodes = [n for n in self.nodes.values() if n.algorithm and "RSA" in n.algorithm]

        direct: Set[str] = set()
        indirect: Set[str] = set()
        critical: Set[str] = set()
        datasets: Set[str] = set()

        for pn in prim_nodes:
            # direct = 1-hop downstream
            for dst in self.adj.get(pn.id, []):
                direct.add(dst)
                node = self.nodes.get(dst)
                if node and node.criticality in ("high", "critical"):
                    critical.add(dst)
                if node and node.type == NodeType.DATA:
                    datasets.add(dst)
            # indirect = 2+ hops downstream (excluding direct)
            all_down = self.downstream(pn.id, max_hops=6)
            for nid in all_down:
                if nid not in direct:
                    indirect.add(nid)
                node = self.nodes.get(nid)
                if node and node.criticality in ("high", "critical") and node.type in (NodeType.APPLICATION, NodeType.DATA):
                    critical.add(nid)
                if node and node.type == NodeType.DATA:
                    datasets.add(nid)

        return {
            "primitive_nodes": [n.id for n in prim_nodes],
            "direct": direct,
            "indirect": indirect,
            "critical_services": critical,
            "datasets": datasets,
        }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== DependencyGraph demo ===")
    g = DependencyGraph()
    # Manual construction
    app = g.add_node("payment-api", NodeType.APPLICATION, criticality="critical")
    lib = g.add_node("openssl", NodeType.LIBRARY)
    prim = g.add_node("RSA-2048", NodeType.CRYPTO_PRIMITIVE, algorithm="RSA-2048", key_size=2048, criticality="critical")
    proto = g.add_node("TLS", NodeType.PROTOCOL)
    cert = g.add_node("cert-payment-rsa", NodeType.CERTIFICATE, algorithm="RSA-2048")
    data = g.add_node("payment_records", NodeType.DATA, sensitivity=5, criticality="critical")
    g.add_edge(app, lib, EdgeType.DEPENDS_ON)
    g.add_edge(lib, prim, EdgeType.IMPLEMENTS)
    g.add_edge(prim, proto, EdgeType.NEGOTIATES)
    g.add_edge(proto, cert, EdgeType.USES)
    g.add_edge(cert, data, EdgeType.PROTECTS)
    g.add_edge(prim, data, EdgeType.PROTECTS, weight=0.5)

    print(f"Stats: {json.dumps(g.stats(), indent=2)}")
    print(f"Downstream of {prim}: {g.downstream(prim)}")
    print(f"Upstream of {data}: {g.upstream(data)}")
    print(f"Blast inputs for RSA-2048: { {k: len(v) if isinstance(v, set) else v for k,v in g.blast_radius_inputs('RSA-2048').items()} }")
    print("\n--- build_from_findings ---")
    g2 = DependencyGraph()
    findings = [
        {"algorithm": "RSA-2048", "file": "src/auth.py", "criticality": "critical", "key_size": 2048},
        {"algorithm": "AES-256", "file": "src/crypto.java", "criticality": "high"},
        {"algorithm": "ECDSA-P256", "file": "src/tls.go", "criticality": "high"},
        {"algorithm": "SHA-256", "file": "src/hash.py", "criticality": "medium"},
        {"algorithm": "ML-KEM-768", "file": "src/pqc.rs", "criticality": "medium"},
    ]
    g2.build_from_findings(findings, app_name="checkout-service", app_criticality="critical")
    print(f"Stats: {json.dumps(g2.stats(), indent=2)}")
    print(g2.to_json()[:800] + "...")

    # Demo with real detector if available
    try:
        from qtrust_ai.discovery.code_detector import CryptoCodeDetector
        import tempfile
        from pathlib import Path
        det = CryptoCodeDetector(seed=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "app.py").write_text("import hashlib\nimport rsa\nrsa.newkeys(2048)\n")
            Path(tmpdir, "server.go").write_text('package main\nimport "crypto/tls"\n')
            findings2 = det.scan_repo(tmpdir)
            g3 = DependencyGraph()
            # Convert CryptoFinding to dict
            dicts = [{"algorithm": f.algorithm, "file": f.file, "criticality": "high"} for f in findings2]
            if dicts:
                g3.build_from_findings(dicts, app_name="demo-app")
                print(f"\n[detector->graph] {len(findings2)} findings -> graph {g3.stats()}")
            else:
                print("\n[detector->graph] no findings (expected for tiny repo)")
    except Exception as e:
        print(f"[detector->graph] skipped: {e}")
