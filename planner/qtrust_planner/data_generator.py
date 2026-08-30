"""Synthetic data generator for training the MigrationGNN.

Generates random dependency graphs of cryptographic assets. Each asset gets a
node feature vector [algorithm_type, key_size, vendor_pqc_ready, criticality] and
the graph gets a random DAG of dependency edges.

The "optimal migration order" label is computed by a heuristic that prefers:
1. High criticality (more urgent)
2. Post-quantum-ready vendor (safe to migrate)
3. Fewer dependencies (can be migrated early)

We then topologically sort by priority to produce the target order 0..N-1.
"""
from __future__ import annotations

import os
import random
import sys
from datetime import datetime, timezone

import numpy as np
import torch
from torch_geometric.data import Data

# Support both `python -m gnn.data_generator` and `python gnn/data_generator.py`.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from model import encode_algorithm_type
else:
    from .model import encode_algorithm_type


# Algorithm pool with typical key sizes.
ALGORITHM_POOL = [
    ("RSA-1024", "RSA", 1024),
    ("RSA-2048", "RSA", 2048),
    ("RSA-3072", "RSA", 3072),
    ("RSA-4096", "RSA", 4096),
    ("ECC-P256", "ECC", 256),
    ("ECC-P384", "ECC", 384),
    ("ECC-P521", "ECC", 521),
    ("DSA-1024", "DSA", 1024),
    ("DSA-2048", "DSA", 2048),
    ("DH-2048", "DH", 2048),
    ("ECDH-P256", "ECDH", 256),
    ("ECDSA-P256", "ECDSA", 256),
    ("Ed25519", "EdDSA", 256),
    ("Ed448", "EdDSA", 448),
    ("SHA-256", "SHA", 256),
    ("SHA-384", "SHA", 384),
    ("SHA-512", "SHA", 512),
    ("AES-128", "AES", 128),
    ("AES-256", "AES", 256),
    ("HMAC-SHA256", "HMAC", 256),
    ("ChaCha20-Poly1305", "ChaCha20", 256),
    # Post-quantum algorithms (already PQC-ready)
    ("ML-KEM-512", "ML-KEM", 512),
    ("ML-KEM-768", "ML-KEM", 768),
    ("ML-KEM-1024", "ML-KEM", 1024),
    ("ML-DSA-44", "ML-DSA", 44),
    ("ML-DSA-65", "ML-DSA", 65),
    ("ML-DSA-87", "ML-DSA", 87),
]


def _is_pqc_algorithm(algorithm_name: str) -> bool:
    """Return True if the algorithm name is a NIST PQC standard."""
    return algorithm_name.startswith(("ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FALCON"))


# Maps CBOM criticality strings to the 1-5 integer scale used by the
# synthetic generator (randint(1, 5)).
CRITICALITY_SCORES = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Default key sizes when a real asset record omits key_size.
_DEFAULT_KEY_SIZE = {"ECC": 256, "ECDSA": 256, "ECDH": 256, "EdDSA": 256, "SHA": 256}


def _assign_labels(
    asset_records: list[tuple[str, int, bool, int]],
    edges_src: list[int],
    edges_dst: list[int],
    days_to_deadline: float,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Compute y_order / y_risk / y_priority labels for a migration graph.

    Uses the same heuristic priority as the synthetic generator so that real
    and synthetic graphs share one label semantics and can be mixed 50/50:
        priority = criticality * 2.0
                 + 1.5 if vendor_pqc_ready
                 + log1p(key_size) / 4.0 if not PQC else -1.0
                 + deadline_pressure * criticality / 5.0
                 - in_degree * 0.3
    """
    n_assets = len(asset_records)
    deadline_pressure = 2.0 if days_to_deadline < 180 else 1.0

    in_degree = np.zeros(n_assets, dtype=np.int32)
    for d in edges_dst:
        in_degree[d] += 1

    priorities = np.zeros(n_assets, dtype=np.float32)
    for i, (alg, key_size, vendor_pqc_ready, criticality) in enumerate(asset_records):
        priority = criticality * 2.0
        if vendor_pqc_ready:
            priority += 1.5  # easy migration — do it early to show progress
        if not _is_pqc_algorithm(alg):
            priority += np.log1p(key_size) / 4.0  # bigger RSA keys = more urgent
        else:
            priority -= 1.0  # already PQC — defer
        priority += deadline_pressure * criticality / 5.0  # deadline urgency
        priority -= in_degree[i] * 0.3  # nodes with many deps are harder to migrate early
        priorities[i] = priority

    sorted_indices = np.argsort(-priorities)  # descending
    y_order = np.zeros(n_assets, dtype=np.int64)
    for rank, node_idx in enumerate(sorted_indices):
        y_order[node_idx] = rank

    y_risk = np.zeros(n_assets, dtype=np.float32)
    for i, (alg, key_size, vendor_pqc_ready, criticality) in enumerate(asset_records):
        out_degree = sum(1 for s in edges_src if s == i)
        risk = out_degree * 0.15 + (1.0 if not vendor_pqc_ready else 0.0)
        if not _is_pqc_algorithm(alg) and criticality >= 4:
            risk += 0.3
        y_risk[i] = float(min(risk, 1.0))

    p_min, p_max = priorities.min(), priorities.max()
    if p_max > p_min:
        y_priority = (priorities - p_min) / (p_max - p_min)
    else:
        y_priority = np.zeros(n_assets, dtype=np.float32)

    return (
        torch.tensor(y_order, dtype=torch.long),
        torch.tensor(y_risk, dtype=torch.float32),
        torch.tensor(y_priority, dtype=torch.float32),
    )


def _cbom_days_until_expiry(asset: dict, now: datetime | None = None) -> float:
    """Best-effort days-until-expiry for a real CBOM asset (default 365)."""
    not_after = asset.get("not_after")
    if not not_after:
        return 365.0
    try:
        expiry = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
    except ValueError:
        return 365.0
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max((expiry - now).total_seconds() / 86400.0, 1.0)


def cbom_to_dependency_graph(cbom: dict, seed: int = 42) -> Data:
    """Convert a real CBOM document into a MigrationGNN training graph.

    Accepts ``qtrust.cbom.v1`` documents produced by crypto-inspector's
    ``ScanResult.to_cbom()`` as well as any dict with an ``assets`` list.

    Node features use the same 6-dim layout as ``generate_migration_graph``.
    Dependency edges are taken from each asset's explicit ``depends_on`` list
    when present; otherwise a deterministic host-affinity fallback is used
    (assets discovered on the same host depend on the host's first asset),
    restricted to edges pointing forward in insertion order so the graph
    stays acyclic.

    Returns a Data object with x, edge_index, y_order, y_risk, y_priority,
    asset_records and n_assets — drop-in mixable with generate_dataset().
    """
    rng = random.Random(seed)
    raw_assets = cbom.get("assets") or []
    n_assets = len(raw_assets)
    if n_assets == 0:
        raise ValueError("CBOM contains no assets")

    asset_records: list[tuple[str, int, bool, int]] = []
    features = torch.zeros((n_assets, 6), dtype=torch.float32)

    # Per-graph deadline: shortest cert lifetime drives the pressure signal.
    expiries = [_cbom_days_until_expiry(a) for a in raw_assets]
    days_to_deadline = min(max(min(expiries), 30.0), 730.0)
    deadline_pressure = 2.0 if days_to_deadline < 180 else 1.0

    for i, asset in enumerate(raw_assets):
        algorithm_name = str(asset.get("algorithm") or "Unknown").upper()
        key_size = asset.get("key_size")
        if not key_size:
            family = algorithm_name.split("-")[0]
            key_size = _DEFAULT_KEY_SIZE.get(family, 2048)
        key_size = int(key_size)
        criticality_score = CRITICALITY_SCORES.get(str(asset.get("criticality", "medium")).lower(), 2)
        vendor_pqc_ready = bool(asset.get("pqc_ready", False)) or _is_pqc_algorithm(algorithm_name)

        type_code = encode_algorithm_type(algorithm_name)
        required_rate = min(deadline_pressure * criticality_score / 5.0, 1.0)
        features[i] = torch.tensor([
            type_code / 14.0,
            min(key_size / 4096.0, 1.0),
            1.0 if vendor_pqc_ready else 0.0,
            criticality_score / 5.0,
            days_to_deadline / 730.0,
            required_rate,
        ], dtype=torch.float32)
        asset_records.append((algorithm_name, key_size, vendor_pqc_ready, criticality_score))

    edges_src: list[int] = []
    edges_dst: list[int] = []

    has_explicit_deps = any(a.get("depends_on") for a in raw_assets)
    first_index_by_host: dict[str, int] = {}
    for i, asset in enumerate(raw_assets):
        if has_explicit_deps:
            for dep in asset.get("depends_on") or []:
                try:
                    dep_idx = int(dep)
                except (TypeError, ValueError):
                    continue
                if dep_idx != i and 0 <= dep_idx < n_assets:
                    edges_src.append(dep_idx)   # dependency migrates first...
                    edges_dst.append(i)         # ...before the dependent
        else:
            # Host-affinity fallback: everything on a host hangs off the
            # host's primary (first-discovered) asset.
            host = str(asset.get("host") or asset.get("location") or "")
            anchor = first_index_by_host.setdefault(host, i)
            if anchor != i:
                edges_src.append(anchor)
                edges_dst.append(i)

    edge_index = torch.tensor([edges_src, edges_dst], dtype=torch.long) if edges_src else \
        torch.zeros((2, 0), dtype=torch.long)

    y_order, y_risk, y_priority = _assign_labels(
        asset_records, edges_src, edges_dst, days_to_deadline
    )
    del rng  # reserved for future stochastic augmentation of real graphs

    data = Data(
        x=features,
        edge_index=edge_index,
        y_order=y_order,
        y_risk=y_risk,
        y_priority=y_priority,
    )
    data.asset_records = asset_records  # type: ignore[attr-defined]
    data.n_assets = n_assets  # type: ignore[attr-defined]
    return data


def generate_migration_graph(n_assets: int = 100, seed: int = 42, enterprise_topology: bool | None = None) -> Data:
    """Generate a single synthetic migration dependency graph.

    Args:
        n_assets: Number of cryptographic assets (nodes) in the graph.
        seed: RNG seed for reproducibility.
        enterprise_topology: If True, use layered enterprise DAG (infra→service→edge);
            if False, use random DAG; if None, choose 70% enterprise / 30% random.

    Returns:
        A torch_geometric Data object with:
            - x: node feature tensor (n_assets, 6)
            - edge_index: dependency edges (2, E), edge [B, A] = A depends on B
            - y_order: optimal migration order label (n_assets,), values 0..n_assets-1
            - y_risk:  risk score label (n_assets,), values in [0, 1]
            - asset_records: list of (algorithm, key_size, vendor_pqc_ready, criticality)
    """
    rng = random.Random(seed)
    if enterprise_topology is None:
        enterprise_topology = False  # default random for backward-compat benchmark; set True for realistic enterprise eval

    # Graph-level deadline: 30-730 days. Pressure grows as the deadline nears.
    days_to_deadline = rng.randint(30, 730)
    deadline_pressure = 2.0 if days_to_deadline < 180 else 1.0

    # Generate node features
    asset_records: list[tuple[str, int, bool, int]] = []
    features = torch.zeros((n_assets, 6), dtype=torch.float32)

    for i in range(n_assets):
        algorithm_name, alg_type, key_size = rng.choice(ALGORITHM_POOL)
        vendor_pqc_ready = rng.random() > 0.7  # ~30% of vendors are PQC-ready
        criticality = rng.randint(1, 5)

        type_code = encode_algorithm_type(algorithm_name)
        required_rate = min(deadline_pressure * criticality / 5.0, 1.0)
        features[i] = torch.tensor([
            type_code / 14.0,
            min(key_size / 4096.0, 1.0),
            1.0 if vendor_pqc_ready else 0.0,
            criticality / 5.0,
            days_to_deadline / 730.0,
            required_rate,
        ], dtype=torch.float32)

        asset_records.append((algorithm_name, key_size, vendor_pqc_ready, criticality))

    # Generate dependency edges (B -> A means A depends on B)
    edges_src: list[int] = []
    edges_dst: list[int] = []

    if enterprise_topology:
        # Layered enterprise DAG: L0 infra (HSM/CA/DB, 15%), L1 services (40%), L2 edge (45%)
        # Edges flow L0→L1/L2 and L1→L2, matching real infra: edge services depend on infra.
        n_l0 = max(1, n_assets * 15 // 100)
        n_l1 = max(1, n_assets * 40 // 100)
        # n_l2 = remainder
        layers = [0]*n_l0 + [1]*n_l1 + [2]*(n_assets - n_l0 - n_l1)
        rng.shuffle(layers)  # shuffle node-to-layer assignment but keep layered edge constraint
        # Assign nodes to layers contiguously for acyclicity: sort nodes by layer
        # Create a permutation that sorts by layer (L0 first)
        order = sorted(range(n_assets), key=lambda i: layers[i])
        pos = {node: idx for idx, node in enumerate(order)}  # topological position
        # Cross-layer edge probability higher than intra-layer
        for a in range(n_assets):
            for b in range(n_assets):
                if a == b:
                    continue
                # Edge a -> b means b depends on a, so a must be earlier than b topologically
                if pos[a] >= pos[b]:
                    continue
                la, lb = layers[a], layers[b]
                if la == 0 and lb in (1, 2):
                    p = 0.12
                elif la == 1 and lb == 2:
                    p = 0.09
                elif la == lb:
                    p = 0.03
                else:
                    p = 0.01  # should not happen due to pos check, but keep
                if rng.random() < p:
                    edges_src.append(a)
                    edges_dst.append(b)
        # Ensure each non-L0 node has at least one dependency
        for node in range(n_assets):
            if layers[node] == 0:
                continue
            if not any(d == node for d in edges_dst):
                # connect to a random L0 or earlier-layer node
                candidates = [c for c in range(n_assets) if pos[c] < pos[node] and layers[c] < layers[node]]
                if candidates:
                    src = rng.choice(candidates)
                    edges_src.append(src)
                    edges_dst.append(node)
    else:
        edge_density = 0.05  # probability of an edge between any pair (i, j) with i < j
        for i in range(n_assets):
            for j in range(i + 1, n_assets):
                if rng.random() < edge_density:
                    edges_src.append(j)
                    edges_dst.append(i)
        for i in range(1, n_assets):
            if not any(d == i for d in edges_dst):
                j = rng.randint(0, i - 1)
                edges_src.append(i)
                edges_dst.append(j)

    edge_index = torch.tensor([edges_src, edges_dst], dtype=torch.long) if edges_src else \
        torch.zeros((2, 0), dtype=torch.long)

    # Compute target labels via heuristic priority score.
    # Priority = criticality * vendor_pqc_ready * (1 + log(key_size)) - dependency_count
    # Higher priority => migrate earlier => smaller order index.
    y_order, y_risk, y_priority = _assign_labels(
        asset_records, edges_src, edges_dst, days_to_deadline
    )

    data = Data(
        x=features,
        edge_index=edge_index,
        y_order=y_order,
        y_risk=y_risk,
        y_priority=y_priority,
    )
    data.asset_records = asset_records  # type: ignore[attr-defined]
    data.n_assets = n_assets  # type: ignore[attr-defined]
    return data


def generate_dataset(
    n_graphs: int = 1000, min_assets: int = 20, max_assets: int = 100, seed: int = 42
) -> list[Data]:
    """Generate a list of synthetic migration graphs for training.

    Args:
        n_graphs: Number of graphs to generate.
        min_assets: Minimum number of assets per graph.
        max_assets: Maximum number of assets per graph.
        seed: Base RNG seed.

    Returns:
        A list of torch_geometric Data objects.
    """
    dataset: list[Data] = []
    for i in range(n_graphs):
        n = random.Random(seed + i).randint(min_assets, max_assets)
        data = generate_migration_graph(n_assets=n, seed=seed + i * 1000)
        dataset.append(data)
    return dataset


if __name__ == "__main__":
    # Quick smoke test
    data = generate_migration_graph(n_assets=50, seed=42)
    print(f"Nodes: {data.x.shape[0]}, Edges: {data.edge_index.shape[1]}")
    print(f"y_order: {data.y_order.shape}, range [{data.y_order.min()}, {data.y_order.max()}]")
    print(f"y_risk:  {data.y_risk.shape}, range [{data.y_risk.min():.3f}, {data.y_risk.max():.3f}]")
    print(f"First 5 node features:\n{data.x[:5]}")
