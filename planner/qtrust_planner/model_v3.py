"""MigrationGNN v3 — Large-scale GPU-optimized model for 100K+ graph training.

Architecture (designed for A100 40GB):
    Input (N, 6) → LayerNorm
                 → GCNConv(6→256) + BatchNorm + ReLU + Dropout + Residual
                 → GATv2Conv(256→128, heads=8, concat=True) + BatchNorm + ReLU + Dropout + Residual
                 → GCNConv(256→256) + BatchNorm + ReLU + Dropout + Residual
                 → GCNConv(256→128) + BatchNorm + ReLU + Dropout + Residual
                 → MLP(128→128→1) [order] + MLP(128→128→1) [risk]

Designed for mixed-precision (BF16) training on A100. At batch_size=256 with
100-node graphs, peak memory is ~8GB — well within the 40GB A100.

Key differences from v2:
  - 4x larger hidden dim (256 vs 64)
  - 4x larger embedding dim (128 vs 32)
  - 2x more attention heads (8 vs 4)
  - Extra GCN layer (4 layers vs 3)
  - 2-layer MLP heads (vs single Linear)
  - Designed for BF16 mixed-precision training

AUDIT NOTE — BatchNorm correctness (planner/model_v3.py:67,105,116,121,126):

    BatchNorm1d normalizes over the N (node) dimension. Under PyG batching,
    DataLoader concatenates all graphs in a mini-batch into one tensor
    ``x: (ΣN_i, F)`` with a ``batch: (ΣN_i,)`` index. BatchNorm then computes
    statistics over the union of nodes from *different* CBOM graphs, leaking
    cross-graph information, violating the per-graph i.i.d. assumption, and
    causing train/test skew when batch composition changes (graph sizes vary
    10–100 nodes).

    Correct choices for batched GNNs are GraphNorm (Li et al., 2020 — per-graph
    affine normalization) or LayerNorm (Ba et al., 2016 — per-node, batch-
    agnostic). Input already uses LayerNorm; hidden layers should follow.

    Current status (2026-08-26):
      * Shipped checkpoints (model.pt, model_gpu_v3.pt) were trained with
        BatchNorm, so this file keeps ``norm="batch"`` as the **default for
        checkpoint compatibility**.
      * ``MigrationGNNv3(norm="layer")`` and ``norm="graph"`` are available
        for the retrain. Pass ``norm="layer"`` to train with LayerNorm
        (no batch dependence, works for single-node graphs) or ``norm="graph"``
        to train with PyG GraphNorm (per-graph statistics via ``batch``).
      * Promotion gate: v2 (BatchNorm, τ=0.961 canonical) remains the default
        in planner/server.py (QTRUST_MODEL_PATH → model.pt) until a LayerNorm/
        GraphNorm v3 retrain **beats v2 on the canonical held-out benchmark**
        (scipy Kendall tau, seed=999, same split as benchmark.py). See
        docs/WHITEPAPER.md §6.5, results/benchmark*.json, and
        qtrust_planner/benchmark_v3.py. CI should enforce this (see below).

    Recommended CI gate (not yet in .github/workflows/ci.yml):

        python -m qtrust_planner.benchmark_v3 --n-graphs 1000 --json-out /tmp/v3.json
        python -c "
        import json
        v2 = json.load(open('planner/results/benchmark.json'))['gnn-listmle']['mean']['kendall']
        v3 = json.load(open('/tmp/v3.json'))['v3 (GPU-trained, 256-dim)']['kendall']
        assert v3 > v2, f'v3 tau {v3:.4f} must beat v2 tau {v2:.4f} before promotion'
        "

    Migration plan:
      1. Train ``MigrationGNNv3(norm="layer")`` at 10K/100K scale via train_gpu.py
         (add ``--norm layer`` flag — TODO).
      2. Evaluate with benchmark_v3.py on the canonical seed=999 split.
      3. If τ_layer > τ_v2, replace planner/model.pt and update server default.

    Checkpoint compatibility: state_dict keys are ``bn*`` for batch and
    ``norm*``/``gn*`` for layer/graph — a small loader shim maps legacy keys.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATv2Conv
from torch_geometric.utils import degree
from typing import Tuple


ALGORITHM_TYPE_MAP = {
    "RSA": 0, "ECC": 1, "DSA": 2, "DH": 3, "ECDH": 4, "ECDSA": 5,
    "EdDSA": 6, "SHA": 7, "AES": 8, "HMAC": 9, "ChaCha20": 10,
    "ML-KEM": 11, "ML-DSA": 12, "SLH-DSA": 13, "Unknown": 14,
}


def encode_algorithm_type(algorithm: str) -> int:
    algorithm = algorithm.upper()
    if algorithm in ALGORITHM_TYPE_MAP:
        return ALGORITHM_TYPE_MAP[algorithm]
    for prefix, code in ALGORITHM_TYPE_MAP.items():
        if algorithm.startswith(prefix):
            return code
    return ALGORITHM_TYPE_MAP["Unknown"]


def _make_norm(norm: str, dim: int) -> nn.Module:
    """Factory for per-node normalization that is correct under PyG batching.

    - "batch": nn.BatchNorm1d — legacy, leaks cross-graph stats (kept for
      checkpoint compat, see module docstring).
    - "layer": nn.LayerNorm — per-node, batch-agnostic (recommended for retrain).
    - "graph": GraphNorm — per-graph (requires ``batch`` vector; falls back to
      LayerNorm when PyG unavailable or for single-graph batches).

    The returned module is always assigned to ``self.bn*`` / ``self.norm`` so
    that ``load_state_dict`` with ``strict=False`` can map legacy ``bn*``
    keys when migrating; new checkpoints store under the same keys.
    """
    norm = norm.lower()
    if norm == "layer":
        return nn.LayerNorm(dim)
    if norm == "graph":
        try:
            from torch_geometric.nn import GraphNorm  # type: ignore

            return GraphNorm(dim)
        except ImportError:  # pragma: no cover
            return nn.LayerNorm(dim)
    # default: legacy BatchNorm (checkpoint-compatible)
    return nn.BatchNorm1d(dim)


class MLPHead(nn.Module):
    """2-layer MLP head with configurable normalization and dropout.

    Args:
        norm: "batch" (legacy BatchNorm1d), "layer" (LayerNorm, recommended),
              or "graph" (GraphNorm — per-graph). Defaults to "batch" for
              checkpoint compatibility with shipped model_gpu_v3.pt.
    """

    def __init__(self, in_dim: int, hidden_dim: int, out_dim: int, dropout: float = 0.15, norm: str = "batch"):
        super().__init__()
        self.norm = _make_norm(norm, in_dim)
        self.norm_type = norm.lower()
        self.fc1 = nn.Linear(in_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, out_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, batch: torch.Tensor | None = None) -> torch.Tensor:
        # GraphNorm needs the batch vector; LayerNorm/BatchNorm ignore it.
        if self.norm_type == "graph" and batch is not None:
            try:
                x = self.norm(x, batch)  # type: ignore[call-arg]
            except TypeError:
                x = self.norm(x)
        else:
            x = self.norm(x)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        return x


class MigrationGNNv3(nn.Module):
    """Large-scale GPU-optimized GNN for migration planning.

    4-layer hybrid GCN+GATv2 with dual MLP heads.
    Designed for 100K+ graph training on A100 with BF16 mixed precision.

    Args:
        input_features: Number of per-node input features (default 6).
        hidden_dim: Width of hidden layers (default 256 — 4x larger than v2).
        embedding_dim: Width of final embedding (default 128 — 4x larger than v2).
        heads: Number of GAT attention heads (default 8 — 2x more than v2).
        dropout: Dropout rate (default 0.15).
        use_centrality: If True, augment features with in/out degree.
        variant: 'hybrid' (GCN+GAT) or 'gcn' (all GCN).
        norm: Normalization for hidden GCN layers and MLP heads — "batch"
              (legacy BatchNorm1d, checkpoint-compatible default), "layer"
              (LayerNorm, recommended for batched graphs), or "graph"
              (GraphNorm, per-graph). See module AUDIT NOTE.
    """

    def __init__(
        self,
        input_features: int = 6,
        hidden_dim: int = 256,
        embedding_dim: int = 128,
        heads: int = 8,
        dropout: float = 0.15,
        use_centrality: bool = True,
        variant: str = "hybrid",
        norm: str = "batch",
    ) -> None:
        super().__init__()
        self.input_features = input_features
        self.hidden_dim = hidden_dim
        self.embedding_dim = embedding_dim
        self.use_centrality = use_centrality
        self.variant = variant
        self.norm = norm.lower()

        # Input normalization (always LayerNorm — per-node, no batch leakage)
        self.input_norm = nn.LayerNorm(input_features)

        # Layer 1: GCN (input → hidden)
        self.conv1 = GCNConv(input_features, hidden_dim)
        self.bn1 = _make_norm(self.norm, hidden_dim)
        self.res1 = nn.Linear(input_features, hidden_dim) if input_features != hidden_dim else nn.Identity()

        # Layer 2: GAT (attention)
        if variant == "hybrid":
            self.conv2 = GATv2Conv(
                hidden_dim, hidden_dim // heads, heads=heads,
                concat=True, dropout=dropout, share_weights=True,
            )
        else:
            self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.bn2 = _make_norm(self.norm, hidden_dim)
        self.res2 = nn.Identity()

        # Layer 3: GCN (hidden → hidden)
        self.conv3 = GCNConv(hidden_dim, hidden_dim)
        self.bn3 = _make_norm(self.norm, hidden_dim)
        self.res3 = nn.Identity()

        # Layer 4: GCN (hidden → embedding) — extra layer vs v2
        self.conv4 = GCNConv(hidden_dim, embedding_dim)
        self.bn4 = _make_norm(self.norm, embedding_dim)
        self.res4 = nn.Linear(hidden_dim, embedding_dim) if hidden_dim != embedding_dim else nn.Identity()

        # 2-layer MLP heads (vs single Linear in v2)
        self.order_head = MLPHead(embedding_dim, embedding_dim, 1, dropout, norm=self.norm)
        self.risk_head = MLPHead(embedding_dim, embedding_dim, 1, dropout, norm=self.norm)

    def forward(self, data) -> Tuple[torch.Tensor, torch.Tensor]:
        """Run a forward pass.

        Args:
            data: PyG Data object with x, edge_index, batch.

        Returns:
            order_logits: (N,) priority scores per node (higher = migrate first).
            risk_logits: (N,) risk scores per node.
        """
        x, edge_index = data.x, data.edge_index
        batch = getattr(data, "batch", None)
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)

        # Input normalization
        x = self.input_norm(x)

        def _norm(m, t):
            # GraphNorm requires the batch vector to compute per-graph stats.
            if self.norm == "graph":
                try:
                    return m(t, batch)  # type: ignore[call-arg]
                except TypeError:
                    return m(t)
            return m(t)

        # Layer 1: GCN + residual
        h = self.conv1(x, edge_index)
        h = _norm(self.bn1, h)
        h = F.relu(h)
        h = F.dropout(h, p=0.15, training=self.training)
        h = h + self.res1(x)

        # Layer 2: GAT (attention) + residual
        h2 = self.conv2(h, edge_index)
        h2 = _norm(self.bn2, h2)
        h2 = F.relu(h2)
        h2 = F.dropout(h2, p=0.15, training=self.training)
        h = h + h2

        # Layer 3: GCN + residual
        h3 = self.conv3(h, edge_index)
        h3 = _norm(self.bn3, h3)
        h3 = F.relu(h3)
        h3 = F.dropout(h3, p=0.15, training=self.training)
        h = h + h3

        # Layer 4: GCN → embedding + residual
        h4 = self.conv4(h, edge_index)
        h4 = _norm(self.bn4, h4)
        h4 = F.relu(h4)
        h4 = F.dropout(h4, p=0.15, training=self.training)
        emb = h4 + self.res4(h)

        # Dual heads (2-layer MLPs) — pass batch for GraphNorm variant
        if self.norm == "graph":
            order_logits = self.order_head(emb, batch).squeeze(-1)
            risk_logits = self.risk_head(emb, batch).squeeze(-1)
        else:
            order_logits = self.order_head(emb).squeeze(-1)
            risk_logits = self.risk_head(emb).squeeze(-1)

        return order_logits, risk_logits

    def predict_order(self, data) -> torch.Tensor:
        self.eval()
        with torch.no_grad():
            order_logits, _ = self.forward(data)
        return order_logits

    def predict_risk(self, data) -> torch.Tensor:
        self.eval()
        with torch.no_grad():
            _, risk_logits = self.forward(data)
        return risk_logits


def build_node_features_v3(
    algorithm_type: int,
    key_size: int,
    vendor_pqc_ready: bool,
    criticality: int,
    days_to_deadline: float = 365.0,
    required_rate: float = 0.5,
) -> torch.Tensor:
    """Build a 6-dim node feature vector for v3.

    Features:
        0: algorithm_type / 14.0
        1: key_size / 4096.0 (capped at 1.0)
        2: vendor_pqc_ready (0.0 or 1.0)
        3: criticality / 5.0
        4: days_to_deadline / 3650.0 (normalized to ~0-1 over 10 years)
        5: required_rate / 1.0 (assets per day needed)
    """
    return torch.tensor([
        algorithm_type / 14.0,
        min(key_size / 4096.0, 1.0),
        1.0 if vendor_pqc_ready else 0.0,
        criticality / 5.0,
        min(days_to_deadline / 3650.0, 1.0),
        min(required_rate, 1.0),
    ], dtype=torch.float32)
