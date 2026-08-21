"""MigrationGNN — PyTorch Geometric GCN that predicts optimal PQC migration order.

The model takes a dependency graph of cryptographic assets and produces:
- order_logits: priority score per node (higher = migrate earlier)
- risk_logits:  risk score per node (higher = riskier to migrate now)

Node features (x):
    [algorithm_type, key_size, vendor_pqc_ready, criticality]

Edge index (edge_index):
    [source, target] — asset source must be migrated before target
    (i.e., edges point in the direction of dependencies: B -> A means A depends on B)
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv

# Algorithm type encoding (used as a one-hot-ish scalar feature).
# The model is agnostic to the actual mapping; we just need a consistent integer.
ALGORITHM_TYPE_MAP = {
    "RSA": 0,
    "ECC": 1,
    "DSA": 2,
    "DH": 3,
    "ECDH": 4,
    "ECDSA": 5,
    "EdDSA": 6,
    "SHA": 7,
    "AES": 8,
    "HMAC": 9,
    "ChaCha20": 10,
    "ML-KEM": 11,   # post-quantum KEM (already PQC)
    "ML-DSA": 12,   # post-quantum DSA (already PQC)
    "SLH-DSA": 13,  # post-quantum hash-based (already PQC)
    "Unknown": 14,
}


def encode_algorithm_type(algorithm: str) -> int:
    """Map an algorithm name to an integer type code."""
    algorithm = algorithm.upper()
    if algorithm in ALGORITHM_TYPE_MAP:
        return ALGORITHM_TYPE_MAP[algorithm]
    for prefix, code in ALGORITHM_TYPE_MAP.items():
        if algorithm.startswith(prefix):
            return code
    return ALGORITHM_TYPE_MAP["Unknown"]


class MigrationGNN(nn.Module):
    """3-layer GCN with order + risk prediction heads.

    Architecture:
        Input  (N, 4)  -> GCNConv(4 -> 64)  -> ReLU
                       -> GCNConv(64 -> 64) -> ReLU
                       -> GCNConv(64 -> 32) -> ReLU
                       -> Linear(32 -> 1)  [order_logits]
                       -> Linear(32 -> 1)  [risk_logits]
    """

    def __init__(
        self,
        input_features: int = 4,
        hidden_dim: int = 64,
        embedding_dim: int = 32,
    ) -> None:
        """Initialize the GNN layers and prediction heads.

        Args:
            input_features: Number of per-node input features.
            hidden_dim: Width of the hidden GCN layers.
            embedding_dim: Width of the final embedding used by the heads.
        """
        super().__init__()
        self.input_features = input_features
        self.hidden_dim = hidden_dim
        self.embedding_dim = embedding_dim

        # 3 GCNConv layers as specified
        self.conv1 = GCNConv(input_features, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, embedding_dim)

        # Linear projectors for residual (skip) connections so that node-level
        # features survive message passing.
        self.res1 = (
            nn.Linear(input_features, hidden_dim) if input_features != hidden_dim else nn.Identity()
        )
        self.res2 = nn.Identity()
        self.res3 = (
            nn.Linear(hidden_dim, embedding_dim) if hidden_dim != embedding_dim else nn.Identity()
        )

        # Prediction heads
        self.order_head = nn.Linear(embedding_dim, 1)
        self.risk_head = nn.Linear(embedding_dim, 1)

    def forward(self, data) -> tuple[torch.Tensor, torch.Tensor]:
        """Run a forward pass over a PyG Data object.

        Args:
            data: A torch_geometric.data.Data object with:
                - x: node feature tensor (N, input_features)
                - edge_index: edge index tensor (2, E)
                - batch: batch vector (N,) — optional, defaults to all zeros

        Returns:
            order_logits: (N,) priority scores per node (higher = migrate first).
            risk_logits:  (N,) risk scores per node (higher = riskier to migrate now).
        """
        x, edge_index = data.x, data.edge_index
        batch = getattr(data, "batch", None)
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)

        # GCN layers with ReLU and residual connections
        h = F.relu(self.conv1(x, edge_index) + self.res1(x))
        h = F.relu(self.conv2(h, edge_index) + self.res2(h))
        h = F.relu(self.conv3(h, edge_index) + self.res3(h))

        # Per-node predictions (no pooling — we want per-node scores)
        order_logits = self.order_head(h).squeeze(-1)
        risk_logits = self.risk_head(h).squeeze(-1)

        return order_logits, risk_logits

    def predict_order(self, data) -> torch.Tensor:
        """Convenience method: return just the order logits (priority scores)."""
        self.eval()
        with torch.no_grad():
            order_logits, _ = self.forward(data)
        return order_logits

    def predict_risk(self, data) -> torch.Tensor:
        """Convenience method: return just the risk logits."""
        self.eval()
        with torch.no_grad():
            _, risk_logits = self.forward(data)
        return risk_logits


def build_node_features(
    algorithm_type: int,
    key_size: int,
    vendor_pqc_ready: bool,
    criticality: int,
    days_to_deadline: float = 0.0,
    required_rate: float = 0.0,
) -> torch.Tensor:
    """Build a single node feature vector.

    Features are normalized:
    - algorithm_type: integer code, normalized by max code (14).
    - key_size: bits / 4096 (so RSA-4096 -> 1.0).
    - vendor_pqc_ready: 0.0 or 1.0.
    - criticality: 1-5 normalized to [0.2, 1.0].
    - days_to_deadline: 0-730 days normalized to [0, 1].
    - required_rate: deadline pressure (higher = more urgent) in [0, 1].
    """
    return torch.tensor([
        algorithm_type / 14.0,
        min(key_size / 4096.0, 1.0),
        1.0 if vendor_pqc_ready else 0.0,
        criticality / 5.0,
        min(max(days_to_deadline / 730.0, 0.0), 1.0),
        min(max(required_rate, 0.0), 1.0),
    ], dtype=torch.float32)
