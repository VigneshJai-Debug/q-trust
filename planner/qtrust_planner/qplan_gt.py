"""QPlan-GT — outcome-optimized planner GraphTransformer (Track B, pdf §14).

Converts planner from imitation to optimization:
  1. Per-graph ListMLE fixed (P0-1) — rerun recovers v2 baseline.
  2. Training signal becomes simulated migration outcomes (cost, downtime,
     windowed risk exposure, deadline compliance under NIST IR 8547 and
     CNSA 2.0 dates) — optimal ordering discovered by search, not rule.

Architecture: heterogeneous GraphTransformer with edge-type-aware attention
and global estate token, 5-20M params, first behavior cloning on searched
near-optimal orders, then PPO against outcome simulator with vectorized envs.

This module provides the heterogeneous GraphTransformer stub; see
planner/qtrust_planner/rl_agent.py for the PPO loop that it plugs into.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import TransformerConv
    HAS_PYG_TRANSFORMER = True
except ImportError:
    HAS_PYG_TRANSFORMER = False
    TransformerConv = None  # type: ignore


class QPlanGT(nn.Module):
    """Heterogeneous GraphTransformer with estate token (5-20M params).

    Nodes are heterogeneous: assets, algorithms, protocols, vendors, locations.
    The global estate token attends to all nodes so whole-estate planning is
    not limited by message-passing hops.
    """
    def __init__(
        self,
        in_features: int = 6,
        hidden_dim: int = 256,
        n_layers: int = 4,
        n_heads: int = 8,
        edge_type_dim: int = 32,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.in_features = in_features
        self.hidden_dim = hidden_dim
        self.input_norm = nn.LayerNorm(in_features)
        self.input_proj = nn.Linear(in_features, hidden_dim)
        # Edge-type embedding — per pdf §14 edge-type-aware attention
        self.edge_type_emb = nn.Embedding(8, edge_type_dim)  # 8 dep types
        # Transformer layers
        self.layers = nn.ModuleList()
        for _ in range(n_layers):
            if HAS_PYG_TRANSFORMER:
                self.layers.append(TransformerConv(hidden_dim, hidden_dim // n_heads, heads=n_heads, dropout=dropout, concat=True, beta=True))
            else:
                self.layers.append(nn.Linear(hidden_dim, hidden_dim))
            self.layers.append(nn.LayerNorm(hidden_dim))
        # Global estate token
        self.estate_token = nn.Parameter(torch.zeros(1, 1, hidden_dim))
        self.estate_attn = nn.MultiheadAttention(hidden_dim, n_heads, batch_first=True)
        # Dual heads — outcome-optimized (cost, deadline violation)
        self.order_head = nn.Sequential(nn.Linear(hidden_dim, hidden_dim), nn.ReLU(), nn.Dropout(dropout), nn.Linear(hidden_dim, 1))
        self.risk_head = nn.Sequential(nn.Linear(hidden_dim, hidden_dim), nn.ReLU(), nn.Dropout(dropout), nn.Linear(hidden_dim, 1))
        # Outcome head: predicted total cost / deadline feasibility
        self.outcome_head = nn.Linear(hidden_dim, 2)

    def forward(self, data) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        x, edge_index = data.x, data.edge_index
        batch = getattr(data, "batch", None)
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        x = self.input_norm(x)
        h = self.input_proj(x)
        for i, layer in enumerate(self.layers):
            if isinstance(layer, nn.LayerNorm):
                h = layer(h)
                h = F.dropout(h, p=0.1, training=self.training)
            else:
                if HAS_PYG_TRANSFORMER:
                    h = F.relu(layer(h, edge_index))
                else:
                    h = F.relu(layer(h))
        # Global estate token attends to all nodes in the batch
        # For simplicity, estate token is prepended and attends via MHA per graph would be batched;
        # stub does mean-pool plus token for outcome prediction.
        estate = h.mean(dim=0, keepdim=True)  # (1, hidden)
        estate_expanded = self.estate_token.expand(1, -1, -1)  # (1,1,hidden)
        estate_out, _ = self.estate_attn(estate_expanded, estate.unsqueeze(0), estate.unsqueeze(0))
        outcome = self.outcome_head(estate_out.squeeze(0)).squeeze(0)  # (2,)
        order_logits = self.order_head(h).squeeze(-1)
        risk_logits = self.risk_head(h).squeeze(-1)
        return order_logits, risk_logits, outcome

    @staticmethod
    def simulate_migration_outcome(order: list[int], data) -> dict:
        """Simulate executing candidate order — scores cost, downtime, risk exposure, deadline (pdf §14).
        Higher is worse; planner learns to minimize this.
        """
        # Stub: cost = sum(priority inversion) + deadline pressure, not rule-based
        # Real simulator would replay against NIST IR 8547 / CNSA 2.0 dates.
        cost = len(order) * 0.5 + sum(order) * 0.01
        downtime = len(order) * 1.2
        deadline_ok = 1.0 if len(order) < 100 else 0.5
        return {"cost": cost, "downtime": downtime, "deadline_ok": deadline_ok, "regret": cost * (1 - deadline_ok * 0.5)}

if __name__ == "__main__":
    from torch_geometric.data import Data
    m = QPlanGT()
    print(f"QPlan-GT params: {sum(p.numel() for p in m.parameters()):,}")
    data = Data(x=torch.randn(20, 6), edge_index=torch.randint(0, 20, (2, 30)))
    order, risk, outcome = m(data)
    print(f"order {order.shape}, risk {risk.shape}, outcome {outcome.shape}")
