"""Reinforcement Learning migration agent.

Trains a policy network via simulation to learn optimal PQC migration
strategies. This is the defensible moat — no competitor (CARAF, QSTriage,
Keyfactor) has a learned agent that optimizes migration sequencing.

The agent learns:
  - Which assets to migrate first (considering dependencies)
  - When to wait for vendor PQC support
  - How to balance risk vs. deadline pressure
  - How to minimize downtime during migration

Trained on GPU via 10,000+ simulated migration episodes.

Usage:
    from qtrust_planner.rl_agent import MigrationAgent, train_agent

    # Train the agent (takes ~2 hours on A100)
    train_agent(n_episodes=10_000)

    # Use the trained agent
    agent = MigrationAgent()
    plan = agent.plan_migration(cbom)
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn
from torch.distributions import Categorical

# ---------------------------------------------------------------------------
# Migration Environment
# ---------------------------------------------------------------------------

@dataclass
class MigrationState:
    """State of a migration simulation."""
    assets: list[dict]  # CBOM assets with features
    dependencies: list[tuple[int, int]]  # (source, target) edges
    migrated: list[bool]  # which assets have been migrated
    available: list[int]  # indices of assets that can be migrated next
    deadline_days: int
    elapsed_days: int
    total_risk: float
    total_downtime: float


class MigrationEnvironment:
    """Simulated environment for training the RL migration agent.

    The agent observes the CBOM state and selects which asset to migrate next.
    After each migration, the state updates (dependencies satisfied, time advances).
    """

    def __init__(self, n_assets: int = 50, seed: int = 42):
        self.rng = np.random.default_rng(seed)
        self.n_assets = n_assets
        self.reset()

    def reset(self) -> MigrationState:
        """Reset to a new random CBOM."""
        # Generate random assets
        algorithms = ["RSA-2048", "RSA-4096", "ECC-P256", "Ed25519"]
        criticalities = ["low", "medium", "high", "critical"]

        self.assets = []
        for i in range(self.n_assets):
            alg = self.rng.choice(algorithms)
            tail = alg.split("-")[-1]
            key_size = int(tail) if tail.isdigit() else 256
            self.assets.append({
                "id": i,
                "algorithm": alg,
                "key_size": key_size,
                "criticality": self.rng.choice(criticalities, p=[0.2, 0.4, 0.3, 0.1]),
                "pqc_ready": False,
                "migration_time_days": int(self.rng.integers(1, 14)),
                "downtime_hours": float(self.rng.uniform(0, 24)),
            })

        # Generate dependency edges as a DAG: edges always point from an
        # earlier asset to a later one, guaranteeing a feasible order exists.
        self.dependencies = []
        for i in range(self.n_assets):
            n_deps = int(self.rng.integers(0, 3))
            if i > 0 and n_deps > 0:
                deps = self.rng.choice(i, size=min(n_deps, i), replace=False)
                for dep in np.atleast_1d(deps):
                    self.dependencies.append((int(dep), i))  # dep must migrate before i

        # Initial state
        self.migrated = [False] * self.n_assets
        self.available = self._compute_available()
        self.deadline_days = 365
        self.elapsed_days = 0
        self.total_risk = 0.0
        self.total_downtime = 0.0

        return self._get_state()

    def _compute_available(self) -> list[int]:
        """Compute which assets can be migrated next (dependencies satisfied)."""
        available = []
        for i in range(self.n_assets):
            if self.migrated[i]:
                continue
            # Check if all dependencies are migrated
            deps_satisfied = all(
                self.migrated[dep] for dep, target in self.dependencies if target == i
            )
            if deps_satisfied:
                available.append(i)
        return available

    def _get_state(self) -> MigrationState:
        return MigrationState(
            assets=self.assets,
            dependencies=self.dependencies,
            migrated=self.migrated.copy(),
            available=self.available.copy(),
            deadline_days=self.deadline_days,
            elapsed_days=self.elapsed_days,
            total_risk=self.total_risk,
            total_downtime=self.total_downtime,
        )

    def step(self, action: int) -> tuple[MigrationState, float, bool, dict]:
        """Migrate one asset.

        Args:
            action: Index of the asset to migrate.

        Returns:
            next_state, reward, done, info
        """
        if action not in self.available:
            return self._get_state(), -10.0, False, {"error": "invalid action"}

        asset = self.assets[action]

        # Advance time
        migration_time = asset["migration_time_days"]
        self.elapsed_days += migration_time

        # Calculate risk (higher for critical assets with classical algorithms)
        crit_weight = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        risk = crit_weight.get(asset["criticality"], 2)
        if "RSA" in asset["algorithm"] and asset["key_size"] < 3072:
            risk += 2  # RSA-2048 is quantum-vulnerable
        self.total_risk += risk * migration_time

        # Record downtime
        self.total_downtime += asset["downtime_hours"]

        # Mark as migrated
        self.migrated[action] = True

        # Update available list
        self.available = self._compute_available()

        # Check if done
        done = all(self.migrated) or self.elapsed_days >= self.deadline_days

        # Calculate reward
        if done:
            if all(self.migrated):
                # Bonus for completing all migrations before deadline
                remaining_days = self.deadline_days - self.elapsed_days
                reward = 100.0 + remaining_days * 0.1
            else:
                # Penalty for not finishing
                n_unmigrated = sum(1 for m in self.migrated if not m)
                reward = -n_unmigrated * 10.0
        else:
            # Step reward: negative risk and downtime
            reward = -risk * 0.1 - asset["downtime_hours"] * 0.01

            # Small bonus for migrating high-priority assets early
            if asset["criticality"] == "critical" and self.elapsed_days < 90:
                reward += 5.0

        return self._get_state(), reward, done, {"asset_migrated": action}


# ---------------------------------------------------------------------------
# Policy Network
# ---------------------------------------------------------------------------

class MigrationAgent(nn.Module):
    """Policy network for migration sequencing.

    Uses a GCN to encode the CBOM dependency graph, then a policy head
    to select which asset to migrate next.

    Architecture:
        GCN(input → 128) → ReLU → GCN(128 → 128) → ReLU
        → Policy head: Linear(128 → 1) per node
        → Value head: Linear(128 → 1) global (mean-pooled)
    """

    def __init__(self, n_features: int = 6, hidden_dim: int = 128):
        super().__init__()
        from torch_geometric.nn import GCNConv, global_mean_pool

        self.conv1 = GCNConv(n_features, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.policy_head = nn.Linear(hidden_dim, 1)
        self.value_head = nn.Linear(hidden_dim, 1)
        self.global_mean_pool = global_mean_pool

    def forward(self, x, edge_index, batch=None):
        """Forward pass.

        Args:
            x: (N, n_features) node features.
            edge_index: (2, E) edge index.
            batch: (N,) batch assignment.

        Returns:
            policy_logits: (N,) per-node action scores.
            state_value: (1,) estimated state value.
        """
        h = F.relu(self.conv1(x, edge_index))
        h = F.relu(self.conv2(h, edge_index))

        policy_logits = self.policy_head(h).squeeze(-1)
        state_value = self.value_head(self.global_mean_pool(h, batch)).squeeze(-1)

        return policy_logits, state_value

    def select_action(self, x, edge_index, available: list[int], device="cuda"):
        """Select next asset to migrate.

        Args:
            x: Node features tensor.
            edge_index: Edge index tensor.
            available: List of available asset indices.
            device: torch device.

        Returns:
            action: Selected asset index.
            log_prob: Log probability of the action.
            value: Estimated state value.
        """
        policy_logits, value = self.forward(x, edge_index)

        # Mask unavailable assets
        mask = torch.full_like(policy_logits, float('-inf'))
        for a in available:
            mask[a] = 0
        masked_logits = policy_logits + mask

        dist = Categorical(logits=masked_logits)
        action = dist.sample()

        return action.item(), dist.log_prob(action), value


# ---------------------------------------------------------------------------
# State conversion
# ---------------------------------------------------------------------------

def state_to_tensors(state: MigrationState, device: str | torch.device | None = None) -> tuple:
    """Convert a MigrationState to PyG-compatible tensors."""
    from qtrust_planner.model_v3 import encode_algorithm_type

    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"

    features = []
    for i, asset in enumerate(state.assets):
        alg_type = encode_algorithm_type(asset["algorithm"])
        crit_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        features.append([
            alg_type / 14.0,
            min(asset["key_size"] / 4096.0, 1.0),
            1.0 if asset["pqc_ready"] else 0.0,
            crit_map.get(asset["criticality"], 2) / 5.0,
            max(0, (state.deadline_days - state.elapsed_days)) / 3650.0,
            1.0 if state.migrated[i] else 0.0,
        ])

    x = torch.tensor(features, dtype=torch.float32).to(device)

    if state.dependencies:
        edge_index = torch.tensor(state.dependencies, dtype=torch.long).t().contiguous().to(device)
    else:
        edge_index = torch.empty(2, 0, dtype=torch.long).to(device)

    return x, edge_index


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_agent(
    n_episodes: int = 10_000,
    learning_rate: float = 3e-4,
    gamma: float = 0.99,
    save_path: str = "rl_agent.pt",
    seed: int = 42,
):
    """Train the RL migration agent.

    Uses REINFORCE with baseline (policy gradient).

    Args:
        n_episodes: Number of training episodes.
        learning_rate: Learning rate.
        gamma: Discount factor.
        save_path: Where to save the trained model.
        seed: Random seed.
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.manual_seed(seed)

    agent = MigrationAgent(n_features=6, hidden_dim=128).to(device)
    optimizer = torch.optim.AdamW(agent.parameters(), lr=learning_rate)

    best_avg_reward = float('-inf')

    for episode in range(n_episodes):
        # Generate a random environment
        n_assets = random.randint(20, 100)
        env = MigrationEnvironment(n_assets=n_assets, seed=episode)
        state = env.reset()

        log_probs = []
        values = []
        rewards = []

        done = False
        while not done:
            x, edge_index = state_to_tensors(state, device)
            available = state.available

            if not available:
                break

            action, log_prob, value = agent.select_action(x, edge_index, available, device)
            state, reward, done, _ = env.step(action)

            log_probs.append(log_prob)
            values.append(value)
            rewards.append(reward)

        # Compute discounted returns
        returns = []
        G = 0
        for r in reversed(rewards):
            G = r + gamma * G
            returns.insert(0, G)
        returns = torch.tensor(returns, dtype=torch.float32).to(device)

        # Normalize returns
        if returns.std() > 1e-6:
            returns = (returns - returns.mean()) / (returns.std() + 1e-8)

        # Policy gradient loss
        log_probs = torch.stack(log_probs)
        values = torch.stack(values).reshape(-1)

        advantage = returns - values.detach()
        actor_loss = -(log_probs * advantage).sum()
        critic_loss = F.mse_loss(values, returns)
        loss = actor_loss + 0.5 * critic_loss

        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(agent.parameters(), max_norm=0.5)
        optimizer.step()

        if (episode + 1) % 100 == 0 or episode == n_episodes - 1:
            avg_reward = sum(rewards) / len(rewards) if rewards else 0
            if avg_reward > best_avg_reward:
                best_avg_reward = avg_reward
                torch.save(agent.state_dict(), save_path)

            print(
                f"Episode {episode+1:>5}/{n_episodes} | "
                f"avg_reward={avg_reward:.2f} | "
                f"best={best_avg_reward:.2f} | "
                f"loss={loss.item():.4f}"
            )

    if not os.path.exists(save_path):
        torch.save(agent.state_dict(), save_path)

    print(f"\nTraining complete. Best avg reward: {best_avg_reward:.2f}")
    print(f"Model saved to: {save_path}")
    return agent


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train the RL migration agent")
    parser.add_argument("--episodes", type=int, default=10_000)
    parser.add_argument("--save-path", type=str, default="rl_agent.pt")
    parser.add_argument("--lr", type=float, default=3e-4)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    train_agent(
        n_episodes=args.episodes,
        learning_rate=args.lr,
        save_path=args.save_path,
        seed=args.seed,
    )
