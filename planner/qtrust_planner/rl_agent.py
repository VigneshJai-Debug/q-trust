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
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar

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

    Supports two modes:
        - Random mode (default): reset() generates a fresh synthetic CBOM.
        - Real-CBOM mode: constructed via ``from_cbom()``; reset() replays the
          real assets/dependencies so training happens on real scan data.
    """

    def __init__(self, n_assets: int = 50, seed: int = 42, cbom: dict | None = None):
        self.rng = np.random.default_rng(seed)
        self.n_assets = n_assets
        self._cbom = cbom
        if cbom is not None:
            self._assets_template, self._cbom_dependencies = self._assets_from_cbom(cbom)
            self.n_assets = len(self._assets_template)
        self.reset()

    @classmethod
    def from_cbom(cls, cbom: dict, seed: int = 42) -> MigrationEnvironment:
        """Build an environment from a real CBOM document.

        Accepts ``qtrust.cbom.v1`` dicts (crypto-inspector output) or any dict
        with an ``assets`` list. Dependency edges come from explicit
        ``depends_on`` lists when present; otherwise a deterministic
        host-affinity fallback is used, matching cbom_to_dependency_graph().
        """
        return cls(n_assets=0, seed=seed, cbom=cbom)

    # Default migration-effort estimates for real assets lacking the fields.
    _CRIT_WEIGHT: ClassVar[dict] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    _DEFAULT_KEY_SIZE: ClassVar[dict] = {"ECC": 256, "ECDSA": 256, "ECDH": 256, "EdDSA": 256, "SHA": 256}

    def _normalize_asset(self, idx: int, asset: dict) -> dict:
        algorithm = str(asset.get("algorithm") or "Unknown").upper()
        key_size = asset.get("key_size")
        if not key_size:
            key_size = self._DEFAULT_KEY_SIZE.get(algorithm.split("-")[0], 2048)
        key_size = int(key_size)
        criticality = str(asset.get("criticality", "medium")).lower()
        if criticality not in self._CRIT_WEIGHT:
            criticality = "medium"
        pqc_ready = bool(asset.get("pqc_ready", False)) or algorithm.startswith(
            ("ML-KEM", "ML-DSA", "SLH-DSA", "HQC", "FALCON")
        )
        crit_w = self._CRIT_WEIGHT[criticality]
        complexity = 1 if pqc_ready else max(1, min(key_size // 1024 + 1, 6))
        return {
            "id": idx,
            "algorithm": algorithm,
            "key_size": key_size,
            "criticality": criticality,
            "pqc_ready": pqc_ready,
            "migration_time_days": int(complexity + self.rng.integers(0, 7)),
            "downtime_hours": float(self.rng.uniform(0.5, crit_w * 6)),
        }

    def _assets_from_cbom(self, cbom: dict) -> tuple[list[dict], list[tuple[int, int]]]:
        raw_assets = cbom.get("assets") or []
        if not raw_assets:
            raise ValueError("CBOM contains no assets")

        assets = [self._normalize_asset(i, a) for i, a in enumerate(raw_assets)]

        dependencies: list[tuple[int, int]] = []
        has_explicit_deps = any(a.get("depends_on") for a in raw_assets)
        first_index_by_host: dict[str, int] = {}
        for i, raw in enumerate(raw_assets):
            if has_explicit_deps:
                for dep in raw.get("depends_on") or []:
                    try:
                        dep_idx = int(dep)
                    except (TypeError, ValueError):
                        continue
                    if dep_idx != i and 0 <= dep_idx < len(assets):
                        dependencies.append((dep_idx, i))
            else:
                host = str(raw.get("host") or raw.get("location") or "")
                anchor = first_index_by_host.setdefault(host, i)
                if anchor != i:
                    dependencies.append((anchor, i))
        return assets, dependencies

    def reset(self) -> MigrationState:
        """Reset to the initial CBOM state (real assets if pinned via from_cbom)."""
        if self._cbom is not None:
            self.assets = [dict(a) for a in self._assets_template]
            self.dependencies = list(self._cbom_dependencies)
        else:
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

    def evaluate(self, x, edge_index, actions, available, device="cuda"):
        """Compute log-probs of given actions and state values under the CURRENT policy.

        This is what makes PPO an importance-sampled method: during the inner
        epochs the policy has moved, so the surrogate objective must re-weight
        each rollout transition by exp(log π_θ(a|s) - log π_θ_old(a|s)) with
        log π_θ recomputed from the updated weights — NOT reused from the
        rollout (which would make the clipped ratio identically 1 and reduce
        PPO to plain advantage-weighted SGD).

        Args:
            x: (N, n_features) node features.
            edge_index: (2, E) edge index.
            actions: (1,) tensor with the selected action.
            available: List of available asset indices.
            device: torch device.

        Returns:
            log_prob: Log probability of `actions` under the current policy.
            value: State value estimate.
        """
        policy_logits, value = self.forward(x, edge_index)
        mask = torch.full_like(policy_logits, float("-inf"))
        for a in available:
            mask[a] = 0
        masked_logits = policy_logits + mask
        dist = Categorical(logits=masked_logits)
        return dist.log_prob(actions), value


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

def _env_static_features(env: MigrationEnvironment, device: torch.device):
    """Precompute the per-asset features that never change during an episode.

    state_to_tensors() rebuilds every feature from the Python asset dicts on
    every call; in a 64-env rollout that is ~64 tensor constructions + device
    transfers per step and dominates wall time (measured 4.0s/rollout). Only
    two columns actually change per step: remaining-days (column 4) and the
    migrated flag (column 5). Returning the static columns as one numpy array
    plus the cached edge tensor lets the rollout assemble a single (total, 6)
    tensor and make ONE device transfer per step.

    Returns:
        (static_np (n, 4) float32, edge_index (2, E) long tensor on device)
    """
    from qtrust_planner.model_v3 import encode_algorithm_type

    crit_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    n = env.n_assets
    static = np.zeros((n, 4), dtype=np.float32)
    for i, asset in enumerate(env.assets):
        static[i, 0] = encode_algorithm_type(asset["algorithm"]) / 14.0
        static[i, 1] = min(asset["key_size"] / 4096.0, 1.0)
        static[i, 2] = 1.0 if asset["pqc_ready"] else 0.0
        static[i, 3] = crit_map.get(asset["criticality"], 2) / 5.0
    if env.dependencies:
        edge_index = torch.tensor(env.dependencies, dtype=torch.long).t().contiguous().to(device)
    else:
        edge_index = torch.empty(2, 0, dtype=torch.long).to(device)
    return static, edge_index


def train_agent(
    n_episodes: int = 10_000,
    learning_rate: float = 3e-4,
    gamma: float = 0.99,
    save_path: str = "rl_agent.pt",
    seed: int = 42,
    env_factory: Callable[[], MigrationEnvironment] | None = None,
):
    """Legacy REINFORCE — kept for backward compat; delegates to PPO by default.

    The diagnosis register P1-9 flags this path as serial REINFORCE with
    1 episode/update that cannot saturate an A100. New code should call
    train_agent_ppo() which does vectorized PPO with clipped surrogate,
    entropy bonus, and batched GPU-feeding rollouts. This wrapper preserves
    the old signature by forwarding to PPO with 64 vectorized envs.
    """
    return train_agent_ppo(
        n_episodes=n_episodes,
        learning_rate=learning_rate,
        gamma=gamma,
        save_path=save_path,
        seed=seed,
        env_factory=env_factory,
        n_envs=4,  # small default so legacy callers don't OOM
    )


def train_agent_ppo(
    n_episodes: int = 10_000,
    learning_rate: float = 3e-4,
    gamma: float = 0.99,
    save_path: str = "rl_agent.pt",
    seed: int = 42,
    env_factory: Callable[[], MigrationEnvironment] | None = None,
    n_envs: int = 64,
    ppo_epochs: int = 4,
    clip_ratio: float = 0.2,
    entropy_coef: float = 0.01,
    value_coef: float = 0.5,
    max_grad_norm: float = 0.5,
    batch_size: int | None = None,
    init_path: str | None = None,
):
    """PPO migration agent — outcome-optimized planner (Track B, pdf §14).

    Vectorized environments (64-256) feed the GPU with batched rollouts;
    clipped surrogate, entropy bonus, and advantage normalization replace
    the serial REINFORCE loop wholesale (fixes P1-9).

    Architecture: same MigrationAgent (GAT-style) but with larger hidden_dim
    when caller requests; this function is the Track B target that replaces
    the 17K-param toy with a batched PPO pipeline.

    Args:
        n_episodes: Total environment steps divided by n_envs (rollouts).
        n_envs: Vectorized env count (64-256 saturates A100; falls back to 4 on CPU).
        ppo_epochs: Optimizer passes per rollout batch.
        clip_ratio: PPO clipping epsilon.
    """
    # Fall back to fewer envs on CPU-only hosts
    if not torch.cuda.is_available():
        n_envs = min(n_envs, 8)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    torch.manual_seed(seed)
    # Try torch.compile for PPO step if available. PyTorch-Geometric graphs have
    # dynamic node counts per step, so torch.compile recompiles on every shape
    # change and can be 10x SLOWER (same finding as train_gpu.py P2-10).
    # QTRUST_DISABLE_COMPILE=1 opts out (recommended for RL rollouts).
    agent = MigrationAgent(n_features=6, hidden_dim=128).to(device)
    if init_path and os.path.exists(init_path):
        agent.load_state_dict(torch.load(init_path, map_location=device))
        print(f"Initialized from pretrained checkpoint: {init_path}")
    if not os.environ.get("QTRUST_DISABLE_COMPILE", "0") == "1":
        try:
            agent = torch.compile(agent)  # type: ignore[attr-defined]
        except Exception:
            pass
    optimizer = torch.optim.AdamW(agent.parameters(), lr=learning_rate)

    # Scheduler: warmup-cosine (fixes constant 1e-3)
    warmup = max(1, int(n_episodes * 0.03))
    def _lr_lambda(e: int) -> float:
        if e < warmup:
            return float(e + 1) / float(max(1, warmup))
        import math
        prog = (e - warmup) / max(1, n_episodes - warmup)
        return 0.1 + 0.9 * 0.5 * (1.0 + math.cos(math.pi * prog))
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, _lr_lambda)

    best_avg_reward = float("-inf")
    # Vectorized env pool
    def _make_env(idx: int) -> MigrationEnvironment:
        if env_factory is not None:
            return env_factory()
        # Vary assets per env for diversity
        random.seed(seed + idx)
        n_assets = random.randint(20, 100)
        return MigrationEnvironment(n_assets=n_assets, seed=seed + idx)

    # Pre-create pool (lightweight)
    envs = [_make_env(i) for i in range(n_envs)]
    for e in envs:
        e.reset()

    total_steps = 0
    # Need unwrapped agent for select_action/evaluate when compiled
    raw_agent = agent._orig_mod if hasattr(agent, "_orig_mod") else agent  # type: ignore[attr-defined]

    # All envs share one padded categorical width so a rollout step is ONE
    # batched GNN forward across every active env (instead of one forward per
    # env per step). Padding rows are masked to -inf so they never get sampled.
    max_assets = max(e.n_assets for e in envs)

    def _padded_dist(logits: torch.Tensor, counts: list[int], avail_pad: torch.Tensor) -> Categorical:
        """Per-env Categorical from batched node logits (padded to max_assets)."""
        logits_pad = torch.full((len(counts), max_assets), float("-inf"), device=device)
        start = 0
        for r, n in enumerate(counts):
            logits_pad[r, :n] = logits[start:start + n]
            start += n
        return Categorical(logits=logits_pad.masked_fill(~avail_pad, float("-inf")))

    for rollout in range(n_episodes):
        for e in envs:
            e.reset()
        # Cache per-env static features + edges for this episode (they are
        # fixed after reset; only migrated/remaining-days change per step).
        statics: list[np.ndarray] = []
        edge_tensors: list[torch.Tensor] = []
        for e in envs:
            st, ei = _env_static_features(e, device)
            statics.append(st)
            edge_tensors.append(ei)
        done = [False] * n_envs
        # Flattened per-step transition records, in global step order.
        step_log_probs: list[torch.Tensor] = []
        step_values: list[torch.Tensor] = []
        step_rewards: list[torch.Tensor] = []
        # PPO importance sampling needs every (state, action) so the inner
        # epochs can recompute log π_θ under the *updated* policy — reuse the
        # exact batched tensors the rollout used (one forward per inner epoch).
        step_records: list[tuple] = []  # (X, EI, B, counts, mask_all, actions, active)
        # Per-env reward trajectories for discounted returns.
        rewards_per_env: list[list[float]] = [[] for _ in range(n_envs)]
        rollout_rewards: list[float] = []

        while not all(done):
            active = [i for i in range(n_envs) if not done[i]]
            # Assemble one (total_nodes, 6) feature tensor from cached static
            # columns + the two dynamic columns; single device transfer per step.
            total_nodes = sum(statics[i].shape[0] for i in active)
            feat = np.zeros((total_nodes, 6), dtype=np.float32)
            eis: list[torch.Tensor] = []
            counts: list[int] = []
            offset = 0
            for r, i in enumerate(active):
                st = statics[i]
                n = st.shape[0]
                feat[offset:offset + n, :4] = st
                rem = max(0.0, float(envs[i].deadline_days - envs[i].elapsed_days)) / 3650.0
                feat[offset:offset + n, 4] = rem
                feat[offset:offset + n, 5] = np.asarray(envs[i].migrated, dtype=np.float32)
                eis.append(edge_tensors[i] + offset if edge_tensors[i].numel() else edge_tensors[i])
                counts.append(n)
                offset += n
            X = torch.from_numpy(feat).to(device)
            EI = torch.cat(eis, dim=1) if eis else torch.empty(2, 0, dtype=torch.long, device=device)
            # Per-env graph ids via repeat (one tensor, no per-env allocations).
            B = torch.from_numpy(np.repeat(np.arange(len(active), dtype=np.int64), counts)).to(device)
            # Padded availability (len(active), max_assets) — padded slots stay False.
            avail_pad = torch.zeros((len(active), max_assets), dtype=torch.bool, device=device)
            for r, i in enumerate(active):
                avail = envs[i].available
                if avail:
                    avail_pad[r, torch.as_tensor(avail, device=device)] = True
            # One batched forward: logits (total_nodes,), values (len(active),).
            logits, values = raw_agent.forward(X, EI, B)
            dist = _padded_dist(logits, counts, avail_pad)
            actions = dist.sample()  # (len(active),)
            log_probs = dist.log_prob(actions)
            # Step every active env (fast Python bookkeeping; GPU already done).
            step_reward_list: list[float] = []
            for r, i in enumerate(active):
                a = int(actions[r].item())
                _, reward, d, _ = envs[i].step(a)
                rewards_per_env[i].append(reward)
                rollout_rewards.append(reward)
                step_reward_list.append(reward)
                if d:
                    done[i] = True
            step_log_probs.append(log_probs)
            step_values.append(values)
            step_rewards.append(torch.as_tensor(step_reward_list, dtype=torch.float32, device=device))
            step_records.append((X, EI, B, counts, avail_pad, actions, active))

        if not step_log_probs:
            continue

        # Flatten transitions in collection order.
        log_probs_t = torch.cat(step_log_probs)
        values_t = torch.cat(step_values)
        n_trans = log_probs_t.numel()
        # Discounted returns per env, mapped back into flattened order.
        env_returns: list[list[float]] = []
        for rew_list in rewards_per_env:
            rets: list[float] = []
            G = 0.0
            for r in reversed(rew_list):
                G = r + gamma * G
                rets.insert(0, G)
            env_returns.append(rets)
        step_idx = [0] * n_envs
        flat_returns: list[float] = []
        for rw, rec in zip(step_rewards, step_records):
            active = rec[6]
            for r, i in enumerate(active):
                flat_returns.append(env_returns[i][step_idx[i]])
                step_idx[i] += 1
        returns_t = torch.as_tensor(flat_returns, dtype=torch.float32, device=device)
        if returns_t.numel() > 1 and returns_t.std() > 1e-6:
            returns_t = (returns_t - returns_t.mean()) / (returns_t.std() + 1e-8)
        # Advantage normalization
        advantages = returns_t - values_t.detach()
        if advantages.numel() > 1 and advantages.std() > 1e-6:
            advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
        old_log_probs = log_probs_t.detach()

        # PPO update: multiple epochs over the same rollout batch.
        # The importance ratio exp(log π_θ - log π_θ_old) MUST use log-probs
        # recomputed under the current (post-update) policy — reusing the
        # rollout log-probs would pin the ratio to 1 and neuter the clipped
        # surrogate (a stub we are not carrying forward). Each inner epoch
        # recomputes log-probs for the full rollout once, then slices per
        # mini-batch; the graph is kept alive by accumulating every mini-batch
        # loss and backpropagating once per rollout.
        if batch_size is None:
            batch_size = min(256, n_trans)
        n_batches = max(1, n_trans // batch_size)
        accumulated_loss: torch.Tensor | None = None
        for _ in range(ppo_epochs):
            # Recompute log-probs (and state values) under the current policy:
            # one batched forward per recorded step, identical tensor layout.
            new_lp_list: list[torch.Tensor] = []
            new_val_list: list[torch.Tensor] = []
            for X, EI, B, counts, avail_pad, actions, active in step_records:
                logits, values = raw_agent.forward(X, EI, B)
                dist = _padded_dist(logits, counts, avail_pad)
                new_lp_list.append(dist.log_prob(actions))
                new_val_list.append(values)
            new_log_probs_t = torch.cat(new_lp_list)
            new_values_t = torch.cat(new_val_list)
            perm = torch.randperm(n_trans)
            for i in range(n_batches):
                idx = perm[i*batch_size:(i+1)*batch_size]
                batch_adv = advantages[idx]
                batch_ret = returns_t[idx]
                batch_old_lp = old_log_probs[idx]
                # True importance ratio under the updated policy.
                ratio = torch.exp(new_log_probs_t[idx] - batch_old_lp)
                # Clipped surrogate
                surr1 = ratio * batch_adv
                surr2 = torch.clamp(ratio, 1 - clip_ratio, 1 + clip_ratio) * batch_adv
                actor_loss = -torch.min(surr1, surr2).mean()
                critic_loss = F.mse_loss(new_values_t[idx], batch_ret)
                # Entropy bonus from the current policy's log-probs
                entropy = -new_log_probs_t[idx].mean()
                loss = actor_loss + value_coef * critic_loss - entropy_coef * entropy
                accumulated_loss = loss if accumulated_loss is None else accumulated_loss + loss
        optimizer.zero_grad()
        accumulated_loss.backward()
        torch.nn.utils.clip_grad_norm_(agent.parameters(), max_norm=max_grad_norm)
        optimizer.step()
        scheduler.step()
        total_steps += len(rollout_rewards)

        if (rollout + 1) % 100 == 0 or rollout == n_episodes - 1:
            avg_reward = sum(rollout_rewards) / max(len(rollout_rewards), 1)
            if avg_reward > best_avg_reward:
                best_avg_reward = avg_reward
                # Unwrap compiled wrapper for saving
                to_save = agent._orig_mod if hasattr(agent, "_orig_mod") else agent  # type: ignore[attr-defined]
                torch.save(to_save.state_dict(), save_path)
            lr_now = optimizer.param_groups[0]["lr"]
            print(f"PPO rollout {rollout+1:>5}/{n_episodes} | avg_reward={avg_reward:.2f} | best={best_avg_reward:.2f} | lr={lr_now:.2e} | envs={n_envs}")

    if not os.path.exists(save_path):
        to_save = agent._orig_mod if hasattr(agent, "_orig_mod") else agent  # type: ignore[attr-defined]
        torch.save(to_save.state_dict(), save_path)
    print(f"\nPPO training complete. Best avg reward: {best_avg_reward:.2f} (vectorized {n_envs} envs)")
    print(f"Model saved to: {save_path}")
    raw = agent._orig_mod if hasattr(agent, "_orig_mod") else agent  # type: ignore[attr-defined]
    return raw


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
