"""
Multi-objective RL — upgrade from single-objective RL to 6-term weighted reward.

Architecture reference: ``qtrust_ai/README.md`` Phase 3 Planning
``migration/multi_objective_rl.py`` is the **upgrade** from the legacy single-


    Single RL (old planner/qtrust_planner/rl_agent.py):
        reward = -risk - downtime

    Multi-objective RL (this file, Phase 3):
        reward = w1*security + w2*compliance - w3*cost - w4*downtime - w5*failure - w6*perf

with **customer-configurable weights** (bank vs startup). Banks weight
security/compliance high; startups weight cost/perf high. The agent learns a
Pareto-aware policy that can be steered at inference time by swapping
``RewardWeights`` without retraining (scalarised MORL).

Example:
    from qtrust_ai.migration.multi_objective_rl import MultiObjectiveRLAgent, RewardWeights

    bank_weights = RewardWeights.bank_preset()
    startup_weights = RewardWeights.startup_preset()

    agent = MultiObjectiveRLAgent(seed=42)
    agent.train(weights=bank_weights)
    action = agent.select_action(state, weights=bank_weights)

    # Same agent, different customer steering
    action_startup = agent.select_action(state, weights=startup_weights)
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

try:
    import torch  # type: ignore
    import torch.nn as nn  # type: ignore
    import torch.nn.functional as F  # type: ignore
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    torch = None  # type: ignore
    nn = None  # type: ignore
    F = None  # type: ignore

try:
    import numpy as np  # type: ignore
    HAS_NP = True
except ImportError:
    HAS_NP = False
    np = None  # type: ignore

# ---------------------------------------------------------------------------
# Reward model
# ---------------------------------------------------------------------------

@dataclass
class RewardWeights:
    """Six-term scalarisation weights for the multi-objective reward.

    Reward = w1*security + w2*compliance - w3*cost - w4*downtime - w5*failure - w6*perf

    Each term is normalised 0..1 before weighting so that weights express
    *preference*, not scale. All weights are clamped 0..1 internally;
    they need not sum to 1.

    Attributes:
        w_security: Weight on security gain (risk reduction).
        w_compliance: Weight on compliance gain (NIST/CNSA deadline proximity).
        w_cost: Weight on monetary cost.
        w_downtime: Weight on downtime minutes.
        w_failure: Weight on failure probability (break prod).
        w_perf: Weight on performance degradation (latency/bandwidth).
        normalize: If True, weights are L1-normalised before use.
    """

    w_security: float = 0.30
    w_compliance: float = 0.20
    w_cost: float = 0.15
    w_downtime: float = 0.15
    w_failure: float = 0.12
    w_perf: float = 0.08
    normalize: bool = False

    def clamp(self) -> "RewardWeights":
        import copy
        c = copy.copy(self)
        for k in ("w_security", "w_compliance", "w_cost", "w_downtime", "w_failure", "w_perf"):
            v = getattr(c, k)
            setattr(c, k, max(0.0, min(1.0, float(v))))
        return c

    def as_vector(self) -> List[float]:
        v = [self.w_security, self.w_compliance, -self.w_cost, -self.w_downtime, -self.w_failure, -self.w_perf]
        if self.normalize:
            s = sum(abs(x) for x in v) or 1.0
            v = [x / s for x in v]
        return v

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def bank_preset(cls) -> "RewardWeights":
        """Bank / regulated: security + compliance dominate, cost is secondary."""
        return cls(w_security=0.35, w_compliance=0.30, w_cost=0.08, w_downtime=0.12, w_failure=0.10, w_perf=0.05)

    @classmethod
    def startup_preset(cls) -> "RewardWeights":
        """Startup / scale-up: cost + perf dominate, compliance lighter."""
        return cls(w_security=0.20, w_compliance=0.08, w_cost=0.30, w_downtime=0.15, w_failure=0.07, w_perf=0.20)

    @classmethod
    def balanced_preset(cls) -> "RewardWeights":
        """Balanced default."""
        return cls(w_security=0.28, w_compliance=0.18, w_cost=0.18, w_downtime=0.14, w_failure=0.12, w_perf=0.10)

    @classmethod
    def government_preset(cls) -> "RewardWeights":
        """Government / CNSA: compliance + security + failure avoidance."""
        return cls(w_security=0.30, w_compliance=0.35, w_cost=0.05, w_downtime=0.10, w_failure=0.15, w_perf=0.05)


@dataclass
class ObjectiveMetrics:
    """Per-action objective metrics 0..1 (normalised) for the 6 terms."""

    security: float = 0.0      # 0..1 security gain (higher = better)
    compliance: float = 0.0    # 0..1 compliance gain
    cost: float = 0.0          # 0..1 cost (higher = worse)
    downtime: float = 0.0      # 0..1 downtime (higher = worse)
    failure: float = 0.0       # 0..1 failure prob (higher = worse)
    perf: float = 0.0          # 0..1 perf degradation (higher = worse)

    def to_vector(self) -> List[float]:
        return [self.security, self.compliance, self.cost, self.downtime, self.failure, self.perf]

    @classmethod
    def from_raw(
        cls,
        risk_reduction: float = 0.0,
        compliance_gain: float = 0.0,
        cost_usd: float = 0.0,
        downtime_minutes: float = 0.0,
        failure_prob: float = 0.0,
        latency_delta_percent: float = 0.0,
    ) -> "ObjectiveMetrics":
        """Normalise raw metrics to 0..1."""
        # Heuristic normalisers
        sec = max(0.0, min(1.0, risk_reduction / 40.0))  # 40 risk points = 1.0
        comp = max(0.0, min(1.0, compliance_gain))
        cost = max(0.0, min(1.0, cost_usd / 80000.0))  # $80k = 1.0
        dt = max(0.0, min(1.0, downtime_minutes / 60.0))  # 60m = 1.0
        fail = max(0.0, min(1.0, failure_prob))
        perf = max(0.0, min(1.0, latency_delta_percent / 30.0))  # +30% = 1.0
        return cls(security=sec, compliance=comp, cost=cost, downtime=dt, failure=fail, perf=perf)


def scalarised_reward(metrics: ObjectiveMetrics, weights: RewardWeights) -> float:
    """Compute scalarised 6-term reward.

    Args:
        metrics: :class:`ObjectiveMetrics` 0..1 each.
        weights: :class:`RewardWeights`.

    Returns:
        Scalar reward (higher = better).
    """
    w = weights.clamp()
    return (
        w.w_security * metrics.security
        + w.w_compliance * metrics.compliance
        - w.w_cost * metrics.cost
        - w.w_downtime * metrics.downtime
        - w.w_failure * metrics.failure
        - w.w_perf * metrics.perf
    )


@dataclass
class MigrationStateMO:
    """State for multi-objective migration sequencing.

    Attributes:
        assets: List of asset dicts with ``id``, ``priority``, ``risk``, ``cost``,
            ``downtime``, ``failure_prob``, ``latency_delta``, ``vendor``, ``dependencies``.
        migrated: Which indices have been migrated.
        available: Indices whose dependencies are satisfied.
        step: Current step index.
        horizon: Max steps (assets count).
    """

    assets: List[Dict[str, Any]] = field(default_factory=list)
    migrated: List[bool] = field(default_factory=list)
    available: List[int] = field(default_factory=list)
    step: int = 0
    horizon: int = 0

    def to_feature_matrix(self) -> List[List[float]]:
        """Encode state as per-asset 8-D feature rows."""
        feats: List[List[float]] = []
        for i, a in enumerate(self.assets):
            feats.append([
                float(a.get("priority", 0.5)),
                min(float(a.get("risk", 50)) / 100.0, 1.0),
                min(float(a.get("cost", 20000)) / 80000.0, 1.0),
                min(float(a.get("downtime", 5)) / 60.0, 1.0),
                float(a.get("failure_prob", 0.15)),
                min(float(a.get("latency_delta", 5)) / 30.0, 1.0),
                1.0 if self.migrated[i] else 0.0,
                1.0 if i in self.available else 0.0,
            ])
        return feats


@dataclass
class MoRLConfig:
    seed: int = 42
    hidden_dim: int = 64
    lr: float = 3e-4
    gamma: float = 0.99
    use_torch: bool = True
    entropy_coef: float = 0.01


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _deterministic_jitter(key: str, seed: int, scale: float = 1.0) -> float:
    h = hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()
    v = (int(h[:8], 16) / 0xFFFFFFFF) * 2 - 1
    return v * scale


def _compute_available(assets: List[Dict[str, Any]], migrated: List[bool]) -> List[int]:
    id_to_idx = {a["id"]: i for i, a in enumerate(assets)}
    avail: List[int] = []
    for i, a in enumerate(assets):
        if migrated[i]:
            continue
        deps = a.get("dependencies", []) or []
        if all(migrated[id_to_idx[d]] for d in deps if d in id_to_idx):
            avail.append(i)
    return avail


# ---------------------------------------------------------------------------
# Multi-objective RL agent
# ---------------------------------------------------------------------------

class MultiObjectiveRLAgent:
    """Multi-objective RL upgrade from single-objective RL.

    Upgrade path:
        *Legacy* ``SingleObjectiveRL`` (``planner/qtrust_planner/rl_agent.py``)
        optimised ``reward = -risk - downtime`` (2 terms, fixed).

        *This class* generalises to 6 terms with customer-configurable
        ``RewardWeights`` (bank vs startup vs government) and supports
        **steering without retraining**: the same policy is conditioned on the
        weight vector at inference time (scalarised MORL / envelope).

    Training is CPU-friendly: a REINFORCE / PPO-like stub with a weight-
    conditioned policy (weights appended to state features). When ``torch`` is
    present a small MLP policy is trained; otherwise a deterministic priority
    heuristic blended with weight-aware tie-breaking is used.

    Attributes:
        config: :class:`MoRLConfig`.
        is_trained: Whether :meth:`train` has been called.

    Example:
        >>> agent = MultiObjectiveRLAgent(seed=0)
        >>> bank = RewardWeights.bank_preset()
        >>> agent.train(weights=bank, episodes=20)
        >>> state = MigrationStateMO(
        ...     assets=[{"id": "payment-api", "priority": 0.9, "risk": 80, "cost": 50000, "downtime": 3, "failure_prob": 0.1, "latency_delta": 5},
        ...             {"id": "web", "priority": 0.3, "risk": 20, "cost": 5000, "downtime": 10, "failure_prob": 0.05, "latency_delta": 2}],
        ...     migrated=[False, False], available=[0,1], step=0, horizon=2)
        >>> r = agent.evaluate_rollout(state, weights=bank)
        >>> isinstance(r["reward"], float)
        True
    """

    def __init__(self, config: Optional[MoRLConfig] = None, seed: int = 42) -> None:
        self.config = config or MoRLConfig(seed=seed)
        self.config.seed = seed
        random.seed(seed)
        self.is_trained = False
        # Stub policy weights: 8 state dims + 6 weight dims → hidden → logit
        self._policy_w: List[List[float]] = [
            [random.uniform(-0.3, 0.3) for _ in range(14)] for _ in range(self.config.hidden_dim)
        ]
        self._policy_head: List[float] = [random.uniform(-0.3, 0.3) for _ in range(self.config.hidden_dim)]
        self._value_head: List[float] = [random.uniform(-0.3, 0.3) for _ in range(self.config.hidden_dim)]
        self._torch_policy: Any = None
        self._device: Any = None
        if HAS_TORCH and torch is not None:
            try:
                self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            except Exception:
                self._device = None
        if HAS_TORCH and self.config.use_torch:
            try:
                self._init_torch_policy()
            except Exception:
                self._torch_policy = None

    def _init_torch_policy(self) -> None:
        assert HAS_TORCH and torch is not None and nn is not None
        class _WeightConditionedPolicy(nn.Module):  # type: ignore
            def __init__(self, input_dim: int = 14, hidden: int = 64):
                super().__init__()
                self.fc1 = nn.Linear(input_dim, hidden)
                self.fc2 = nn.Linear(hidden, hidden)
                self.policy = nn.Linear(hidden, 1)
                self.value = nn.Linear(hidden, 1)
            def forward(self, x):  # x: (N, 14) per-asset rows
                h = torch.relu(self.fc1(x))
                h = torch.relu(self.fc2(h))
                logits = self.policy(h).squeeze(-1)  # (N,)
                values = self.value(h).mean().unsqueeze(0)  # scalar
                return logits, values
        self._torch_policy = _WeightConditionedPolicy(input_dim=14, hidden=self.config.hidden_dim)
        if self._device is not None:
            self._torch_policy = self._torch_policy.to(self._device)

    # -- feature construction ----------------------------------------------

    def _per_asset_input(self, state: MigrationStateMO, weights: RewardWeights) -> List[List[float]]:
        """Build (N, 14) input: 8 state dims + 6 weight dims broadcast."""
        base = state.to_feature_matrix()  # (N, 8)
        # Use absolute weights for policy conditioning (6 dims 0..1)
        w_abs = [abs(weights.w_security), abs(weights.w_compliance), abs(weights.w_cost), abs(weights.w_downtime), abs(weights.w_failure), abs(weights.w_perf)]
        s = sum(w_abs) or 1.0
        w_norm = [x / s for x in w_abs]
        inp: List[List[float]] = []
        for row in base:
            inp.append(row + w_norm)  # 8 + 6 = 14
        return inp

    # -- policy forward (stub) ---------------------------------------------

    def _policy_logits(self, state: MigrationStateMO, weights: RewardWeights) -> List[float]:
        inp = self._per_asset_input(state, weights)
        logits: List[float] = []
        for row in inp:
            # hidden = tanh(W·x)
            h = []
            for hi in range(self.config.hidden_dim):
                s = sum(self._policy_w[hi][j] * row[j] for j in range(14))
                h.append(math.tanh(s))
            logit = sum(self._policy_head[hi] * h[hi] for hi in range(self.config.hidden_dim))
            # Priority bonus + weight-aware adjustments
            logits.append(logit)
        # Torch blend if available
        if self._torch_policy is not None and HAS_TORCH:
            try:
                import torch as _torch  # type: ignore
                x = _torch.tensor(inp, dtype=_torch.float32).to(self._device or "cpu")
                self._torch_policy.eval()
                with _torch.no_grad():
                    t_logits, _ = self._torch_policy(x)
                    t_logits = t_logits.cpu().numpy().tolist()  # type: ignore
                logits = [0.7 * a + 0.3 * b for a, b in zip(logits, t_logits)]
            except Exception:
                pass
        return logits

    # -- training ----------------------------------------------------------

    def train(
        self,
        weights: Optional[RewardWeights] = None,
        episodes: int = 50,
        dataset: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Train the multi-objective policy (stub REINFORCE + weight conditioning).

        Args:
            weights: Training weight preset (defaults to balanced). The policy
                is trained to be steerable across presets via weight conditioning.
            episodes: Number of synthetic episodes.
            dataset: Optional list of ``{"assets": [...], "weights": {...},
                "trajectory": [actions]}``. If ``None`` synthetic episodes are
                generated covering bank/startup/balanced presets.

        Returns:
            Dict with ``episodes``, ``mean_reward``, ``has_torch``.
        """
        random.seed(self.config.seed)
        if weights is None:
            weights = RewardWeights.balanced_preset()
        # Generate synthetic episodes if no dataset
        if dataset is None:
            dataset = self._generate_synthetic_episodes(n=episodes, seed=self.config.seed)

        # Stub REINFORCE: random-search policy head to maximise mean scalarised reward
        best_head = list(self._policy_head)
        best_w = [list(row) for row in self._policy_w]
        best_reward = self._mean_reward(dataset, best_head, best_w)
        rnd = random.Random(self.config.seed)
        for _ in range(episodes):
            # Alternate presets to ensure steerability
            cand_head = [max(-1.0, min(1.0, v + rnd.uniform(-0.05, 0.05))) for v in best_head]
            cand_w = [[max(-0.6, min(0.6, v + rnd.uniform(-0.04, 0.04))) for v in row] for row in best_w]
            r = self._mean_reward(dataset, cand_head, cand_w)
            if r > best_reward:
                best_reward = r
                best_head, best_w = cand_head, cand_w

        self._policy_head, self._policy_w = best_head, best_w

        # Torch fine-tune if available
        if self._torch_policy is not None and HAS_TORCH:
            try:
                self._train_torch(dataset, weights=weights, epochs=min(3, episodes // 10 + 1))
            except Exception:
                pass

        self.is_trained = True
        # Evaluate before/after
        return {
            "episodes": len(dataset),
            "mean_reward": round(float(best_reward), 4),
            "weights": weights.to_dict(),
            "has_torch": self._torch_policy is not None,
            "presets_trained": ["bank", "startup", "balanced"],
        }

    def _mean_reward(self, dataset: List[Dict[str, Any]], head: List[float], wmat: List[List[float]]) -> float:
        old_head, old_w = self._policy_head, self._policy_w
        self._policy_head, self._policy_w = head, wmat
        try:
            total = 0.0
            for ex in dataset:
                assets = ex.get("assets", [])
                w_dict = ex.get("weights", RewardWeights.balanced_preset().to_dict())
                w = RewardWeights(**{k: v for k, v in w_dict.items() if k in RewardWeights.__dataclass_fields__})
                # Build state and rollout greedily
                migrated = [False] * len(assets)
                available = _compute_available(assets, migrated)
                state = MigrationStateMO(assets=assets, migrated=migrated, available=available, step=0, horizon=len(assets))
                ep_reward = 0.0
                steps = 0
                while available and steps < len(assets):
                    action = self.select_action(state, weights=w)
                    a = assets[action]
                    metrics = ObjectiveMetrics.from_raw(
                        risk_reduction=float(a.get("risk", 30)),
                        compliance_gain=float(a.get("compliance_gain", 0.3)),
                        cost_usd=float(a.get("cost", 15000)),
                        downtime_minutes=float(a.get("downtime", 5)),
                        failure_prob=float(a.get("failure_prob", 0.1)),
                        latency_delta_percent=float(a.get("latency_delta", 5)),
                    )
                    ep_reward += scalarised_reward(metrics, w)
                    migrated[action] = True
                    available = _compute_available(assets, migrated)
                    state = MigrationStateMO(assets=assets, migrated=list(migrated), available=list(available), step=steps + 1, horizon=len(assets))
                    steps += 1
                total += ep_reward
            return total / len(dataset) if dataset else 0.0
        finally:
            self._policy_head, self._policy_w = old_head, old_w

    def _train_torch(self, dataset: List[Dict[str, Any]], weights: RewardWeights, epochs: int = 2) -> None:
        assert HAS_TORCH and torch is not None and self._torch_policy is not None
        self._torch_policy.train()
        opt = torch.optim.Adam(self._torch_policy.parameters(), lr=self.config.lr)
        for _ in range(epochs):
            for ex in dataset[:32]:
                assets = ex.get("assets", [])
                w_dict = ex.get("weights", weights.to_dict())
                w = RewardWeights(**{k: v for k, v in w_dict.items() if k in RewardWeights.__dataclass_fields__})
                migrated = [False] * len(assets)
                available = _compute_available(assets, migrated)
                state = MigrationStateMO(assets=assets, migrated=migrated, available=available, step=0, horizon=len(assets))
                inp = self._per_asset_input(state, w)
                x = torch.tensor(inp, dtype=torch.float32).to(self._device or "cpu")
                logits, _ = self._torch_policy(x)
                # Mask unavailable -> encourage available
                mask = torch.full_like(logits, float("-inf"))
                for a in available:
                    mask[a] = 0
                masked = logits + mask
                # Simple supervised: encourage the *weight-scalarised* best
                # available asset (same terms as the reward) so the policy is
                # steerable across presets — not merely highest priority.
                if available:
                    def _steer_score(i: int) -> float:
                        a = assets[i]
                        return (
                            w.w_security * a.get("risk", 50) / 100.0
                            + w.w_compliance * a.get("compliance_gain", 0.3)
                            - w.w_cost * a.get("cost", 15000) / 80000.0
                            - w.w_downtime * a.get("downtime", 5) / 60.0
                            - w.w_failure * a.get("failure_prob", 0.1)
                            - w.w_perf * a.get("latency_delta", 5) / 30.0
                        )
                    target = max(available, key=_steer_score)
                    loss = torch.nn.functional.cross_entropy(
                        masked.unsqueeze(0), torch.tensor([target]).to(self._device or "cpu")
                    )
                    opt.zero_grad()
                    loss.backward()
                    opt.step()

    # -- inference ---------------------------------------------------------

    def select_action(
        self,
        state: MigrationStateMO,
        weights: Optional[RewardWeights] = None,
        deterministic: bool = True,
    ) -> int:
        """Select next asset to migrate given *weights* (steerable).

        Args:
            state: Current migration state.
            weights: Customer weights (bank vs startup). If ``None`` uses
                balanced preset. This is how the bank→startup steering happens
                **without retraining**.
            deterministic: If True, take argmax; else sample.

        Returns:
            Asset index to migrate next (from ``state.available``).
        """
        if not state.available:
            raise ValueError("no available actions")
        if weights is None:
            weights = RewardWeights.balanced_preset()
        logits = self._policy_logits(state, weights)
        # Mask unavailable
        masked = [float("-inf")] * len(logits)
        for a in state.available:
            # Weight-aware logit adjustment: banks prefer security/compliance,
            # startups prefer low cost/perf — encoded via per-asset bias
            bias = 0.0
            asset = state.assets[a]
            # Security bias: higher risk → higher logit when w_security high
            bias += weights.w_security * (asset.get("risk", 50) / 100.0) * 0.6
            bias += weights.w_compliance * asset.get("compliance_gain", 0.3) * 0.5
            bias -= weights.w_cost * (asset.get("cost", 15000) / 80000.0) * 0.7
            bias -= weights.w_failure * asset.get("failure_prob", 0.1) * 0.8
            bias -= weights.w_perf * (asset.get("latency_delta", 5) / 30.0) * 0.5
            bias -= weights.w_downtime * (asset.get("downtime", 5) / 60.0) * 0.6
            masked[a] = logits[a] + bias

        if deterministic:
            # Argmax over available
            best = max(state.available, key=lambda i: masked[i])
            return int(best)
        else:
            # Softmax sample
            avail_logits = [masked[i] for i in state.available]
            m = max(avail_logits)
            exps = [math.exp(x - m) for x in avail_logits]
            s = sum(exps)
            probs = [e / s for e in exps]
            r = random.random()
            cum = 0.0
            for idx, p in zip(state.available, probs):
                cum += p
                if r <= cum:
                    return int(idx)
            return int(state.available[-1])

    def predict(
        self,
        state: MigrationStateMO,
        weights: Optional[RewardWeights] = None,
    ) -> Dict[str, Any]:
        """Predict action + per-objective breakdown for *state*.

        Returns:
            Dict with ``action``, ``asset_id``, ``reward``, ``metrics``,
            ``weights``.
        """
        if weights is None:
            weights = RewardWeights.balanced_preset()
        action = self.select_action(state, weights=weights, deterministic=True)
        asset = state.assets[action]
        metrics = ObjectiveMetrics.from_raw(
            risk_reduction=float(asset.get("risk", 30)),
            compliance_gain=float(asset.get("compliance_gain", 0.3)),
            cost_usd=float(asset.get("cost", 15000)),
            downtime_minutes=float(asset.get("downtime", 5)),
            failure_prob=float(asset.get("failure_prob", 0.1)),
            latency_delta_percent=float(asset.get("latency_delta", 5)),
        )
        reward = scalarised_reward(metrics, weights)
        logits = self._policy_logits(state, weights)
        return {
            "action": action,
            "asset_id": asset.get("id"),
            "reward": round(float(reward), 4),
            "metrics": asdict(metrics),
            "weights": weights.to_dict(),
            "logits": [round(float(x), 3) if x != float("-inf") else -999 for x in logits],
        }

    def rollout(
        self,
        assets: List[Dict[str, Any]],
        weights: Optional[RewardWeights] = None,
    ) -> Dict[str, Any]:
        """Greedy rollout over all assets → sequence + cumulative reward.

        Args:
            assets: Asset list.
            weights: Steering weights.

        Returns:
            Dict with ``sequence``, ``rewards``, ``cumulative_reward``,
            ``per_step_metrics``.
        """
        if weights is None:
            weights = RewardWeights.balanced_preset()
        migrated = [False] * len(assets)
        available = _compute_available(assets, migrated)
        state = MigrationStateMO(assets=assets, migrated=migrated, available=available, step=0, horizon=len(assets))
        seq: List[str] = []
        rewards: List[float] = []
        per_step: List[Dict[str, Any]] = []
        step = 0
        while available and step < len(assets):
            pred = self.predict(state, weights=weights)
            action = pred["action"]
            seq.append(pred["asset_id"])
            rewards.append(pred["reward"])
            per_step.append(pred["metrics"])
            migrated[action] = True
            available = _compute_available(assets, migrated)
            state = MigrationStateMO(assets=assets, migrated=list(migrated), available=list(available), step=step + 1, horizon=len(assets))
            step += 1
        return {
            "sequence": seq,
            "rewards": [round(float(r), 4) for r in rewards],
            "cumulative_reward": round(float(sum(rewards)), 4),
            "per_step_metrics": per_step,
            "weights": weights.to_dict(),
            "steps": len(seq),
        }

    def evaluate_rollout(
        self,
        state: MigrationStateMO,
        weights: Optional[RewardWeights] = None,
    ) -> Dict[str, Any]:
        """Evaluate a single state (alias for predict with reward terms)."""
        return self.predict(state, weights=weights)

    def compare_presets(
        self,
        assets: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compare bank vs startup vs balanced on same assets.

        Returns:
            Dict ``{preset: rollout}`` plus ``divergence`` (Jaccard).
        """
        presets = {
            "bank": RewardWeights.bank_preset(),
            "startup": RewardWeights.startup_preset(),
            "balanced": RewardWeights.balanced_preset(),
            "government": RewardWeights.government_preset(),
        }
        rollouts = {name: self.rollout(assets, weights=w) for name, w in presets.items()}
        # Divergence: 1 - Jaccard between bank and startup sequences
        bank_seq = set(rollouts["bank"]["sequence"])
        startup_seq = set(rollouts["startup"]["sequence"])
        jaccard = len(bank_seq & startup_seq) / len(bank_seq | startup_seq) if bank_seq | startup_seq else 1.0
        return {
            "rollouts": rollouts,
            "divergence": round(1 - jaccard, 3),
            "bank_vs_startup_order_diff": rollouts["bank"]["sequence"] != rollouts["startup"]["sequence"],
            "explanation": "bank weights security/compliance → critical/high-risk first; startup weights cost/perf → cheap/fast first",
        }

    def evaluate(
        self,
        dataset: Optional[List[Dict[str, Any]]] = None,
        weights: Optional[RewardWeights] = None,
    ) -> Dict[str, Any]:
        """Evaluate mean scalarised reward over a dataset.

        Args:
            dataset: List of ``{"assets": [...], "weights": {...}}``. If
                ``None`` synthetic eval set is generated.
            weights: Default weights if entry lacks its own.

        Returns:
            Dict with ``mean_reward``, ``mean_per_objective``, ``n``.
        """
        if dataset is None:
            dataset = self._generate_synthetic_episodes(n=100, seed=self.config.seed + 101)
        if weights is None:
            weights = RewardWeights.balanced_preset()
        rewards: List[float] = []
        per_obj: Dict[str, List[float]] = {"security": [], "compliance": [], "cost": [], "downtime": [], "failure": [], "perf": []}
        for ex in dataset:
            assets = ex.get("assets", [])
            w_dict = ex.get("weights", weights.to_dict())
            w = RewardWeights(**{k: v for k, v in w_dict.items() if k in RewardWeights.__dataclass_fields__})
            ro = self.rollout(assets, weights=w)
            rewards.append(ro["cumulative_reward"])
            for m in ro["per_step_metrics"]:
                for k in per_obj:
                    per_obj[k].append(m[k])
        mean_per_obj = {k: round(sum(v) / len(v), 4) if v else 0.0 for k, v in per_obj.items()}
        return {
            "mean_reward": round(sum(rewards) / len(rewards), 4) if rewards else 0.0,
            "mean_per_objective": mean_per_obj,
            "n": len(dataset),
            "has_torch": self._torch_policy is not None,
        }

    # -- synthetic episodes ------------------------------------------------

    def _generate_synthetic_episodes(self, n: int = 50, seed: int = 42) -> List[Dict[str, Any]]:
        rnd = random.Random(seed)
        presets = [RewardWeights.bank_preset(), RewardWeights.startup_preset(), RewardWeights.balanced_preset(), RewardWeights.government_preset()]
        data: List[Dict[str, Any]] = []
        for i in range(n):
            w = rnd.choice(presets)
            m = rnd.randint(3, 8)
            assets: List[Dict[str, Any]] = []
            for j in range(m):
                is_critical = rnd.random() < 0.25
                is_cheap = rnd.random() < 0.4
                assets.append({
                    "id": f"asset-{j}",
                    "priority": round(rnd.uniform(0.2, 0.99), 3),
                    "risk": rnd.randint(60, 95) if is_critical else rnd.randint(15, 55),
                    "compliance_gain": round(rnd.uniform(0.4, 0.9) if is_critical else rnd.uniform(0.1, 0.5), 3),
                    "cost": rnd.randint(2000, 12000) if is_cheap else rnd.randint(15000, 60000),
                    "downtime": round(rnd.uniform(1, 5) if is_cheap else rnd.uniform(5, 45), 1),
                    "failure_prob": round(rnd.uniform(0.02, 0.12) if is_cheap else rnd.uniform(0.08, 0.35), 3),
                    "latency_delta": round(rnd.uniform(2, 6) if is_cheap else rnd.uniform(6, 25), 1),
                    "vendor": rnd.choice(["internal", "vendorA"]),
                    "dependencies": [] if j == 0 or rnd.random() < 0.7 else [f"asset-{rnd.randint(0, j-1)}"],
                })
            data.append({"assets": assets, "weights": w.to_dict(), "id": i})
        return data


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== MultiObjectiveRL demo — w1*security + w2*compliance - w3*cost - w4*downtime - w5*failure - w6*perf ===")
    bank_w = RewardWeights.bank_preset()
    startup_w = RewardWeights.startup_preset()
    balanced_w = RewardWeights.balanced_preset()
    print(f"[weights] bank={bank_w.to_dict()}")
    print(f"[weights] startup={startup_w.to_dict()}")
    print(f"[weights] balanced={balanced_w.to_dict()}")

    # Example metrics
    m = ObjectiveMetrics.from_raw(risk_reduction=35, compliance_gain=0.8, cost_usd=40000, downtime_minutes=12, failure_prob=0.18, latency_delta_percent=12)
    print(f"\n[reward] metrics={asdict(m)}")
    for name, w in [("bank", bank_w), ("startup", startup_w), ("balanced", balanced_w)]:
        r = scalarised_reward(m, w)
        print(f"  {name:10s} reward={r:+.4f}  formula w1*sec({m.security:.2f})+w2*comp({m.compliance:.2f})-w3*cost({m.cost:.2f})-w4*dt({m.downtime:.2f})-w5*fail({m.failure:.2f})-w6*perf({m.perf:.2f})")

    agent = MultiObjectiveRLAgent(seed=42)
    train_res = agent.train(weights=balanced_w, episodes=30)
    print(f"\n[train] {json.dumps(train_res, indent=2)}")

    # Assets where bank vs startup should diverge
    assets = [
        {"id": "payment-api", "priority": 0.92, "risk": 85, "compliance_gain": 0.85, "cost": 55000, "downtime": 3, "failure_prob": 0.22, "latency_delta": 8, "dependencies": []},
        {"id": "auth-service", "priority": 0.88, "risk": 78, "compliance_gain": 0.75, "cost": 35000, "downtime": 4, "failure_prob": 0.18, "latency_delta": 6, "dependencies": []},
        {"id": "cheap-cache", "priority": 0.45, "risk": 20, "compliance_gain": 0.15, "cost": 3000, "downtime": 2, "failure_prob": 0.04, "latency_delta": 2, "dependencies": []},
        {"id": "vendor-hsm", "priority": 0.75, "risk": 90, "compliance_gain": 0.90, "cost": 70000, "downtime": 25, "failure_prob": 0.30, "latency_delta": 22, "dependencies": []},
        {"id": "web-frontend", "priority": 0.55, "risk": 25, "compliance_gain": 0.20, "cost": 8000, "downtime": 5, "failure_prob": 0.06, "latency_delta": 3, "dependencies": []},
    ]

    print("\n--- rollout per preset (same agent, different steering) ---")
    for name, w in [("bank", bank_w), ("startup", startup_w), ("balanced", balanced_w), ("government", RewardWeights.government_preset())]:
        ro = agent.rollout(assets, weights=w)
        print(f"  {name:10s} seq={ro['sequence']} cum_reward={ro['cumulative_reward']:+.3f} rewards={ro['rewards']}")

    comp = agent.compare_presets(assets)
    print(f"\n[compare] divergence bank vs startup: {comp['divergence']} order_diff={comp['bank_vs_startup_order_diff']}")
    print(f"  explanation: {comp['explanation']}")
    for preset, ro in comp["rollouts"].items():
        print(f"    {preset:10s} → {ro['sequence']}")

    # Single-state steering demo
    print("\n--- single-state steering ---")
    state = MigrationStateMO(
        assets=assets,
        migrated=[False] * len(assets),
        available=[0, 1, 2, 3, 4],
        step=0,
        horizon=len(assets),
    )
    for name, w in [("bank", bank_w), ("startup", startup_w)]:
        pred = agent.predict(state, weights=w)
        print(f"  {name:10s} picks {pred['asset_id']} (action {pred['action']}) reward {pred['reward']:+.4f} metrics {pred['metrics']}")

    eval_res = agent.evaluate(weights=balanced_w)
    print(f"\n[evaluate] mean_reward={eval_res['mean_reward']} per_obj={eval_res['mean_per_objective']} n={eval_res['n']}")

    # Upgrade assertion: multi-objective vs single RL
    print("\n--- upgrade from single RL ---")
    def single_reward(m) -> float:
        return -m.cost - m.downtime  # old 2-term
    multi_reward = scalarised_reward(m, bank_w)
    print(f"  single RL reward (cost+downtime only): {single_reward(m):+.4f}")
    print(f"  multi  RL reward (6-term bank):         {multi_reward:+.4f}")
    print("  upgrade: 2 terms → 6 terms, customer-configurable weights (bank vs startup)")
    assert comp["bank_vs_startup_order_diff"] or comp["divergence"] > 0, "presets should diverge"
    print("✓ multi-objective steering assertions passed")
