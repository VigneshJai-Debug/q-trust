"""Smoke tests for the RL migration agent (CPU-safe)."""
import sys
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qtrust_planner.rl_agent import (  # noqa: E402
    MigrationAgent,
    MigrationEnvironment,
    _env_static_features,
    state_to_tensors,
)


def test_environment_step_and_completion():
    env = MigrationEnvironment(n_assets=12, seed=0)
    state = env.reset()
    steps = 0
    while state.available and steps < 50:
        action = state.available[0]
        state, reward, done, info = env.step(action)
        steps += 1
        if done:
            break
    assert steps > 0
    assert all(state.migrated) or not state.available or state.elapsed_days >= state.deadline_days


def test_invalid_action_penalized():
    env = MigrationEnvironment(n_assets=10, seed=1)
    env.reset()
    migrated_idx = next(i for i, m in enumerate(env.migrated) if not m)
    env.migrated[migrated_idx] = True  # force unavailable
    env.available = [i for i in env._compute_available()]
    bad = migrated_idx
    _, reward, done, info = env.step(bad)
    assert reward == -10.0
    assert done is False


def test_policy_network_shapes():
    agent = MigrationAgent(n_features=6, hidden_dim=32)
    x = torch.randn(15, 6)
    edge_index = torch.randint(0, 15, (2, 30))
    logits, value = agent(x, edge_index)
    assert logits.shape == (15,)
    assert value.numel() >= 1


def test_select_action_masks_unavailable():
    torch.manual_seed(3)
    agent = MigrationAgent(n_features=6, hidden_dim=16)
    x = torch.randn(10, 6)
    edge_index = torch.empty((2, 0), dtype=torch.long)
    for _ in range(20):
        action, log_prob, value = agent.select_action(x, edge_index, available=[2, 5])
        assert action in (2, 5)
        assert torch.isfinite(log_prob)


def test_evaluate_matches_select_action_log_prob():
    """PPO ratio recomputation primitive: log_prob of a chosen action under
    the same policy must exactly equal what select_action returned."""
    torch.manual_seed(3)
    agent = MigrationAgent(n_features=6, hidden_dim=16)
    x = torch.randn(10, 6)
    edge_index = torch.empty((2, 0), dtype=torch.long)
    for _ in range(10):
        action, log_prob, _ = agent.select_action(x, edge_index, available=[2, 5])
        lp2, _ = agent.evaluate(x, edge_index, torch.tensor(action), [2, 5])
        assert torch.allclose(log_prob, lp2, atol=1e-6)


def test_env_static_features_match_state_to_tensors():
    """The vectorized rollout's cached feature columns must equal the reference
    state_to_tensors encoding (columns 0-3 static, 4-5 dynamic)."""
    env = MigrationEnvironment(n_assets=12, seed=9)
    env.reset()

    def _rebuild(env) -> torch.Tensor:
        static, _ = _env_static_features(env, torch.device("cpu"))
        n = static.shape[0]
        feat = torch.zeros((n, 6))
        feat[:, :4] = torch.as_tensor(static)
        feat[:, 4] = max(0.0, float(env.deadline_days - env.elapsed_days)) / 3650.0
        feat[:, 5] = torch.as_tensor(env.migrated, dtype=torch.float32)
        return feat

    x, _ = state_to_tensors(env, "cpu")
    assert torch.allclose(x, _rebuild(env), atol=1e-6)
    # Must stay identical after the environment advances a step.
    env.step(env.available[0])
    x2, _ = state_to_tensors(env, "cpu")
    assert torch.allclose(x2, _rebuild(env), atol=1e-6)


def test_state_to_tensors_device_and_shape():
    env = MigrationEnvironment(n_assets=8, seed=4)
    state = env.reset()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    x, edge_index = state_to_tensors(state, device)
    assert x.shape == (8, 6)
    assert x.device.type == device
    assert edge_index.shape[0] == 2


def test_train_agent_saves_checkpoint(tmp_path):
    from qtrust_planner.rl_agent import train_agent

    out = tmp_path / "agent.pt"
    train_agent(n_episodes=3, save_path=str(out))
    assert out.exists()
    sd = torch.load(out, map_location="cpu", weights_only=True)
    assert any("conv1" in k for k in sd.keys())


REAL_CBOM = {
    "schema_version": "qtrust.cbom.v1",
    "target": "example.edu",
    "assets": [
        {"host": "example.edu", "algorithm": "RSA-2048", "key_size": 2048,
         "criticality": "critical", "expired": False, "not_after": "2027-01-01T00:00:00+00:00"},
        {"host": "mail.example.edu", "algorithm": "ECDSA-P256", "key_size": 256,
         "criticality": "high"},
        {"host": "vpn.example.edu", "algorithm": "ML-DSA-659", "key_size": 659,
         "criticality": "medium"},
    ],
}


def test_from_cbom_pins_real_assets():
    env = MigrationEnvironment.from_cbom(REAL_CBOM, seed=7)
    env.reset()
    assert env.n_assets == 3
    assert [a["algorithm"] for a in env.assets] == ["RSA-2048", "ECDSA-P256", "ML-DSA-659"]
    # PQC asset is detected as ready; classical ones are not.
    assert env.assets[2]["pqc_ready"] is True
    assert env.assets[0]["pqc_ready"] is False


def test_from_cbom_host_affinity_edges_are_dag():
    env = MigrationEnvironment.from_cbom(REAL_CBOM, seed=7)
    for dep, target in env.dependencies:
        assert dep < target  # acyclic: dependency migrates before dependent
    x, _edge_index = state_to_tensors(env.reset())
    assert x.shape == (3, 6)


def test_from_cbom_explicit_dependencies():
    cbom = {
        "assets": [
            {"host": "h1", "algorithm": "RSA-4096", "key_size": 4096,
             "criticality": "low", "depends_on": []},
            {"host": "h1", "algorithm": "ECC-P256", "key_size": 256,
             "criticality": "high", "depends_on": [0]},
        ]
    }
    env = MigrationEnvironment.from_cbom(cbom)
    assert (0, 1) in env.dependencies


def test_train_agent_with_real_cbom_env_factory(tmp_path):
    from qtrust_planner.rl_agent import train_agent

    out = tmp_path / "agent_real.pt"

    def factory():
        return MigrationEnvironment.from_cbom(REAL_CBOM, seed=1)

    train_agent(n_episodes=2, save_path=str(out), env_factory=factory)
    assert out.exists()
