"""Smoke tests for the RL migration agent (CPU-safe)."""
import sys
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qtrust_planner.rl_agent import (  # noqa: E402
    MigrationAgent,
    MigrationEnvironment,
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
