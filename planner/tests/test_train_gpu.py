"""Smoke tests for GPU GNN training (model_v3 + loss + metrics).

Runs on CPU; GPU is exercised separately via Makefile.gpu targets.
"""
import sys
from pathlib import Path

import pytest

from torch_geometric.data import Data

torch = pytest.importorskip("torch")
pyg = pytest.importorskip("torch_geometric")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qtrust_planner.model_v3 import MigrationGNNv3, build_node_features_v3  # noqa: E402
from qtrust_planner.train_gpu import compute_metrics, listMLE_loss  # noqa: E402


def test_model_v3_construction_and_forward():
    model = MigrationGNNv3(
        input_features=6,
        hidden_dim=32,
        embedding_dim=16,
        heads=4,
        dropout=0.0,
    )
    n = sum(p.numel() for p in model.parameters())
    assert n > 0

    x = torch.randn(20, 6)
    edge_index = torch.randint(0, 20, (2, 40))
    data = Data(x=x, edge_index=edge_index)
    order_logits, risk_logits = model(data)
    assert order_logits.shape == (20,)
    assert risk_logits.shape == (20,)


def test_listMLE_loss_gradient_flow():
    torch.manual_seed(0)
    scores = torch.randn(20, requires_grad=True)
    y_order = torch.randperm(20).float()
    loss = listMLE_loss(scores, y_order)
    assert torch.isfinite(loss)
    loss.backward()
    assert scores.grad is not None
    assert torch.isfinite(scores.grad).all()


def test_listMLE_prefers_correct_ranking():
    torch.manual_seed(1)
    good_scores = -torch.arange(20).float()
    bad_scores = torch.randn(20)
    y_order = torch.arange(20).float()
    assert listMLE_loss(good_scores, y_order) < listMLE_loss(bad_scores, y_order)


def test_compute_metrics_bounds():
    torch.manual_seed(2)
    pred = torch.randn(30)
    truth = torch.randperm(30)
    m = compute_metrics(pred, truth)
    assert -1.0 <= m["kendall"] <= 1.0
    assert 0.0 <= m["top5"] <= 1.0
    assert 0.0 <= m["top10"] <= 1.0


def test_kendall_perfect_and_reversed():
    truth = torch.arange(12).float()
    perfect_pred = -truth.clone()
    reversed_pred = truth.clone()
    assert compute_metrics(perfect_pred, truth)["kendall"] == pytest.approx(1.0)
    assert compute_metrics(reversed_pred, truth)["kendall"] == pytest.approx(-1.0)


def test_build_node_features_v3_shape():
    feats = build_node_features_v3(algorithm_type=0, key_size=8192, vendor_pqc_ready=True,
                                   criticality=5, days_to_deadline=99999, required_rate=2.0)
    assert feats.shape == (6,)
    assert torch.isfinite(feats).all()
    assert feats.max() <= 1.0


def test_train_gpu_cpu_fallback_tiny():
    from qtrust_planner.train_gpu import train_gpu

    out = train_gpu(n_graphs=8, epochs=1, batch_size=2,
                    model_path=str(Path(__file__).parent / "_smoke_model.pt"),
                    device_name="cpu" if not torch.cuda.is_available() else None)
    assert Path(out).exists()
    Path(out).unlink(missing_ok=True)


def test_train_gpu_batch_too_small_raises():
    from qtrust_planner.train_gpu import train_gpu

    with pytest.raises(ValueError, match="batch size"):
        train_gpu(n_graphs=4, epochs=1, batch_size=8, device_name="cpu")


def test_generate_dataset_labels_match_v3_contract():
    from qtrust_planner.data_generator import generate_dataset

    ds = generate_dataset(n_graphs=2, min_assets=10, max_assets=10, seed=123)
    for data in ds:
        assert data.x.shape[1] == 6
        assert hasattr(data, "y_order") and hasattr(data, "y_risk")
        n = data.x.shape[0]
        assert sorted(data.y_order.tolist()) == list(range(n))
