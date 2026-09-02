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


def test_per_graph_listMLE_vectorized_matches_reference():
    """The vectorized per-graph ListMLE must match the per-graph loop exactly.

    Regression test for the P0-1 vectorization: the segmented suffix-logsumexp
    trick is only trustworthy if it reproduces the reference loop to fp noise,
    including size-1 graphs and mixed batch shapes.
    """
    from qtrust_planner.train_gpu import per_graph_listMLE_loss

    torch.manual_seed(7)
    max_err = 0.0
    for _ in range(50):
        n_graphs = int(torch.randint(1, 10, (1,)).item())
        sizes = torch.randint(1, 15, (n_graphs,))
        n = int(sizes.sum().item())
        batch_idx = torch.repeat_interleave(torch.arange(n_graphs), sizes)
        order_logits = torch.randn(n)
        y_order = torch.cat([torch.randperm(int(s)) for s in sizes])

        # Reference: per-graph loop (the pre-vectorization implementation).
        total = torch.zeros(())
        for gid in range(n_graphs):
            mask = batch_idx == gid
            total = total + listMLE_loss(order_logits[mask], y_order[mask])
        reference = total / n_graphs

        vec = per_graph_listMLE_loss(order_logits.clone(), y_order.clone(), batch_idx.clone())
        max_err = max(max_err, (reference - vec).abs().item())
        assert torch.isfinite(vec), "vectorized loss must be finite"
        assert vec.item() >= -1e-6, "ListMLE loss must be non-negative"

    assert max_err < 1e-4, f"vectorized loss drifted from reference: {max_err:.2e}"


def test_per_graph_listMLE_no_nan_on_edge_shapes():
    """Regression: catastrophic cancellation in the fp32 segmented suffix sums
    produced log(negative) => NaN for some batches (fixed by fp64 cumsum +
    positive clamp). Reproduce the shape regime that used to fail and assert
    finite, non-negative losses for many random batches.
    """
    from qtrust_planner.train_gpu import per_graph_listMLE_loss

    torch.manual_seed(11)
    for trial in range(80):
        n_graphs = int(torch.randint(4, 20, (1,)).item())
        sizes = torch.randint(2, 25, (n_graphs,))
        n = int(sizes.sum().item())
        batch_idx = torch.repeat_interleave(torch.arange(n_graphs), sizes)
        order_logits = torch.randn(n)
        y_order = torch.cat([torch.randperm(int(s)) for s in sizes])
        loss = per_graph_listMLE_loss(order_logits, y_order, batch_idx)
        assert torch.isfinite(loss), f"trial {trial}: loss not finite: {loss.item()}"
        assert loss.item() >= -1e-6, f"trial {trial}: negative loss {loss.item()}"


def test_train_gpu_cpu_fallback_tiny():
    from qtrust_planner.train_gpu import train_gpu

    out = train_gpu(n_graphs=8, epochs=1, batch_size=2,
                    model_path=str(Path(__file__).parent / "_smoke_model.pt"),
                    device_name="cpu" if not torch.cuda.is_available() else None)
    assert Path(out).exists()
    Path(out).unlink(missing_ok=True)


def test_train_gpu_deterministic_same_seed_same_weights():
    """Regression: with determinism enabled, two runs with the same seed
    must produce bit-identical weights (flips in the real-CBOM LOO folds were
    traced to non-deterministic BF16/cuBLAS kernels; fixed in train_gpu.py)."""
    from qtrust_planner.train_gpu import train_gpu

    kwargs = dict(n_graphs=8, epochs=1, batch_size=2, seed=42,
                  model_path=str(Path(__file__).parent / "_det_1.pt"),
                  device_name="cpu" if not torch.cuda.is_available() else None)
    train_gpu(**kwargs)
    train_gpu(**{**kwargs, "model_path": str(Path(__file__).parent / "_det_2.pt")})

    import torch as _torch
    a = _torch.load(Path(__file__).parent / "_det_1.pt", map_location="cpu", weights_only=True)
    b = _torch.load(Path(__file__).parent / "_det_2.pt", map_location="cpu", weights_only=True)
    try:
        sd_a = a["state_dict"]
        sd_b = b["state_dict"]
    except (KeyError, TypeError):
        sd_a, sd_b = a, b
    n_diff = 0
    for k in sd_a:
        try:
            n_diff += int((sd_a[k] != sd_b[k]).sum())
        except RuntimeError:  # non-tensor metadata race is not a weight diff
            continue
    for _p in (Path(__file__).parent / "_det_1.pt", Path(__file__).parent / "_det_2.pt"):
        _p.unlink(missing_ok=True)
    assert n_diff == 0, f"same seed produced {n_diff} differing params"


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
