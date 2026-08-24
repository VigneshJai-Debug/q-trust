"""Regression tests for the benchmark scoring protocol.

Guards against reintroducing the sequence-correlation bug where
kendalltau was called on the two *order sequences* (node IDs per position)
instead of on per-node ranks — silently understating tau for imperfect
models (see CHANGELOG v2.1).
"""
import torch

from qtrust_planner.benchmark import score_order


class _Graph:
    """Minimal stand-in with just what score_order reads."""

    def __init__(self, y_order: torch.Tensor):
        self.y_order = y_order


def _true_graph(n: int) -> _Graph:
    return _Graph(torch.arange(n))


def test_perfect_prediction_scores_one():
    graph = _true_graph(6)
    scores = score_order([0, 1, 2, 3, 4, 5], graph)
    assert scores["exact_rank"] == 1.0
    assert scores["top5"] == 1.0
    assert abs(scores["kendall"] - 1.0) < 1e-9
    assert scores["node_rank"] == 1.0


def test_reversed_prediction_scores_minus_one():
    graph = _true_graph(6)
    scores = score_order([5, 4, 3, 2, 1, 0], graph)
    assert abs(scores["kendall"] + 1.0) < 1e-9


def test_single_swap_matches_scipy_rank_tau():
    """One adjacent transposition in a 10-item ranking → tau = 1 - 2/45."""
    from scipy.stats import kendalltau

    n = 10
    graph = _true_graph(n)
    pred = list(range(n))
    pred[3], pred[4] = pred[4], pred[3]

    scores = score_order(pred, graph)
    expected = kendalltau(list(range(n)), pred).statistic  # both already ranks
    assert abs(scores["kendall"] - expected) < 1e-9
    assert abs(scores["kendall"] - (1 - 2 / 45)) < 1e-9


def test_node_id_values_do_not_influence_tau():
    """Ranking agreement is invariant to which node IDs occupy which rank —
    the exact property the old sequence-correlation implementation broke."""
    # Truth order: nodes [3, 0, 1, 2]; prediction: the same order. The
    # highest-numbered node sits at rank 0, so index-correlating the two
    # sequences would score ~0 even though the ranking is perfect.
    graph = _Graph(torch.tensor([1, 2, 3, 0]))  # y_order[node] = its rank
    scores = score_order([3, 0, 1, 2], graph)
    assert abs(scores["kendall"] - 1.0) < 1e-9
