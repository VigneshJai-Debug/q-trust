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

    def __init__(self, y_order: torch.Tensor, y_priority: torch.Tensor | None = None):
        self.y_order = y_order
        if y_priority is not None:
            self.y_priority = y_priority


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


def test_tie_aware_tau_b_does_not_penalize_identical_assets():
    """Real inventories contain genuinely identical assets (e.g. eight
    RSA-2048 certs with the same key size and expiry). Dense ranks force an
    arbitrary order among them, so τ-a collapses to noise and every model
    scores negative. τ-b against tied priorities must reward getting the
    *distinguishable groups* right and ignore within-group order.

    Setup: 4 assets. True priority: assets 0-1 tied high, assets 2-3 tied
    low (y_priority higher = migrate first). A model that ranks one high
    asset first then the other high asset (order within the tied group
    swapped) must still score near-perfectly.
    """
    # y_order here is unused when y_priority is present; it mirrors the
    # priority (arbitrary dense ranks inside tied groups).
    graph = _Graph(
        y_order=torch.tensor([0, 1, 2, 3]),
        y_priority=torch.tensor([1.0, 1.0, 0.0, 0.0]),
    )
    # Perfect ranking of the distinguishable groups (ties broken one way).
    perfect = score_order([0, 1, 2, 3], graph)["kendall"]
    # Predicted order: swap the two tied-high assets — must score the SAME
    # as the perfect ranking (τ-b treats within-tie order as unpenalized).
    swapped = score_order([1, 0, 3, 2], graph)["kendall"]
    assert abs(swapped - perfect) < 1e-9
    # Both hit the τ-b tie ceiling for this configuration (>0.8, <1).
    assert perfect > 0.8
    assert perfect < 1.0

    # A model that ranks the low group first is anti-correlated.
    scores_bad = score_order([3, 2, 1, 0], graph)["kendall"]
    assert scores_bad < -0.5


def test_all_identical_priorities_do_not_return_nan():
    """Real inventories contain CBOMs where EVERY asset is identical (e.g.
    eight RSA-2048 certs with the same key size and expiry). scipy's τ-b
    divides by the number of distinguishable pairs — zero here — and returns
    NaN, which would silently poison any mean/max/min aggregate. Since no
    pair's relative order can be wrong, the tie-aware score must be 1.0 for
    ANY ranking (regardless of which identical asset is listed first)."""
    import math

    n = 8
    graph = _Graph(
        y_order=torch.arange(n),
        y_priority=torch.full((n,), 0.5),  # all tied
    )
    for pred in ([0, 1, 2, 3, 4, 5, 6, 7], [7, 6, 5, 4, 3, 2, 1, 0]):
        kendall = score_order(pred, graph)["kendall"]
        assert not math.isnan(kendall), "τ-b must not be NaN for all-tied priorities"
        assert abs(kendall - 1.0) < 1e-9
    # Without y_priority (legacy graphs) the same must hold via the rank path.
    legacy = _Graph(y_order=torch.arange(n))
    assert not math.isnan(score_order(list(range(n)), legacy)["kendall"])


def test_tie_aware_tau_b_matches_tau_a_when_no_ties():
    """On synthetic graphs (all priorities distinct) τ-b must equal the
    classic τ-a — so historical synthetic numbers remain comparable."""
    n = 6
    priorities = torch.tensor([6.0, 5.0, 4.0, 3.0, 2.0, 1.0])  # all distinct
    graph = _Graph(y_order=torch.arange(n), y_priority=priorities)
    pred = [0, 1, 2, 3, 4, 5]
    from scipy.stats import kendalltau

    scores = score_order(pred, graph)
    expected = kendalltau(list(range(n)), pred).statistic
    assert abs(scores["kendall"] - expected) < 1e-9
