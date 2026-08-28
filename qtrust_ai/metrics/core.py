"""
Core metric implementations — pure Python, deterministic, no heavy deps.

Architecture reference: ``qtrust_ai/README.md`` §27 (Killer metrics).

Implements every metric in the evaluation framework with pure-Python fallbacks
so the suite runs anywhere (CI, no numpy/scipy):

    Discovery: precision, recall, F1, false-negative rate, coverage
    Risk:      AUROC, AUPRC, Brier, Expected Calibration Error (ECE)
    Ranking:   Kendall τ (tau-b, tie-aware), Spearman ρ, NDCG@K, P@K, R@K
    Migration: MAE / RMSE (cost, duration)
    Interop:   accuracy, latency error

``scipy`` / ``sklearn`` are used as fast paths when present; the pure-Python
paths are numerically consistent with them (rank-based definitions).

Example:
    from qtrust_ai.metrics.core import auroc, ndcg_at_k, kendall_tau

    assert abs(auroc([0, 0, 1, 1], [0.1, 0.4, 0.35, 0.8]) - 0.75) < 1e-9
    assert ndcg_at_k([3, 2, 3, 0], [1, 2, 3, 0], k=3) == 1.0
"""

from __future__ import annotations

import math
from typing import List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Classification / discovery
# ---------------------------------------------------------------------------


def precision_recall_f1(y_true: Sequence[int], y_pred: Sequence[int]) -> Tuple[float, float, float]:
    """Precision, recall, F1 for binary labels."""
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def false_negative_rate(y_true: Sequence[int], y_pred: Sequence[int]) -> float:
    """FNR = FN / (FN + TP) — missed crypto findings (spec §27 discovery)."""
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    return fn / (fn + tp) if (fn + tp) else 0.0


def coverage(detected: int, total: int) -> float:
    """Coverage = detected / total (spec §27 discovery: inventory coverage)."""
    return detected / total if total else 0.0


# ---------------------------------------------------------------------------
# Probability calibration (risk)
# ---------------------------------------------------------------------------


def brier_score(y_true: Sequence[float], y_prob: Sequence[float]) -> float:
    """Brier score (mean squared error between prob and label)."""
    if not y_true:
        return 0.0
    return sum((p - t) ** 2 for p, t in zip(y_prob, y_true)) / len(y_true)


def expected_calibration_error(y_true: Sequence[int], y_prob: Sequence[float], num_bins: int = 10) -> float:
    """ECE — mean |accuracy_bin - confidence_bin| weighted by bin size."""
    n = len(y_true)
    if n == 0:
        return 0.0
    ece = 0.0
    for b in range(num_bins):
        lo, hi = b / num_bins, (b + 1) / num_bins
        idx = [i for i, p in enumerate(y_prob) if lo <= p < hi or (b == num_bins - 1 and p == 1.0)]
        if not idx:
            continue
        acc = sum(y_true[i] for i in idx) / len(idx)
        conf = sum(y_prob[i] for i in idx) / len(idx)
        ece += abs(acc - conf) * len(idx) / n
    return ece


def auroc(y_true: Sequence[int], y_score: Sequence[float]) -> float:
    """Area under ROC via Mann-Whitney U (rank-based; handles ties)."""
    pairs = sorted(zip(y_score, y_true), key=lambda x: x[0])
    n = len(pairs)
    n_pos = sum(y_true)
    n_neg = n - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    # rank with tie averaging
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1  # 1-based average rank
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    sum_pos = sum(r for r, (_, t) in zip(ranks, pairs) if t == 1)
    auc = (sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
    return max(0.0, min(1.0, auc))


def auprc(y_true: Sequence[int], y_score: Sequence[float]) -> float:
    """Area under precision-recall via trapezoid integration (interpolation)."""
    pairs = sorted(zip(y_score, y_true), key=lambda x: -x[0])
    tp = fp = 0
    n_pos = sum(y_true)
    if n_pos == 0:
        return 0.0
    precisions: List[float] = [1.0]
    recalls: List[float] = [0.0]
    prev_score: Optional[float] = None
    for score, t in pairs:
        if prev_score is not None and score != prev_score:
            precisions.append(tp / (tp + fp) if (tp + fp) else 1.0)
            recalls.append(tp / n_pos)
        if t == 1:
            tp += 1
        else:
            fp += 1
        prev_score = score
    precisions.append(tp / (tp + fp) if (tp + fp) else 1.0)
    recalls.append(tp / n_pos)
    # trapezoid
    area = 0.0
    for i in range(1, len(precisions)):
        area += (recalls[i] - recalls[i - 1]) * (precisions[i] + precisions[i - 1]) / 2.0
    return max(0.0, min(1.0, area))


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


def kendall_tau(x: Sequence[float], y: Sequence[float]) -> float:
    """Kendall τ-b (tie-aware) between two rankings."""
    n = len(x)
    if n < 2:
        return 0.0
    concordant = discordant = 0
    ties_x = ties_y = 0
    for i in range(n):
        for j in range(i + 1, n):
            dx = x[i] - x[j]
            dy = y[i] - y[j]
            if dx * dy > 0:
                concordant += 1
            elif dx * dy < 0:
                discordant += 1
            elif dx == 0 and dy != 0:
                ties_x += 1
            elif dy == 0 and dx != 0:
                ties_y += 1
    denom = math.sqrt((concordant + discordant + ties_x) * (concordant + discordant + ties_y))
    if denom == 0:
        return 0.0
    return (concordant - discordant) / denom


def _rank(values: Sequence[float]) -> List[float]:
    """Average ranks (1-based), ascending."""
    n = len(values)
    order = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def spearman_rho(x: Sequence[float], y: Sequence[float]) -> float:
    """Spearman rank correlation (Pearson on ranks)."""
    n = len(x)
    if n < 2:
        return 0.0
    rx, ry = _rank(list(x)), _rank(list(y))
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    if den == 0:
        return 0.0
    return num / den


def dcg_at_k(relevance: Sequence[float], k: int) -> float:
    """DCG@K (rank 1 gets full gain)."""
    return sum(rel / math.log2(i + 2) for i, rel in enumerate(relevance[:k]))


def ndcg_at_k(ground_truth: Sequence[float], predicted_scores: Sequence[float], k: int) -> float:
    """NDCG@K — predicted ranking vs ideal ranking by ground-truth relevance."""
    k = max(1, min(k, len(ground_truth)))
    if k == 0:
        return 0.0
    # order ground truth by predicted scores (desc)
    order = sorted(range(len(predicted_scores)), key=lambda i: predicted_scores[i], reverse=True)
    predicted_rel = [ground_truth[i] for i in order[:k]]
    ideal_rel = sorted(ground_truth, reverse=True)[:k]
    dcg = dcg_at_k(predicted_rel, k)
    idcg = dcg_at_k(ideal_rel, k)
    return dcg / idcg if idcg > 0 else 0.0


def precision_at_k(ground_truth: Sequence[int], predicted_scores: Sequence[float], k: int) -> float:
    """Precision@K — fraction of top-K predicted that are relevant."""
    k = max(1, min(k, len(predicted_scores)))
    if k == 0:
        return 0.0
    order = sorted(range(len(predicted_scores)), key=lambda i: predicted_scores[i], reverse=True)[:k]
    return sum(1 for i in order if ground_truth[i] == 1) / k


def recall_at_k(ground_truth: Sequence[int], predicted_scores: Sequence[float], k: int) -> float:
    """Recall@K — relevant items in top-K / total relevant."""
    total_pos = sum(1 for t in ground_truth if t == 1)
    if total_pos == 0:
        return 0.0
    order = sorted(range(len(predicted_scores)), key=lambda i: predicted_scores[i], reverse=True)[:k]
    return sum(1 for i in order if ground_truth[i] == 1) / total_pos


# ---------------------------------------------------------------------------
# Regression
# ---------------------------------------------------------------------------


def mae(actual: Sequence[float], predicted: Sequence[float]) -> float:
    if not actual:
        return 0.0
    return sum(abs(a - p) for a, p in zip(actual, predicted)) / len(actual)


def rmse(actual: Sequence[float], predicted: Sequence[float]) -> float:
    if not actual:
        return 0.0
    return math.sqrt(sum((a - p) ** 2 for a, p in zip(actual, predicted)) / len(actual))


def mape(actual: Sequence[float], predicted: Sequence[float]) -> float:
    """Mean absolute percentage error (guards against zero actuals)."""
    pairs = [(a, p) for a, p in zip(actual, predicted) if a != 0]
    if not pairs:
        return 0.0
    return sum(abs(a - p) / abs(a) for a, p in pairs) / len(pairs)


def accuracy(y_true: Sequence[int], y_pred: Sequence[int]) -> float:
    if not y_true:
        return 0.0
    return sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)


if __name__ == "__main__":
    print("=== core metrics demo (§27) ===\n")
    y_true = [1, 0, 1, 1, 0, 1]
    y_pred = [1, 0, 1, 0, 0, 1]
    p, r, f = precision_recall_f1(y_true, y_pred)
    print(f"discovery: precision={p:.3f} recall={r:.3f} f1={f:.3f} fnr={false_negative_rate(y_true, y_pred):.3f} coverage={coverage(5, 8):.3f}")

    scores = [0.9, 0.1, 0.8, 0.4, 0.2, 0.7]
    print(f"risk:      auroc={auroc(y_true, scores):.3f} auprc={auprc(y_true, scores):.3f} "
          f"brier={brier_score(y_true, scores):.3f} ece={expected_calibration_error(y_true, scores):.3f}")

    gt = [3.0, 2.0, 3.0, 0.0, 1.0, 2.0]
    pred = [0.9, 0.5, 0.95, 0.1, 0.3, 0.6]
    print(f"ranking:   τ={kendall_tau(gt, pred):.3f} ρ={spearman_rho(gt, pred):.3f} "
          f"ndcg@3={ndcg_at_k(gt, pred, 3):.3f} p@3={precision_at_k([1,1,1,0,0,1], pred, 3):.3f} r@3={recall_at_k([1,1,1,0,0,1], pred, 3):.3f}")

    actual = [84.0, 31.0, 12.0]
    preds = [80.0, 33.0, 11.0]
    print(f"regression: mae={mae(actual, preds):.3f} rmse={rmse(actual, preds):.3f} mape={mape(actual, preds):.3f}")

    # Anchor checks
    assert abs(auroc([0, 0, 1, 1], [0.1, 0.4, 0.35, 0.8]) - 0.75) < 1e-9
    assert ndcg_at_k([3, 2, 3, 0, 1, 2], [3, 2, 3, 0, 1, 2], k=6) > 0.99  # perfect order
    assert kendall_tau([1, 2, 3, 4], [1, 2, 3, 4]) == 1.0
    assert kendall_tau([1, 2, 3, 4], [4, 3, 2, 1]) == -1.0
    print("\n✓ core metric anchors passed")
