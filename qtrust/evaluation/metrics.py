"""
Metrics — §32, §35 (Killer metrics).

Discovery: P/R/F1/AUROC/AUPRC/FN/FP + Critical Recall
Ranking: Kendall τ, Spearman ρ, NDCG@K, P@K, Recall@K, Critical Recall
Migration: MAE/RMSE/MAPE/R²
Failure: AUROC/AUPRC/Brier/ECE/Recall@critical
Uncertainty: ECE/coverage/width/selective risk
Cost of being wrong: Expected Loss = FP×FP_cost + FN×FN_cost (§33)

Tuned for: minimize critical missed vulns (Recall@Critical ≥97%, §34-35).
"""
from __future__ import annotations

import math
from typing import Dict, List

import numpy as np


def precision_recall_f1(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return {"precision": prec, "recall": rec, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def critical_recall(y_true: List[int], y_pred: List[int], is_critical: List[bool]) -> float:
    fn_crit = sum(1 for t, p, c in zip(y_true, y_pred, is_critical) if t == 1 and p == 0 and c)
    total_crit = sum(1 for t, c in zip(y_true, is_critical) if t == 1 and c)
    return 1 - fn_crit / total_crit if total_crit else 1.0


def kendall_tau(pred_scores: List[float], true_ranks: List[int]) -> float:
    n = len(pred_scores)
    if n < 2:
        return 1.0
    # Higher score = earlier rank
    pred_ranks = np.argsort(np.argsort([-s for s in pred_scores]))
    concordant = discordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            dp = pred_ranks[i] - pred_ranks[j]
            dt = true_ranks[i] - true_ranks[j]
            if dp * dt > 0:
                concordant += 1
            elif dp * dt < 0:
                discordant += 1
    total = n * (n - 1) / 2
    return (concordant - discordant) / total if total else 0


def ndcg_at_k(pred_scores: List[float], true_relevance: List[float], k: int = 10) -> float:
    order = np.argsort([-s for s in pred_scores])[:k]
    dcg = sum((2 ** true_relevance[i] - 1) / math.log2(idx + 2) for idx, i in enumerate(order))
    ideal = np.argsort([-r for r in true_relevance])[:k]
    idcg = sum((2 ** true_relevance[i] - 1) / math.log2(idx + 2) for idx, i in enumerate(ideal))
    return dcg / idcg if idcg else 0


def expected_loss(fp: int, fn: int, fp_cost: float = 1.0, fn_cost: float = 10.0) -> float:
    # FN (missed critical vuln) 10× more expensive (§33)
    return fp * fp_cost + fn * fn_cost


def ece(probs: List[float], labels: List[int], n_bins: int = 10) -> float:
    bins = [[] for _ in range(n_bins)]
    for p, y in zip(probs, labels):
        b = min(n_bins - 1, int(p * n_bins))
        bins[b].append((p, y))
    total = len(labels)
    err = 0.0
    for b in bins:
        if not b:
            continue
        avg_conf = sum(p for p, _ in b) / len(b)
        avg_acc = sum(y for _, y in b) / len(b)
        err += abs(avg_conf - avg_acc) * len(b) / total
    return err


def brier_score(probs: List[float], labels: List[int]) -> float:
    return sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(labels) if labels else 0
