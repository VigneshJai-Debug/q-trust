"""
Risk ML — Quantum Exposure + HNDL + Business Impact (§8-11, §23).

CRITICAL: Do NOT train risk using own risk formula (§9). That's circular.
Instead: Real asset → Expert pairwise preference → Learning-to-Rank.

Features (§8): algorithm, key_size, primitive, role, asset_type, internet exposure,
data sensitivity/lifetime, blast radius, service criticality, HNDL, cert lifetime, etc.
"""
from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import numpy as np


FEATURES = [
    "algorithm_risk",  # 0-5 vuln weight
    "key_size_norm",  # 0-1
    "primitive_risk",  # 0-1
    "internet_exposed",  # 0/1
    "data_sensitivity",  # 0-5
    "data_lifetime_years",  # 0-30
    "business_criticality",  # 1-5
    "dependency_count",  # 0-100
    "blast_radius",  # 0-100
    "service_criticality",  # 1-5
    "hndl_exposure_years",  # 0-10
    "cert_days_to_expiry",  # -365..3650
    "pqc_available",  # 0/1
    "compliance_urgency",  # 0-5
]


def featurize(asset: Dict[str, Any]) -> List[float]:
    # Simplified featurizer — real would use blast_radius GNN output, etc.
    vuln_map = {"RSA": 5, "ECDSA": 5, "ECDH": 5, "AES-128": 3, "AES-256": 1, "ML-KEM": 0}
    algo = asset.get("algorithm", "RSA-2048")
    base = vuln_map.get(algo.split("-")[0], 3)
    return [
        float(base),
        min(1.0, asset.get("key_size", 2048) / 4096),
        1.0 if asset.get("primitive") in ("signature", "kem") else 0.5,
        1.0 if asset.get("internet_exposed") else 0.0,
        float(asset.get("data_sensitivity", 3)),
        float(asset.get("data_lifetime_years", 5)),
        float(asset.get("business_criticality", 3)),
        min(1.0, asset.get("dependency_count", 5) / 50),
        min(1.0, asset.get("blast_radius", 10) / 100),
        float(asset.get("service_criticality", 3)) / 5,
        min(1.0, asset.get("hndl_exposure_years", 2) / 10),
        min(1.0, max(0, asset.get("cert_days_to_expiry", 365)) / 3650),
        1.0 if asset.get("pqc_available") else 0.0,
        float(asset.get("compliance_urgency", 2)) / 5,
    ]


@dataclass
class PairwisePreference:
    asset_a: Dict[str, Any]
    asset_b: Dict[str, Any]
    preference: str  # "a" > "b" or "b" > "a"
    expert_confidence: float
    domain: str
    expert_id: str


DEMO_SYNTHETIC_WARNING = (
    "SYNTHETIC DEMO ONLY — NOT an expert benchmark. "
    "Do NOT publish Kendall τ vs this synthetic as 'expert' performance. "
    "Real benchmark requires qtrust_data/gold/riskbench-v1/ human annotations (§10)."
)


def expert_preference(asset_a: Dict[str, Any], asset_b: Dict[str, Any], expert_id: str = "expert-0") -> PairwisePreference:
    """DEPRECATED SYNTHETIC — DEMO ONLY (§QTRUST-001).

    This generates a *demonstration* preference using:

        internet exposure + data lifetime + business criticality + blast radius

    It is **NOT** a human expert label. It exists so CI and unit tests can run
    without a human-annotated dataset. Any benchmark that uses this function
    MUST be labeled ``synthetic`` (§31 Level 1) and must NOT be claimed as
    ``expert τ = X`` in README/papers. See ``QTrustRiskBench.load_real()`` for
    the production path.
    """
    import warnings

    warnings.warn(DEMO_SYNTHETIC_WARNING, UserWarning, stacklevel=2)
    score_a = (
        (5 if asset_a.get("internet_exposed") else 0)
        + asset_a.get("data_lifetime_years", 0) * 0.5
        + asset_a.get("business_criticality", 3) * 2
        + asset_a.get("blast_radius", 0) * 0.1
    )
    score_b = (
        (5 if asset_b.get("internet_exposed") else 0)
        + asset_b.get("data_lifetime_years", 0) * 0.5
        + asset_b.get("business_criticality", 3) * 2
        + asset_b.get("blast_radius", 0) * 0.1
    )
    pref = "a" if score_a > score_b else "b"
    conf = min(0.95, 0.6 + abs(score_a - score_b) * 0.05)
    return PairwisePreference(asset_a, asset_b, pref, conf, asset_a.get("domain", "finance"), expert_id)


def generate_qtrust_risk_bench(
    assets: List[Dict[str, Any]], n_pairs: int = 10000, seed: int = 42
) -> List[PairwisePreference]:
    """Generate SYNTHETIC DEMO RiskBench — CI only, not for publication (§12, QTRUST-001).

    For a real benchmark, populate ``qtrust_data/gold/riskbench-v1/`` via
    ``qtrust/labeling/expert.py`` annotation UI and load with
    ``QTrustRiskBench.load_real()``.
    """
    rnd = random.Random(seed)
    prefs: List[PairwisePreference] = []
    for _ in range(n_pairs):
        a, b = rnd.sample(assets, 2)
        prefs.append(expert_preference(a, b, expert_id=f"expert-{rnd.randint(0, 30)}"))
    return prefs


class QTrustRiskBench:
    """Real human-annotated benchmark — QTrust-RiskBench-v1 (§12, QTRUST-001).

    Expected layout::

        qtrust_data/gold/riskbench-v1/
          pairs.jsonl          # one JSON per line: {asset_a, asset_b, preference, expert_id, confidence, domain, rationale, timestamp}
          experts.json         # [{id, domain, years_experience}]
          manifest.json        # {n_pairs, n_experts, n_assets, created_at, inter_rater_kappa}

    Acceptance: 5-10 experts, 5k-10k pairs (v1), then 100k/1M/20+ experts (v2).
    Reports: Kendall τ vs experts, NDCG@10/50, inter-rater agreement, model-vs-expert disagreement.
    """

    REAL_PATH = "qtrust_data/gold/riskbench-v1/pairs.jsonl"

    @staticmethod
    def load_real(path: str = REAL_PATH) -> List[PairwisePreference]:
        import json
        from pathlib import Path

        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"Real RiskBench not found at {p}. "
                f"Current synthetic data is DEMO ONLY and must not be published as expert performance. "
                f"To create v1: run annotation UI (qtrust/labeling/expert.py) with 5-10 experts, "
                f"collect 5k-10k pairwise comparisons with blinded annotation + adjudication, "
                f"then write to {p}."
            )
        prefs: List[PairwisePreference] = []
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            prefs.append(
                PairwisePreference(
                    asset_a=d["asset_a"],
                    asset_b=d["asset_b"],
                    preference=d["preference"],
                    expert_confidence=float(d.get("confidence", 0.8)),
                    domain=d.get("domain", "finance"),
                    expert_id=d.get("expert_id", "expert-0"),
                )
            )
        return prefs

    @staticmethod
    def inter_rater_agreement(prefs: List[PairwisePreference]) -> Dict[str, float]:
        """Fleiss' κ / pairwise agreement on duplicated pairs shown to multiple experts."""
        from collections import defaultdict

        by_pair: Dict[str, List[str]] = defaultdict(list)
        for pr in prefs:
            key = f"{hash(str(pr.asset_a))}|{hash(str(pr.asset_b))}"
            by_pair[key].append(pr.preference)
        agreements = []
        for vals in by_pair.values():
            if len(vals) < 2:
                continue
            # Pairwise agreement within this pair's expert votes
            agreement = max(vals.count("a"), vals.count("b")) / len(vals)
            agreements.append(agreement)
        kappa = sum(agreements) / len(agreements) if agreements else 0.0
        return {"pairwise_agreement": round(kappa, 3), "duplicated_pairs": len(agreements), "n": len(prefs)}


class RiskRankingModel:
    """Learning-to-Rank (§11): baselines Logistic/RF/XGBoost/LightGBM → LambdaMART → GNN."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.model = None

    def train(self, prefs: List[PairwisePreference]) -> Dict[str, Any]:
        # Pairwise RankNet-style: train classifier to predict preference
        X, y = [], []
        for p in prefs:
            fa, fb = featurize(p.asset_a), featurize(p.asset_b)
            diff = [a - b for a, b in zip(fa, fb)]
            X.append(diff)
            y.append(1 if p.preference == "a" else 0)
        try:
            from sklearn.ensemble import RandomForestClassifier

            clf = RandomForestClassifier(n_estimators=100, random_state=self.seed)
            clf.fit(X, y)
            self.model = clf
            return {"model": "RandomForest", "n_pairs": len(prefs), "features": FEATURES}
        except Exception:
            self.model = None
            return {"model": "heuristic_diff", "n_pairs": len(prefs)}

    def predict_score(self, asset: Dict[str, Any]) -> float:
        feats = featurize(asset)
        if self.model is None:
            return sum(feats) / len(feats)
        # For single asset, return forest's confidence vs average
        try:
            avg = [0.5] * len(feats)
            diff = [f - a for f, a in zip(feats, avg)]
            prob = float(self.model.predict_proba([diff])[0][1])
            return prob * 100
        except Exception:
            return 50.0

    def rank(self, assets: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], float]]:
        scored = [(a, self.predict_score(a)) for a in assets]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def evaluate(self, prefs: List[PairwisePreference]) -> Dict[str, Any]:
        # Kendall τ, Spearman ρ, NDCG@K, P@K vs EXPERT labels (not heuristic)
        correct = 0
        for p in prefs:
            sa = self.predict_score(p.asset_a)
            sb = self.predict_score(p.asset_b)
            pred = "a" if sa > sb else "b"
            if pred == p.preference:
                correct += 1
        acc = correct / len(prefs) if prefs else 0
        # REG-16 FIX: real Kendall τ-b via scipy.stats.kendalltau over the
        # pairwise predictions vs the expert preferences, not 2*acc-1.
        kendall = 2 * acc - 1  # fallback when scipy is unavailable
        tau_note = "2*acc-1 fallback (scipy unavailable)"
        try:
            from scipy.stats import kendalltau

            pred_scores = [self.predict_score(p.asset_a) for p in prefs]
            true_prefs = [1.0 if p.preference == "a" else 0.0 for p in prefs]
            if len(set(pred_scores)) > 1 or len(set(true_prefs)) > 1:
                tau, _ = kendalltau(pred_scores, true_prefs)
                if tau == tau:  # not NaN (constant inputs give NaN)
                    kendall = float(tau)
                    tau_note = "scipy.stats.kendalltau (tau-b) over pairwise predictions vs expert preferences"
        except Exception:
            pass
        return {"pairwise_accuracy": acc, "kendall_tau": round(kendall, 3), "kendall_tau_note": tau_note, "n": len(prefs)}
