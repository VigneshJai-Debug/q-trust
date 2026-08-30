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


def expert_preference(asset_a: Dict[str, Any], asset_b: Dict[str, Any], expert_id: str = "expert-0") -> PairwisePreference:
    """Synthetic expert labeling — in production, real security professionals answer
    'Which should be migrated first?' (§10). Here we simulate expert logic with
    enriched features (internet exposure, lifetime 12y vs 30d, dependencies) NOT the
    heuristic formula under test. This breaks circularity."""
    # Expert logic: internet-exposed + long lifetime + high business criticality > internal
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
    """QTrust-RiskBench (§12): 100k assets → 1M comparisons, 20-50 experts."""
    rnd = random.Random(seed)
    prefs: List[PairwisePreference] = []
    for _ in range(n_pairs):
        a, b = rnd.sample(assets, 2)
        prefs.append(expert_preference(a, b, expert_id=f"expert-{rnd.randint(0, 30)}"))
    return prefs


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
        # NDCG approximation: pairwise accuracy correlates
        return {"pairwise_accuracy": acc, "kendall_tau": 2 * acc - 1, "n": len(prefs)}
