"""Fast smoke tests for the Q-Trust AI intelligence layer (qtrust_ai).

Covers the headline public APIs across all five phases (discovery, migration
intel, planning, enterprise, interface). Every test is CPU-friendly and fast;
models that need heavier fitting are exercised by scripts/train_qtrust_all.py
(which asserts the spec anchors in qtrust_ai/artifacts/training_report.json).

These tests exist because the layer shipped with zero coverage — the sklearn
regression below (LogisticRegression `multi_class` kwarg removed in sklearn
1.9) is the kind of bug that silently degraded a model with no test noticing.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from qtrust_ai.benchmark.dataset import BenchmarkConfig, QTrustBenchmark
from qtrust_ai.discovery.algorithm_classifier import AlgorithmPurposeClassifier
from qtrust_ai.discovery.code_detector import CryptoCodeDetector
from qtrust_ai.metrics.suite import QTrustMetricSuite
from qtrust_ai.migration.replacement_recommender import PQCRecommender
from qtrust_ai.monitoring.anomaly import CryptoAnomalyDetector, CryptoSnapshot
from qtrust_ai.monitoring.regression import CryptoRegressionDetector
from qtrust_ai.policy.engine import PolicyEngine
from qtrust_ai.risk.quantum_exposure import ExposureFactors, QuantumExposureModel
from qtrust_ai.twin.digital_twin import DigitalTwin

# ---------------------------------------------------------------------------
# Phase 1 — Discovery
# ---------------------------------------------------------------------------

def test_code_detector_finds_rsa_usage() -> None:
    detector = CryptoCodeDetector(seed=42)
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "service.py"), "w") as f:
            f.write(
                "import rsa\n"
                "key = rsa.generate_private_key(2048)\n"
                "sig = key.sign(b'payload')\n"
            )
        findings = detector.scan_repo(td)
    assert findings, "expected at least one crypto finding in the RSA snippet"
    assert any("RSA" in (f.algorithm or "").upper() for f in findings)


def test_purpose_classifier_disambiguates_dual_use() -> None:
    clf = AlgorithmPurposeClassifier(seed=42)
    clf.train()
    assert clf.predict("RSA", context="private_key.sign(data, padding=PSS)").purpose.value == "signature"
    assert clf.predict("RSA", context="public_key.encrypt(plaintext, padding=OAEP)").purpose.value == "encryption"
    assert clf.predict("ECDH", context="derive shared secret").purpose.value == "key-establishment"


def test_purpose_classifier_uses_sklearn_when_available() -> None:
    """Regression: sklearn >= 1.9 removed LogisticRegression(multi_class=...);
    the swallow-all except silently fell back to the deterministic scorer.
    When sklearn is importable the sklearn path must actually be used."""
    pytest.importorskip("sklearn")
    clf = AlgorithmPurposeClassifier(seed=42)
    res = clf.train()
    assert res["has_sklearn"] is True, "sklearn is installed but the TF-IDF/LogReg path failed"


def test_code_detector_fine_tune_is_deterministic() -> None:
    """Regression: the real transformer fine-tune used the UNSET global RNG
    for per-epoch shuffling (plus cuDNN autotune), so the same corpus + seed
    produced a different model — and a different held-out F1 — on every run
    (observed 0.812 vs 0.899 on the same 10K real-code corpus). Benchmark
    claims are only meaningful if a re-run reproduces the number."""
    pytest.importorskip("torch")
    pytest.importorskip("transformers")
    corpus = [
        {"code": "import hashlib; hashlib.sha256(b'x')", "language": "python", "label": "HASH", "is_crypto": True},
        {"code": "def add(a, b): return a + b", "language": "python", "label": "UNKNOWN", "is_crypto": False},
        {"code": "from Crypto.Cipher import AES; AES.new(k, AES.MODE_GCM)", "language": "python", "label": "AES", "is_crypto": True},
        {"code": "print('hello')", "language": "python", "label": "UNKNOWN", "is_crypto": False},
        {"code": "rsa.generate_private_key(2048)", "language": "python", "label": "RSA", "is_crypto": True},
        {"code": "x = [i for i in range(10)]", "language": "python", "label": "UNKNOWN", "is_crypto": False},
        {"code": "ecdh.ECDH().generate_keypair()", "language": "python", "label": "RSA/ECC", "is_crypto": True},
        {"code": "class Foo: pass", "language": "python", "label": "UNKNOWN", "is_crypto": False},
    ] * 4  # enough to matter for shuffling
    det1 = CryptoCodeDetector(seed=42)
    det2 = CryptoCodeDetector(seed=42)
    r1 = det1.fine_tune(corpus, epochs=1, device="cpu")
    r2 = det2.fine_tune(corpus, epochs=1, device="cpu")
    assert r1.get("status") == "trained", f"fine_tune failed: {r1}"
    assert r1["train_accuracy"] == r2["train_accuracy"], (
        f"fine_tune is non-deterministic for a fixed seed: "
        f"run1 acc={r1['train_accuracy']} run2 acc={r2['train_accuracy']} — "
        "the per-epoch shuffle and/or cuDNN must be seeded"
    )


# ---------------------------------------------------------------------------
# Phase 2 — Migration intel
# ---------------------------------------------------------------------------

def test_pqc_recommender_anchors() -> None:
    rec = PQCRecommender(seed=42)
    rec.train()
    assert rec.recommend("RSA-2048", purpose="signature").primary_pqc.startswith("ML-DSA")
    assert rec.recommend("RSA-2048", purpose="key-establishment").primary_pqc.startswith("ML-KEM")
    assert rec.recommend("AES-128", purpose="encryption").primary_pqc == "AES-256"


def test_quantum_exposure_ordering() -> None:
    model = QuantumExposureModel()
    legacy = model.predict(ExposureFactors(algorithm="RSA-2048", lifetime_years=10, attractiveness=4))
    pqc = model.predict(ExposureFactors(algorithm="ML-KEM-768", lifetime_years=10))
    # RSA-2048 long-lived must be strictly riskier than a PQC KEM.
    assert legacy.score > pqc.score
    assert pqc.level in ("NONE", "LOW")


# ---------------------------------------------------------------------------
# Phase 3/4 — Planning & enterprise
# ---------------------------------------------------------------------------

def test_anomaly_detector_flags_new_algorithm_and_rsa_spike() -> None:
    mon = CryptoAnomalyDetector(seed=42)
    mon.establish_baseline([CryptoSnapshot(algorithm_counts={"RSA-2048": 40, "AES-256": 30}, total_assets=70)])
    alerts = mon.detect(CryptoSnapshot(algorithm_counts={"RSA-2048": 65, "AES-256": 30, "DES": 2}, total_assets=97))
    types = {a.alert_type for a in alerts}
    assert "new_algorithm" in types
    assert "rsa_spike" in types


def test_regression_detector_blocks_mlkem_to_rsa() -> None:
    rd = CryptoRegressionDetector(seed=42)
    verdict = rd.check_ci_gate(
        {"assets": [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]},
        {"assets": [{"algorithm": "RSA-2048"}, {"algorithm": "ML-DSA-65"}]},
    )
    assert verdict.blocked is True
    assert verdict.severity == "CRITICAL"


def test_digital_twin_simulates_without_touching_prod() -> None:
    twin = DigitalTwin(seed=42)
    sim = twin.simulate("hybrid-migration", assets_to_migrate=20)
    assert sim.assets_simulated == 20
    assert sim.total_cost_usd > 0
    assert sim.total_downtime_hours >= 0


# ---------------------------------------------------------------------------
# Phase 5 — Interface
# ---------------------------------------------------------------------------

def test_benchmark_org_level_splits_have_no_leakage() -> None:
    bench = QTrustBenchmark(BenchmarkConfig(n_orgs=30, seed=42)).generate()
    splits = bench.splits()
    assert set(splits) == {"train", "val", "test", "enterprise_holdout", "adversarial_holdout"}
    assert not (set(splits["train"]["org_ids"]) & set(splits["test"]["org_ids"]))


def test_metric_suite_reports() -> None:
    report = QTrustMetricSuite().full_report(
        discovery=([1, 0, 1, 1], [1, 1, 0, 1]),
        risk=([1, 0, 1], [0.9, 0.1, 0.8]),
    )
    assert "discovery" in report
    assert "risk" in report
    assert report["discovery"]["precision"] >= 0


def test_policy_engine_parses_downtime_constraint() -> None:
    engine = PolicyEngine()
    cs = engine.parse("Payment API cannot be down > 5 minutes")
    assert cs.constraints, "expected at least one parsed constraint"
    assert cs.constraints[0].constraint_type == "downtime_limit"
    # Must map onto the constrained optimizer without raising.
    engine.apply_to_optimizer(cs)
