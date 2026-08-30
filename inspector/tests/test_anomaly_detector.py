"""Smoke tests for the CBOM anomaly detector (VAE)."""
import pytest

torch = pytest.importorskip("torch")

from qtrust_inspector.anomaly_detector import (  # noqa: E402
    CBOMAnomalyDetector,
    CBOMVariationalAutoencoder,
)


def test_vae_forward_shapes():
    model = CBOMVariationalAutoencoder(n_features=10, latent_dim=16)
    x = torch.randn(8, 10)
    recon, mu, logvar = model(x)
    assert recon.shape == (8, 10)
    assert mu.shape == (8, 16)
    assert logvar.shape == (8, 16)


def test_feature_extraction_shape():
    detector = CBOMAnomalyDetector()
    cbom = {
        "assets": [
            {"algorithm": "RSA-2048", "key_size": 2048, "criticality": "high",
             "expired": False, "vendor": "DigiCert", "self_signed": False,
             "days_until_expiry": 90, "location": "host1.com"},
            {"algorithm": "ML-KEM-768", "key_size": 768, "criticality": "medium",
             "expired": False, "vendor": None, "self_signed": False,
             "days_until_expiry": 30, "location": "host2.com"},
        ]
    }
    features = detector._extract_features(cbom)
    assert features.shape == (2, 10)
    assert torch.isfinite(features).all()


def test_feature_extraction_handles_null_fields_from_real_scans():
    """Live TLS scans can return findings with null algorithm / key_size
    (e.g. an endpoint that refused the handshake). The feature extractor must
    treat those as Unknown/0 instead of crashing on `.upper()` / division."""
    detector = CBOMAnomalyDetector()
    cbom = {
        "assets": [
            {"algorithm": None, "key_size": None, "criticality": None,
             "expired": False, "vendor": None, "self_signed": False,
             "days_until_expiry": None, "location": "uic.edu"},
            {"algorithm": "sha256WithRSAEncryption", "key_size": 2048,
             "criticality": "medium", "expired": False, "vendor": None,
             "self_signed": False, "days_until_expiry": 90, "location": "h2"},
        ]
    }
    features = detector._extract_features(cbom)
    assert features.shape == (2, 10)
    assert torch.isfinite(features).all()
    # Null-key asset is treated as Unknown algorithm type (13/13 = 1.0).
    assert features[0, 0] == 1.0


def test_score_requires_training():
    detector = CBOMAnomalyDetector()
    with pytest.raises(RuntimeError, match="not trained"):
        detector.score_cbom({"assets": [
            {"algorithm": "RSA-2048", "key_size": 2048, "criticality": "high",
             "expired": False, "vendor": None, "self_signed": False,
             "days_until_expiry": 90, "location": "h"},
        ]})


def test_train_and_detect_weak_key_anomaly(tmp_path):
    detector = CBOMAnomalyDetector()
    training = detector.generate_synthetic_training_data(n_cboms=30, n_assets_per_cbom=20)
    detector.train(training, epochs=8, save_path=str(tmp_path / "vae.pt"))

    normal_result = detector.score_cbom(training[5])
    assert 0.0 <= normal_result.anomaly_score <= 1.0
    assert isinstance(normal_result.is_anomalous, bool)

    weak_key_cbom = {
        "assets": [
            {"algorithm": "RSA-512", "key_size": 512, "criticality": "critical",
             "expired": True, "vendor": None, "self_signed": True,
             "days_until_expiry": 0, "location": f"h{i}"}
            for i in range(15)
        ]
    }
    bad_result = detector.score_cbom(weak_key_cbom)
    assert bad_result.anomaly_score >= normal_result.anomaly_score
    assert bad_result.is_anomalous
    assert len(bad_result.top_anomalous_assets) > 0
    assert len(bad_result.evidence_hash) == 66


def test_synthetic_training_data_shape():
    detector = CBOMAnomalyDetector()
    cboms = detector.generate_synthetic_training_data(n_cboms=4, n_assets_per_cbom=10, seed=7)
    assert len(cboms) == 4
    for c in cboms:
        assert 5 <= len(c["assets"]) <= 20
        assert "algorithm" in c["assets"][0]
