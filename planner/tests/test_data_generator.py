"""Tests for real-CBOM to GNN graph conversion."""
import sys
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qtrust_planner.data_generator import (  # noqa: E402
    cbom_to_dependency_graph,
    generate_migration_graph,
)
from qtrust_planner.model import encode_algorithm_type as encode_v2  # noqa: E402
from qtrust_planner.model_v3 import encode_algorithm_type as encode_v3  # noqa: E402


REAL_CBOM = {
    "schema_version": "qtrust.cbom.v1",
    "target": "example.edu",
    "assets": [
        {"host": "example.edu", "algorithm": "RSA-2048", "key_size": 2048,
         "criticality": "critical", "expired": False,
         "not_after": "2027-01-01T00:00:00+00:00"},
        {"host": "mail.example.edu", "algorithm": "ECDSA-P256", "key_size": 256,
         "criticality": "high"},
        {"host": "vpn.example.edu", "algorithm": "ML-DSA-65", "key_size": 65,
         "criticality": "medium"},
        {"host": "vpn.example.edu", "algorithm": "ML-KEM-768", "key_size": 768,
         "criticality": "low"},
    ],
}


def test_x509_signature_names_encode_to_underlying_key_type():
    """X.509 OID display names ('sha256WithRSAEncryption') must map to the
    underlying key type (RSA), not the leading hash prefix (SHA).

    Regression: prefix-matching 'sha256WithRSAEncryption' hit 'SHA' (type 7),
    silently poisoning real-CBOM features and driving real-CBOM Kendall tau
    negative. See CHANGELOG real-data campaign.
    """
    cases = {
        "sha256WithRSAEncryption": "RSA",
        "sha384WithRSAEncryption": "RSA",
        "sha512WithRSAEncryption": "RSA",
        "rsaEncryption": "RSA",
        "ecdsa-with-SHA256": "ECDSA",
        "ecdsa-with-SHA384": "ECDSA",
        "Ed25519": "EdDSA",
        "ed25519": "EdDSA",
        "id-ecPublicKey": "ECC",
        "ML-KEM-768": "ML-KEM",
        "ML-DSA-65": "ML-DSA",
        "SLH-DSA-128s": "SLH-DSA",
    }
    for name, family in cases.items():
        assert encode_v2(name) == encode_v2(family), f"v2: {name} -> {encode_v2(name)}"
        assert encode_v3(name) == encode_v3(family), f"v3: {name} -> {encode_v3(name)}"
    # sanity: RSA and ECDSA must not be confused with each other or with SHA
    assert encode_v3("sha256WithRSAEncryption") == encode_v3("RSA")
    assert encode_v3("sha256WithRSAEncryption") != encode_v3("SHA")
    assert encode_v3("ecdsa-with-SHA384") == encode_v3("ECDSA")


def test_cbom_to_dependency_graph_schema_matches_synthetic():
    real = cbom_to_dependency_graph(REAL_CBOM, seed=0)
    synthetic = generate_migration_graph(n_assets=4, seed=0)
    for attr in ("x", "edge_index", "y_order", "y_risk", "y_priority"):
        assert hasattr(real, attr)
    assert real.x.shape == (4, 6)
    assert real.x.shape[1] == synthetic.x.shape[1]
    assert real.y_order.shape == (4,)
    assert sorted(real.y_order.tolist()) == [0, 1, 2, 3]
    assert float(real.y_priority.min()) >= 0.0
    assert float(real.y_priority.max()) <= 1.0


def test_cbom_features_reflect_real_asset_values():
    data = cbom_to_dependency_graph(REAL_CBOM, seed=1)
    # PQC assets flagged vendor-ready in feature column 2
    assert data.x[2, 2].item() == 1.0
    assert data.x[3, 2].item() == 1.0
    assert data.x[0, 2].item() == 0.0
    # key size normalization: RSA-2048 -> 2048/4096 = 0.5
    assert pytest.approx(data.x[0, 1].item(), abs=1e-6) == 0.5
    assert len(data.asset_records) == 4


def test_cbom_host_affinity_edges_acyclic():
    data = cbom_to_dependency_graph(REAL_CBOM, seed=2)
    src, dst = data.edge_index[0], data.edge_index[1]
    for s, d in zip(src.tolist(), dst.tolist()):
        assert s < d  # forward-only edges keep the graph acyclic


def test_cbom_explicit_depends_on_become_edges():
    cbom = {
        "assets": [
            {"host": "h1", "algorithm": "RSA-4096", "key_size": 4096,
             "criticality": "low", "depends_on": []},
            {"host": "h1", "algorithm": "ECC-P256", "key_size": 256,
             "criticality": "high", "depends_on": [0]},
        ]
    }
    data = cbom_to_dependency_graph(cbom)
    assert data.edge_index.tolist() == [[0], [1]]


def test_cbom_expiry_drives_deadline_feature():
    soon = {
        "assets": [
            {"host": "h", "algorithm": "RSA-2048", "key_size": 2048,
             "criticality": "medium", "not_after": "2026-09-01T00:00:00+00:00"},
            {"host": "h", "algorithm": "RSA-4096", "key_size": 4096,
             "criticality": "medium"},
        ]
    }
    data = cbom_to_dependency_graph(soon)
    days = data.x[:, 4] * 730.0
    assert float(days.max()) < 180.0  # min expiry clamps into pressure window


def test_empty_cbom_raises():
    with pytest.raises(ValueError):
        cbom_to_dependency_graph({"assets": []})
