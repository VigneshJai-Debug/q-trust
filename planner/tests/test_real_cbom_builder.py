"""Regression tests for scripts/build_real_cboms.py.

Guards the audit fix that made the real-CBOM corpus reproducible and
host-disjoint:

- Previously the committed `planner/data/real_cboms/` was hand-packed and
  UNREPRODUCIBLE, and every scanned host appeared in TWO CBOMs — so any
  train/eval split over CBOMs silently leaked hosts (label leakage), and the
  flagship real-CBOM benchmark (τ-b 0.807) was effectively in-sample.
- The builder now emits a deterministic corpus where each host appears in
  exactly one CBOM, records provenance (scan timestamp / seed / builder),
  and normalizes real cert signature names to the actual key type
  (sha256WithRSAEncryption + ECPublicKey → ECDSA-P256, not RSA).
"""
import json
from pathlib import Path

import pytest

from qtrust_planner.benchmark import heuristic_order, score_order  # noqa: E402
from qtrust_planner.data_generator import cbom_to_dependency_graph  # noqa: E402

sys_path = None


@pytest.fixture(scope="module")
def corpus_dir(tmp_path_factory):
    """Build a small host-disjoint corpus from a synthetic scan file."""
    import sys

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "scripts"))
    from build_real_cboms import build_cboms

    scan_dir = tmp_path_factory.mktemp("scan")
    scan = scan_dir / "tls_scan.json"
    # 12 hosts across two industries; one EC-key cert mislabeled with an RSA
    # signature name (the exact real-world case found in the 2026-08 scan).
    scan.write_text(json.dumps({
        "scan_timestamp": "2026-08-29T12:00:00Z",
        "findings": [
            {"host": f"bank{i}.com", "port": 443, "algorithm": "sha256WithRSAEncryption",
             "key_type": "RSAPublicKey", "key_size": 2048, "criticality": "medium"}
            for i in range(6)
        ] + [
            {"host": f"uni{i}.edu", "port": 443, "algorithm": "sha256WithRSAEncryption",
             "key_type": "ECPublicKey", "key_size": 256, "criticality": "medium"}
            for i in range(6)
        ],
    }))
    cboms = build_cboms(scan, hosts_per_cbom=3, seed=7)
    return cboms, scan.name


def test_corpus_is_host_disjoint(corpus_dir):
    """Every host appears in exactly one CBOM — no cross-CBOM leakage."""
    cboms, _ = corpus_dir
    hosts = []
    for cbom in cboms:
        hosts.extend(a["host"] for a in cbom["assets"])
    assert len(hosts) == len(set(hosts)), "a host appears in two CBOMs"
    assert len(hosts) == 12


def test_corpus_covers_all_scanned_hosts(corpus_dir):
    cboms, _ = corpus_dir
    hosts = {a["host"] for c in cboms for a in c["assets"]}
    assert hosts == {f"bank{i}.com" for i in range(6)} | {f"uni{i}.edu" for i in range(6)}


def test_ec_key_with_rsa_signature_is_normalized(corpus_dir):
    """Real certs can carry an RSA *signature* name over an EC *key*
    (capitalone.com, facebook.com, fda.gov, ... in the live scan). The key
    type is authoritative: the corpus must featurize them as ECDSA, not RSA."""
    cboms, _ = corpus_dir
    ec = [a for c in cboms for a in c["assets"] if a["host"].endswith(".edu")]
    assert len(ec) == 6
    for a in ec:
        assert a["algorithm"].startswith("ECDSA"), a["algorithm"]
        assert "_sig_algorithm" in a, "original signature name must be kept as provenance"


def test_builder_is_idempotent(corpus_dir, tmp_path):
    """Rebuilding into a clean dir must produce identical files (same seed)."""
    import sys

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "scripts"))
    from build_real_cboms import build_cboms

    cboms, scan_name = corpus_dir
    scan = tmp_path / scan_name
    scan.write_text(json.dumps({
        "scan_timestamp": "2026-08-29T12:00:00Z",
        "findings": [
            {"host": f"bank{i}.com", "port": 443, "algorithm": "sha256WithRSAEncryption",
             "key_type": "RSAPublicKey", "key_size": 2048, "criticality": "medium"}
            for i in range(6)
        ] + [
            {"host": f"uni{i}.edu", "port": 443, "algorithm": "sha256WithRSAEncryption",
             "key_type": "ECPublicKey", "key_size": 256, "criticality": "medium"}
            for i in range(6)
        ],
    }))
    again = build_cboms(scan, hosts_per_cbom=3, seed=7)
    assert json.dumps(again, sort_keys=True) == json.dumps(cboms, sort_keys=True)


def test_corpus_graphs_are_evaluable_and_no_nan(corpus_dir):
    """Every CBOM converts to a valid graph with a finite τ-b under the
    canonical protocol — identical-asset CBOMs must score 1.0, not NaN."""
    import math

    cboms, _ = corpus_dir
    graphs = [cbom_to_dependency_graph(c, seed=42) for c in cboms]
    assert all(g.n_assets >= 2 for g in graphs)
    for g in graphs:
        scores = score_order(heuristic_order(g), g)
        assert not math.isnan(scores["kendall"]), "τ-b must not be NaN"
        assert 0.0 <= scores["kendall"] <= 1.0
