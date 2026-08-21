"""Tests for the qtrust_inspector scanner package."""
import json

import pytest

from qtrust_inspector import AssetFinding, CryptoScanner, ScanResult


def test_scan_result_properties():
    result = ScanResult(
        target="example.com",
        findings=[
            AssetFinding(
                asset_type="tls_certificate", host="a.com", port=443, algorithm="RSA-2048"
            ),
            AssetFinding(
                asset_type="tls_certificate", host="b.com", port=443, algorithm="ECC-P256"
            ),
            AssetFinding(
                asset_type="ssh_host_key", host="c.com", port=22, algorithm="ssh-ed25519"
            ),
        ],
    )
    assert result.finding_count == 3
    assert result.by_algorithm == {"RSA-2048": 1, "ECC-P256": 1, "ssh-ed25519": 1}
    assert result.by_type == {"tls_certificate": 2, "ssh_host_key": 1}
    assert result.findings[0].location == "a.com:443"


def test_scan_result_to_cbom():
    result = ScanResult(
        target="example.com",
        findings=[
            AssetFinding(
                asset_type="tls_certificate",
                host="a.com",
                port=443,
                algorithm="RSA-2048",
                criticality="high",
            ),
        ],
    )
    cbom = result.to_cbom()
    assert cbom["schema_version"] == "qtrust.cbom.v1"
    assert cbom["asset_count"] == 1
    assert cbom["assets"][0]["algorithm"] == "RSA-2048"
    # Round-trips through JSON
    json.dumps(cbom)


def test_scan_tls_localhost_smoke():
    """Localhost has no TLS on 443 usually; ensure no crash and returns None or finding."""
    scanner = CryptoScanner(timeout=2)
    res = scanner.scan_tls("127.0.0.1", 443)
    assert res is None or res.asset_type == "tls_certificate"


def test_assess_criticality():
    assert CryptoScanner._assess_criticality("RSA", 1024, False) == "Critical"
    assert CryptoScanner._assess_criticality("RSA", 2048, False) == "High"
    assert CryptoScanner._assess_criticality("RSA", 4096, False) == "Low"
    assert CryptoScanner._assess_criticality("RSA", 2048, True) == "Critical"


def test_hash_cbom_deterministic():
    cbom = {"schema_version": "qtrust.cbom.v1", "assets": []}
    h1 = CryptoScanner.hash_cbom(cbom)
    h2 = CryptoScanner.hash_cbom(cbom)
    assert h1 == h2
    assert h1.startswith("0x") and len(h1) == 66


@pytest.mark.skipif(True, reason="Requires network access to example.com")
def test_scan_example_com_network():
    scanner = CryptoScanner(timeout=5)
    res = scanner.scan_tls("example.com", 443)
    assert res is not None
    assert res.key_size in (256, 384, 2048, 3072, 4096)
