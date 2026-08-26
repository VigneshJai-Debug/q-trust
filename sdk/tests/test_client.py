"""Smoke tests for QTrustClient."""
import hashlib

import pytest

from qtrust import QTrustClient
from qtrust.schema import CBOM, CBOMEntry


def test_hash_string():
    h = QTrustClient.hash_string("test")
    assert h.startswith("0x")
    assert len(h) == 66
    expected = "0x" + hashlib.sha256(b"test").hexdigest()
    assert h == expected


def test_hash_file(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")
    h = QTrustClient.hash_file(str(test_file))
    assert h.startswith("0x")
    assert len(h) == 66
    expected = "0x" + hashlib.sha256(b"hello world").hexdigest()
    assert h == expected


def test_hash_cbom():
    cbom = CBOM(
        org_did="did:ethr:0x1234567890123456789012345678901234567890",
        generated_at=1700000000,
        scanner_version="0.1.0",
        assets=[
            CBOMEntry(
                asset_type="tls_cert",
                algorithm="RSA-2048",
                location="example.com:443",
                criticality="high",
            )
        ],
    )
    h = QTrustClient.hash_cbom(cbom)
    assert h.startswith("0x")
    assert len(h) == 66


def test_cbom_validation():
    entry = CBOMEntry(
        asset_type="tls_cert",
        algorithm="RSA-2048",
        location="example.com:443",
    )
    assert entry.criticality == "medium"
    assert entry.vendor is None


def test_cbom_summary():
    cbom = CBOM(
        org_did="did:ethr:0x1234567890123456789012345678901234567890",
        generated_at=1700000000,
        scanner_version="0.1.0",
        assets=[
            CBOMEntry(asset_type="tls_cert", algorithm="RSA-2048", location="a.com:443"),
            CBOMEntry(asset_type="tls_cert", algorithm="ECC-P256", location="b.com:443"),
            CBOMEntry(asset_type="ssh_key", algorithm="RSA-2048", location="host:22"),
        ],
        summary={"total_assets": 3, "by_algorithm": {"RSA-2048": 2, "ECC-P256": 1}},
    )
    assert len(cbom.assets) == 3
    assert cbom.summary["total_assets"] == 3


def test_readonly_mode_constructor(monkeypatch):
    """A client without a private key is read-only: constructors work, writes guard."""
    monkeypatch.delenv("QTRUST_DEPLOYER_PRIVATE_KEY", raising=False)
    monkeypatch.setenv(
        "QTRUST_ASSET_REGISTRY_ADDRESS",
        "0x0000000000000000000000000000000000000001",
    )
    try:
        client = QTrustClient(rpc_url="http://127.0.0.1:8545", chain_id=84532)
    except ConnectionError:
        pytest.skip("anvil not running — read-only mode covered live in e2e_anvil.py")
    assert client.account is None, "no account should be derived without a key"

    try:
        client._require_account()
        raise AssertionError("write without key must raise")
    except ValueError as e:
        assert "private key" in str(e)

    client2 = QTrustClient(
        private_key=(
            "0xac0974bec39a17e36ba4a6b4d238ff944"
            "bacb478cbed5efcae784d7bf4f2ff80"
        ),
        rpc_url="http://127.0.0.1:8545",
        chain_id=84532,
    )
    assert client2.account is not None
    assert client2._require_account() is client2.account


class TestCleartextRpcGuardHardening:
    """Audit M-3: substring loopback check was bypassable via URL userinfo."""

    def test_userinfo_substring_bypass_blocked(self):
        # "127.0.0.1" appears in the userinfo position but the real host is
        # evil.com — the guard must reject this.
        with pytest.raises(ValueError, match="non-HTTPS"):
            QTrustClient(rpc_url="http://127.0.0.1@evil.com:8545/")

    def test_https_remote_allowed(self):
        client = QTrustClient(rpc_url="https://sepolia.base.org")
        assert client.rpc_url == "https://sepolia.base.org"
