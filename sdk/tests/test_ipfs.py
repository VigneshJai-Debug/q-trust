# sdk/tests/test_ipfs.py
"""Tests for multi-provider IPFS pinning (HTTP layer mocked)."""
import json
import logging
from unittest.mock import patch

import pytest
import requests

from qtrust.ipfs import (
    MultiPinataClient,
    MultiProviderClient,
    PinataClient,
    Web3StorageProvider,
    create_ipfs_client,
)


def _response(payload=None, status_code=200, headers=None):
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = json.dumps(payload or {}).encode()
    if headers:
        for k, v in headers.items():
            resp.headers[k] = v
    return resp


PINATA_ENV = {
    "QTRUST_PINATA_API_KEY": "key",
    "QTRUST_PINATA_API_SECRET": "secret",
}


def _mock_post(side_effects):
    mock = patch("qtrust.ipfs.requests.post", side_effect=side_effects)
    sleep_mock = patch("qtrust.ipfs.time.sleep")
    return mock, sleep_mock


def test_default_single_provider_matches_bare_pinata():
    env = dict(PINATA_ENV)
    with patch("qtrust.ipfs.requests.post", side_effect=[_response({"IpfsHash": "QmDefault"})]):
        client = create_ipfs_client(env)
        cid = client.pin_json('{"a": 1}')
    assert [name for name, _ in client.providers] == ["pinata"]
    assert cid == "QmDefault"

    with patch("qtrust.ipfs.requests.post", return_value=_response({"IpfsHash": "QmDefault"})):
        bare = PinataClient(api_key="key", api_secret="secret").pin_json('{"a": 1}')
    assert bare == cid


def test_default_providers_env_is_pinata_only():
    with patch("qtrust.ipfs.requests.post", side_effect=[_response({"IpfsHash": "QmX"})] * 2):
        default_client = create_ipfs_client(dict(PINATA_ENV))
        explicit_client = create_ipfs_client({**PINATA_ENV, "QTRUST_IPFS_PROVIDERS": "pinata"})
    assert [n for n, _ in default_client.providers] == ["pinata"]
    assert [n for n, _ in explicit_client.providers] == ["pinata"]


def test_kubo_success_primary(monkeypatch):
    monkeypatch.setenv("QTRUST_IPFS_PROVIDERS", "kubo")
    monkeypatch.setenv("QTRUST_IPFS_KUBO_API", "http://127.0.0.1:5001")

    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["auth"] = kwargs.get("auth")
        return _response({"Name": "payload.json", "Hash": "bafkqubo"})

    with patch("qtrust.ipfs.requests.post", side_effect=fake_post):
        client = create_ipfs_client()
        cid = client.pin_json('{"cbom": true}')

    assert cid == "bafkqubo"
    assert captured["url"].endswith("/api/v0/add?pin=true")
    assert captured["url"].startswith("http://127.0.0.1:5001")
    assert captured["auth"] is None


def test_kubo_basic_auth(monkeypatch):
    monkeypatch.setenv("QTRUST_IPFS_PROVIDERS", "kubo")
    monkeypatch.setenv("QTRUST_IPFS_KUBO_USER", "admin")
    monkeypatch.setenv("QTRUST_IPFS_KUBO_PASS", "hunter2")

    captured = {}

    def fake_post(url, **kwargs):
        captured["auth"] = kwargs.get("auth")
        return _response({"Hash": "bafkauth"})

    with patch("qtrust.ipfs.requests.post", side_effect=fake_post):
        from qtrust.ipfs import KuboProvider

        cid = KuboProvider().pin_json("{}")

    assert cid == "bafkauth"
    assert captured["auth"] == ("admin", "hunter2")


def test_web3_storage_header_cid_and_json_fallback():
    provider = Web3StorageProvider(token="tok-123")
    with patch(
        "qtrust.ipfs.requests.post",
        side_effect=[
            _response({}, headers={"X-Digest": "bafyheader"}),
            _response({"cid": "bafyjson"}),
        ],
    ) as post:
        cid1 = provider.pin_json('{"x": 1}')
        cid2 = provider.pin_json('{"x": 2}')
    assert cid1 == "bafyheader"
    assert cid2 == "bafyjson"
    _, kwargs = post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer tok-123"


def test_mixed_failure_secondary_failure_tolerated(caplog):
    env = {**PINATA_ENV, "QTRUST_IPFS_PROVIDERS": "pinata,kubo"}
    effects = [
        _response({"IpfsHash": "QmPrimary"}),  # pinata ok
        requests.ConnectionError("kubo down"),  # kubo best-effort fails
    ]
    with caplog.at_level(logging.WARNING, logger="qtrust.ipfs"):
        with patch("qtrust.ipfs.requests.post", side_effect=effects):
            with patch("qtrust.ipfs.time.sleep"):
                cid = create_ipfs_client(env).pin_json("{}")
    assert cid == "QmPrimary"
    assert any("kubo" in r.message.lower() or "'kubo'" in r.message for r in caplog.records)


def test_primary_fail_falls_back_with_warning(caplog, monkeypatch):
    monkeypatch.setenv("QTRUST_IPFS_PROVIDERS", "pinata,kubo")
    env = {**PINATA_ENV, "QTRUST_IPFS_PROVIDERS": "pinata,kubo"}
    effects = [
        requests.HTTPError("502 from pinata"),  # primary fails (retries exhausted)
        requests.HTTPError("502 from pinata"),
        requests.HTTPError("502 from pinata"),
        _response({"Hash": "bafkkubo"}),  # kubo succeeds
    ]
    with caplog.at_level(logging.WARNING, logger="qtrust.ipfs"):
        with patch("qtrust.ipfs.requests.post", side_effect=effects):
            with patch("qtrust.ipfs.time.sleep"):
                cid = create_ipfs_client(env).pin_json("{}")
    assert cid == "bafkkubo"
    assert any("primary" in r.message.lower() for r in caplog.records)


def test_all_providers_fail_raises():
    env = {**PINATA_ENV, "QTRUST_IPFS_PROVIDERS": "pinata,kubo"}
    effects = [
        requests.ConnectionError("pinata 1"),
        requests.ConnectionError("pinata 2"),
        requests.ConnectionError("pinata 3"),
        requests.ConnectionError("kubo"),
    ]
    with patch("qtrust.ipfs.requests.post", side_effect=effects):
        with patch("qtrust.ipfs.time.sleep"):
            with pytest.raises(requests.RequestException):
                create_ipfs_client(env).pin_json("{}")


def test_all_fail_single_provider_reraises_last():
    env = {**PINATA_ENV}
    effects = [
        requests.ConnectionError("a"),
        requests.ConnectionError("b"),
        requests.ConnectionError("c"),
    ]
    with patch("qtrust.ipfs.requests.post", side_effect=effects):
        with patch("qtrust.ipfs.time.sleep"):
            with pytest.raises(requests.ConnectionError):
                create_ipfs_client(env).pin_json("{}")


def test_cid_mismatch_logged_as_warning(caplog):
    env = {**PINATA_ENV, "QTRUST_IPFS_PROVIDERS": "pinata,kubo"}
    effects = [
        _response({"IpfsHash": "QmReal"}),  # pinata
        _response({"Hash": "bafkmismatch"}),  # kubo disagrees
    ]
    with caplog.at_level(logging.WARNING, logger="qtrust.ipfs"):
        with patch("qtrust.ipfs.requests.post", side_effect=effects):
            cid = create_ipfs_client(env).pin_json("{}")
    assert cid == "QmReal"
    mismatch_logs = [r for r in caplog.records if "mismatch" in r.message.lower()]
    assert mismatch_logs, "expected a CID mismatch warning"


def test_missing_credentials_skip_provider_with_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="qtrust.ipfs"):
        with pytest.raises(ValueError, match="No usable IPFS providers"):
            create_ipfs_client({"QTRUST_IPFS_PROVIDERS": "pinata"})
    assert any("skipped" in r.message for r in caplog.records)


def test_unknown_provider_name_raises():
    with pytest.raises(ValueError, match="Unknown IPFS provider"):
        create_ipfs_client({**PINATA_ENV, "QTRUST_IPFS_PROVIDERS": "ipfs://weird"})


def test_multiprovider_requires_at_least_one_provider():
    with pytest.raises(ValueError):
        MultiProviderClient(providers=[])


def test_multi_pinata_client_still_works():
    clients = MultiPinataClient([("k1", "s1"), ("k2", "s2")])
    assert len(clients.clients) == 2
    with patch(
        "qtrust.ipfs.requests.post",
        side_effect=[requests.ConnectionError("first down"), _response({"IpfsHash": "QmFallback"})],
    ):
        with patch("qtrust.ipfs.time.sleep"):
            cid = clients.pin_json('{"fallback": true}')
    assert cid == "QmFallback"
