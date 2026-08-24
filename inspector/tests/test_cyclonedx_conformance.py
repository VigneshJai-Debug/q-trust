"""Conformance checks for the inspector's emitted CycloneDX 1.7 CBOM."""
from __future__ import annotations

import re
import uuid

import pytest

from qtrust_inspector.cyclonedx import generate_cyclonedx
from qtrust_inspector.models import AssetFinding, ScanResult

URN_UUID_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _fixture_scan() -> ScanResult:
    return ScanResult(
        target="example.com",
        findings=[
            AssetFinding(
                asset_type="tls_certificate",
                host="example.com",
                port=443,
                algorithm="RSA-2048",
                key_size=2048,
                criticality="high",
                issuer="CN=Test Root CA",
                subject="CN=example.com",
                serial_number="04:aa:bb",
                not_before="2026-01-01T00:00:00Z",
                not_after="2027-01-01T00:00:00Z",
                expired=False,
                fingerprint_sha256="ab" * 32,
            ),
            AssetFinding(
                asset_type="ssh_host_key",
                host="git.example.com",
                port=22,
                algorithm="ssh-ed25519",
            ),
            AssetFinding(
                asset_type="file_key",
                host="/opt/app/key.pem",
                algorithm="RSA-4096",
                key_size=4096,
            ),
        ],
    )


@pytest.fixture()
def bom() -> dict:
    return generate_cyclonedx(_fixture_scan())


class TestBOMEnvelope:
    def test_bom_format_and_spec_version(self, bom):
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.7"

    def test_serial_number_urn_uuid(self, bom):
        assert URN_UUID_RE.match(bom["serialNumber"])
        uuid.UUID(bom["serialNumber"].removeprefix("urn:uuid:"))

    def test_version_is_int(self, bom):
        assert isinstance(bom["version"], int)
        assert bom["version"] >= 1

    def test_metadata_tools_declared(self, bom):
        tool = bom["metadata"]["tools"][0]
        assert tool["vendor"] == "qtrust"
        assert tool["name"] == "qtrust-inspector"
        assert "timestamp" in bom["metadata"]

    def test_component_count_matches_findings(self, bom):
        assert len(bom["components"]) == 3

    def test_json_serializable(self, bom):
        import json

        serialized = json.dumps(bom)
        data = json.loads(serialized)
        assert data["bomFormat"] == "CycloneDX"


class TestCryptoComponents:
    def test_all_components_are_cryptographic_assets(self, bom):
        for component in bom["components"]:
            assert component["type"] == "cryptographic-asset"

    def test_crypto_properties_present_for_every_crypto_asset(self, bom):
        for component in bom["components"]:
            crypto = component.get("cryptoProperties")
            assert crypto, f"missing cryptoProperties on {component['name']}"
            assert crypto["assetType"]
            assert "algorithmProperties" in crypto

    def test_algorithm_properties_shape(self, bom):
        rsa = next(
            c
            for c in bom["components"]
            if c["cryptoProperties"]["algorithmProperties"]["name"].startswith("RSA")
        )
        props = rsa["cryptoProperties"]["algorithmProperties"]
        assert props["scheme"]
        assert props["strength"] in {"2048", "4096"}

    def test_asset_type_mapping(self, bom):
        types = {c["cryptoProperties"]["assetType"] for c in bom["components"]}
        assert "certificate" in types
        assert "key" in types

    def test_certificate_block_from_tls_details(self, bom):
        cert_component = next(
            c for c in bom["components"] if "certificates" in c["cryptoProperties"]
        )
        cert = cert_component["cryptoProperties"]["certificates"][0]
        assert cert["issuer"] == "CN=Test Root CA"
        assert cert["subject"] == "CN=example.com"
        assert cert["notAfter"] == "2027-01-01T00:00:00Z"
        assert cert["expired"] is False

    def test_hash_entry_for_fingerprint(self, bom):
        hashed = [c for c in bom["components"] if c.get("hashes")]
        assert len(hashed) == 1
        entry = hashed[0]["hashes"][0]
        assert entry["alg"] == "SHA-256"
        assert entry["content"] == "ab" * 32

    def test_quantum_safe_flag_present(self, bom):
        for component in bom["components"]:
            assert "quantumSafe" in component["cryptoProperties"]

    def test_qtrust_extension_properties(self, bom):
        component = bom["components"][0]
        names = {p["name"] for p in component["properties"]}
        assert "qtrust:criticality" in names
