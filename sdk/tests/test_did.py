# sdk/tests/test_did.py
"""Tests for did:web resolver."""
import pytest
from qtrust.did import DIDResolver, DIDDocument


def test_did_to_url_simple():
    resolver = DIDResolver()
    url = resolver._did_to_url("did:web:example.com")
    assert url == "https://example.com/.well-known/did.json"


def test_did_to_url_with_path():
    resolver = DIDResolver()
    url = resolver._did_to_url("did:web:example.com:users:alice")
    assert url == "https://example.com/users/alice/did.json"


def test_parse_did():
    resolver = DIDResolver()
    method, identifier, fragment = resolver._parse_did("did:web:example.com#key-1")
    assert method == "web"
    assert identifier == "example.com"
    assert fragment == "key-1"


def test_parse_did_no_fragment():
    resolver = DIDResolver()
    method, identifier, fragment = resolver._parse_did("did:web:example.com")
    assert method == "web"
    assert identifier == "example.com"
    assert fragment is None


def test_parse_did_invalid():
    resolver = DIDResolver()
    with pytest.raises(ValueError, match="Invalid DID"):
        resolver._parse_did("not-a-did")


def test_did_document_model():
    doc = DIDDocument(
        id="did:web:example.com",
        verificationMethod=[{
            "id": "did:web:example.com#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:example.com",
            "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        }],
        authentication=["did:web:example.com#key-1"],
    )
    assert doc.id == "did:web:example.com"
    assert len(doc.verificationMethod) == 1
    assert len(doc.authentication) == 1


def test_get_verification_key():
    resolver = DIDResolver()
    doc = DIDDocument(
        id="did:web:example.com",
        verificationMethod=[{
            "id": "did:web:example.com#key-1",
            "type": "Ed25519VerificationKey2020",
        }],
    )
    key = resolver.get_verification_key(doc, "did:web:example.com#key-1")
    assert key["id"] == "did:web:example.com#key-1"


def test_get_verification_key_default():
    resolver = DIDResolver()
    doc = DIDDocument(
        id="did:web:example.com",
        verificationMethod=[{
            "id": "did:web:example.com#key-1",
            "type": "Ed25519VerificationKey2020",
        }],
    )
    key = resolver.get_verification_key(doc)
    assert key["type"] == "Ed25519VerificationKey2020"


def test_get_verification_key_not_found():
    resolver = DIDResolver()
    doc = DIDDocument(id="did:web:example.com", verificationMethod=[])
    with pytest.raises(ValueError, match="no verification methods"):
        resolver.get_verification_key(doc)
