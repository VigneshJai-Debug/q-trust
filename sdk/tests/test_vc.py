# sdk/tests/test_vc.py
"""Tests for W3C Verifiable Credentials."""
import json
from types import SimpleNamespace

import pytest

from qtrust.vc import (
    VCIssuer,
    VCPresenter,
    VCVerificationResult,
    VCVerifier,
    VerifiableCredential,
)


def test_issue_vc():
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(
        subject_did="did:web:creditunion.com",
        credential_type=["PQCReadinessCredential"],
        claims={"pqc_readiness_level": "Level 2", "no_rsa_1024": True},
    )

    assert vc.issuer == "did:web:trailofbits.com"
    assert vc.credentialSubject["id"] == "did:web:creditunion.com"
    assert vc.credentialSubject["pqc_readiness_level"] == "Level 2"
    assert "PQCReadinessCredential" in vc.type
    assert vc.id.startswith("urn:uuid:")


def test_issue_vc_with_expiration():
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(
        subject_did="did:web:creditunion.com",
        expiration_date="2027-12-31T00:00:00Z",
    )
    assert vc.expirationDate == "2027-12-31T00:00:00Z"


def test_issue_vc_with_schema():
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(
        subject_did="did:web:creditunion.com",
        schema_id="https://qtrust.dev/schemas/pqc-readiness/v1",
    )
    assert vc.credentialSchema["id"] == "https://qtrust.dev/schemas/pqc-readiness/v1"
    assert vc.credentialSchema["type"] == "JsonSchema2021"


def test_vc_to_json():
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(subject_did="did:web:creditunion.com")
    json_str = vc.to_json()
    assert isinstance(json_str, str)
    data = json.loads(json_str)
    assert data["issuer"] == "did:web:trailofbits.com"
    assert "@context" in data


def test_vc_to_jwt_claims():
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(subject_did="did:web:creditunion.com")
    claims = vc.to_jwt_claims()
    assert claims["iss"] == "did:web:trailofbits.com"
    assert "vc" in claims


def test_present_vc_rejects_selective_disclosure():
    """Field-stripping 'selective disclosure' was cryptographically fake
    (audit Critical #6) — it must now be rejected explicitly."""
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(
        subject_did="did:web:creditunion.com",
        claims={"pqc_readiness_level": "Level 2", "no_rsa_1024": True, "secret": "hidden"},
    )

    presenter = VCPresenter(holder_did="did:web:creditunion.com")
    with pytest.raises(ValueError, match="Selective disclosure"):
        presenter.present(
            vc=vc,
            disclosed_fields=["pqc_readiness_level"],
            verifier_did="did:web:ncua.gov",
        )


def test_present_vc_full_binds_issuer_proof():
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(
        subject_did="did:web:creditunion.com",
        claims={"pqc_readiness_level": "Level 2", "secret": "hidden"},
    )

    presenter = VCPresenter(holder_did="did:web:creditunion.com")
    vp = presenter.present(vc=vc, verifier_did="did:web:ncua.gov")

    assert vp.holder == "did:web:creditunion.com"
    presented_vc = vp.verifiableCredential[0]
    assert isinstance(presented_vc, dict)
    # The full issuer-signed subject is embedded — no silent field stripping.
    subject = presented_vc.get("credentialSubject", {})
    assert "pqc_readiness_level" in subject
    assert vp.proof is not None
    assert vp.proof.get("domain") == "did:web:ncua.gov"


def test_present_vc_full():
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(
        subject_did="did:web:creditunion.com",
        claims={"pqc_readiness_level": "Level 2"},
    )

    presenter = VCPresenter(holder_did="did:web:creditunion.com")
    vp = presenter.present(vc=vc)

    assert vp.holder == "did:web:creditunion.com"


def test_verify_vc_sync():
    verifier = VCVerifier()
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(
        subject_did="did:web:creditunion.com",
        claims={"pqc_readiness_level": "Level 2"},
    )

    result = verifier.verify_credential_sync(vc)
    assert isinstance(result, VCVerificationResult)
    assert result.issuer_did == "did:web:trailofbits.com"
    assert result.subject_did == "did:web:creditunion.com"


def test_verify_vc_expired():
    verifier = VCVerifier()
    issuer = VCIssuer(issuer_did="did:web:trailofbits.com")
    vc = issuer.issue(
        subject_did="did:web:creditunion.com",
        expiration_date="2020-01-01T00:00:00Z",
    )

    result = verifier.verify_credential_sync(vc)
    assert result.expired is True
    assert result.valid is False


def test_vc_model_roundtrip():
    vc = VerifiableCredential(
        issuer="did:web:example.com",
        credentialSubject={"id": "did:web:subject.com", "claim": "value"},
    )
    data = json.loads(vc.to_json())
    vc2 = VerifiableCredential(**data)
    assert vc2.issuer == vc.issuer
    assert vc2.credentialSubject["claim"] == "value"


class TestMalformedProofValue:
    """Audit M-4: bytes.fromhex(proofValue) must not raise on untrusted input."""

    def test_malformed_hex_returns_invalid_signature(self):
        verifier = VCVerifier(resolver=None)
        vc = SimpleNamespace(
            issuer="did:web:example.com",
            proof={"proofValue": "zz-not-hex!!"},
            credentialSubject={},
            type=["VerifiableCredential"],
            # _verify_proof canonicalizes the VC before checking the proof.
            model_dump=lambda **_: {"issuer": "did:web:example.com", "credentialSubject": {}},
        )
        # _verify_proof returns a reason string instead of raising ValueError.
        assert verifier._verify_proof(vc, None) == "invalid_signature"
