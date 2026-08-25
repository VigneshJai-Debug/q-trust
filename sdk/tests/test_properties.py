# sdk/tests/test_properties.py
"""Property-based tests (hypothesis): CBOM hash determinism, VC round-trip,
DID parsing, risk-score monotonicity."""
from __future__ import annotations

import base64
import json
import os

import base58
import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from nacl.signing import SigningKey
from pydantic import ValidationError

from qtrust.client import QTrustClient
from qtrust.did import DIDDocument, DIDResolver
from qtrust.risk import QuantumVulnerability, RiskScoringEngine
from qtrust.schema import CBOM, CBOMEntry
from qtrust.vc import VCIssuer, VCVerifier, VerifiableCredential

# Hypothesis profiles: CI runs the "ci" profile (1000 examples, no per-case
# deadline) via HYPOTHESIS_PROFILE=ci; local default stays fast.
settings.register_profile("ci", max_examples=1000, deadline=None)
if os.environ.get("HYPOTHESIS_PROFILE"):
    settings.load_profile(os.environ["HYPOTHESIS_PROFILE"])

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.text(
        alphabet=st.characters(blacklist_characters='"\\', blacklist_categories=("Cs",)),
        max_size=12,
    ),
)

json_objects = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(
            st.text(alphabet="abcdefghijkmnpqrstuvwxyz_", min_size=1, max_size=8),
            children,
            max_size=4,
        ),
    ),
    max_leaves=12,
)

summary_objects = st.dictionaries(
    st.text(alphabet="abcdefghijkmnpqrstuvwxyz_", min_size=1, max_size=8),
    json_objects,
    max_size=6,
)

asset_entries = st.fixed_dictionaries({
    "asset_type": st.sampled_from(["tls_cert", "ssh_key", "code_signing", "jwt"]),
    "algorithm": st.sampled_from(["RSA-2048", "ECC-P256", "ML-KEM-768", "AES-256"]),
    "location": st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789.:-", min_size=3, max_size=20
    ),
    "criticality": st.sampled_from(["low", "medium", "high", "critical"]),
})

label = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=6)

domains = st.lists(label, min_size=1, max_size=3).map(lambda parts: ".".join(parts))

path_segments = st.lists(label, min_size=0, max_size=2)

fragments = st.one_of(st.none(), st.text(alphabet="abcXYZ0123456789-", min_size=1, max_size=10))

subject_dids = st.sampled_from([
    "did:web:creditunion.com",
    "did:web:example.com:users:alice",
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
])


# ---------------------------------------------------------------------------
# CBOM hash / canonicalization determinism
# ---------------------------------------------------------------------------

def _reverse_nested(value):
    if isinstance(value, dict):
        return {k: _reverse_nested(v) for k, v in reversed(list(value.items()))}
    if isinstance(value, list):
        return [_reverse_nested(item) for item in value]
    return value


def _make_cbom(assets_meta, summary):
    return CBOM(
        org_did="did:ethr:0x1234567890123456789012345678901234567890",
        generated_at=1700000000,
        scanner_version="0.1.0",
        assets=[CBOMEntry(**meta) for meta in assets_meta],
        summary=summary,
    )


@settings(max_examples=50)
@given(assets_meta=st.lists(asset_entries, max_size=5), summary=summary_objects)
def test_hash_cbom_insertion_order_invariant(assets_meta, summary):
    a = _make_cbom(assets_meta, summary)
    b = _make_cbom(
        [{k: _reverse_nested(v) for k, v in reversed(list(m.items()))} for m in assets_meta],
        _reverse_nested(summary),
    )
    assert QTrustClient.hash_cbom(a) == QTrustClient.hash_cbom(b)


@settings(max_examples=25)
@given(assets_meta=st.lists(asset_entries, max_size=4), summary=summary_objects)
def test_hash_cbom_is_deterministic(assets_meta, summary):
    cbom = _make_cbom(assets_meta, summary)
    assert QTrustClient.hash_cbom(cbom) == QTrustClient.hash_cbom(cbom)


@settings(max_examples=50)
@given(data=st.data())
def test_hash_cbom_differs_on_different_payload(data):
    summary_a = data.draw(summary_objects)
    summary_b = data.draw(summary_objects)
    assume(summary_a != summary_b)
    a = _make_cbom([], summary_a)
    b = _make_cbom([], summary_b)
    assert QTrustClient.hash_cbom(a) != QTrustClient.hash_cbom(b)


# ---------------------------------------------------------------------------
# VC issue -> verify round-trip and tamper detection
# ---------------------------------------------------------------------------

class _StaticResolver:
    """Offline DID resolver backed by a fixed document."""

    def __init__(self, doc: DIDDocument):
        self.doc = doc

    async def resolve(self, did: str) -> DIDDocument:
        return self.doc

    def resolve_sync(self, did: str) -> DIDDocument:
        return self.doc

    def get_authentication_key(self, doc: DIDDocument) -> dict:
        return doc.verificationMethod[0]


ISSUER_DID = "did:web:issuer.example.com"


def _resolver_for(signing_key: SigningKey) -> _StaticResolver:
    pub = bytes(signing_key.verify_key)
    x = base64.urlsafe_b64encode(pub).decode().rstrip("=")
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    doc = DIDDocument(
        id=ISSUER_DID,
        verificationMethod=[{
            "id": f"{ISSUER_DID}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": ISSUER_DID,
            "publicKeyJwk": jwk,
        }],
        authentication=[f"{ISSUER_DID}#key-1"],
    )
    return _StaticResolver(doc)


def _issue_signed_vc(signing_key: SigningKey, subject: str, claims: dict) -> VerifiableCredential:
    issuer = VCIssuer(issuer_did=ISSUER_DID, private_key=bytes(signing_key))
    return issuer.issue(subject_did=subject, claims=claims)


claim_sets = st.dictionaries(
    st.text(alphabet="abcdefghijklmnop_", min_size=1, max_size=10),
    st.one_of(json_scalars, st.lists(json_scalars, max_size=3)),
    max_size=4,
).filter(lambda d: all(not isinstance(v, dict) for v in d.values()) and "id" not in d)


@settings(max_examples=40)
@given(subject=subject_dids, claims=claim_sets)
def test_vc_issue_verify_roundtrip(subject, claims):
    signing_key = SigningKey.generate()
    verifier = VCVerifier(resolver=_resolver_for(signing_key))
    vc = _issue_signed_vc(signing_key, subject, claims)
    result = verifier.verify_credential_sync(vc)
    assert result.valid is True
    assert result.subject_did == subject


def test_vc_issue_rejects_reserved_id_claim():
    """Caller claims must not clobber the subject DID binding (audit follow-up)."""
    signing_key = SigningKey.generate()
    issuer = VCIssuer(issuer_did=ISSUER_DID, private_key=bytes(signing_key))
    with pytest.raises(ValueError, match="reserved"):
        issuer.issue(subject_did="did:web:creditunion.com", claims={"id": "evil"})


@settings(max_examples=40)
@given(data=st.data())
def test_vc_signature_byte_flip_detected(data):
    signing_key = SigningKey.generate()
    claims = data.draw(claim_sets)
    vc = _issue_signed_vc(signing_key, "did:web:creditunion.com", claims)

    signature = bytearray(bytes.fromhex(vc.proof["proofValue"]))
    idx = data.draw(st.integers(min_value=0, max_value=len(signature) - 1))
    bit = data.draw(st.integers(min_value=0, max_value=7))
    signature[idx] ^= 1 << bit

    tampered = vc.model_copy(deep=True)
    tampered.proof["proofValue"] = bytes(signature).hex()

    verifier = VCVerifier(resolver=_resolver_for(signing_key))
    result = verifier.verify_credential_sync(tampered)
    assert result.valid is False


@settings(max_examples=60, deadline=None)
@given(data=st.data())
def test_vc_payload_byte_flip_detected(data):
    signing_key = SigningKey.generate()
    claims = data.draw(claim_sets)
    vc = _issue_signed_vc(signing_key, "did:web:creditunion.com", claims)

    original = json.loads(VCVerifier._signed_message(vc))
    message = bytearray(VCVerifier._signed_message(vc))
    idx = data.draw(st.integers(min_value=0, max_value=len(message) - 1))
    message[idx] ^= 1 << data.draw(st.integers(min_value=0, max_value=7))

    try:
        mutated = json.loads(bytes(message).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    assume(mutated != original)

    try:
        tampered = VerifiableCredential(**{**mutated, "proof": vc.proof})
    except ValidationError:
        return

    if VCVerifier._signed_message(tampered) == VCVerifier._signed_message(vc):
        return

    verifier = VCVerifier(resolver=_resolver_for(signing_key))
    result = verifier.verify_credential_sync(tampered)
    assert result.valid is False


@settings(max_examples=30)
@given(data=st.data())
def test_vc_modified_claim_with_original_proof_detected(data):
    signing_key = SigningKey.generate()
    value = data.draw(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8))
    other = value + "x"
    assume(other != value)
    vc = _issue_signed_vc(
        signing_key, "did:web:creditunion.com", {"pqc_readiness_level": value}
    )

    tampered = vc.model_copy(deep=True)
    tampered.credentialSubject["pqc_readiness_level"] = other

    verifier = VCVerifier(resolver=_resolver_for(signing_key))
    result = verifier.verify_credential_sync(tampered)
    assert result.valid is False


# ---------------------------------------------------------------------------
# DID parsing grammar
# ---------------------------------------------------------------------------

@settings(max_examples=50)
@given(domain=domains, path=path_segments, fragment=fragments)
def test_valid_did_web_parses(domain, path, fragment):
    did = "did:web:" + domain + "".join(f":{seg}" for seg in path)
    if fragment is not None:
        did += f"#{fragment}"

    resolver = DIDResolver()
    method, identifier, parsed_fragment = resolver._parse_did(did)
    assert method == "web"
    assert identifier == domain + "".join(f":{seg}" for seg in path)
    assert parsed_fragment == fragment

    did_without_fragment = "did:web:" + domain + "".join(f":{seg}" for seg in path)
    url = resolver._did_to_url(did_without_fragment)
    if path:
        assert url == f"https://{domain}/{'/'.join(path)}/did.json"
    else:
        assert url == f"https://{domain}/.well-known/did.json"


@settings(max_examples=50)
@given(seed=st.binary(min_size=32, max_size=32), fragment=fragments)
def test_valid_did_key_parses(seed, fragment):
    public_key = bytes(SigningKey(seed).verify_key)
    multibase = base58.b58encode(b"\xed\x01" + public_key).decode()
    did = f"did:key:z{multibase}"
    if fragment is not None:
        did += f"#{fragment}"

    resolver = DIDResolver()
    method, identifier, parsed_fragment = resolver._parse_did(did)
    assert method == "key"
    assert identifier == f"z{multibase}"
    assert parsed_fragment == fragment


malformed_dids = st.sampled_from([
    "",
    "not-a-did",
    "https://example.com",
    "did",
    "did:web",
    "urn:uuid:123e4567-e89b",
])


@settings(max_examples=25)
@given(bad=malformed_dids)
def test_malformed_did_raises_valueerror(bad):
    with pytest.raises(ValueError):
        DIDResolver()._parse_did(bad)


@settings(max_examples=25)
@given(domain=domains)
def test_non_web_method_rejected_for_resolution(domain):
    with pytest.raises(ValueError, match="Only did:web"):
        DIDResolver()._did_to_url(f"did:key:z{domain}")


# ---------------------------------------------------------------------------
# Risk scoring monotonicity
# ---------------------------------------------------------------------------

_BY_VULN_CLASS = {
    QuantumVulnerability.BROKEN: ("RSA-2048", "ECDSA-P256", "DH-2048"),
    QuantumVulnerability.WEAKENED: ("Ed25519", "AES-128", "SHA-256"),
    QuantumVulnerability.SAFE: ("AES-192", "SHA-384", "ChaCha20-Poly1305"),
    QuantumVulnerability.PQC_READY: ("ML-KEM-768", "ML-DSA-65", "SLH-DSA-128s"),
}

_CLASS_RANK = {
    QuantumVulnerability.PQC_READY: 0,
    QuantumVulnerability.SAFE: 1,
    QuantumVulnerability.WEAKENED: 2,
    QuantumVulnerability.BROKEN: 3,
}


def _score(algorithm: str, hndl: float) -> float:
    finding = {"algorithm": algorithm, "hndl_exposure_score": hndl}
    return RiskScoringEngine().calculate(finding).overall_risk_score


@settings(max_examples=75)
@given(
    cls_a=st.sampled_from(list(_BY_VULN_CLASS)),
    cls_b=st.sampled_from(list(_BY_VULN_CLASS)),
    hndl=st.floats(min_value=0.0, max_value=1.0),
)
def test_higher_vulnerability_class_never_scores_lower(cls_a, cls_b, hndl):
    algorithm_a = _BY_VULN_CLASS[cls_a][0]
    algorithm_b = _BY_VULN_CLASS[cls_b][0]
    score_a = _score(algorithm_a, hndl)
    score_b = _score(algorithm_b, hndl)
    if _CLASS_RANK[cls_a] > _CLASS_RANK[cls_b]:
        assert score_a >= score_b


@settings(max_examples=75)
@given(
    hndl_low=st.floats(min_value=0.0, max_value=1.0),
    hndl_high=st.floats(min_value=0.0, max_value=1.0),
    algorithm=st.sampled_from([a for group in _BY_VULN_CLASS.values() for a in group]),
)
def test_score_monotonic_in_hndl_exposure(hndl_low, hndl_high, algorithm):
    if hndl_low > hndl_high:
        hndl_low, hndl_high = hndl_high, hndl_low
    assert _score(algorithm, hndl_low) <= _score(algorithm, hndl_high)


@settings(max_examples=25)
@given(findings=st.lists(
    st.fixed_dictionaries({
        "algorithm": st.sampled_from([a for g in _BY_VULN_CLASS.values() for a in g]),
        "hndl_exposure_score": st.floats(min_value=0.0, max_value=1.0),
    }),
    max_size=10,
))
def test_batch_calculate_matches_individual(findings):
    engine = RiskScoringEngine()
    batch = engine.batch_calculate(findings)
    assert len(batch) == len(findings)
    for finding, scored in zip(findings, batch):
        assert scored.overall_risk_score == engine.calculate(finding).overall_risk_score
