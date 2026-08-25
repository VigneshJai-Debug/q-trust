# sdk/tests/test_trust.py
"""Tests for Trust Assessment."""
from qtrust.trust import Conflict, EvidenceContribution, TrustAssessment, TrustEvaluator


def test_basic_evaluation():
    evaluator = TrustEvaluator()
    assessment = evaluator.evaluate(
        subject_did="did:web:creditunion.com",
        policy_id="ncua_part_748_pqc",
        policy_version="1.0.0",
        evidence=[
            {
                "evidence_id": "cred-1",
                "evidence_type": "credential",
                "claims": {"no_rsa_1024": True},
            },
            {
                "evidence_id": "cred-2",
                "evidence_type": "credential",
                "claims": {"tls_min_key_bits": 2048},
            },
            {
                "evidence_id": "cred-3",
                "evidence_type": "credential",
                "claims": {"migration_plan_date": "2026-12-31"},
            },
            {
                "evidence_id": "cred-4",
                "evidence_type": "credential",
                "claims": {"no_md5_sha1_signing": True},
            },
            {
                "evidence_id": "cred-5",
                "evidence_type": "credential",
                "claims": {"vendor_pqc_ready_count": 3},
            },
        ],
    )

    assert isinstance(assessment, TrustAssessment)
    assert assessment.subject_did == "did:web:creditunion.com"
    assert assessment.policy_id == "ncua_part_748_pqc"
    assert assessment.passed is True
    assert assessment.confidence == 1.0
    assert len(assessment.evidence_used) == 5
    assert len(assessment.conflicts) == 0


def test_partial_evaluation():
    evaluator = TrustEvaluator()
    assessment = evaluator.evaluate(
        subject_did="did:web:creditunion.com",
        policy_id="ncua_part_748_pqc",
        policy_version="1.0.0",
        evidence=[
            {
                "evidence_id": "cred-1",
                "evidence_type": "credential",
                "claims": {"no_rsa_1024": True},
            },
        ],
    )

    assert assessment.passed is False
    assert assessment.confidence < 1.0
    assert len(assessment.evidence_used) == 1
    assert len(assessment.conflicts) == 0


def test_deterministic():
    evaluator = TrustEvaluator()
    evidence = [
        {"evidence_id": "cred-1", "evidence_type": "credential", "claims": {"no_rsa_1024": True}},
    ]

    a1 = evaluator.evaluate("did:web:x.com", "policy", "1.0", evidence)
    a2 = evaluator.evaluate("did:web:x.com", "policy", "1.0", evidence)

    assert a1.passed == a2.passed
    assert a1.confidence == a2.confidence
    assert a1.compute_hash_without_timestamp() == a2.compute_hash_without_timestamp()


def test_compute_hash():
    evaluator = TrustEvaluator()
    assessment = evaluator.evaluate(
        subject_did="did:web:x.com",
        policy_id="test",
        policy_version="1.0",
        evidence=[],
    )
    h = assessment.compute_hash()
    assert h.startswith("0x")
    assert len(h) == 66


def test_default_pqc_clauses():
    clauses = TrustEvaluator._default_pqc_clauses()
    assert "no_rsa_1024" in clauses
    assert "tls_min_2048" in clauses
    assert "pqc_plan_exists" in clauses
    assert "no_weak_hash" in clauses
    assert "vendor_attestations" in clauses


def test_evidence_contribution_model():
    ec = EvidenceContribution(
        evidence_id="cred-1",
        evidence_type="credential",
        contribution=0.3,
        matched_clauses=["clause_a"],
        summary="Test",
    )
    assert ec.evidence_id == "cred-1"
    assert ec.contribution == 0.3


def test_conflict_model():
    c = Conflict(
        evidence_ids=["cred-1", "cred-2"],
        conflict_type="contradiction",
        description="Test conflict",
    )
    assert c.conflict_type == "contradiction"
