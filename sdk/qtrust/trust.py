# sdk/qtrust/trust.py
"""Trust Assessment - deterministic, explainable evaluation.

Implements the TrustAssessment data model from the Q-Trust 2030 Blueprint.
Trust assessments are deterministic: same evidence + same policy + same version = same result.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class EvidenceContribution(BaseModel):
    """How a single piece of evidence contributed to the assessment."""
    evidence_id: str
    evidence_type: str
    contribution: float = Field(ge=0.0, le=1.0)
    matched_clauses: list[str] = Field(default_factory=list)
    summary: str = ""


class Conflict(BaseModel):
    """A conflict between evidence sources."""
    evidence_ids: list[str]
    conflict_type: str
    description: str
    resolution: str = ""


class PolicyClauseStatus(BaseModel):
    """Status of a single policy clause evaluation."""
    clause_id: str
    status: str
    evidence: str | None = None
    explanation: str = ""


class TrustAssessment(BaseModel):
    """A deterministic, explainable trust assessment."""
    assessment_id: str = Field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    subject_did: str
    policy_id: str
    policy_version: str
    passed: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_used: list[EvidenceContribution] = Field(default_factory=list)
    conflicts: list[Conflict] = Field(default_factory=list)
    explanation: dict[str, PolicyClauseStatus] = Field(default_factory=dict)
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    valid_until: str | None = None
    assessment_hash: str = ""

    def compute_hash(self) -> str:
        """Compute a deterministic hash of the assessment."""
        data = {
            "subject_did": self.subject_did,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "passed": self.passed,
            "confidence": self.confidence,
            "evidence_used": [e.model_dump() for e in self.evidence_used],
            "conflicts": [c.model_dump() for c in self.conflicts],
            "explanation": {k: v.model_dump() for k, v in self.explanation.items()},
            "evaluated_at": self.evaluated_at,
            "valid_until": self.valid_until,
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return "0x" + hashlib.sha256(canonical.encode()).hexdigest()

    def compute_hash_without_timestamp(self) -> str:
        """Compute a deterministic hash excluding the evaluated_at timestamp."""
        data = {
            "subject_did": self.subject_did,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "passed": self.passed,
            "confidence": self.confidence,
            "evidence_used": [e.model_dump() for e in self.evidence_used],
            "conflicts": [c.model_dump() for c in self.conflicts],
            "explanation": {k: v.model_dump() for k, v in self.explanation.items()},
            "valid_until": self.valid_until,
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return "0x" + hashlib.sha256(canonical.encode()).hexdigest()


class TrustEvaluator:
    """Deterministic trust evaluation engine.

    Evaluates a subject's trust against a policy, given a set of evidence.
    The evaluation is deterministic: same inputs always produce the same output.
    """

    def evaluate(
        self,
        subject_did: str,
        policy_id: str,
        policy_version: str,
        evidence: list[dict[str, Any]],
        policy_clauses: dict[str, dict[str, Any]] | None = None,
    ) -> TrustAssessment:
        """Run a deterministic trust evaluation.

        Args:
            subject_did: The DID of the subject being evaluated.
            policy_id: The policy identifier.
            policy_version: The policy version.
            evidence: List of evidence objects with evidence_id, evidence_type, claims.
            policy_clauses: Dict of clause_id to clause definition with required_claims and weight.
        """
        if policy_clauses is None:
            policy_clauses = self._default_pqc_clauses()

        evidence_used: list[EvidenceContribution] = []
        conflicts: list[Conflict] = []
        explanation: dict[str, PolicyClauseStatus] = {}
        total_weight = 0.0
        satisfied_weight = 0.0

        for clause_id, clause in policy_clauses.items():
            required_claims = clause.get("required_claims", [])
            weight = clause.get("weight", 1.0 / max(len(policy_clauses), 1))
            total_weight += weight

            matching_evidence = None
            for ev in evidence:
                claims = ev.get("claims", {})
                if all(claims.get(rc) is not None for rc in required_claims):
                    matching_evidence = ev
                    break

            if matching_evidence:
                explanation[clause_id] = PolicyClauseStatus(
                    clause_id=clause_id,
                    status="satisfied",
                    evidence=matching_evidence["evidence_id"],
                    explanation=f"Evidence {matching_evidence['evidence_id']} satisfies clause",
                )
                satisfied_weight += weight

                evidence_used.append(EvidenceContribution(
                    evidence_id=matching_evidence["evidence_id"],
                    evidence_type=matching_evidence.get("evidence_type", "unknown"),
                    contribution=weight,
                    matched_clauses=[clause_id],
                    summary=f"Satisfies {clause_id}",
                ))
            else:
                explanation[clause_id] = PolicyClauseStatus(
                    clause_id=clause_id,
                    status="insufficient_evidence",
                    explanation=f"No evidence satisfies required claims: {required_claims}",
                )

        confidence = satisfied_weight / total_weight if total_weight > 0 else 0.0

        all_satisfied = all(ps.status == "satisfied" for ps in explanation.values())

        evidence_ids = [e.evidence_id for e in evidence_used]
        if len(evidence_ids) != len(set(evidence_ids)):
            conflicts.append(Conflict(
                evidence_ids=list(set(evidence_ids)),
                conflict_type="duplicate_evidence",
                description="Same evidence used for multiple clauses",
            ))

        assessment = TrustAssessment(
            subject_did=subject_did,
            policy_id=policy_id,
            policy_version=policy_version,
            passed=all_satisfied and len(conflicts) == 0,
            confidence=confidence,
            evidence_used=evidence_used,
            conflicts=conflicts,
            explanation=explanation,
            valid_until=(datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )).isoformat(),
        )
        assessment.assessment_hash = assessment.compute_hash()
        return assessment

    @staticmethod
    def _default_pqc_clauses() -> dict[str, dict[str, Any]]:
        """Default PQC readiness policy clauses."""
        return {
            "no_rsa_1024": {
                "required_claims": ["no_rsa_1024"],
                "weight": 0.3,
            },
            "tls_min_2048": {
                "required_claims": ["tls_min_key_bits"],
                "weight": 0.25,
            },
            "pqc_plan_exists": {
                "required_claims": ["migration_plan_date"],
                "weight": 0.2,
            },
            "no_weak_hash": {
                "required_claims": ["no_md5_sha1_signing"],
                "weight": 0.15,
            },
            "vendor_attestations": {
                "required_claims": ["vendor_pqc_ready_count"],
                "weight": 0.1,
            },
        }
