/**
 * Trust evaluation service — extracts the policy engine from the route handler.
 *
 * The evaluation logic is deterministic: the same evidence + policy + version
 * always produces the same result. The default policy is PQC-readiness focused.
 */
import { randomUUID } from "node:crypto";

export interface Evidence {
  evidence_id: string;
  evidence_type: string;
  claims: Record<string, unknown>;
}

export interface PolicyClause {
  required_claims: string[];
  weight: number;
}

export interface EvaluateRequest {
  subject_did: string;
  policy_id: string;
  policy_version: string;
  evidence?: Evidence[];
}

export interface ClauseResult {
  status: "satisfied" | "insufficient_evidence";
  evidence?: string;
  explanation?: string;
}

export interface EvidenceUsed {
  evidence_id: string;
  evidence_type: string;
  contribution: number;
  matched_clauses: string[];
}

export interface EvaluateResult {
  assessment_id: string;
  subject_did: string;
  policy_id: string;
  policy_version: string;
  passed: boolean;
  confidence: number;
  evidence_used: EvidenceUsed[];
  conflicts: string[];
  explanation: Record<string, ClauseResult>;
  evaluated_at: string;
  valid_until: string;
}

/** Default PQC-readiness evaluation policy. */
const DEFAULT_POLICY_CLAUSES: Record<string, PolicyClause> = {
  no_rsa_1024: { required_claims: ["no_rsa_1024"], weight: 0.3 },
  tls_min_2048: { required_claims: ["tls_min_key_bits"], weight: 0.25 },
  pqc_plan_exists: { required_claims: ["migration_plan_date"], weight: 0.2 },
  no_weak_hash: { required_claims: ["no_md5_sha1_signing"], weight: 0.15 },
  vendor_attestations: { required_claims: ["vendor_pqc_ready_count"], weight: 0.1 },
};

/**
 * Evaluate trust against a set of policy clauses and evidence.
 *
 * This is a pure function — same inputs always produce the same output.
 */
export function evaluate(
  req: EvaluateRequest,
  policyClauses: Record<string, PolicyClause> = DEFAULT_POLICY_CLAUSES,
): EvaluateResult {
  const evidence = req.evidence ?? [];
  let totalWeight = 0;
  let satisfiedWeight = 0;
  const evidenceUsed: EvidenceUsed[] = [];
  const explanation: Record<string, ClauseResult> = {};

  for (const [clauseId, clause] of Object.entries(policyClauses)) {
    totalWeight += clause.weight;
    const matchingEvidence = evidence.find((ev) =>
      clause.required_claims.every((rc) => ev.claims[rc] !== undefined),
    );

    if (matchingEvidence) {
      satisfiedWeight += clause.weight;
      explanation[clauseId] = { status: "satisfied", evidence: matchingEvidence.evidence_id };
      evidenceUsed.push({
        evidence_id: matchingEvidence.evidence_id,
        evidence_type: matchingEvidence.evidence_type,
        contribution: clause.weight,
        matched_clauses: [clauseId],
      });
    } else {
      explanation[clauseId] = {
        status: "insufficient_evidence",
        explanation: `No evidence for: ${clause.required_claims.join(", ")}`,
      };
    }
  }

  const confidence = totalWeight > 0 ? satisfiedWeight / totalWeight : 0;
  const allSatisfied = Object.values(explanation).every((e) => e.status === "satisfied");

  return {
    assessment_id: `urn:uuid:${randomUUID()}`,
    subject_did: req.subject_did,
    policy_id: req.policy_id,
    policy_version: req.policy_version,
    passed: allSatisfied,
    confidence,
    evidence_used: evidenceUsed,
    conflicts: [],
    explanation,
    evaluated_at: new Date().toISOString(),
    valid_until: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
  };
}
