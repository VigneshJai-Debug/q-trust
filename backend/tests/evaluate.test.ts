import { describe, it, expect } from "vitest";
import { evaluate } from "../src/services/evaluate.js";

describe("evaluate service", () => {
  const baseRequest = {
    subject_did: "did:ethr:0x1234",
    policy_id: "pqc-readiness-v1",
    policy_version: "1.0",
  };

  it("returns high confidence with all evidence", () => {
    const result = evaluate({
      ...baseRequest,
      evidence: [
        { evidence_id: "e1", evidence_type: "scan", claims: { no_rsa_1024: true } },
        { evidence_id: "e2", evidence_type: "scan", claims: { tls_min_key_bits: 2048 } },
        { evidence_id: "e3", evidence_type: "plan", claims: { migration_plan_date: "2025-12-31" } },
        { evidence_id: "e4", evidence_type: "scan", claims: { no_md5_sha1_signing: true } },
        { evidence_id: "e5", evidence_type: "vendor", claims: { vendor_pqc_ready_count: 5 } },
      ],
    });

    expect(result.passed).toBe(true);
    expect(result.confidence).toBe(1.0);
    expect(result.evidence_used).toHaveLength(5);
  });

  it("returns low confidence with no evidence", () => {
    const result = evaluate({
      ...baseRequest,
      evidence: [],
    });

    expect(result.passed).toBe(false);
    expect(result.confidence).toBe(0);
    expect(result.evidence_used).toHaveLength(0);
  });

  it("returns partial confidence with some evidence", () => {
    const result = evaluate({
      ...baseRequest,
      evidence: [
        { evidence_id: "e1", evidence_type: "scan", claims: { no_rsa_1024: true } },
      ],
    });

    expect(result.passed).toBe(false);
    expect(result.confidence).toBeGreaterThan(0);
    expect(result.confidence).toBeLessThan(1);
  });

  it("generates unique assessment IDs", () => {
    const r1 = evaluate(baseRequest);
    const r2 = evaluate(baseRequest);
    expect(r1.assessment_id).not.toBe(r2.assessment_id);
  });

  it("uses default policy when none provided", () => {
    const result = evaluate({
      ...baseRequest,
      evidence: [
        { evidence_id: "e1", evidence_type: "scan", claims: { no_rsa_1024: true } },
        { evidence_id: "e2", evidence_type: "scan", claims: { tls_min_key_bits: 2048 } },
        { evidence_id: "e3", evidence_type: "plan", claims: { migration_plan_date: "2025-12-31" } },
        { evidence_id: "e4", evidence_type: "scan", claims: { no_md5_sha1_signing: true } },
        { evidence_id: "e5", evidence_type: "vendor", claims: { vendor_pqc_ready_count: 5 } },
      ],
    });
    expect(result.confidence).toBe(1.0);
  });
});
