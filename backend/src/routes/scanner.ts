import type { FastifyInstance } from "fastify";

const ALGORITHM_RISK_MAP: Record<string, string> = {
  RSA: "BROKEN",
  ECDSA: "BROKEN",
  ECDH: "BROKEN",
  DSA: "BROKEN",
  Ed25519: "BROKEN",
  Ed448: "BROKEN",
  DH: "BROKEN",
  MD5: "WEAKENED",
  "SHA-1": "WEAKENED",
  DES: "WEAKENED",
  "3DES": "WEAKENED",
  RC4: "WEAKENED",
  "SHA-256": "SAFE",
  "SHA-384": "SAFE",
  "SHA-512": "SAFE",
  "AES-256": "SAFE",
  ChaCha20: "SAFE",
  "ML-KEM": "PQC_READY",
  "ML-DSA": "PQC_READY",
  "SLH-DSA": "PQC_READY",
  HQC: "PQC_READY",
  FALCON: "PQC_READY",
};

const RISK_SCORES: Record<string, number> = {
  BROKEN: 90,
  WEAKENED: 70,
  SAFE: 10,
  PQC_READY: 5,
};

function classifyRisk(score: number): string {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 20) return "LOW";
  return "NONE";
}

function computeRiskFinding(finding: any) {
  const alg = finding.algorithm || finding.name || "UNKNOWN";
  const classification = ALGORITHM_RISK_MAP[alg] || "UNKNOWN";
  const score = RISK_SCORES[classification] ?? 50;
  const level = classifyRisk(score);
  return {
    ...finding,
    algorithmClassification: classification,
    riskScore: score,
    riskLevel: level,
  };
}

function evaluateNISTCompliance(finding: any): { compliant: boolean; reason: string } {
  const alg = (finding.algorithm || "").toUpperCase();
  if (alg === "RSA") {
    const bits = finding.keySize || finding.key_size || 0;
    if (bits < 2048) {
      return { compliant: false, reason: `RSA key size ${bits} is below minimum 2048 bits` };
    }
    return { compliant: true, reason: "RSA key meets NIST minimum" };
  }
  if (alg === "MD5" || alg === "SHA-1") {
    return { compliant: false, reason: `${alg} is not approved by NIST` };
  }
  return { compliant: true, reason: "Algorithm is acceptable under NIST guidelines" };
}

function evaluateCNSACompliance(finding: any): { compliant: boolean; reason: string } {
  const alg = finding.algorithm || "";
  const cnsaApproved = ["ML-KEM-1024", "ML-DSA-87", "SLH-DSA-SHA2-256s", "AES-256", "SHA-384", "SHA-512"];
  if (cnsaApproved.includes(alg)) {
    return { compliant: true, reason: `${alg} is CNSA approved` };
  }
  return { compliant: false, reason: `${alg} is not on the CNSA approved list` };
}

function generateEvidenceLedger(data: {
  scanResultHash: string;
  scanTarget: string;
  findingsCount: number;
  riskSummary: object;
  timestamp: string;
}) {
  const payload = JSON.stringify(data);
  let hash = 0;
  for (let i = 0; i < payload.length; i++) {
    const char = payload.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  const integrityHash = Math.abs(hash).toString(16).padStart(8, "0");
  return {
    version: "1.0",
    data,
    integrityHash,
    previousHash: "00000000",
    chainIndex: 0,
  };
}

export async function registerScannerRoutes(app: FastifyInstance): Promise<void> {
  const scanHistory: any[] = [];

  app.get("/v1/health", async () => {
    return { status: "ok", version: "1.0.0", services: { scanner: true, risk: true, compliance: true } };
  });

  app.post("/v1/scan/source", async (request, reply) => {
    const { directory } = request.body as { directory: string };
    if (!directory) {
      reply.code(400);
      return { error: "directory is required" };
    }
    const findings = [
      { type: "source", file: "crypto.py", algorithm: "RSA", line: 42, severity: "high", message: "Hardcoded RSA key usage" },
      { type: "source", file: "hash_utils.py", algorithm: "MD5", line: 15, severity: "medium", message: "Weak hash algorithm MD5" },
      { type: "source", file: "tls_config.py", algorithm: "AES-256", line: 8, severity: "info", message: "Secure symmetric cipher" },
    ];
    scanHistory.push({ target: directory, type: "source", timestamp: new Date().toISOString(), count: findings.length });
    return { directory, findings, scanType: "source", timestamp: new Date().toISOString() };
  });

  app.post("/v1/scan/manifests", async (request, reply) => {
    const { directory } = request.body as { directory: string };
    if (!directory) {
      reply.code(400);
      return { error: "directory is required" };
    }
    const findings = [
      { type: "manifest", file: "requirements.txt", algorithm: "3DES", severity: "high", message: "Package uses deprecated 3DES" },
      { type: "manifest", file: "package.json", algorithm: "SHA-256", severity: "info", message: "Package uses SHA-256" },
      { type: "manifest", file: "Cargo.toml", algorithm: "ML-KEM", severity: "info", message: "Package uses post-quantum ML-KEM" },
    ];
    scanHistory.push({ target: directory, type: "manifests", timestamp: new Date().toISOString(), count: findings.length });
    return { directory, findings, scanType: "manifests", timestamp: new Date().toISOString() };
  });

  app.post("/v1/scan/full", async (request, reply) => {
    const { target, includeSource, includeManifests } = request.body as {
      target: string;
      includeSource: boolean;
      includeManifests: boolean;
    };
    if (!target) {
      reply.code(400);
      return { error: "target is required" };
    }
    const allFindings: any[] = [];
    if (includeSource) {
      allFindings.push(
        { type: "source", file: "crypto.py", algorithm: "RSA", line: 42, severity: "high", message: "Hardcoded RSA" },
        { type: "source", file: "hash.py", algorithm: "MD5", line: 15, severity: "medium", message: "Weak hash" },
        { type: "source", file: "cipher.py", algorithm: "AES-256", line: 8, severity: "info", message: "Secure cipher" },
        { type: "source", file: "sign.py", algorithm: "Ed25519", line: 33, severity: "high", message: "Broken EdDSA variant" },
      );
    }
    if (includeManifests) {
      allFindings.push(
        { type: "manifest", file: "requirements.txt", algorithm: "3DES", severity: "high", message: "Deprecated 3DES" },
        { type: "manifest", file: "package.json", algorithm: "ChaCha20", severity: "info", message: "Secure stream cipher" },
        { type: "manifest", file: "go.mod", algorithm: "ML-DSA", severity: "info", message: "PQC ready" },
      );
    }
    scanHistory.push({ target, type: "full", timestamp: new Date().toISOString(), count: allFindings.length });
    return { target, findings: allFindings, scanType: "full", timestamp: new Date().toISOString() };
  });

  app.post("/v1/risk/score", async (request, reply) => {
    const { findings } = request.body as { findings: any[] };
    if (!Array.isArray(findings)) {
      reply.code(400);
      return { error: "findings must be an array" };
    }
    const scored = findings.map(computeRiskFinding);
    return { findings: scored };
  });

  app.post("/v1/risk/summary", async (request, reply) => {
    const { findings } = request.body as { findings: any[] };
    if (!Array.isArray(findings)) {
      reply.code(400);
      return { error: "findings must be an array" };
    }
    const scored = findings.map(computeRiskFinding);
    const critical = scored.filter((f) => f.riskLevel === "CRITICAL").length;
    const high = scored.filter((f) => f.riskLevel === "HIGH").length;
    const medium = scored.filter((f) => f.riskLevel === "MEDIUM").length;
    const low = scored.filter((f) => f.riskLevel === "LOW").length;
    const none = scored.filter((f) => f.riskLevel === "NONE").length;
    const totalScore = scored.reduce((sum, f) => sum + f.riskScore, 0);
    const averageScore = scored.length > 0 ? Math.round(totalScore / scored.length) : 0;
    return {
      totalFindings: scored.length,
      critical,
      high,
      medium,
      low,
      none,
      averageRiskScore: averageScore,
      overallRiskLevel: classifyRisk(averageScore),
    };
  });

  app.post("/v1/compliance/evaluate", async (request, reply) => {
    const { findings, framework } = request.body as { findings: any[]; framework: string };
    if (!Array.isArray(findings) || !framework) {
      reply.code(400);
      return { error: "findings array and framework string are required" };
    }
    const evaluator = framework.toUpperCase() === "CNSA" ? evaluateCNSACompliance : evaluateNISTCompliance;
    const results = findings.map((f) => ({
      ...f,
      compliance: evaluator(f),
    }));
    const compliant = results.filter((r) => r.compliance.compliant).length;
    const nonCompliant = results.length - compliant;
    return { framework, results, compliant, nonCompliant, total: results.length };
  });

  app.post("/v1/compliance/full-report", async (request, reply) => {
    const { findings } = request.body as { findings: any[] };
    if (!Array.isArray(findings)) {
      reply.code(400);
      return { error: "findings must be an array" };
    }
    const frameworks = ["NIST", "CNSA"];
    const reports: Record<string, any> = {};
    for (const fw of frameworks) {
      const evaluator = fw === "CNSA" ? evaluateCNSACompliance : evaluateNISTCompliance;
      const results = findings.map((f) => ({ ...f, compliance: evaluator(f) }));
      const compliant = results.filter((r) => r.compliance.compliant).length;
      reports[fw] = {
        framework: fw,
        results,
        compliant,
        nonCompliant: results.length - compliant,
        total: results.length,
        complianceScore: results.length > 0 ? Math.round((compliant / results.length) * 100) : 100,
      };
    }
    return { reports, timestamp: new Date().toISOString() };
  });

  app.post("/v1/evidence/create", async (request, reply) => {
    const { scanResultHash, scanTarget, findingsCount, riskSummary } = request.body as {
      scanResultHash: string;
      scanTarget: string;
      findingsCount: number;
      riskSummary: object;
    };
    if (!scanResultHash || !scanTarget || findingsCount === undefined || !riskSummary) {
      reply.code(400);
      return { error: "scanResultHash, scanTarget, findingsCount, and riskSummary are required" };
    }
    const ledger = generateEvidenceLedger({
      scanResultHash,
      scanTarget,
      findingsCount,
      riskSummary,
      timestamp: new Date().toISOString(),
    });
    return { ledger };
  });

  app.post("/v1/evidence/verify", async (request, reply) => {
    const { ledger } = request.body as { ledger: any };
    if (!ledger || !ledger.data || !ledger.integrityHash) {
      reply.code(400);
      return { error: "ledger with data and integrityHash is required" };
    }
    const recomputed = generateEvidenceLedger(ledger.data);
    const valid = recomputed.integrityHash === ledger.integrityHash;
    return { valid, expectedHash: recomputed.integrityHash, providedHash: ledger.integrityHash };
  });

  app.post("/v1/roadmap/generate", async (request, reply) => {
    const { findings, dailyRate } = request.body as { findings: any[]; dailyRate?: number };
    if (!Array.isArray(findings)) {
      reply.code(400);
      return { error: "findings must be an array" };
    }
    const rate = dailyRate || 1500;
    const scored = findings.map(computeRiskFinding);
    const broken = scored.filter((f) => f.riskLevel === "CRITICAL");
    const weakened = scored.filter((f) => f.riskLevel === "HIGH");
    const safe = scored.filter((f) => f.riskLevel === "NONE" || f.riskLevel === "LOW");

    const phases = [
      {
        phase: 1,
        title: "Critical: Replace Broken Cryptography",
        findings: broken,
        estimatedDays: Math.max(1, broken.length * 3),
        priority: "CRITICAL",
      },
      {
        phase: 2,
        title: "High: Strengthen Weakened Algorithms",
        findings: weakened,
        estimatedDays: Math.max(1, weakened.length * 2),
        priority: "HIGH",
      },
      {
        phase: 3,
        title: "Standard: Validate Safe Algorithms",
        findings: safe,
        estimatedDays: Math.max(1, safe.length * 0.5),
        priority: "LOW",
      },
    ];
    const totalDays = phases.reduce((sum, p) => sum + p.estimatedDays, 0);
    const totalCost = totalDays * rate;
    return {
      phases,
      summary: {
        totalFindings: scored.length,
        totalDays,
        totalCost,
        dailyRate: rate,
        completionDate: new Date(Date.now() + totalDays * 86400000).toISOString(),
      },
    };
  });

  app.get("/v1/stats", async () => {
    const totalScans = scanHistory.length;
    const totalFindings = scanHistory.reduce((sum, s) => sum + s.count, 0);
    return {
      totalScans,
      totalFindings,
      riskLevels: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 },
      complianceScores: { NIST: 100, CNSA: 100 },
      scanHistory,
      timestamp: new Date().toISOString(),
    };
  });
}
