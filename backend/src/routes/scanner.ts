import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, promises as fsp, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Type } from "@sinclair/typebox";
import type { FastifyInstance } from "fastify";
import { requireApiKey } from "../middleware/auth.js";
import {
  ScanRequestSchema,
  ScanFullRequestSchema,
  ScanResponseSchema,
  ErrorResponseSchema,
  RiskScoreSchema,
  ScoredFindingsResponseSchema,
  ComplianceEvaluateSchema,
  ComplianceEvaluateResponseSchema,
  EvidenceCreateSchema,
  EvidenceCreateResponseSchema,
  EvidenceVerifySchema,
} from "../schemas/index.js";

const scanResponseSchemas = {
  200: ScanResponseSchema,
  400: ErrorResponseSchema,
  403: ErrorResponseSchema,
  503: ErrorResponseSchema,
};

const execFileAsync = promisify(execFile);

const INSPECTOR_SCRIPT = fileURLToPath(new URL("../../scripts/run_inspector.py", import.meta.url));

/**
 * Execute the real Python inspector and parse its JSON output.
 * Fails loudly (throws) — callers must NEVER substitute fabricated findings.
 */
async function runInspector(args: string[]): Promise<any> {
  const pythonBin = process.env.QTRUST_INSPECTOR_PYTHON || "python3";
  const script = process.env.QTRUST_INSPECTOR_SCRIPT || INSPECTOR_SCRIPT;
  const { stdout } = await execFileAsync(pythonBin, [script, ...args], {
    timeout: 60_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  return JSON.parse(stdout);
}

/** Validate a scan directory against SSRF/path-traversal abuse. Throws on invalid input. */
async function validateScanDirectory(rawDir: string): Promise<string> {
  if (!path.isAbsolute(rawDir)) {
    throw Object.assign(new Error("directory must be an absolute path"), { statusCode: 400 });
  }
  // Resolve symlinks/.. segments so the allowed-roots check cannot be bypassed.
  let resolved: string;
  try {
    resolved = await fsp.realpath(path.resolve(rawDir));
  } catch {
    throw Object.assign(new Error("directory does not exist"), { statusCode: 400 });
  }
  const stat = await fsp.stat(resolved).catch(() => null);
  if (!stat?.isDirectory()) {
    throw Object.assign(new Error("path is not a directory"), { statusCode: 400 });
  }
  const allowedRootsRaw = process.env.QTRUST_SCAN_ALLOWED_ROOTS;
  if (!allowedRootsRaw && process.env.NODE_ENV === "production") {
    // Fail closed: in production an unset allowlist would let any caller scan
    // arbitrary absolute paths on this host.
    throw Object.assign(
      new Error("QTRUST_SCAN_ALLOWED_ROOTS must be configured in production"),
      { statusCode: 503 },
    );
  }
  if (allowedRootsRaw) {
    const roots = allowedRootsRaw
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean);
    const allowed = roots.some((root) => resolved === root || resolved.startsWith(root + path.sep));
    if (!allowed) {
      throw Object.assign(
        new Error(`directory is outside allowed scan roots (${allowedRootsRaw})`),
        { statusCode: 403 },
      );
    }
  }
  return resolved;
}

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

interface LedgerEntry {
  version: string;
  data: unknown;
  integrityHash: string;
  previousHash: string;
  chainIndex: number;
}

const GENESIS_HASH = "0".repeat(64);

// Evidence chain persistence: JSONL append-only log so the SHA-256 chain
// survives restarts. Primary store is the file below; if persistence fails
// (read-only fs, bad path) the chain degrades gracefully to in-memory only.
const EVIDENCE_DB_PATH =
  process.env.QTRUST_EVIDENCE_DB_PATH ||
  path.join(process.env.QTRUST_DATA_DIR || "/var/lib/qtrust", "evidence_chain.jsonl");

const evidenceChain: LedgerEntry[] = [];

/** Load persisted chain entries from the JSONL evidence log at module init. */
function loadEvidenceChain(): void {
  if (!existsSync(EVIDENCE_DB_PATH)) {
    return;
  }
  let raw: string;
  try {
    raw = readFileSync(EVIDENCE_DB_PATH, "utf8");
  } catch (err) {
    console.warn(
      "Evidence chain unreadable at",
      EVIDENCE_DB_PATH,
      "— starting empty:",
      err instanceof Error ? err.message : err,
    );
    return;
  }
  const lines = raw.split("\n");
  while (lines.length > 0 && lines[lines.length - 1].trim() === "") {
    lines.pop();
  }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      const entry = JSON.parse(line) as LedgerEntry;
      if (
        typeof entry.chainIndex !== "number" ||
        typeof entry.previousHash !== "string" ||
        typeof entry.integrityHash !== "string"
      ) {
        throw new Error("entry missing chain metadata");
      }
      evidenceChain.push(entry);
    } catch {
      // A torn final write (crash mid-append) leaves a partial trailing line —
      // skip it quietly-ish; corruption elsewhere is worth a louder warning.
      if (i === lines.length - 1) {
        console.warn(
          `Evidence chain: skipping incomplete trailing line in ${EVIDENCE_DB_PATH}`,
        );
      } else {
        console.warn(
          `Evidence chain: skipping corrupt line ${i + 1} in ${EVIDENCE_DB_PATH}`,
        );
      }
    }
  }
}

loadEvidenceChain();

/** Append one JSONL line per entry. Creates the directory on first write; never rewrites existing data. */
function persistEvidenceEntry(entry: LedgerEntry): void {
  try {
    mkdirSync(path.dirname(EVIDENCE_DB_PATH), { recursive: true });
    appendFileSync(EVIDENCE_DB_PATH, `${JSON.stringify(entry)}\n`, "utf8");
  } catch (err) {
    console.warn(
      `Evidence chain persistence failed at ${EVIDENCE_DB_PATH} — continuing in memory only:`,
      err instanceof Error ? err.message : err,
    );
  }
}

function computeIntegrityHash(entry: Omit<LedgerEntry, "integrityHash">): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        data: entry.data,
        previousHash: entry.previousHash,
        chainIndex: entry.chainIndex,
      }),
    )
    .digest("hex");
}

function generateEvidenceLedger(data: {
  scanResultHash: string;
  scanTarget: string;
  findingsCount: number;
  riskSummary: object;
  timestamp: string;
}): LedgerEntry {
  const last = evidenceChain.length ? evidenceChain[evidenceChain.length - 1] : null;
  const entry: Omit<LedgerEntry, "integrityHash"> = {
    version: "1.0",
    data,
    previousHash: last ? last.integrityHash : GENESIS_HASH,
    chainIndex: last ? last.chainIndex + 1 : 0,
  };
  const full: LedgerEntry = { ...entry, integrityHash: computeIntegrityHash(entry) };
  evidenceChain.push(full);
  persistEvidenceEntry(full);
  return full;
}

/** Re-compute every hash and validate the whole chain. Returns a reason on any mismatch/tamper. */
function verifyEvidenceChain(entries: LedgerEntry[]): { valid: boolean; reason?: string; failedIndex?: number } {
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (typeof entry.chainIndex !== "number" || typeof entry.previousHash !== "string") {
      return { valid: false, reason: "malformed_entry", failedIndex: i };
    }
    const expectedPrevious = i === 0 ? GENESIS_HASH : entries[i - 1].integrityHash;
    if (entry.previousHash !== expectedPrevious) {
      return { valid: false, reason: "previous_hash_mismatch", failedIndex: i };
    }
    if (entry.chainIndex !== i) {
      return { valid: false, reason: "chain_index_mismatch", failedIndex: i };
    }
    const recomputed = computeIntegrityHash(entry);
    if (recomputed !== entry.integrityHash) {
      return { valid: false, reason: "integrity_hash_mismatch", failedIndex: i };
    }
  }
  return { valid: true };
}

export async function registerScannerRoutes(app: FastifyInstance): Promise<void> {
  const scanHistory: any[] = [];

  app.get("/v1/health", async () => {
    return { status: "ok", version: "1.0.0", services: { scanner: true, risk: true, compliance: true } };
  });

  app.post("/v1/scan/source", {
    preHandler: requireApiKey,
    schema: { body: ScanRequestSchema, response: scanResponseSchemas },
  }, async (request, reply) => {
    const { directory } = request.body as { directory: string };
    let resolvedDir: string;
    try {
      resolvedDir = await validateScanDirectory(directory);
    } catch (err) {
      reply.code((err as { statusCode?: number }).statusCode === 403 ? 403 : 400);
      return { error: (err as Error).message };
    }
    let result: { findings?: any[]; error?: string };
    try {
      result = await runInspector(["--scan-type", "source", "--path", resolvedDir]);
    } catch (err) {
      request.log.error(err, "Inspector scan failed");
      reply.code(503);
      return {
        error: `Cryptographic scanner unavailable or failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (result?.error) {
      reply.code(503);
      return { error: `Cryptographic scanner failed: ${result.error}` };
    }
    const findings = Array.isArray(result.findings) ? result.findings : [];
    scanHistory.push({ target: resolvedDir, type: "source", timestamp: new Date().toISOString(), count: findings.length });
    return { directory: resolvedDir, findings, scanType: "source", timestamp: new Date().toISOString() };
  });

  app.post("/v1/scan/manifests", {
    preHandler: requireApiKey,
    schema: { body: ScanRequestSchema, response: scanResponseSchemas },
  }, async (request, reply) => {
    const { directory } = request.body as { directory: string };
    let resolvedDir: string;
    try {
      resolvedDir = await validateScanDirectory(directory);
    } catch (err) {
      reply.code((err as { statusCode?: number }).statusCode === 403 ? 403 : 400);
      return { error: (err as Error).message };
    }
    let result: { findings?: any[]; error?: string };
    try {
      result = await runInspector(["--scan-type", "manifests", "--path", resolvedDir]);
    } catch (err) {
      request.log.error(err, "Inspector scan failed");
      reply.code(503);
      return {
        error: `Cryptographic scanner unavailable or failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (result?.error) {
      reply.code(503);
      return { error: `Cryptographic scanner failed: ${result.error}` };
    }
    const findings = Array.isArray(result.findings) ? result.findings : [];
    scanHistory.push({ target: resolvedDir, type: "manifests", timestamp: new Date().toISOString(), count: findings.length });
    return { directory: resolvedDir, findings, scanType: "manifests", timestamp: new Date().toISOString() };
  });

  app.post("/v1/scan/full", {
    preHandler: requireApiKey,
    schema: { body: ScanFullRequestSchema, response: scanResponseSchemas },
  }, async (request, reply) => {
    const { target, includeSource = true, includeManifests = true } = request.body as {
      target: string;
      includeSource?: boolean;
      includeManifests?: boolean;
    };
    if (!includeSource && !includeManifests) {
      reply.code(400);
      return { error: "at least one of includeSource or includeManifests must be true" };
    }
    let resolvedTarget: string;
    try {
      resolvedTarget = await validateScanDirectory(target);
    } catch (err) {
      reply.code((err as { statusCode?: number }).statusCode === 403 ? 403 : 400);
      return { error: (err as Error).message };
    }
    const scanType =
      includeSource && includeManifests ? "full" : includeSource ? "source" : "manifests";
    let result: { findings?: any[]; error?: string };
    try {
      result = await runInspector(["--scan-type", scanType, "--path", resolvedTarget]);
    } catch (err) {
      request.log.error(err, "Inspector scan failed");
      reply.code(503);
      return {
        error: `Cryptographic scanner unavailable or failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (result?.error) {
      reply.code(503);
      return { error: `Cryptographic scanner failed: ${result.error}` };
    }
    const allFindings = Array.isArray(result.findings) ? result.findings : [];
    scanHistory.push({ target: resolvedTarget, type: "full", timestamp: new Date().toISOString(), count: allFindings.length });
    return { target: resolvedTarget, findings: allFindings, scanType: "full", timestamp: new Date().toISOString() };
  });

  app.post("/v1/risk/score", {
    schema: { body: RiskScoreSchema, response: { 200: ScoredFindingsResponseSchema } },
  }, async (request) => {
    const { findings } = request.body as { findings: any[] };
    const scored = findings.map(computeRiskFinding);
    return { findings: scored };
  });

  app.post("/v1/risk/summary", {
    schema: {
      body: RiskScoreSchema,
      response: {
        200: Type.Object({
          totalFindings: Type.Integer(),
          critical: Type.Integer(),
          high: Type.Integer(),
          medium: Type.Integer(),
          low: Type.Integer(),
          none: Type.Integer(),
          averageRiskScore: Type.Integer(),
          overallRiskLevel: Type.String(),
        }),
      },
    },
  }, async (request) => {
    const { findings } = request.body as { findings: any[] };
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

  app.post("/v1/compliance/evaluate", {
    schema: { body: ComplianceEvaluateSchema, response: { 200: ComplianceEvaluateResponseSchema } },
  }, async (request) => {
    const { findings, framework } = request.body as { findings: any[]; framework: string };
    const evaluator = framework.toUpperCase() === "CNSA" ? evaluateCNSACompliance : evaluateNISTCompliance;
    const results = findings.map((f) => ({
      ...f,
      compliance: evaluator(f),
    }));
    const compliant = results.filter((r) => r.compliance.compliant).length;
    const nonCompliant = results.length - compliant;
    return { framework, results, compliant, nonCompliant, total: results.length };
  });

  app.post("/v1/compliance/full-report", {
    schema: { body: RiskScoreSchema },
  }, async (request) => {
    const { findings } = request.body as { findings: any[] };
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

  app.post("/v1/evidence/create", {
    schema: { body: EvidenceCreateSchema, response: { 200: EvidenceCreateResponseSchema } },
  }, async (request) => {
    const { scanResultHash, scanTarget, findingsCount, riskSummary } = request.body as {
      scanResultHash: string;
      scanTarget: string;
      findingsCount: number;
      riskSummary: object;
    };
    const ledger = generateEvidenceLedger({
      scanResultHash,
      scanTarget,
      findingsCount,
      riskSummary,
      timestamp: new Date().toISOString(),
    });
    return { ledger };
  });

  app.post("/v1/evidence/verify", {
    schema: { body: EvidenceVerifySchema },
  }, async (request) => {
    const { ledger } = request.body as { ledger: any };
    if (typeof ledger.previousHash !== "string" || typeof ledger.chainIndex !== "number") {
      return {
        valid: false,
        reason: "malformed_entry",
        detail: "Ledger entry is missing chain metadata (previousHash/chainIndex)",
        expectedHash: null,
        providedHash: ledger.integrityHash,
      };
    }

    // 1. Re-compute the submitted entry's own integrity hash.
    const recomputed = computeIntegrityHash(ledger);
    if (recomputed !== ledger.integrityHash) {
      return {
        valid: false,
        reason: "integrity_hash_mismatch",
        expectedHash: recomputed,
        providedHash: ledger.integrityHash,
      };
    }

    // 2. Validate the whole in-memory chain (tamper detection across history).
    const chainCheck = verifyEvidenceChain(evidenceChain);
    if (!chainCheck.valid) {
      return {
        valid: false,
        reason: `chain_broken_at_index_${chainCheck.failedIndex}`,
        detail: chainCheck.reason,
      };
    }

    // 3. If this entry was issued by this node, confirm it still matches the
    //    chain entry at its index (detects tampering of historical entries).
    const known = evidenceChain[ledger.chainIndex];
    if (known && known.integrityHash !== ledger.integrityHash) {
      return {
        valid: false,
        reason: "entry_not_in_chain",
        detail: "Entry does not match the chain record at its index",
      };
    }
    if (!known) {
      return {
        valid: false,
        reason: "unknown_chain_index",
        detail: `No ledger entry exists at chainIndex ${ledger.chainIndex} on this node`,
      };
    }

    return { valid: true, expectedHash: recomputed, providedHash: ledger.integrityHash, chainLength: evidenceChain.length };
  });

  app.post("/v1/roadmap/generate", {
    schema: { body: RiskScoreSchema },
  }, async (request) => {
    const { findings, dailyRate } = request.body as { findings: any[]; dailyRate?: number };
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
