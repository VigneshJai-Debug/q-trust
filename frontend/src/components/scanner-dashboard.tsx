"use client";

/**
 * Scanner dashboard — scan targets for PQC vulnerabilities, view risk scores,
 * compliance status, migration roadmap, and evidence records.
 *
 * Endpoints used are the ones that actually exist on the backend:
 *   POST /v1/scan/full            POST /v1/risk/score
 *   POST /v1/compliance/evaluate  POST /v1/roadmap/generate
 *   POST /v1/evidence/create      POST /v1/evidence/verify
 * Panels marked "(client-side)" are computed locally from fetched data.
 */
import { useState } from "react";
import * as Tabs from "@radix-ui/react-tabs";
import { API_BASE_URL } from "@/lib/api";
import { Button } from "@/components/ui/button";
import SideChannelPanel from "@/components/side-channel-panel";
import { ShieldCheckIcon, XCircleIcon, ClockIcon } from "@/app/icons";

/* -------------------------------------------------------------------------- */
/*  Types                                                                      */
/* -------------------------------------------------------------------------- */

interface ScanFinding {
  type?: string;
  file: string;
  algorithm: string;
  line?: number;
  severity?: string;
  message?: string;
}

interface ScanSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  algorithmsDetected: string[];
}

/** Shape returned by POST /v1/scan/full (summary is computed client-side). */
interface ScanResult {
  target: string;
  scanType: string;
  timestamp: string;
  findings: ScanFinding[];
  summary: ScanSummary;
}

type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

/** Shape returned by POST /v1/risk/score. */
interface ScoredFinding extends ScanFinding {
  algorithmClassification: string;
  riskScore: number;
  riskLevel: RiskLevel;
}

interface ComplianceFinding extends ScanFinding {
  compliance: { compliant: boolean; reason: string };
}

/** Shape returned by POST /v1/compliance/evaluate (+ client-side score). */
interface ComplianceReport {
  framework: string;
  results: ComplianceFinding[];
  compliant: number;
  nonCompliant: number;
  total: number;
  scorePercent: number;
}

/** Shape returned by POST /v1/roadmap/generate. */
interface RoadmapPhase {
  phase: number;
  title: string;
  priority: string;
  estimatedDays: number;
  findings: ScanFinding[];
}

interface RoadmapSummary {
  totalFindings: number;
  totalDays: number;
  totalCost: number;
  dailyRate: number;
  completionDate: string;
}

interface Roadmap {
  phases: RoadmapPhase[];
  summary: RoadmapSummary;
}

/** Shape returned by POST /v1/evidence/create. */
interface EvidenceLedger {
  version: string;
  data: {
    scanResultHash: string;
    scanTarget: string;
    findingsCount: number;
    riskSummary: ScanSummary;
    timestamp: string;
  };
  integrityHash: string;
  previousHash: string;
  chainIndex: number;
}

/** Shape returned by POST /v1/evidence/verify. */
interface EvidenceVerifyResult {
  valid: boolean;
  expectedHash: string;
  providedHash: string;
}

/* -------------------------------------------------------------------------- */
/*  Tab configuration                                                          */
/* -------------------------------------------------------------------------- */

type TabId = "scan" | "risk" | "compliance" | "roadmap" | "evidence" | "sidechannel";

const TABS: { id: TabId; label: string }[] = [
  { id: "scan", label: "Scan" },
  { id: "risk", label: "Risk Scores" },
  { id: "compliance", label: "Compliance" },
  { id: "roadmap", label: "Roadmap" },
  { id: "evidence", label: "Evidence" },
  { id: "sidechannel", label: "Side Channel" },
];

const COMPLIANCE_FRAMEWORKS = [
  { value: "NIST", label: "NIST SP 800-131A" },
  { value: "CNSA", label: "CNSA 2.0" },
] as const;

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function severityColor(s: string) {
  switch (s.toLowerCase()) {
    case "critical":
      return "bg-rose-100 text-rose-700";
    case "high":
      return "bg-amber-100 text-amber-700";
    case "medium":
      return "bg-indigo-100 text-indigo-700";
    case "low":
      return "bg-emerald-100 text-emerald-700";
    case "info":
      return "bg-sky-100 text-sky-700";
    default:
      return "bg-slate-100 text-slate-600";
  }
}

function complianceColor(status: string) {
  switch (status) {
    case "pass":
      return "bg-emerald-50 text-emerald-700";
    case "fail":
      return "bg-rose-50 text-rose-700";
    case "warning":
      return "bg-amber-50 text-amber-700";
    default:
      return "bg-slate-50 text-slate-600";
  }
}

function Spinner() {
  return (
    <svg className="h-4 w-4 animate-spin text-current" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function safeName(input: string): string {
  return input.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "scan";
}

async function sha256Hex(input: string): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error("Web Crypto is unavailable in this context — cannot hash scan evidence.");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function summarizeFindings(findings: ScanFinding[]): ScanSummary {
  const algorithms = new Set<string>();
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let info = 0;
  for (const f of findings) {
    if (f.algorithm) algorithms.add(f.algorithm);
    switch ((f.severity ?? "").toLowerCase()) {
      case "critical":
        critical++;
        break;
      case "high":
        high++;
        break;
      case "medium":
        medium++;
        break;
      case "low":
        low++;
        break;
      default:
        info++;
    }
  }
  return {
    totalFindings: findings.length,
    critical,
    high,
    medium,
    low,
    info,
    algorithmsDetected: Array.from(algorithms).sort(),
  };
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errBody = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(errBody.error ?? `Request failed (${res.status})`);
  }
  return (await res.json()) as T;
}

/* Client-side CycloneDX-style CBOM generated from the returned findings. */
function buildCbom(result: ScanResult): Record<string, unknown> {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "Q-Trust", name: "Q-Trust Scanner Dashboard", version: "1.0" }],
      properties: [
        { name: "qtrust:generatedBy", value: "client-side export from scan findings" },
        { name: "qtrust:scanTarget", value: result.target },
        { name: "qtrust:scanTimestamp", value: result.timestamp },
      ],
    },
    components: result.findings.map((f, i) => ({
      type: "cryptographic-asset",
      "bom-ref": `qtrust-finding-${i + 1}`,
      name: f.algorithm,
      properties: [
        ...(f.file ? [{ name: "qtrust:file", value: f.file }] : []),
        ...(f.line !== undefined ? [{ name: "qtrust:line", value: String(f.line) }] : []),
        ...(f.severity ? [{ name: "qtrust:severity", value: f.severity }] : []),
        ...(f.message ? [{ name: "qtrust:message", value: f.message }] : []),
      ],
    })),
  };
}

/* Client-side SARIF 2.1.0 generated from the returned findings. */
function buildSarif(result: ScanResult): Record<string, unknown> {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Q-Trust PQC Scanner",
            version: "1.0",
            properties: { generatedBy: "client-side export from scan findings" },
          },
        },
        invocations: [{ endTimeUtc: new Date().toISOString() }],
        results: result.findings.map((f) => ({
          ruleId: f.algorithm,
          level:
            f.severity === "critical" || f.severity === "high"
              ? "error"
              : f.severity === "medium"
                ? "warning"
                : "note",
          message: { text: f.message ?? `${f.algorithm} usage detected` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                ...(f.line !== undefined ? { region: { startLine: f.line } } : {}),
              },
            },
          ],
        })),
      },
    ],
  };
}

/* -------------------------------------------------------------------------- */
/*  Main component                                                             */
/* -------------------------------------------------------------------------- */

export function ScannerDashboard() {
  /* ---- Scan state ---- */
  const [target, setTarget] = useState("");
  const [scanSource, setScanSource] = useState(true);
  const [scanManifest, setScanManifest] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState("");

  /* ---- Risk state ---- */
  const [riskScores, setRiskScores] = useState<ScoredFinding[]>([]);
  const [riskLoading, setRiskLoading] = useState(false);
  const [riskError, setRiskError] = useState("");

  /* ---- Compliance state ---- */
  const [complianceFramework, setComplianceFramework] = useState<string>(COMPLIANCE_FRAMEWORKS[0].value);
  const [complianceReport, setComplianceReport] = useState<ComplianceReport | null>(null);
  const [complianceLoading, setComplianceLoading] = useState(false);
  const [complianceError, setComplianceError] = useState("");

  /* ---- Roadmap state ---- */
  const [roadmapDailyRate, setRoadmapDailyRate] = useState("");
  const [roadmap, setRoadmap] = useState<Roadmap | null>(null);
  const [roadmapLoading, setRoadmapLoading] = useState(false);
  const [roadmapError, setRoadmapError] = useState("");

  /* ---- Evidence state ---- */
  const [evidenceLedger, setEvidenceLedger] = useState<EvidenceLedger | null>(null);
  const [evidenceVerify, setEvidenceVerify] = useState<EvidenceVerifyResult | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState("");
  const [verifyLoading, setVerifyLoading] = useState(false);

  /* ---- Export state ---- */
  const [exportLoading, setExportLoading] = useState<string | null>(null);

  /* ---- API calls ---- */

  async function runScan() {
    if (!target.trim()) return;
    setScanLoading(true);
    setScanError("");
    setScanResult(null);
    try {
      const data = await postJson<{
        target: string;
        scanType: string;
        timestamp: string;
        findings: ScanFinding[];
      }>("/v1/scan/full", {
        target: target.trim(),
        includeSource: scanSource,
        includeManifests: scanManifest,
      });
      setScanResult({ ...data, summary: summarizeFindings(data.findings) });
    } catch (err) {
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanLoading(false);
    }
  }

  async function fetchRiskScores() {
    if (!scanResult) return;
    setRiskLoading(true);
    setRiskError("");
    try {
      const data = await postJson<{ findings: ScoredFinding[] }>("/v1/risk/score", {
        findings: scanResult.findings,
      });
      setRiskScores(Array.isArray(data.findings) ? data.findings : []);
    } catch (err) {
      setRiskError(err instanceof Error ? err.message : String(err));
    } finally {
      setRiskLoading(false);
    }
  }

  async function fetchCompliance() {
    if (!scanResult) return;
    setComplianceLoading(true);
    setComplianceError("");
    try {
      const data = await postJson<{
        framework: string;
        results: ComplianceFinding[];
        compliant: number;
        nonCompliant: number;
        total: number;
      }>("/v1/compliance/evaluate", {
        findings: scanResult.findings,
        framework: complianceFramework,
      });
      setComplianceReport({
        ...data,
        // The evaluate endpoint returns counts only; percentage derived here.
        scorePercent: data.total > 0 ? Math.round((data.compliant / data.total) * 100) : 100,
      });
    } catch (err) {
      setComplianceError(err instanceof Error ? err.message : String(err));
    } finally {
      setComplianceLoading(false);
    }
  }

  async function fetchRoadmap() {
    if (!scanResult) return;
    setRoadmapLoading(true);
    setRoadmapError("");
    try {
      const rate = Number(roadmapDailyRate);
      const body: { findings: ScanFinding[]; dailyRate?: number } = {
        findings: scanResult.findings,
      };
      if (roadmapDailyRate.trim() !== "" && Number.isFinite(rate) && rate > 0) {
        body.dailyRate = rate;
      }
      const data = await postJson<{ phases: RoadmapPhase[]; summary: RoadmapSummary }>(
        "/v1/roadmap/generate",
        body,
      );
      setRoadmap(data);
    } catch (err) {
      setRoadmapError(err instanceof Error ? err.message : String(err));
    } finally {
      setRoadmapLoading(false);
    }
  }

  async function createEvidence() {
    if (!scanResult) return;
    setEvidenceLoading(true);
    setEvidenceError("");
    setEvidenceVerify(null);
    try {
      const scanResultHash = await sha256Hex(JSON.stringify(scanResult.findings));
      const data = await postJson<{ ledger: EvidenceLedger }>("/v1/evidence/create", {
        scanResultHash,
        scanTarget: scanResult.target,
        findingsCount: scanResult.findings.length,
        riskSummary: scanResult.summary,
      });
      setEvidenceLedger(data.ledger);
    } catch (err) {
      setEvidenceError(err instanceof Error ? err.message : String(err));
    } finally {
      setEvidenceLoading(false);
    }
  }

  async function verifyLedger() {
    if (!evidenceLedger) return;
    setVerifyLoading(true);
    setEvidenceError("");
    try {
      const data = await postJson<EvidenceVerifyResult>("/v1/evidence/verify", {
        ledger: evidenceLedger,
      });
      setEvidenceVerify(data);
    } catch (err) {
      setEvidenceError(err instanceof Error ? err.message : String(err));
    } finally {
      setVerifyLoading(false);
    }
  }

  async function exportCbom() {
    if (!scanResult) return;
    setExportLoading("cbom");
    try {
      downloadBlob(
        JSON.stringify(buildCbom(scanResult), null, 2),
        `cbom-${safeName(scanResult.target)}.json`,
        "application/json",
      );
    } catch (err) {
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setExportLoading(null);
    }
  }

  async function exportSarif() {
    if (!scanResult) return;
    setExportLoading("sarif");
    try {
      downloadBlob(
        JSON.stringify(buildSarif(scanResult), null, 2),
        `sarif-${safeName(scanResult.target)}.sarif`,
        "application/sarif+json",
      );
    } catch (err) {
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setExportLoading(null);
    }
  }

  function exportJson() {
    if (!scanResult) return;
    setExportLoading("json");
    try {
      downloadBlob(
        JSON.stringify(scanResult, null, 2),
        `scan-${safeName(scanResult.target)}.json`,
        "application/json",
      );
    } finally {
      setExportLoading(null);
    }
  }

  /* ---- Render ---- */

  return (
    <Tabs.Root defaultValue="scan" className="space-y-6">
      {/* Tab bar */}
      <Tabs.List className="flex gap-1 rounded-lg border border-slate-200 bg-white p-1 shadow-sm">
        {TABS.map((tab) => (
          <Tabs.Trigger
            key={tab.id}
            value={tab.id}
            className="rounded-md px-4 py-2 text-sm font-medium transition data-[state=active]:bg-indigo-600 data-[state=active]:text-white data-[state=active]:shadow data-[state=inactive]:text-slate-600 hover:data-[state=inactive]:bg-slate-100"
          >
            {tab.label}
          </Tabs.Trigger>
        ))}
      </Tabs.List>

      {/* ==================== SCAN TAB ==================== */}
      <Tabs.Content value="scan">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Cryptographic Asset Scan
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Enter a directory target to scan source files and dependency manifests for
            quantum-vulnerable cryptography.
          </p>

          <div className="mt-4 flex flex-wrap items-end gap-3">
            <label className="flex-1 min-w-[240px] text-xs font-medium text-slate-600">
              Target directory
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. /opt/app or ./src"
                className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm"
                onKeyDown={(e) => e.key === "Enter" && void runScan()}
              />
            </label>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-4">
            <label className="flex items-center gap-2 text-xs text-slate-600">
              <input
                type="checkbox"
                checked={scanSource}
                onChange={(e) => setScanSource(e.target.checked)}
                className="h-4 w-4 rounded border-slate-300 text-indigo-600"
              />
              Source code
            </label>
            <label className="flex items-center gap-2 text-xs text-slate-600">
              <input
                type="checkbox"
                checked={scanManifest}
                onChange={(e) => setScanManifest(e.target.checked)}
                className="h-4 w-4 rounded border-slate-300 text-indigo-600"
              />
              Dependency manifests
            </label>
            <Button onClick={() => void runScan()} disabled={scanLoading || !target.trim()}>
              {scanLoading && <Spinner />}
              {scanLoading ? "Scanning…" : "Run scan"}
            </Button>
          </div>

          {scanError && <p className="mt-3 text-xs text-rose-600">{scanError}</p>}

          {/* Scan results */}
          {scanResult && (
            <div className="mt-6">
              <div className="flex flex-wrap items-center gap-4">
                <h3 className="text-sm font-semibold text-slate-800">Results</h3>
                <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600">
                  {scanResult.summary.totalFindings} findings
                </span>
                {scanResult.summary.algorithmsDetected.length > 0 && (
                  <span className="text-xs text-slate-500">
                    Algorithms: {scanResult.summary.algorithmsDetected.join(", ")}
                  </span>
                )}
              </div>
              <p className="mt-1 text-[11px] text-slate-400">
                Summary counts are computed client-side from the backend findings.
              </p>

              {/* Summary badges */}
              <div className="mt-3 flex flex-wrap gap-2">
                {scanResult.summary.critical > 0 && (
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${severityColor("critical")}`}>
                    {scanResult.summary.critical} critical
                  </span>
                )}
                {scanResult.summary.high > 0 && (
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${severityColor("high")}`}>
                    {scanResult.summary.high} high
                  </span>
                )}
                {scanResult.summary.medium > 0 && (
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${severityColor("medium")}`}>
                    {scanResult.summary.medium} medium
                  </span>
                )}
                {scanResult.summary.low > 0 && (
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${severityColor("low")}`}>
                    {scanResult.summary.low} low
                  </span>
                )}
                {scanResult.summary.info > 0 && (
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${severityColor("info")}`}>
                    {scanResult.summary.info} info
                  </span>
                )}
              </div>

              {/* Findings table */}
              <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                      <th className="px-4 py-2 font-medium">File</th>
                      <th className="px-4 py-2 font-medium">Line</th>
                      <th className="px-4 py-2 font-medium">Algorithm</th>
                      <th className="px-4 py-2 font-medium">Severity</th>
                      <th className="px-4 py-2 font-medium">Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.findings.map((f, i) => (
                      <tr key={i} className="border-b border-slate-100">
                        <td className="px-4 py-2 font-mono text-slate-700">{f.file}</td>
                        <td className="px-4 py-2 text-slate-500">{f.line ?? "—"}</td>
                        <td className="px-4 py-2 font-medium text-slate-800">{f.algorithm}</td>
                        <td className="px-4 py-2">
                          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${severityColor(f.severity ?? "")}`}>
                            {f.severity ?? "unknown"}
                          </span>
                        </td>
                        <td className="max-w-[240px] truncate px-4 py-2 text-slate-500">{f.message}</td>
                      </tr>
                    ))}
                    {scanResult.findings.length === 0 && (
                      <tr>
                        <td colSpan={5} className="px-4 py-6 text-center text-slate-500">
                          No findings — no quantum-vulnerable algorithms detected.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Export buttons */}
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => void exportCbom()}
                  disabled={exportLoading === "cbom"}
                >
                  {exportLoading === "cbom" ? <Spinner /> : null}
                  CycloneDX CBOM
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => void exportSarif()}
                  disabled={exportLoading === "sarif"}
                >
                  {exportLoading === "sarif" ? <Spinner /> : null}
                  SARIF 2.1
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => exportJson()}
                  disabled={exportLoading === "json"}
                >
                  {exportLoading === "json" ? <Spinner /> : null}
                  Raw JSON
                </Button>
                <span className="text-[11px] text-slate-400">
                  CBOM &amp; SARIF are generated client-side from the returned findings.
                </span>
              </div>
            </div>
          )}
        </div>
      </Tabs.Content>

      {/* ==================== RISK SCORES TAB ==================== */}
      <Tabs.Content value="risk">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Quantum Risk Scores
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Risk assessment for each finding based on algorithm classification (POST /v1/risk/score).
          </p>

          {!scanResult ? (
            <p className="mt-6 text-sm text-slate-500">
              Run a scan first to generate risk scores.
            </p>
          ) : (
            <>
              <div className="mt-4 flex justify-end">
                <button
                  onClick={() => void fetchRiskScores()}
                  disabled={riskLoading}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:opacity-50"
                >
                  {riskLoading && <Spinner />}
                  {riskLoading ? "Calculating…" : "Calculate risk scores"}
                </button>
              </div>

              {riskError && <p className="mt-3 text-xs text-rose-600">{riskError}</p>}

              {riskScores.length > 0 && (
                <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                        <th className="px-4 py-2 font-medium">File</th>
                        <th className="px-4 py-2 font-medium">Line</th>
                        <th className="px-4 py-2 font-medium">Algorithm</th>
                        <th className="px-4 py-2 font-medium">Quantum Vulnerable</th>
                        <th className="px-4 py-2 font-medium">Classification</th>
                        <th className="px-4 py-2 font-medium">Risk Level</th>
                        <th className="px-4 py-2 font-medium">Risk Score</th>
                        <th className="px-4 py-2 font-medium">Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {riskScores.map((r, i) => {
                        const broken = r.algorithmClassification === "BROKEN" || r.algorithmClassification === "WEAKENED";
                        return (
                          <tr key={i} className="border-b border-slate-100">
                            <td className="max-w-[160px] truncate px-4 py-2 font-mono text-slate-700">
                              {r.file}
                            </td>
                            <td className="px-4 py-2 text-slate-500">{r.line ?? "—"}</td>
                            <td className="px-4 py-2 font-medium text-slate-800">{r.algorithm}</td>
                            <td className="px-4 py-2">
                              {broken ? (
                                <span className="inline-flex items-center gap-1 text-rose-600">
                                  <XCircleIcon className="h-3.5 w-3.5" /> Yes
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 text-emerald-600">
                                  <ShieldCheckIcon className="h-3.5 w-3.5" /> No
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-2 text-slate-600">{r.algorithmClassification}</td>
                            <td className="px-4 py-2">
                              <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${severityColor(r.riskLevel.toLowerCase())}`}>
                                {r.riskLevel}
                              </span>
                            </td>
                            <td className="px-4 py-2 font-mono text-slate-700">{r.riskScore.toFixed(0)}</td>
                            <td className="max-w-[200px] truncate px-4 py-2 text-slate-500">{r.message}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      </Tabs.Content>

      {/* ==================== COMPLIANCE TAB ==================== */}
      <Tabs.Content value="compliance">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Compliance Assessment
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Evaluate scan results against NIST SP 800-131A and CNSA 2.0 frameworks (POST /v1/compliance/evaluate).
          </p>

          {!scanResult ? (
            <p className="mt-6 text-sm text-slate-500">
              Run a scan first to evaluate compliance.
            </p>
          ) : (
            <>
              <div className="mt-4 flex flex-wrap items-end gap-3">
                <label className="text-xs font-medium text-slate-600">
                  Framework
                  <select
                    value={complianceFramework}
                    onChange={(e) => setComplianceFramework(e.target.value)}
                    className="mt-1 block rounded-lg border border-slate-300 px-3 py-2 text-sm"
                  >
                    {COMPLIANCE_FRAMEWORKS.map((fw) => (
                      <option key={fw.value} value={fw.value}>
                        {fw.label}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  onClick={() => void fetchCompliance()}
                  disabled={complianceLoading}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:opacity-50"
                >
                  {complianceLoading && <Spinner />}
                  {complianceLoading ? "Evaluating…" : "Evaluate"}
                </button>
              </div>

              {complianceError && <p className="mt-3 text-xs text-rose-600">{complianceError}</p>}

              {complianceReport && (
                <div className="mt-6">
                  {/* Score gauge (percentage computed client-side) */}
                  <div className="flex items-center gap-6">
                    <div className="relative h-24 w-24">
                      <svg className="h-24 w-24 -rotate-90" viewBox="0 0 36 36">
                        <circle
                          cx="18"
                          cy="18"
                          r="15.9155"
                          fill="none"
                          stroke="#e2e8f0"
                          strokeWidth="3"
                        />
                        <circle
                          cx="18"
                          cy="18"
                          r="15.9155"
                          fill="none"
                          stroke={
                            complianceReport.scorePercent >= 80
                              ? "#10b981"
                              : complianceReport.scorePercent >= 50
                                ? "#f59e0b"
                                : "#ef4444"
                          }
                          strokeWidth="3"
                          strokeDasharray={`${complianceReport.scorePercent} ${100 - complianceReport.scorePercent}`}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-lg font-bold text-slate-900">
                          {complianceReport.scorePercent}%
                        </span>
                      </div>
                    </div>
                    <div className="text-sm text-slate-600">
                      <div>
                        <span className="font-medium text-emerald-600">{complianceReport.compliant}</span>{" "}
                        compliant
                      </div>
                      <div>
                        <span className="font-medium text-rose-600">{complianceReport.nonCompliant}</span>{" "}
                        non-compliant
                      </div>
                      <div className="text-xs text-slate-500">
                        {complianceReport.total} findings evaluated ({complianceReport.framework})
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Percentage derived client-side from server counts.
                      </div>
                    </div>
                  </div>

                  {/* Results table */}
                  <div className="mt-6 overflow-x-auto rounded-lg border border-slate-200">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                          <th className="px-4 py-2 font-medium">File</th>
                          <th className="px-4 py-2 font-medium">Algorithm</th>
                          <th className="px-4 py-2 font-medium">Status</th>
                          <th className="px-4 py-2 font-medium">Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {complianceReport.results.map((r, i) => (
                          <tr key={i} className="border-b border-slate-100">
                            <td className="max-w-[180px] truncate px-4 py-2 font-mono text-slate-700">{r.file}</td>
                            <td className="px-4 py-2 font-medium text-slate-800">{r.algorithm}</td>
                            <td className="px-4 py-2">
                              <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${complianceColor(r.compliance?.compliant ? "pass" : "fail")}`}>
                                {r.compliance?.compliant ? "pass" : "fail"}
                              </span>
                            </td>
                            <td className="max-w-[320px] px-4 py-2 text-slate-500">
                              {r.compliance?.reason}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </Tabs.Content>

      {/* ==================== ROADMAP TAB ==================== */}
      <Tabs.Content value="roadmap">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Migration Roadmap
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Phased remediation plan with effort and cost estimates (POST /v1/roadmap/generate).
          </p>

          {!scanResult ? (
            <p className="mt-6 text-sm text-slate-500">
              Run a scan first to generate a migration roadmap.
            </p>
          ) : (
            <>
              <div className="mt-4 flex flex-wrap items-end gap-3">
                <label className="text-xs font-medium text-slate-600">
                  Daily rate ($, optional)
                  <input
                    type="number"
                    min="1"
                    value={roadmapDailyRate}
                    onChange={(e) => setRoadmapDailyRate(e.target.value)}
                    placeholder="1500"
                    className="mt-1 block w-40 rounded-lg border border-slate-300 px-3 py-2 text-sm"
                  />
                </label>
                <button
                  onClick={() => void fetchRoadmap()}
                  disabled={roadmapLoading}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:opacity-50"
                >
                  {roadmapLoading && <Spinner />}
                  {roadmapLoading ? "Planning…" : "Generate roadmap"}
                </button>
              </div>

              {roadmapError && <p className="mt-3 text-xs text-rose-600">{roadmapError}</p>}

              {roadmap && (
                <div className="mt-6">
                  {/* Summary */}
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs font-medium uppercase tracking-wider text-slate-500">
                        Total Effort
                      </div>
                      <div className="mt-1 text-2xl font-bold text-slate-900">
                        {roadmap.summary.totalDays} days
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs font-medium uppercase tracking-wider text-slate-500">
                        Estimated Cost
                      </div>
                      <div className="mt-1 text-2xl font-bold text-slate-900">
                        ${roadmap.summary.totalCost.toLocaleString()}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs font-medium uppercase tracking-wider text-slate-500">
                        Est. Completion
                      </div>
                      <div className="mt-1 flex items-center gap-2 text-lg font-bold text-slate-900">
                        <ClockIcon className="h-4 w-4 text-slate-400" />
                        {new Date(roadmap.summary.completionDate).toLocaleDateString()}
                      </div>
                    </div>
                  </div>

                  {/* Phases */}
                  <div className="mt-6 space-y-4">
                    {roadmap.phases.map((phase) => (
                      <div key={phase.phase} className="relative rounded-lg border border-slate-200 bg-white p-4 pl-12 shadow-sm">
                        {/* Timeline dot */}
                        <div className="absolute left-3 top-4 flex h-5 w-5 items-center justify-center rounded-full bg-indigo-600 text-[10px] font-bold text-white">
                          {phase.phase}
                        </div>
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div>
                            <h3 className="text-sm font-semibold text-slate-800">{phase.title}</h3>
                            <span className={`mt-1 inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold ${severityColor(phase.priority.toLowerCase())}`}>
                              {phase.priority}
                            </span>
                          </div>
                          <span className="inline-flex items-center gap-1 text-xs text-slate-500">
                            <ClockIcon className="h-3.5 w-3.5" />
                            {phase.estimatedDays}d
                          </span>
                        </div>

                        {phase.findings.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {phase.findings.slice(0, 8).map((f, i) => (
                              <span
                                key={i}
                                className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600"
                              >
                                {f.file}
                              </span>
                            ))}
                            {phase.findings.length > 8 && (
                              <span className="text-[10px] text-slate-400">
                                +{phase.findings.length - 8} more
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </Tabs.Content>

      {/* ==================== EVIDENCE TAB ==================== */}
      <Tabs.Content value="evidence">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Evidence Record
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Generate a tamper-evident integrity record for your latest scan (POST /v1/evidence/create)
            and verify its hash (POST /v1/evidence/verify). Records are created per request — the
            backend does not persist them.
          </p>

          <div className="mt-4 flex justify-end gap-2">
            <button
              onClick={() => void createEvidence()}
              disabled={evidenceLoading || !scanResult}
              className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:opacity-50"
            >
              {evidenceLoading && <Spinner />}
              {!scanResult ? "Run a scan first" : evidenceLoading ? "Creating…" : "Create evidence record"}
            </button>
          </div>

          {evidenceError && <p className="mt-3 text-xs text-rose-600">{evidenceError}</p>}

          {evidenceLedger && (
            <div className="mt-4 rounded-lg border border-slate-200 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-slate-700">
                      {evidenceLedger.integrityHash.slice(0, 16)}…
                    </span>
                    {evidenceVerify?.valid ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700">
                        <ShieldCheckIcon className="h-3 w-3" /> verified
                      </span>
                    ) : evidenceVerify && !evidenceVerify.valid ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-rose-50 px-2 py-0.5 text-xs font-medium text-rose-700">
                        <XCircleIcon className="h-3 w-3" /> mismatch
                      </span>
                    ) : (
                      <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-500">
                        unverified
                      </span>
                    )}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    Target: <span className="font-mono">{safeName(evidenceLedger.data.scanTarget)}</span>
                    {" · "}
                    {evidenceLedger.data.findingsCount} finding
                    {evidenceLedger.data.findingsCount !== 1 ? "s" : ""}
                    {" · "}
                    {new Date(evidenceLedger.data.timestamp).toLocaleString()}
                    {" · "}
                    v{evidenceLedger.version}, index #{evidenceLedger.chainIndex}
                  </div>
                  {evidenceVerify && !evidenceVerify.valid && (
                    <div className="mt-1 text-[11px] text-rose-600">
                      Expected {evidenceVerify.expectedHash.slice(0, 16)}… but got{" "}
                      {evidenceVerify.providedHash.slice(0, 16)}…
                    </div>
                  )}
                </div>
                <div className="shrink-0">
                  <button
                    onClick={() => void verifyLedger()}
                    disabled={verifyLoading || Boolean(evidenceVerify?.valid)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-emerald-400 hover:text-emerald-700 disabled:opacity-50"
                  >
                    {verifyLoading ? <Spinner /> : null}
                    {evidenceVerify?.valid ? "Verified" : verifyLoading ? "Verifying…" : "Verify"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {!evidenceLedger && !evidenceError && (
            <p className="py-6 text-center text-sm text-slate-500">
              No evidence record yet. Run a scan to create one.
            </p>
          )}
        </div>
      </Tabs.Content>

      {/* ==================== SIDE CHANNEL TAB ==================== */}
      <Tabs.Content value="sidechannel">
        <div className="max-w-xl">
          <SideChannelPanel />
        </div>
      </Tabs.Content>
    </Tabs.Root>
  );
}
