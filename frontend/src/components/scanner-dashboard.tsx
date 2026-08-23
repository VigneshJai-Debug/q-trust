"use client";

/**
 * Scanner dashboard — scan targets for PQC vulnerabilities, view risk scores,
 * compliance status, migration roadmap, and evidence ledger.
 */
import { useState } from "react";
import { API_BASE_URL } from "@/lib/api";
import { ShieldCheckIcon, XCircleIcon, ClockIcon } from "@/app/icons";

/* -------------------------------------------------------------------------- */
/*  Types                                                                      */
/* -------------------------------------------------------------------------- */

interface ScanFinding {
  file: string;
  line: number;
  algorithm: string;
  key_size: number;
  context: string;
  severity: "critical" | "high" | "medium" | "low";
}

interface ScanResult {
  scan_id: string;
  target: string;
  scan_type: string;
  timestamp: number;
  findings: ScanFinding[];
  summary: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    algorithms_detected: string[];
  };
}

interface RiskScore {
  finding: string;
  algorithm: string;
  quantum_vulnerable: boolean;
  risk_level: "critical" | "high" | "medium" | "low";
  hndl_score: number;
  recommended_action: string;
}

interface ComplianceRule {
  rule_id: string;
  description: string;
  status: "pass" | "fail" | "warning";
  details: string;
}

interface ComplianceReport {
  framework: string;
  score: number;
  total_rules: number;
  passed: number;
  failed: number;
  warnings: number;
  rules: ComplianceRule[];
}

interface RoadmapPhase {
  phase: number;
  name: string;
  description: string;
  start_date: string;
  end_date: string;
  effort_days: number;
  assets: string[];
  cost_estimate: number;
}

interface Roadmap {
  phases: RoadmapPhase[];
  total_effort_days: number;
  total_cost_estimate: number;
  deadline: string | null;
}

interface EvidenceEntry {
  evidence_id: string;
  scan_id: string;
  cbom_hash: string;
  timestamp: number;
  verified: boolean;
  signer: string;
}

interface EvidenceLedger {
  entries: EvidenceEntry[];
  total: number;
}

/* -------------------------------------------------------------------------- */
/*  Tab configuration                                                          */
/* -------------------------------------------------------------------------- */

type TabId = "scan" | "risk" | "compliance" | "roadmap" | "evidence";

const TABS: { id: TabId; label: string }[] = [
  { id: "scan", label: "Scan" },
  { id: "risk", label: "Risk Scores" },
  { id: "compliance", label: "Compliance" },
  { id: "roadmap", label: "Roadmap" },
  { id: "evidence", label: "Evidence" },
];

const COMPLIANCE_FRAMEWORKS = [
  { value: "NIST-SP-800-131A", label: "NIST SP 800-131A" },
  { value: "CNSA-2.0", label: "CNSA 2.0" },
  { value: "FIPS-140-3", label: "FIPS 140-3" },
  { value: "EU-NIS2", label: "EU NIS2" },
  { value: "FISMA", label: "FISMA" },
  { value: "FedRAMP", label: "FedRAMP" },
  { value: "CMMC", label: "CMMC" },
] as const;

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function severityColor(s: string) {
  switch (s) {
    case "critical":
      return "bg-rose-100 text-rose-700";
    case "high":
      return "bg-amber-100 text-amber-700";
    case "medium":
      return "bg-indigo-100 text-indigo-700";
    case "low":
      return "bg-emerald-100 text-emerald-700";
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

/* -------------------------------------------------------------------------- */
/*  Main component                                                             */
/* -------------------------------------------------------------------------- */

export function ScannerDashboard() {
  const [activeTab, setActiveTab] = useState<TabId>("scan");

  /* ---- Scan state ---- */
  const [target, setTarget] = useState("");
  const [scanSource, setScanSource] = useState(true);
  const [scanManifest, setScanManifest] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState("");

  /* ---- Risk state ---- */
  const [riskScores, setRiskScores] = useState<RiskScore[]>([]);
  const [riskLoading, setRiskLoading] = useState(false);
  const [riskError, setRiskError] = useState("");

  /* ---- Compliance state ---- */
  const [complianceFramework, setComplianceFramework] = useState<string>(COMPLIANCE_FRAMEWORKS[0].value);
  const [complianceReport, setComplianceReport] = useState<ComplianceReport | null>(null);
  const [complianceLoading, setComplianceLoading] = useState(false);
  const [complianceError, setComplianceError] = useState("");

  /* ---- Roadmap state ---- */
  const [roadmapDeadline, setRoadmapDeadline] = useState("");
  const [roadmap, setRoadmap] = useState<Roadmap | null>(null);
  const [roadmapLoading, setRoadmapLoading] = useState(false);
  const [roadmapError, setRoadmapError] = useState("");

  /* ---- Evidence state ---- */
  const [evidenceLedger, setEvidenceLedger] = useState<EvidenceLedger | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState("");
  const [verifyLoading, setVerifyLoading] = useState<string | null>(null);

  /* ---- Export state ---- */
  const [exportLoading, setExportLoading] = useState<string | null>(null);

  /* ---- API calls ---- */

  async function runScan() {
    if (!target.trim()) return;
    setScanLoading(true);
    setScanError("");
    setScanResult(null);
    try {
      const res = await fetch(`${API_BASE_URL}/v1/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.trim(),
          scan_type: scanSource && scanManifest ? "full" : scanSource ? "source" : "manifest",
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? body.error ?? `Scan failed (${res.status})`);
      }
      const data: ScanResult = await res.json();
      setScanResult(data);
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
      const res = await fetch(`${API_BASE_URL}/v1/risk/${encodeURIComponent(scanResult.scan_id)}`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? body.error ?? `Risk fetch failed (${res.status})`);
      }
      const data: RiskScore[] = await res.json();
      setRiskScores(data);
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
      const res = await fetch(
        `${API_BASE_URL}/v1/compliance/${encodeURIComponent(scanResult.scan_id)}?framework=${encodeURIComponent(complianceFramework)}`,
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? body.error ?? `Compliance fetch failed (${res.status})`);
      }
      const data: ComplianceReport = await res.json();
      setComplianceReport(data);
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
      const res = await fetch(
        `${API_BASE_URL}/v1/roadmap/${encodeURIComponent(scanResult.scan_id)}${roadmapDeadline ? `?deadline=${encodeURIComponent(roadmapDeadline)}` : ""}`,
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? body.error ?? `Roadmap fetch failed (${res.status})`);
      }
      const data: Roadmap = await res.json();
      setRoadmap(data);
    } catch (err) {
      setRoadmapError(err instanceof Error ? err.message : String(err));
    } finally {
      setRoadmapLoading(false);
    }
  }

  async function fetchEvidence() {
    setEvidenceLoading(true);
    setEvidenceError("");
    try {
      const res = await fetch(`${API_BASE_URL}/v1/evidence`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? body.error ?? `Evidence fetch failed (${res.status})`);
      }
      const data: EvidenceLedger = await res.json();
      setEvidenceLedger(data);
    } catch (err) {
      setEvidenceError(err instanceof Error ? err.message : String(err));
    } finally {
      setEvidenceLoading(false);
    }
  }

  async function verifyEvidence(evidenceId: string) {
    setVerifyLoading(evidenceId);
    try {
      const res = await fetch(`${API_BASE_URL}/v1/evidence/${encodeURIComponent(evidenceId)}/verify`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? body.error ?? `Verify failed (${res.status})`);
      }
      if (evidenceLedger) {
        setEvidenceLedger({
          ...evidenceLedger,
          entries: evidenceLedger.entries.map((e) =>
            e.evidence_id === evidenceId ? { ...e, verified: true } : e,
          ),
        });
      }
    } catch (err) {
      setEvidenceError(err instanceof Error ? err.message : String(err));
    } finally {
      setVerifyLoading(null);
    }
  }

  async function exportCbom() {
    if (!scanResult) return;
    setExportLoading("cbom");
    try {
      const res = await fetch(
        `${API_BASE_URL}/v1/scan/${encodeURIComponent(scanResult.scan_id)}/export/cbom`,
      );
      if (!res.ok) throw new Error(`Export failed (${res.status})`);
      const data = await res.json();
      downloadBlob(JSON.stringify(data, null, 2), `cbom-${scanResult.scan_id}.json`, "application/json");
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
      const res = await fetch(
        `${API_BASE_URL}/v1/scan/${encodeURIComponent(scanResult.scan_id)}/export/sarif`,
      );
      if (!res.ok) throw new Error(`Export failed (${res.status})`);
      const data = await res.json();
      downloadBlob(JSON.stringify(data, null, 2), `sarif-${scanResult.scan_id}.sarif`, "application/sarif+json");
    } catch (err) {
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setExportLoading(null);
    }
  }

  async function exportJson() {
    if (!scanResult) return;
    setExportLoading("json");
    try {
      downloadBlob(JSON.stringify(scanResult, null, 2), `scan-${scanResult.scan_id}.json`, "application/json");
    } finally {
      setExportLoading(null);
    }
  }

  /* ---- Render ---- */

  return (
    <div className="space-y-6">
      {/* Tab bar */}
      <div className="flex gap-1 rounded-lg border border-slate-200 bg-white p-1 shadow-sm">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`rounded-md px-4 py-2 text-sm font-medium transition ${
              activeTab === tab.id
                ? "bg-indigo-600 text-white shadow"
                : "text-slate-600 hover:bg-slate-100"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ==================== SCAN TAB ==================== */}
      {activeTab === "scan" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Cryptographic Asset Scan
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Enter a target host, directory, or CIDR range to scan for quantum-vulnerable cryptography.
          </p>

          <div className="mt-4 flex flex-wrap items-end gap-3">
            <label className="flex-1 min-w-[240px] text-xs font-medium text-slate-600">
              Target (host / directory / CIDR)
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. 192.168.1.0/24, /opt/app, api.example.com"
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
            <button
              onClick={() => void runScan()}
              disabled={scanLoading || !target.trim()}
              className="ml-auto inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-5 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:opacity-50"
            >
              {scanLoading && <Spinner />}
              {scanLoading ? "Scanning…" : "Run scan"}
            </button>
          </div>

          {scanError && <p className="mt-3 text-xs text-rose-600">{scanError}</p>}

          {/* Scan results */}
          {scanResult && (
            <div className="mt-6">
              <div className="flex flex-wrap items-center gap-4">
                <h3 className="text-sm font-semibold text-slate-800">Results</h3>
                <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600">
                  {scanResult.summary.total_findings} findings
                </span>
                {scanResult.summary.algorithms_detected.length > 0 && (
                  <span className="text-xs text-slate-500">
                    Algorithms: {scanResult.summary.algorithms_detected.join(", ")}
                  </span>
                )}
              </div>

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
              </div>

              {/* Findings table */}
              <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                      <th className="px-4 py-2 font-medium">File</th>
                      <th className="px-4 py-2 font-medium">Line</th>
                      <th className="px-4 py-2 font-medium">Algorithm</th>
                      <th className="px-4 py-2 font-medium">Key Size</th>
                      <th className="px-4 py-2 font-medium">Severity</th>
                      <th className="px-4 py-2 font-medium">Context</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.findings.map((f, i) => (
                      <tr key={i} className="border-b border-slate-100">
                        <td className="px-4 py-2 font-mono text-slate-700">{f.file}</td>
                        <td className="px-4 py-2 text-slate-500">{f.line}</td>
                        <td className="px-4 py-2 font-medium text-slate-800">{f.algorithm}</td>
                        <td className="px-4 py-2 text-slate-600">{f.key_size || "—"}</td>
                        <td className="px-4 py-2">
                          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${severityColor(f.severity)}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="max-w-[200px] truncate px-4 py-2 text-slate-500">{f.context}</td>
                      </tr>
                    ))}
                    {scanResult.findings.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-4 py-6 text-center text-slate-500">
                          No findings — no quantum-vulnerable algorithms detected.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Export buttons */}
              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  onClick={() => void exportCbom()}
                  disabled={exportLoading === "cbom"}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-indigo-400 hover:text-indigo-700 disabled:opacity-50"
                >
                  {exportLoading === "cbom" ? <Spinner /> : null}
                  CycloneDX 1.7 CBOM
                </button>
                <button
                  onClick={() => void exportSarif()}
                  disabled={exportLoading === "sarif"}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-indigo-400 hover:text-indigo-700 disabled:opacity-50"
                >
                  {exportLoading === "sarif" ? <Spinner /> : null}
                  SARIF 2.1
                </button>
                <button
                  onClick={() => void exportJson()}
                  disabled={exportLoading === "json"}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-indigo-400 hover:text-indigo-700 disabled:opacity-50"
                >
                  {exportLoading === "json" ? <Spinner /> : null}
                  Raw JSON
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ==================== RISK SCORES TAB ==================== */}
      {activeTab === "risk" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Quantum Risk Scores
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Risk assessment for each finding based on HNDL attack feasibility and algorithm vulnerability.
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
                        <th className="px-4 py-2 font-medium">Finding</th>
                        <th className="px-4 py-2 font-medium">Algorithm</th>
                        <th className="px-4 py-2 font-medium">Quantum Vulnerable</th>
                        <th className="px-4 py-2 font-medium">Risk Level</th>
                        <th className="px-4 py-2 font-medium">HNDL Score</th>
                        <th className="px-4 py-2 font-medium">Recommended Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {riskScores.map((r, i) => (
                        <tr key={i} className="border-b border-slate-100">
                          <td className="max-w-[160px] truncate px-4 py-2 font-mono text-slate-700">
                            {r.finding}
                          </td>
                          <td className="px-4 py-2 font-medium text-slate-800">{r.algorithm}</td>
                          <td className="px-4 py-2">
                            {r.quantum_vulnerable ? (
                              <span className="inline-flex items-center gap-1 text-rose-600">
                                <XCircleIcon className="h-3.5 w-3.5" /> Yes
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-emerald-600">
                                <ShieldCheckIcon className="h-3.5 w-3.5" /> No
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2">
                            <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${severityColor(r.risk_level)}`}>
                              {r.risk_level}
                            </span>
                          </td>
                          <td className="px-4 py-2 font-mono text-slate-700">{r.hndl_score.toFixed(2)}</td>
                          <td className="max-w-[200px] px-4 py-2 text-slate-600">{r.recommended_action}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ==================== COMPLIANCE TAB ==================== */}
      {activeTab === "compliance" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Compliance Assessment
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Evaluate scan results against NIST and industry compliance frameworks.
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
                  {/* Score gauge */}
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
                            complianceReport.score >= 80
                              ? "#10b981"
                              : complianceReport.score >= 50
                                ? "#f59e0b"
                                : "#ef4444"
                          }
                          strokeWidth="3"
                          strokeDasharray={`${complianceReport.score} ${100 - complianceReport.score}`}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-lg font-bold text-slate-900">
                          {complianceReport.score}%
                        </span>
                      </div>
                    </div>
                    <div className="text-sm text-slate-600">
                      <div>
                        <span className="font-medium text-emerald-600">{complianceReport.passed}</span> passed
                      </div>
                      <div>
                        <span className="font-medium text-rose-600">{complianceReport.failed}</span> failed
                      </div>
                      <div>
                        <span className="font-medium text-amber-600">{complianceReport.warnings}</span> warnings
                      </div>
                      <div className="text-xs text-slate-500">
                        {complianceReport.total_rules} total rules
                      </div>
                    </div>
                  </div>

                  {/* Rules table */}
                  <div className="mt-6 overflow-x-auto rounded-lg border border-slate-200">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                          <th className="px-4 py-2 font-medium">Rule ID</th>
                          <th className="px-4 py-2 font-medium">Description</th>
                          <th className="px-4 py-2 font-medium">Status</th>
                          <th className="px-4 py-2 font-medium">Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {complianceReport.rules.map((rule) => (
                          <tr key={rule.rule_id} className="border-b border-slate-100">
                            <td className="px-4 py-2 font-mono text-slate-700">{rule.rule_id}</td>
                            <td className="px-4 py-2 text-slate-700">{rule.description}</td>
                            <td className="px-4 py-2">
                              <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${complianceColor(rule.status)}`}>
                                {rule.status}
                              </span>
                            </td>
                            <td className="max-w-[240px] px-4 py-2 text-slate-500">{rule.details}</td>
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
      )}

      {/* ==================== ROADMAP TAB ==================== */}
      {activeTab === "roadmap" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Migration Roadmap
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Phased migration plan with effort estimates, timelines, and cost projections.
          </p>

          {!scanResult ? (
            <p className="mt-6 text-sm text-slate-500">
              Run a scan first to generate a migration roadmap.
            </p>
          ) : (
            <>
              <div className="mt-4 flex flex-wrap items-end gap-3">
                <label className="text-xs font-medium text-slate-600">
                  Deadline (optional)
                  <input
                    type="date"
                    value={roadmapDeadline}
                    onChange={(e) => setRoadmapDeadline(e.target.value)}
                    className="mt-1 block rounded-lg border border-slate-300 px-3 py-2 text-sm"
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
                        {roadmap.total_effort_days} days
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs font-medium uppercase tracking-wider text-slate-500">
                        Estimated Cost
                      </div>
                      <div className="mt-1 text-2xl font-bold text-slate-900">
                        ${roadmap.total_cost_estimate.toLocaleString()}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs font-medium uppercase tracking-wider text-slate-500">
                        Phases
                      </div>
                      <div className="mt-1 text-2xl font-bold text-slate-900">
                        {roadmap.phases.length}
                      </div>
                    </div>
                  </div>

                  {/* Timeline */}
                  <div className="mt-6 space-y-4">
                    {roadmap.phases.map((phase) => (
                      <div
                        key={phase.phase}
                        className="relative rounded-lg border border-slate-200 bg-white p-4 pl-8 shadow-sm"
                      >
                        {/* Timeline dot */}
                        <div className="absolute left-3 top-4 flex h-5 w-5 items-center justify-center rounded-full bg-indigo-600 text-[10px] font-bold text-white">
                          {phase.phase}
                        </div>
                        {/* Timeline line */}
                        <div className="absolute bottom-0 left-[19px] top-9 w-0.5 bg-slate-200" />

                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div>
                            <h3 className="text-sm font-semibold text-slate-800">{phase.name}</h3>
                            <p className="mt-0.5 text-xs text-slate-500">{phase.description}</p>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-slate-500">
                            <span className="inline-flex items-center gap-1">
                              <ClockIcon className="h-3.5 w-3.5" />
                              {phase.effort_days}d
                            </span>
                            <span className="font-medium text-slate-700">
                              ${phase.cost_estimate.toLocaleString()}
                            </span>
                          </div>
                        </div>

                        <div className="mt-2 flex flex-wrap items-center gap-3 text-xs">
                          <span className="text-slate-500">
                            {phase.start_date} → {phase.end_date}
                          </span>
                          {phase.assets.length > 0 && (
                            <span className="text-slate-400">
                              {phase.assets.length} asset{phase.assets.length !== 1 ? "s" : ""}
                            </span>
                          )}
                        </div>

                        {phase.assets.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {phase.assets.map((a) => (
                              <span
                                key={a}
                                className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600"
                              >
                                {a}
                              </span>
                            ))}
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
      )}

      {/* ==================== EVIDENCE TAB ==================== */}
      {activeTab === "evidence" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-500">
            Evidence Ledger
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Cryptographically signed scan evidence stored on-chain. Verify integrity and view CBOM diffs.
          </p>

          <div className="mt-4 flex justify-end">
            <button
              onClick={() => void fetchEvidence()}
              disabled={evidenceLoading}
              className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:opacity-50"
            >
              {evidenceLoading && <Spinner />}
              {evidenceLoading ? "Loading…" : "Load evidence"}
            </button>
          </div>

          {evidenceError && <p className="mt-3 text-xs text-rose-600">{evidenceError}</p>}

          {evidenceLedger && (
            <div className="mt-4">
              <p className="mb-3 text-xs text-slate-500">
                {evidenceLedger.total} evidence record{evidenceLedger.total !== 1 ? "s" : ""}
              </p>

              <div className="space-y-3">
                {evidenceLedger.entries.map((entry) => (
                  <div
                    key={entry.evidence_id}
                    className="flex items-center justify-between gap-4 rounded-lg border border-slate-200 p-4"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-slate-700">{entry.evidence_id}</span>
                        {entry.verified ? (
                          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700">
                            <ShieldCheckIcon className="h-3 w-3" /> verified
                          </span>
                        ) : (
                          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-500">
                            unverified
                          </span>
                        )}
                      </div>
                      <div className="mt-1 text-xs text-slate-500">
                        CBOM: <span className="font-mono">{entry.cbom_hash.slice(0, 16)}…</span>
                        {" · "}
                        {new Date(entry.timestamp * 1000).toLocaleDateString()}
                        {" · "}
                        signer: <span className="font-mono">{entry.signer.slice(0, 10)}…</span>
                      </div>
                    </div>
                    <div className="flex shrink-0 gap-2">
                      <button
                        onClick={() => void verifyEvidence(entry.evidence_id)}
                        disabled={verifyLoading === entry.evidence_id || entry.verified}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-emerald-400 hover:text-emerald-700 disabled:opacity-50"
                      >
                        {verifyLoading === entry.evidence_id ? <Spinner /> : null}
                        {entry.verified ? "Verified" : "Verify"}
                      </button>
                    </div>
                  </div>
                ))}

                {evidenceLedger.entries.length === 0 && (
                  <p className="py-6 text-center text-sm text-slate-500">
                    No evidence records yet. Run a scan to generate evidence.
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
