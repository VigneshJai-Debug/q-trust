"use client";

/**
 * AI migration planning panel.
 *
 * Paste a CBOM JSON (produced by `crypto-inspector scan`) or fetch one from a
 * registered asset's metadata URI, optionally set a migration deadline, and
 * get the GNN-ranked migration order + a deadline feasibility schedule.
 */
import { useMemo, useState } from "react";
import { fetchMigrationPlan } from "@/lib/api";

const SAMPLE_CBOM = JSON.stringify(
  {
    schema_version: "1.0",
    assets: [
      { asset_id: "asset-0001", algorithm: "RSA-2048", key_size: 2048, criticality: "Critical", pqc_ready: false },
      { asset_id: "asset-0002", algorithm: "ECC-P256", key_size: 256, criticality: "High", pqc_ready: false },
      { asset_id: "asset-0003", algorithm: "AES-256", key_size: 256, criticality: "Medium", pqc_ready: true },
      { asset_id: "asset-0004", algorithm: "SHA-256", key_size: 0, criticality: "Low", pqc_ready: true },
    ],
  },
  null,
  2,
);

interface PlanResult {
  migration_order: Array<{
    rank: number;
    asset_id: string;
    algorithm: string;
    criticality: string;
    pqc_ready: boolean;
    risk_score: number;
    migrate_days: number;
  }>;
  schedule?: {
    feasible: boolean;
    days_available: number;
    total_effort_days: number;
    suggested_daily_rate: number | null;
    windows: Array<{ asset_id: string; start: string; end: string }>;
  } | null;
  total_assets: number;
}

export function PlanningPanel() {
  const [cbomText, setCbomText] = useState("");
  const [deadline, setDeadline] = useState("");
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [plan, setPlan] = useState<PlanResult | null>(null);
  const [error, setError] = useState("");

  const cbom = useMemo(() => {
    if (!cbomText.trim()) return null;
    try {
      return JSON.parse(cbomText) as Record<string, unknown>;
    } catch {
      return null;
    }
  }, [cbomText]);

  async function run() {
    if (!cbom) {
      setError("CBOM JSON is invalid or empty.");
      setState("error");
      return;
    }
    setError("");
    setState("loading");
    try {
      const result = await fetchMigrationPlan({ cbom, deadline: deadline || undefined });
      setPlan(result);
      setState("done");
    } catch (err) {
      setState("error");
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="mt-3 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h3 className="text-sm font-semibold text-slate-800">AI migration planner</h3>
      <p className="mt-1 text-xs text-slate-500">
        Paste a CBOM JSON (from <code className="rounded bg-slate-100 px-1">crypto-inspector scan</code>)
        and optionally a deadline. The GNN ranks assets by migration priority and estimates feasibility.
      </p>

      <div className="mt-4 flex gap-3">
        <textarea
          value={cbomText}
          onChange={(e) => setCbomText(e.target.value)}
          placeholder='{"assets": [{"asset_id": "…", "algorithm": "RSA-2048", "key_size": 2048, "criticality": "Critical"}]}'
          rows={6}
          className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs"
        />
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          onClick={() => setCbomText(SAMPLE_CBOM)}
          className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-slate-600 hover:border-qtrust-500"
        >
          Load sample CBOM
        </button>
        <label className="flex items-center gap-2 text-xs font-medium text-slate-600">
          Deadline
          <input
            type="date"
            value={deadline}
            onChange={(e) => setDeadline(e.target.value)}
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs"
          />
        </label>
        <button
          onClick={() => void run()}
          disabled={state === "loading"}
          className="ml-auto rounded-lg bg-qtrust-600 px-4 py-2 text-xs font-medium text-white transition hover:bg-qtrust-700 disabled:opacity-50"
        >
          {state === "loading" ? "Planning…" : "Generate plan"}
        </button>
      </div>

      {state === "error" && error ? (
        <p className="mt-3 text-xs text-rose-600">{error}</p>
      ) : null}

      {state === "done" && plan ? (
        <PlanView plan={plan} />
      ) : state === "loading" ? (
        <div className="mt-4 space-y-2">
          <div className="h-4 w-1/3 animate-pulse rounded bg-slate-100" />
          <div className="h-8 w-full animate-pulse rounded bg-slate-100" />
          <div className="h-8 w-full animate-pulse rounded bg-slate-100" />
        </div>
      ) : null}
    </div>
  );
}

function PlanView({ plan }: { plan: PlanResult }) {
  const sched = plan.schedule;
  return (
    <div className="mt-4">
      {sched ? (
        <div
          className={`mb-3 rounded-lg px-4 py-3 text-xs ${
            sched.feasible ? "bg-emerald-50 text-emerald-800" : "bg-rose-50 text-rose-800"
          }`}
        >
          {sched.feasible
            ? `✓ Feasible: ${sched.total_effort_days.toFixed(1)} days of effort fits in ${sched.days_available} days`
            : `✗ Not feasible in time: ${sched.total_effort_days.toFixed(1)} days of effort vs ${sched.days_available} days available`}
          {sched.suggested_daily_rate
            ? ` — suggested rate: ${sched.suggested_daily_rate} assets/day.`
            : ""}
        </div>
      ) : null}

      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-slate-200 text-slate-500">
            <th className="py-2 pr-2 font-medium">Rank</th>
            <th className="py-2 pr-2 font-medium">Asset</th>
            <th className="py-2 pr-2 font-medium">Algorithm</th>
            <th className="py-2 pr-2 font-medium">Criticality</th>
            <th className="py-2 pr-2 font-medium">Effort</th>
            {sched ? <th className="py-2 pr-2 font-medium">Window</th> : null}
          </tr>
        </thead>
        <tbody>
          {plan.migration_order.map((a) => {
            const window = sched?.windows.find((w) => w.asset_id === a.asset_id);
            return (
              <tr key={a.asset_id} className="border-b border-slate-100">
                <td className="py-2 pr-2 font-mono text-slate-400">#{a.rank}</td>
                <td className="py-2 pr-2 font-mono text-slate-800">{a.asset_id}</td>
                <td className="py-2 pr-2 text-slate-600">{a.algorithm}</td>
                <td className="py-2 pr-2">
                  {a.pqc_ready ? (
                    <span className="rounded-full bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
                      PQC-ready
                    </span>
                  ) : (
                    <span className="text-slate-600">{a.criticality}</span>
                  )}
                </td>
                <td className="py-2 pr-2 text-slate-600">{a.migrate_days}d</td>
                {window ? (
                  <td className="py-2 pr-2 font-mono text-xs text-slate-500">
                    {window.start.slice(0, 10)} → {window.end.slice(0, 10)}
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}