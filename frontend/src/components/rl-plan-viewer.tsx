"use client";

import { useState } from "react";

interface MigrationStep {
  asset_id?: number | string;
  algorithm?: string;
  location?: string;
  priority?: number;
  [key: string]: unknown;
}

interface RLPlanResponse {
  method: string;
  migration_order: MigrationStep[];
  [key: string]: unknown;
}

const DEMO_CBOM = JSON.stringify(
  {
    assets: [
      { id: 0, algorithm: "RSA-2048", key_size: 2048, criticality: "critical" },
      { id: 1, algorithm: "RSA-4096", key_size: 4096, criticality: "medium" },
      { id: 2, algorithm: "ECC-P256", key_size: 256, criticality: "high" },
      { id: 3, algorithm: "Ed25519", key_size: 256, criticality: "low" },
      { id: 4, algorithm: "RSA-2048", key_size: 2048, criticality: "high" },
    ],
    dependencies: [[0, 2]],
  },
  null,
  2,
);

export default function RLPlanViewer() {
  const [cbomText, setCbomText] = useState<string>(DEMO_CBOM);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RLPlanResponse | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      let cbom: unknown;
      try {
        cbom = JSON.parse(cbomText);
      } catch {
        throw new Error("CBOM is not valid JSON");
      }
      const base =
        process.env.NEXT_PUBLIC_QTRUST_API_URL ?? "http://localhost:3001";
      const res = await fetch(`${base}/v1/gpu/rl/plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cbom }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        if (res.status === 503) {
          throw new Error(
            "RL planner microservice unreachable. Start it with `docker compose up planner`.",
          );
        }
        throw new Error(`API ${res.status}: ${body.error ?? "planning failed"}`);
      }
      setResult(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-foreground">
          RL Migration Planner
        </h3>
        <span className="rounded-full bg-blue-500/10 px-2 py-0.5 text-xs font-medium text-blue-600">
          Policy network
        </span>
      </div>
      <p className="mb-3 text-sm text-muted-foreground">
        A reinforcement-learning agent trained on simulated migrations orders
        your assets: dependencies first, critical assets early, downtime
        minimized.
      </p>

      <textarea
        value={cbomText}
        onChange={(e) => setCbomText(e.target.value)}
        rows={6}
        aria-label="CBOM JSON for planning"
        className="mb-3 w-full rounded-md border border-border bg-background p-2 font-mono text-xs text-foreground"
      />

      <button
        type="button"
        onClick={run}
        disabled={loading}
        className="w-full rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
      >
        {loading ? "Planning..." : "Generate migration plan"}
      </button>

      {error && (
        <div
          role="alert"
          className="mt-3 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-600"
        >
          {error}
        </div>
      )}

      {result && (
        <div className="mt-4 rounded-md border border-border p-3">
          <p className="mb-2 text-xs text-muted-foreground">
            Method:{" "}
            <span
              className={`font-semibold ${
                result.method === "rl_policy"
                  ? "text-blue-600"
                  : "text-amber-600"
              }`}
            >
              {result.method}
            </span>{" "}
            · {result.migration_order.length} steps
          </p>
          <ol className="space-y-1.5">
            {result.migration_order.map((step, i) => (
              <li key={i} className="flex items-center gap-2 text-sm">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/10 font-mono text-xs text-primary">
                  {i + 1}
                </span>
                <span className="font-mono text-xs text-foreground">
                  {String(step.algorithm ?? step.asset_id ?? "?")}
                </span>
                {"location" in step && step.location ? (
                  <span className="truncate text-xs text-muted-foreground">
                    {String(step.location)}
                  </span>
                ) : null}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
