"use client";

import { useState } from "react";

type Verdict = "SIDE_CHANNEL_VERIFIED" | "SIDE_CHANNEL_LOW_RISK" | "SIDE_CHANNEL_HIGH_RISK";

interface SideChannelResponse {
  implementation: string;
  traces_collected: number;
  leakage_probability: number;
  verdict: Verdict;
  evidence_hash: string;
  timestamp: string;
  gpu_used: boolean;
}

const VERDICT_CONFIG: Record<Verdict, { label: string; text: string; bg: string }> = {
  SIDE_CHANNEL_VERIFIED: {
    label: "Side-Channel Verified",
    text: "text-green-600",
    bg: "bg-green-500/15",
  },
  SIDE_CHANNEL_LOW_RISK: {
    label: "Low Risk",
    text: "text-amber-600",
    bg: "bg-amber-500/15",
  },
  SIDE_CHANNEL_HIGH_RISK: {
    label: "High Risk",
    text: "text-red-600",
    bg: "bg-red-500/15",
  },
};

async function analyze(
  body: Record<string, unknown>,
): Promise<SideChannelResponse> {
  const base =
    process.env.NEXT_PUBLIC_QTRUST_API_URL ?? "http://localhost:3001";
  const res = await fetch(`${base}/v1/gpu/side-channel/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = "";
    try {
      const errBody = await res.json();
      detail = errBody.error ?? JSON.stringify(errBody);
    } catch {
      detail = await res.text();
    }
    throw new Error(`API ${res.status}: ${detail}`);
  }
  return res.json();
}

export default function SideChannelPanel() {
  const [mode, setMode] = useState<"simulated" | "real">("simulated");
  const [leakageProb, setLeakageProb] = useState(0);
  const [command, setCommand] = useState("./ml_dsa_sign input.hex");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SideChannelResponse | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const body =
        mode === "simulated"
          ? { simulated: true, leakage_prob: leakageProb, n_traces: 10_000 }
          : {
              simulated: false,
              implementation_cmd: command.trim().split(/\s+/).filter(Boolean),
              n_traces: 10_000,
            };
      setResult(await analyze(body));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const config = result ? VERDICT_CONFIG[result.verdict] : null;

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-foreground">
          PQC Side-Channel Analysis
        </h3>
        <span className="rounded-full bg-blue-500/10 px-2 py-0.5 text-xs font-medium text-blue-600">
          GPU-accelerated
        </span>
      </div>
      <p className="mb-4 text-sm text-muted-foreground">
        Collects timing traces from a PQC implementation and classifies them
        with a CNN+LSTM detector to verify constant-time execution.
      </p>

      <div className="mb-3 flex gap-2">
        <button
          type="button"
          onClick={() => setMode("simulated")}
          className={`rounded-md px-3 py-1.5 text-sm ${
            mode === "simulated"
              ? "bg-primary/10 text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Demo (simulated)
        </button>
        <button
          type="button"
          onClick={() => setMode("real")}
          className={`rounded-md px-3 py-1.5 text-sm ${
            mode === "real"
              ? "bg-primary/10 text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Real binary
        </button>
      </div>

      {mode === "simulated" ? (
        <label className="mb-4 block text-sm text-muted-foreground">
          Injected leakage probability:{" "}
          <span className="font-mono text-foreground">
            {leakageProb.toFixed(2)}
          </span>
          <input
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={leakageProb}
            onChange={(e) => setLeakageProb(Number(e.target.value))}
            className="mt-2 w-full accent-blue-600"
            aria-label="Injected leakage probability"
          />
        </label>
      ) : (
        <input
          type="text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          placeholder="./pqc_binary args..."
          aria-label="Implementation command"
          className="mb-4 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground"
        />
      )}

      <button
        type="button"
        onClick={run}
        disabled={loading || (mode === "real" && command.trim().length === 0)}
        className="w-full rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
      >
        {loading ? "Analyzing 10,000 traces..." : "Run analysis"}
      </button>

      {error && (
        <div
          role="alert"
          className="mt-3 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-600"
        >
          {error.includes("409")
            ? "Detector not trained yet. Train it via `make -f Makefile.gpu side-channel-train` and set QTRUST_SIDE_CHANNEL_MODEL."
            : error}
        </div>
      )}

      {result && config && (
        <dl className="mt-4 space-y-2 rounded-md border border-border p-3 text-sm">
          <div className="flex items-center justify-between gap-4">
            <dt className="shrink-0 text-muted-foreground">Target</dt>
            <dd
              className="truncate font-mono text-xs"
              title={result.implementation}
            >
              {result.implementation}
            </dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-muted-foreground">Verdict</dt>
            <dd>
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-semibold ${config.bg} ${config.text}`}
              >
                {config.label}
              </span>
            </dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-muted-foreground">Leakage probability</dt>
            <dd className="font-mono">
              {(result.leakage_probability * 100).toFixed(1)}%
            </dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-muted-foreground">Traces analyzed</dt>
            <dd className="font-mono">
              {result.traces_collected.toLocaleString()}
            </dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-muted-foreground">Accelerator</dt>
            <dd>{result.gpu_used ? "NVIDIA GPU" : "CPU"}</dd>
          </div>
          <div className="flex items-center justify-between gap-4">
            <dt className="shrink-0 text-muted-foreground">Evidence hash</dt>
            <dd
              className="truncate font-mono text-xs"
              title={result.evidence_hash}
            >
              {result.evidence_hash.slice(0, 18)}…
              {result.evidence_hash.slice(-6)}
            </dd>
          </div>
        </dl>
      )}
    </div>
  );
}
