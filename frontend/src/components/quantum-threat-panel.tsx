"use client";

import { useState } from "react";

interface QuantumEstimate {
  rsa_key_size: number;
  logical_qubits_needed: number;
  physical_qubits_needed: number;
  estimated_breakable_year: number | null;
  based_on: string;
}

const KEY_SIZES = [1024, 2048, 3072, 4096] as const;

function urgency(year: number | null): { label: string; cls: string } {
  if (year === null) return { label: "Not before 2033", cls: "text-green-600" };
  const yearsAway = year - 2026;
  if (yearsAway <= 2) return { label: "CRITICAL", cls: "text-red-600" };
  if (yearsAway <= 5) return { label: "HIGH", cls: "text-orange-600" };
  if (yearsAway <= 8) return { label: "MEDIUM", cls: "text-amber-600" };
  return { label: "LOW", cls: "text-green-600" };
}

export default function QuantumThreatPanel() {
  const [bits, setBits] = useState<number>(2048);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<QuantumEstimate | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const base =
        process.env.NEXT_PUBLIC_QTRUST_API_URL ?? "http://localhost:3001";
      const res = await fetch(
        `${base}/v1/gpu/quantum/estimate/${bits}`,
      );
      if (!res.ok) {
        let detail = "";
        try {
          const body = await res.json();
          detail = body.error ?? JSON.stringify(body);
        } catch {
          detail = await res.text();
        }
        throw new Error(`API ${res.status}: ${detail}`);
      }
      setResult(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const u = urgency(result?.estimated_breakable_year ?? null);

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-foreground">
          Quantum Threat Estimate
        </h3>
        <span className="rounded-full bg-blue-500/10 px-2 py-0.5 text-xs font-medium text-blue-600">
          Shor-backed
        </span>
      </div>
      <p className="mb-4 text-sm text-muted-foreground">
        Estimates the quantum resources required to break an RSA key of the
        given size, based on published hardware roadmaps.
      </p>

      <div className="mb-4 flex gap-2">
        {KEY_SIZES.map((size) => (
          <button
            key={size}
            type="button"
            onClick={() => setBits(size)}
            className={`flex-1 rounded-md px-3 py-1.5 text-sm ${
              bits === size
                ? "bg-primary/10 font-medium text-primary"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {size}
          </button>
        ))}
      </div>

      <button
        type="button"
        onClick={run}
        disabled={loading}
        className="w-full rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
      >
        {loading ? "Estimating..." : `Estimate RSA-${bits} threat`}
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
        <dl className="mt-4 space-y-2 rounded-md border border-border p-3 text-sm">
          <div className="flex items-center justify-between">
            <dt className="text-muted-foreground">Migration urgency</dt>
            <dd>
              <span className={`font-semibold ${u.cls}`}>{u.label}</span>
              {result.estimated_breakable_year !== null && (
                <span className={`ml-1 ${u.cls}`}>
                  (~{result.estimated_breakable_year})
                </span>
              )}
            </dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-muted-foreground">Logical qubits</dt>
            <dd className="font-mono">
              {result.logical_qubits_needed.toLocaleString()}
            </dd>
          </div>
          <div className="flex items-center justify-between">
            <dt className="text-muted-foreground">Physical qubits</dt>
            <dd className="font-mono">
              {result.physical_qubits_needed.toLocaleString()}
            </dd>
          </div>
          <div className="pt-1 text-xs text-muted-foreground">
            Basis: {result.based_on}
          </div>
        </dl>
      )}
    </div>
  );
}
