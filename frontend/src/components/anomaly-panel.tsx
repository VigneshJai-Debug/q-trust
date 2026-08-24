"use client";

import { useState } from "react";

interface AnomalousAsset {
  asset_index: number;
  location: string;
  algorithm: string;
  reconstruction_error: number;
}

interface AnomalyResponse {
  anomaly_score: number;
  is_anomalous: boolean;
  threshold: number;
  asset_count: number;
  top_anomalous_assets: AnomalousAsset[];
  evidence_hash: string;
  timestamp: string;
}

const DEMO_CBOM = JSON.stringify(
  {
    assets: [
      {
        algorithm: "RSA-1024",
        key_size: 1024,
        criticality: "critical",
        expired: true,
        vendor: null,
        self_signed: true,
        days_until_expiry: 0,
        location: "legacy-gateway.example.com",
      },
      {
        algorithm: "RSA-2048",
        key_size: 2048,
        criticality: "high",
        expired: false,
        vendor: "DigiCert",
        self_signed: false,
        days_until_expiry: 200,
        location: "api.example.com",
      },
      {
        algorithm: "ML-KEM-768",
        key_size: 3168,
        criticality: "low",
        expired: false,
        vendor: null,
        self_signed: false,
        days_until_expiry: 365,
        location: "pilot.example.com",
      },
    ],
  },
  null,
  2,
);

export default function AnomalyPanel() {
  const [cbomText, setCbomText] = useState<string>(DEMO_CBOM);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnomalyResponse | null>(null);

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
      const res = await fetch(`${base}/v1/gpu/anomaly/score`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cbom }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        if (res.status === 409) {
          throw new Error(
            "Detector not trained yet. Train it via `make -f Makefile.gpu anomaly-train` and set QTRUST_ANOMALY_MODEL.",
          );
        }
        throw new Error(`API ${res.status}: ${body.error ?? "scoring failed"}`);
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
          CBOM Anomaly Detection
        </h3>
        <span className="rounded-full bg-blue-500/10 px-2 py-0.5 text-xs font-medium text-blue-600">
          VAE
        </span>
      </div>
      <p className="mb-3 text-sm text-muted-foreground">
        Scores a CBOM against a variational autoencoder trained on normal
        cryptographic inventories — flags weak keys, drift, and unusual
        certificate patterns.
      </p>

      <textarea
        value={cbomText}
        onChange={(e) => setCbomText(e.target.value)}
        rows={6}
        aria-label="CBOM JSON"
        className="mb-3 w-full rounded-md border border-border bg-background p-2 font-mono text-xs text-foreground"
      />

      <button
        type="button"
        onClick={run}
        disabled={loading}
        className="w-full rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
      >
        {loading ? "Scoring..." : "Score CBOM"}
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
        <div
          className={`mt-4 rounded-md border p-3 ${
            result.is_anomalous
              ? "border-red-500/40 bg-red-500/10"
              : "border-green-500/40 bg-green-500/10"
          }`}
        >
          <div className="flex items-center justify-between">
            <span
              className={`text-sm font-semibold ${
                result.is_anomalous ? "text-red-600" : "text-green-600"
              }`}
            >
              {result.is_anomalous ? "ANOMALY DETECTED" : "Normal"}
            </span>
            <span className="font-mono text-xs text-muted-foreground">
              score {result.anomaly_score.toFixed(3)} / thr{" "}
              {result.threshold.toFixed(3)}
            </span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {result.asset_count} assets · evidence{" "}
            <span className="font-mono">{result.evidence_hash.slice(0, 14)}…</span>
          </p>
          {result.top_anomalous_assets.length > 0 && (
            <ul className="mt-2 space-y-1">
              {result.top_anomalous_assets.slice(0, 3).map((a) => (
                <li key={a.asset_index} className="text-xs">
                  <span className="font-mono text-foreground">
                    {a.location || `#${a.asset_index}`}
                  </span>{" "}
                  <span className="text-muted-foreground">
                    {a.algorithm} (err {a.reconstruction_error.toFixed(3)})
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
