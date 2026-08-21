"use client";

/**
 * Home page — links to dashboard, verification, and vendor portal.
 */
import Link from "next/link";

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-gradient-to-b from-slate-50 to-slate-100 px-4 text-center">
      <div className="max-w-2xl">
        <h1 className="text-4xl font-bold tracking-tight text-slate-900 sm:text-5xl">
          Q-Trust
        </h1>
        <p className="mt-4 text-lg text-slate-600">
          The cross-organizational protocol that coordinates the migration from classical
          cryptography (RSA, ECC) to post-quantum cryptography (PQC), on Base L2.
        </p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link
            href="/dashboard"
            className="rounded-lg bg-qtrust-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-qtrust-700"
          >
            Organization dashboard
          </Link>
          <Link
            href="/vendors"
            className="rounded-lg border border-slate-300 bg-white px-5 py-2.5 text-sm font-medium text-slate-700 transition hover:bg-slate-50"
          >
            Vendor portal
          </Link>
        </div>
        <p className="mt-8 text-xs text-slate-500">
          Verify an attestation by ID:{" "}
          <code className="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-slate-700">
            /v/&lt;asset-id&gt;
          </code>
        </p>
      </div>
    </main>
  );
}
