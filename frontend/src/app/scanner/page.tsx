import type { Metadata } from "next";
import { ScannerDashboard } from "@/components/scanner-dashboard";

export const metadata: Metadata = {
  title: "PQC Migration Scanner — Q-Trust",
  description:
    "Comprehensive cryptographic asset scanning for post-quantum migration readiness. Detect vulnerable algorithms, assess risk, and plan your migration roadmap.",
};

export default function ScannerPage() {
  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <div className="mx-auto max-w-6xl px-4 py-10">
        <div className="mb-8">
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            PQC Migration Scanner
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            Comprehensive cryptographic asset scanning — detect vulnerable algorithms,
            assess quantum risk, evaluate compliance, and plan your migration roadmap.
          </p>
        </div>
        <ScannerDashboard />
      </div>
    </main>
  );
}
