/**
 * Public verification entry — enter an asset ID or go straight to a link.
 */
import Link from "next/link";
import { ShieldCheckIcon } from "@/app/icons";

export default function VerifyIndexPage() {
  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <div className="mx-auto flex min-h-screen max-w-2xl flex-col items-center justify-center px-4 text-center">
        <div className="rounded-xl border border-slate-200 bg-white p-8 shadow-sm">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-50">
            <ShieldCheckIcon className="h-6 w-6 text-emerald-600" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Verify a Q-Trust attestation
          </h1>
          <p className="mt-3 text-sm text-slate-600">
            Paste a full asset ID (0x-prefixed, 32 bytes) into the address bar:
          </p>
          <pre className="mt-4 overflow-auto rounded-lg bg-slate-900 p-4 text-left text-xs text-slate-100">
            <code>/v/0x7b52d7b29272207cab6c061ee4e58141b434ce20eef955b5684c175ceb12c6b6</code>
          </pre>
          <p className="mt-4 text-sm text-slate-600">
            Or use the SDK CLI:
          </p>
          <pre className="mt-2 overflow-auto rounded-lg bg-slate-900 p-4 text-left text-xs text-slate-100">
            <code>crypto-inspector verify 0x&lt;asset-id&gt;</code>
          </pre>
          <Link
            href="/"
            className="mt-6 inline-block rounded-lg bg-qtrust-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-qtrust-700"
          >
            Back to home
          </Link>
        </div>
      </div>
    </main>
  );
}