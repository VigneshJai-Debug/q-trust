"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { parseAssetId } from "@/lib/config";
import { ShieldCheckIcon, ArrowRightIcon } from "@/app/icons";

const EXAMPLE_ASSET_ID = "0x7b52d7b29272207cab6c061ee4e58141b434ce20eef955b5684c175ceb12c6b6";

export function VerifyBox() {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleVerify() {
    const trimmed = value.trim();
    if (!trimmed) {
      setError("Enter an asset ID (0x + 64 hex chars).");
      return;
    }
    try {
      const parsed = parseAssetId(trimmed);
      setError(null);
      router.push(`/v/${parsed}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid asset ID.");
    }
  }

  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/60 bg-white/80 p-5 shadow-xl shadow-slate-200/50 backdrop-blur-xl supports-[backdrop-filter]:bg-white/70 sm:p-6">
      {/* subtle inner highlight for glass */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 rounded-2xl border border-white/40"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-16 -right-16 h-40 w-40 rounded-full bg-gradient-to-br from-qtrust-500/20 via-teal-400/15 to-cyan-300/20 blur-2xl"
      />
      <div className="relative flex items-center gap-2">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-600/20" aria-hidden="true">
          <ShieldCheckIcon className="h-4 w-4" />
        </span>
        <div>
          <h2 className="text-sm font-semibold text-slate-900">Verify an attestation</h2>
          <p className="text-xs text-slate-500">Public, no wallet required. Checked on-chain.</p>
        </div>
        <span className="ml-auto hidden items-center gap-1 rounded-full bg-slate-900 px-2 py-1 text-[10px] font-medium uppercase tracking-wide text-white sm:inline-flex">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" aria-hidden="true" />
          Live
        </span>
      </div>

      <label htmlFor="verify-input" className="relative mt-4 block text-xs font-medium text-slate-700">
        Asset ID <span className="font-normal text-slate-500">(0x + 64 hex)</span>
      </label>
      <div className="relative mt-1 flex gap-2">
        <input
          id="verify-input"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            if (error) setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleVerify();
          }}
          placeholder={EXAMPLE_ASSET_ID}
          spellCheck={false}
          autoComplete="off"
          inputMode="text"
          aria-describedby={error ? "verify-error verify-help" : "verify-help"}
          aria-invalid={error ? "true" : undefined}
          className="min-w-0 flex-1 rounded-lg border border-slate-300/80 bg-white/90 px-3 py-2.5 font-mono text-xs text-slate-900 placeholder:text-slate-400 backdrop-blur focus:border-qtrust-600 focus:outline-none focus:ring-2 focus:ring-qtrust-600/20"
        />
        <button
          type="button"
          onClick={handleVerify}
          className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-black focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-900 focus-visible:ring-offset-2 disabled:opacity-50"
        >
          Verify
          <ArrowRightIcon className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </div>
      <p id="verify-help" className="relative mt-2 text-[11px] leading-relaxed text-slate-500">
        Paste a full asset ID or try the example. You’ll be taken to{" "}
        <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[11px] text-slate-700">/v/&lt;asset-id&gt;</code> with on-chain status, provenance, and CLI instructions.
      </p>
      {error ? (
        <p id="verify-error" role="alert" aria-live="polite" className="relative mt-2 rounded-lg bg-rose-50 px-3 py-2 text-xs font-medium text-rose-700 ring-1 ring-inset ring-rose-600/20">
          {error}
        </p>
      ) : null}

      <div className="relative mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setValue(EXAMPLE_ASSET_ID)}
          className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-700 transition hover:bg-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
        >
          Fill example
        </button>
        <Link
          href="/v"
          className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-600 transition hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
        >
          What is an asset ID?
        </Link>
      </div>

      <div className="relative mt-4 rounded-lg bg-slate-900 p-3">
        <div className="text-[10px] font-medium uppercase tracking-widest text-slate-400">Independently via CLI</div>
        <pre className="mt-1 overflow-x-auto text-[11px] leading-relaxed text-slate-100">
          <code>{`pip install qtrust-sdk
python -c "from qtrust import QTrustClient; print(QTrustClient().verify_asset('${EXAMPLE_ASSET_ID.slice(0, 18)}…'))"
# or
crypto-inspector verify ${EXAMPLE_ASSET_ID.slice(0, 18)}…`}</code>
        </pre>
      </div>
    </div>
  );
}

export const VERIFY_EXAMPLE_ASSET_ID = EXAMPLE_ASSET_ID;
