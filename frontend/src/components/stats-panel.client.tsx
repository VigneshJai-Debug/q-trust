"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { CHAIN, CONTRACTS } from "@/lib/config";
import { API_BASE_URL } from "@/lib/api";
import { ShieldCheckIcon, ChartBarIcon, DocumentCheckIcon, BeakerIcon, CpuChipIcon, ClockIcon } from "@/app/icons";

function useCountUp(target: number, duration = 1100, enabled = true): number {
  const [value, setValue] = useState(0);
  const rafRef = useRef<number | null>(null);
  const startRef = useRef<number | null>(null);
  const prefersReduced = useRef(false);

  useEffect(() => {
    if (typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      prefersReduced.current = true;
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    if (prefersReduced.current) {
      setValue(target);
      return;
    }
    const start = performance.now();
    startRef.current = start;

    const tick = (now: number) => {
      const elapsed = now - (startRef.current ?? now);
      const progress = Math.min(elapsed / duration, 1);
      // easeOutCubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(eased * target));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [target, duration, enabled]);

  return value;
}

function LiveTicker() {
  const items = [
    `Chain ${CHAIN.name} · ID ${CHAIN.id}`,
    "Hash-only on-chain · IPFS off-chain",
    "NIST FIPS 203/204/205 · OMB M-23-02 ready",
    "11 registry + infra contracts",
    "364 tests · Foundry · Inspector · SDK · Backend",
    "EIP-712 gasless · UUPS · Pausable",
  ];
  return (
    <div
      aria-label="Live network ticker"
      className="relative overflow-hidden border-y border-slate-200/70 bg-slate-900 py-2"
    >
      <div className="pointer-events-none absolute inset-y-0 left-0 w-20 bg-gradient-to-r from-slate-900 to-transparent" aria-hidden="true" />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-20 bg-gradient-to-l from-slate-900 to-transparent" aria-hidden="true" />
      <div className="flex animate-[ticker_28s_linear_infinite] whitespace-nowrap will-change-transform hover:[animation-play-state:paused] motion-reduce:animate-none">
        {[...items, ...items].map((text, i) => (
          <span key={i} className="inline-flex items-center gap-2 px-6 text-xs font-medium tracking-wide text-slate-300">
            <span className="h-1 w-1 rounded-full bg-emerald-400" aria-hidden="true" />
            {text}
            <span className="mx-2 text-slate-600" aria-hidden="true">·</span>
          </span>
        ))}
      </div>
      <style>{`@keyframes ticker { 0% { transform: translateX(0); } 100% { transform: translateX(-50%); } }`}</style>
    </div>
  );
}

function ChainStatusPill({
  health,
  error,
}: {
  health: { status: string; chain_id: number; relayer: string } | null;
  error: string | null;
}) {
  const isLive = health?.status === "ok" || health?.status === "healthy";
  const label = health ? `API ${health.status}` : error ? "API unreachable" : "Checking API…";
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium shadow-sm backdrop-blur ${
        isLive
          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
          : error
            ? "border-amber-200 bg-amber-50 text-amber-800"
            : "border-slate-200 bg-white text-slate-600"
      }`}
      aria-live="polite"
      aria-label={`Network status: ${label}`}
    >
      <span className="relative flex h-2 w-2">
        <span
          className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 motion-reduce:hidden ${isLive ? "bg-emerald-400" : error ? "bg-amber-400" : "bg-slate-400"}`}
          aria-hidden="true"
        />
        <span className={`relative inline-flex h-2 w-2 rounded-full ${isLive ? "bg-emerald-500" : error ? "bg-amber-500" : "bg-slate-400"}`} aria-hidden="true" />
      </span>
      {CHAIN.name}
      <span className="text-slate-300" aria-hidden="true">·</span>
      <span className={isLive ? "text-emerald-700" : error ? "text-amber-700" : "text-slate-500"}>{label}</span>
      {health?.relayer ? (
        <>
          <span className="text-slate-300" aria-hidden="true">·</span>
          <span className="font-mono text-[11px]">relayer {health.relayer.slice(0, 10)}…</span>
        </>
      ) : null}
    </span>
  );
}

export function StatsTicker() {
  return <LiveTicker />;
}

export function PublicStatsClient() {
  const [health, setHealth] = useState<{ status: string; chain_id: number; relayer: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    let cancelled = false;
    const ctrl = new AbortController();
    fetch(`${API_BASE_URL.replace(/\/$/, "")}/health`, { signal: ctrl.signal, cache: "no-store" })
      .then(async (r) => {
        if (!r.ok) throw new Error(`${r.status}`);
        const j = (await r.json()) as { status: string; chain_id: number; relayer: string };
        if (!cancelled) setHealth(j);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, []);

  const count11 = useCountUp(11, 900, mounted);
  const count364 = useCountUp(364, 1400, mounted);

  const stats = [
    {
      label: "Registry contracts",
      value: mounted ? String(count11) : "11",
      sub: "Asset · Vendor · Migration · Audit + 7 infra",
      icon: DocumentCheckIcon,
      live: false,
    },
    {
      label: "Tests & audits",
      value: mounted ? String(count364) : "364",
      sub: "144 Foundry · 166 inspector · 32 SDK · 22 backend",
      icon: BeakerIcon,
      live: false,
    },
    {
      label: "Chain",
      value: CHAIN.name,
      sub: `ID ${CHAIN.id} · ${health ? `health: ${health.status}` : error ? `API unreachable (${error})` : "checking API…"}`,
      icon: CpuChipIcon,
      live: true,
    },
    {
      label: "Verification",
      value: "Public",
      sub: health?.relayer ? `Relayer ${health.relayer.slice(0, 10)}…` : "No wallet needed for /v/[id]",
      icon: ShieldCheckIcon,
      live: true,
    },
  ] as const;

  return (
    <section aria-labelledby="stats-heading" className="border-y border-slate-200 bg-white">
      <LiveTicker />
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 sm:py-10 lg:px-8">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 id="stats-heading" className="text-sm font-semibold uppercase tracking-widest text-slate-500">
              Network at a glance
            </h2>
            <p className="mt-1 text-sm text-slate-600">Public, verifiable, and hash-only on-chain. Full CBOMs stay off-chain.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <ChainStatusPill health={health} error={error} />
            <span className="inline-flex w-fit items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-700">
              <ClockIcon className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
              API: <code className="font-mono text-[11px]">{API_BASE_URL}</code>
            </span>
          </div>
        </div>

        <dl className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {stats.map((s) => (
            <div
              key={s.label}
              className="group relative overflow-hidden rounded-xl border border-slate-200 bg-slate-50 p-5 transition hover:border-slate-300 hover:shadow-sm"
            >
              <div
                aria-hidden="true"
                className="pointer-events-none absolute -right-8 -top-8 h-20 w-20 rounded-full bg-gradient-to-br from-qtrust-500/10 to-teal-500/10 opacity-0 transition group-hover:opacity-100"
              />
              <dt className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-500">
                <s.icon className="h-3.5 w-3.5" aria-hidden="true" />
                {s.label}
                {s.live ? <span className="ml-auto h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500 motion-reduce:animate-none" aria-hidden="true" /> : null}
              </dt>
              <dd className="mt-2 text-2xl font-bold tracking-tight text-slate-900 tabular-nums">{s.value}</dd>
              <dd className="mt-1 text-xs leading-5 text-slate-600">{s.sub}</dd>
            </div>
          ))}
        </dl>

        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="rounded-lg border border-slate-200 bg-white p-4">
            <div className="text-xs font-semibold text-slate-900">For orgs</div>
            <p className="mt-1 text-xs leading-5 text-slate-600">Connect wallet → see migrations, audit result, and registered assets. EIP-712 gasless — you sign, the relayer pays.</p>
            <Link href="/dashboard" className="mt-3 inline-flex text-xs font-medium text-qtrust-600 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">Go to dashboard →</Link>
          </div>
          <div className="rounded-lg border border-slate-200 bg-white p-4">
            <div className="text-xs font-semibold text-slate-900">For vendors</div>
            <p className="mt-1 text-xs leading-5 text-slate-600">Attest product × version × algorithm readiness with evidence URIs. Verifiable by any customer before procurement.</p>
            <Link href="/vendors" className="mt-3 inline-flex text-xs font-medium text-qtrust-600 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">Open vendor portal →</Link>
          </div>
          <div className="rounded-lg border border-slate-200 bg-white p-4">
            <div className="text-xs font-semibold text-slate-900">For auditors</div>
            <p className="mt-1 text-xs leading-5 text-slate-600">Post audit attestations bound to on-chain migration counts. Auditors cannot claim more migrations than exist on-chain.</p>
            <a href={`${(CHAIN.blockExplorers?.default?.url ?? (CHAIN.id === 8453 ? "https://basescan.org" : "https://sepolia.basescan.org")).replace(/\/$/, "")}/address/${CONTRACTS.auditRegistry !== "0x0" ? CONTRACTS.auditRegistry : ""}`} target="_blank" rel="noreferrer" className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-qtrust-600 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
              View AuditRegistry
              <span aria-hidden="true">↗</span>
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
