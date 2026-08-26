"use client";

/**
 * Landing page — hero with live verify, 3-step how-it-works, public stats,
 * contract addresses with explorer links, docs links, and architecture visual.
 *
 * Production-grade: mobile-responsive, Tailwind 4, accessible (headings, landmarks,
 * focus rings, aria-live for validation, skip link, reduced-motion safe).
 */

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { CHAIN, CONTRACTS, parseAssetId } from "@/lib/config";
import { API_BASE_URL } from "@/lib/api";
import {
  ShieldCheckIcon,
  ArrowRightIcon,
  ArrowTopRightOnSquareIcon,
  ChartBarIcon,
  DocumentCheckIcon,
  BeakerIcon,
  CpuChipIcon,
  ClockIcon,
} from "@/app/icons";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const EXAMPLE_ASSET_ID = "0x7b52d7b29272207cab6c061ee4e58141b434ce20eef955b5684c175ceb12c6b6";

function explorerBase(): string {
  const fromChain = (CHAIN.blockExplorers?.default?.url as string | undefined) ?? null;
  if (fromChain) return fromChain.replace(/\/$/, "");
  return CHAIN.id === 8453 ? "https://basescan.org" : "https://sepolia.basescan.org";
}

function isConfigured(addr: string): boolean {
  return !!addr && addr !== "0x0" && /^0x[0-9a-fA-F]{40}$/.test(addr);
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SkipLink() {
  return (
    <a
      href="#main-content"
      className="sr-only z-[100] rounded bg-qtrust-600 px-4 py-2 text-sm font-medium text-white focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2"
    >
      Skip to content
    </a>
  );
}

function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200/70 bg-white/80 backdrop-blur supports-[backdrop-filter]:bg-white/60">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
        <Link href="/" className="flex items-center gap-2.5 rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-qtrust-600 text-[11px] font-bold tracking-widest text-white" aria-hidden="true">
            QT
          </span>
          <span className="text-sm font-semibold tracking-tight text-slate-900">Q-Trust</span>
          <span className="hidden rounded-full bg-slate-900 px-2 py-0.5 text-[10px] font-medium tracking-wide text-white sm:inline-flex">Base L2</span>
        </Link>

        <nav aria-label="Primary" className="hidden items-center gap-1 md:flex">
          <Link href="/dashboard" className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            Dashboard
          </Link>
          <Link href="/vendors" className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            Vendors
          </Link>
          <Link href="/v" className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            Verify
          </Link>
          <a
            href={`${API_BASE_URL.replace(/\/$/, "")}/docs`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
          >
            API docs
            <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
            <span className="sr-only">(opens in new tab)</span>
          </a>
        </nav>

        <div className="flex items-center gap-2">
          <span className="hidden items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700 sm:inline-flex" aria-label="Network status: live">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" aria-hidden="true" />
            {CHAIN.name}
          </span>
          <Link
            href="/dashboard"
            className="inline-flex items-center justify-center rounded-lg bg-qtrust-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-qtrust-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2"
          >
            Launch app
          </Link>
        </div>
      </div>
    </header>
  );
}

function VerifyBox() {
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
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-lg shadow-slate-200/50 sm:p-6">
      <div className="flex items-center gap-2">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-600/20" aria-hidden="true">
          <ShieldCheckIcon className="h-4 w-4" />
        </span>
        <div>
          <h2 className="text-sm font-semibold text-slate-900">Verify an attestation</h2>
          <p className="text-xs text-slate-500">Public, no wallet required. Checked on-chain.</p>
        </div>
        <span className="ml-auto hidden rounded-full bg-slate-900 px-2 py-1 text-[10px] font-medium uppercase tracking-wide text-white sm:inline-flex">Live</span>
      </div>

      <label htmlFor="verify-input" className="mt-4 block text-xs font-medium text-slate-700">
        Asset ID <span className="font-normal text-slate-500">(0x + 64 hex)</span>
      </label>
      <div className="mt-1 flex gap-2">
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
          className="min-w-0 flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2.5 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-qtrust-600 focus:outline-none focus:ring-2 focus:ring-qtrust-600/20"
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
      <p id="verify-help" className="mt-2 text-[11px] leading-relaxed text-slate-500">
        Paste a full asset ID or try the example. You’ll be taken to{" "}
        <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[11px] text-slate-700">/v/&lt;asset-id&gt;</code> with on-chain status, provenance, and CLI instructions.
      </p>
      {error ? (
        <p id="verify-error" role="alert" aria-live="polite" className="mt-2 rounded-lg bg-rose-50 px-3 py-2 text-xs font-medium text-rose-700 ring-1 ring-inset ring-rose-600/20">
          {error}
        </p>
      ) : null}

      <div className="mt-4 flex flex-wrap gap-2">
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

      <div className="mt-4 rounded-lg bg-slate-900 p-3">
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

function Hero() {
  return (
    <section aria-labelledby="hero-heading" className="relative overflow-hidden border-b border-slate-200 bg-gradient-to-b from-white via-slate-50/70 to-slate-50">
      {/* decorative grid */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,theme(colors.slate.200)_1px,transparent_1px),linear-gradient(to_bottom,theme(colors.slate.200)_1px,transparent_1px)] bg-[size:32px_32px] opacity-[0.18] [mask-image:radial-gradient(ellipse_at_center,black_60%,transparent_75%)]" />
      <div className="relative mx-auto grid max-w-7xl grid-cols-1 gap-8 px-4 py-10 sm:px-6 sm:py-12 lg:grid-cols-12 lg:items-center lg:gap-10 lg:px-8 lg:py-16">
        <div className="lg:col-span-7">
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-600 shadow-sm">
            <span className="inline-flex h-2 w-2 rounded-full bg-emerald-500" aria-hidden="true" />
            NIST FIPS 203/204/205 — OMB M-23-02 ready
            <span aria-hidden="true" className="text-slate-300">·</span>
            <span className="text-slate-500">Base Sepolia by default</span>
          </div>

          <h1 id="hero-heading" className="mt-4 text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl lg:text-[2.6rem] lg:leading-[1.05]">
            The verifiable protocol for <span className="bg-gradient-to-r from-qtrust-600 to-teal-600 bg-clip-text text-transparent">PQC migration</span>
          </h1>
          <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-600 sm:text-[15px] sm:leading-7">
            Q-Trust coordinates the migration from classical cryptography (RSA, ECC) to post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA) — with every CBOM hash, vendor attestation, migration step, and audit anchored on <span className="font-medium text-slate-900">Base L2</span> and verifiable without trusting any single party.
          </p>

          <div className="mt-6 flex flex-wrap gap-3">
            <Link
              href="/dashboard"
              className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-qtrust-600 px-5 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-qtrust-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2"
            >
              Organization dashboard
              <ArrowRightIcon className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
            <Link
              href="/vendors"
              className="inline-flex items-center justify-center rounded-lg border border-slate-300 bg-white px-5 py-2.5 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2"
            >
              Vendor portal
            </Link>
            <a
              href="https://humoge7502.github.io/q-trust"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center justify-center gap-1 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-600 transition hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
            >
              Documentation
              <ArrowTopRightOnSquareIcon className="h-3.5 w-3.5" aria-hidden="true" />
            </a>
          </div>

          <ul className="mt-6 flex flex-wrap gap-2 text-xs text-slate-500" aria-label="Trust signals">
            <li className="inline-flex items-center gap-1.5 rounded-full bg-white px-3 py-1 ring-1 ring-slate-200">
              <ShieldCheckIcon className="h-3.5 w-3.5 text-emerald-600" aria-hidden="true" />
              Hash-only on-chain
            </li>
            <li className="inline-flex items-center gap-1.5 rounded-full bg-white px-3 py-1 ring-1 ring-slate-200">
              <DocumentCheckIcon className="h-3.5 w-3.5 text-slate-600" aria-hidden="true" />
              EIP-712 gasless
            </li>
            <li className="inline-flex items-center gap-1.5 rounded-full bg-white px-3 py-1 ring-1 ring-slate-200">
              <ChartBarIcon className="h-3.5 w-3.5 text-slate-600" aria-hidden="true" />
              GNN-ranked planning
            </li>
          </ul>

          <p className="mt-4 text-xs text-slate-500">
            Why now: NIST finalized PQC standards in 2024. U.S. federal agencies must inventory cryptography per OMB M-23-02. EU NIS2 and CISA impose similar obligations. Every regulated org must prove migration progress — Q-Trust makes that proof <em className="font-medium not-italic text-slate-700">verifiable</em>.
          </p>
        </div>

        <div className="lg:col-span-5">
          <VerifyBox />
          <p className="mt-3 text-center text-[11px] text-slate-500">
            No wallet needed to verify. Verification hits{" "}
            <code className="rounded bg-white px-1 py-0.5 font-mono ring-1 ring-slate-200">{CHAIN.name}</code> directly.
          </p>
        </div>
      </div>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    {
      n: "01",
      title: "Scan",
      desc: "Discover quantum-vulnerable crypto across 12+ languages and 10+ manifest formats. Emit CycloneDX CBOM + SARIF.",
      icon: BeakerIcon,
      cta: { label: "Run scanner", href: "/dashboard" },
      code: "crypto-inspector scan ./src --cyclonedx cbom.json --sarif results.sarif",
    },
    {
      n: "02",
      title: "Register & coordinate",
      desc: "Pin CBOM to IPFS, anchor its SHA-256 on AssetRegistry (gasless via EIP-712). Vendors attest PQC readiness; planner ranks migrations.",
      icon: CpuChipIcon,
      cta: { label: "Plan migration", href: "/dashboard" },
      code: "QTrustClient().register_cbom(cbom, pin_to_ipfs=True)",
    },
    {
      n: "03",
      title: "Verify",
      desc: "Anyone verifies on-chain without trusting Q-Trust: public page, Basescan, or SDK — all read the same contract state.",
      icon: ShieldCheckIcon,
      cta: { label: "Verify now", href: "/v" },
      code: "crypto-inspector verify 0x<asset-id>  # or /v/<asset-id>",
    },
  ] as const;

  return (
    <section aria-labelledby="how-heading" className="mx-auto max-w-7xl px-4 py-10 sm:px-6 sm:py-12 lg:px-8">
      <div className="mx-auto max-w-2xl text-center">
        <h2 id="how-heading" className="text-2xl font-bold tracking-tight text-slate-900 sm:text-3xl">
          How it works
        </h2>
        <p className="mt-3 text-sm leading-6 text-slate-600">
          A 3-step loop from discovery to verifiable delivery. Built for the cross-organizational reality: orgs, vendors, auditors, and regulators coordinate on shared, tamper-proof state.
        </p>
      </div>

      <ol className="mt-8 grid grid-cols-1 gap-4 sm:gap-6 lg:grid-cols-3" role="list">
        {steps.map((s) => (
          <li key={s.n} className="group relative flex flex-col rounded-2xl border border-slate-200 bg-white p-6 shadow-sm transition hover:shadow-md focus-within:ring-2 focus-within:ring-qtrust-600 focus-within:ring-offset-2">
            <div className="flex items-center gap-3">
              <span aria-hidden="true" className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-900 text-xs font-bold tracking-widest text-white">
                {s.n}
              </span>
              <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-50 text-slate-700 ring-1 ring-inset ring-slate-200">
                <s.icon className="h-4 w-4" aria-hidden="true" />
              </span>
              <h3 className="text-sm font-semibold text-slate-900">{s.title}</h3>
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-600">{s.desc}</p>
            <pre className="mt-4 overflow-x-auto rounded-lg bg-slate-900 p-3 text-[11px] leading-relaxed text-slate-100">
              <code>{s.code}</code>
            </pre>
            <Link href={s.cta.href} className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-qtrust-600 hover:text-qtrust-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
              {s.cta.label}
              <ArrowRightIcon className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
          </li>
        ))}
      </ol>

      <div className="mt-6 rounded-xl border border-amber-200 bg-amber-50 p-4">
        <p className="text-xs leading-6 text-amber-900">
          <strong className="font-semibold">Off-chain stays off-chain.</strong> Full CBOMs, evidence packages, and audit reports are pinned to IPFS or kept in customer storage. On-chain we store only 32-byte hashes, addresses, timestamps, and IPFS URIs — verifiable, gas-efficient, and privacy-preserving.
        </p>
      </div>
    </section>
  );
}

function PublicStats() {
  const [health, setHealth] = useState<{ status: string; chain_id: number; relayer: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
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

  const stats = [
    {
      label: "Registry contracts",
      value: "11",
      sub: "Asset · Vendor · Migration · Audit + 7 infra",
      icon: DocumentCheckIcon,
    },
    {
      label: "Tests & audits",
      value: "364",
      sub: "144 Foundry · 166 inspector · 32 SDK · 22 backend",
      icon: BeakerIcon,
    },
    {
      label: "Chain",
      value: CHAIN.name,
      sub: `ID ${CHAIN.id} · ${health ? `health: ${health.status}` : error ? `API unreachable (${error})` : "checking API…"}`,
      icon: CpuChipIcon,
    },
    {
      label: "Verification",
      value: "Public",
      sub: health?.relayer ? `Relayer ${health.relayer.slice(0, 10)}…` : "No wallet needed for /v/[id]",
      icon: ShieldCheckIcon,
    },
  ] as const;

  return (
    <section aria-labelledby="stats-heading" className="border-y border-slate-200 bg-white">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 sm:py-10 lg:px-8">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 id="stats-heading" className="text-sm font-semibold uppercase tracking-widest text-slate-500">
              Network at a glance
            </h2>
            <p className="mt-1 text-sm text-slate-600">Public, verifiable, and hash-only on-chain. Full CBOMs stay off-chain.</p>
          </div>
          <span className="inline-flex w-fit items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-700">
            <ClockIcon className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
            API: <code className="font-mono text-[11px]">{API_BASE_URL}</code>
          </span>
        </div>

        <dl className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {stats.map((s) => (
            <div key={s.label} className="rounded-xl border border-slate-200 bg-slate-50 p-5">
              <dt className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-500">
                <s.icon className="h-3.5 w-3.5" aria-hidden="true" />
                {s.label}
              </dt>
              <dd className="mt-2 text-2xl font-bold tracking-tight text-slate-900">{s.value}</dd>
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
            <a href={`${explorerBase()}/address/${CONTRACTS.auditRegistry !== "0x0" ? CONTRACTS.auditRegistry : ""}`} target="_blank" rel="noreferrer" className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-qtrust-600 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
              View AuditRegistry
              <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}

function ContractsSection() {
  const base = explorerBase();
  const contracts: Array<{ name: string; addr: string; role: string; desc: string }> = [
    { name: "AssetRegistry", addr: CONTRACTS.assetRegistry, role: "CBOM hashes", desc: "Registers SHA-256 CBOM hashes + IPFS URIs; EIP-712 gasless." },
    { name: "VendorRegistry", addr: CONTRACTS.vendorRegistry, role: "PQC attestations", desc: "Vendor product × version × algorithm support claims." },
    { name: "MigrationRegistry", addr: CONTRACTS.migrationRegistry, role: "Migration steps", desc: "Records from-algo → to-algo steps, validated against AssetRegistry." },
    { name: "AuditRegistry", addr: CONTRACTS.auditRegistry, role: "Audit results", desc: "Auditor results bound to on-chain migration count." },
  ];

  return (
    <section aria-labelledby="contracts-heading" className="mx-auto max-w-7xl px-4 py-10 sm:px-6 sm:py-12 lg:px-8">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between">
        <h2 id="contracts-heading" className="text-xl font-bold tracking-tight text-slate-900">
          Contracts on {CHAIN.name}
        </h2>
        <span className="inline-flex w-fit items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-600">
          <span className="h-2 w-2 rounded-full bg-emerald-500" aria-hidden="true" />
          Chain ID {CHAIN.id} ·{" "}
          <a href={base} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-qtrust-600 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            {base.replace(/^https?:\/\//, "")}
            <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
          </a>
        </span>
      </div>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
        All addresses are public and verifiable on Basescan. Hash-only on-chain storage keeps gas at ~$0.01 per attestation. Replace demo addresses by setting{" "}
        <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs">NEXT_PUBLIC_QTRUST_*_ADDRESS</code> at build time.
      </p>

      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        {contracts.map((c) => {
          const configured = isConfigured(c.addr);
          const href = configured ? `${base}/address/${c.addr}` : base;
          return (
            <div key={c.name} className="flex flex-col rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-slate-900">{c.name}</h3>
                    <span className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium ring-1 ring-inset ${configured ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20" : "bg-amber-50 text-amber-800 ring-amber-600/20"}`}>
                      {configured ? "configured" : "not configured"}
                    </span>
                  </div>
                  <p className="mt-1 text-xs font-medium uppercase tracking-wide text-slate-500">{c.role}</p>
                  <p className="mt-1 text-xs leading-5 text-slate-600">{c.desc}</p>
                </div>
                <a
                  href={href}
                  target="_blank"
                  rel="noreferrer"
                  aria-label={`${c.name} on Basescan${configured ? ` (${c.addr})` : ""}`}
                  className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
                >
                  Explorer
                  <ArrowTopRightOnSquareIcon className="h-3.5 w-3.5" aria-hidden="true" />
                </a>
              </div>
              <div className="mt-3 rounded-lg bg-slate-900 px-3 py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <code className="min-w-0 break-all font-mono text-xs text-slate-100" aria-label={`${c.name} address`}>
                    {c.addr}
                  </code>
                  {configured ? (
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(c.addr).catch(() => undefined)}
                      className="shrink-0 rounded border border-white/15 bg-white/10 px-2 py-1 text-[11px] font-medium text-white hover:bg-white/15 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
                      aria-label={`Copy ${c.name} address`}
                    >
                      Copy
                    </button>
                  ) : null}
                </div>
                {!configured ? (
                  <p className="mt-2 text-[11px] leading-5 text-amber-200/90">Set the env var to wire this contract. Deploys are verified on Basescan via <code className="rounded bg-white/10 px-1">forge script</code>.</p>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>

      <details className="mt-6 rounded-xl border border-slate-200 bg-white p-5">
        <summary className="cursor-pointer text-sm font-semibold text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">Environment variables</summary>
        <pre className="mt-3 overflow-x-auto rounded-lg bg-slate-50 p-3 text-xs leading-6 text-slate-700 ring-1 ring-inset ring-slate-200">
          <code>{`NEXT_PUBLIC_QTRUST_ASSET_REGISTRY_ADDRESS=0x...
NEXT_PUBLIC_QTRUST_VENDOR_REGISTRY_ADDRESS=0x...
NEXT_PUBLIC_QTRUST_MIGRATION_REGISTRY_ADDRESS=0x...
NEXT_PUBLIC_QTRUST_AUDIT_REGISTRY_ADDRESS=0x...
NEXT_PUBLIC_QTRUST_API_URL=https://api.qtrust.dev
NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID=<from cloud.walletconnect.com>
QTRUST_USE_MAINNET=false  # true → Base mainnet (8453)`}</code>
        </pre>
      </details>
    </section>
  );
}

function ArchitecturePlaceholder() {
  return (
    <section aria-labelledby="arch-heading" className="border-y border-slate-200 bg-slate-50">
      <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 sm:py-12 lg:px-8">
        <div className="flex flex-col gap-2">
          <h2 id="arch-heading" className="text-xl font-bold tracking-tight text-slate-900">
            Architecture
          </h2>
          <p className="max-w-3xl text-sm leading-6 text-slate-600">
            5-layer separation: Inspector → Risk → Planning → On-Chain → Presentation. Inspector fans out to language-specific probes; findings flow through risk and compliance scoring into CycloneDX, SARIF, evidence, and roadmap outputs — then optionally on-chain via gasless EIP-712.
          </p>
        </div>

        {/* Visual placeholder — accessible SVG with title/desc; replace with a real diagram image when available */}
        <figure className="mt-6 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 bg-slate-900 px-4 py-2.5">
            <figcaption className="flex items-center gap-2 text-xs font-medium tracking-wide text-slate-300">
              <span className="h-2 w-2 rounded-full bg-emerald-400" aria-hidden="true" />
              Q-Trust dataflow · replace this placeholder with{" "}
              <code className="rounded bg-white/10 px-1 py-0.5 font-mono text-[11px]">docs/architecture.svg</code>
            </figcaption>
          </div>
          <div role="img" aria-labelledby="arch-diagram-title arch-diagram-desc" className="p-4 sm:p-6">
            <p id="arch-diagram-title" className="sr-only">
              Q-Trust architecture diagram
            </p>
            <p id="arch-diagram-desc" className="sr-only">
              Inspector scans source, manifest, binary, and TLS sources and emits AssetFindings; Risk and Compliance score them; CycloneDX, SARIF, Evidence, and Roadmap outputs are produced; SDK pins to IPFS and submits EIP-712 gasless transactions to the four registries on Base; Frontend verifies on-chain and visualizes the pipeline.
            </p>
            <svg viewBox="0 0 960 280" className="h-auto w-full" role="img" aria-hidden="true">
              <title>Q-Trust architecture</title>
              <rect x="0" y="0" width="960" height="280" rx="16" fill="#f8fafc" stroke="#e2e8f0" />
              {/* nodes */}
              {[
                { x: 24, y: 56, w: 164, h: 72, label: "Inspector", sub: "source · manifest · binary · tls", fill: "#ffffff" },
                { x: 204, y: 56, w: 164, h: 72, label: "Risk & Compliance", sub: "NIST · CNSA · HNDL", fill: "#ffffff" },
                { x: 384, y: 56, w: 164, h: 72, label: "Outputs", sub: "CBOM · SARIF · Evidence · Roadmap", fill: "#ffffff" },
                { x: 564, y: 56, w: 184, h: 72, label: "SDK + IPFS", sub: "Pinata · CBOM hash · metadata URI", fill: "#f0fdfa" },
                { x: 764, y: 56, w: 172, h: 72, label: "Base L2", sub: "Asset · Vendor · Migration · Audit", fill: "#0a675f" },
              ].map((n) => (
                <g key={n.label}>
                  <rect x={n.x} y={n.y} width={n.w} height={n.h} rx="12" fill={n.fill} stroke="#e2e8f0" />
                  <text x={n.x + n.w / 2} y={n.y + 30} textAnchor="middle" fontSize="12" fontWeight="700" fill={n.fill === "#0a675f" ? "#ffffff" : "#0f172a"} fontFamily="ui-sans-serif, system-ui">
                    {n.label}
                  </text>
                  <text x={n.x + n.w / 2} y={n.y + 48} textAnchor="middle" fontSize="10" fill={n.fill === "#0a675f" ? "#ccfbf1" : "#64748b"} fontFamily="ui-monospace, monospace">
                    {n.sub}
                  </text>
                </g>
              ))}
              {/* arrows */}
              {[104, 284, 464, 654].map((x) => (
                <g key={x}>
                  <line x1={x + 84} y1={92} x2={x + 100} y2={92} stroke="#94a3b8" strokeWidth="1.5" markerEnd="url(#arrow)" />
                </g>
              ))}
              <defs>
                <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
                </marker>
              </defs>
              {/* bottom lane */}
              <rect x="24" y="160" width="912" height="96" rx="12" fill="#ffffff" stroke="#e2e8f0" strokeDasharray="6 4" />
              <text x="32" y="182" fontSize="10" fontWeight="600" fill="#475569" fontFamily="ui-sans-serif, system-ui">Presentation</text>
              <text x="32" y="200" fontSize="11" fill="#334155" fontFamily="ui-sans-serif, system-ui">Frontend — scanner dashboard · risk gauge · compliance panel · provenance graph · public verification (/v/[id])</text>
              <text x="32" y="218" fontSize="11" fill="#64748b" fontFamily="ui-sans-serif, system-ui">Verifier fetches CBOM from IPFS, checks hash on-chain, renders Code → Scanner → CBOM → Asset → Migration graph</text>
              <text x="32" y="240" fontSize="10" fill="#64748b" fontFamily="ui-monospace, monospace">Next.js 16 · wagmi 2 · RainbowKit · viem · Tailwind 4 · Radix · dynamic provenance graph</text>
            </svg>
            <p className="mt-3 text-center text-[11px] text-slate-500">
              Placeholder visual — export a high-fidelity diagram to{" "}
              <code className="rounded bg-slate-100 px-1 py-0.5 font-mono">docs/architecture.svg</code> and replace the inline SVG with an <code className="rounded bg-slate-100 px-1 py-0.5 font-mono">next/image</code> when ready.
            </p>
          </div>
        </figure>

        <div className="mt-4 flex flex-wrap gap-2 text-xs">
          <a href="/docs/ARCHITECTURE.md" className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-white px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            Read architecture doc →
          </a>
          <a href={`${API_BASE_URL.replace(/\/$/, "")}/docs`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-white px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            OpenAPI at /docs
            <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
          </a>
        </div>
      </div>
    </section>
  );
}

function DocsLinks() {
  const docs = [
    { title: "Whitepaper", href: "/docs/WHITEPAPER.md", desc: "Protocol spec + trust model + cryptographic choices." },
    { title: "Architecture", href: "/docs/ARCHITECTURE.md", desc: "5-layer design, data placement, cross-registry integrity." },
    { title: "API reference", href: `${API_BASE_URL.replace(/\/$/, "")}/docs`, desc: "OpenAPI + Swagger UI. 30+ routes, TypeBox validation.", external: true },
    { title: "Scanner guide", href: "/docs/PHASE_3_SCANNER.md", desc: "10 probe modules + CycloneDX output." },
    { title: "Contracts", href: "/docs/PHASE_1_CONTRACTS.md", desc: "UUPS · Pausable · EIP-712 · Timelock · 144 tests." },
    { title: "Backend", href: "/docs/PHASE_6_BACKEND.md", desc: "Fastify 5 · Postgres indexer · Redis · Prometheus." },
    { title: "GPU features", href: "/docs/GPU_FEATURES.md", desc: "GNN training, side-channel, quantum threat, VAE, RL." },
    { title: "GitHub", href: "https://github.com/humoge7502/q-trust", desc: "Source, CI, releases, discussions.", external: true },
  ];
  return (
    <section aria-labelledby="docs-heading" className="mx-auto max-w-7xl px-4 py-10 sm:px-6 sm:py-12 lg:px-8">
      <h2 id="docs-heading" className="text-xl font-bold tracking-tight text-slate-900">
        Documentation
      </h2>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">Start with the whitepaper, then dive into the component that matches your role. All docs are versioned alongside the code.</p>
      <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {docs.map((d) => (
          <a
            key={d.title}
            href={d.href}
            target={d.external ? "_blank" : undefined}
            rel={d.external ? "noreferrer" : undefined}
            className="group flex flex-col rounded-xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-slate-300 hover:shadow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2"
          >
            <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-900">
              {d.title}
              {d.external ? <ArrowTopRightOnSquareIcon className="h-3.5 w-3.5 text-slate-400 group-hover:text-slate-600" aria-hidden="true" /> : <span aria-hidden="true" className="text-slate-300">→</span>}
            </span>
            <span className="mt-1 text-xs leading-5 text-slate-600">{d.desc}</span>
          </a>
        ))}
      </div>

      <div className="mt-8 rounded-xl border border-slate-200 bg-white p-5 sm:p-6">
        <h3 className="text-sm font-semibold text-slate-900">Quick start</h3>
        <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
          <div className="rounded-lg bg-slate-900 p-4">
            <div className="text-[11px] font-medium uppercase tracking-widest text-slate-400">1 · Scan</div>
            <pre className="mt-2 overflow-x-auto text-xs text-slate-100">
              <code>{`pip install -e ./inspector
crypto-inspector scan ./src --cyclonedx cbom.json`}</code>
            </pre>
          </div>
          <div className="rounded-lg bg-slate-900 p-4">
            <div className="text-[11px] font-medium uppercase tracking-widest text-slate-400">2 · Contracts</div>
            <pre className="mt-2 overflow-x-auto text-xs text-slate-100">
              <code>{`cd contracts && forge test
forge script script/Deploy.s.sol --broadcast`}</code>
            </pre>
          </div>
          <div className="rounded-lg bg-slate-900 p-4">
            <div className="text-[11px] font-medium uppercase tracking-widest text-slate-400">3 · Verify</div>
            <pre className="mt-2 overflow-x-auto text-xs text-slate-100">
              <code>{`pip install -e ./sdk
python -c "from qtrust import QTrustClient; print(QTrustClient().verify_asset('0x...'))"`}</code>
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}

function SiteFooter() {
  return (
    <footer className="border-t border-slate-200 bg-white">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-slate-900 text-[11px] font-bold tracking-widest text-white" aria-hidden="true">
                QT
              </span>
              <span className="text-sm font-semibold text-slate-900">Q-Trust</span>
              <span className="text-xs text-slate-500">© {new Date().getFullYear()} · MIT</span>
            </div>
            <p className="mt-2 max-w-md text-xs leading-5 text-slate-500">
              PQC migration assurance on Base L2. Hash-only on-chain, verifiable by anyone. Not financial advice; not an audit. See{" "}
              <Link href="/docs/WHITEPAPER.md" className="underline decoration-slate-300 underline-offset-4 hover:text-slate-700">
                whitepaper
              </Link>{" "}
              and{" "}
              <a href="https://humoge7502.github.io/q-trust" target="_blank" rel="noreferrer" className="underline decoration-slate-300 underline-offset-4 hover:text-slate-700">
                docs site
              </a>
              .
            </p>
          </div>
          <nav aria-label="Footer" className="flex flex-wrap gap-x-6 gap-y-3 text-xs font-medium text-slate-600">
            <Link href="/dashboard" className="hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">Dashboard</Link>
            <Link href="/vendors" className="hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">Vendors</Link>
            <Link href="/v" className="hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">Verify</Link>
            <a href={`${API_BASE_URL.replace(/\/$/, "")}/docs`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
              API
              <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
            </a>
            <a href="https://github.com/humoge7502/q-trust" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
              GitHub
              <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
            </a>
            <a href="https://basescan.org" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
              Basescan
              <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
            </a>
          </nav>
        </div>
      </div>
    </footer>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function HomePage() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 antialiased">
      <SkipLink />
      <SiteHeader />
      <main id="main-content">
        <Hero />
        <HowItWorks />
        <PublicStats />
        <ContractsSection />
        <ArchitecturePlaceholder />
        <DocsLinks />
      </main>
      <SiteFooter />
    </div>
  );
}
