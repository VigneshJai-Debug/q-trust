/**
 * Org dashboard — migration progress, latest audit result, asset list.
 * Uses the connected wallet (wagmi/RainbowKit) for the org address.
 * Role-aware: shows onboarding wizard for new orgs, dashboard for existing ones.
 */
"use client";

import Link from "next/link";
import dynamic from "next/dynamic";
import { useQuery } from "@tanstack/react-query";
import { useAccount } from "wagmi";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { useUserRole } from "@/hooks/use-user-role";
import { GateLoading, WalletGate, useMounted } from "@/components/wallet-gate";
import { ShieldCheckIcon, XCircleIcon, ClockIcon } from "@/app/icons";
import { fetchOrgMigrations, fetchOrgAssets, fetchAssetVerification } from "@/lib/api";

const PlanningPanel = dynamic(
  () => import("@/components/planning-panel").then((m) => m.PlanningPanel),
  {
    ssr: false,
    loading: () => (
      <div className="mt-3 space-y-2" aria-hidden="true">
        <div className="h-4 w-1/3 animate-pulse rounded bg-slate-100" />
        <div className="h-8 w-full animate-pulse rounded bg-slate-100" />
        <div className="h-8 w-full animate-pulse rounded bg-slate-100" />
      </div>
    ),
  },
);

const SideChannelPanel = dynamic(() => import("@/components/side-channel-panel"), { ssr: false });
const QuantumThreatPanel = dynamic(() => import("@/components/quantum-threat-panel"), { ssr: false });
const AnomalyPanel = dynamic(() => import("@/components/anomaly-panel"), { ssr: false });
const RLPlanViewer = dynamic(() => import("@/components/rl-plan-viewer"), { ssr: false });

function StatCard({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</div>
      <div className="mt-2 text-2xl font-bold text-slate-900">{value}</div>
      {sub ? <div className="mt-1 text-xs text-slate-500">{sub}</div> : null}
    </div>
  );
}

function AuditBadge({ code, exists }: { code: number | null; exists: boolean }) {
  if (!exists) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-600">
        <ClockIcon className="h-3.5 w-3.5" /> No audit yet
      </span>
    );
  }
  if (code === 1) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700">
        <ShieldCheckIcon className="h-3.5 w-3.5" /> Passed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-rose-50 px-3 py-1 text-xs font-medium text-rose-700">
      <XCircleIcon className="h-3.5 w-3.5" /> Failed
    </span>
  );
}

function DashboardInner() {
  const { address, isConnecting, isReconnecting } = useAccount();
  const org = address ?? null;
  const loading = isConnecting || isReconnecting;
  const { role, isOrg, isLoading: roleLoading } = useUserRole();

  const orgQuery = useQuery({
    queryKey: ["org", org],
    queryFn: async () => {
      const [migrations, assets] = await Promise.all([
        fetchOrgMigrations(org!),
        fetchOrgAssets(org!),
      ]);
      return { migrations, assets };
    },
    enabled: Boolean(org),
    staleTime: 30_000,
  });

  if (loading || roleLoading) {
    return <div className="py-24 text-center text-sm text-slate-500">Loading wallet…</div>;
  }

  if (!org) {
    return (
      <div className="mx-auto max-w-md py-24 text-center">
        <h1 className="text-xl font-bold text-slate-900">Org dashboard</h1>
        <p className="mt-3 text-sm text-slate-600">
          Connect a wallet to view your migration progress and audit status.
        </p>
        <div className="mt-6 flex justify-center [&>div]:w-auto">
          <ConnectButton />
        </div>
      </div>
    );
  }

  // Role-aware routing: show onboarding for new orgs, dashboard for existing ones
  if (!isOrg) {
    return (
      <div className="mx-auto max-w-md py-24 text-center">
        <h1 className="text-xl font-bold text-slate-900">Welcome to Q-Trust</h1>
        <p className="mt-3 text-sm text-slate-600">
          Your wallet is connected, but you haven&rsquo;t registered any assets yet.
        </p>
        <div className="mt-6 space-y-3">
          <Link
            href="/"
            className="block rounded-lg bg-qtrust-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-qtrust-700"
          >
            Register your organization
          </Link>
          <p className="text-xs text-slate-500">
            Or visit the{" "}
            <Link href="/vendors" className="text-qtrust-600 hover:underline">
              vendor portal
            </Link>{" "}
            if you&rsquo;re a vendor.
          </p>
        </div>
      </div>
    );
  }

  const p = orgQuery.data?.migrations?.progress;
  const latest = orgQuery.data?.migrations?.latest_audit;
  const assets = orgQuery.data?.assets ?? [];

  return (
    <div className="mx-auto max-w-5xl px-4 py-10">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Org dashboard</h1>
          <p className="mt-1 break-all font-mono text-xs text-slate-500">{org}</p>
        </div>
        <AuditBadge code={latest?.result_code ?? null} exists={latest?.exists ?? false} />
      </div>

      <div className="mt-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Total migrations" value={String(p?.total_migrations ?? 0)} />
        <StatCard label="Verified" value={String(p?.verified_migrations ?? 0)} sub="on-chain verified" />
        <StatCard label="Pending" value={String(p?.unverified_migrations ?? 0)} />
      </div>

      {latest?.exists ? (
        <p className="mt-4 text-xs text-slate-500">
          Latest audit: <span className="font-medium">{latest.result}</span> (code {latest.result_code}) at{" "}
          {new Date(latest.timestamp * 1000).toLocaleString()}
        </p>
      ) : null}

      <h2 className="mt-10 text-sm font-semibold uppercase tracking-wider text-slate-500">
        Migration plan
      </h2>
      <PlanningPanel />

      <h2 className="mt-10 text-sm font-semibold uppercase tracking-wider text-slate-500">
        Registered assets ({assets.length})
      </h2>
      <div className="mt-3 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        {assets.length === 0 ? (
          <p className="p-6 text-sm text-slate-500">
            No assets registered yet. Register one with{" "}
            <code className="rounded bg-slate-100 px-1">crypto-inspector register-cbom</code>.
          </p>
        ) : (
          <ul className="divide-y divide-slate-100">
            {assets.map((a) => (
              <li key={a.asset_id} className="flex items-center justify-between gap-4 px-5 py-4">
                <div className="min-w-0">
                  <div className="truncate font-mono text-xs text-slate-700">{a.asset_id}</div>
                  <div className="mt-1 truncate text-xs text-slate-500">{a.metadata_uri}</div>
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  {a.active ? (
                    <span className="rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700">active</span>
                  ) : (
                    <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-500">inactive</span>
                  )}
                  <Link href={`/v/${a.asset_id}`} className="text-xs font-medium text-qtrust-600 hover:underline">
                    Verify
                  </Link>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <h2 className="mt-10 text-sm font-semibold uppercase tracking-wider text-slate-500">
        Sample verification flow
      </h2>
      <div className="mt-3 flex flex-wrap gap-3">
        {assets.slice(0, 3).map((a) => (
          <VerifyButton key={a.asset_id} assetId={a.asset_id} />
        ))}
      </div>

      <h2 className="mt-10 text-sm font-semibold uppercase tracking-wider text-slate-500">
        GPU-accelerated analysis
      </h2>
      <p className="mt-1 text-xs text-slate-500">
        Live A100-backed tools: side-channel verification of PQC binaries,
        Shor-based quantum threat estimates, VAE anomaly scoring, and the RL
        migration planner. Requires <code className="rounded bg-slate-100 px-1">QTRUST_GPU_ENABLED=true</code> on
        the API.
      </p>
      <div className="mt-3 grid grid-cols-1 gap-4 md:grid-cols-2">
        <SideChannelPanel />
        <QuantumThreatPanel />
        <AnomalyPanel />
        <RLPlanViewer />
      </div>
    </div>
  );
}

function VerifyButton({ assetId }: { assetId: string }) {
  const { data } = useQuery({
    queryKey: ["verify", assetId],
    queryFn: () => fetchAssetVerification(assetId),
    enabled: false,
  });
  return (
    <button
      onClick={() => fetchAssetVerification(assetId).catch(() => undefined)}
      className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-medium text-slate-700 shadow-sm transition hover:border-qtrust-500 hover:text-qtrust-700"
    >
      Verify {data ? (data.active ? "✓ active" : "✗ inactive") : "on-chain"}
    </button>
  );
}

export default function DashboardPage() {
  const mounted = useMounted();
  const { address, isConnecting, isReconnecting } = useAccount();
  const { role, isLoading: roleLoading } = useUserRole();

  if (!mounted || isConnecting || isReconnecting || roleLoading) {
    return (
      <main className="min-h-screen bg-slate-50 text-slate-900">
        <GateLoading />
      </main>
    );
  }

  if (!address || role === "none") {
    return (
      <main className="min-h-screen bg-slate-50 text-slate-900">
        <WalletGate description="Connect a wallet to view your organization's migration progress, audit status, and registered assets." />
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <DashboardInner />
    </main>
  );
}