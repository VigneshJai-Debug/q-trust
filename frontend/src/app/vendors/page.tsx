/**
 * Vendor portal — attestations for a vendor address, product support lookup.
 * Role-aware: shows onboarding for new vendors, portal for existing ones.
 */
"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useAccount } from "wagmi";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { useUserRole } from "@/hooks/use-user-role";
import { AttestationForm } from "@/components/attestation-form";
import { ShieldCheckIcon, XCircleIcon } from "@/app/icons";
import { fetchVendorAttestations, checkProductSupport, type VendorAttestationInfo } from "@/lib/api";

function AttestationRow({ att }: { att: VendorAttestationInfo }) {
  return (
    <li className="flex items-center justify-between gap-4 px-5 py-4">
      <div className="min-w-0">
        <div className="truncate font-mono text-xs text-slate-700">{att.attestation_id}</div>
        <div className="mt-1 text-xs text-slate-500">
          {att.product_id} · v{att.version} · {att.algorithm}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        {att.revoked ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-rose-50 px-2.5 py-0.5 text-xs font-medium text-rose-700">
            <XCircleIcon className="h-3.5 w-3.5" /> revoked
          </span>
        ) : att.supported ? (
          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700">
            <ShieldCheckIcon className="h-3.5 w-3.5" /> supported
          </span>
        ) : (
          <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-500">unsupported</span>
        )}
        <a
          href={att.evidence_uri}
          target="_blank"
          rel="noreferrer"
          className="text-xs font-medium text-qtrust-600 hover:underline"
        >
          evidence
        </a>
      </div>
    </li>
  );
}

function VendorsInner() {
  const { address, isConnecting, isReconnecting } = useAccount();
  const vendor = address ?? null;
  const loading = isConnecting || isReconnecting;
  const { isVendor, isLoading: roleLoading } = useUserRole();

  const [productId, setProductId] = useState("DigiCert-TLS");
  const [version, setVersion] = useState("5.2.1");
  const [algorithm, setAlgorithm] = useState("ML-DSA-441");

  const attestations = useQuery({
    queryKey: ["vendor-attestations", vendor],
    queryFn: () => fetchVendorAttestations(vendor!),
    enabled: Boolean(vendor),
  });

  const support = useQuery({
    queryKey: ["product-support", productId, version, algorithm],
    queryFn: () => checkProductSupport(productId, version, algorithm),
    enabled: Boolean(productId && version && algorithm),
  });

  if (loading || roleLoading) {
    return <div className="py-24 text-center text-sm text-slate-500">Loading wallet…</div>;
  }

  // Role-aware routing: show onboarding for non-vendors
  if (vendor && !isVendor) {
    return (
      <div className="mx-auto max-w-md py-24 text-center">
        <h1 className="text-xl font-bold text-slate-900">Welcome to Q-Trust Vendor Portal</h1>
        <p className="mt-3 text-sm text-slate-600">
          Your wallet is connected, but you're not registered as a vendor yet.
        </p>
        <div className="mt-6 space-y-3">
          <Link
            href="/"
            className="block rounded-lg bg-qtrust-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-qtrust-700"
          >
            Register as a vendor
          </Link>
          <p className="text-xs text-slate-500">
            Or visit the{" "}
            <Link href="/dashboard" className="text-qtrust-600 hover:underline">
              org dashboard
            </Link>{" "}
            if you're an organization.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl px-4 py-10">
      <h1 className="text-2xl font-bold tracking-tight text-slate-900">Vendor portal</h1>
      <p className="mt-1 text-sm text-slate-600">
        Attestations issued by a vendor and product support lookups.
      </p>

      {!loading && !vendor ? (
        <div className="mt-6 [&>div]:w-auto">
          <ConnectButton />
        </div>
      ) : null}

      {vendor ? (
        <>
          <h2 className="mt-10 text-sm font-semibold uppercase tracking-wider text-slate-500">
            Attestations ({attestations.data?.attestations.length ?? 0})
          </h2>
          <div className="mt-3 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            {attestations.isLoading ? (
              <p className="p-6 text-sm text-slate-500">Loading…</p>
            ) : attestations.data?.attestations.length ? (
              <ul className="divide-y divide-slate-100">
                {attestations.data.attestations.map((a) => (
                  <AttestationRow key={a.attestation_id} att={a} />
                ))}
              </ul>
            ) : (
              <p className="p-6 text-sm text-slate-500">
                No attestations. Issue one with the form below or{" "}
                <code className="rounded bg-slate-100 px-1">crypto-inspector attest-product</code>.
              </p>
            )}
          </div>

          <AttestationForm vendor={vendor} />

          <h2 className="mt-10 text-sm font-semibold uppercase tracking-wider text-slate-500">
            Product support check
          </h2>
          <div className="mt-3 flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <label className="block text-xs font-medium text-slate-600">
              Product ID
              <input
                value={productId}
                onChange={(e) => setProductId(e.target.value)}
                className="mt-1 block w-48 rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
            </label>
            <label className="block text-xs font-medium text-slate-600">
              Version
              <input
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                className="mt-1 block w-28 rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
            </label>
            <label className="block text-xs font-medium text-slate-600">
              Algorithm
              <input
                value={algorithm}
                onChange={(e) => setAlgorithm(e.target.value)}
                className="mt-1 block w-40 rounded-lg border border-slate-300 px-3 py-2 text-sm"
              />
            </label>
            <div className="ml-auto text-sm">
              {support.data?.supported ? (
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-3 py-1 font-medium text-emerald-700">
                  <ShieldCheckIcon className="h-4 w-4" /> Supported
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-3 py-1 font-medium text-slate-600">
                  <XCircleIcon className="h-4 w-4" /> Not supported
                </span>
              )}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}

export default function VendorsPage() {
  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <VendorsInner />
    </main>
  );
}