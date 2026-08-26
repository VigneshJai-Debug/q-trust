/**
 * Public verification page — renders an attestation by its on-chain asset ID.
 *
 * Server component (async). Fetches from the Q-Trust backend at request time
 * (force-dynamic — a verification result must never be served stale).
 * Shows:
 *   - Status badge (VALID/REVOKED)
 *   - Organization DID
 *   - Timestamp
 *   - CBOM hash
 *   - Provenance graph (Code -> Scanner -> CBOM -> Asset -> Migration),
 *     rendered client-side via next/dynamic so its bundle stays off the
 *   - Metadata from IPFS (if available)
 *   - "Verify independently" CLI command at the bottom
 */
import { notFound } from "next/navigation";
import { ArrowTopRightOnSquareIcon, ShieldCheckIcon, XCircleIcon, ClockIcon } from "@/app/icons";
import { ProvenanceGraph } from "@/components/provenance-graph";

import { fetchAsset, fetchAssetVerification, fetchIpfsJson, type AssetInfo, type AssetVerification } from "@/lib/api";
import { parseAssetId } from "@/lib/config";

interface Props {
  params: Promise<{ id: string }>;
}

export default async function VerificationPage({ params }: Props) {
  const { id } = await params;

  let asset: AssetInfo;
  let verification: AssetVerification;
  let ipfsMetadata: Record<string, unknown> | null = null;

  try {
    asset = await fetchAsset(id);
    verification = await fetchAssetVerification(id);
  } catch (err) {
    if (err instanceof Error && err.message.includes("404")) {
      notFound();
    }
    throw err;
  }

  // Fetch IPFS metadata in parallel (non-blocking — page renders without it).
  if (asset.metadata_uri) {
    try {
      ipfsMetadata = await fetchIpfsJson(asset.metadata_uri);
    } catch {
      // ignore — page still renders
    }
  }

  const status = verification.active ? "VALID" : "REVOKED";
  const timestamp = new Date(asset.timestamp * 1000).toISOString();

  // Audit H-7: asset.asset_id is server-controlled but must never be trusted
  // blindly — it is interpolated into copy-pastable shell/Python snippets
  // below. Only render the CLI block when the ID strictly matches
  // 0x + 64 hex chars (parseAssetId enforces this).
  let safeAssetId: string | null = null;
  try {
    safeAssetId = parseAssetId(asset.asset_id);
  } catch {
    safeAssetId = null;
  }

  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <header className="mb-8 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 sm:text-3xl">
              Q-Trust Attestation
            </h1>
            <p className="mt-1 text-sm text-slate-600">
              Public verification of cryptographic asset provenance on {verification.chain_name}
            </p>
          </div>
          <StatusBadge status={status} />
        </header>

        {/* Asset ID + key facts */}
        <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold text-slate-800">Asset details</h2>
          <dl className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
            <Field label="Asset ID" value={asset.asset_id} mono />
            <Field label="Status" value={status} />
            <Field label="Organization DID" value={asset.org_did} mono />
            <Field label="Chain" value={`${verification.chain_name} (id ${verification.chain_id})`} />
            <Field
              label="Registered at"
              value={timestamp}
              icon={<ClockIcon className="h-4 w-4 text-slate-500" />}
            />
            <Field label="Last updated" value={new Date(asset.last_updated * 1000).toISOString()} />
            <Field label="CBOM hash" value={asset.cbom_hash} mono colSpan2 />
            <Field label="Metadata URI" value={asset.metadata_uri} mono colSpan2 />
          </dl>
        </section>

        {/* Provenance graph */}
        <section className="mt-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold text-slate-800">
            Provenance graph
          </h2>
          <p className="mb-4 text-sm text-slate-600">
            The chain of trust from source code scan to on-chain attestation.
          </p>
          <ProvenanceGraph asset={asset} verification={verification} />
        </section>

        {/* IPFS metadata */}
        {ipfsMetadata && (
          <section className="mt-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-lg font-semibold text-slate-800">
              IPFS metadata
            </h2>
            <pre className="max-h-96 overflow-auto rounded-lg bg-slate-900 p-4 text-xs text-slate-100">
              <code>{JSON.stringify(ipfsMetadata, null, 2)}</code>
            </pre>
          </section>
        )}

        {/* Verify independently */}
        <section className="mt-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold text-slate-800">Verify independently</h2>
          <p className="mb-3 text-sm text-slate-600">
            Anyone can verify this attestation without trusting Q-Trust. Run the CLI:
          </p>
          {safeAssetId ? (
            <pre className="overflow-auto rounded-lg bg-slate-900 p-4 text-xs text-slate-100">
              <code>{`# Install the Q-Trust SDK
pip install qtrust-sdk

# Verify on-chain
python -c "from qtrust import QTrustClient; print(QTrustClient().verify_asset('${safeAssetId}'))"

# Or use the scanner CLI
crypto-inspector verify ${safeAssetId}`}</code>
            </pre>
          ) : (
            <p className="rounded-lg bg-amber-50 p-4 text-xs text-amber-800 ring-1 ring-inset ring-amber-600/20">
              The asset ID for this record is not in the expected format, so the
              copy-paste verification commands are hidden. Copy the Asset ID from
              the table above and pass it to <code>crypto-inspector verify</code> manually.
            </p>
          )}
          <p className="mt-3 text-xs text-slate-500">
            The CLI calls the AssetRegistry contract directly on {verification.chain_name} —
            no central server involved.
          </p>
        </section>

        <footer className="mt-8 flex flex-col gap-2 text-center text-xs text-slate-500 sm:flex-row sm:justify-between">
          <span>
            Verified at {new Date(verification.verified_at * 1000).toISOString()}
          </span>
          <a
            href={`${verification.chain_id === 8453 ? "https://basescan.org" : "https://sepolia.basescan.org"}/address/${verification.org_did}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-slate-600 hover:text-slate-900"
          >
            View on Basescan
            <ArrowTopRightOnSquareIcon className="h-3 w-3" />
          </a>
        </footer>
      </div>
    </main>
  );
}

// ------------------------------------------------------------------
// Sub-components
// ------------------------------------------------------------------
function StatusBadge({ status }: { status: "VALID" | "REVOKED" }) {
  if (status === "VALID") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1.5 text-sm font-medium text-emerald-700 ring-1 ring-inset ring-emerald-600/20">
        <ShieldCheckIcon className="h-4 w-4" />
        VALID
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 px-3 py-1.5 text-sm font-medium text-red-700 ring-1 ring-inset ring-red-600/20">
      <XCircleIcon className="h-4 w-4" />
      REVOKED
    </span>
  );
}

function Field({
  label,
  value,
  mono = false,
  colSpan2 = false,
  icon,
}: {
  label: string;
  value: string;
  mono?: boolean;
  colSpan2?: boolean;
  icon?: React.ReactNode;
}) {
  return (
    <div className={colSpan2 ? "sm:col-span-2" : ""}>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
        {label}
      </dt>
      <dd className={`mt-1 flex items-center gap-2 text-slate-900 ${mono ? "font-mono text-xs break-all" : ""}`}>
        {icon}
        <span className="break-all">{value}</span>
      </dd>
    </div>
  );
}

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: Props) {
  const { id } = await params;
  return {
    title: `Q-Trust — Asset ${id.slice(0, 10)}...`,
    description: "Public verification of a Q-Trust attestation on Base.",
  };
}
