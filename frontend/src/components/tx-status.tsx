"use client";

import Link from "next/link";

type TxState = "idle" | "awaiting-wallet" | "rejected" | "pending-chain" | "confirmed" | "reverted";

interface TxStatusProps {
  state: TxState;
  txHash?: `0x${string}`;
  explorerBase?: string;
  error?: string;
  assetId?: string;
  onRetry?: () => void;
}

const COPY: Record<TxState, { title: string; desc: string }> = {
  idle: { title: "Ready to submit", desc: "Click to register — you will confirm in your wallet." },
  "awaiting-wallet": { title: "Confirm in your wallet", desc: "Approve the signature request in your wallet to continue." },
  rejected: { title: "Request rejected — nothing was sent", desc: "You rejected the wallet request. Your funds are safe — try again when ready." },
  "pending-chain": { title: "Waiting for Base confirmation…", desc: "Your transaction was submitted. This usually takes a few seconds." },
  confirmed: { title: "Attestation anchored", desc: "Verified on-chain. Anyone can verify without trusting Q-Trust." },
  reverted: { title: "Reverted", desc: "Transaction was reverted on-chain. Check the explorer for the reason — retry is safe." },
};

export function TxStatus({ state, txHash, explorerBase, error, assetId, onRetry }: TxStatusProps) {
  const c = COPY[state];
  const explorerLink = txHash && explorerBase ? `${explorerBase}/tx/${txHash}` : null;

  return (
    <div role="status" aria-live="polite" className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-start gap-3">
        <div className={`mt-0.5 h-2 w-2 shrink-0 rounded-full ${state === "confirmed" ? "bg-emerald-500" : state === "reverted" || state === "rejected" ? "bg-amber-500" : state === "pending-chain" ? "bg-sky-500 animate-pulse" : "bg-slate-300"}`} aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-900">{c.title}</p>
          <p className="mt-1 text-xs leading-5 text-slate-600">{c.desc}</p>
          {error && <p className="mt-2 rounded bg-amber-50 px-2 py-1 font-mono text-xs text-amber-900 ring-1 ring-amber-200">{error}</p>}
          {txHash && (
            <p className="mt-2 flex flex-wrap items-center gap-2 text-xs">
              <span className="font-mono text-slate-600">{txHash.slice(0, 10)}…{txHash.slice(-8)}</span>
              {explorerLink && (
                <Link href={explorerLink} target="_blank" rel="noreferrer" className="font-medium text-qtrust-600 hover:underline">
                  View on Basescan
                </Link>
              )}
            </p>
          )}
          {state === "confirmed" && assetId && <p className="mt-2 text-xs text-slate-600">Asset <code className="rounded bg-slate-100 px-1 py-0.5 font-mono">{assetId}</code> is now verifiable at <Link href={`/v/${assetId}`} className="font-medium text-qtrust-600 hover:underline">/v/{assetId}</Link>.</p>}
          {(state === "rejected" || state === "reverted") && onRetry && (
            <button type="button" onClick={onRetry} className="mt-3 rounded-lg bg-qtrust-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-qtrust-700">
              Try again
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
