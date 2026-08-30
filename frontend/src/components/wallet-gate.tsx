"use client";

import { useSyncExternalStore } from "react";
import { ConnectButton } from "@rainbow-me/rainbowkit";

const emptySubscribe = (): (() => void) => () => {};

/**
 * Returns false during server render and hydration, true after mount.
 * Implemented as a stable external-store read so wagmi/RainbowKit (and derived
 * role lookups) only run on the client without the set-state-in-effect anti-
 * pattern that cascading renders away.
 */
export function useMounted(): boolean {
  return useSyncExternalStore(
    emptySubscribe,
    () => true, // client snapshot
    () => false, // server snapshot
  );
}

interface WalletGateProps {
  description: string;
}

export function WalletGate({ description }: WalletGateProps) {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4 py-16">
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-8 text-center shadow-sm">
        <h1 className="text-xl font-bold text-slate-900">Connect your wallet</h1>
        <p className="mt-3 text-sm text-slate-600">{description}</p>
        <div className="mt-6 flex justify-center [&>div]:w-auto">
          <ConnectButton />
        </div>
      </div>
    </div>
  );
}

export function GateLoading() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4 py-16" role="status" aria-live="polite">
      <div className="flex flex-col items-center gap-3">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-slate-300 border-t-qtrust-600" />
        <span className="text-sm text-slate-500">Checking wallet…</span>
      </div>
    </div>
  );
}
