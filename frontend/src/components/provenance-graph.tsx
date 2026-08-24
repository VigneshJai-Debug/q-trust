"use client";

import dynamic from "next/dynamic";
import type { AssetInfo, AssetVerification } from "@/lib/api";

const ProvenanceGraphCanvas = dynamic(
  () => import("@/components/provenance-graph-canvas"),
  {
    ssr: false,
    loading: () => (
      <div className="flex min-w-max items-center gap-2 py-4" aria-hidden="true">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className="h-[62px] w-40 animate-pulse rounded-lg bg-slate-100" />
        ))}
      </div>
    ),
  },
);

interface ProvenanceGraphProps {
  asset: AssetInfo;
  verification: AssetVerification;
}

export function ProvenanceGraph({ asset, verification }: ProvenanceGraphProps) {
  return <ProvenanceGraphCanvas asset={asset} verification={verification} />;
}
