"use client";

import type { AssetInfo, AssetVerification } from "@/lib/api";

interface GraphCanvasProps {
  asset: AssetInfo;
  verification: AssetVerification;
}

export default function ProvenanceGraphCanvas({ asset, verification }: GraphCanvasProps) {
  const nodes = [
    { id: "code", label: "Source Code", sub: "scanned by cryptography-inspector", color: "slate" },
    { id: "scanner", label: "Scanner", sub: "cryptography-inspector v0.1", color: "slate" },
    { id: "cbom", label: "CBOM", sub: asset.cbom_hash.slice(0, 18) + "...", color: "indigo" },
    { id: "asset", label: "On-chain Asset", sub: asset.asset_id.slice(0, 18) + "...", color: "emerald" },
    { id: "migration", label: "Migration", sub: "pending", color: "amber" },
  ];

  return (
    <div className="overflow-x-auto">
      <div className="flex min-w-max items-center gap-2 py-4">
        {nodes.map((node, i) => (
          <div key={node.id} className="flex items-center gap-2">
            <div
              className={`flex w-40 flex-col rounded-lg border-2 px-3 py-2 text-center bg-${node.color}-50 border-${node.color}-200`}
              style={{
                backgroundColor:
                  node.color === "emerald" ? "#ecfdf5" :
                  node.color === "amber" ? "#fffbeb" :
                  node.color === "indigo" ? "#eef2ff" : "#f8fafc",
                borderColor:
                  node.color === "emerald" ? "#a7f3d0" :
                  node.color === "amber" ? "#fde68a" :
                  node.color === "indigo" ? "#c7d2fe" : "#e2e8f0",
              }}
            >
              <div className="text-xs font-semibold text-slate-800">{node.label}</div>
              <div className="mt-1 font-mono text-[10px] text-slate-500">{node.sub}</div>
            </div>
            {i < nodes.length - 1 && (
              <svg className="h-4 w-6 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <path d="M5 12h14M13 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </div>
        ))}
      </div>
      <div className="mt-2 text-xs text-slate-500">
        Verified by {verification.org_did.slice(0, 8)}...{verification.org_did.slice(-6)} on{" "}
        {verification.chain_name}.
      </div>
    </div>
  );
}
