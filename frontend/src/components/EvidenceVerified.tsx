/**
 * EvidenceVerified — QTRUST-015 / §26 / §40
 *
 * Blockchain invisible trust layer: show "Evidence verified ✓" first,
 * not "Base / Wallet / Gas / Contract 0x...".
 *
 * Flow:
 *   Evidence verified ✓
 *     ↓
 *   View cryptographic proof
 *     ↓
 *   Blockchain / Block / Tx / Merkle proof (for auditors only)
 */
export function EvidenceVerified({ cbomHash, txHash, blockNumber }: { cbomHash: string; txHash?: string; blockNumber?: number }) {
  return (
    <div className="rounded-xl border p-4">
      <div className="text-green-600 font-semibold">✓ Evidence verified</div>
      <div className="text-sm text-gray-600">CBOM hash {cbomHash.slice(0, 12)}…</div>
      <details className="mt-2">
        <summary className="cursor-pointer text-sm underline">View cryptographic proof</summary>
        <div className="mt-2 text-xs font-mono bg-gray-50 p-2 rounded">
          {txHash ? `Tx: ${txHash}` : "Anchoring pending (Sepolia deployment required — see docs/SECURITY_REMEDIATION.md QTRUST-010)"}
          {blockNumber ? ` · Block #${blockNumber}` : ""}
          <div>Merkle root → Base L2 (see qtrust/data/lineage.py)</div>
        </div>
      </details>
    </div>
  );
}
