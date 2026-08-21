"use client";

/**
 * Gasless attestation form.
 *
 * Vendors sign an EIP-712 typed message with their injected wallet
 * (MetaMask) — no funds needed. The backend relayer verifies the signature
 * and submits it on-chain; the contract records the SIGNER as the vendor.
 * If no wallet is connected, the form offers the mock/dev path instead.
 */
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { fetchVendorNonce, relayAttestation, PQC_ALGORITHMS } from "@/lib/api";
import { signAttestationTypedData, useWallet } from "@/components/dynamic-provider";

const STATUS = {
  idle: "Attest product (gasless — wallet signs, relayer pays)",
  signing: "Waiting for your wallet signature…",
  relaying: "Verifying signature and submitting on-chain…",
  done: "Attestation recorded on-chain.",
  error: "",
} as const;

export function AttestationForm({ vendor }: { vendor: string }) {
  const { user } = useWallet();
  const queryClient = useQueryClient();

  const [productId, setProductId] = useState("QTrust-PQC-Lib");
  const [version, setVersion] = useState("1.4.0");
  const [algorithm, setAlgorithm] = useState("ML-KEM-768");
  const [supported, setSupported] = useState(true);
  const [evidenceURI, setEvidenceURI] = useState("");
  const [status, setStatus] = useState<keyof typeof STATUS>("idle");
  const [error, setError] = useState("");
  const [txHash, setTxHash] = useState("");

  const walletConnected = Boolean(user?.isAuthenticated && !user.mock);

  async function submit() {
    setError("");
    setStatus("signing");
    try {
      if (!walletConnected) {
        throw new Error(
          "Connect a real wallet (MetaMask) to sign gasless attestations. The mock wallet cannot sign.",
        );
      }
      const nonce = await fetchVendorNonce(vendor);
      setStatus("relaying");
      const signature = await signAttestationTypedData({
        productId,
        version,
        algorithm,
        supported,
        evidenceURI,
        nonce,
      });
      const result = await relayAttestation({
        productId,
        version,
        algorithm,
        supported,
        evidenceURI,
        nonce,
        signature,
      });
      setTxHash(result.txHash);
      setStatus("done");
      queryClient.invalidateQueries({ queryKey: ["vendor-attestations"] });
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="mt-3 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h3 className="text-sm font-semibold text-slate-800">Issue a gasless attestation</h3>
      <p className="mt-1 text-xs text-slate-500">
        You sign a typed message in your wallet; the Q-Trust relayer submits it on-chain and the
        contract records <span className="font-mono">{vendor}</span> as the vendor.
      </p>

      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="block text-xs font-medium text-slate-600">
          Product ID
          <input
            value={productId}
            onChange={(e) => setProductId(e.target.value)}
            className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
          />
        </label>
        <label className="block text-xs font-medium text-slate-600">
          Version
          <input
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
          />
        </label>
        <label className="block text-xs font-medium text-slate-600">
          Algorithm
          <select
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
            className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
          >
            {PQC_ALGORITHMS.map((a) => (
              <option key={a.value} value={a.value}>
                {a.label}
              </option>
            ))}
          </select>
        </label>
        <label className="block text-xs font-medium text-slate-600">
          Evidence URI (optional)
          <input
            value={evidenceURI}
            onChange={(e) => setEvidenceURI(e.target.value)}
            placeholder="ipfs://…"
            className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
          />
        </label>
      </div>

      <div className="mt-4 flex items-center gap-4">
        <label className="flex items-center gap-2 text-xs font-medium text-slate-600">
          <input
            type="checkbox"
            checked={supported}
            onChange={(e) => setSupported(e.target.checked)}
            className="h-4 w-4 rounded border-slate-300"
          />
          Product supports this algorithm
        </label>
        <button
          onClick={submit}
          disabled={status === "signing" || status === "relaying"}
          className="ml-auto rounded-lg bg-qtrust-600 px-4 py-2 text-xs font-medium text-white transition hover:bg-qtrust-700 disabled:opacity-50"
        >
          {STATUS[status]}
        </button>
      </div>

      {!walletConnected ? (
        <p className="mt-3 text-xs text-amber-600">
          No real wallet connected — gasless signing requires MetaMask. (The mock wallet can&apos;t
          sign; use the CLI to attest in dev.)
        </p>
      ) : null}

      {status === "done" && txHash ? (
        <p className="mt-3 text-xs text-emerald-700">
          ✓ Attestation on-chain. Tx: <span className="font-mono">{txHash}</span>
        </p>
      ) : null}
      {status === "error" && error ? (
        <p className="mt-3 text-xs text-rose-600">{error}</p>
      ) : null}
    </div>
  );
}