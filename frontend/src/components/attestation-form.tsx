"use client";

/**
 * Gasless attestation form.
 *
 * Vendors sign an EIP-712 typed message with their connected wallet via wagmi
 * (RainbowKit) — no funds needed. The backend relayer verifies the signature
 * and submits it on-chain; the contract records the SIGNER as the vendor.
 * If no wallet is connected, the RainbowKit ConnectButton is offered instead.
 */
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useAccount, useSignTypedData, useSwitchChain } from "wagmi";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { fetchVendorNonce, relayAttestation, PQC_ALGORITHMS } from "@/lib/api";
import { CHAIN, CONTRACTS } from "@/lib/config";

const STATUS = {
  idle: "Attest product (gasless — wallet signs, relayer pays)",
  signing: "Waiting for your wallet signature…",
  relaying: "Verifying signature and submitting on-chain…",
  done: "Attestation recorded on-chain.",
  error: "",
} as const;

/** The chain this deployment's contracts live on — signing must match it. */
const EXPECTED_CHAIN_ID = CHAIN.id;

export function AttestationForm({ vendor }: { vendor: string }) {
  const { address, isConnected, chainId } = useAccount();
  const { switchChainAsync } = useSwitchChain();
  const { signTypedDataAsync } = useSignTypedData();
  const queryClient = useQueryClient();

  const [productId, setProductId] = useState("QTrust-PQC-Lib");
  const [version, setVersion] = useState("1.4.0");
  const [algorithm, setAlgorithm] = useState("ML-KEM-768");
  const [supported, setSupported] = useState(true);
  const [evidenceURI, setEvidenceURI] = useState("");
  const [status, setStatus] = useState<keyof typeof STATUS>("idle");
  const [error, setError] = useState("");
  const [txHash, setTxHash] = useState("");

  async function submit() {
    setError("");
    setStatus("signing");
    try {
      if (!isConnected || !address) {
        throw new Error("Connect a wallet (RainbowKit) to sign gasless attestations.");
      }
      // Security: the verifyingContract ALWAYS comes from the locally
      // configured environment (QTRUST_VENDOR_REGISTRY_ADDRESS via
      // lib/config) — never from any backend/API payload.
      const verifyingContract = CONTRACTS.vendorRegistry;
      if (!/^0x[0-9a-fA-F]{40}$/.test(verifyingContract)) {
        throw new Error(
          "Vendor registry contract address is not configured locally (QTRUST_VENDOR_REGISTRY_ADDRESS) — refusing to sign against an unknown contract.",
        );
      }

      // Ensure the wallet is on the chain the contracts are deployed to
      // before any signing (switches automatically when possible).
      if (chainId !== EXPECTED_CHAIN_ID) {
        await switchChainAsync({ chainId: EXPECTED_CHAIN_ID });
      }

      const nonce = await fetchVendorNonce(vendor);
      const signature = await signTypedDataAsync({
        domain: {
          name: "QTrustVendorRegistry",
          version: "1",
          chainId: EXPECTED_CHAIN_ID,
          verifyingContract,
        },
        types: {
          ProductAttestation: [
            { name: "productId", type: "string" },
            { name: "version", type: "string" },
            { name: "algorithm", type: "string" },
            { name: "supported", type: "bool" },
            { name: "evidenceURI", type: "string" },
            { name: "nonce", type: "uint256" },
          ],
        },
        primaryType: "ProductAttestation",
        message: {
          productId,
          version,
          algorithm,
          supported,
          evidenceURI,
          nonce: BigInt(nonce),
        },
      });
      setStatus("relaying");
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

      {!isConnected ? (
        <div className="mt-3 flex flex-col items-start gap-2">
          <ConnectButton />
          <p className="text-xs text-amber-600">
            Connect a wallet to sign the attestation — the relayer submits it on-chain.
          </p>
        </div>
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