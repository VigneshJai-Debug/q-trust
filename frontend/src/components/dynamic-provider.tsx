"use client";

/**
 * Wallet provider for the Q-Trust frontend.
 *
 * Real wallet first: connects to an EIP-1193 injected provider (MetaMask)
 * via viem. If no provider is present (and QTRUST_MOCK_WALLET=true, or in
 * dev), falls back to a mock wallet so the UI remains testable without
 * signing in. No private keys are ever handled in the browser bundle.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { connectWallet, type WalletHandle } from "@/lib/config";

export interface WalletUser {
  address: string;
  chain: string;
  isAuthenticated: boolean;
  mock: boolean;
}

interface WalletContextValue {
  user: WalletUser | null;
  loading: boolean;
  connect: () => Promise<void>;
  disconnect: () => void;
}

const WalletContext = createContext<WalletContextValue>({
  user: null,
  loading: true,
  connect: async () => undefined,
  disconnect: () => undefined,
});

export function useWallet(): WalletContextValue {
  return useContext(WalletContext);
}

const MOCK_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

export function DynamicProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<WalletUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Try the injected wallet on mount; fall back to a stored mock.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (typeof window !== "undefined" && window.ethereum) {
        try {
          const handle: WalletHandle = await connectWallet();
          if (!cancelled && handle.connected) {
            setUser({
              address: handle.address!,
              chain: "base-sepolia",
              isAuthenticated: true,
              mock: handle.mock,
            });
            setLoading(false);
            return;
          }
        } catch {
          /* user rejected — fall through to mock */
        }
      }
      const stored = typeof window !== "undefined"
        ? window.localStorage.getItem("qtrust.mockWallet")
        : null;
      if (!cancelled) {
        if (stored) {
          try {
            setUser(JSON.parse(stored) as WalletUser);
          } catch {
            /* ignore */
          }
        }
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function connect(): Promise<void> {
    if (typeof window !== "undefined" && window.ethereum) {
      try {
        const handle = await connectWallet();
        if (handle.connected) {
          setUser({
            address: handle.address!,
            chain: "base-sepolia",
            isAuthenticated: true,
            mock: handle.mock,
          });
          return;
        }
      } catch {
        /* fall through to mock */
      }
    }
    const u: WalletUser = {
      address: MOCK_ADDRESS,
      chain: "base-sepolia",
      isAuthenticated: true,
      mock: true,
    };
    if (typeof window !== "undefined") {
      window.localStorage.setItem("qtrust.mockWallet", JSON.stringify(u));
      setUser(u);
    }
  }

  function disconnect() {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem("qtrust.mockWallet");
    }
    setUser(null);
  }

  return (
    <WalletContext.Provider value={{ user, loading, connect, disconnect }}>
      {children}
    </WalletContext.Provider>
  );
}

/** Gasless EIP-712 signing helper for the attestation form. */
export async function signAttestationTypedData(
  payload: {
    productId: string;
    version: string;
    algorithm: string;
    supported: boolean;
    evidenceURI: string;
    nonce: number;
  },
): Promise<string> {
  if (typeof window === "undefined" || !window.ethereum) {
    throw new Error("No injected wallet available to sign the attestation.");
  }
  const provider = window.ethereum;
  const accounts = (await provider.request({ method: "eth_requestAccounts" })) as string[];
  const chainIdHex = (await provider.request({ method: "eth_chainId" })) as string;
  const verifyingContract = await fetchContractAddress();

  const typedData = {
    domain: {
      name: "QTrustVendorRegistry",
      version: "1",
      chainId: Number(parseInt(chainIdHex, 16)),
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
      productId: payload.productId,
      version: payload.version,
      algorithm: payload.algorithm,
      supported: payload.supported,
      evidenceURI: payload.evidenceURI,
      nonce: payload.nonce,
    },
  };

  const result = (await provider.request({
    method: "eth_signTypedData_v4",
    params: [accounts[0], JSON.stringify(typedData)],
  })) as string;
  return result;
}

async function fetchContractAddress(): Promise<string> {
  const res = await fetch("/api/vendor-registry-address");
  const json = await res.json();
  return json.address;
}