"use client";

/**
 * Wallet provider for the Q-Trust frontend.
 *
 * Real wallet first: connects to an EIP-1193 injected provider (MetaMask)
 * via viem. If no provider is present (and QTRUST_MOCK_WALLET=true, and only
 * outside production), falls back to a mock wallet so the UI remains testable
 * without signing in. No private keys are ever handled in the browser bundle.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { CHAIN, connectWallet, CONTRACTS, type WalletHandle } from "@/lib/config";

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
const MOCK_WALLET_KEY = "qtrust.mockWallet";

/**
 * Mock wallets are a dev/test convenience only. Checked at runtime (not just
 * build time) so a production bundle can never activate one, even if mock
 * state lingers in localStorage.
 */
function mockWalletsAllowed(): boolean {
  return process.env.NODE_ENV !== "production";
}

const EXPECTED_CHAIN_ID = CHAIN.id;
const EXPECTED_CHAIN_ID_HEX = `0x${EXPECTED_CHAIN_ID.toString(16)}`;
const EXPECTED_CHAIN_NAME = CHAIN.name;

function chainLabel(chainIdHex: string): string {
  const id = Number.parseInt(chainIdHex, 16);
  if (id === 84532) return "base-sepolia";
  if (id === 8453) return "base-mainnet";
  return `chain-${id}`;
}

function clearStoredMock(): void {
  if (typeof window !== "undefined") {
    window.localStorage.removeItem(MOCK_WALLET_KEY);
  }
}

type InjectedProvider = NonNullable<Window["ethereum"]>;

/**
 * Ensure the wallet is on the chain this deployment's contracts live on
 * before any signing. Attempts wallet_switchEthereumChain on mismatch and
 * throws a user-actionable error if the switch is rejected or fails.
 */
async function ensureWalletOnExpectedChain(provider: InjectedProvider): Promise<string> {
  const currentHex = (await provider.request({ method: "eth_chainId" })) as string;
  const currentId = Number.parseInt(currentHex, 16);
  if (currentId === EXPECTED_CHAIN_ID) return currentHex;

  try {
    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: EXPECTED_CHAIN_ID_HEX }],
    });
  } catch {
    throw new Error(
      `Wrong network: your wallet is connected to chain ${currentId}, but signing requires ${EXPECTED_CHAIN_NAME} (${EXPECTED_CHAIN_ID_HEX}). Approve the network switch in your wallet or switch manually, then try again.`,
    );
  }

  const switchedHex = (await provider.request({ method: "eth_chainId" })) as string;
  if (Number.parseInt(switchedHex, 16) !== EXPECTED_CHAIN_ID) {
    throw new Error(
      `Wrong network: your wallet is still not on ${EXPECTED_CHAIN_NAME} (${EXPECTED_CHAIN_ID_HEX}). Switch networks in your wallet and retry.`,
    );
  }
  return switchedHex;
}

export function DynamicProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<WalletUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Try the injected wallet on mount; fall back to a stored mock (dev only).
  // Track wallet account/network changes so connection state stays accurate.
  useEffect(() => {
    let cancelled = false;
    const provider = typeof window !== "undefined" ? window.ethereum : undefined;

    function onAccountsChanged(accounts: unknown): void {
      const list = Array.isArray(accounts)
        ? accounts.filter((a): a is string => typeof a === "string" && a.startsWith("0x"))
        : [];
      setUser((prev) => {
        if (list.length > 0) {
          return prev && !prev.mock ? { ...prev, address: list[0], isAuthenticated: true } : prev;
        }
        return prev?.mock ? prev : null;
      });
    }

    function onChainChanged(chainIdHex: unknown): void {
      if (typeof chainIdHex !== "string") return;
      setUser((prev) => (prev && !prev.mock ? { ...prev, chain: chainLabel(chainIdHex) } : prev));
    }

    provider?.on?.("accountsChanged", onAccountsChanged);
    provider?.on?.("chainChanged", onChainChanged);

    (async () => {
      if (provider) {
        try {
          const handle: WalletHandle = await connectWallet();
          if (!cancelled && handle.connected && handle.address) {
            const chainIdHex = (await provider.request({ method: "eth_chainId" })) as string;
            if (!cancelled) {
              setUser({
                address: handle.address,
                chain: chainLabel(chainIdHex),
                isAuthenticated: true,
                mock: false,
              });
              setLoading(false);
              return;
            }
          }
        } catch {
          /* user rejected — fall through */
        }
      }
      if (!cancelled) {
        if (mockWalletsAllowed()) {
          const stored = window.localStorage.getItem(MOCK_WALLET_KEY);
          if (stored) {
            try {
              const parsed = JSON.parse(stored) as WalletUser | null;
              if (
                parsed &&
                parsed.mock === true &&
                parsed.isAuthenticated === true &&
                typeof parsed.address === "string" &&
                parsed.address.startsWith("0x")
              ) {
                setUser(parsed);
              } else {
                clearStoredMock();
              }
            } catch {
              clearStoredMock();
            }
          }
        } else {
          // Production: never honor stored mock state.
          clearStoredMock();
        }
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      provider?.removeListener?.("accountsChanged", onAccountsChanged);
      provider?.removeListener?.("chainChanged", onChainChanged);
    };
  }, []);

  async function connect(): Promise<void> {
    if (typeof window !== "undefined" && window.ethereum) {
      try {
        const handle = await connectWallet();
        if (handle.connected && handle.address) {
          const chainIdHex = (await window.ethereum.request({ method: "eth_chainId" })) as string;
          setUser({
            address: handle.address,
            chain: chainLabel(chainIdHex),
            isAuthenticated: true,
            mock: false,
          });
          return;
        }
      } catch {
        /* fall through */
      }
    }
    if (!mockWalletsAllowed()) {
      clearStoredMock();
      return;
    }
    const u: WalletUser = {
      address: MOCK_ADDRESS,
      chain: chainLabel(EXPECTED_CHAIN_ID_HEX),
      isAuthenticated: true,
      mock: true,
    };
    window.localStorage.setItem(MOCK_WALLET_KEY, JSON.stringify(u));
    setUser(u);
  }

  function disconnect() {
    clearStoredMock();
    setUser(null);
  }

  return (
    <WalletContext.Provider value={{ user, loading, connect, disconnect }}>
      {user?.mock && (
        <div className="bg-yellow-500/10 border-b border-yellow-500/30 px-4 py-2 text-center text-sm text-yellow-600 dark:text-yellow-400">
          Mock wallet active ({user.address.slice(0, 6)}...{user.address.slice(-4)}).
          Connect MetaMask for real transactions.
        </div>
      )}
      {children}
    </WalletContext.Provider>
  );
}

/**
 * Gasless EIP-712 signing helper for the attestation form.
 *
 * Security: the verifyingContract is ALWAYS taken from the locally configured
 * environment (NEXT_PUBLIC/QTRUST_VENDOR_REGISTRY_ADDRESS via lib/config) —
 * never from any backend/API payload, which could be tampered with.
 */
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
  if (!Array.isArray(accounts) || !accounts[0]) {
    throw new Error("No wallet account authorized for signing.");
  }

  const verifyingContract = CONTRACTS.vendorRegistry;
  if (!/^0x[0-9a-fA-F]{40}$/.test(verifyingContract)) {
    throw new Error(
      "Vendor registry contract address is not configured locally (QTRUST_VENDOR_REGISTRY_ADDRESS) — refusing to sign against an unknown contract.",
    );
  }

  const chainIdHex = await ensureWalletOnExpectedChain(provider);

  const typedData = {
    domain: {
      name: "QTrustVendorRegistry",
      version: "1",
      chainId: Number.parseInt(chainIdHex, 16),
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
