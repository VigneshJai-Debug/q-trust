/**
 * viem client configuration for Base / Base Sepolia.
 *
 * Read-only: publicClient (view calls only).
 * Signing: browser EIP-1193 injected wallet (MetaMask) — no private keys ever
 * touch the server or the browser bundle. A mock wallet is provided for dev
 * when no injected provider exists (QTRUST_MOCK_WALLET=true).
 */
import { createPublicClient, createWalletClient, custom, http, type Address, type Chain } from "viem";
import { baseSepolia } from "viem/chains";

const RPC_URL = process.env.QTRUST_BASE_SEPOLIA_RPC ?? "https://sepolia.base.org";
const USE_MAINNET = process.env.QTRUST_USE_MAINNET === "true";

export const CHAIN: Chain = USE_MAINNET ? {
  id: 8453,
  name: "Base",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
  blockExplorers: { default: { name: "Basescan", url: "https://basescan.org" } },
} : baseSepolia;

/** Read-only viem client — for view calls and event logs. */
export const publicClient = createPublicClient({
  chain: CHAIN,
  transport: http(RPC_URL, { timeout: 30_000 }),
});

/** Contract addresses, sourced from environment. */
export const CONTRACTS = {
  assetRegistry: (process.env.QTRUST_REGISTRY_ADDRESS ?? "0x0") as Address,
  vendorRegistry: (process.env.QTRUST_VENDOR_REGISTRY_ADDRESS ?? "0x0") as Address,
  migrationRegistry: (process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS ?? "0x0") as Address,
  auditRegistry: (process.env.QTRUST_AUDIT_REGISTRY_ADDRESS ?? "0x0") as Address,
} as const;

declare global {
  interface Window {
    ethereum?: {
      request(args: { method: string; params?: unknown[] }): Promise<unknown>;
      isMetaMask?: boolean;
    };
  }
}

export interface WalletHandle {
  address: Address | null;
  connected: boolean;
  mock: boolean;
}

/**
 * Detect an EIP-1193 injected provider (MetaMask, Coinbase Wallet, ...).
 * Returns null in SSR contexts or when no provider is present.
 */
export function getInjectedProvider(): Window["ethereum"] | null {
  if (typeof window === "undefined") return null;
  return window.ethereum ?? null;
}

/** Request accounts from the injected wallet (prompts the user). */
export async function connectWallet(): Promise<WalletHandle> {
  const provider = getInjectedProvider();
  if (provider) {
    const accounts = (await provider.request({
      method: "eth_requestAccounts",
    })) as string[];
    return {
      address: accounts[0] as Address,
      connected: true,
      mock: false,
    };
  }
  if (process.env.QTRUST_MOCK_WALLET === "true") {
    // Dev fallback: a fixed anvil test account (never used in production).
    return {
      address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as Address,
      connected: true,
      mock: true,
    };
  }
  return { address: null, connected: false, mock: false };
}

/**
 * Create a wallet client bound to the injected provider.
 * Call after connectWallet() succeeded.
 */
export function createBrowserWalletClient() {
  const provider = getInjectedProvider();
  if (!provider) {
    throw new Error("No injected wallet detected — install MetaMask and connect.");
  }
  return createWalletClient({
    chain: CHAIN,
    transport: custom(provider),
  });
}

/** Resolve a 0x-prefixed hex asset ID into a bytes32 for ABI calls. */
export function parseAssetId(id: string): `0x${string}` {
  if (!id.startsWith("0x")) {
    throw new Error(`Asset ID must be 0x-prefixed hex, got: ${id}`);
  }
  if (id.length !== 66) {
    throw new Error(`Asset ID must be 32 bytes (66 chars including 0x), got: ${id.length}`);
  }
  return id as `0x${string}`;
}

/** Pad a 0x-prefixed hex string to bytes32. */
export function toBytes32(hash: string): `0x${string}` {
  if (!hash.startsWith("0x")) {
    throw new Error("Hash must start with 0x");
  }
  const hex = hash.slice(2).padStart(64, "0").slice(0, 64);
  return `0x${hex}` as `0x${string}`;
}