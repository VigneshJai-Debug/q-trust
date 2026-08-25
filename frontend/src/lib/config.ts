/**
 * viem client configuration for Base / Base Sepolia.
 *
 * Read-only: publicClient (view calls only).
 * Signing/connection: wagmi + RainbowKit (see components/providers.tsx).
 */
import { createPublicClient, http, type Address, type Chain } from "viem";
import { baseSepolia } from "viem/chains";

const RPC_URL = process.env.NEXT_PUBLIC_QTRUST_BASE_SEPOLIA_RPC ??
  process.env.QTRUST_BASE_SEPOLIA_RPC ?? "https://sepolia.base.org";
const USE_MAINNET = process.env.NEXT_PUBLIC_QTRUST_USE_MAINNET === "true" ||
  process.env.QTRUST_USE_MAINNET === "true";

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

/** Contract addresses, sourced from environment.
 *
 * Client components only see NEXT_PUBLIC_* vars (Next.js inlines them into
 * the browser bundle); server-side env names are accepted as a fallback so
 * API routes / SSR still work without duplication (audit Critical #3).
 */
export const CONTRACTS = {
  assetRegistry: (
    process.env.NEXT_PUBLIC_QTRUST_ASSET_REGISTRY_ADDRESS ??
    process.env.QTRUST_ASSET_REGISTRY_ADDRESS ??
    process.env.QTRUST_REGISTRY_ADDRESS ??
    "0x0"
  ) as Address,
  vendorRegistry: (
    process.env.NEXT_PUBLIC_QTRUST_VENDOR_REGISTRY_ADDRESS ??
    process.env.QTRUST_VENDOR_REGISTRY_ADDRESS ??
    "0x0"
  ) as Address,
  migrationRegistry: (
    process.env.NEXT_PUBLIC_QTRUST_MIGRATION_REGISTRY_ADDRESS ??
    process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS ??
    "0x0"
  ) as Address,
  auditRegistry: (
    process.env.NEXT_PUBLIC_QTRUST_AUDIT_REGISTRY_ADDRESS ??
    process.env.QTRUST_AUDIT_REGISTRY_ADDRESS ??
    "0x0"
  ) as Address,
} as const;

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