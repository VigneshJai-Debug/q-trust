/**
 * Shared viem configuration for the Q-Trust backend.
 *
 * Reads RPC URL, chain, and contract addresses from environment variables.
 */
import { createPublicClient, http, type Address, type Chain } from "viem";
import { baseSepolia } from "viem/chains";
import * as dotenv from "dotenv";

dotenv.config();

const RPC_URL = process.env.QTRUST_BASE_SEPOLIA_RPC ?? "http://127.0.0.1:8545";
const USE_MAINNET = process.env.QTRUST_USE_MAINNET === "true";

export const CHAIN: Chain = USE_MAINNET
  ? {
      id: 8453,
      name: "Base",
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: [RPC_URL] } },
      blockExplorers: { default: { name: "Basescan", url: "https://basescan.org" } },
    }
  : baseSepolia;

/** Read-only viem client — for view calls and event logs. */
export const publicClient = createPublicClient({
  chain: CHAIN,
  transport: http(RPC_URL, { timeout: 30_000 }),
});

/** Contract addresses, sourced from environment. */
export const CONTRACTS = {
  assetRegistry: (process.env.QTRUST_ASSET_REGISTRY_ADDRESS ?? "0x0") as Address,
  vendorRegistry: (process.env.QTRUST_VENDOR_REGISTRY_ADDRESS ?? "0x0") as Address,
  migrationRegistry: (process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS ?? "0x0") as Address,
  auditRegistry: (process.env.QTRUST_AUDIT_REGISTRY_ADDRESS ?? "0x0") as Address,
} as const;

/** All contract addresses are configured (used to gate indexer/webhooks). */
export function allContractsConfigured(): boolean {
  return Object.values(CONTRACTS).every((a) => a !== "0x0");
}

/** CORS allowlist. Comma-separated origins; "*" allows all (dev only). */
export const CORS_ORIGINS: string[] = (process.env.QTRUST_CORS_ORIGINS ?? "*")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/** Admin API keys (comma-separated) for the write API. */
export const API_KEYS: string[] = (process.env.QTRUST_API_KEYS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/** Postgres connection string (optional — indexer degrades to direct RPC). */
export const PG_URL = process.env.QTRUST_PG_URL ?? process.env.DATABASE_URL ?? "";

/** Planner microservice URL (optional — /v1/plans returns 503 when absent). */
export const PLANNER_URL =
  process.env.QTRUST_PLANNER_URL ?? "http://127.0.0.1:8000";

/** Block to start indexing from (set to the contract deployment block). */
export const INDEXER_FROM_BLOCK = Number(process.env.QTRUST_INDEXER_FROM_BLOCK ?? 0);

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