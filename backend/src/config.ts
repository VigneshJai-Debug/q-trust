/**
 * Shared viem configuration for the Q-Trust backend.
 *
 * Reads RPC URL, chain, and contract addresses from environment variables.
 * Validates configuration at startup to fail fast on misconfiguration.
 */
import { createPublicClient, http, type Address, type Chain } from "viem";
import { baseSepolia, base } from "viem/chains";
import * as dotenv from "dotenv";

dotenv.config();

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

// ── Environment helpers ──────────────────────────────────────────────────────

function optionalEnv(name: string, fallback: string): string {
  return process.env[name] || fallback;
}

const IS_PRODUCTION = process.env.NODE_ENV === "production";

// Audit L-8: default to the public HTTPS Base Sepolia endpoint instead of a
// plaintext local HTTP URL, and refuse to boot production against an HTTP
// (unencrypted, spoofable) RPC.
function resolveRpcUrl(): string {
  const url = optionalEnv("QTRUST_BASE_SEPOLIA_RPC", "https://sepolia.base.org");
  if (IS_PRODUCTION && url.startsWith("http://")) {
    throw new ConfigError(
      "Refusing to start: QTRUST_BASE_SEPOLIA_RPC uses plaintext http:// in production — use an HTTPS endpoint",
    );
  }
  return url;
}

const RPC_URL = resolveRpcUrl();
const USE_MAINNET = process.env.QTRUST_USE_MAINNET === "true";

export const CHAIN: Chain = USE_MAINNET ? base : baseSepolia;

/** Dynamic chainId from the configured chain. */
export const CHAIN_ID: number = CHAIN.id;

/** Read-only viem client — for view calls and event logs. */
export const publicClient = createPublicClient({
  chain: CHAIN,
  transport: http(RPC_URL, { timeout: 30_000 }),
});

/** Contract addresses, sourced from environment. */
export const CONTRACTS = {
  assetRegistry: (optionalEnv("QTRUST_ASSET_REGISTRY_ADDRESS", "0x0")) as Address,
  vendorRegistry: (optionalEnv("QTRUST_VENDOR_REGISTRY_ADDRESS", "0x0")) as Address,
  migrationRegistry: (optionalEnv("QTRUST_MIGRATION_REGISTRY_ADDRESS", "0x0")) as Address,
  auditRegistry: (optionalEnv("QTRUST_AUDIT_REGISTRY_ADDRESS", "0x0")) as Address,
  revocationAnchor: (optionalEnv("QTRUST_REVOCATION_ANCHOR_ADDRESS", "0x0")) as Address,
  policyCommitment: (optionalEnv("QTRUST_POLICY_COMMITMENT_ADDRESS", "0x0")) as Address,
  schemaRegistry: (optionalEnv("QTRUST_SCHEMA_REGISTRY_ADDRESS", "0x0")) as Address,
  trustAnchorRegistry: (optionalEnv("QTRUST_TRUST_ANCHOR_REGISTRY_ADDRESS", "0x0")) as Address,
} as const;

/** All contract addresses are configured (used to gate indexer/webhooks). */
export function allContractsConfigured(): boolean {
  return Object.values(CONTRACTS).every((a) => a !== "0x0");
}

/** Thrown when required configuration is missing or invalid. */
/** CORS allowlist. Comma-separated origins; "*" allows all (dev only). */
export const CORS_ORIGINS: string[] = (() => {
  const raw = process.env.QTRUST_CORS_ORIGINS ?? "*";
  const origins = raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (IS_PRODUCTION && (origins.length === 0 || origins.includes("*"))) {
    throw new ConfigError(
      "CORS_ORIGINS must be set to explicit origins in production — empty or * is not allowed (set QTRUST_CORS_ORIGINS)",
    );
  }
  if (!IS_PRODUCTION && raw === "*") {
    console.warn("WARNING: CORS defaults to * — set QTRUST_CORS_ORIGINS for production");
  }
  return origins;
})();

/** Validate address format (0x-prefixed, 40 hex chars). */
export function isValidAddress(addr: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(addr);
}

/** Validate bytes32 format (0x-prefixed, 66 hex chars). */
export function isValidBytes32(id: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(id);
}

/** Admin API keys (comma-separated) for the write API. */
export const API_KEYS: string[] = optionalEnv("QTRUST_API_KEYS", "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/** Whether API key gating is enforced. Fail-closed in production. */
export const API_KEY_REQUIRED = IS_PRODUCTION || API_KEYS.length > 0;

/** Postgres connection string (optional — indexer degrades to direct RPC). */
export const PG_URL = process.env.QTRUST_PG_URL ?? process.env.DATABASE_URL ?? "";

/** Planner microservice URL (optional — /v1/plans returns 503 when absent). */
export const PLANNER_URL =
  process.env.QTRUST_PLANNER_URL ?? "http://127.0.0.1:8000";

/** Shared planner API key — forwarded as X-Api-Key on proxied calls
 *  (planner audit HIGH-1). */
export const PLANNER_API_KEY = process.env.QTRUST_PLANNER_API_KEY ?? "";

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
