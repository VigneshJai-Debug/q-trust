/**
 * Verification service — read-only access to the Q-Trust contracts via viem.
 *
 * Each function returns a typed plain-old-data object so the Fastify layer can
 * serialize it directly to JSON.
 *
 * When the Postgres indexer is available, list endpoints are served from the
 * read model (fast, paginated); otherwise they fall back to direct RPC calls.
 */
import { type Address, getContract } from "viem";
import { publicClient, CONTRACTS, CHAIN, parseAssetId } from "../config.js";
import {
  AssetRegistryAbi,
  VendorRegistryAbi,
  MigrationRegistryAbi,
  AuditRegistryAbi,
  auditResultName,
} from "../lib/abis.js";
import { pool, queryAssets, queryAttestations, queryMigrations, querySummary } from "./indexer.js";

// ------------------------------------------------------------------
// Types
// ------------------------------------------------------------------
export interface AssetInfo {
  asset_id: string;
  org_did: string;
  cbom_hash: string;
  metadata_uri: string;
  timestamp: number;
  last_updated: number;
  active: boolean;
}

export interface AssetVerification {
  asset_id: string;
  exists: boolean;
  active: boolean;
  org_did: string;
  chain_id: number;
  chain_name: string;
  verified_at: number;
}

export interface VendorAttestationInfo {
  attestation_id: string;
  vendor_did: string;
  product_id: string;
  version: string;
  algorithm: string;
  supported: boolean;
  evidence_uri: string;
  timestamp: number;
  revoked: boolean;
}

export interface MigrationProgressInfo {
  org_address: string;
  total_migrations: number;
  verified_migrations: number;
  unverified_migrations: number;
  fetched_at: number;
}

export interface MigrationInfo {
  migration_id: string;
  asset_id: string;
  org_did: string;
  from_algorithm: string;
  to_algorithm: string;
  evidence_hash: string;
  evidence_uri: string;
  timestamp: number;
  verified: boolean;
}

export interface LatestAuditInfo {
  org_address: string;
  exists: boolean;
  result: string;
  result_code: number;
  timestamp: number;
}

export interface OrgSummary {
  org: string;
  asset_count: number;
  migration_counts: {
    total: number;
    verified: number;
    unverified: number;
  };
  latest_audit: LatestAuditInfo | null;
  source: "indexer" | "rpc";
}

export interface Page<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}

// ------------------------------------------------------------------
// Contract instances
// ------------------------------------------------------------------
const assetRegistry = getContract({
  address: CONTRACTS.assetRegistry,
  abi: AssetRegistryAbi,
  client: publicClient,
});

const vendorRegistry = getContract({
  address: CONTRACTS.vendorRegistry,
  abi: VendorRegistryAbi,
  client: publicClient,
});

const migrationRegistry = getContract({
  address: CONTRACTS.migrationRegistry,
  abi: MigrationRegistryAbi,
  client: publicClient,
});

const auditRegistry = getContract({
  address: CONTRACTS.auditRegistry,
  abi: AuditRegistryAbi,
  client: publicClient,
});

// ------------------------------------------------------------------
// AssetRegistry
// ------------------------------------------------------------------
/**
 * Fetch a CBOM registration by its on-chain asset ID.
 * @param assetId - 0x-prefixed 32-byte hex asset ID
 * @returns An AssetInfo object, or null if the asset does not exist.
 */
export async function getAsset(assetId: string): Promise<AssetInfo | null> {
  // Indexed path (fast, avoids an RPC round-trip).
  if (pool) {
    const res = await pool.query(
      `SELECT asset_id, org_did, cbom_hash, metadata_uri, timestamp, last_updated, active
       FROM assets WHERE asset_id=$1`,
      [assetId.toLowerCase()],
    );
    if (res.rows.length) {
      const r = res.rows[0];
      return {
        asset_id: r.asset_id,
        org_did: r.org_did,
        cbom_hash: r.cbom_hash,
        metadata_uri: r.metadata_uri,
        timestamp: Number(r.timestamp),
        last_updated: Number(r.last_updated),
        active: r.active,
      };
    }
    return null;
  }

  try {
    const id = parseAssetId(assetId);
    const result = await assetRegistry.read.getAsset([id]);
    if (result.orgDid === "0x0000000000000000000000000000000000000000") {
      return null;
    }
    return {
      asset_id: assetId,
      org_did: result.orgDid,
      cbom_hash: result.cbomHash,
      metadata_uri: result.metadataURI,
      timestamp: Number(result.timestamp),
      last_updated: Number(result.lastUpdated),
      active: result.active,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("AssetNotFound") || msg.includes("execution reverted")) {
      return null;
    }
    throw new Error(`getAsset(${assetId}) failed: ${msg}`);
  }
}

/**
 * Verify that an asset exists and is active on-chain.
 * @param assetId - 0x-prefixed 32-byte hex asset ID
 */
export async function verifyAsset(assetId: string): Promise<AssetVerification> {
  const id = parseAssetId(assetId);
  const result = await assetRegistry.read.verifyAsset([id]);
  return {
    asset_id: assetId,
    exists: result[0],
    active: result[1],
    org_did: result[2],
    chain_id: CHAIN.id,
    chain_name: CHAIN.name,
    verified_at: Math.floor(Date.now() / 1000),
  };
}

/**
 * List all asset IDs registered by a given organization.
 * @param orgAddress - The org's wallet address
 */
export async function getAssetsByOrg(
  orgAddress: Address,
  offset = 0,
  limit = 50,
): Promise<Page<AssetInfo>> {
  const indexed = await queryAssets(orgAddress.toLowerCase(), offset, limit);
  if (indexed) {
    const items = indexed.rows.map((r: any) => ({
      asset_id: r.asset_id,
      org_did: r.org_did,
      cbom_hash: r.cbom_hash,
      metadata_uri: r.metadata_uri,
      timestamp: Number(r.timestamp),
      last_updated: Number(r.last_updated),
      active: r.active,
    }));
    return { items, total: indexed.total, offset, limit };
  }

  const ids = (await assetRegistry.read.getAssetsByOrg([orgAddress])) as readonly `0x${string}`[];
  const items: AssetInfo[] = [];
  for (const id of ids.slice(offset, offset + limit)) {
    const asset = await getAsset(id);
    if (asset) items.push(asset);
  }
  return { items, total: ids.length, offset, limit };
}

// ------------------------------------------------------------------
// VendorRegistry
// ------------------------------------------------------------------
/**
 * Get all attestations posted by a vendor.
 * @param vendorAddress - The vendor's wallet address
 * @returns An array of attestation objects (in chronological order).
 */
export async function getVendorAttestations(
  vendorAddress: Address,
  offset = 0,
  limit = 50,
): Promise<Page<VendorAttestationInfo>> {
  const indexed = await queryAttestations(vendorAddress.toLowerCase(), offset, limit);
  if (indexed) {
    const items = indexed.rows.map((r: any) => ({
      attestation_id: r.attestation_id,
      vendor_did: r.vendor_did,
      product_id: r.product_id,
      version: r.version,
      algorithm: r.algorithm,
      supported: r.supported,
      evidence_uri: r.evidence_uri,
      timestamp: Number(r.timestamp),
      revoked: r.revoked,
    }));
    return { items, total: indexed.total, offset, limit };
  }

  const attestationIds = (await vendorRegistry.read.getAttestationsByVendor([
    vendorAddress,
  ])) as readonly `0x${string}`[];

  const results: VendorAttestationInfo[] = [];
  for (const attId of attestationIds.slice(offset, offset + limit)) {
    try {
      const att = await vendorRegistry.read.getAttestation([attId]);
      results.push({
        attestation_id: attId,
        vendor_did: att.vendorDid,
        product_id: att.productId,
        version: att.version,
        algorithm: att.algorithm,
        supported: att.supported,
        evidence_uri: att.evidenceURI,
        timestamp: Number(att.timestamp),
        revoked: att.revoked,
      });
    } catch {
      // Skip attestations that cannot be fetched (shouldn't happen)
      continue;
    }
  }
  return { items: results, total: attestationIds.length, offset, limit };
}

/**
 * Check if a specific product version supports a given algorithm.
 */
export async function checkProductSupport(
  productId: string,
  version: string,
  algorithm: string,
): Promise<{ supported: boolean; vendor_did: string; attestation_id: string | null }> {
  const result = await vendorRegistry.read.checkProductSupport([
    productId, version, algorithm,
  ]);
  return {
    supported: result[0],
    vendor_did: result[1],
    attestation_id:
      result[2] === "0x0000000000000000000000000000000000000000000000000000000000000000"
        ? null
        : result[2],
  };
}

// ------------------------------------------------------------------
// MigrationRegistry
// ------------------------------------------------------------------
/**
 * Get migration progress for an org.
 * @param orgAddress - The org's wallet address
 */
export async function getMigrationProgress(
  orgAddress: Address,
): Promise<MigrationProgressInfo> {
  const migrationIds = (await migrationRegistry.read.getMigrationsByOrg([orgAddress])) as
    readonly `0x${string}`[];

  let verified = 0;
  for (const migId of migrationIds) {
    try {
      const m = await migrationRegistry.read.getMigration([migId]);
      if (m.verified) verified += 1;
    } catch {
      continue;
    }
  }
  return {
    org_address: orgAddress,
    total_migrations: migrationIds.length,
    verified_migrations: verified,
    unverified_migrations: migrationIds.length - verified,
    fetched_at: Math.floor(Date.now() / 1000),
  };
}

/**
 * Get all migrations recorded for an org, with full detail.
 */
export async function getMigrationsByOrg(
  orgAddress: Address,
  offset = 0,
  limit = 50,
): Promise<Page<MigrationInfo>> {
  const indexed = await queryMigrations(orgAddress.toLowerCase(), offset, limit);
  if (indexed) {
    const items = indexed.rows.map((r: any) => ({
      migration_id: r.migration_id,
      asset_id: r.asset_id,
      org_did: r.org_did,
      from_algorithm: r.from_algorithm,
      to_algorithm: r.to_algorithm,
      evidence_hash: r.evidence_hash,
      evidence_uri: r.evidence_uri,
      timestamp: Number(r.timestamp),
      verified: r.verified,
    }));
    return { items, total: indexed.total, offset, limit };
  }

  const migrationIds = (await migrationRegistry.read.getMigrationsByOrg([orgAddress])) as
    readonly `0x${string}`[];

  const results: MigrationInfo[] = [];
  for (const migId of migrationIds.slice(offset, offset + limit)) {
    try {
      const m = await migrationRegistry.read.getMigration([migId]);
      results.push({
        migration_id: migId,
        asset_id: m.assetId,
        org_did: m.orgDid,
        from_algorithm: m.fromAlgorithm,
        to_algorithm: m.toAlgorithm,
        evidence_hash: m.evidenceHash,
        evidence_uri: m.evidenceURI,
        timestamp: Number(m.timestamp),
        verified: m.verified,
      });
    } catch {
      continue;
    }
  }
  return { items: results, total: migrationIds.length, offset, limit };
}

/**
 * Fetch a single migration by its ID.
 */
export async function getMigration(
  migrationId: string,
): Promise<MigrationInfo | null> {
  try {
    const m = await migrationRegistry.read.getMigration([parseAssetId(migrationId)]);
    return {
      migration_id: migrationId,
      asset_id: m.assetId,
      org_did: m.orgDid,
      from_algorithm: m.fromAlgorithm,
      to_algorithm: m.toAlgorithm,
      evidence_hash: m.evidenceHash,
      evidence_uri: m.evidenceURI,
      timestamp: Number(m.timestamp),
      verified: m.verified,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("MigrationNotFound") || msg.includes("execution reverted")) {
      return null;
    }
    throw err;
  }
}

// ------------------------------------------------------------------
// AuditRegistry
// ------------------------------------------------------------------
/**
 * Get the latest audit result for an org.
 */
export async function getLatestAudit(
  orgAddress: Address,
): Promise<LatestAuditInfo> {
  const result = await auditRegistry.read.getLatestAudit([orgAddress]);
  return {
    org_address: orgAddress,
    exists: result[0],
    result: auditResultName(result[1]),
    result_code: result[1],
    timestamp: Number(result[2]),
  };
}

// ------------------------------------------------------------------
// Org summary (indexer-backed)
// ------------------------------------------------------------------
export async function getOrgSummary(orgAddress: Address): Promise<OrgSummary> {
  const indexed = await querySummary(orgAddress.toLowerCase());
  if (indexed) {
    const auditRow = indexed.latest_audit as { result: number; timestamp: string } | null;
    return {
      org: orgAddress,
      asset_count: indexed.asset_count,
      migration_counts: {
        total: indexed.migration_counts.total,
        verified: indexed.migration_counts.verified,
        unverified: indexed.migration_counts.unverified,
      },
      latest_audit: auditRow
        ? {
            org_address: orgAddress,
            exists: true,
            result: auditResultName(auditRow.result),
            result_code: auditRow.result,
            timestamp: Number(auditRow.timestamp),
          }
        : null,
      source: "indexer",
    };
  }

  const [assets, progress, latestAudit] = await Promise.all([
    getAssetsByOrg(orgAddress, 0, 1),
    getMigrationProgress(orgAddress),
    getLatestAudit(orgAddress),
  ]);
  return {
    org: orgAddress,
    asset_count: assets.total,
    migration_counts: {
      total: progress.total_migrations,
      verified: progress.verified_migrations,
      unverified: progress.unverified_migrations,
    },
    latest_audit: latestAudit.exists ? latestAudit : null,
    source: "rpc",
  };
}