/**
 * Postgres indexer — materializes on-chain registry state into a read model.
 *
 * The blockchain stays the source of truth; Postgres enables fast paginated
 * queries, summary endpoints, and catch-up after downtime.
 *
 * Behavior:
 *   - On boot: backfill all events from INDEXER_FROM_BLOCK (or 0) to head.
 *   - Then: subscribe to watchEvent for real-time updates.
 *   - If Postgres is unavailable, the API degrades gracefully to direct RPC
 *     reads (see services/verify.ts).
 */
import pg from "pg";
import { getContract, parseAbiItem, type AbiEvent, type Address, type Log } from "viem";
import { publicClient, CONTRACTS, PG_URL } from "../config.js";
import {
  AssetRegistryAbi,
  VendorRegistryAbi,
  MigrationRegistryAbi,
  AuditRegistryAbi,
} from "../lib/abis.js";

const { Pool } = pg;

export const pool = PG_URL ? new Pool({ connectionString: PG_URL, max: 10 }) : null;

export async function initSchema(): Promise<void> {
  if (!pool) return;
  const sql = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../db/schema.sql", import.meta.url), "utf-8"),
  );
  await pool.query(sql);
}

const EVENTS = [
  {
    key: "assets",
    contract: () => CONTRACTS.assetRegistry,
    abi: AssetRegistryAbi,
    event:
      "event CBOMRegistered(bytes32 indexed assetId, address indexed orgDid, bytes32 cbomHash, string metadataURI, uint256 timestamp)",
    upsert: `
      INSERT INTO assets (asset_id, org_did, cbom_hash, metadata_uri, timestamp, last_updated, active, tx_hash, block_number)
      VALUES ($1,$2,$3,$4,$5,$5,TRUE,$6,$7)
      ON CONFLICT (asset_id) DO UPDATE SET
        cbom_hash=EXCLUDED.cbom_hash, metadata_uri=EXCLUDED.metadata_uri,
        last_updated=EXCLUDED.last_updated, active=TRUE`,
  },
  {
    key: "assets.updated",
    contract: () => CONTRACTS.assetRegistry,
    abi: AssetRegistryAbi,
    event:
      "event CBOMUpdated(bytes32 indexed assetId, bytes32 newCbomHash, string newMetadataURI, uint256 timestamp)",
    upsert: `
      INSERT INTO assets (asset_id, org_did, cbom_hash, metadata_uri, timestamp, last_updated, active, tx_hash, block_number)
      VALUES ($1,'', $2,$3,0,$4,TRUE,$5,$6)
      ON CONFLICT (asset_id) DO UPDATE SET
        cbom_hash=EXCLUDED.cbom_hash, metadata_uri=EXCLUDED.metadata_uri,
        last_updated=EXCLUDED.last_updated, active=TRUE`,
  },
  {
    key: "assets.retired",
    contract: () => CONTRACTS.assetRegistry,
    abi: AssetRegistryAbi,
    event: "event CBOMRetired(bytes32 indexed assetId, uint256 timestamp)",
    upsert: `
      INSERT INTO assets (asset_id, org_did, cbom_hash, metadata_uri, timestamp, last_updated, active, tx_hash, block_number)
      VALUES ($1,'', '', '', 0, $2, FALSE, $3, $4)
      ON CONFLICT (asset_id) DO UPDATE SET last_updated=EXCLUDED.last_updated, active=FALSE`,
  },
  {
    key: "attestations",
    contract: () => CONTRACTS.vendorRegistry,
    abi: VendorRegistryAbi,
    event:
      "event ProductAttested(bytes32 indexed attestationId, address indexed vendorDid, string productId, string version, string algorithm, bool supported, string evidenceURI, uint256 timestamp)",
    upsert: `
      INSERT INTO attestations (attestation_id, vendor_did, product_id, version, algorithm, supported, evidence_uri, timestamp, revoked, tx_hash, block_number)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE,$9,$10)
      ON CONFLICT (attestation_id) DO UPDATE SET
        vendor_did=EXCLUDED.vendor_did, supported=EXCLUDED.supported,
        evidence_uri=EXCLUDED.evidence_uri, revoked=FALSE`,
  },
  {
    key: "attestations.revoked",
    contract: () => CONTRACTS.vendorRegistry,
    abi: VendorRegistryAbi,
    event: "event AttestationRevoked(bytes32 indexed attestationId, uint256 timestamp)",
    upsert: `
      INSERT INTO attestations (attestation_id, vendor_did, product_id, version, algorithm, supported, evidence_uri, timestamp, revoked, tx_hash, block_number)
      VALUES ($1,'','','','',FALSE,'', $2, TRUE, $3, $4)
      ON CONFLICT (attestation_id) DO UPDATE SET revoked=TRUE`,
  },
  {
    key: "migrations",
    contract: () => CONTRACTS.migrationRegistry,
    abi: MigrationRegistryAbi,
    event:
      "event MigrationRecorded(bytes32 indexed migrationId, bytes32 indexed assetId, address indexed orgDid, string fromAlgorithm, string toAlgorithm, bytes32 evidenceHash, string evidenceURI, uint256 timestamp)",
    upsert: `
      INSERT INTO migrations (migration_id, asset_id, org_did, from_algorithm, to_algorithm, evidence_hash, evidence_uri, timestamp, verified, tx_hash, block_number)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE,$9,$10)
      ON CONFLICT (migration_id) DO UPDATE SET
        from_algorithm=EXCLUDED.from_algorithm, to_algorithm=EXCLUDED.to_algorithm,
        evidence_hash=EXCLUDED.evidence_hash, evidence_uri=EXCLUDED.evidence_uri`,
  },
  {
    key: "audits",
    contract: () => CONTRACTS.auditRegistry,
    abi: AuditRegistryAbi,
    event:
      "event AuditPosted(bytes32 indexed auditId, address indexed orgDid, address indexed auditorDid, uint8 result, uint256 assetsReviewed, uint256 assetsMigrated, bytes32 reportHash, string reportURI, uint256 timestamp)",
    upsert: `
      INSERT INTO audits (audit_id, org_did, auditor_did, result, assets_reviewed, assets_migrated, report_hash, report_uri, timestamp, tx_hash, block_number)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (audit_id) DO UPDATE SET
        auditor_did=EXCLUDED.auditor_did, result=EXCLUDED.result,
        assets_reviewed=EXCLUDED.assets_reviewed, assets_migrated=EXCLUDED.assets_migrated`,
  },
] as const;

interface EventSpec {
  key: string;
  contract: () => Address;
  abi: typeof AssetRegistryAbi;
  event: string;
  upsert: string;
}

async function applyLog(spec: EventSpec, log: Log): Promise<void> {
  if (!pool) return;
  const args = (log as any).args as Record<string, unknown>;
  const row = [log.transactionHash, log.blockNumber?.toString() ?? "0"];

  switch (spec.key) {
    case "assets":
      await pool.query(spec.upsert, [
        args.assetId, args.orgDid, args.cbomHash, args.metadataURI,
        Number(args.timestamp), ...row,
      ]);
      break;
    case "assets.updated":
      await pool.query(spec.upsert, [
        args.assetId, args.newCbomHash, args.newMetadataURI, Number(args.timestamp), ...row,
      ]);
      break;
    case "assets.retired":
      await pool.query(spec.upsert, [args.assetId, Number(args.timestamp), ...row]);
      break;
    case "attestations":
      await pool.query(spec.upsert, [
        args.attestationId, args.vendorDid, args.productId, args.version,
        args.algorithm, args.supported, args.evidenceURI, Number(args.timestamp), ...row,
      ]);
      break;
    case "attestations.revoked":
      await pool.query(spec.upsert, [args.attestationId, Number(args.timestamp), ...row]);
      break;
    case "migrations":
      await pool.query(spec.upsert, [
        args.migrationId, args.assetId, args.orgDid, args.fromAlgorithm,
        args.toAlgorithm, args.evidenceHash, args.evidenceURI,
        Number(args.timestamp), ...row,
      ]);
      break;
    case "audits":
      await pool.query(spec.upsert, [
        args.auditId, args.orgDid, args.auditorDid, Number(args.result),
        Number(args.assetsReviewed), Number(args.assetsMigrated),
        args.reportHash, args.reportURI, Number(args.timestamp), ...row,
      ]);
      break;
    default:
      break;
  }
}

export async function getCursor(key: string): Promise<bigint> {
  if (!pool) return 0n;
  const res = await pool.query("SELECT block FROM indexer_state WHERE key=$1", [key]);
  return res.rows.length ? BigInt(res.rows[0].block) : BigInt(0);
}

export async function setCursor(key: string, block: bigint): Promise<void> {
  if (!pool) return;
  await pool.query(
    `INSERT INTO indexer_state (key, block, updated_at) VALUES ($1,$2,now())
     ON CONFLICT (key) DO UPDATE SET block=EXCLUDED.block, updated_at=now()`,
    [key, block.toString()],
  );
}

/** Backfill one event stream from the stored cursor to head, then advance. */
async function backfill(spec: EventSpec): Promise<void> {
  if (!pool) return;
  const address = spec.contract();
  if (address === "0x0") return;

  let from = await getCursor(spec.key);
  if (from === 0n) from = BigInt(process.env.QTRUST_INDEXER_FROM_BLOCK ?? 0);
  const head = await publicClient.getBlockNumber();

  if (from >= head) return;

  const eventItem = parseAbiItem(spec.event) as AbiEvent;
  const step = 2000n;
  for (let start = from; start < head; start += step) {
    const end = start + step > head ? head : start + step;
    const logs = await publicClient.getLogs({
      address,
      event: eventItem,
      fromBlock: start,
      toBlock: end,
    });
    for (const log of logs) await applyLog(spec, log as Log);
    await setCursor(spec.key, end);
  }
  console.log(`Indexer: ${spec.key} caught up to block ${head}`);
}

/** Subscribe to live events after the initial backfill. */
function watchLive(spec: EventSpec): void {
  const address = spec.contract();
  if (address === "0x0") return;
  publicClient.watchEvent({
    address,
    event: parseAbiItem(spec.event) as AbiEvent,
    onLogs: async (logs) => {
      for (const log of logs) {
        await applyLog(spec, log as Log);
        await setCursor(spec.key, (log.blockNumber ?? 0n) + 1n);
      }
    },
  });
}

let started = false;

/** Start the indexer (idempotent). Call once at server boot. */
export async function startIndexer(): Promise<void> {
  if (!pool || started) return;
  started = true;
  try {
    await initSchema();
    for (const spec of EVENTS) {
      await backfill(spec as unknown as EventSpec);
      watchLive(spec as unknown as EventSpec);
    }
    console.log("Indexer started (Postgres read model live)");
  } catch (err) {
    console.warn("Indexer failed to start — API will use direct RPC reads:", err);
  }
}

// ------------------------------------------------------------------
// Query helpers (used by verify.ts when Postgres is available)
// ------------------------------------------------------------------

export async function querySummary(org: string) {
  if (!pool) return null;
  const [assets, migrations, audits] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS count FROM assets WHERE org_did=$1", [org]),
    pool.query(
      `SELECT COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE verified)::int AS verified,
              COUNT(*) FILTER (WHERE NOT verified)::int AS unverified
       FROM migrations WHERE org_did=$1`,
      [org],
    ),
    pool.query(
      "SELECT result, timestamp FROM audits WHERE org_did=$1 ORDER BY timestamp DESC LIMIT 1",
      [org],
    ),
  ]);
  return {
    asset_count: assets.rows[0].count,
    migration_counts: migrations.rows[0],
    latest_audit: audits.rows[0] ?? null,
  };
}

export async function queryAssets(
  org?: string,
  offset = 0,
  limit = 50,
): Promise<{ rows: unknown[]; total: number } | null> {
  if (!pool) return null;
  const where = org ? "WHERE org_did=$1" : "";
  const params = org ? [org, limit, offset] : [limit, offset];
  const [rows, total] = await Promise.all([
    pool.query(
      `SELECT asset_id, org_did, cbom_hash, metadata_uri, timestamp, last_updated, active
       FROM assets ${where} ORDER BY timestamp DESC LIMIT $${org ? 2 : 1} OFFSET $${org ? 3 : 2}`,
      params,
    ),
    pool.query(`SELECT COUNT(*)::int AS count FROM assets ${where}`, org ? [org] : []),
  ]);
  return { rows: rows.rows, total: total.rows[0].count };
}

export async function queryAttestations(
  vendor?: string,
  offset = 0,
  limit = 50,
): Promise<{ rows: unknown[]; total: number } | null> {
  if (!pool) return null;
  const where = vendor ? "WHERE vendor_did=$1" : "";
  const params = vendor ? [vendor, limit, offset] : [limit, offset];
  const [rows, total] = await Promise.all([
    pool.query(
      `SELECT attestation_id, vendor_did, product_id, version, algorithm, supported, evidence_uri, timestamp, revoked
       FROM attestations ${where} ORDER BY timestamp DESC LIMIT $${vendor ? 2 : 1} OFFSET $${vendor ? 3 : 2}`,
      params,
    ),
    pool.query(`SELECT COUNT(*)::int AS count FROM attestations ${where}`, vendor ? [vendor] : []),
  ]);
  return { rows: rows.rows, total: total.rows[0].count };
}

export async function queryMigrations(
  org?: string,
  offset = 0,
  limit = 50,
): Promise<{ rows: unknown[]; total: number } | null> {
  if (!pool) return null;
  const where = org ? "WHERE org_did=$1" : "";
  const params = org ? [org, limit, offset] : [limit, offset];
  const [rows, total] = await Promise.all([
    pool.query(
      `SELECT migration_id, asset_id, org_did, from_algorithm, to_algorithm, evidence_hash, evidence_uri, timestamp, verified
       FROM migrations ${where} ORDER BY timestamp DESC LIMIT $${org ? 2 : 1} OFFSET $${org ? 3 : 2}`,
      params,
    ),
    pool.query(`SELECT COUNT(*)::int AS count FROM migrations ${where}`, org ? [org] : []),
  ]);
  return { rows: rows.rows, total: total.rows[0].count };
}