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
import { CONTRACTS, PG_URL } from "../config.js";
import { getPublicClient } from "./rpc-pool.js";
import { setIndexerLag } from "../plugins/metrics.js";
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

export async function setCursor(key: string, block: bigint, blockHash = ""): Promise<void> {
  if (!pool) return;
  await pool.query(
    `INSERT INTO indexer_state (key, block, block_hash, updated_at) VALUES ($1,$2,$3,now())
     ON CONFLICT (key) DO UPDATE SET block=EXCLUDED.block, block_hash=EXCLUDED.block_hash, updated_at=now()`,
    [key, block.toString(), blockHash],
  );
}

// ------------------------------------------------------------------
// Reorg detection
// ------------------------------------------------------------------

/** Number of recent blocks to keep for reorg verification (≈ one epoch). */
const REORG_CHECK_DEPTH = Number(process.env.QTRUST_INDEXER_REORG_DEPTH ?? 12);

/** Record a processed block number + hash so forks can be detected later. */
async function recordProcessedBlock(blockNumber: bigint, blockHash: string): Promise<void> {
  if (!pool || !blockNumber || !blockHash) return;
  await pool.query(
    `INSERT INTO processed_blocks (block_number, block_hash) VALUES ($1,$2)
     ON CONFLICT (block_number) DO UPDATE SET block_hash=EXCLUDED.block_hash`,
    [blockNumber.toString(), blockHash],
  );
}

/**
 * Verify the last REORG_CHECK_DEPTH processed blocks against the canonical
 * chain. On a hash mismatch (reorg), delete all indexed rows from the forked
 * blocks and rewind the cursor so backfill re-indexes from the fork point.
 * Returns the block the cursor was rewound to, or null if no reorg occurred.
 */
async function detectAndHandleReorg(spec: EventSpec): Promise<bigint | null> {
  if (!pool) return null;
  const res = await pool.query(
    `SELECT block_number, block_hash FROM processed_blocks ORDER BY block_number DESC LIMIT $1`,
    [REORG_CHECK_DEPTH],
  );
  for (const row of res.rows) {
    const storedNumber = BigInt(row.block_number);
    let canonical;
    try {
      canonical = await getPublicClient().getBlock({ blockNumber: storedNumber });
    } catch {
      continue; // transient RPC error — retry on next poll
    }
    if (canonical.hash.toLowerCase() !== String(row.block_hash).toLowerCase()) {
      // Fork detected at this block: purge everything at/after it.
      console.warn(
        `Indexer: reorg detected at block ${storedNumber} (stored ${row.block_hash}, canonical ${canonical.hash}) — rewinding ${spec.key}`,
      );
      // B-5 remediation: pool.query("BEGIN") does NOT pin a connection — each
      // statement may land on a different pooled connection and autocommit,
      // leaving a partially-purged read model. Pin one client for the whole
      // transaction instead.
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("DELETE FROM assets WHERE block_number >= $1", [storedNumber]);
        await client.query("DELETE FROM attestations WHERE block_number >= $1", [storedNumber]);
        await client.query("DELETE FROM migrations WHERE block_number >= $1", [storedNumber]);
        await client.query("DELETE FROM audits WHERE block_number >= $1", [storedNumber]);
        await client.query("DELETE FROM processed_blocks WHERE block_number >= $1", [storedNumber]);
        // B-6 remediation: the purge above wipes every spec's data, so every
        // spec cursor must rewind to the fork point — not just the caller's.
        // Otherwise the other streams resume past the fork and permanently
        // miss the re-executed events.
        for (const s of EVENTS as unknown as EventSpec[]) {
          await client.query(
            `INSERT INTO indexer_state (key, block, block_hash, updated_at) VALUES ($1, $2, '', now())
             ON CONFLICT (key) DO UPDATE SET block = EXCLUDED.block, block_hash = '', updated_at = now()`,
            [s.key, storedNumber.toString()],
          );
        }
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        throw err;
      } finally {
        client.release();
      }
      for (const s of EVENTS as unknown as EventSpec[]) {
        await setCursor(s.key, storedNumber);
      }
      return storedNumber;
    }
  }
  return null;
}

/** Backfill one event stream from the stored cursor to head, then advance. */
async function backfill(spec: EventSpec): Promise<void> {
  if (!pool) return;
  const address = spec.contract();
  if (address === "0x0") return;

  // Reorg check first: if previously indexed blocks are no longer canonical,
  // purge forked rows and resume from the fork point.
  await detectAndHandleReorg(spec).catch((err) => {
    console.warn(`Indexer: reorg check failed for ${spec.key}:`, err);
  });

  let from = await getCursor(spec.key);
  // detectAndHandleReorg already rewrote the cursor to the fork point on a
  // reorg, so a plain read resumes indexing from there.
  if (from === 0n) from = BigInt(process.env.QTRUST_INDEXER_FROM_BLOCK ?? 0);
  const head = await getPublicClient().getBlockNumber();

  if (from >= head) {
    setIndexerLag(0);
    return;
  }

  const eventItem = parseAbiItem(spec.event) as AbiEvent;
  const step = 2000n;
  for (let start = from; start < head; start += step) {
    const end = start + step > head ? head : start + step;
    const logs = await getPublicClient().getLogs({
      address,
      event: eventItem,
      fromBlock: start,
      toBlock: end,
    });
    for (const log of logs) {
      await applyLog(spec, log as Log);
      if (log.blockNumber && log.blockHash) {
        await recordProcessedBlock(log.blockNumber, log.blockHash);
      }
    }
    await setCursor(spec.key, end);
    setIndexerLag(Number(head - end));
  }
  setIndexerLag(0);
  console.log(`Indexer: ${spec.key} caught up to block ${head}`);
}

/** Number of block confirmations to wait before treating an event as final. */
const CONFIRMATIONS = Number(process.env.QTRUST_INDEXER_CONFIRMATIONS ?? 12);

/** Minimum interval between reorg checks triggered by live polls (ms). */
const REORG_CHECK_INTERVAL_MS = Number(process.env.QTRUST_INDEXER_REORG_CHECK_INTERVAL_MS ?? 30_000);
let lastReorgCheckAt = 0;

/** Subscribe to live events after the initial backfill. */
const unwatchers: Array<() => void> = [];

function watchLive(spec: EventSpec): void {
  const address = spec.contract();
  if (address === "0x0") return;
  const unwatch = getPublicClient().watchEvent({
    address,
    event: parseAbiItem(spec.event) as AbiEvent,
    onLogs: async (logs) => {
      // Reorg check on each poll — verify recently indexed blocks are still
      // canonical; purge + rewind if the chain reorganized underneath us.
      const now = Date.now();
      if (now - lastReorgCheckAt >= REORG_CHECK_INTERVAL_MS) {
        lastReorgCheckAt = now;
        try {
          await detectAndHandleReorg(spec);
        } catch (err) {
          console.warn(`Indexer: reorg check failed for ${spec.key}:`, err);
        }
      }
      let head: bigint | null = null;
      if (CONFIRMATIONS > 0) {
        // Guarded: an RPC outage here must not reject inside the watcher
        // callback and crash the process (audit Critical #10).
        try {
          head = await getPublicClient().getBlockNumber();
        } catch (err) {
          // Args passed separately (not interpolated) — semgrep unsafe-formatstring.
          console.warn("Indexer: getBlockNumber failed for", spec.key, "— skipping batch:", err);
          return;
        }
      }
      for (const log of logs) {
        const blockNum = log.blockNumber ?? 0n;
        // Wait for N confirmations before processing to handle re-orgs.
        if (head !== null) {
          if (head - blockNum < BigInt(CONFIRMATIONS)) {
            // Not enough confirmations yet — skip, backfill will catch it on next restart.
            continue;
          }
        }
        try {
          await applyLog(spec, log as Log);
          if (log.blockNumber && log.blockHash) {
            await recordProcessedBlock(log.blockNumber, log.blockHash);
          }
          await setCursor(spec.key, blockNum + 1n, log.blockHash ?? "");
          // Fan out webhook delivery for this event.
          try {
            const { fanOut } = await import("./webhook.js");
            const orgDid = (log.args as Record<string, unknown>)?.orgDid
              ?? (log.args as Record<string, unknown>)?.vendorDid
              ?? "";
            if (orgDid) {
              await fanOut(orgDid as string, spec.key, {
                event: spec.key,
                blockNumber: Number(blockNum),
                txHash: log.transactionHash,
                args: log.args,
              });
            }
          } catch {
            // Webhook delivery is best-effort — do not block indexing.
          }
        } catch (err) {
          console.error(`Indexer applyLog failed for ${spec.key} at block ${blockNum}:`, err);
          // Do not advance the cursor — backfill will retry on next restart.
        }
      }
    },
  });
  unwatchers.push(unwatch);
}

let started = false;

/** Stop live event subscriptions (graceful shutdown). */
export function stopIndexer(): void {
  for (const unwatch of unwatchers.splice(0)) {
    try {
      unwatch();
    } catch {
      // best-effort during shutdown
    }
  }
  started = false;
}

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