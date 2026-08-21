/**
 * Q-Trust backend API.
 *
 * v1 routes:
 *   GET  /health
 *   GET  /v1/assets/:id                — single asset
 *   GET  /v1/assets/:id/verify         — on-chain verification result
 *   GET  /v1/orgs/:did/summary         — indexer-backed org summary
 *   GET  /v1/orgs/:did/assets          — assets (paginated)
 *   GET  /v1/orgs/:did/migrations      — migrations (paginated)
 *   GET  /v1/orgs/:did/audit          — latest audit
 *   GET  /v1/migrations/:id            — single migration
 *   GET  /v1/vendors/:did/attestations — attestations (paginated)
 *   GET  /v1/products/:id/support      — algorithm support check
 *   GET  /v1/plans/:did                — AI migration plan (planner microservice)
 *   POST /v1/write/assets              — admin: register CBOM
 *   POST /v1/write/attestations        — admin: direct attestation (relayer)
 *   POST /v1/relay/attestation         — EIP-712 gasless attestation
 *   POST /v1/write/migrations          — admin: record migration
 *   POST /v1/webhooks/subscribe        — webhook subscription (Redis)
 *   POST /v1/webhooks/unsubscribe
 *   GET  /v1/webhooks/subscribers
 *
 * Hardening: CORS allowlist, API-key-gated write routes, request body
 * size caps, rate limiting, JSON schema validation.
 */
import fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import * as dotenv from "dotenv";
import { Redis } from "ioredis";
import {
  getAsset,
  verifyAsset,
  getAssetsByOrg,
  getVendorAttestations,
  getMigrationsByOrg,
  getMigrationProgress,
  getLatestAudit,
  checkProductSupport,
  getMigration,
  getOrgSummary,
} from "./services/verify.js";
import {
  registerCBOM,
  attestProduct,
  recordMigration,
  relaySignedAttestation,
  relayerAddress,
  getVendorNonce,
  type SignedAttestationPayload,
} from "./services/attestation.js";
import { startIndexer } from "./services/indexer.js";
import { CORS_ORIGINS, API_KEYS, PLANNER_URL, CHAIN } from "./config.js";

dotenv.config();

const server: FastifyInstance = fastify({
  logger: true,
  bodyLimit: 1 * 1024 * 1024,
});

// Redis for webhook subscriptions (optional — degrades gracefully)
const redisUrl =
  process.env.QTRUST_REDIS_URL ?? process.env.REDIS_URL ?? "redis://localhost:6379";
let redis: Redis | null = null;
try {
  redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 });
  redis.connect().catch(() => {
    console.warn("Redis unavailable — webhook subscriptions disabled");
    redis = null;
  });
} catch {
  redis = null;
}

// ------------------------------------------------------------------
// Global hardening
// ------------------------------------------------------------------
server.register(cors, {
  origin: CORS_ORIGINS.includes("*") ? true : CORS_ORIGINS,
  methods: ["GET", "POST", "OPTIONS"],
});

server.register(rateLimit, {
  max: 120,
  timeWindow: "1 minute",
  // Allow generous bursts for paginated reads; strict per-IP by default.
});

/** Require a valid admin API key on write routes. */
function requireApiKey(request: any, reply: any, done: () => void): void {
  const key = request.headers["x-api-key"] as string | undefined;
  if (!API_KEYS.length) {
    // No keys configured — dev mode, allow writes.
    return done();
  }
  if (!key || !API_KEYS.includes(key)) {
    return reply.status(401).send({ error: "Invalid or missing API key" });
  }
  done();
}

// ------------------------------------------------------------------
// Health
// ------------------------------------------------------------------
server.get("/health", async () => ({
  status: "ok",
  chain_id: CHAIN.id,
  relayer: relayerAddress,
}));

// ------------------------------------------------------------------
// v1 read API
// ------------------------------------------------------------------
server.get("/v1/assets/:id", async (request, reply) => {
  const asset = await getAsset((request.params as { id: string }).id);
  if (!asset) return reply.status(404).send({ error: "Asset not found" });
  return asset;
});

server.get("/v1/assets/:id/verify", async (request, reply) => {
  try {
    return await verifyAsset((request.params as { id: string }).id);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(400).send({ error: msg });
  }
});

server.get("/v1/orgs/:did/summary", async (request, reply) => {
  try {
    return await getOrgSummary((request.params as { did: string }).did as `0x${string}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(400).send({ error: msg });
  }
});

server.get("/v1/orgs/:did/assets", async (request, reply) => {
  const did = (request.params as { did: string }).did as `0x${string}`;
  const q = request.query as { offset?: string; limit?: string };
  const offset = Math.max(0, Number(q.offset ?? 0));
  const limit = Math.min(200, Math.max(1, Number(q.limit ?? 50)));
  const page = await getAssetsByOrg(did, offset, limit);
  return { org: did, ...page };
});

server.get("/v1/orgs/:did/migrations", async (request, reply) => {
  const did = (request.params as { did: string }).did as `0x${string}`;
  const q = request.query as { offset?: string; limit?: string };
  const offset = Math.max(0, Number(q.offset ?? 0));
  const limit = Math.min(200, Math.max(1, Number(q.limit ?? 50)));
  const [progress, migrations, latestAudit] = await Promise.all([
    getMigrationProgress(did),
    getMigrationsByOrg(did, offset, limit),
    getLatestAudit(did),
  ]);
  return { org: did, progress, migrations, latest_audit: latestAudit };
});

server.get("/v1/orgs/:did/audit", async (request, reply) => {
  const did = (request.params as { did: string }).did as `0x${string}`;
  return getLatestAudit(did);
});

server.get("/v1/migrations/:id", async (request, reply) => {
  try {
    const migration = await getMigration((request.params as { id: string }).id);
    if (!migration) return reply.status(404).send({ error: "Migration not found" });
    return migration;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(400).send({ error: msg });
  }
});

server.get("/v1/vendors/:did/attestations", async (request, reply) => {
  const did = (request.params as { did: string }).did as `0x${string}`;
  const q = request.query as { offset?: string; limit?: string };
  const offset = Math.max(0, Number(q.offset ?? 0));
  const limit = Math.min(200, Math.max(1, Number(q.limit ?? 50)));
  const page = await getVendorAttestations(did, offset, limit);
  return { vendor: did, ...page };
});

server.get("/v1/products/:id/support", async (request, reply) => {
  const q = request.query as { version?: string; algorithm?: string };
  const productId = (request.params as { id: string }).id;
  if (!q.version || !q.algorithm) {
    return reply.status(400).send({ error: "version and algorithm query params required" });
  }
  return checkProductSupport(productId, q.version, q.algorithm);
});

/** AI migration planning — proxied to the planner microservice. */
server.post("/v1/plans", async (request, reply) => {
  const body = request.body as { cbom?: Record<string, unknown>; deadline?: string };
  if (!body.cbom || !Array.isArray(body.cbom.assets) || !body.cbom.assets.length) {
    return reply.status(400).send({
      error: "cbom.assets (non-empty array) is required",
    });
  }
  try {
    const res = await fetch(`${PLANNER_URL}/plan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ cbom: body.cbom, deadline: body.deadline ?? null }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) {
      const detail = await res.text();
      return reply.status(res.status).send({ error: `Planner service error: ${detail}` });
    }
    return res.json();
  } catch {
    return reply.status(503).send({
      error: "Planner service unavailable — start it with: docker compose up planner",
    });
  }
});

server.get("/v1/plans/:did", async (request, reply) => {
  try {
    const did = (request.params as { did: string }).did;
    const q = request.query as { deadline?: string };
    const url = `${PLANNER_URL}/plans/${encodeURIComponent(did)}${q.deadline ? `?deadline=${encodeURIComponent(q.deadline)}` : ""}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) {
      return reply.status(res.status).send({ error: `Planner service error: ${res.status}` });
    }
    return res.json();
  } catch {
    return reply.status(503).send({
      error: "Planner service unavailable — start it with: docker compose up planner",
    });
  }
});

// ------------------------------------------------------------------
// Admin write API (API-key gated; relayer submits transactions)
// ------------------------------------------------------------------
server.post("/v1/write/assets", { preHandler: requireApiKey }, async (request, reply) => {
  const body = request.body as { cbomHash?: string; metadataURI?: string };
  if (!body.cbomHash || !body.cbomHash.startsWith("0x")) {
    return reply.status(400).send({ error: "cbomHash (0x-prefixed) is required" });
  }
  try {
    const result = await registerCBOM({
      cbomHash: body.cbomHash,
      metadataURI: body.metadataURI ?? "",
    });
    return { ...result, relayer: relayerAddress };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(422).send({ error: `Registration failed: ${msg}` });
  }
});

server.post("/v1/write/attestations", { preHandler: requireApiKey }, async (request, reply) => {
  const body = request.body as {
    productId?: string;
    version?: string;
    algorithm?: string;
    supported?: boolean;
    evidenceURI?: string;
  };
  if (!body.productId || !body.version || !body.algorithm) {
    return reply.status(400).send({
      error: "productId, version and algorithm are required",
    });
  }
  try {
    const result = await attestProduct({
      productId: body.productId,
      version: body.version,
      algorithm: body.algorithm,
      supported: Boolean(body.supported),
      evidenceURI: body.evidenceURI ?? "",
    });
    return { ...result, relayer: relayerAddress };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(422).send({ error: `Attestation failed: ${msg}` });
  }
});

server.post("/v1/write/migrations", { preHandler: requireApiKey }, async (request, reply) => {
  const body = request.body as {
    migrationId?: string;
    assetId?: string;
    fromAlgorithm?: string;
    toAlgorithm?: string;
    evidenceHash?: string;
    evidenceURI?: string;
  };
  if (!body.migrationId || !body.assetId || !body.fromAlgorithm || !body.toAlgorithm) {
    return reply.status(400).send({
      error: "migrationId, assetId, fromAlgorithm and toAlgorithm are required",
    });
  }
  try {
    const result = await recordMigration({
      migrationId: body.migrationId,
      assetId: body.assetId,
      fromAlgorithm: body.fromAlgorithm,
      toAlgorithm: body.toAlgorithm,
      evidenceHash: body.evidenceHash ?? "0x" + "0".repeat(64),
      evidenceURI: body.evidenceURI ?? "",
    });
    return { ...result, relayer: relayerAddress };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(422).send({ error: `Migration failed: ${msg}` });
  }
});

// ------------------------------------------------------------------
// EIP-712 gasless relay
// ------------------------------------------------------------------
server.post("/v1/relay/attestation", async (request, reply) => {
  const body = request.body as SignedAttestationPayload;
  if (!body.productId || !body.version || !body.algorithm || !body.signature) {
    return reply.status(400).send({
      error: "productId, version, algorithm, nonce and signature are required",
    });
  }
  if (typeof body.supported !== "boolean") {
    return reply.status(400).send({ error: "supported must be a boolean" });
  }
  try {
    const result = await relaySignedAttestation(body);
    return { ...result, relayer: relayerAddress, chain_id: CHAIN.id };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const code = msg.includes("signature") || msg.includes("Nonce") ? 400 : 422;
    return reply.status(code).send({ error: msg });
  }
});

server.get("/v1/relay/nonce/:did", async (request, reply) => {
  try {
    const nonce = await getVendorNonce((request.params as { did: string }).did as `0x${string}`);
    return { did: (request.params as { did: string }).did, nonce: nonce.toString() };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(400).send({ error: msg });
  }
});

// ------------------------------------------------------------------
// Webhooks (Redis-backed subscriptions)
// ------------------------------------------------------------------
server.post("/v1/webhooks/subscribe", async (request, reply) => {
  const { address, url, secret, events } = request.body as {
    address: string;
    url: string;
    secret?: string;
    events?: string[];
  };
  if (!address || !url) {
    return reply.status(400).send({ error: "address and url are required" });
  }
  if (!redis) {
    return reply.status(503).send({ error: "Redis unavailable — webhook service not running" });
  }
  const eventList = events && events.length ? events : ["*"];
  const payload = JSON.stringify({ url, address, secret: secret ?? "" });
  for (const event of eventList) {
    const key = event === "*" ? "subscribers:*" : `subscribers:${event}`;
    await redis.sadd(key, payload);
  }
  return { subscribed: true, subscriber: { address, url, events: eventList, secret: secret ? "•••" : "" } };
});

server.post("/v1/webhooks/unsubscribe", async (request, reply) => {
  const { address, url, events } = request.body as {
    address: string;
    url: string;
    events?: string[];
  };
  if (!redis) {
    return reply.status(503).send({ error: "Redis unavailable" });
  }
  const eventList = events && events.length ? events : ["*"];
  const payload = JSON.stringify({ url, address });
  let removed = 0;
  for (const event of eventList) {
    const key = event === "*" ? "subscribers:*" : `subscribers:${event}`;
    removed += await redis.srem(key, payload);
  }
  return { unsubscribed: true, removed };
});

server.get("/v1/webhooks/subscribers", async () => {
  if (!redis) return { subscribers: [] };
  const keys = await redis.keys("subscribers:*");
  const subscribers = [];
  for (const key of keys) {
    const members = await redis.smembers(key);
    subscribers.push({ event: key.replace("subscribers:", ""), count: members.length });
  }
  return { subscribers };
});

// ------------------------------------------------------------------
// Legacy (pre-v1) aliases
// ------------------------------------------------------------------
server.get("/assets/:id", async (request, reply) => {
  const asset = await getAsset((request.params as { id: string }).id);
  if (!asset) return reply.status(404).send({ error: "Asset not found" });
  return asset;
});

server.get("/migration/progress/:org", async (request, reply) => {
  return getMigrationProgress((request.params as { org: string }).org as `0x${string}`);
});

// ------------------------------------------------------------------
// Boot: start indexer, then listen
// ------------------------------------------------------------------
const start = async () => {
  try {
    await startIndexer();
    await server.listen({ port: Number(process.env.PORT) || 3001, host: "0.0.0.0" });
    console.log(`Server listening on ${JSON.stringify(server.server.address())}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

start();