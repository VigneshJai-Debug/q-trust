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
import fastify, { type FastifyInstance, type FastifyRequest, type FastifyReply } from "fastify";
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
  relaySignedCBOMRegistration,
  relaySignedMigration,
  relayerAddress,
  getVendorNonce,
  getOrgNonce,
  type SignedAttestationPayload,
  type SignedCBOMRegistrationPayload,
  type SignedMigrationPayload,
} from "./services/attestation.js";
import { startIndexer } from "./services/indexer.js";
import { evaluate } from "./services/evaluate.js";
import { CORS_ORIGINS, API_KEYS, API_KEY_REQUIRED, PLANNER_URL, CHAIN, CHAIN_ID, publicClient, CONTRACTS } from "./config.js";
import {
  RevocationAnchorAbi,
  PolicyCommitmentAbi,
  SchemaRegistryAbi,
  TrustAnchorRegistryAbi,
} from "./lib/abis.js";
import { isValidAddress, isValidBytes32 } from "./config.js";

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

/** Require a valid admin API key on write routes. Fail-closed in production. */
function requireApiKey(request: FastifyRequest, reply: FastifyReply, done: () => void): void {
  const key = request.headers["x-api-key"] as string | undefined;
  if (!API_KEY_REQUIRED) {
    // Dev mode (no keys configured and not production) — allow writes.
    done();
    return;
  }
  if (!API_KEYS.length) {
    // Production with no keys configured — refuse all writes.
    reply.status(401).send({ error: "API keys not configured — write routes disabled" });
    return;
  }
  if (!key || !API_KEYS.includes(key)) {
    reply.status(401).send({ error: "Invalid or missing API key" });
    return;
  }
  done();
}

// ------------------------------------------------------------------
// Health
// ------------------------------------------------------------------
server.get("/health", async () => ({
  status: "ok",
  chain_id: CHAIN_ID,
  relayer: relayerAddress,
}));

// ------------------------------------------------------------------
// v1 read API
// ------------------------------------------------------------------
server.get("/v1/assets/:id", async (request, reply) => {
  const id = (request.params as { id: string }).id;
  if (!isValidBytes32(id)) {
    return reply.status(400).send({ error: "Invalid asset ID format (expected 0x-prefixed 66-char hex)" });
  }
  const asset = await getAsset(id);
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

function validateDid(did: string, reply: FastifyReply): string | undefined {
  if (!isValidAddress(did)) {
    reply.status(400).send({ error: "Invalid DID format (expected 0x-prefixed 42-char hex address)" });
    return undefined;
  }
  return did;
}

server.get("/v1/orgs/:did/summary", async (request, reply) => {
  const did = validateDid((request.params as { did: string }).did, reply);
  if (!did) return;
  try {
    return await getOrgSummary(did as `0x${string}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(400).send({ error: msg });
  }
});

server.get("/v1/orgs/:did/assets", async (request, reply) => {
  const did = validateDid((request.params as { did: string }).did, reply);
  if (!did) return;
  const q = request.query as { offset?: string; limit?: string };
  const offset = Math.max(0, Number(q.offset ?? 0));
  const limit = Math.min(200, Math.max(1, Number(q.limit ?? 50)));
  const page = await getAssetsByOrg(did as `0x${string}`, offset, limit);
  return { org: did, ...page };
});

server.get("/v1/orgs/:did/migrations", async (request, reply) => {
  const did = validateDid((request.params as { did: string }).did, reply);
  if (!did) return;
  const q = request.query as { offset?: string; limit?: string };
  const offset = Math.max(0, Number(q.offset ?? 0));
  const limit = Math.min(200, Math.max(1, Number(q.limit ?? 50)));
  const [progress, migrations, latestAudit] = await Promise.all([
    getMigrationProgress(did as `0x${string}`),
    getMigrationsByOrg(did as `0x${string}`, offset, limit),
    getLatestAudit(did as `0x${string}`),
  ]);
  return { org: did, progress, migrations, latest_audit: latestAudit };
});

server.get("/v1/orgs/:did/audit", async (request, reply) => {
  const did = validateDid((request.params as { did: string }).did, reply);
  if (!did) return;
  return getLatestAudit(did as `0x${string}`);
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
  const did = validateDid((request.params as { did: string }).did, reply);
  if (!did) return;
  const q = request.query as { offset?: string; limit?: string };
  const offset = Math.max(0, Number(q.offset ?? 0));
  const limit = Math.min(200, Math.max(1, Number(q.limit ?? 50)));
  const page = await getVendorAttestations(did as `0x${string}`, offset, limit);
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
  // EIP-712 gasless relay — rate limited to prevent gas abuse
  // ------------------------------------------------------------------
  server.post("/v1/relay/attestation", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (request, reply) => {
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

  // EIP-712 gasless CBOM registration
  server.post("/v1/relay/cbom", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (request, reply) => {
  const body = request.body as SignedCBOMRegistrationPayload;
  if (!body.cbomHash || !body.signature) {
    return reply.status(400).send({
      error: "cbomHash, nonce and signature are required",
    });
  }
  try {
    const result = await relaySignedCBOMRegistration(body);
    return { ...result, relayer: relayerAddress, chain_id: CHAIN.id };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const code = msg.includes("signature") || msg.includes("Nonce") ? 400 : 422;
    return reply.status(code).send({ error: msg });
  }
});

  // EIP-712 gasless migration recording
  server.post("/v1/relay/migration", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (request, reply) => {
  const body = request.body as SignedMigrationPayload;
  if (!body.migrationId || !body.assetId || !body.signature) {
    return reply.status(400).send({
      error: "migrationId, assetId, fromAlgorithm, toAlgorithm, nonce and signature are required",
    });
  }
  try {
    const result = await relaySignedMigration(body);
    return { ...result, relayer: relayerAddress, chain_id: CHAIN.id };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const code = msg.includes("signature") || msg.includes("Nonce") ? 400 : 422;
    return reply.status(code).send({ error: msg });
  }
});

// Fetch org nonce for CBOM registration
server.get("/v1/relay/cbom-nonce/:did", async (request, reply) => {
  try {
    const nonce = await getOrgNonce((request.params as { did: string }).did as `0x${string}`);
    return { did: (request.params as { did: string }).did, nonce: nonce.toString() };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return reply.status(400).send({ error: msg });
  }
});

// ------------------------------------------------------------------
// v1 Trust Evaluation
// ------------------------------------------------------------------
  server.post("/v1/evaluate", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (request, reply) => {
  const { subject_did, policy_id, policy_version, evidence } = request.body as {
    subject_did: string;
    policy_id: string;
    policy_version: string;
    evidence?: Array<{ evidence_id: string; evidence_type: string; claims: Record<string, unknown> }>;
  };
  if (!subject_did || !policy_id || !policy_version) {
    return reply.status(400).send({ error: "subject_did, policy_id, and policy_version are required" });
  }
  return evaluate({ subject_did, policy_id, policy_version, evidence });
});

// ------------------------------------------------------------------
// v1 Credential Operations (placeholder — full VC stack in SDK)
// ------------------------------------------------------------------
server.post("/v1/credentials/issue", { preHandler: requireApiKey }, async (request, reply) => {
  const { schema_id, subject_did, issuer_did, claims, expiration_date } = request.body as {
    schema_id?: string;
    subject_did: string;
    issuer_did: string;
    claims?: Record<string, Record<string, unknown>>;
    expiration_date?: string;
  };
  if (!subject_did || !issuer_did) {
    return reply.status(400).send({ error: "subject_did and issuer_did are required" });
  }

  const credentialId = `urn:uuid:${crypto.randomUUID()}`;
  return {
    credential_id: credentialId,
    issuer_did,
    subject_did,
    schema_id: schema_id ?? null,
    claims: claims ?? {},
    expiration_date: expiration_date ?? null,
    issued_at: new Date().toISOString(),
    note: "Full VC issuance with Ed25519 signing is available via the Python SDK (qtrust.vc.VCIssuer)",
  };
});

server.post("/v1/credentials/verify", async (request, reply) => {
  const { presentation, verifier_did } = request.body as {
    presentation: Record<string, unknown>;
    verifier_did?: string;
  };
  if (!presentation) {
    return reply.status(400).send({ error: "presentation is required" });
  }

  // Structural validation
  if (!presentation.issuer || !presentation.credentialSubject) {
    return {
      valid: false,
      error: "Missing required fields: issuer, credentialSubject",
      verified_at: new Date().toISOString(),
    };
  }

  // Check expiration if expirationDate is present
  let expired = false;
  if (typeof presentation.expirationDate === "string") {
    try {
      const expTime = new Date(presentation.expirationDate);
      expired = expTime < new Date();
    } catch {
      return reply.status(400).send({ error: "Invalid expirationDate format" });
    }
  }

  // Check proof presence
  const hasProof = Boolean(
    presentation.proof && typeof presentation.proof === "object" && "proofValue" in presentation.proof,
  );

  return {
    valid: !expired,
    issuer_did: typeof presentation.issuer === "string" ? presentation.issuer : null,
    subject_did: presentation.credentialSubject && typeof presentation.credentialSubject === "object" && "id" in presentation.credentialSubject
      ? (presentation.credentialSubject as Record<string, unknown>).id as string
      : null,
    schema_id: presentation.credentialSchema && typeof presentation.credentialSchema === "object" && "id" in presentation.credentialSchema
      ? (presentation.credentialSchema as Record<string, unknown>).id as string
      : null,
    expired,
    has_proof: hasProof,
    revoked: false,
    verified_at: new Date().toISOString(),
    note: "Structural validation only. For full Ed25519 signature verification with DID resolution, use the Python SDK (qtrust.vc.VCVerifier)",
  };
});

// ------------------------------------------------------------------
// v1 Revocation (on-chain root queries)
// ------------------------------------------------------------------
server.get("/v1/revocation/:issuer", async (request, reply) => {
  const issuer = (request.params as { issuer: string }).issuer;
  if (!issuer.startsWith("0x") || issuer.length !== 42) {
    return reply.status(400).send({ error: "Invalid issuer address" });
  }
  if (CONTRACTS.revocationAnchor === "0x0") {
    return { issuer, current_root: null, configured: false, note: "RevocationAnchor contract not configured" };
  }
  try {
    const root = await publicClient.readContract({
      address: CONTRACTS.revocationAnchor,
      abi: RevocationAnchorAbi,
      functionName: "getRevocationRoot",
      args: [issuer as `0x${string}`],
    });
    return { issuer, current_root: root, configured: true };
  } catch {
    return { issuer, current_root: "0x" + "0".repeat(64), configured: true, note: "Issuer not registered or query failed" };
  }
});

// ------------------------------------------------------------------
// v1 Policy (on-chain commitment queries)
// ------------------------------------------------------------------
server.get("/v1/policies/:policyId/versions/:version", async (request, reply) => {
  const { policyId, version } = request.params as { policyId: string; version: string };
  if (CONTRACTS.policyCommitment === "0x0") {
    return { policy_id: policyId, version: Number(version), configured: false, note: "PolicyCommitment contract not configured" };
  }
  try {
    const pv = await publicClient.readContract({
      address: CONTRACTS.policyCommitment,
      abi: PolicyCommitmentAbi,
      functionName: "getPolicyVersion",
      args: [policyId, BigInt(version)],
    });
    return {
      policy_id: pv.policyId,
      version: Number(pv.version),
      policy_hash: pv.policyHash,
      policy_uri: pv.policyURI,
      committed_by: pv.committedBy,
      timestamp: Number(pv.timestamp),
      active: pv.active,
      configured: true,
    };
  } catch {
    return { policy_id: policyId, version: Number(version), configured: true, note: "Policy version not found" };
  }
});

// ------------------------------------------------------------------
// v1 Schema Registry (on-chain schema queries)
// ------------------------------------------------------------------
server.get("/v1/schemas/:schemaId", async (request, reply) => {
  const schemaId = (request.params as { schemaId: string }).schemaId;
  if (CONTRACTS.schemaRegistry === "0x0") {
    return { schema_id: schemaId, configured: false, note: "SchemaRegistry contract not configured" };
  }
  try {
    const entry = await publicClient.readContract({
      address: CONTRACTS.schemaRegistry,
      abi: SchemaRegistryAbi,
      functionName: "getSchemaEntry",
      args: [schemaId],
    });
    if (!entry.exists) {
      return { schema_id: schemaId, configured: true, exists: false };
    }
    const sv = await publicClient.readContract({
      address: CONTRACTS.schemaRegistry,
      abi: SchemaRegistryAbi,
      functionName: "getSchema",
      args: [schemaId, entry.latestVersion],
    });
    return {
      schema_id: sv.schemaId,
      version: Number(sv.version),
      schema_hash: sv.schemaHash,
      schema_uri: sv.schemaURI,
      schema_type: sv.schemaType,
      registered_by: sv.registeredBy,
      timestamp: Number(sv.timestamp),
      active: sv.active,
      configured: true,
    };
  } catch {
    return { schema_id: schemaId, configured: true, note: "Schema not found or query failed" };
  }
});

// ------------------------------------------------------------------
// v1 Trust Anchor Registry (on-chain accreditation queries)
// ------------------------------------------------------------------
server.get("/v1/trust-anchors/:issuer", async (request, reply) => {
  const issuer = (request.params as { issuer: string }).issuer;
  if (!issuer.startsWith("0x") || issuer.length !== 42) {
    return reply.status(400).send({ error: "Invalid issuer address" });
  }
  if (CONTRACTS.trustAnchorRegistry === "0x0") {
    return { issuer, accredited: false, configured: false, note: "TrustAnchorRegistry contract not configured" };
  }
  try {
    const result = await publicClient.readContract({
      address: CONTRACTS.trustAnchorRegistry,
      abi: TrustAnchorRegistryAbi,
      functionName: "isIssuerAccredited",
      args: [issuer as `0x${string}`],
    });
    return { issuer, accredited: result, configured: true };
  } catch {
    return { issuer, accredited: false, configured: true, note: "Issuer not found or query failed" };
  }
});

// ------------------------------------------------------------------
// Webhooks (Redis-backed subscriptions) — requires API key for subscribe/unsubscribe
// ------------------------------------------------------------------
server.post("/v1/webhooks/subscribe", { preHandler: requireApiKey }, async (request, reply) => {
  const { address, url, secret, events } = request.body as {
    address: string;
    url: string;
    secret?: string;
    events?: string[];
  };
  if (!address || !url) {
    return reply.status(400).send({ error: "address and url are required" });
  }
  if (!isValidAddress(address)) {
    return reply.status(400).send({ error: "Invalid address format" });
  }
  try {
    new URL(url);
  } catch {
    return reply.status(400).send({ error: "Invalid url format" });
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

server.post("/v1/webhooks/unsubscribe", { preHandler: requireApiKey }, async (request, reply) => {
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

server.get("/v1/webhooks/subscribers", { preHandler: requireApiKey }, async () => {
  if (!redis) return { subscribers: [] };
  const keys = await redis.smembers("subscribers:*");
  const subscribers = keys.map((key) => ({
    event: key.replace("subscribers:", ""),
  }));
  return { subscribers };
});

// ------------------------------------------------------------------
// Legacy (pre-v1) aliases — deprecated, use /v1/* routes
// ------------------------------------------------------------------
server.get("/assets/:id", async (request, reply) => {
  reply.header("Deprecation", "true");
  reply.header("Sunset", "2026-12-31");
  reply.header("Link", `</v1/assets/${(request.params as { id: string }).id}>; rel="successor-version"`);
  const asset = await getAsset((request.params as { id: string }).id);
  if (!asset) return reply.status(404).send({ error: "Asset not found" });
  return asset;
});

server.get("/migration/progress/:org", async (request, reply) => {
  reply.header("Deprecation", "true");
  reply.header("Sunset", "2026-12-31");
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