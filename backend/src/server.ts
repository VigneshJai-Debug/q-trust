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
 *   POST /v1/relay/cbom                — EIP-712 gasless CBOM registration
 *   POST /v1/relay/migration           — EIP-712 gasless migration recording
 *   POST /v1/relay/audit               — EIP-712 gasless audit attestation
 *   POST /v1/write/migrations          — admin: record migration
 *   POST /v1/webhooks/subscribe        — webhook subscription (Redis)
 *   POST /v1/webhooks/unsubscribe
 *   GET  /v1/webhooks/subscribers
 *
 * Docs: OpenAPI JSON at /docs/json, Swagger UI at /docs
 *
 * Hardening: CORS allowlist, API-key-gated write routes, request body
 * size caps, rate limiting, JSON schema validation.
 */
import fastify, { type FastifyRequest, type FastifyReply } from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import { createHash, timingSafeEqual } from "node:crypto";
import { encryptSecret, decryptSecret } from "./services/secret-box.js";
import { setSubscriberResolver } from "./services/webhook.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
  relaySignedAudit,
  relayerAddress,
  getVendorNonce,
  getOrgNonce,
  getAuditNonce,
  type SignedAttestationPayload,
  type SignedCBOMRegistrationPayload,
  type SignedMigrationPayload,
} from "./services/attestation.js";
import { startIndexer, stopIndexer, pool as pgPool } from "./services/indexer.js";
import { evaluate } from "./services/evaluate.js";
import { registerScannerRoutes } from "./routes/scanner.js";
import { registerGPURoutes } from "./services/gpu-service.js";
import { gracefulShutdown } from "./middleware/auth.js";
import { initSentry, registerSentryHooks } from "./plugins/sentry.js";
import { registerMetrics } from "./plugins/metrics.js";
import {
  CredentialVerifySchema,
  RelayAuditBodySchema,
  RelayAttestationBodySchema,
  RelayCBOMBodySchema,
  RelayMigrationBodySchema,
} from "./schemas/index.js";
import { CORS_ORIGINS, API_KEYS, API_KEY_REQUIRED, PLANNER_URL, CHAIN, CHAIN_ID, publicClient, CONTRACTS } from "./config.js";
import {
  RevocationAnchorAbi,
  PolicyCommitmentAbi,
  SchemaRegistryAbi,
  TrustAnchorRegistryAbi,
} from "./lib/abis.js";
import { isValidAddress, isValidBytes32 } from "./config.js";

dotenv.config();

// Sentry (no-op unless QTRUST_SENTRY_DSN is configured) — init before any
// route work so early errors are captured.
initSentry();

const PACKAGE_VERSION: string = (
  JSON.parse(
    readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
  ) as { version: string }
).version;

const server = fastify({
  logger: true,
  bodyLimit: 1 * 1024 * 1024,
}).withTypeProvider<TypeBoxTypeProvider>();

// ------------------------------------------------------------------
// Process-level fault handlers (audit Critical #10): without these, a
// single unhandled promise rejection (e.g. an RPC outage inside an indexer
// callback) takes down the whole API process.
// ------------------------------------------------------------------
process.on("unhandledRejection", (reason) => {
  server.log.error({ err: reason }, "Unhandled promise rejection — keeping process alive");
});
process.on("uncaughtException", (err) => {
  server.log.error({ err }, "Uncaught exception — exiting");
  // An uncaught exception leaves the process in an undefined state; exit
  // cleanly so the process manager restarts us.
  process.exit(1);
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
// Global hardening + OpenAPI docs
// ------------------------------------------------------------------
await server.register(helmet, {
  contentSecurityPolicy: false,
  hsts: { maxAge: 15552000 },
});

server.register(cors, {
  origin: CORS_ORIGINS.includes("*") ? true : CORS_ORIGINS,
  methods: ["GET", "POST", "OPTIONS"],
});

// Per-IP ceiling. QTRUST_RATE_LIMIT_MAX=0 disables the global limiter
// entirely (for load tests or when fronted by an edge proxy that already
// rate-limits); any other value overrides the ceiling; default 120/min
// protects against single-IP abusive clients.
if (process.env.QTRUST_RATE_LIMIT_MAX === "0") {
  server.register(rateLimit, { global: false });
} else {
  server.register(rateLimit, {
    max: Number(process.env.QTRUST_RATE_LIMIT_MAX) || 120,
    timeWindow: "1 minute",
    // Allow generous bursts for paginated reads; strict per-IP by default.
  });
}

// ------------------------------------------------------------------
// Observability — Sentry error hook + Prometheus /metrics endpoint.
// Applied to the root instance so hooks cover every route below.
// ------------------------------------------------------------------
registerSentryHooks(server);
registerMetrics(server);

await server.register(swagger, {
  openapi: {
    info: {
      title: "Q-Trust API",
      version: PACKAGE_VERSION,
      description:
        "Q-Trust supply-chain verification API. PQC readiness scanning, migration tracking, and post-quantum migration evidence anchoring with tamper-evident SHA-256 chains.",
    },
    servers: [{ url: process.env.QTRUST_PUBLIC_URL ?? "http://localhost:3001" }],
  },
});

await server.register(swaggerUi, {
  routePrefix: "/docs",
});

/** Timing-safe API key comparison: hash both sides to fixed-length digests so
 *  neither length nor content short-circuits the comparison. */
function safeApiKeyEquals(a: string, b: string): boolean {
  const sha = (s: string) => createHash("sha256").update(s, "utf8").digest();
  return timingSafeEqual(sha(a), sha(b)) && a === b;
}

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
  if (!key || !API_KEYS.some((k) => safeApiKeyEquals(k, key))) {
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
  relayer: relayerAddress(),
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
// Admin write API (API-key gated; relayer submits transactions).
//
// Each route spawns on-chain transactions via the relayer — they get an
// explicit per-route rate limit (audit Critical #12 / High #17): with
// QTRUST_RATE_LIMIT_MAX=0 the global limiter is disabled, and without a
// per-route config these routes would be unlimited.
// ------------------------------------------------------------------
server.post("/v1/write/assets", {
  preHandler: requireApiKey,
  config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
}, async (request, reply) => {
  const body = request.body as { cbomHash?: string; metadataURI?: string };
  if (!body.cbomHash || !body.cbomHash.startsWith("0x")) {
    return reply.status(400).send({ error: "cbomHash (0x-prefixed) is required" });
  }
  try {
    const result = await registerCBOM({
      cbomHash: body.cbomHash,
      metadataURI: body.metadataURI ?? "",
    });
    return { ...result, relayer: relayerAddress() };
  } catch (err) {
    request.log.error(err, "CBOM registration failed");
    return reply.status(422).send({ error: "Registration failed" });
  }
});

server.post("/v1/write/attestations", {
  preHandler: requireApiKey,
  config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
}, async (request, reply) => {
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
    return { ...result, relayer: relayerAddress() };
  } catch (err) {
    request.log.error(err, "Attestation failed");
    return reply.status(422).send({ error: "Attestation failed" });
  }
});

server.post("/v1/write/migrations", {
  preHandler: requireApiKey,
  config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
}, async (request, reply) => {
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
    return { ...result, relayer: relayerAddress() };
  } catch (err) {
    request.log.error(err, "Migration recording failed");
    return reply.status(422).send({ error: "Migration recording failed" });
  }
});

  // ------------------------------------------------------------------
  // EIP-712 gasless relay — rate limited to prevent gas abuse
  // ------------------------------------------------------------------
  server.post("/v1/relay/attestation", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
    schema: {
      body: RelayAttestationBodySchema,
      tags: ["relay"],
      summary: "Relay an EIP-712-signed vendor attestation",
      description:
        "Verifies the vendor's signature against VendorRegistry's domain, checks the on-chain nonce, and submits attestProductSigned via the relayer.",
    },
  }, async (request, reply) => {
  const body = request.body as SignedAttestationPayload;
  try {
    const result = await relaySignedAttestation(body);
    return { ...result, relayer: relayerAddress(), chain_id: CHAIN.id };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // Only echo our own validation errors; raw transport/RPC errors stay in
    // the logs so internal details never leak to clients (audit H-6).
    if (/Nonce mismatch|signature verification|must be/.test(msg)) {
      return reply.status(400).send({ error: msg });
    }
    request.log.error(err, "Relay attestation failed");
    return reply.status(422).send({ error: "Relay submission failed" });
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
    schema: {
      body: RelayCBOMBodySchema,
      tags: ["relay"],
      summary: "Relay an EIP-712-signed CBOM registration",
      description:
        "Verifies the org's signature against AssetRegistry's domain, checks the on-chain nonce, and submits registerCBOMSigned via the relayer.",
    },
  }, async (request, reply) => {
  const body = request.body as SignedCBOMRegistrationPayload;
  try {
    const result = await relaySignedCBOMRegistration(body);
    return { ...result, relayer: relayerAddress(), chain_id: CHAIN.id };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/Nonce mismatch|signature verification|must be/.test(msg)) {
      return reply.status(400).send({ error: msg });
    }
    request.log.error(err, "Relay CBOM failed");
    return reply.status(422).send({ error: "Relay submission failed" });
  }
});

  // EIP-712 gasless migration recording
  server.post("/v1/relay/migration", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
    schema: {
      body: RelayMigrationBodySchema,
      tags: ["relay"],
      summary: "Relay an EIP-712-signed migration recording",
      description:
        "Verifies the org's signature against MigrationRegistry's domain, checks asset ownership on-chain, and submits recordMigrationSigned via the relayer.",
    },
  }, async (request, reply) => {
  const body = request.body as SignedMigrationPayload;
  try {
    const result = await relaySignedMigration(body);
    return { ...result, relayer: relayerAddress(), chain_id: CHAIN.id };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/Nonce mismatch|signature verification|must be/.test(msg)) {
      return reply.status(400).send({ error: msg });
    }
    request.log.error(err, "Relay migration failed");
    return reply.status(422).send({ error: "Relay submission failed" });
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

  // EIP-712 gasless audit posting
  server.post("/v1/relay/audit", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
    schema: {
      body: RelayAuditBodySchema,
      tags: ["relay"],
      summary: "Relay an EIP-712-signed audit attestation",
      description:
        "Verifies the auditor's signature against AuditRegistry's domain, checks the on-chain nonce, and submits postAuditSigned via the relayer. The signer must hold AUDITOR_ROLE; the recorded auditor is the signer.",
    },
  }, async (request, reply) => {
  const body = request.body;
  try {
    const result = await relaySignedAudit(body);
    return { ...result, relayer: relayerAddress(), chain_id: CHAIN.id };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const code = msg.includes("signature") || msg.includes("Nonce") || msg.includes("must be") ? 400 : 422;
    return reply.status(code).send({ error: msg });
  }
});

// Fetch auditor nonce for audit posting
server.get("/v1/relay/audit-nonce/:did", async (request, reply) => {
  try {
    const nonce = await getAuditNonce((request.params as { did: string }).did as `0x${string}`);
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

server.post("/v1/credentials/verify", { schema: { body: CredentialVerifySchema } }, async (request, reply) => {
  const { presentation, verifier_did } = request.body as {
    presentation: Record<string, unknown>;
    verifier_did?: string;
  };

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
    presentation.proof &&
      typeof presentation.proof === "object" &&
      "proofValue" in presentation.proof &&
      (presentation.proof as Record<string, unknown>).proofValue,
  );
  if (!hasProof) {
    return {
      valid: false,
      reason: "unsigned_credential",
      detail: "Credential has no proof — cryptographic verification required",
      checked: { structure: true, expiration: !expired, signature: false },
      timestamp: new Date().toISOString(),
    };
  }

  // Fail closed: a proof being present is NOT proof of validity. The backend
  // cannot verify Ed25519 signatures, so never report valid:true here.
  return {
    valid: false,
    reason: "signature_verification_unavailable_in_backend",
    detail:
      "Backend cannot verify Ed25519 signatures. Use the Python SDK VCVerifier for full verification, or integrate Veramo.",
    has_proof: true,
    checked: { structure: true, expiration: !expired, signature: false },
    timestamp: new Date().toISOString(),
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
server.post("/v1/webhooks/subscribe", {
  preHandler: requireApiKey,
  config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
}, async (request, reply) => {
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
  const stored = JSON.stringify({
    url,
    address,
    secret: encryptSecret(secret ?? "", () =>
      server.log.warn(
        "QTRUST_WEBHOOK_ENC_KEY not set — webhook secrets are stored UNENCRYPTED in Redis"
      )
    ),
  });
  for (const event of eventList) {
    const key = event === "*" ? "subscribers:*" : `subscribers:${event}`;
    await redis.sadd(key, stored);
  }
  return { subscribed: true, subscriber: { address, url, events: eventList, secret: secret ? "•••" : "" } };
});

server.post("/v1/webhooks/unsubscribe", {
  preHandler: requireApiKey,
  config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
}, async (request, reply) => {
  const { address, url, events } = request.body as {
    address: string;
    url: string;
    events?: string[];
  };
  if (!redis) {
    return reply.status(503).send({ error: "Redis unavailable" });
  }
  if (!address || !url) {
    return reply.status(400).send({ error: "address and url are required" });
  }
  const eventList = events && events.length ? events : ["*"];
  let removed = 0;
  for (const event of eventList) {
    const key = event === "*" ? "subscribers:*" : `subscribers:${event}`;
    // Records may or may not carry an encrypted secret, so exact-string srem
    // cannot match. Remove by identity (url + address) instead.
    const records = await redis.smembers(key);
    for (const raw of records) {
      try {
        const parsed = JSON.parse(raw) as { url?: string; address?: string };
        if (parsed.url === url && parsed.address === address) {
          removed += await redis.srem(key, raw);
        }
      } catch {
        continue; // malformed record — leave untouched
      }
    }
  }
  return { unsubscribed: true, removed };
});

server.get("/v1/webhooks/subscribers", { preHandler: requireApiKey }, async () => {
  if (!redis) return { subscribers: [] };
  // Records are JSON strings ({url, address, secret}) stored in per-event sets.
  const keys = await redis.keys("subscribers:*");
  const byId = new Map<string, { id: string; url: string; events: string[] }>();
  for (const key of keys) {
    const event = key.replace("subscribers:", "");
    const records = await redis.smembers(key);
    for (const raw of records) {
      let url = "";
      try {
        const parsed = JSON.parse(raw) as { url?: string; address?: string; secret?: string };
        url = typeof parsed.url === "string" ? parsed.url : "";
      } catch {
        continue; // skip malformed records rather than leaking raw contents
      }
      if (!url) continue;
      // Stable ID from the record contents — never expose address/secret.
      const id = createHash("sha256").update(url).digest("hex").slice(0, 16);
      const existing = byId.get(id);
      if (existing) {
        if (!existing.events.includes(event)) existing.events.push(event);
      } else {
        byId.set(id, { id, url, events: [event] });
      }
    }
  }
  // Only { id, url, events } are returned — secrets are stripped entirely.
  return { subscribers: Array.from(byId.values()) };
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
// Scanner, risk, compliance, evidence, and roadmap routes
// ------------------------------------------------------------------
registerScannerRoutes(server);
await server.register(registerGPURoutes);

// ------------------------------------------------------------------
// Boot: start indexer, then listen
// ------------------------------------------------------------------
const start = async () => {
  try {
    if (process.env.NODE_ENV === "production" && !process.env.QTRUST_SCAN_ALLOWED_ROOTS) {
      // Critical B-3 remediation: without an allowlist, /v1/scan/* would accept
      // any absolute path on this host. Refuse to serve rather than guess.
      server.log.error("Refusing to start: QTRUST_SCAN_ALLOWED_ROOTS is required in production");
      process.exit(1);
    }
    // Wire Redis subscriptions into webhook delivery (audit B-4: previously
    // stored but never consulted).
    if (redis) {
      setSubscriberResolver(async (eventType: string) => {
        const keys = [`subscribers:${eventType}`, "subscribers:*"];
        const seen = new Set<string>();
        const out: Array<{ url: string; secret?: string }> = [];
        for (const key of keys) {
          const records = await redis!.smembers(key);
          for (const raw of records) {
            try {
              const parsed = JSON.parse(raw) as { url?: string; address?: string; secret?: string };
              if (!parsed.url || seen.has(`${parsed.address ?? ""}|${parsed.url}`)) continue;
              seen.add(`${parsed.address ?? ""}|${parsed.url}`);
              let secret: string | undefined;
              try {
                secret = parsed.secret ? decryptSecret(parsed.secret) : undefined;
              } catch {
                console.warn(`Webhook subscriber ${parsed.url}: undecryptable secret — delivering unsigned`);
              }
              out.push({ url: parsed.url, secret });
            } catch {
              continue;
            }
          }
        }
        return out;
      });
    }
    await startIndexer();
    await server.listen({ port: Number(process.env.PORT) || 3001, host: "0.0.0.0" });
    console.log(`Server listening on ${JSON.stringify(server.server.address())}`);

    // Audit Critical #11: gracefulShutdown was exported but never invoked —
    // on every deploy/restart the Postgres pool, Redis client, indexer
    // subscriptions, and in-flight requests were abandoned mid-flight.
    gracefulShutdown(server, "SIGTERM", async () => {
      stopIndexer();
      if (redis) {
        try {
          await redis.quit();
        } catch {
          // already disconnected
        }
      }
      if (pgPool) {
        await pgPool.end();
      }
    });
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

start();