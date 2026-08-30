
import type { FastifyInstance, FastifyReply } from "fastify";
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
} from "../services/verify.js";
import { isValidAddress, isValidBytes32, CONTRACTS, publicClient, PLANNER_URL, PLANNER_API_KEY } from "../config.js";
import { requireApiKey } from "../middleware/auth.js"; // REG-18: prevent unauthenticated compute amplification
import {
  RevocationAnchorAbi,
  PolicyCommitmentAbi,
  SchemaRegistryAbi,
  TrustAnchorRegistryAbi,
} from "../lib/abis.js";

function validateDid(did: string, reply: FastifyReply): string | undefined {
  if (!isValidAddress(did)) {
    reply.status(400).send({ error: "Invalid DID format (expected 0x-prefixed 42-char hex address)" });
    return undefined;
  }
  return did;
}

export async function registerReadRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/assets/:id", async (request, reply) => {
    const id = (request.params as { id: string }).id;
    if (!isValidBytes32(id)) {
      return reply.status(400).send({ error: "Invalid asset ID format (expected 0x-prefixed 66-char hex)" });
    }
    const asset = await getAsset(id);
    if (!asset) return reply.status(404).send({ error: "Asset not found" });
    return asset;
  });

  app.get("/v1/assets/:id/verify", async (request, reply) => {
    try {
      return await verifyAsset((request.params as { id: string }).id);
    } catch (err) {
      request.log.warn({ err }, "asset verify failed");
      return reply.status(400).send({ error: "Verification failed — check asset ID format" });
    }
  });

  app.get("/v1/orgs/:did/summary", async (request, reply) => {
    const did = validateDid((request.params as { did: string }).did, reply);
    if (!did) return;
    try {
      return await getOrgSummary(did as `0x${string}`);
    } catch (err) {
      request.log.warn({ err }, "org summary failed");
      return reply.status(400).send({ error: "Failed to load organization summary" });
    }
  });

  app.get("/v1/orgs/:did/assets", async (request, reply) => {
    const did = validateDid((request.params as { did: string }).did, reply);
    if (!did) return;
    const q = request.query as { offset?: string; limit?: string };
    const offset = Math.max(0, Number(q.offset ?? 0));
    const limit = Math.min(200, Math.max(1, Number(q.limit ?? 50)));
    const page = await getAssetsByOrg(did as `0x${string}`, offset, limit);
    return { org: did, ...page };
  });

  app.get("/v1/orgs/:did/migrations", async (request, reply) => {
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

  app.get("/v1/orgs/:did/audit", async (request, reply) => {
    const did = validateDid((request.params as { did: string }).did, reply);
    if (!did) return;
    return getLatestAudit(did as `0x${string}`);
  });

  app.get("/v1/migrations/:id", async (request, reply) => {
    try {
      const migration = await getMigration((request.params as { id: string }).id);
      if (!migration) return reply.status(404).send({ error: "Migration not found" });
      return migration;
    } catch (err) {
      request.log.warn({ err }, "migration fetch failed");
      return reply.status(400).send({ error: "Failed to load migration" });
    }
  });

  app.get("/v1/vendors/:did/attestations", async (request, reply) => {
    const did = validateDid((request.params as { did: string }).did, reply);
    if (!did) return;
    const q = request.query as { offset?: string; limit?: string };
    const offset = Math.max(0, Number(q.offset ?? 0));
    const limit = Math.min(200, Math.max(1, Number(q.limit ?? 50)));
    const page = await getVendorAttestations(did as `0x${string}`, offset, limit);
    return { vendor: did, ...page };
  });

  app.get("/v1/products/:id/support", async (request, reply) => {
    const q = request.query as { version?: string; algorithm?: string };
    const productId = (request.params as { id: string }).id;
    if (!q.version || !q.algorithm) {
      return reply.status(400).send({ error: "version and algorithm query params required" });
    }
    return checkProductSupport(productId, q.version, q.algorithm);
  });

  app.post("/v1/plans", { preHandler: requireApiKey }, async (request, reply) => {
    const body = request.body as { cbom?: Record<string, unknown>; deadline?: string };
    if (!body.cbom || !Array.isArray((body.cbom as any).assets) || !(body.cbom as any).assets.length) {
      return reply.status(400).send({ error: "cbom.assets (non-empty array) is required" });
    }
    try {
      const res = await fetch(`${PLANNER_URL}/plan`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(PLANNER_API_KEY ? { "x-api-key": PLANNER_API_KEY } : {}),
        },
        body: JSON.stringify({ cbom: body.cbom, deadline: body.deadline ?? null }),
        signal: AbortSignal.timeout(60_000),
      });
      if (!res.ok) {
        const detail = await res.text();
        return reply.status(res.status).send({ error: `Planner service error: ${detail}` });
      }
      return res.json();
    } catch {
      return reply.status(503).send({ error: "Planner service unavailable — start it with: docker compose up planner" });
    }
  });

  app.get("/v1/plans/:did", { preHandler: requireApiKey }, async (request, reply) => {
    try {
      const did = (request.params as { did: string }).did;
      const q = request.query as { deadline?: string };
      const url = `${PLANNER_URL}/plans/${encodeURIComponent(did)}${q.deadline ? `?deadline=${encodeURIComponent(q.deadline)}` : ""}`;
      const res = await fetch(url, {
        signal: AbortSignal.timeout(30_000),
        ...(PLANNER_API_KEY ? { headers: { "x-api-key": PLANNER_API_KEY } as Record<string, string> } : {}),
      });
      if (!res.ok) {
        return reply.status(res.status).send({ error: `Planner service error: ${res.status}` });
      }
      return res.json();
    } catch {
      return reply.status(503).send({ error: "Planner service unavailable — start it with: docker compose up planner" });
    }
  });

  app.get("/v1/revocation/:issuer", async (request, reply) => {
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

  app.get("/v1/policies/:policyId/versions/:version", async (request, reply) => {
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

  app.get("/v1/schemas/:schemaId", async (request, reply) => {
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

  app.get("/v1/trust-anchors/:issuer", async (request, reply) => {
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

  // legacy aliases
  app.get("/assets/:id", async (request, reply) => {
    reply.header("Deprecation", "true");
    reply.header("Sunset", "2026-12-31");
    reply.header("Link", `</v1/assets/${(request.params as { id: string }).id}>; rel="successor-version"`);
    const asset = await getAsset((request.params as { id: string }).id);
    if (!asset) return reply.status(404).send({ error: "Asset not found" });
    return asset;
  });

  app.get("/migration/progress/:org", async (request, reply) => {
    reply.header("Deprecation", "true");
    reply.header("Sunset", "2026-12-31");
    return getMigrationProgress((request.params as { org: string }).org as `0x${string}`);
  });
}
