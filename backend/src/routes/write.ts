
import type { FastifyInstance } from "fastify";
import { requireApiKey } from "../middleware/auth.js";
import { registerCBOM, attestProduct, recordMigration, relayerAddress } from "../services/attestation.js";
import { evaluate } from "../services/evaluate.js";
import { issueCredential, verifyCredential } from "../services/vc.js";
import { CredentialVerifySchema } from "../schemas/index.js";

export async function registerWriteRoutes(app: FastifyInstance): Promise<void> {
  app.post("/v1/write/assets", {
    preHandler: requireApiKey,
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const body = request.body as { cbomHash?: string; metadataURI?: string };
    if (!body.cbomHash || !body.cbomHash.startsWith("0x")) {
      return reply.status(400).send({ error: "cbomHash (0x-prefixed) is required" });
    }
    try {
      const result = await registerCBOM({ cbomHash: body.cbomHash, metadataURI: body.metadataURI ?? "" });
      return { ...result, relayer: relayerAddress() };
    } catch (err) {
      request.log.error(err, "CBOM registration failed");
      return reply.status(422).send({ error: "Registration failed" });
    }
  });

  app.post("/v1/write/attestations", {
    preHandler: requireApiKey,
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const body = request.body as { productId?: string; version?: string; algorithm?: string; supported?: boolean; evidenceURI?: string };
    if (!body.productId || !body.version || !body.algorithm) {
      return reply.status(400).send({ error: "productId, version and algorithm are required" });
    }
    try {
      const result = await attestProduct({ productId: body.productId, version: body.version, algorithm: body.algorithm, supported: Boolean(body.supported), evidenceURI: body.evidenceURI ?? "" });
      return { ...result, relayer: relayerAddress() };
    } catch (err) {
      request.log.error(err, "Attestation failed");
      return reply.status(422).send({ error: "Attestation failed" });
    }
  });

  app.post("/v1/write/migrations", {
    preHandler: requireApiKey,
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const body = request.body as { migrationId?: string; assetId?: string; fromAlgorithm?: string; toAlgorithm?: string; evidenceHash?: string; evidenceURI?: string };
    if (!body.migrationId || !body.assetId || !body.fromAlgorithm || !body.toAlgorithm) {
      return reply.status(400).send({ error: "migrationId, assetId, fromAlgorithm and toAlgorithm are required" });
    }
    try {
      const result = await recordMigration({ migrationId: body.migrationId, assetId: body.assetId, fromAlgorithm: body.fromAlgorithm, toAlgorithm: body.toAlgorithm, evidenceHash: body.evidenceHash ?? "0x" + "0".repeat(64), evidenceURI: body.evidenceURI ?? "" });
      return { ...result, relayer: relayerAddress() };
    } catch (err) {
      request.log.error(err, "Migration recording failed");
      return reply.status(422).send({ error: "Migration recording failed" });
    }
  });

  app.post("/v1/evaluate", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const { subject_did, policy_id, policy_version, evidence } = request.body as { subject_did: string; policy_id: string; policy_version: string; evidence?: Array<{ evidence_id: string; evidence_type: string; claims: Record<string, unknown> }> };
    if (!subject_did || !policy_id || !policy_version) {
      return reply.status(400).send({ error: "subject_did, policy_id, and policy_version are required" });
    }
    return evaluate({ subject_did, policy_id, policy_version, evidence });
  });

  app.post("/v1/credentials/issue", { preHandler: requireApiKey }, async (request, reply) => {
    const { schema_id, subject_did, claims, expiration_date } = request.body as { schema_id?: string; subject_did: string; claims?: Record<string, Record<string, unknown>>; expiration_date?: string };
    if (!subject_did) {
      return reply.status(400).send({ error: "subject_did is required" });
    }
    const vc = issueCredential({
      subject_did,
      issuer_did: "", // issuer identity is the backend's configured did:key
      schema_id: schema_id ?? null,
      claims: claims ?? {},
      expiration_date: expiration_date ?? null,
    });
    return {
      credential: vc,
      credential_id: vc.id,
      issuer_did: vc.issuer,
      subject_did,
      schema_id: schema_id ?? null,
      issued_at: vc.issuanceDate,
      proof_type: vc.proof?.type ?? null,
      note: "Signed with Ed25519Signature2020 (Ed25519). Verify via POST /v1/credentials/verify.",
    };
  });

  app.post("/v1/credentials/verify", { schema: { body: CredentialVerifySchema } }, async (request, reply) => {
    const { presentation } = request.body as { presentation: Record<string, unknown> };
    const result = await verifyCredential(presentation);
    return result;
  });
}
