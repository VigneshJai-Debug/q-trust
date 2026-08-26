import type { FastifyInstance } from "fastify";
import { requireApiKey } from "../middleware/auth.js";
import { CHAIN } from "../config.js";
import {
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
} from "../services/attestation.js";
import {
  RelayAuditBodySchema,
  RelayAttestationBodySchema,
  RelayCBOMBodySchema,
  RelayMigrationBodySchema,
} from "../schemas/index.js";

/**
 * EIP-712 gasless relay routes — rate limited to prevent gas abuse and
 * API-key gated (audit H-3).
 *
 * Extracted from server.ts to keep the 1000-line monolith split into
 * routes/{scanner,relay,gpu,webhooks} as claimed in the audit commit.
 */
export async function registerRelayRoutes(app: FastifyInstance): Promise<void> {
  app.post("/v1/relay/attestation", {
    // Audit H-3: requireApiKey on every relay POST — without it anyone can
    // mint valid EIP-712 signatures for addresses they control and drain the
    // relayer wallet (per-IP limits are trivially bypassed with a botnet).
    preHandler: requireApiKey,
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
      if (/Nonce mismatch|signature verification|must be/.test(msg)) {
        return reply.status(400).send({ error: msg });
      }
      request.log.error(err, "Relay attestation failed");
      return reply.status(422).send({ error: "Relay submission failed" });
    }
  });

  app.get("/v1/relay/nonce/:did", async (request, reply) => {
    try {
      const nonce = await getVendorNonce((request.params as { did: string }).did as `0x${string}`);
      return { did: (request.params as { did: string }).did, nonce: nonce.toString() };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(400).send({ error: msg });
    }
  });

  app.post("/v1/relay/cbom", {
    preHandler: requireApiKey, // Audit H-3
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

  app.post("/v1/relay/migration", {
    preHandler: requireApiKey, // Audit H-3
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

  app.get("/v1/relay/cbom-nonce/:did", async (request, reply) => {
    try {
      const nonce = await getOrgNonce((request.params as { did: string }).did as `0x${string}`);
      return { did: (request.params as { did: string }).did, nonce: nonce.toString() };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(400).send({ error: msg });
    }
  });

  app.post("/v1/relay/audit", {
    preHandler: requireApiKey, // Audit H-3
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
      const result = await relaySignedAudit(body as any);
      return { ...result, relayer: relayerAddress(), chain_id: CHAIN.id };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const code = msg.includes("signature") || msg.includes("Nonce") || msg.includes("must be") ? 400 : 422;
      return reply.status(code).send({ error: msg });
    }
  });

  app.get("/v1/relay/audit-nonce/:did", async (request, reply) => {
    try {
      const nonce = await getAuditNonce((request.params as { did: string }).did as `0x${string}`);
      return { did: (request.params as { did: string }).did, nonce: nonce.toString() };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.status(400).send({ error: msg });
    }
  });
}
