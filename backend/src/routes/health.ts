import type { FastifyInstance } from "fastify";
import { CHAIN_ID } from "../config.js";
import { relayerAddress } from "../services/attestation.js";

export async function registerHealthRoutes(app: FastifyInstance): Promise<void> {
  app.get("/health", async () => ({
    status: "ok",
    chain_id: CHAIN_ID,
    relayer: relayerAddress(),
  }));
}
