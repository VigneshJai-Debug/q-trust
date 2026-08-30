
import fastify, { type FastifyRequest, type FastifyReply } from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { TypeBoxTypeProvider } from "@fastify/type-provider-typebox";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as dotenv from "dotenv";
import { Redis } from "ioredis";
import { startIndexer, stopIndexer, pool as pgPool } from "./services/indexer.js";
import { registerScannerRoutes } from "./routes/scanner.js";
import { registerRelayRoutes } from "./routes/relay.js";
import { registerGPURoutes } from "./services/gpu-service.js";
import { registerHealthRoutes } from "./routes/health.js";
import { registerReadRoutes } from "./routes/read.js";
import { registerWriteRoutes } from "./routes/write.js";
import { registerWebhookRoutes } from "./routes/webhooks.js";
import { gracefulShutdown } from "./middleware/auth.js";
import { initSentry, registerSentryHooks } from "./plugins/sentry.js";
import { registerMetrics } from "./plugins/metrics.js";
import { CORS_ORIGINS, CHAIN_ID } from "./config.js";
import { relayerAddress } from "./services/attestation.js";

dotenv.config();
initSentry();

const PACKAGE_VERSION: string = (JSON.parse(readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8")) as { version: string }).version;

const server = fastify({ logger: true, bodyLimit: 1 * 1024 * 1024 }).withTypeProvider<TypeBoxTypeProvider>();

process.on("unhandledRejection", (reason) => {
  server.log.error({ err: reason }, "Unhandled promise rejection — keeping process alive");
});
process.on("uncaughtException", (err) => {
  server.log.error({ err }, "Uncaught exception — exiting");
  process.exit(1);
});

const redisUrl = process.env.QTRUST_REDIS_URL ?? process.env.REDIS_URL ?? "redis://localhost:6379";
let redis: Redis | null = null;
try {
  redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 });
  redis.connect().catch(() => { console.warn("Redis unavailable — webhook subscriptions disabled"); redis = null; });
} catch { redis = null; }

// REG-14: API returns JSON, not HTML — CSP false is intentional for /docs Swagger UI.
// Frontend (Next.js) enforces strict CSP via next.config.js (QTRUST-014).
await server.register(helmet, { contentSecurityPolicy: false, hsts: { maxAge: 15552000 } });
server.register(cors, { origin: CORS_ORIGINS.includes("*") ? true : CORS_ORIGINS, methods: ["GET", "POST", "OPTIONS"] });

if (process.env.QTRUST_RATE_LIMIT_MAX === "0") {
  server.register(rateLimit, { global: false });
} else {
  server.register(rateLimit, { max: Number(process.env.QTRUST_RATE_LIMIT_MAX) || 120, timeWindow: "1 minute" });
}

registerSentryHooks(server);
registerMetrics(server);

await server.register(swagger, {
  openapi: { info: { title: "Q-Trust API", version: PACKAGE_VERSION, description: "Q-Trust supply-chain verification API." }, servers: [{ url: process.env.QTRUST_PUBLIC_URL ?? "http://localhost:3001" }] },
});
await server.register(swaggerUi, { routePrefix: "/docs" });

// Route plugins — each is a Fastify plugin with its own schemas and per-route limits.
await registerHealthRoutes(server);
await registerReadRoutes(server);
await registerWriteRoutes(server);
await registerRelayRoutes(server);
registerScannerRoutes(server);
await server.register(registerGPURoutes);
await registerWebhookRoutes(server, redis);

const start = async () => {
  try {
    if (process.env.NODE_ENV === "production" && !process.env.QTRUST_SCAN_ALLOWED_ROOTS) {
      server.log.error("Refusing to start: QTRUST_SCAN_ALLOWED_ROOTS is required in production");
      process.exit(1);
    }
    await startIndexer();
    await server.listen({ port: Number(process.env.PORT) || 3001, host: "0.0.0.0" });
    console.log(`Server listening on ${JSON.stringify(server.server.address())}`);
    gracefulShutdown(server, "SIGTERM", async () => {
      stopIndexer();
      if (redis) { try { await redis.quit(); } catch {} }
      if (pgPool) { await pgPool.end(); }
    });
  } catch (err) { server.log.error(err); process.exit(1); }
};
start();
