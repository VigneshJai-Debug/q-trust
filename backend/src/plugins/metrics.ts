/**
 * Prometheus metrics for the Q-Trust backend.
 *
 * Exposes default Node.js process metrics plus an HTTP request duration
 * histogram labelled by route, method and status code, served at /metrics
 * (deliberately NOT under /v1 so scrapers never hit versioned routes).
 *
 * Dependency-light: prom-client only. The plugin is applied directly to the
 * root Fastify instance (no encapsulation) so hooks cover every route.
 */
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import client from "prom-client";

const registry = new client.Registry();

const REQUEST_START = Symbol("qtrust.requestStart");

let httpDuration: client.Histogram<string> | null = null;
let initialized = false;

function ensureCollectors(): void {
  if (initialized) return;
  initialized = true;

  client.collectDefaultMetrics({ register: registry });

  httpDuration = new client.Histogram({
    name: "qtrust_http_request_duration_seconds",
    help: "HTTP request duration in seconds",
    labelNames: ["route", "method", "status"],
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    registers: [registry],
  });
}

/** Wire process + HTTP metrics collection and the /metrics endpoint. */
export function registerMetrics(server: FastifyInstance): void {
  ensureCollectors();

  server.addHook("onRequest", async (request: FastifyRequest) => {
    (request as unknown as Record<symbol, bigint>)[REQUEST_START] = process.hrtime.bigint();
  });

  server.addHook("onResponse", async (request: FastifyRequest, reply: FastifyReply) => {
    const start = (request as unknown as Record<symbol, bigint | undefined>)[REQUEST_START];
    if (!httpDuration || start === undefined) return;
    const seconds = Number(process.hrtime.bigint() - start) / 1e9;
    // routeOptions.url is the registered pattern (e.g. /v1/assets/:id);
    // unmatched paths (404s) report as "unmatched" to bound label cardinality.
    const route = request.routeOptions?.url ?? "unmatched";
    httpDuration
      .labels(route, request.method, String(reply.statusCode))
      .observe(seconds);
  });

  server.get("/metrics", async (_request, reply) => {
    reply.header("content-type", registry.contentType);
    return registry.metrics();
  });
}
