/**
 * Sentry error tracking for the Q-Trust backend.
 *
 * Enabled ONLY when QTRUST_SENTRY_DSN is configured; otherwise every call
 * is a no-op so local/dev/test environments stay completely silent and
 * dependency-free at runtime (no network, no timers).
 */
import { readFileSync } from "node:fs";
import type { FastifyInstance } from "fastify";
import * as Sentry from "@sentry/node";

let initialized = false;

/** Release identifier from backend/package.json ("qtrust-backend@x.y.z"). */
function release(): string | undefined {
  try {
    // Resolves to backend/package.json both via tsx (src/) and node (dist/).
    const pkgUrl = new URL("../../package.json", import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgUrl, "utf8")) as { name?: string; version?: string };
    return pkg.name && pkg.version ? `${pkg.name}@${pkg.version}` : pkg.version;
  } catch {
    return undefined;
  }
}

/** Initialise Sentry if (and only if) QTRUST_SENTRY_DSN is set. Idempotent. */
export function initSentry(): void {
  const dsn = process.env.QTRUST_SENTRY_DSN;
  if (!dsn || initialized) return;
  initialized = true;

  // Audit H-4: never transmit credentials to Sentry infrastructure.
  const SENSITIVE_HEADERS = new Set(["x-api-key", "authorization", "cookie"]);
  const KEY_PATTERN = /0x[0-9a-fA-F]{64}/g;
  const scrub = (value: unknown): unknown => {
    if (typeof value === "string") {
      return value.replace(KEY_PATTERN, "[redacted-private-key]");
    }
    if (Array.isArray(value)) return value.map(scrub);
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(([k, v]) => [
          k,
          SENSITIVE_HEADERS.has(k.toLowerCase()) ? "[redacted]" : scrub(v),
        ]),
      );
    }
    return value;
  };

  Sentry.init({
    dsn,
    release: release(),
    tracesSampleRate: 0.1,
    sendDefaultPii: false,
    beforeSend(event) {
      if (event.request?.headers) {
        for (const header of Object.keys(event.request.headers)) {
          if (SENSITIVE_HEADERS.has(header.toLowerCase())) {
            event.request.headers[header] = "[redacted]";
          }
        }
      }
      // Request bodies may contain signed payloads or relayer secrets —
      // never capture them.
      if (event.request?.data) {
        event.request.data = "[redacted]";
      }
      // Belt-and-braces: scrub any 32-byte hex private key shape anywhere in
      // the event (breadcrumbs, extra, contexts, ...).
      return scrub(event) as typeof event;
    },
  });
}

/** Capture route errors via the Fastify onError hook. No-op without a DSN. */
export function registerSentryHooks(server: FastifyInstance): void {
  server.addHook("onError", async (_request, _reply, error) => {
    if (!initialized) return;
    Sentry.captureException(error);
  });
}
