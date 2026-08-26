
import type { FastifyInstance } from "fastify";
import { createHash } from "node:crypto";
import { Redis } from "ioredis";
import { requireApiKey } from "../middleware/auth.js";
import { encryptSecret, decryptSecret } from "../services/secret-box.js";
import { setSubscriberResolver } from "../services/webhook.js";
import { isValidAddress } from "../config.js";

export async function registerWebhookRoutes(app: FastifyInstance, redis: Redis | null): Promise<void> {
  app.post("/v1/webhooks/subscribe", {
    preHandler: requireApiKey,
    config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const { address, url, secret, events } = request.body as { address: string; url: string; secret?: string; events?: string[] };
    if (!address || !url) {
      return reply.status(400).send({ error: "address and url are required" });
    }
    if (!isValidAddress(address)) {
      return reply.status(400).send({ error: "Invalid address format" });
    }
    try { new URL(url); } catch { return reply.status(400).send({ error: "Invalid url format" }); }
    if (!redis) {
      return reply.status(503).send({ error: "Redis unavailable — webhook service not running" });
    }
    const eventList = events && events.length ? events : ["*"];
    const stored = JSON.stringify({
      url, address,
      secret: encryptSecret(secret ?? "", () => app.log.warn("QTRUST_WEBHOOK_ENC_KEY not set — webhook secrets are stored UNENCRYPTED in Redis")),
    });
    for (const event of eventList) {
      const key = event === "*" ? "subscribers:*" : `subscribers:${event}`;
      await redis.sadd(key, stored);
    }
    return { subscribed: true, subscriber: { address, url, events: eventList, secret: secret ? "•••" : "" } };
  });

  app.post("/v1/webhooks/unsubscribe", {
    preHandler: requireApiKey,
    config: { rateLimit: { max: 20, timeWindow: "1 minute" } },
  }, async (request, reply) => {
    const { address, url, events } = request.body as { address: string; url: string; events?: string[] };
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
      const records = await redis.smembers(key);
      for (const raw of records) {
        try {
          const parsed = JSON.parse(raw) as { url?: string; address?: string };
          if (parsed.url === url && parsed.address === address) {
            removed += await redis.srem(key, raw);
          }
        } catch { continue; }
      }
    }
    return { unsubscribed: true, removed };
  });

  app.get("/v1/webhooks/subscribers", { preHandler: requireApiKey }, async () => {
    if (!redis) return { subscribers: [] };
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
        } catch { continue; }
        if (!url) continue;
        const id = createHash("sha256").update(url).digest("hex").slice(0, 16);
        const existing = byId.get(id);
        if (existing) {
          if (!existing.events.includes(event)) existing.events.push(event);
        } else {
          byId.set(id, { id, url, events: [event] });
        }
      }
    }
    return { subscribers: Array.from(byId.values()) };
  });

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
            try { secret = parsed.secret ? decryptSecret(parsed.secret) : undefined; } catch { console.warn(`Webhook subscriber ${parsed.url}: undecryptable secret — delivering unsigned`); }
            out.push({ url: parsed.url, secret });
          } catch { continue; }
        }
      }
      return out;
    });
  }
}
