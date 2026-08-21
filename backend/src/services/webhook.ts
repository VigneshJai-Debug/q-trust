/**
 * Webhook delivery service with hardening:
 *  - HTTPS-only URLs (no localhost/private IP exfiltration)
 *  - Strict timeout + response size caps
 *  - Bounded retries with exponential backoff + jitter
 *  - Fan-out to all registered webhooks for an org
 */
import { randomUUID } from "node:crypto";

const MAX_ATTEMPTS = 3;
const BASE_BACKOFF_MS = 500;
const MAX_BACKOFF_MS = 10_000;
const TIMEOUT_MS = 5_000;
const MAX_BODY_BYTES = 256 * 1024;

interface WebhookEvent {
  type: string;
  orgDid: string;
  payload: Record<string, unknown>;
}

function isPublicHttpsUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
    // Block obviously non-routable / private targets.
    if (
      host === "localhost" ||
      host === "0.0.0.0" ||
      host.endsWith(".local") ||
      host.endsWith(".internal") ||
      /^127\./.test(host) ||
      /^10\./.test(host) ||
      /^192\.168\./.test(host) ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host) ||
      host === "::1" ||
      host.startsWith("fe80:")
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function deliverOnce(url: string, event: WebhookEvent): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: randomUUID(), ...event }),
      signal: controller.signal,
    });
    if (!res.ok) return false;
    const len = Number(res.headers.get("content-length") ?? 0);
    if (len > MAX_BODY_BYTES) return false;
    await res.arrayBuffer(); // consume body so the socket can be reused
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export async function deliverWebhook(url: string, event: WebhookEvent): Promise<boolean> {
  if (!isPublicHttpsUrl(url)) {
    console.warn(`Webhook delivery blocked: non-HTTPS or private URL (${url})`);
    return false;
  }
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (await deliverOnce(url, event)) return true;
    if (attempt < MAX_ATTEMPTS - 1) {
      const jitter = Math.random() * 250;
      const delay = Math.min(BASE_BACKOFF_MS * 2 ** attempt + jitter, MAX_BACKOFF_MS);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  console.warn(`Webhook delivery failed after ${MAX_ATTEMPTS} attempts: ${url}`);
  return false;
}

/** Fan out one event to every webhook endpoint configured for the org. */
export async function fanOut(orgDid: string, type: string, payload: Record<string, unknown>): Promise<void> {
  const urls = (process.env.QTRUST_WEBHOOKS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!urls.length) return;
  const event: WebhookEvent = { type, orgDid, payload };
  await Promise.all(urls.map((u) => deliverWebhook(u, event)));
}