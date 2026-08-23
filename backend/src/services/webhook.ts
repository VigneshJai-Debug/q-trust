/**
 * Webhook delivery service with hardening:
 *  - HTTPS-only URLs (no localhost/private IP exfiltration)
 *  - Strict timeout + response size caps
 *  - Bounded retries with exponential backoff + jitter
 *  - Fan-out to all registered webhooks for an org
 */
import { randomUUID, createHmac, timingSafeEqual } from "node:crypto";
import * as dns from "node:dns";
import * as https from "node:https";

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
      /^169\.254\./.test(host) ||
      /^100\.64\./.test(host) ||
      /^198\.18\./.test(host) ||
      /^192\.0\.0\./.test(host) ||
      host === "::1" ||
      host.startsWith("fe80:") ||
      host.startsWith("fc") ||
      host.startsWith("fd") ||
      /^::ffff:/.test(host) ||
      /^fec0:/.test(host) ||
      /^\[::ffff:/.test(host) ||
      /^\[fc/.test(host) ||
      /^\[fd/.test(host) ||
      /^\[fe80:/.test(host) ||
      /^\[fec0:/.test(host) ||
      /^\[::1\]/.test(host)
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------
// SSRF hardening: IP-range checks (applied to ALL resolved addresses)
// ------------------------------------------------------------------

function ipv4ToLong(ip: string): number {
  return ip.split(".").reduce((acc, octet) => (acc * 256 + Number(octet)) >>> 0, 0) >>> 0;
}

function ipv4InCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToLong(ip) & mask) === (ipv4ToLong(range) & mask);
}

const BLOCKED_IPV4_CIDRS = [
  "0.0.0.0/8", // "this" network
  "10.0.0.0/8", // private
  "100.64.0.0/10", // CGNAT / carrier-grade NAT
  "127.0.0.0/8", // loopback
  "169.254.0.0/16", // link-local (cloud metadata)
  "172.16.0.0/12", // private
  "192.0.0.0/24", // IETF protocol assignments
  "192.0.2.0/24", // TEST-NET-1
  "192.88.99.0/24", // 6to4 relay anycast
  "192.168.0.0/16", // private
  "198.18.0.0/15", // benchmarking
  "198.51.100.0/24", // TEST-NET-2
  "203.0.113.0/24", // TEST-NET-3
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // reserved
];

const BLOCKED_IPV6_PREFIXES = [
  "::", // unspecified
  "::1", // loopback
  "fc", // fc00::/7 — unique local addresses (covers fd00::/8)
  "fd",
  "fe8", // fe80::/10 — link-local
  "fe9",
  "fea",
  "feb",
  "ff", // ff00::/8 — multicast
  "fec0", // deprecated site-local
];

export function isPrivateIp(address: string): boolean {
  if (address.includes(":")) {
    const lower = address.toLowerCase();
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) — check the embedded v4 address.
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return BLOCKED_IPV6_PREFIXES.some((p) => lower === p || lower.startsWith(p));
  }
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) return true; // unparseable → treat as unsafe
  return BLOCKED_IPV4_CIDRS.some((cidr) => ipv4InCidr(address, cidr));
}

/**
 * Resolve the hostname ONCE and validate every returned address.
 * Returns a public IP to connect to directly (prevents DNS rebinding:
 * the connection cannot silently re-resolve to an internal address).
 */
export async function resolvePublicAddress(hostname: string): Promise<{ address: string; family: number }> {
  const results = await dns.promises.lookup(hostname, { all: true });
  if (!results.length) {
    throw new Error(`DNS resolution returned no addresses for ${hostname}`);
  }
  for (const { address } of results) {
    if (isPrivateIp(address)) {
      throw new Error(`Webhook hostname ${hostname} resolves to a blocked (private/reserved) address`);
    }
  }
  return results[0];
}

function signPayload(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

function verifySignature(body: string, secret: string, signature: string): boolean {
  if (!secret || !signature) return false;
  const expected = signPayload(body, secret);
  try {
    return timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(signature, "hex"));
  } catch {
    return false;
  }
}

function deliverOnce(url: string, event: WebhookEvent, secret?: string): Promise<boolean> {
  const body = JSON.stringify({ id: randomUUID(), ...event });
  return new Promise<boolean>((resolve) => {
    (async () => {
      try {
        const parsed = new URL(url);
        // Resolve once; connect to the validated IP directly so the request
        // cannot be re-bound to a different (internal) address between the
        // SSRF check and the connection.
        const { address } = await resolvePublicAddress(parsed.hostname);
        const headers: Record<string, string> = {
          "content-type": "application/json",
          "content-length": String(Buffer.byteLength(body)),
          // Pin Host to the original hostname — required for vhost routing
          // since we dial the IP directly.
          host: parsed.host,
        };
        if (secret) {
          headers["x-webhook-signature"] = signPayload(body, secret);
        }
        const req = https.request(
          {
            protocol: "https:",
            hostname: address,
            port: parsed.port ? Number(parsed.port) : 443,
            path: `${parsed.pathname}${parsed.search}`,
            method: "POST",
            headers,
            servername: parsed.hostname, // SNI + certificate validation against original hostname
            timeout: TIMEOUT_MS,
          },
          (res) => {
            const status = res.statusCode ?? 0;
            const declaredLen = Number(res.headers["content-length"] ?? 0);
            if (status < 200 || status >= 300 || declaredLen > MAX_BODY_BYTES) {
              res.resume();
              resolve(false);
              return;
            }
            let received = 0;
            let ok = true;
            res.on("data", (chunk: Buffer) => {
              received += chunk.length;
              if (received > MAX_BODY_BYTES) {
                ok = false;
                res.destroy();
              }
            });
            res.on("end", () => resolve(ok));
            res.on("error", () => resolve(false));
          },
        );
        req.on("timeout", () => {
          req.destroy(new Error("timeout"));
        });
        req.on("error", () => resolve(false));
        req.end(body);
      } catch {
        resolve(false);
      }
    })();
  });
}

export async function deliverWebhook(url: string, event: WebhookEvent, secret?: string): Promise<boolean> {
  if (!isPublicHttpsUrl(url)) {
    console.warn(`Webhook delivery blocked: non-HTTPS or private URL (${url})`);
    return false;
  }
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    if (await deliverOnce(url, event, secret)) return true;
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