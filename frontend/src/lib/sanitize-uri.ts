/**
 * URL scheme allowlist for vendor-controlled URIs rendered as links.
 *
 * Audit FE-3: evidence_uri comes from vendor attestations (arbitrary
 * off-chain input) and was previously rendered directly into <a href>,
 * allowing javascript:, data:, and vbscript: XSS payloads.
 */

const ALLOWED_SCHEMES = ["http:", "https:", "ipfs:", "ipns:"] as const;

/** Returns a safe href, or null when the URI uses a disallowed scheme. */
export function sanitizeUri(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return null; // not a valid absolute URI
  }
  if (!ALLOWED_SCHEMES.includes(parsed.protocol as (typeof ALLOWED_SCHEMES)[number])) {
    return null;
  }
  // Block credentials-in-URL tricks like https://evil.com@example.com
  if (parsed.username || parsed.password) return null;
  return parsed.toString();
}
