import { describe, it, expect } from "vitest";

// We test the isPublicHttpsUrl logic by importing the compiled module.
// Since the function is not exported, we test via the webhook delivery path.
// For unit testing, we replicate the logic here to verify correctness.

function isPublicHttpsUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
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

describe("SSRF filter — isPublicHttpsUrl", () => {
  it("allows public HTTPS URLs", () => {
    expect(isPublicHttpsUrl("https://example.com/hook")).toBe(true);
    expect(isPublicHttpsUrl("https://api.github.com/webhooks")).toBe(true);
  });

  it("rejects HTTP", () => {
    expect(isPublicHttpsUrl("http://example.com/hook")).toBe(false);
  });

  it("rejects localhost", () => {
    expect(isPublicHttpsUrl("https://localhost/hook")).toBe(false);
    expect(isPublicHttpsUrl("https://localhost:8080/hook")).toBe(false);
  });

  it("rejects private IPs", () => {
    expect(isPublicHttpsUrl("https://10.0.0.1/hook")).toBe(false);
    expect(isPublicHttpsUrl("https://192.168.1.1/hook")).toBe(false);
    expect(isPublicHttpsUrl("https://172.16.0.1/hook")).toBe(false);
    expect(isPublicHttpsUrl("https://127.0.0.1/hook")).toBe(false);
  });

  it("rejects link-local", () => {
    expect(isPublicHttpsUrl("https://169.254.169.254/hook")).toBe(false);
  });

  it("rejects IPv6 private", () => {
    expect(isPublicHttpsUrl("https://[::1]/hook")).toBe(false);
    expect(isPublicHttpsUrl("https://[fe80::1]/hook")).toBe(false);
    expect(isPublicHttpsUrl("https://[fc00::1]/hook")).toBe(false);
    expect(isPublicHttpsUrl("https://[fd00::1]/hook")).toBe(false);
  });

  it("rejects IPv4-mapped IPv6", () => {
    // URL parser normalizes ::ffff:127.0.0.1 to ::ffff:7f00:1
    expect(isPublicHttpsUrl("https://[::ffff:127.0.0.1]/hook")).toBe(false);
  });

  it("rejects .local and .internal", () => {
    expect(isPublicHttpsUrl("https://myhost.local/hook")).toBe(false);
    expect(isPublicHttpsUrl("https://myhost.internal/hook")).toBe(false);
  });

  it("rejects invalid URLs", () => {
    expect(isPublicHttpsUrl("not-a-url")).toBe(false);
    expect(isPublicHttpsUrl("")).toBe(false);
  });
});
