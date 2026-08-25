import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  encryptSecret,
  decryptSecret,
  encryptionConfigured,
} from "../src/services/secret-box.js";

const TEST_KEY =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

describe("secret-box", () => {
  beforeEach(() => {
    process.env.QTRUST_WEBHOOK_ENC_KEY = TEST_KEY;
  });

  afterEach(() => {
    delete process.env.QTRUST_WEBHOOK_ENC_KEY;
  });

  it("round-trips a secret through encrypt/decrypt", () => {
    const secret = "whsec_abc123-XYZ/+=~";
    const stored = encryptSecret(secret);
    expect(stored).not.toBe(secret);
    expect(stored.startsWith("enc.v1.")).toBe(true);
    expect(decryptSecret(stored)).toBe(secret);
  });

  it("produces unique ciphertexts (random IV)", () => {
    const a = encryptSecret("same-input");
    const b = encryptSecret("same-input");
    expect(a).not.toBe(b);
    expect(decryptSecret(a)).toBe("same-input");
    expect(decryptSecret(b)).toBe("same-input");
  });

  it("passes through empty strings", () => {
    expect(encryptSecret("")).toBe("");
    expect(decryptSecret("")).toBe("");
  });

  it("returns legacy plaintext unchanged on decrypt", () => {
    expect(decryptSecret("old-plaintext-secret")).toBe("old-plaintext-secret");
  });

  it("falls back to plaintext when no key is configured", () => {
    delete process.env.QTRUST_WEBHOOK_ENC_KEY;
    expect(encryptionConfigured()).toBe(false);
    let warned = false;
    const stored = encryptSecret("no-key-secret", () => {
      warned = true;
    });
    expect(warned).toBe(true);
    expect(stored).toBe("no-key-secret");
  });

  it("rejects malformed keys", () => {
    process.env.QTRUST_WEBHOOK_ENC_KEY = "tooshort";
    expect(() => encryptionConfigured()).toThrow(/must be 32 bytes/);
  });

  it("detects tampering via GCM auth tag", () => {
    const stored = encryptSecret("tamper-me");
    const parts = stored.split(".");
    const ct = Buffer.from(parts[4], "base64url");
    ct[0] ^= 0xff;
    parts[4] = Buffer.from(ct).toString("base64url");
    expect(() => decryptSecret(parts.join("."))).toThrow();
  });
});
