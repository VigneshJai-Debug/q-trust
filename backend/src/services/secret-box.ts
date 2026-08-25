import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Encryption-at-rest helper for sensitive values stored in Redis
 * (webhook signing secrets). AES-256-GCM with a key from
 * QTRUST_WEBHOOK_ENC_KEY (64 hex chars = 32 bytes).
 *
 * Ciphertext format: "enc.v1.<iv-b64url>.<tag-b64url>.<ct-b64url>"
 *
 * If QTRUST_WEBHOOK_ENC_KEY is not configured, values pass through
 * unencrypted so existing deployments keep working; a one-time
 * warning is logged via onPlaintextFallback.
 */

const KEY_ENV_VAR = "QTRUST_WEBHOOK_ENC_KEY";
const PREFIX = "enc.v1";
let warnedNoKey = false;

export function getEncryptionKey(): Buffer | null {
  const raw = process.env[KEY_ENV_VAR];
  if (!raw) return null;
  const key = /^[0-9a-fA-F]{64}$/.test(raw)
    ? Buffer.from(raw, "hex")
    : Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error(
      `${KEY_ENV_VAR} must be 32 bytes (64 hex chars or base64) — got ${key.length}`
    );
  }
  return key;
}

export function encryptionConfigured(): boolean {
  return getEncryptionKey() !== null;
}

export function encryptSecret(
  plaintext: string,
  onPlaintextFallback?: () => void
): string {
  if (!plaintext) return "";
  const key = getEncryptionKey();
  if (!key) {
    if (!warnedNoKey) {
      warnedNoKey = true;
      onPlaintextFallback?.();
    }
    return plaintext;
  }
  const iv = randomBytes(12);
  // Explicit 128-bit auth tag length (semgrep gcm-no-tag-length): the tag is
  // stored alongside the ciphertext, so its length must be fixed and known.
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const enc = (b: Buffer) => b.toString("base64url");
  return `${PREFIX}.${enc(iv)}.${enc(tag)}.${enc(ct)}`;
}

export function decryptSecret(stored: string): string {
  if (!stored) return "";
  const parts = stored.split(".");
  if (parts.length !== 5 || parts[0] !== "enc" || parts[1] !== "v1") {
    // Legacy plaintext record (or empty) — return as-is.
    return stored;
  }
  const key = getEncryptionKey();
  if (!key) {
    throw new Error(`Cannot decrypt webhook secret: ${KEY_ENV_VAR} not configured`);
  }
  const [, , ivB64, tagB64, ctB64] = parts;
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64url"), {
    authTagLength: 16,
  });
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  const pt = Buffer.concat([
    decipher.update(Buffer.from(ctB64, "base64url")),
    decipher.final(),
  ]);
  return pt.toString("utf8");
}
