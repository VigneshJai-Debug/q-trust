import { describe, it, expect, vi, afterEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { issueCredential, verifyCredential, signCredential, canonicalJson, publicKeyToDidKey, didKeyToPublicKey } from "../src/services/vc.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("vc canonicalization (Python-SDK compatible)", () => {
  it("sorts keys recursively with compact separators", () => {
    const out = canonicalJson({ b: 2, a: { d: 4, c: 3 } });
    expect(out).toBe('{"a":{"c":3,"d":4},"b":2}');
  });

  it("omits undefined fields (exclude_none semantics)", () => {
    const out = canonicalJson({ a: 1, b: undefined, c: null });
    expect(out).toBe('{"a":1,"c":null}');
  });
});

describe("did:key helpers", () => {
  it("round-trips an Ed25519 public key", () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    const did = publicKeyToDidKey(pub);
    expect(did.startsWith("did:key:z")).toBe(true);
    const back = didKeyToPublicKey(did);
    expect(back).not.toBeNull();
    expect(Buffer.from(back!).toString("hex")).toBe(Buffer.from(pub).toString("hex"));
  });

  it("rejects malformed did:key values", () => {
    expect(didKeyToPublicKey("did:web:example.com")).toBeNull();
    expect(didKeyToPublicKey("did:key:zzz")).toBeNull();
  });
});

describe("issueCredential", () => {
  it("produces a signed credential with an Ed25519Signature2020 proof", () => {
    const vc = issueCredential({
      subject_did: "did:ethr:0x1234",
      schema_id: "https://schemas.example/pqc-readiness.json",
      claims: { pqc_readiness_level: "Level 2" },
      expiration_date: new Date(Date.now() + 86_400_000).toISOString(),
    });
    expect(vc.type).toContain("VerifiableCredential");
    expect(vc.credentialSubject.id).toBe("did:ethr:0x1234");
    expect(vc.credentialSubject.pqc_readiness_level).toBe("Level 2");
    expect(vc.issuer.startsWith("did:key:z")).toBe(true);
    expect(vc.proof?.type).toBe("Ed25519Signature2020");
    expect(vc.proof?.proofPurpose).toBe("assertionMethod");
    expect((vc.proof?.proofValue as string).length).toBe(128); // 64 bytes hex
  });
});

describe("verifyCredential — fail-closed", () => {
  it("verifies a genuinely issued credential", async () => {
    const vc = issueCredential({
      subject_did: "did:ethr:0xabc",
      claims: { pqc_ready: true },
    });
    const result = await verifyCredential(vc);
    expect(result.valid).toBe(true);
    expect(result.checked.signature).toBe(true);
    expect(result.issuer_did).toBe(vc.issuer);
    expect(result.subject_did).toBe("did:ethr:0xabc");
  });

  it("rejects a credential with a tampered claim", async () => {
    const vc = issueCredential({ subject_did: "did:ethr:0xabc", claims: { pqc_ready: true } });
    (vc.credentialSubject as Record<string, unknown>).pqc_ready = false;
    const result = await verifyCredential(vc);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  it("rejects a credential whose proof was forged under a different key", async () => {
    const vc = issueCredential({ subject_did: "did:ethr:0xabc" });
    // Attacker holds a DIFFERENT key but claims the victim's issuer DID.
    const attackerPriv = ed25519.utils.randomPrivateKey();
    const attackerPub = ed25519.getPublicKey(attackerPriv);
    const forged = signCredential(vc, attackerPriv, attackerPub);
    // signCredential rebinds the DID to the attacker key, so restore the
    // victim's issuer DID to simulate a forged proof under the victim's identity.
    forged.issuer = vc.issuer;
    const result = await verifyCredential(forged);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });

  it("rejects an unsigned credential", async () => {
    const vc = issueCredential({ subject_did: "did:ethr:0xabc" });
    delete vc.proof;
    const result = await verifyCredential(vc);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unsigned_credential");
  });

  it("rejects an expired credential even with a valid signature", async () => {
    const vc = issueCredential({
      subject_did: "did:ethr:0xabc",
      expiration_date: new Date(Date.now() - 86_400_000).toISOString(),
    });
    const result = await verifyCredential(vc);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("expired");
    expect(result.expired).toBe(true);
  });

  it("rejects a credential missing required fields", async () => {
    const result = await verifyCredential({ foo: "bar" });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("missing_required_fields");
  });

  it("rejects when the issuer DID cannot resolve", async () => {
    const vc = issueCredential({ subject_did: "did:ethr:0xabc" });
    (vc as Record<string, unknown>).issuer = "did:unsupported:xyz";
    const result = await verifyCredential(vc);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("did_resolution_failed");
  });

  it("resolves did:web issuers via HTTPS (DID document fetch)", async () => {
    // Deterministic key for the mock did:web document.
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    const did = publicKeyToDidKey(pub);
    const vc = signCredential(
      {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: "urn:uuid:mock",
        type: ["VerifiableCredential"],
        issuer: "did:web:qtrust.example",
        issuanceDate: new Date().toISOString(),
        credentialSubject: { id: "did:ethr:0x1" },
      },
      priv,
      pub,
    );
    const doc = {
      "@context": "https://www.w3.org/ns/did/v1",
      id: "did:web:qtrust.example",
      verificationMethod: [
        {
          id: "did:web:qtrust.example#key-1",
          type: "Ed25519VerificationKey2020",
          controller: "did:web:qtrust.example",
          publicKeyMultibase: (() => {
            const payload = new Uint8Array(2 + pub.length);
            payload[0] = 0xed;
            payload[1] = 0x01;
            payload.set(pub, 2);
            return `z${Buffer.from(payload).toString("base64url")}`;
          })(),
        },
      ],
    };
    // The base58btc encoding is NOT base64url — build it properly for the mock.
    const { base58 } = await import("@scure/base");
    const payload = new Uint8Array(2 + pub.length);
    payload[0] = 0xed;
    payload[1] = 0x01;
    payload.set(pub, 2);
    doc.verificationMethod[0].publicKeyMultibase = `z${base58.encode(payload)}`;

    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => doc,
    })));

    const result = await verifyCredential(vc);
    expect(result.valid).toBe(true);
    expect(result.checked.signature).toBe(true);
    expect((fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0]).toContain(
      "https://qtrust.example/.well-known/did.json",
    );
  });

  it("rejects did:web issuers on forbidden SSRF hosts", async () => {
    const vc = issueCredential({ subject_did: "did:ethr:0xabc" });
    (vc as Record<string, unknown>).issuer = "did:web:localhost";
    const result = await verifyCredential(vc);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("did_resolution_failed");
  });
});
