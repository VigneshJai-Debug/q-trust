import { describe, it, expect, vi, beforeEach } from "vitest";

const SIGNER = "0x1111111111111111111111111111111111111111";
const AUDIT_REGISTRY = "0x3333333333333333333333333333333333333333";
const TX_HASH = "0x" + "ab".repeat(32);
const AUDIT_ID = "0x" + "cd".repeat(32);

process.env.NODE_ENV = "test";
process.env.QTRUST_RELAYER_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
process.env.QTRUST_ASSET_REGISTRY_ADDRESS = "0x" + "11".repeat(20);
process.env.QTRUST_VENDOR_REGISTRY_ADDRESS = "0x" + "22".repeat(20);
process.env.QTRUST_MIGRATION_REGISTRY_ADDRESS = "0x" + "44".repeat(20);
process.env.QTRUST_AUDIT_REGISTRY_ADDRESS = AUDIT_REGISTRY;

vi.mock("../src/services/rpc-pool.js", () => {
  const calls = {
    readContract: vi.fn(),
    writeContract: vi.fn(),
    waitForTransactionReceipt: vi.fn(),
  };
  return {
    getPublicClient: () => ({
      readContract: calls.readContract,
      waitForTransactionReceipt: calls.waitForTransactionReceipt,
    }),
    getWalletClient: () => ({
      writeContract: calls.writeContract,
    }),
    __mockCalls: calls,
  };
});

vi.mock("viem", async (importOriginal) => {
  const actual = await importOriginal<typeof import("viem")>();
  return {
    ...actual,
    recoverTypedDataAddress: vi.fn(async () => SIGNER),
  };
});

const { relaySignedAudit, getAuditNonce, EIP712_AUDIT_DOMAIN, EIP712_AUDIT_TYPES } =
  await import("../src/services/attestation.js");
const { recoverTypedDataAddress } = await import("viem");
const { __mockCalls: calls } = await import("../src/services/rpc-pool.js");

function validPayload() {
  return {
    orgDid: "0x9999999999999999999999999999999999999999",
    result: 1,
    assetsReviewed: 10,
    assetsMigrated: 4,
    reportHash: "0x" + "ef".repeat(32),
    reportURI: "ipfs://bafyauditreport",
    nonce: 0,
    signature: "0x" + "be".repeat(65),
  };
}

describe("relaySignedAudit (EIP-712 gasless audit posting)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    calls.readContract.mockResolvedValue(0n);
    calls.writeContract.mockResolvedValue(TX_HASH);
    calls.waitForTransactionReceipt.mockResolvedValue({
      logs: [{ eventName: "AuditPosted", args: { auditId: AUDIT_ID } }],
    });
  });

  it("submits postAuditSigned with the contract's exact argument order", async () => {
    const payload = validPayload();
    const result = await relaySignedAudit(payload);

    expect(calls.readContract).toHaveBeenCalledWith(
      expect.objectContaining({
        address: AUDIT_REGISTRY,
        functionName: "nonces",
        args: [SIGNER],
      }),
    );
    expect(calls.writeContract).toHaveBeenCalledWith(
      expect.objectContaining({
        address: AUDIT_REGISTRY,
        functionName: "postAuditSigned",
        args: [
          payload.orgDid,
          payload.result,
          10n,
          4n,
          payload.reportHash,
          payload.reportURI,
          0n,
          payload.signature,
        ],
      }),
    );
    expect(result).toEqual({
      txHash: TX_HASH,
      auditorDid: SIGNER,
      orgDid: payload.orgDid,
      auditId: AUDIT_ID,
    });
    expect(recoverTypedDataAddress).toHaveBeenCalledWith(
      expect.objectContaining({
        domain: EIP712_AUDIT_DOMAIN,
        types: EIP712_AUDIT_TYPES,
        primaryType: "Audit",
      }),
    );
  });

  it("rejects a bad EIP-712 signature before any chain interaction", async () => {
    vi.mocked(recoverTypedDataAddress).mockRejectedValueOnce(new Error("bad sig"));
    await expect(relaySignedAudit(validPayload())).rejects.toThrow(
      /signature verification failed/,
    );
    expect(calls.writeContract).not.toHaveBeenCalled();
  });

  it("rejects a stale/replayed nonce without submitting", async () => {
    calls.readContract.mockResolvedValue(5n);
    await expect(relaySignedAudit(validPayload())).rejects.toThrow(/Nonce mismatch/);
    expect(calls.writeContract).not.toHaveBeenCalled();
  });

  it("rejects malformed reportHash and orgDid client-side", async () => {
    await expect(
      relaySignedAudit({ ...validPayload(), reportHash: "0x1234" }),
    ).rejects.toThrow(/reportHash/);
    await expect(
      relaySignedAudit({ ...validPayload(), orgDid: "not-an-address" }),
    ).rejects.toThrow(/orgDid/);
    expect(calls.writeContract).not.toHaveBeenCalled();
  });

  it("returns empty auditId when the receipt has no AuditPosted log", async () => {
    calls.waitForTransactionReceipt.mockResolvedValue({ logs: [] });
    const result = await relaySignedAudit(validPayload());
    expect(result.auditId).toBe("");
    expect(result.txHash).toBe(TX_HASH);
  });

  it("getAuditNonce reads the on-chain nonce for an auditor", async () => {
    calls.readContract.mockResolvedValue(7n);
    const nonce = await getAuditNonce(SIGNER as `0x${string}`);
    expect(nonce).toBe(7n);
    expect(calls.readContract).toHaveBeenCalledWith(
      expect.objectContaining({ functionName: "nonces", args: [SIGNER] }),
    );
  });
});
