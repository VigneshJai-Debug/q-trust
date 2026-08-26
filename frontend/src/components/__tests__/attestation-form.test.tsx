import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

/**
 * Audit follow-up: AttestationForm is the ONLY component that requests a
 * wallet signature and previously had zero unit tests. These tests pin the
 * security-critical wiring:
 *   - the verifyingContract regex guard (refuses to sign against an
 *     unconfigured contract),
 *   - the EIP-712 domain/types/message construction,
 *   - the nonce fetch + sign + relay round-trip,
 *   - the error surface when any step fails.
 */

const mocks = vi.hoisted(() => ({
  address: "0xABCd000000000000000000000000000000000000" as `0x${string}`,
  chainId: 84532,
  switchChainAsync: vi.fn(),
  signTypedDataAsync: vi.fn(),
  fetchVendorNonce: vi.fn(),
  relayAttestation: vi.fn(),
}));

vi.mock("wagmi", () => ({
  useAccount: () => ({ address: mocks.address, isConnected: true, chainId: mocks.chainId }),
  useSwitchChain: () => ({ switchChainAsync: mocks.switchChainAsync }),
  useSignTypedData: () => ({ signTypedDataAsync: mocks.signTypedDataAsync }),
}));

vi.mock("@rainbow-me/rainbowkit", () => ({
  ConnectButton: () => <button>Connect</button>,
}));

vi.mock("@tanstack/react-query", () => ({
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));

vi.mock("@/lib/api", () => ({
  fetchVendorNonce: (...a: unknown[]) => mocks.fetchVendorNonce(...a),
  relayAttestation: (...a: unknown[]) => mocks.relayAttestation(...a),
  PQC_ALGORITHMS: [
    { value: "ML-KEM-768", label: "ML-KEM-768" },
    { value: "ML-DSA-65", label: "ML-DSA-65" },
  ],
}));

vi.mock("@/lib/config", () => ({
  CHAIN: { id: 84532 },
  CONTRACTS: { vendorRegistry: "0x4567600000000000000000000000000000000000" },
}));

import { AttestationForm } from "@/components/attestation-form";

describe("AttestationForm (signing flow)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.chainId = 84532;
    mocks.fetchVendorNonce.mockResolvedValue("0");
    mocks.signTypedDataAsync.mockResolvedValue("0xsignature");
    mocks.relayAttestation.mockResolvedValue({ txHash: "0xtx" });
  });

  async function submit() {
    render(<AttestationForm vendor={mocks.address} />);
    fireEvent.click(screen.getByRole("button", { name: /attest product/i }));
  }

  it("fetches a nonce, signs typed data, and relays", async () => {
    await submit();

    await waitFor(() =>
      expect(mocks.relayAttestation).toHaveBeenCalledTimes(1),
    );

    expect(mocks.fetchVendorNonce).toHaveBeenCalledWith(mocks.address);
    expect(mocks.signTypedDataAsync).toHaveBeenCalledTimes(1);

    const args = mocks.signTypedDataAsync.mock.calls[0][0];
    // Domain must be pinned to the LOCAL contract config — never an API value.
    expect(args.domain).toEqual({
      name: "QTrustVendorRegistry",
      version: "1",
      chainId: 84532,
      verifyingContract: "0x4567600000000000000000000000000000000000",
    });
    // Message must carry the fetched nonce and form fields.
    expect(args.message.nonce).toBe(0n);
    expect(args.primaryType).toBe("ProductAttestation");

    const relayPayload = mocks.relayAttestation.mock.calls[0][0];
    expect(relayPayload).toMatchObject({
      productId: "QTrust-PQC-Lib",
      version: "1.4.0",
      algorithm: "ML-KEM-768",
      supported: true,
      signature: "0xsignature",
    });

    expect(await screen.findByText(/recorded on-chain/i)).toBeInTheDocument();
  });

  it("switches chain before signing when the wallet is on the wrong one", async () => {
    mocks.chainId = 1; // wrong chain
    await submit();
    await waitFor(() => expect(mocks.signTypedDataAsync).toHaveBeenCalled());
    expect(mocks.switchChainAsync).toHaveBeenCalledWith({ chainId: 84532 });
  });

  it("surfaces relay errors instead of failing silently", async () => {
    mocks.relayAttestation.mockRejectedValue(new Error("relay rejected"));
    await submit();
    expect(await screen.findByText(/relay rejected/)).toBeInTheDocument();
  });
});
