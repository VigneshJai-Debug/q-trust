import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { DEFAULT_ADMIN_ROLE, isAdminRole, useUserRole } from "@/hooks/use-user-role";
import { fetchOrgAssets, fetchVendorAttestations } from "@/lib/api";

const ADMIN_ADDRESS = "0x1111111111111111111111111111111111111111" as const;
const VENDOR_ADDRESS = "0x2222222222222222222222222222222222222222" as const;

const readContract = vi.fn();

vi.mock("wagmi", () => ({
  useAccount: vi.fn(),
  usePublicClient: vi.fn(),
}));

vi.mock("@/lib/config", () => ({
  CONTRACTS: {
    vendorRegistry: "0x00000000000000000000000000000000000fab1e",
  },
}));

vi.mock("@/lib/api", () => ({
  fetchOrgAssets: vi.fn(),
  fetchVendorAttestations: vi.fn(),
}));

import { useAccount, usePublicClient } from "wagmi";

function mockWallet(address: string | undefined) {
  vi.mocked(useAccount).mockReturnValue({
    address,
    isConnecting: false,
    isReconnecting: false,
  } as unknown as ReturnType<typeof useAccount>);
  vi.mocked(usePublicClient).mockReturnValue({
    readContract,
  } as unknown as ReturnType<typeof usePublicClient>);
}

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 60_000 } },
  });
  const Wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return Wrapper;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(fetchOrgAssets).mockResolvedValue([]);
  vi.mocked(fetchVendorAttestations).mockResolvedValue({
    vendor: VENDOR_ADDRESS,
    count: 0,
    attestations: [],
  });
});

describe("useUserRole admin detection", () => {
  it("reads DEFAULT_ADMIN_ROLE on VendorRegistry and grants role 'admin' when hasRole is true", async () => {
    mockWallet(ADMIN_ADDRESS);
    readContract.mockResolvedValue(true);

    const { result } = renderHook(() => useUserRole(), { wrapper: createWrapper() });

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.role).toBe("admin");
    expect(result.current.isPrivileged).toBe(true);
    expect(readContract).toHaveBeenCalledWith(
      expect.objectContaining({
        address: "0x00000000000000000000000000000000000fab1e",
        functionName: "hasRole",
        args: [DEFAULT_ADMIN_ROLE, ADMIN_ADDRESS],
      }),
    );
  });

  it("falls through to the org/vendor detection when hasRole is false", async () => {
    mockWallet(VENDOR_ADDRESS);
    readContract.mockResolvedValue(false);
    vi.mocked(fetchVendorAttestations).mockResolvedValue({
      vendor: VENDOR_ADDRESS,
      count: 1,
      attestations: [
        {
          attestation_id: "att-1",
          vendor_did: VENDOR_ADDRESS,
          product_id: "DigiCert-TLS",
          version: "5.2.1",
          algorithm: "ML-DSA-44",
          supported: true,
          evidence_uri: "ipfs://evidence",
          timestamp: 1_700_000_000,
          revoked: false,
        },
      ],
    });

    const { result } = renderHook(() => useUserRole(), { wrapper: createWrapper() });

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.isVendor).toBe(true);
    expect(result.current.role).toBe("vendor");
    expect(result.current.isPrivileged).toBe(false);
  });

  it("resolves to plain 'none' for a connected wallet with no roles", async () => {
    mockWallet(VENDOR_ADDRESS);
    readContract.mockResolvedValue(false);

    const { result } = renderHook(() => useUserRole(), { wrapper: createWrapper() });

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.role).toBe("none");
    expect(result.current.isPrivileged).toBe(false);
  });

  it("treats a failing on-chain hasRole call as not-admin without breaking the hook", async () => {
    mockWallet(ADMIN_ADDRESS);
    readContract.mockRejectedValue(new Error("rpc down"));

    const { result } = renderHook(() => useUserRole(), { wrapper: createWrapper() });

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.role).toBe("none");
    expect(result.current.isPrivileged).toBe(false);
  });

  it("reports role 'none' while no wallet is connected", async () => {
    mockWallet(undefined);

    const { result } = renderHook(() => useUserRole(), { wrapper: createWrapper() });

    expect(result.current.role).toBe("none");
    expect(result.current.isPrivileged).toBe(false);
    expect(readContract).not.toHaveBeenCalled();
  });
});

describe("isAdminRole", () => {
  it("is reachable only for the admin role", () => {
    expect(isAdminRole("admin")).toBe(true);
    expect(isAdminRole("org")).toBe(false);
    expect(isAdminRole("vendor")).toBe(false);
    expect(isAdminRole("none")).toBe(false);
  });
});
